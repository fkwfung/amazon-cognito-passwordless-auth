import { createHash, createPublicKey, constants, createVerify } from "crypto";
import {
  CreateAuthChallengeTriggerEvent,
  VerifyAuthChallengeResponseTriggerEvent,
} from "aws-lambda";
import {
  DynamoDBClient,
  ConditionalCheckFailedException,
} from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  PutCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";
import {
  SESClient,
  SendEmailCommand,
  MessageRejected,
} from "@aws-sdk/client-ses";
import {
  KMSClient,
  SignCommand,
  GetPublicKeyCommand,
} from "@aws-sdk/client-kms";
import {
  logger,
  UserFacingError,
  handleConditionalCheckFailedException,
} from "./common.js";

let config = {
  /** Should Email OTP Code sign-in be enabled? If set to false, clients cannot sign-in with email OTP codes (an error is shown instead when they request an email OTP code) */
  emailOTPEnabled: !!process.env.EMAIL_OTP_ENABLED,
  /** The length of the email OTP code */
  otpLength: Number(process.env.OTP_LENGTH || 6),
  /** Number of seconds a Email OTP Code should be valid */
  secondsUntilExpiry: Number(process.env.SECONDS_UNTIL_EXPIRY || 60 * 15),
  /** Number of seconds that must lapse between unused Email OTP Codes (to prevent misuse) */
  minimumSecondsBetween: Number(process.env.MIN_SECONDS_BETWEEN || 30 * 1),
  /** The origins that are allowed to be used in the Email OTP Codes */
  // allowedOrigins: process.env.ALLOWED_ORIGINS?.split(",")
  //   .map((href) => new URL(href))
  //   .map((url) => url.origin),
  /** The e-mail address that Email OTP Codes will be sent from */
  sesFromAddress: process.env.SES_FROM_ADDRESS,
  /** The Amazon SES region, override e.g. to set a region where you are out of the SES sandbox */
  sesRegion: process.env.SES_REGION || process.env.AWS_REGION,
  /** KMS Key ID to use for generating Email OTP Codes (signatures) */
  // kmsKeyId: process.env.KMS_KEY_ID,
  /** The name of the DynamoDB table where (hashes of) Email OTP Codes will be stored */
  dynamodbSecretsTableName: process.env.DYNAMODB_OTP_SECRETS_TABLE,
  /** Function that will send the actual Email OTP Code e-mails. Override this to e.g. use another e-mail provider instead of Amazon SES */
  emailSender: sendEmailWithOtpCode,
  /** A salt to use for storing hashes of email OTP codes in the DynamoDB table */
  salt: process.env.STACK_ID,
  /** Function to create the content of the Email OTP Code e-mails, override to e.g. use a custom e-mail template */
  contentCreator: createEmailContent,
  /** Error message that will be shown to the client, if the client requests an Email OTP Code but isn't allowed to yet */
  notNowMsg:
    "We can't send you an email OTP code right now, please try again in a minute",
};

function requireConfig<K extends keyof typeof config>(
  k: K
): NonNullable<(typeof config)[K]> {
  // eslint-disable-next-line security/detect-object-injection
  const value = config[k];
  if (value === undefined) throw new Error(`Missing configuration for: ${k}`);
  return value;
}

export function configure(update?: Partial<typeof config>) {
  const oldSesRegion = config.sesRegion;
  config = { ...config, ...update };
  if (update && update.sesRegion !== oldSesRegion) {
    ses = new SESClient({ region: config.sesRegion });
  }
  return config;
}

const ddbDocClient = DynamoDBDocumentClient.from(new DynamoDBClient({}), {
  marshallOptions: {
    removeUndefinedValues: true,
  },
});
let ses = new SESClient({ region: config.sesRegion });

export async function addChallengeToEvent(
  event: CreateAuthChallengeTriggerEvent
): Promise<void> {
  if (!config.emailOTPEnabled)
    throw new UserFacingError("Sign-in with Email OTP Code not supported");
  event.response.challengeMetadata = "EMAIL_OTP_CODE";
  const alreadyHaveEmailOtpCode =
    event.request.clientMetadata?.alreadyHaveEmailOtpCode;
  if (alreadyHaveEmailOtpCode === "yes") {
    // The client already has a sign-in code, we don't need to send a new one
    logger.info("Client will use already obtained email OTP code");
    return;
  }
  logger.info("Client needs email OTP code");
  // Skip redirectUri for Email OTP Code
  // Determine the redirect URI for the email OTP code
  // const redirectUri = event.request.clientMetadata?.redirectUri;
  // if (
  //   !redirectUri ||
  //   !requireConfig("allowedOrigins").includes(new URL(redirectUri).origin)
  // ) {
  //   throw new UserFacingError(`Invalid redirectUri: ${redirectUri}`);
  // }
  const otpParams = JSON.parse(event.request.clientMetadata?.otpParams ?? "{}");
  // Send challenge with new secret login code
  await createAndSendEmailOtpCode(event, otpParams);
  const email = event.request.userAttributes.email;
  // The event.request.userNotFound is only present in the Lambda trigger if "Prevent user existence errors" is checked
  // in the Cognito app client. If it is *not* checked, the client receives the error, which potentially allows for
  // user enumeration. Additional guardrails are advisable.
  if (event.request.userNotFound) {
    logger.info("User not found");
  }
  // Current implementation has no use for publicChallengeParameters - feel free to provide them
  // if you want to use them in your front-end:
  // event.response.publicChallengeParameters = {};
  event.response.privateChallengeParameters = {
    email: email,
  };
}

async function createEmailContent({
  otpCode, otpParams
}: {
  otpCode: string;
  otpParams: any;
}) {
  return {
    html: {
      data: `<html><body><p>You recently requested a one-time password (OTP) code to access our service.</p></p><div>Your OTP Code: <strong>${otpCode}</strong></div><p>This code is valid for ${Math.floor(
        config.secondsUntilExpiry / 60
      )} minutes<p></p></body></html>`,
      charSet: "UTF-8",
    },
    text: {
      data: `Your One-Time Password (OTP) code: ${otpCode}`,
      charSet: "UTF-8",
    },
    subject: {
      data: "Your One-Time Password (OTP) code",
      charSet: "UTF-8",
    },
  };
}

async function sendEmailWithOtpCode({
  emailAddress,
  content,
}: {
  emailAddress: string;
  content: {
    html: { charSet: string; data: string };
    text: { charSet: string; data: string };
    subject: { charSet: string; data: string };
  };
}) {
  await ses
    .send(
      new SendEmailCommand({
        Destination: { ToAddresses: [emailAddress] },
        Message: {
          Body: {
            Html: {
              Charset: content.html.charSet,
              Data: content.html.data,
            },
            Text: {
              Charset: content.text.charSet,
              Data: content.text.data,
            },
          },
          Subject: {
            Charset: content.subject.charSet,
            Data: content.subject.data,
          },
        },
        Source: requireConfig("sesFromAddress"),
      })
    )
    .catch((err) => {
      if (
        err instanceof MessageRejected &&
        err.message.includes("Email address is not verified")
      ) {
        logger.error(err);
        throw new UserFacingError(
          "E-mail address must still be verified in the e-mail service"
        );
      }
      throw err;
    });
}

async function createAndSendEmailOtpCode(
  event: CreateAuthChallengeTriggerEvent,
  otpParams: any,
): Promise<void> {
  logger.debug("Creating new email OTP code ...");
  const exp = Math.floor(Date.now() / 1000 + config.secondsUntilExpiry);
  const iat = Math.floor(Date.now() / 1000);
  // Check whether a hard-coded OTP code is provided
  const hardcodedOtpCode = otpParams.fixedOtpCode;

  // Generate a random numeric OTP code if no hard-coded OTP code is provided
  const otpCode = hardcodedOtpCode ? hardcodedOtpCode : Array(config.otpLength)
    .fill(0)
    .map(() => Math.floor(Math.random() * 10))
    .join('');
  const messageContext = Buffer.from(
    JSON.stringify({
      userPoolId: event.userPoolId,
      clientId: event.callerContext.clientId,
      otpCode: otpCode,
    })
  );
  
  logger.debug("Storing email OTP code hash in DynamoDB ...");
  const salt = requireConfig("salt");
  await ddbDocClient
    .send(
      new PutCommand({
        TableName: requireConfig("dynamodbSecretsTableName"),
        Item: {
          userNameHash: createHash("sha256")
            .update(salt)
            .end(event.userName)
            .digest(),          
          optCodeHash: createHash("sha256")
            .update(salt)
            .end(messageContext)
            .digest(),
          iat,
          exp,          
        },
        // Throttle: fail if we've alreay sent a magic link less than SECONDS_BETWEEN seconds ago:
        ConditionExpression: "attribute_not_exists(#iat) or #iat < :iat",
        ExpressionAttributeNames: {
          "#iat": "iat",
        },
        ExpressionAttributeValues: {
          ":iat": Math.floor(Date.now() / 1000) - config.minimumSecondsBetween,
        },
      })
    )
    .catch(handleConditionalCheckFailedException(config.notNowMsg));

  logger.debug("Sending email OTP code ...");
  // Toggle userNotFound error with "Prevent user existence errors" in the Cognito app client. (see above)
  if (event.request.userNotFound) {
    return;
  }
  await config.emailSender({
    emailAddress: event.request.userAttributes.email,
    content: await config.contentCreator.call(undefined, {
      otpCode: otpCode,
      otpParams: otpParams,
    }),
  });
  logger.debug("Email OTP code sent!");
}

export async function addChallengeVerificationResultToEvent(
  event: VerifyAuthChallengeResponseTriggerEvent
) {
  logger.info("Verifying Email OTP Code Challenge Response ...");
  // Toggle userNotFound error with "Prevent user existence errors" in the Cognito app client. (see above)
  if (event.request.userNotFound) {
    logger.info("User not found");
  }
  if (!config.emailOTPEnabled)
    throw new UserFacingError("Sign-in with Email OTP Code not supported");
  if (
    event.request.privateChallengeParameters.challenge ===
      "PROVIDE_AUTH_PARAMETERS" &&
    event.request.clientMetadata?.alreadyHaveEmailOtpCode !== "yes"
  )
    return;
  event.response.answerCorrect = await verifyEmailOtpCode(
    event.request.challengeAnswer,
    event.userName,
    {
      userPoolId: event.userPoolId,
      clientId: event.callerContext.clientId,
    }
  );
}

async function verifyEmailOtpCode(
  otpCode: string,
  userName: string,
  context: { userPoolId: string; clientId: string }
) {
  logger.debug(
    "Verifying email OTP code for user:",
    userName
  );
  // Read and update item from DynamoDB. If the item has `uat` (used at)
  // attribute, no update is performed and no item is returned.
  let dbItem: Record<string, unknown> | undefined = undefined;
  try {
    // Hash the userName and signature and check if they match the ones in the database
    const salt = requireConfig("salt");
    const userNameHash = createHash("sha256")
      .update(salt)
      .end(userName)
      .digest();
    const optCodeHash = createHash("sha256")
      .update(salt)
      .end(
        Buffer.from(
          JSON.stringify({
            userPoolId: context.userPoolId,
            clientId: context.clientId,
            otpCode: otpCode,
          })
        )
      )
      .digest();
    const uat = Math.floor(Date.now() / 1000);

    ({ Attributes: dbItem } = await ddbDocClient.send(
      new UpdateCommand({
        TableName: requireConfig("dynamodbSecretsTableName"),
        Key: {
          userNameHash,
        },
        ReturnValues: "ALL_OLD",
        UpdateExpression: "SET #uat = :uat",
        ConditionExpression:
          "attribute_exists(#userNameHash) AND attribute_exists(#optCodeHash) AND #optCodeHash = :optCodeHash AND attribute_not_exists(#uat)",
        ExpressionAttributeNames: {
          "#userNameHash": "userNameHash",          
          "#optCodeHash": "optCodeHash",
          "#uat": "uat",
        },
        ExpressionAttributeValues: {
          ":optCodeHash": optCodeHash,
          ":uat": uat,
        },
      })
    ));
  } catch (err) {
    if (err instanceof ConditionalCheckFailedException) {
      logger.error(
        "Attempt to use invalid (potentially superseeded) email OTP code"
      );
      return false;
    }
    throw err;
  }
  if (!dbItem) {
    logger.error("Attempt to use invalid (potentially superseeded) email OTP code");
    return false;
  }
  assertIsEmailOtpCodeRecord(dbItem);
  if (dbItem.exp < Date.now() / 1000) {
    logger.error("Email OTP code expired");
    return false;
  }
  logger.debug(`Email OTP code is valid`);
  return true;
}

function assertIsEmailOtpCodeRecord(msg: unknown): asserts msg is {
  userNameHash: string;  
  optCodeHash: string;
  exp: number;
  iat: number;  
  uat?: number;
} {
  if (
    !msg ||
    typeof msg !== "object" ||
    !("userNameHash" in msg) ||
    !(msg.userNameHash instanceof Uint8Array) ||
    !("optCodeHash" in msg) ||
    !(msg.optCodeHash instanceof Uint8Array) ||
    !("exp" in msg) ||
    typeof msg.exp !== "number" ||
    !("iat" in msg) ||
    typeof msg.iat !== "number" ||
    ("uat" in msg && typeof msg.uat !== "number")
  ) {
    throw new Error("Invalid email OTP code record");
  }
}

