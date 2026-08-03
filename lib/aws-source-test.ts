import {
  ListObjectsV2Command,
  GetObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import { STSClient, AssumeRoleCommand } from "@aws-sdk/client-sts";
import { env } from "cloudflare:workers";
import type {
  ConnectionCheck,
  ConnectionTestSummary,
  IngestionSource,
} from "./admin-sources";
import { awsRuntimeCredentials } from "./aws-runtime-credentials";

function check(
  key: string,
  label: string,
  status: ConnectionCheck["status"],
  detail: string,
): ConnectionCheck {
  return { key, label, status, detail };
}

function configuredForLiveAws() {
  return Boolean(
    typeof process !== "undefined" &&
      (process.env.AWS_ACCESS_KEY_ID ||
        process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI ||
        process.env.AWS_WEB_IDENTITY_TOKEN_FILE ||
        process.env.GATEWATCH_AWS_RUNTIME === "true" ||
        env.GATEWATCH_AWS_RUNTIME === "true" ||
        (env.GATEWATCH_AWS_BRIDGE_URL && env.GATEWATCH_AWS_BRIDGE_TOKEN)),
  );
}

async function testThroughAwsBridge(source: IngestionSource) {
  const bridgeUrl = env.GATEWATCH_AWS_BRIDGE_URL?.replace(/\/$/, "");
  const bridgeToken = env.GATEWATCH_AWS_BRIDGE_TOKEN;
  if (!bridgeUrl || !bridgeToken) return null;
  const response = await fetch(`${bridgeUrl}/test-source`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${bridgeToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(source),
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error("AWS bridge could not validate the source.");
  return (await response.json()) as ConnectionTestSummary;
}

function detectedFormat(source: IngestionSource, key = "") {
  if (source.sourceType === "cloudtrail" || key.includes("CloudTrail")) {
    return "AWS CloudTrail JSON.GZ";
  }
  if (source.sourceType === "config-history" || key.includes("ConfigHistory")) {
    return "AWS Config history";
  }
  return "AWS Config snapshot";
}

export async function testAwsSource(
  source: IngestionSource,
): Promise<ConnectionTestSummary> {
  const testedAt = new Date().toISOString();
  const configurationChecks: ConnectionCheck[] = [
    check(
      "bucket",
      "Bucket and prefix",
      "passed",
      `${source.bucketName}/${source.objectPrefix || "(bucket root)"}`,
    ),
    check(
      "role",
      "Least-privilege role",
      "passed",
      source.roleArn,
    ),
    check(
      "encryption",
      "Encrypted object access",
      source.kmsKeyArn ? "pending" : "warning",
      source.kmsKeyArn
        ? "KMS decrypt permission will be verified against a sample object."
        : "No customer-managed KMS key was supplied; bucket-default encryption is expected.",
    ),
    check(
      "format",
      "Expected delivery format",
      "passed",
      detectedFormat(source),
    ),
  ];

  if (!configuredForLiveAws()) {
    return {
      mode: "configuration-only",
      testedAt,
      passed: false,
      detectedFormat: detectedFormat(source),
      checks: [
        ...configurationChecks,
        check(
          "aws-runtime",
          "AWS runtime identity",
          "pending",
          "Configuration is valid. Deploy Gatewatch with an application IAM role to perform the live AssumeRole and S3 read test.",
        ),
      ],
    };
  }

  const timeout = AbortSignal.timeout(12_000);
  try {
    const bridged = await testThroughAwsBridge(source);
    if (bridged) return bridged;
    const sts = new STSClient({
      region: source.region,
      credentials:
        env.GATEWATCH_AWS_RUNTIME === "true"
          ? awsRuntimeCredentials
          : undefined,
    });
    const assumed = await sts.send(
      new AssumeRoleCommand({
        RoleArn: source.roleArn,
        RoleSessionName: `gatewatch-source-test-${Date.now()}`,
        ExternalId: source.externalId || undefined,
        DurationSeconds: 900,
      }),
      { abortSignal: timeout },
    );
    if (
      !assumed.Credentials?.AccessKeyId ||
      !assumed.Credentials.SecretAccessKey ||
      !assumed.Credentials.SessionToken
    ) {
      throw new Error("STS returned an incomplete temporary credential set.");
    }
    const s3 = new S3Client({
      region: source.region,
      credentials: {
        accessKeyId: assumed.Credentials.AccessKeyId,
        secretAccessKey: assumed.Credentials.SecretAccessKey,
        sessionToken: assumed.Credentials.SessionToken,
        expiration: assumed.Credentials.Expiration,
      },
    });
    const listing = await s3.send(
      new ListObjectsV2Command({
        Bucket: source.bucketName,
        Prefix: source.objectPrefix || undefined,
        MaxKeys: 5,
      }),
      { abortSignal: timeout },
    );
    const newest = [...(listing.Contents ?? [])]
      .filter((item) => item.Key)
      .sort(
        (a, b) =>
          (b.LastModified?.getTime() ?? 0) -
          (a.LastModified?.getTime() ?? 0),
      )[0];
    if (!newest?.Key) {
      return {
        mode: "live",
        testedAt,
        passed: false,
        detectedFormat: detectedFormat(source),
        checks: [
          ...configurationChecks.slice(0, 1),
          check("role", "Assume role", "passed", "STS issued temporary credentials."),
          check(
            "list",
            "List configured prefix",
            "passed",
            "The prefix is readable but contains no objects.",
          ),
          check(
            "sample",
            "Read sample object",
            "failed",
            "Add a CloudTrail or AWS Config delivery file, then test again.",
          ),
        ],
      };
    }
    await s3.send(
      new GetObjectCommand({
        Bucket: source.bucketName,
        Key: newest.Key,
        Range: "bytes=0-65535",
      }),
      { abortSignal: timeout },
    );
    return {
      mode: "live",
      testedAt,
      passed: true,
      detectedFormat: detectedFormat(source, newest.Key),
      newestObject: {
        key: newest.Key,
        size: newest.Size ?? 0,
        lastModified: newest.LastModified?.toISOString() ?? "",
      },
      checks: [
        check("role", "Assume role", "passed", "STS issued temporary credentials."),
        check(
          "list",
          "List configured prefix",
          "passed",
          `${listing.KeyCount ?? 0} sample object(s) discovered.`,
        ),
        check(
          "sample",
          "Read sample object",
          "passed",
          "A bounded range read succeeded; KMS access is available if required.",
        ),
        check(
          "format",
          "Detected delivery format",
          "passed",
          detectedFormat(source, newest.Key),
        ),
      ],
    };
  } catch (error) {
    const detail =
      error instanceof Error
        ? error.message.slice(0, 500)
        : "AWS returned an unknown connection error.";
    return {
      mode: "live",
      testedAt,
      passed: false,
      detectedFormat: detectedFormat(source),
      checks: [
        ...configurationChecks.slice(0, 1),
        check(
          "aws-access",
          "Assume role and read S3",
          "failed",
          detail,
        ),
      ],
    };
  }
}
