export const sourceTypes = [
  "cloudtrail",
  "config-history",
  "config-snapshot",
] as const;

export type SourceType = (typeof sourceTypes)[number];
export type SourceStatus =
  | "draft"
  | "testing"
  | "ready"
  | "backfilling"
  | "live"
  | "degraded"
  | "paused";

export type IngestionSource = {
  id: string;
  name: string;
  sourceType: SourceType;
  bucketArn: string;
  bucketName: string;
  region: string;
  objectPrefix: string;
  roleArn: string;
  externalId: string;
  kmsKeyArn: string;
  organizationId: string;
  ingestionMode: "continuous" | "backfill" | "both";
  backfillStart: string;
  includedAccounts: string[];
  excludedAccounts: string[];
  includedRegions: string[];
  configResourceTypes: string[];
  retentionDays: number;
  status: SourceStatus;
  testSummary?: ConnectionTestSummary;
  lastTestedAt?: string;
  lastSuccessfulObjectAt?: string;
  createdBy?: string;
  createdAt?: string;
  updatedAt?: string;
};

export type ConnectionCheck = {
  key: string;
  label: string;
  status: "passed" | "failed" | "warning" | "pending";
  detail: string;
};

export type ConnectionTestSummary = {
  mode: "live" | "configuration-only";
  testedAt: string;
  passed: boolean;
  checks: ConnectionCheck[];
  newestObject?: {
    key: string;
    size: number;
    lastModified: string;
  };
  detectedFormat?: string;
};

export const defaultConfigResourceTypes = [
  "AWS::EC2::SecurityGroup",
  "AWS::EC2::NetworkInterface",
  "AWS::EC2::Instance",
  "AWS::ElasticLoadBalancingV2::LoadBalancer",
  "AWS::RDS::DBInstance",
];

export function cleanText(value: unknown, maxLength: number) {
  return typeof value === "string" ? value.trim().slice(0, maxLength) : "";
}

export function cleanStringList(
  value: unknown,
  maxItems = 100,
  maxLength = 200,
) {
  const values = Array.isArray(value)
    ? value
    : typeof value === "string"
      ? value.split(/[\n,]/)
      : [];
  return [
    ...new Set(
      values
        .map((item) => cleanText(item, maxLength))
        .filter(Boolean)
        .slice(0, maxItems),
    ),
  ];
}

export function bucketNameFromArn(bucketArn: string) {
  return bucketArn.replace(/^arn:(aws|aws-us-gov|aws-cn):s3:::/, "");
}

export function normalizePrefix(value: string) {
  return value.replace(/^\/+/, "").replace(/\/{2,}/g, "/");
}

export function validateSourceInput(value: unknown) {
  const record =
    value && typeof value === "object"
      ? (value as Record<string, unknown>)
      : {};
  const sourceType = cleanText(record.sourceType, 30) as SourceType;
  const bucketArn = cleanText(record.bucketArn, 300);
  const roleArn = cleanText(record.roleArn, 300);
  const region = cleanText(record.region, 40);
  const organizationId = cleanText(record.organizationId, 30);
  const kmsKeyArn = cleanText(record.kmsKeyArn, 300);
  const ingestionMode = cleanText(record.ingestionMode, 20);
  const backfillStart = cleanText(record.backfillStart, 20);
  const externalId = cleanText(record.externalId, 128);
  const objectPrefix = normalizePrefix(cleanText(record.objectPrefix, 900));
  const retentionDays = Math.min(
    3650,
    Math.max(30, Math.trunc(Number(record.retentionDays) || 365)),
  );
  const errors: string[] = [];

  if (cleanText(record.name, 120).length < 3) {
    errors.push("Give the source a name of at least 3 characters.");
  }
  if (!sourceTypes.includes(sourceType)) {
    errors.push("Choose CloudTrail, Config history, or Config snapshot.");
  }
  if (!/^arn:(aws|aws-us-gov|aws-cn):s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(bucketArn)) {
    errors.push("Enter a valid S3 bucket ARN.");
  }
  if (!/^[a-z]{2}(-gov)?-[a-z]+-\d$/.test(region)) {
    errors.push("Enter a valid AWS region.");
  }
  if (
    !/^arn:(aws|aws-us-gov|aws-cn):iam::\d{12}:role\/[\w+=,.@/-]{1,512}$/.test(
      roleArn,
    )
  ) {
    errors.push("Enter a valid IAM role ARN.");
  }
  if (!/^[A-Za-z0-9+=,.@:/_-]{16,128}$/.test(externalId)) {
    errors.push("Use a 16–128 character external ID without whitespace or control characters.");
  }
  if (
    /[\u0000-\u001f\u007f]/.test(objectPrefix)
    || objectPrefix.includes("\\")
  ) {
    errors.push("The S3 prefix cannot contain control characters or backslashes.");
  }
  if (organizationId && !/^o-[a-z0-9]{10,32}$/.test(organizationId)) {
    errors.push("Enter a valid AWS Organizations ID or leave it blank.");
  }
  if (
    kmsKeyArn &&
    !/^arn:(aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:\d{12}:key\/[a-f0-9-]{20,}$/.test(
      kmsKeyArn,
    )
  ) {
    errors.push("Enter a valid KMS key ARN or leave it blank.");
  }
  if (!["continuous", "backfill", "both"].includes(ingestionMode)) {
    errors.push("Choose a supported ingestion mode.");
  }
  if (
    ["backfill", "both"].includes(ingestionMode) &&
    !/^\d{4}-\d{2}-\d{2}$/.test(backfillStart)
  ) {
    errors.push("Choose a backfill start date.");
  }

  return {
    errors,
    source: {
      name: cleanText(record.name, 120),
      sourceType,
      bucketArn,
      bucketName: bucketNameFromArn(bucketArn),
      region,
      objectPrefix,
      roleArn,
      externalId,
      kmsKeyArn,
      organizationId,
      ingestionMode: ingestionMode as IngestionSource["ingestionMode"],
      backfillStart,
      includedAccounts: cleanStringList(record.includedAccounts, 500, 12),
      excludedAccounts: cleanStringList(record.excludedAccounts, 500, 12),
      includedRegions: cleanStringList(record.includedRegions, 50, 40),
      configResourceTypes:
        sourceType === "cloudtrail"
          ? []
          : cleanStringList(
              record.configResourceTypes,
              100,
              160,
            ).length
            ? cleanStringList(record.configResourceTypes, 100, 160)
            : defaultConfigResourceTypes,
      retentionDays,
    },
  };
}

export function generateExternalId() {
  return `gw-${crypto.randomUUID()}`;
}

export function sourceAccessCloudFormation(source: IngestionSource) {
  const prefix = normalizePrefix(source.objectPrefix);
  const objectArn = `${source.bucketArn}/${prefix ? `${prefix}*` : "*"}`;
  const statements: Record<string, unknown>[] = [
    {
      Sid: "ListConfiguredPrefix",
      Effect: "Allow",
      Action: "s3:ListBucket",
      Resource: source.bucketArn,
      Condition: {
        StringLike: {
          "s3:prefix": prefix ? [`${prefix}*`] : ["*"],
        },
      },
    },
    {
      Sid: "ReadConfiguredLogObjects",
      Effect: "Allow",
      Action: ["s3:GetObject", "s3:GetObjectVersion"],
      Resource: objectArn,
    },
  ];
  if (source.kmsKeyArn) {
    statements.push({
      Sid: "DecryptConfiguredLogObjects",
      Effect: "Allow",
      Action: "kms:Decrypt",
      Resource: source.kmsKeyArn,
      Condition: {
        StringEquals: {
          "kms:ViaService": `s3.${source.region}.amazonaws.com`,
        },
      },
    });
  }
  const template = {
    AWSTemplateFormatVersion: "2010-09-09",
    Description: "Read-only Gatewatch access to one AWS log prefix.",
    Parameters: {
      GatewatchApplicationRoleArn: {
        Type: "String",
        Description: "IAM role used by the deployed Gatewatch ingestion service.",
        AllowedPattern:
          "^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$",
      },
      GatewatchSourceRoleName: {
        Type: "String",
        Default: "GatewatchLogReadRole",
        AllowedPattern: "^[A-Za-z0-9+=,.@_-]{1,64}$",
      },
    },
    Resources: {
      GatewatchLogReadRole: {
        Type: "AWS::IAM::Role",
        Properties: {
          RoleName: { Ref: "GatewatchSourceRoleName" },
          AssumeRolePolicyDocument: {
            Version: "2012-10-17",
            Statement: [
              {
                Effect: "Allow",
                Principal: {
                  AWS: { Ref: "GatewatchApplicationRoleArn" },
                },
                Action: "sts:AssumeRole",
                Condition: {
                  StringEquals: {
                    "sts:ExternalId": source.externalId,
                  },
                },
              },
            ],
          },
          Policies: [
            {
              PolicyName: "ReadGatewatchLogPrefix",
              PolicyDocument: {
                Version: "2012-10-17",
                Statement: statements,
              },
            },
          ],
        },
      },
    },
    Outputs: {
      RoleArn: {
        Value: { "Fn::GetAtt": ["GatewatchLogReadRole", "Arn"] },
      },
    },
  };
  return `${JSON.stringify(template, null, 2)}\n`;
}
