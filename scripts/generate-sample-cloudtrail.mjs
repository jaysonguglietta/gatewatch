import { once } from "node:events";
import {
  createReadStream,
  createWriteStream,
  mkdirSync,
  statSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { pipeline } from "node:stream/promises";
import { createGzip } from "node:zlib";

const recordCount = 50_000;
const outputPath = resolve(
  process.argv[2] ?? "samples/cloudtrail-security-groups-50000.json.gz",
);
const groupIds = [
  "sg-0a41f2e91b71",
  "sg-04bc18a21e7d",
  "sg-08ee42b1ca70",
  "sg-0e42f90b3c61",
  "sg-0d3c99118aae",
  "sg-0611a2fb089c",
];
const accounts = [
  "428196730552",
  "718345229104",
  "100293744720",
];
const regions = ["us-east-1", "us-west-2", "eu-west-1"];
const roles = [
  "terraform-ci",
  "cloud-operations",
  "security-automation",
  "developer-platform",
];
const baseTime = Date.parse("2026-07-30T16:00:00.000Z");

function uuid(index, prefix = "00000000") {
  return `${prefix}-0000-4000-8000-${String(index).padStart(12, "0")}`;
}

function eventDefinition(index, groupId) {
  const cycle = index % 10;
  const iteration = Math.floor(index / 10);
  if (cycle === 0) {
    return {
      eventName: "AuthorizeSecurityGroupIngress",
      requestParameters: {
        groupId,
        ipPermissions: {
          items: [
            {
              ipProtocol: "tcp",
              fromPort: 22,
              toPort: 22,
              ipRanges: { items: [{ cidrIp: "0.0.0.0/0" }] },
            },
          ],
        },
      },
    };
  }
  if (cycle === 1) {
    return {
      eventName: "AuthorizeSecurityGroupEgress",
      requestParameters: {
        groupId,
        ipPermissions: {
          items: [
            {
              ipProtocol: "-1",
              ipRanges: { items: [{ cidrIp: "0.0.0.0/0" }] },
            },
          ],
        },
      },
    };
  }
  if (cycle === 2) {
    return {
      eventName: "RevokeSecurityGroupIngress",
      requestParameters: {
        groupId,
        ipPermissions: {
          items: [
            {
              ipProtocol: "tcp",
              fromPort: 3389,
              toPort: 3389,
              ipRanges: { items: [{ cidrIp: "10.0.0.0/8" }] },
            },
          ],
        },
      },
    };
  }
  if (cycle === 3) {
    return {
      eventName: "ModifySecurityGroupRules",
      requestParameters: {
        groupId,
        securityGroupRuleSet: {
          items: [
            {
              securityGroupRuleId: `sgr-${String(index).padStart(8, "0")}`,
              securityGroupRule: {
                ipProtocol: "tcp",
                fromPort: iteration % 2 === 0 ? 443 : 5432,
                toPort: iteration % 2 === 0 ? 443 : 5432,
                cidrIpv4:
                  iteration % 2 === 0 ? "0.0.0.0/0" : "10.20.0.0/16",
              },
            },
          ],
        },
      },
    };
  }
  if (cycle === 4) {
    return {
      eventName: "UpdateSecurityGroupRuleDescriptionsIngress",
      requestParameters: {
        groupId,
        ipPermissions: {
          items: [
            {
              ipProtocol: "tcp",
              fromPort: 443,
              toPort: 443,
              ipRanges: {
                items: [
                  {
                    cidrIp: "198.51.100.0/24",
                    description: "Approved corporate egress",
                  },
                ],
              },
            },
          ],
        },
      },
    };
  }
  if (cycle === 5) {
    return {
      eventName: "CreateSecurityGroup",
      requestParameters: {
        groupName: `sample-application-${iteration}`,
        groupDescription: "Synthetic Gatewatch CloudTrail test group",
        vpcId: "vpc-0a12bc34de56f7890",
      },
    };
  }
  if (cycle === 6) {
    return {
      eventName: "DeleteSecurityGroup",
      requestParameters: { groupId },
    };
  }
  if (cycle === 7) {
    return {
      eventName: "RevokeSecurityGroupEgress",
      requestParameters: {
        groupId,
        ipPermissions: {
          items: [
            {
              ipProtocol: "tcp",
              fromPort: 0,
              toPort: 65535,
              ipv6Ranges: { items: [{ cidrIpv6: "::/0" }] },
            },
          ],
        },
      },
    };
  }
  if (cycle === 8) {
    return {
      eventName: "DescribeSecurityGroups",
      requestParameters: {
        filterSet: { items: [{ name: "group-id", valueSet: { items: [groupId] } }] },
      },
    };
  }
  return {
    eventName: "RunInstances",
    requestParameters: {
      instancesSet: { items: [{ imageId: "ami-0123456789abcdef0", minCount: 1, maxCount: 1 }] },
    },
  };
}

function createRecord(index) {
  const groupId = groupIds[index % groupIds.length];
  const accountId = accounts[index % accounts.length];
  const region = regions[index % regions.length];
  const role = roles[index % roles.length];
  const definition = eventDefinition(index, groupId);
  const failed = index > 0 && index % 97 === 0;
  return {
    eventVersion: "1.09",
    userIdentity: {
      type: "AssumedRole",
      principalId: `AROASAMPLE:${role}`,
      arn: `arn:aws:sts::${accountId}:assumed-role/${role}/sample-session`,
      accountId,
    },
    eventTime: new Date(baseTime - index * 1000).toISOString(),
    eventSource: "ec2.amazonaws.com",
    eventName: definition.eventName,
    awsRegion: region,
    sourceIPAddress: `198.51.100.${(index % 240) + 1}`,
    userAgent:
      index % 3 === 0
        ? "APN/1.0 HashiCorp/1.0 Terraform/1.9"
        : "aws-cli/2.17.35 md/Botocore#1.34.133",
    requestParameters: definition.requestParameters,
    responseElements: failed ? null : { return: true },
    requestID: uuid(index, "11111111"),
    eventID: uuid(index),
    readOnly: ["DescribeSecurityGroups"].includes(definition.eventName),
    eventType: "AwsApiCall",
    managementEvent: true,
    recipientAccountId: accountId,
    eventCategory: "Management",
    ...(failed
      ? {
          errorCode: "Client.UnauthorizedOperation",
          errorMessage:
            "You are not authorized to perform this operation in the synthetic sample.",
        }
      : {}),
  };
}

mkdirSync(dirname(outputPath), { recursive: true });
const gzip = createGzip({ level: 9 });
const output = createWriteStream(outputPath, { flags: "w", mode: 0o600 });
const completion = pipeline(gzip, output);
let uncompressedBytes = 0;

function write(value) {
  uncompressedBytes += Buffer.byteLength(value);
  return gzip.write(value);
}

write('{"Records":[');
for (let index = 0; index < recordCount; index += 1) {
  const chunk = `${index === 0 ? "" : ","}${JSON.stringify(
    createRecord(index),
  )}`;
  if (!write(chunk)) await once(gzip, "drain");
}
write("]}");
gzip.end();
await completion;

const hash = createHash("sha256");
for await (const chunk of createReadStream(outputPath)) hash.update(chunk);
const compressedBytes = statSync(outputPath).size;

console.log(
  JSON.stringify(
    {
      output: outputPath,
      records: recordCount,
      uncompressedBytes,
      compressedBytes,
      sha256: hash.digest("hex"),
    },
    null,
    2,
  ),
);
