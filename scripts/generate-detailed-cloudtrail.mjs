import { createHash } from "node:crypto";
import { once } from "node:events";
import {
  createReadStream,
  createWriteStream,
  mkdirSync,
  statSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { pipeline } from "node:stream/promises";
import { createGzip } from "node:zlib";

const recordCount = 10_000;
const outputPath = resolve(
  process.argv[2] ??
    "samples/cloudtrail-security-groups-detailed-10000.json.gz",
);
const baseTime = Date.parse("2026-07-31T15:30:00.000Z");

// These IDs intentionally match security groups in the current personal AWS
// test deployment so imported events can be linked to live inventory.
const targets = [
  {
    id: "sg-0466fa0a89794dc0d",
    name: "launch-wizard-1",
    accountId: "171058045575",
    region: "us-east-1",
    vpcId: "vpc-0a12bc34de56f7890",
  },
  {
    id: "sg-a32127da",
    name: "default",
    accountId: "171058045575",
    region: "us-east-1",
    vpcId: "vpc-0a12bc34de56f7890",
  },
  {
    id: "sg-3126d655",
    name: "rdp",
    accountId: "171058045575",
    region: "us-west-2",
    vpcId: "vpc-0b23cd45ef67a8901",
  },
  {
    id: "sg-e6b9d19c",
    name: "aws-test",
    accountId: "171058045575",
    region: "us-west-2",
    vpcId: "vpc-0b23cd45ef67a8901",
  },
  {
    id: "sg-0377cc6c3353a1686",
    name: "northscope-beta-database",
    accountId: "171058045575",
    region: "us-east-1",
    vpcId: "vpc-0c34de56fa78b9012",
  },
  {
    id: "sg-0c70cfb866b143ac8",
    name: "gatewatch-personal-web",
    accountId: "171058045575",
    region: "us-east-1",
    vpcId: "vpc-0d45ef67ab89c0123",
  },
];

const actors = [
  {
    channel: "Terraform",
    userAgent: "APN/1.0 HashiCorp/1.0 Terraform/1.9.8 (+https://www.terraform.io) aws-sdk-go-v2/1.30.4",
    identity(accountId, index) {
      return {
        type: "AssumedRole",
        principalId: `AROASYNTHETIC0001:terraform-run-${index % 40}`,
        arn: `arn:aws:sts::${accountId}:assumed-role/terraform-ci/terraform-run-${index % 40}`,
        accountId,
        sessionContext: {
          sessionIssuer: {
            type: "Role",
            principalId: "AROASYNTHETIC0001",
            arn: `arn:aws:iam::${accountId}:role/terraform-ci`,
            accountId,
            userName: "terraform-ci",
          },
          attributes: {
            creationDate: "2026-07-31T14:45:00Z",
            mfaAuthenticated: "false",
          },
          sourceIdentity: "pipeline/network-policy",
        },
      };
    },
  },
  {
    channel: "AWS Console",
    userAgent: "Mozilla/5.0 AWS Console ec2.amazonaws.com",
    identity(accountId) {
      return {
        type: "AssumedRole",
        principalId: "AROASYNTHETIC0002:jayson@example.test",
        arn: `arn:aws:sts::${accountId}:assumed-role/AWSReservedSSO_CloudAdministrator/jayson@example.test`,
        accountId,
        sessionContext: {
          sessionIssuer: {
            type: "Role",
            principalId: "AROASYNTHETIC0002",
            arn: `arn:aws:iam::${accountId}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_CloudAdministrator`,
            accountId,
            userName: "AWSReservedSSO_CloudAdministrator",
          },
          attributes: {
            creationDate: "2026-07-31T15:00:00Z",
            mfaAuthenticated: "true",
          },
          sourceIdentity: "jayson@example.test",
        },
      };
    },
  },
  {
    channel: "AWS CLI",
    userAgent: "aws-cli/2.27.49 md/awscrt#0.27.5 ua/2.1 os/macos#24.5.0",
    identity(accountId) {
      return {
        type: "IAMUser",
        principalId: "AIDASYNTHETIC0003",
        arn: `arn:aws:iam::${accountId}:user/security-engineer`,
        accountId,
        userName: "security-engineer",
      };
    },
  },
  {
    channel: "CloudFormation",
    userAgent: "cloudformation.amazonaws.com",
    identity(accountId) {
      return {
        type: "AWSService",
        invokedBy: "cloudformation.amazonaws.com",
        principalId: "cloudformation.amazonaws.com",
        accountId,
      };
    },
  },
  {
    channel: "Federated automation",
    userAgent: "Boto3/1.40.0 md/Botocore#1.40.0 ua/2.1 os/linux",
    identity(accountId) {
      return {
        type: "FederatedUser",
        principalId: "171058045575:incident-response@example.test",
        arn: `arn:aws:sts::${accountId}:federated-user/incident-response@example.test`,
        accountId,
        sessionContext: {
          attributes: {
            creationDate: "2026-07-31T15:10:00Z",
            mfaAuthenticated: "true",
          },
        },
      };
    },
  },
];

function uuid(index, prefix = "00000000") {
  return `${prefix}-0000-4000-8000-${String(index).padStart(12, "0")}`;
}

function permission({ protocol, fromPort, toPort, ipv4, ipv6, groupId, prefixListId, description }) {
  return {
    ipProtocol: protocol,
    ...(fromPort === undefined ? {} : { fromPort }),
    ...(toPort === undefined ? {} : { toPort }),
    ...(ipv4
      ? { ipRanges: { items: [{ cidrIp: ipv4, description }] } }
      : {}),
    ...(ipv6
      ? { ipv6Ranges: { items: [{ cidrIpv6: ipv6, description }] } }
      : {}),
    ...(groupId
      ? {
          groups: {
            items: [
              {
                groupId,
                userId: "171058045575",
                description,
              },
            ],
          },
        }
      : {}),
    ...(prefixListId
      ? {
          prefixListIds: {
            items: [{ prefixListId, description }],
          },
        }
      : {}),
  };
}

function eventDefinition(index, target) {
  const cycle = index % 14;
  const iteration = Math.floor(index / 14);
  const common = { groupId: target.id };
  if (cycle === 0) {
    return {
      eventName: "AuthorizeSecurityGroupIngress",
      requestParameters: {
        ...common,
        ipPermissions: {
          items: [permission({ protocol: "tcp", fromPort: 22, toPort: 22, ipv4: "0.0.0.0/0", description: "Temporary vendor SSH" })],
        },
      },
      responseRules: [{ direction: "ingress", protocol: "tcp", fromPort: 22, toPort: 22, cidrIpv4: "0.0.0.0/0" }],
    };
  }
  if (cycle === 1) {
    return {
      eventName: "AuthorizeSecurityGroupIngress",
      requestParameters: {
        ...common,
        ipPermissions: {
          items: [permission({ protocol: "tcp", fromPort: 443, toPort: 443, ipv6: "::/0", description: "Public HTTPS IPv6" })],
        },
      },
      responseRules: [{ direction: "ingress", protocol: "tcp", fromPort: 443, toPort: 443, cidrIpv6: "::/0" }],
    };
  }
  if (cycle === 2) {
    return {
      eventName: "AuthorizeSecurityGroupIngress",
      requestParameters: {
        ...common,
        ipPermissions: {
          items: [
            permission({ protocol: "tcp", fromPort: 8443, toPort: 8443, ipv4: "10.42.0.0/16", description: "Private application tier" }),
            permission({ protocol: "tcp", fromPort: 5432, toPort: 5432, groupId: targets[(index + 1) % targets.length].id, description: "Database clients" }),
            permission({ protocol: "tcp", fromPort: 443, toPort: 443, prefixListId: "pl-63a5400a", description: "AWS service prefix" }),
          ],
        },
      },
      responseRules: [{ direction: "ingress", protocol: "tcp", fromPort: 8443, toPort: 8443, cidrIpv4: "10.42.0.0/16" }],
    };
  }
  if (cycle === 3) {
    return {
      eventName: "AuthorizeSecurityGroupEgress",
      requestParameters: {
        ...common,
        ipPermissions: { items: [permission({ protocol: "-1", ipv4: "0.0.0.0/0", description: "Unrestricted internet egress" })] },
      },
      responseRules: [{ direction: "egress", protocol: "-1", cidrIpv4: "0.0.0.0/0" }],
    };
  }
  if (cycle === 4 || cycle === 5) {
    const ingress = cycle === 4;
    return {
      eventName: ingress ? "RevokeSecurityGroupIngress" : "RevokeSecurityGroupEgress",
      requestParameters: {
        ...common,
        ipPermissions: {
          items: [permission({ protocol: "tcp", fromPort: ingress ? 3389 : 0, toPort: ingress ? 3389 : 65535, ...(ingress ? { ipv4: "0.0.0.0/0" } : { ipv6: "::/0" }), description: "Exposure removed" })],
        },
      },
      responseRules: [],
    };
  }
  if (cycle === 6 || cycle === 7) {
    const broadens = cycle === 6;
    return {
      eventName: "ModifySecurityGroupRules",
      requestParameters: {
        ...common,
        securityGroupRuleSet: {
          items: [
            {
              securityGroupRuleId: `sgr-${String(index).padStart(17, "0")}`,
              securityGroupRule: {
                ipProtocol: "tcp",
                fromPort: broadens ? 5432 : 443,
                toPort: broadens ? 5432 : 443,
                cidrIpv4: broadens ? "0.0.0.0/0" : "198.51.100.0/24",
                description: broadens ? "Emergency database access" : "Approved corporate proxy",
              },
            },
          ],
        },
      },
      responseRules: [],
    };
  }
  if (cycle === 8 || cycle === 9) {
    const ingress = cycle === 8;
    return {
      eventName: ingress ? "UpdateSecurityGroupRuleDescriptionsIngress" : "UpdateSecurityGroupRuleDescriptionsEgress",
      requestParameters: {
        ...common,
        ipPermissions: {
          items: [permission({ protocol: "tcp", fromPort: 443, toPort: 443, ipv4: ingress ? "198.51.100.0/24" : "10.0.0.0/8", description: `CHG-${String(iteration).padStart(6, "0")} approved access` })],
        },
      },
      responseRules: [],
    };
  }
  if (cycle === 10) {
    return {
      eventName: "CreateSecurityGroup",
      requestParameters: {
        groupName: `sample-application-${iteration}`,
        groupDescription: "Synthetic Gatewatch detailed CloudTrail test group",
        vpcId: target.vpcId,
        tagSpecificationSet: {
          items: [{ resourceType: "security-group", tags: [{ key: "Owner", value: "Platform Security" }, { key: "Environment", value: "Test" }] }],
        },
      },
      responseRules: [],
    };
  }
  if (cycle === 11) {
    return {
      eventName: "DeleteSecurityGroup",
      requestParameters: common,
      responseRules: [],
    };
  }
  if (cycle === 12) {
    return {
      eventName: "DescribeSecurityGroups",
      requestParameters: { groupIdSet: { items: [{ groupId: target.id }] } },
      responseRules: [],
      readOnly: true,
    };
  }
  return {
    eventName: "RunInstances",
    requestParameters: {
      instancesSet: { items: [{ imageId: "ami-0123456789abcdef0", minCount: 1, maxCount: 1 }] },
      networkInterfaceSet: { items: [{ deviceIndex: 0, groupSet: { items: [{ groupId: target.id }] } }] },
    },
    responseRules: [],
  };
}

function createRecord(index) {
  const target = targets[index % targets.length];
  const actor = actors[index % actors.length];
  const definition = eventDefinition(index, target);
  const failed = index > 0 && index % 113 === 0;
  const duplicate = index > 0 && index % 997 === 0;
  const eventId = duplicate ? uuid(index - 1) : uuid(index);
  const eventTime = new Date(baseTime - index * 2_000).toISOString();
  const responseRules = definition.responseRules.map((rule, ruleIndex) => ({
    groupId: target.id,
    securityGroupRuleId: `sgr-${String(index * 10 + ruleIndex).padStart(17, "0")}`,
    groupOwnerId: target.accountId,
    isEgress: rule.direction === "egress",
    ipProtocol: rule.protocol,
    fromPort: rule.fromPort,
    toPort: rule.toPort,
    cidrIpv4: rule.cidrIpv4,
    cidrIpv6: rule.cidrIpv6,
  }));
  return {
    eventVersion: "1.11",
    userIdentity: actor.identity(target.accountId, index),
    eventTime,
    eventSource: "ec2.amazonaws.com",
    eventName: definition.eventName,
    awsRegion: target.region,
    sourceIPAddress:
      actor.channel === "CloudFormation"
        ? "cloudformation.amazonaws.com"
        : `198.51.100.${(index % 240) + 1}`,
    userAgent: actor.userAgent,
    requestParameters: {
      ...definition.requestParameters,
      ...(failed && index % 2 === 0 ? { dryRun: true } : {}),
    },
    responseElements: failed
      ? null
      : definition.eventName === "CreateSecurityGroup"
        ? { requestId: uuid(index, "22222222"), groupId: target.id, tagSet: {} }
        : {
            requestId: uuid(index, "22222222"),
            return: true,
            ...(responseRules.length
              ? { securityGroupRuleSet: { items: responseRules } }
              : {}),
          },
    requestID: uuid(index, "11111111"),
    eventID: eventId,
    readOnly: Boolean(definition.readOnly),
    eventType: "AwsApiCall",
    apiVersion: "2016-11-15",
    managementEvent: true,
    recipientAccountId: target.accountId,
    sharedEventID: index % 211 === 0 ? uuid(index, "33333333") : undefined,
    vpcEndpointId: index % 7 === 0 ? "vpce-0123456789abcdef0" : undefined,
    eventCategory: "Management",
    tlsDetails: {
      tlsVersion: "TLSv1.3",
      cipherSuite: "TLS_AES_128_GCM_SHA256",
      clientProvidedHostHeader: `ec2.${target.region}.amazonaws.com`,
    },
    resources: [
      {
        accountId: target.accountId,
        type: "AWS::EC2::SecurityGroup",
        ARN: `arn:aws:ec2:${target.region}:${target.accountId}:security-group/${target.id}`,
      },
    ],
    additionalEventData: {
      channel: actor.channel,
      syntheticScenario: `security-group-${index % 14}`,
    },
    ...(failed
      ? {
          errorCode:
            index % 2 === 0
              ? "Client.UnauthorizedOperation"
              : "InvalidGroup.NotFound",
          errorMessage:
            index % 2 === 0
              ? "Synthetic access denial for negative-path testing."
              : "The synthetic security group was not found.",
        }
      : {}),
  };
}

mkdirSync(dirname(outputPath), { recursive: true });
const gzip = createGzip({ level: 9 });
const output = createWriteStream(outputPath, { flags: "w", mode: 0o600 });
const completion = pipeline(gzip, output);
let uncompressedBytes = 0;
let supportedEvents = 0;
let failedEvents = 0;
let duplicateEventIds = 0;

function write(value) {
  uncompressedBytes += Buffer.byteLength(value);
  return gzip.write(value);
}

write('{"Records":[');
for (let index = 0; index < recordCount; index += 1) {
  const record = createRecord(index);
  if (!record.readOnly && record.eventName !== "RunInstances") supportedEvents += 1;
  if (record.errorCode) failedEvents += 1;
  if (index > 0 && index % 997 === 0) duplicateEventIds += 1;
  const chunk = `${index === 0 ? "" : ","}${JSON.stringify(record)}`;
  if (!write(chunk)) await once(gzip, "drain");
}
write("]}");
gzip.end();
await completion;

const hash = createHash("sha256");
for await (const chunk of createReadStream(outputPath)) hash.update(chunk);
console.log(
  JSON.stringify(
    {
      output: outputPath,
      records: recordCount,
      supportedSecurityGroupEvents: supportedEvents,
      unrelatedEvents: recordCount - supportedEvents,
      failedEvents,
      duplicateEventIds,
      uncompressedBytes,
      compressedBytes: statSync(outputPath).size,
      sha256: hash.digest("hex"),
    },
    null,
    2,
  ),
);
