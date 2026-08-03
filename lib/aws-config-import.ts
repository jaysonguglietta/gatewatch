export type ConfigSecurityGroupRule = {
  direction: "Ingress" | "Egress";
  protocol: string;
  fromPort: number | null;
  toPort: number | null;
  peer: string;
  peerType: "IPv4" | "IPv6" | "Security group" | "Prefix list";
  description: string;
  internetWide: boolean;
};

export type NormalizedConfigItem = {
  id: string;
  accountId: string;
  region: string;
  resourceType: string;
  resourceId: string;
  resourceArn: string;
  configurationStateId: string;
  captureTime: string;
  status: string;
  groupName: string;
  vpcId: string;
  rules: ConfigSecurityGroupRule[];
  relationships: Array<{ resourceType: string; resourceId: string; name: string }>;
};

type JsonObject = Record<string, unknown>;

function object(value: unknown): JsonObject {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonObject)
    : {};
}

function text(value: unknown, limit = 500) {
  return typeof value === "string" ? value.slice(0, limit) : "";
}

function numberOrNull(value: unknown) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function parseConfiguration(value: unknown) {
  if (typeof value !== "string") return object(value);
  try {
    return object(JSON.parse(value));
  } catch {
    return {};
  }
}

function ranges(
  permission: JsonObject,
  direction: ConfigSecurityGroupRule["direction"],
) {
  const protocol = text(
    permission.ipProtocol ?? permission.IpProtocol ?? permission.protocol,
    20,
  );
  const fromPort = numberOrNull(permission.fromPort ?? permission.FromPort);
  const toPort = numberOrNull(permission.toPort ?? permission.ToPort);
  const candidates: Array<{
    values: unknown;
    peerType: ConfigSecurityGroupRule["peerType"];
    keys: string[];
  }> = [
    {
      values: permission.ipRanges ?? permission.IpRanges,
      peerType: "IPv4",
      keys: ["cidrIp", "CidrIp"],
    },
    {
      values: permission.ipv6Ranges ?? permission.Ipv6Ranges,
      peerType: "IPv6",
      keys: ["cidrIpv6", "CidrIpv6"],
    },
    {
      values: permission.userIdGroupPairs ?? permission.UserIdGroupPairs,
      peerType: "Security group",
      keys: ["groupId", "GroupId"],
    },
    {
      values: permission.prefixListIds ?? permission.PrefixListIds,
      peerType: "Prefix list",
      keys: ["prefixListId", "PrefixListId"],
    },
  ];
  return candidates.flatMap(({ values, peerType, keys }) =>
    (Array.isArray(values) ? values : []).flatMap((raw) => {
      const item = object(raw);
      const peer = keys.map((key) => text(item[key], 160)).find(Boolean) ?? "";
      if (!peer) return [];
      return [{
        direction,
        protocol: protocol === "-1" ? "All" : protocol || "All",
        fromPort,
        toPort,
        peer,
        peerType,
        description: text(item.description ?? item.Description, 500),
        internetWide: peer === "0.0.0.0/0" || peer === "::/0",
      }];
    }),
  );
}

function normalizeItem(raw: unknown, index: number): NormalizedConfigItem | null {
  const item = object(raw);
  const resourceType = text(item.resourceType, 160);
  if (!resourceType) return null;
  const configuration = parseConfiguration(item.configuration);
  const ingress = configuration.ipPermissions ?? configuration.IpPermissions;
  const egress =
    configuration.ipPermissionsEgress ?? configuration.IpPermissionsEgress;
  const resourceId = text(item.resourceId, 160);
  const captureTime = text(
    item.configurationItemCaptureTime ?? item.captureTime,
    60,
  );
  const relationships = (Array.isArray(item.relationships)
    ? item.relationships
    : []
  ).map((rawRelationship) => {
    const relationship = object(rawRelationship);
    return {
      resourceType: text(relationship.resourceType, 160),
      resourceId: text(relationship.resourceId, 300),
      name: text(relationship.name, 160),
    };
  });
  return {
    id:
      text(item.configurationStateId, 160) ||
      `${text(item.awsAccountId, 20)}:${text(item.awsRegion, 40)}:${resourceId}:${captureTime || index}`,
    accountId: text(item.awsAccountId ?? item.accountId, 20),
    region: text(item.awsRegion ?? item.region, 40),
    resourceType,
    resourceId,
    resourceArn: text(item.ARN ?? item.arn, 600),
    configurationStateId: text(item.configurationStateId, 160),
    captureTime,
    status: text(item.configurationItemStatus, 80) || "OK",
    groupName: text(configuration.groupName ?? configuration.GroupName, 300),
    vpcId: text(configuration.vpcId ?? configuration.VpcId, 160),
    rules: [
      ...(Array.isArray(ingress) ? ingress : []).flatMap((permission) =>
        ranges(object(permission), "Ingress"),
      ),
      ...(Array.isArray(egress) ? egress : []).flatMap((permission) =>
        ranges(object(permission), "Egress"),
      ),
    ],
    relationships,
  };
}

export function parseAwsConfigText(value: string) {
  if (!value.trim()) throw new Error("The AWS Config file is empty.");
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error("The AWS Config file is not valid JSON.");
  }
  const root = object(parsed);
  const items = Array.isArray(parsed)
    ? parsed
    : Array.isArray(root.configurationItems)
      ? root.configurationItems
      : Array.isArray(root.ConfigSnapshot)
        ? root.ConfigSnapshot
        : root.resourceType
          ? [root]
          : [];
  if (!items.length) {
    throw new Error("No AWS Config configuration items were found.");
  }
  const normalized = items
    .map(normalizeItem)
    .filter((item): item is NormalizedConfigItem => item !== null)
    .sort((a, b) => b.captureTime.localeCompare(a.captureTime));
  return {
    items: normalized,
    totalItems: items.length,
    securityGroups: normalized.filter(
      (item) => item.resourceType === "AWS::EC2::SecurityGroup",
    ),
    internetWideRules: normalized.flatMap((item) =>
      item.rules
        .filter((rule) => rule.internetWide)
        .map((rule) => ({ resourceId: item.resourceId, rule })),
    ),
  };
}

export function correlateConfigAndCloudTrail(
  configItems: NormalizedConfigItem[],
  events: Array<{
    id: string;
    eventTime: string;
    accountId: string;
    region: string;
    groupIds: string[];
    errorCode: string;
  }>,
  windowMinutes = 30,
) {
  const windowMs = windowMinutes * 60_000;
  return configItems.map((item) => {
    const capture = Date.parse(item.captureTime);
    const matches = events
      .filter(
        (event) =>
          !event.errorCode &&
          event.accountId === item.accountId &&
          event.region === item.region &&
          event.groupIds.includes(item.resourceId) &&
          Number.isFinite(capture) &&
          Math.abs(capture - Date.parse(event.eventTime)) <= windowMs,
      )
      .sort((a, b) => b.eventTime.localeCompare(a.eventTime));
    return {
      configItem: item,
      cloudTrailEvent: matches[0] ?? null,
      correlationStatus: matches.length ? "confirmed" : "unattributed",
    };
  });
}
