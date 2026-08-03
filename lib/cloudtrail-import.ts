export const MAX_CLOUDTRAIL_FILE_BYTES = 25 * 1024 * 1024;
const MAX_DECOMPRESSED_BYTES = 50 * 1024 * 1024;
const MAX_RECORDS = 50_000;

const SECURITY_GROUP_EVENTS = new Set([
  "AuthorizeSecurityGroupIngress",
  "AuthorizeSecurityGroupEgress",
  "RevokeSecurityGroupIngress",
  "RevokeSecurityGroupEgress",
  "ModifySecurityGroupRules",
  "CreateSecurityGroup",
  "DeleteSecurityGroup",
  "UpdateSecurityGroupRuleDescriptionsIngress",
  "UpdateSecurityGroupRuleDescriptionsEgress",
]);

export type ImportedCloudTrailEvent = {
  id: string;
  eventName: string;
  eventTime: string;
  region: string;
  accountId: string;
  actor: string;
  actorType: string;
  sourceIp: string;
  userAgent: string;
  groupIds: string[];
  cidrs: string[];
  protocol: string;
  ports: string;
  effect: "Broadens access" | "Restricts access" | "Changes access" | "Lifecycle";
  internetWide: boolean;
  direction: "Ingress" | "Egress" | "Unknown";
  errorCode: string;
  requestId: string;
};

export type CloudTrailImportResult = {
  events: ImportedCloudTrailEvent[];
  totalRecords: number;
  skippedRecords: number;
  internetWideChanges: number;
  warnings: string[];
};

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function cleanString(value: unknown, maxLength = 500) {
  return typeof value === "string" ? value.slice(0, maxLength) : "";
}

function visitObject(
  value: unknown,
  visitor: (key: string, value: unknown) => void,
  depth = 0,
) {
  if (depth > 9 || value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 10_000)) {
      visitObject(item, visitor, depth + 1);
    }
    return;
  }
  for (const [key, child] of Object.entries(value as JsonObject)) {
    visitor(key, child);
    visitObject(child, visitor, depth + 1);
  }
}

function extractRequestDetails(requestParameters: unknown) {
  const groupIds = new Set<string>();
  const cidrs = new Set<string>();
  let fromPort: number | null = null;
  let toPort: number | null = null;
  let protocol = "";

  visitObject(requestParameters, (key, value) => {
    const stringValue = cleanString(value, 300);
    if (
      ["groupId", "groupID", "securityGroupId"].includes(key) &&
      /^sg-[a-zA-Z0-9-]+$/.test(stringValue)
    ) {
      groupIds.add(stringValue);
    }
    if (
      [
        "cidrIp",
        "cidrIpv4",
        "cidrIpv6",
        "cidrIPv4",
        "cidrIPv6",
        "cidr",
        "ipRange",
      ].includes(key) &&
      (stringValue.includes("/") ||
        stringValue === "0.0.0.0/0" ||
        stringValue === "::/0")
    ) {
      cidrs.add(stringValue);
    }
    if (key === "fromPort" && typeof value === "number") fromPort = value;
    if (key === "toPort" && typeof value === "number") toPort = value;
    if (
      ["ipProtocol", "protocol"].includes(key) &&
      (typeof value === "string" || typeof value === "number")
    ) {
      protocol = String(value).slice(0, 30);
    }
  });

  const ports =
    fromPort === null
      ? ""
      : toPort === null || fromPort === toPort
        ? String(fromPort)
        : `${fromPort}–${toPort}`;
  return {
    groupIds: [...groupIds],
    cidrs: [...cidrs],
    protocol,
    ports,
  };
}

function actorFrom(record: JsonObject) {
  const identity = isObject(record.userIdentity) ? record.userIdentity : {};
  const sessionContext = isObject(identity.sessionContext)
    ? identity.sessionContext
    : {};
  const issuer = isObject(sessionContext.sessionIssuer)
    ? sessionContext.sessionIssuer
    : {};
  return {
    actor:
      cleanString(identity.arn, 500) ||
      cleanString(issuer.arn, 500) ||
      cleanString(identity.principalId, 300) ||
      "Unknown principal",
    actorType: cleanString(identity.type, 100) || "Unknown",
    accountId:
      cleanString(identity.accountId, 20) ||
      cleanString(record.recipientAccountId, 20),
  };
}

function normalizeRecord(record: unknown, index: number) {
  if (!isObject(record)) return null;
  const eventName = cleanString(record.eventName, 120);
  if (!SECURITY_GROUP_EVENTS.has(eventName)) return null;

  const requestDetails = extractRequestDetails(record.requestParameters);
  const identity = actorFrom(record);
  const direction = eventName.includes("Ingress")
    ? "Ingress"
    : eventName.includes("Egress")
      ? "Egress"
      : "Unknown";
  const internetWide = requestDetails.cidrs.some(
    (cidr) => cidr === "0.0.0.0/0" || cidr === "::/0",
  );
  const effect = eventName.startsWith("Authorize")
    ? "Broadens access"
    : eventName.startsWith("Revoke")
      ? "Restricts access"
      : eventName === "ModifySecurityGroupRules"
        ? "Changes access"
        : "Lifecycle";

  return {
    id:
      cleanString(record.eventID, 160) ||
      cleanString(record.requestID, 160) ||
      `imported-${index}`,
    eventName,
    eventTime: cleanString(record.eventTime, 50),
    region: cleanString(record.awsRegion, 40),
    accountId: identity.accountId,
    actor: identity.actor,
    actorType: identity.actorType,
    sourceIp: cleanString(record.sourceIPAddress, 200),
    userAgent: cleanString(record.userAgent, 300),
    groupIds: requestDetails.groupIds,
    cidrs: requestDetails.cidrs,
    protocol: requestDetails.protocol,
    ports: requestDetails.ports,
    effect,
    internetWide,
    direction,
    errorCode: cleanString(record.errorCode, 160),
    requestId: cleanString(record.requestID, 160),
  } satisfies ImportedCloudTrailEvent;
}

export function parseCloudTrailText(text: string): CloudTrailImportResult {
  if (!text.trim()) throw new Error("The selected file is empty.");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new Error(
      "The file is not valid JSON. Select a CloudTrail JSON or JSON.GZ log.",
    );
  }

  const records = Array.isArray(parsed)
    ? parsed
    : isObject(parsed) && Array.isArray(parsed.Records)
      ? parsed.Records
      : isObject(parsed) && typeof parsed.eventName === "string"
        ? [parsed]
        : null;
  if (!records) {
    throw new Error(
      'CloudTrail logs must contain a top-level "Records" array, an event array, or one CloudTrail event.',
    );
  }
  if (records.length > MAX_RECORDS) {
    throw new Error(
      `This file contains ${records.length.toLocaleString()} records. Import at most ${MAX_RECORDS.toLocaleString()} records at a time.`,
    );
  }

  const events = records
    .map((record, index) => normalizeRecord(record, index))
    .filter((event): event is ImportedCloudTrailEvent => event !== null)
    .sort((a, b) => b.eventTime.localeCompare(a.eventTime));
  const warnings: string[] = [];
  if (!events.length) {
    warnings.push(
      "No supported EC2 security-group management events were found.",
    );
  }
  if (events.some((event) => !event.groupIds.length)) {
    warnings.push(
      "Some events do not contain a security-group ID and cannot be correlated automatically.",
    );
  }
  if (events.some((event) => event.errorCode)) {
    warnings.push(
      "Failed AWS API calls are included and labeled; they did not necessarily change access.",
    );
  }

  return {
    events,
    totalRecords: records.length,
    skippedRecords: records.length - events.length,
    internetWideChanges: events.filter(
      (event) =>
        event.internetWide &&
        ["Broadens access", "Changes access"].includes(event.effect) &&
        !event.errorCode,
    ).length,
    warnings,
  };
}

async function readGzipFile(file: File) {
  if (typeof DecompressionStream === "undefined") {
    throw new Error(
      "Compressed CloudTrail logs are not supported by this browser. Decompress the file and import the JSON.",
    );
  }
  const reader = file
    .stream()
    .pipeThrough(new DecompressionStream("gzip"))
    .getReader();
  const decoder = new TextDecoder();
  let totalBytes = 0;
  let text = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    totalBytes += value.byteLength;
    if (totalBytes > MAX_DECOMPRESSED_BYTES) {
      await reader.cancel();
      throw new Error(
        "The decompressed log is larger than 50 MB. Split it into smaller files before importing.",
      );
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}

export async function readCloudTrailFile(file: File) {
  if (file.size === 0) throw new Error("The selected file is empty.");
  if (file.size > MAX_CLOUDTRAIL_FILE_BYTES) {
    throw new Error(
      "The selected file is larger than 25 MB. Split large CloudTrail exports before importing.",
    );
  }
  const filename = file.name.toLowerCase();
  if (!filename.endsWith(".json") && !filename.endsWith(".json.gz")) {
    throw new Error("Choose a .json or .json.gz CloudTrail log.");
  }
  return filename.endsWith(".gz") ? readGzipFile(file) : file.text();
}
