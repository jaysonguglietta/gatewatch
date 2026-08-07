import {
  sourceTypeDefinition,
  type EvidenceClass,
  type SourceType,
} from "./admin-sources.ts";
import {
  parseCloudTrailText,
  type CloudTrailImportResult,
} from "./cloudtrail-import.ts";
import { parseAwsConfigText } from "./aws-config-import.ts";

export const MAX_AWS_EVIDENCE_FILE_BYTES = 25 * 1024 * 1024;
const MAX_DECOMPRESSED_BYTES = 50 * 1024 * 1024;
const MAX_RECORDS = 50_000;
const DEFAULT_FLOW_FIELDS = [
  "version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport",
  "dstport", "protocol", "packets", "bytes", "start", "end", "action",
  "log-status",
];

type JsonObject = Record<string, unknown>;

export type NormalizedAwsEvidenceRecord = {
  id: string;
  observedAt: string;
  accountId: string;
  region: string;
  resource: string;
  event: string;
  disposition: string;
  source: string;
  destination: string;
  summary: string;
  raw: JsonObject;
};

export type AwsEvidenceImportResult = {
  sourceType: SourceType;
  sourceLabel: string;
  evidenceClass: EvidenceClass;
  totalRecords: number;
  skippedRecords: number;
  records: NormalizedAwsEvidenceRecord[];
  warnings: string[];
  cloudTrail?: CloudTrailImportResult;
};

function object(value: unknown): JsonObject {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as JsonObject
    : {};
}

function string(value: unknown, maxLength = 2_000) {
  if (typeof value === "string") return value.slice(0, maxLength);
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value).slice(0, maxLength);
  }
  return "";
}

function first(record: JsonObject, keys: string[], maxLength = 2_000) {
  for (const key of keys) {
    const value = string(record[key], maxLength);
    if (value) return value;
  }
  return "";
}

function jsonLines(text: string) {
  const records: JsonObject[] = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        records.push(parsed as JsonObject);
      }
    } catch {
      return null;
    }
  }
  return records.length ? records : null;
}

function jsonRecords(text: string, sourceType: SourceType) {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return jsonLines(text);
  }
  const root = object(parsed);
  if (Array.isArray(parsed)) return parsed.map(object);
  const candidates = sourceType === "security-hub"
    ? [root.Findings, root.findings]
    : sourceType === "guardduty" || sourceType === "inspector"
      ? [root.Findings, root.findings, root.detail ? [root.detail] : undefined]
      : sourceType === "reachability-analyzer"
        ? [root.NetworkInsightsAnalyses, root.NetworkInsightsPaths, root.NetworkInsightsAnalysis ? [root.NetworkInsightsAnalysis] : undefined]
        : sourceType === "network-access-analyzer"
          ? [root.NetworkInsightsAccessScopeAnalyses, root.Findings, root.NetworkInsightsAccessScopeAnalysis ? [root.NetworkInsightsAccessScopeAnalysis] : undefined]
          : [root.Records, root.records, root.logEvents, root.events];
  const found = candidates.find(Array.isArray);
  return found ? (found as unknown[]).map(object) : [root];
}

function flowLogRecords(text: string) {
  const records: JsonObject[] = [];
  let fields = DEFAULT_FLOW_FIELDS;
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#Version:")) continue;
    if (trimmed.startsWith("#Fields:")) {
      fields = trimmed.slice(8).trim().split(/\s+/);
      continue;
    }
    const values = trimmed.split(/\s+/);
    if (values.length < 8) continue;
    records.push(Object.fromEntries(values.map((value, index) => [fields[index] ?? `field-${index + 1}`, value])));
  }
  return records;
}

function cloudFrontRecords(text: string) {
  const records: JsonObject[] = [];
  let fields: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.startsWith("#Version:")) continue;
    if (line.startsWith("#Fields:")) {
      fields = line.slice(8).trim().split(/\s+/);
      continue;
    }
    const values = line.split("\t");
    if (!fields.length || values.length < 2) continue;
    records.push(Object.fromEntries(values.map((value, index) => [fields[index] ?? `field-${index + 1}`, value])));
  }
  return records;
}

function accessLogRecords(text: string) {
  return text.split(/\r?\n/).flatMap((line, index) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) return [];
    const values = trimmed.match(/(?:[^\s"]+|"[^"]*")+/g) ?? [];
    if (values.length < 3) return [];
    const networkLoadBalancer = /^\d+\.\d+$/.test(values[1] ?? "");
    return [{
      "record-number": index + 1,
      type: values[0],
      timestamp: values[networkLoadBalancer ? 2 : 1],
      resource: values[networkLoadBalancer ? 3 : 2],
      client: values[networkLoadBalancer ? 5 : 3] ?? "",
      target: values[networkLoadBalancer ? 6 : 4] ?? "",
      status: values[8] ?? values[7] ?? "",
      raw: trimmed.slice(0, 16_000),
    }];
  });
}

function sourceRecords(text: string, sourceType: SourceType) {
  if (sourceType === "vpc-flow-logs" || sourceType === "transit-gateway-flow-logs") {
    return jsonRecords(text, sourceType) ?? flowLogRecords(text);
  }
  if (sourceType === "cloudfront") {
    return jsonRecords(text, sourceType) ?? cloudFrontRecords(text);
  }
  if (sourceType === "elastic-load-balancing" || sourceType === "api-gateway") {
    return jsonRecords(text, sourceType) ?? accessLogRecords(text);
  }
  return jsonRecords(text, sourceType) ?? [];
}

function hasAny(record: JsonObject, keys: string[]) {
  return keys.some((key) => record[key] !== undefined && record[key] !== null && record[key] !== "");
}

function isAwsSourceRecord(record: JsonObject, sourceType: SourceType) {
  if (sourceType === "vpc-flow-logs") {
    return hasAny(record, ["interface-id", "interfaceId"]) && hasAny(record, ["srcaddr", "sourceAddress"]) && hasAny(record, ["dstaddr", "destinationAddress"]);
  }
  if (sourceType === "transit-gateway-flow-logs") {
    return hasAny(record, ["tgw-id", "tgw-attachment-id", "transitGatewayId"]) && hasAny(record, ["srcaddr", "sourceAddress"]);
  }
  if (sourceType === "reachability-analyzer") {
    return hasAny(record, ["NetworkInsightsAnalysisId", "NetworkInsightsPathId", "NetworkPathFound", "Explanations"]);
  }
  if (sourceType === "network-access-analyzer") {
    return hasAny(record, ["NetworkInsightsAccessScopeAnalysisId", "NetworkInsightsAccessScopeId", "NetworkInsightsAccessScopeArn", "Findings"]);
  }
  if (sourceType === "elastic-load-balancing") {
    return hasAny(record, ["client", "clientIp"]) && hasAny(record, ["resource", "elb", "loadBalancerArn"]);
  }
  if (sourceType === "waf") {
    return hasAny(record, ["webaclId", "terminatingRuleId", "httpRequest"]);
  }
  if (sourceType === "cloudfront") {
    return (hasAny(record, ["date", "timestamp"]) && hasAny(record, ["c-ip", "clientIp", "cs-method", "uri"]));
  }
  if (sourceType === "api-gateway") {
    return hasAny(record, ["requestId", "routeKey", "resourcePath", "httpMethod"]) && hasAny(record, ["status", "statusCode", "responseStatus", "protocol"]);
  }
  if (sourceType === "route53-resolver") {
    return hasAny(record, ["query_name", "query_type", "query_type_id"]) && hasAny(record, ["srcids", "vpc_id", "instance_id"]);
  }
  if (sourceType === "network-firewall") {
    return hasAny(record, ["firewall_name", "availability_zone"]) && hasAny(record, ["event", "event_type"]);
  }
  if (sourceType === "guardduty") {
    return hasAny(record, ["type", "severity", "service", "resource"]) && hasAny(record, ["id", "arn", "accountId"]);
  }
  if (sourceType === "security-hub") {
    return hasAny(record, ["SchemaVersion", "ProductArn", "GeneratorId", "Types"]) && hasAny(record, ["Id", "AwsAccountId"]);
  }
  if (sourceType === "inspector") {
    return hasAny(record, ["findingArn", "awsAccountId", "resources"]) && hasAny(record, ["type", "status", "severity"]);
  }
  return false;
}

function resourceIdentity(record: JsonObject) {
  const resources = Array.isArray(record.Resources)
    ? record.Resources
    : Array.isArray(record.resources)
      ? record.resources
      : [];
  const firstResource = object(resources[0]);
  const direct = first(record, [
    "resourceId", "resourceArn", "ResourceId", "Arn", "Id", "interface-id",
    "tgw-id", "tgw-attachment-id", "firewall_name", "webaclId", "resource",
  ], 800);
  return first(firstResource, ["Id", "id", "arn", "resourceArn"], 800) || direct;
}

function normalizeGeneric(record: JsonObject, index: number, sourceType: SourceType) {
  const resourceObject = object(record.Resource ?? record.resource);
  const service = object(record.service);
  const httpRequest = object(record.httpRequest ?? record.http);
  const rawObservedAt = first(record, [
    "eventTime", "timestamp", "time", "updatedAt", "UpdatedAt", "createdAt",
    "CreatedAt", "start", "date", "datetime", "@timestamp",
  ], 100);
  const observedAt = /^\d{10}$/.test(rawObservedAt)
    ? new Date(Number(rawObservedAt) * 1000).toISOString()
    : /^\d{13}$/.test(rawObservedAt)
      ? new Date(Number(rawObservedAt)).toISOString()
      : rawObservedAt;
  const accountId = first(record, ["accountId", "account-id", "AwsAccountId", "awsAccountId", "recipientAccountId"], 20)
    || first(resourceObject, ["accountId"], 20);
  const region = first(record, ["region", "awsRegion", "Region", "aws_region"], 50)
    || first(service, ["region"], 50);
  const resource = resourceIdentity(record)
    || first(resourceObject, ["instanceDetails", "resourceType", "id"], 800);
  const event = first(record, [
    "eventName", "eventType", "event_type", "Type", "type", "action",
    "findingStatus", "Status", "query_type", "routeKey", "httpMethod",
  ], 240) || sourceTypeDefinition(sourceType).label;
  const disposition = first(record, [
    "action", "Action", "status", "Status", "log-status", "statusCode",
    "responseStatus", "workflowStatus", "RecordState", "findingStatus",
  ], 160);
  const source = first(record, [
    "srcaddr", "pkt-srcaddr", "sourceIPAddress", "client", "clientIp",
    "sourceAddress", "source_ip", "c-ip", "x-edge-location",
  ], 500) || first(httpRequest, ["clientIp", "country"], 500);
  const destination = first(record, [
    "dstaddr", "pkt-dstaddr", "target", "destinationAddress", "destination_ip",
    "cs-host", "host", "query_name", "resourcePath",
  ], 500) || first(httpRequest, ["uri"], 500);
  const title = first(record, ["Title", "title", "Description", "description", "message", "Message"], 800);
  const summaryParts = [event, resource, source && destination ? `${source} → ${destination}` : source || destination, disposition]
    .filter(Boolean);
  return {
    id: first(record, ["eventID", "eventId", "Id", "id", "findingArn", "requestId", "analysisId"], 500)
      || `${sourceType}-${index + 1}`,
    observedAt,
    accountId,
    region,
    resource,
    event,
    disposition,
    source,
    destination,
    summary: title || summaryParts.join(" · "),
    raw: record,
  } satisfies NormalizedAwsEvidenceRecord;
}

export function parseAwsEvidenceText(text: string, sourceType: SourceType): AwsEvidenceImportResult {
  if (!text.trim()) throw new Error("The selected AWS evidence file is empty.");
  const definition = sourceTypeDefinition(sourceType);
  if (sourceType === "cloudtrail") {
    const cloudTrail = parseCloudTrailText(text);
    return {
      sourceType,
      sourceLabel: definition.label,
      evidenceClass: definition.evidenceClass,
      totalRecords: cloudTrail.totalRecords,
      skippedRecords: cloudTrail.skippedRecords,
      warnings: cloudTrail.warnings,
      cloudTrail,
      records: cloudTrail.events.map((event) => ({
        id: event.id,
        observedAt: event.eventTime,
        accountId: event.accountId,
        region: event.region,
        resource: event.groupIds.join(", "),
        event: event.eventName,
        disposition: event.errorCode || event.effect,
        source: event.sourceIp,
        destination: event.cidrs.join(", "),
        summary: `${event.actor} · ${event.direction} ${event.protocol} ${event.ports}`.trim(),
        raw: {},
      })),
    };
  }
  if (sourceType === "config-history" || sourceType === "config-snapshot") {
    const config = parseAwsConfigText(text);
    return {
      sourceType,
      sourceLabel: definition.label,
      evidenceClass: definition.evidenceClass,
      totalRecords: config.totalItems,
      skippedRecords: config.totalItems - config.items.length,
      warnings: config.securityGroups.length ? [] : ["No security-group configuration items were found in this AWS Config export."],
      records: config.items.map((item) => ({
        id: item.id,
        observedAt: item.captureTime,
        accountId: item.accountId,
        region: item.region,
        resource: `${item.resourceType} · ${item.resourceId}`,
        event: item.status,
        disposition: `${item.rules.length} network rule${item.rules.length === 1 ? "" : "s"}`,
        source: item.vpcId,
        destination: item.resourceArn,
        summary: item.groupName || item.resourceId,
        raw: {
          resourceType: item.resourceType,
          resourceId: item.resourceId,
          resourceArn: item.resourceArn,
          vpcId: item.vpcId,
          relationships: item.relationships,
          rules: item.rules,
        },
      })),
    };
  }
  const extractedRecords = sourceRecords(text, sourceType);
  const rawRecords = extractedRecords.filter((record) => isAwsSourceRecord(record, sourceType));
  if (!rawRecords.length) {
    throw new Error(`No records matched the selected ${definition.label} schema. Expected ${definition.format}.`);
  }
  if (rawRecords.length > MAX_RECORDS) {
    throw new Error(`This file contains more than ${MAX_RECORDS.toLocaleString()} records. Split it into smaller AWS exports.`);
  }
  const records = rawRecords.map((record, index) => normalizeGeneric(record, index, sourceType));
  const warnings = records.some((record) => !record.observedAt)
    ? ["Some AWS records do not contain an event timestamp; Gatewatch preserves them without inventing an observation time."]
    : [];
  if (rawRecords.length !== extractedRecords.length) {
    warnings.push(`${(extractedRecords.length - rawRecords.length).toLocaleString()} record(s) did not match the selected AWS source schema and were skipped.`);
  }
  if (sourceType === "vpc-flow-logs" || sourceType === "transit-gateway-flow-logs") {
    warnings.push("Flow logs show observed traffic but do not identify the exact security-group rule that allowed or rejected a packet.");
  }
  if (sourceType === "reachability-analyzer" || sourceType === "network-access-analyzer") {
    warnings.push("AWS network analysis is configuration-based evidence, not proof that packets were transmitted.");
  }
  return {
    sourceType,
    sourceLabel: definition.label,
    evidenceClass: definition.evidenceClass,
    totalRecords: rawRecords.length,
    skippedRecords: extractedRecords.length - rawRecords.length,
    records,
    warnings,
  };
}

async function readGzipFile(file: File) {
  if (typeof DecompressionStream === "undefined") {
    throw new Error("Gzip files are not supported by this browser. Decompress the AWS log before importing it.");
  }
  const reader = file.stream().pipeThrough(new DecompressionStream("gzip")).getReader();
  const decoder = new TextDecoder();
  let totalBytes = 0;
  let text = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    totalBytes += value.byteLength;
    if (totalBytes > MAX_DECOMPRESSED_BYTES) {
      await reader.cancel();
      throw new Error("The decompressed AWS log is larger than 50 MB. Split it into smaller files.");
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}

export async function readAwsEvidenceFile(file: File) {
  if (!file.size) throw new Error("The selected AWS evidence file is empty.");
  if (file.size > MAX_AWS_EVIDENCE_FILE_BYTES) {
    throw new Error("The selected file is larger than 25 MB. Split large AWS exports before importing.");
  }
  const filename = file.name.toLowerCase();
  const supported = [".json", ".json.gz", ".log", ".log.gz", ".txt", ".txt.gz", ".csv", ".tsv"];
  if (!supported.some((extension) => filename.endsWith(extension))) {
    throw new Error("Choose an AWS JSON, JSON.GZ, LOG, TXT, CSV, or TSV export.");
  }
  return filename.endsWith(".gz") ? readGzipFile(file) : file.text();
}
