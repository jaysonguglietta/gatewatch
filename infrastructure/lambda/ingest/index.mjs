import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { AssumeRoleCommand, STSClient } from "@aws-sdk/client-sts";
import {
  BatchExecuteStatementCommand,
  BeginTransactionCommand,
  CommitTransactionCommand,
  ExecuteStatementCommand,
  RDSDataClient,
  RollbackTransactionCommand,
} from "@aws-sdk/client-rds-data";

const MAX_COMPRESSED_BYTES = 50 * 1024 * 1024;
const MAX_DECOMPRESSED_BYTES = 256 * 1024 * 1024;
const MAX_RECORDS = 100_000;
const MAX_GENERIC_PAYLOAD_BYTES = 64 * 1024;
const SG_EVENTS = new Set([
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
const GENERIC_SOURCE_CLASSES = new Map([
  ["vpc-flow-logs", "observed-traffic"],
  ["transit-gateway-flow-logs", "observed-traffic"],
  ["reachability-analyzer", "reachability"],
  ["network-access-analyzer", "reachability"],
  ["elastic-load-balancing", "service-access"],
  ["waf", "service-access"],
  ["cloudfront", "service-access"],
  ["api-gateway", "service-access"],
  ["route53-resolver", "service-access"],
  ["network-firewall", "observed-traffic"],
  ["guardduty", "threat-finding"],
  ["security-hub", "threat-finding"],
  ["inspector", "threat-finding"],
]);
const DEFAULT_FLOW_FIELDS = [
  "version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport",
  "dstport", "protocol", "packets", "bytes", "start", "end", "action",
  "log-status",
];

const rds = new RDSDataClient({});
const sts = new STSClient({});
const database = process.env.DATABASE_NAME;
const resourceArn = process.env.DB_CLUSTER_ARN;
const secretArn = process.env.DB_SECRET_ARN;
const organizationEvidenceBucket = process.env.ORGANIZATION_EVIDENCE_BUCKET ?? "";
const runtimeS3 = new S3Client({});

function parameters(values) {
  return Object.entries(values).map(([name, value]) => ({
    name,
    value:
      typeof value === "number"
        ? { longValue: value }
        : typeof value === "boolean"
          ? { booleanValue: value }
          : { stringValue: String(value ?? "") },
  }));
}

async function sql(statement, values = {}, transactionId = undefined) {
  return rds.send(
    new ExecuteStatementCommand({
      database,
      resourceArn,
      secretArn,
      sql: statement,
      parameters: parameters(values),
      includeResultMetadata: true,
      transactionId,
    }),
  );
}

async function transaction(callback) {
  const begun = await rds.send(new BeginTransactionCommand({
    database,
    resourceArn,
    secretArn,
  }));
  if (!begun.transactionId) throw new Error("DATABASE_TRANSACTION_UNAVAILABLE");
  try {
    const result = await callback(begun.transactionId);
    await rds.send(new CommitTransactionCommand({
      resourceArn,
      secretArn,
      transactionId: begun.transactionId,
    }));
    return result;
  } catch (error) {
    await rds.send(new RollbackTransactionCommand({
      resourceArn,
      secretArn,
      transactionId: begun.transactionId,
    })).catch(() => undefined);
    throw error;
  }
}

async function bodyBuffer(body) {
  const chunks = [];
  let total = 0;
  for await (const chunk of body) {
    total += chunk.length;
    if (total > MAX_COMPRESSED_BYTES) throw new Error("OBJECT_TOO_LARGE");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function extractS3(record) {
  const envelope = JSON.parse(record.body);
  const event = envelope.detail
    ? envelope
    : envelope.Message
      ? JSON.parse(envelope.Message)
      : envelope;
  if (event.detail?.bucket?.name && event.detail?.object?.key) {
    return {
      bucket: event.detail.bucket.name,
      key: decodeURIComponent(event.detail.object.key.replaceAll("+", " ")),
      versionId: event.detail.object["version-id"] ?? "",
      etag: event.detail.object.etag ?? "",
      size: Number(event.detail.object.size ?? 0),
      runId: event.detail.gatewatch?.runId ?? "",
    };
  }
  const s3 = event.Records?.[0]?.s3;
  if (!s3?.bucket?.name || !s3?.object?.key) throw new Error("INVALID_S3_EVENT");
  return {
    bucket: s3.bucket.name,
    key: decodeURIComponent(s3.object.key.replaceAll("+", " ")),
    versionId: s3.object.versionId ?? "",
    etag: s3.object.eTag ?? "",
    size: Number(s3.object.size ?? 0),
    runId: "",
  };
}

function fieldString(field) {
  return field?.stringValue ?? "";
}

async function findSource(bucket, key) {
  const result = await sql(
    `SELECT id::text, workspace_id::text, source_type, role_arn, external_id,
            region, object_prefix
     FROM ingestion_sources
     WHERE bucket_name = :bucket
       AND status IN ('live', 'backfilling')
       AND left(:key, length(object_prefix)) = object_prefix
     ORDER BY length(object_prefix) DESC
     LIMIT 1`,
    { bucket, key },
  );
  const row = result.records?.[0];
  if (!row) throw new Error("SOURCE_NOT_ACTIVE");
  return {
    id: fieldString(row[0]),
    workspaceId: fieldString(row[1]),
    sourceType: fieldString(row[2]),
    roleArn: fieldString(row[3]),
    externalId: fieldString(row[4]),
    region: fieldString(row[5]),
  };
}

async function sourceS3(source) {
  const assumed = await sts.send(
    new AssumeRoleCommand({
      RoleArn: source.roleArn,
      RoleSessionName: `gatewatch-ingest-${Date.now()}`,
      ExternalId: source.externalId || undefined,
      DurationSeconds: 900,
    }),
  );
  const value = assumed.Credentials;
  if (!value?.AccessKeyId || !value.SecretAccessKey || !value.SessionToken) {
    throw new Error("ASSUME_ROLE_INCOMPLETE");
  }
  return new S3Client({
    region: source.region,
    credentials: {
      accessKeyId: value.AccessKeyId,
      secretAccessKey: value.SecretAccessKey,
      sessionToken: value.SessionToken,
      expiration: value.Expiration,
    },
  });
}

function visit(value, callback, depth = 0) {
  if (!value || typeof value !== "object" || depth > 9) return;
  if (Array.isArray(value)) {
    for (const item of value.slice(0, MAX_RECORDS)) visit(item, callback, depth + 1);
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    callback(key, child);
    visit(child, callback, depth + 1);
  }
}

function normalizeCloudTrail(record) {
  if (!record || !SG_EVENTS.has(record.eventName)) return [];
  const groupIds = new Set();
  const cidrs = new Set();
  visit(record.requestParameters, (key, value) => {
    if (["groupId", "groupID", "securityGroupId"].includes(key) && /^sg-[\w-]+$/.test(String(value))) groupIds.add(String(value));
    if (["cidrIp", "cidrIpv4", "cidrIpv6", "cidrIPv4", "cidrIPv6"].includes(key)) cidrs.add(String(value));
  });
  const identity = record.userIdentity ?? {};
  const base = {
    eventId: String(record.eventID ?? record.requestID ?? createHash("sha256").update(JSON.stringify(record)).digest("hex")),
    accountId: String(identity.accountId ?? record.recipientAccountId ?? ""),
    region: String(record.awsRegion ?? ""),
    eventName: String(record.eventName),
    eventTime: String(record.eventTime),
    actorArn: String(identity.arn ?? identity.principalId ?? ""),
    actorType: String(identity.type ?? ""),
    sourceIp: String(record.sourceIPAddress ?? ""),
    successful: !record.errorCode,
    direction: record.eventName.includes("Ingress") ? "Ingress" : record.eventName.includes("Egress") ? "Egress" : "Unknown",
    effect: record.eventName.startsWith("Authorize") ? "Broadens access" : record.eventName.startsWith("Revoke") ? "Restricts access" : "Changes access",
    internetWide: cidrs.has("0.0.0.0/0") || cidrs.has("::/0"),
    request: JSON.stringify(record.requestParameters ?? {}),
  };
  return [...(groupIds.size ? groupIds : [""])].map((securityGroupId) => ({ ...base, securityGroupId }));
}

function normalizeConfig(item) {
  if (!item?.resourceType) return null;
  let configuration = item.configuration ?? {};
  if (typeof configuration === "string") {
    try { configuration = JSON.parse(configuration); } catch { configuration = {}; }
  }
  const captureTime = String(item.configurationItemCaptureTime ?? item.captureTime ?? "");
  return {
    id: String(item.configurationStateId ?? `${item.awsAccountId}:${item.awsRegion}:${item.resourceId}:${captureTime}`),
    accountId: String(item.awsAccountId ?? item.accountId ?? ""),
    region: String(item.awsRegion ?? item.region ?? ""),
    resourceType: String(item.resourceType),
    resourceId: String(item.resourceId ?? ""),
    resourceArn: String(item.ARN ?? item.arn ?? ""),
    configurationStateId: String(item.configurationStateId ?? ""),
    captureTime,
    status: String(item.configurationItemStatus ?? "OK"),
    configuration: JSON.stringify(configuration),
    relationships: JSON.stringify(item.relationships ?? []),
  };
}

function recordObject(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function recordString(value, maximum = 2_000) {
  if (typeof value === "string") return value.slice(0, maximum);
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value).slice(0, maximum);
  }
  return "";
}

function firstRecordValue(record, keys, maximum = 2_000) {
  for (const key of keys) {
    const value = recordString(record?.[key], maximum);
    if (value) return value;
  }
  return "";
}

function parseJsonLines(text) {
  const records = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    try {
      const value = JSON.parse(trimmed);
      if (!value || typeof value !== "object" || Array.isArray(value)) return null;
      records.push(value);
    } catch {
      return null;
    }
  }
  return records.length ? records : null;
}

function parseFlowText(text) {
  const records = [];
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

function parseCloudFrontText(text) {
  const records = [];
  let fields = [];
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

function parseAccessText(text) {
  return text.split(/\r?\n/).flatMap((line, index) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) return [];
    const values = trimmed.match(/(?:[^\s"]+|"[^"]*")+/g) ?? [];
    if (values.length < 3) return [];
    const networkLoadBalancer = /^\d+\.\d+$/.test(values[1] ?? "");
    return [{
      recordNumber: index + 1,
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

function recordsFromJson(parsed, sourceType) {
  if (Array.isArray(parsed)) return parsed;
  const root = recordObject(parsed);
  const candidates = sourceType === "security-hub"
    ? [root.Findings, root.findings]
    : sourceType === "guardduty" || sourceType === "inspector"
      ? [root.Findings, root.findings, root.detail ? [root.detail] : undefined]
      : sourceType === "reachability-analyzer"
        ? [root.NetworkInsightsAnalyses, root.NetworkInsightsPaths, root.NetworkInsightsAnalysis ? [root.NetworkInsightsAnalysis] : undefined]
        : sourceType === "network-access-analyzer"
          ? [root.NetworkInsightsAccessScopeAnalyses, root.Findings, root.NetworkInsightsAccessScopeAnalysis ? [root.NetworkInsightsAccessScopeAnalysis] : undefined]
          : [root.Records, root.records, root.logEvents, root.events];
  const records = candidates.find(Array.isArray);
  return records ?? [root];
}

function recordHasAny(record, keys) {
  return keys.some((key) => record?.[key] !== undefined && record?.[key] !== null && record?.[key] !== "");
}

function isAwsSourceRecord(record, sourceType) {
  const item = recordObject(record);
  if (sourceType === "vpc-flow-logs") return recordHasAny(item, ["interface-id", "interfaceId"]) && recordHasAny(item, ["srcaddr", "sourceAddress"]) && recordHasAny(item, ["dstaddr", "destinationAddress"]);
  if (sourceType === "transit-gateway-flow-logs") return recordHasAny(item, ["tgw-id", "tgw-attachment-id", "transitGatewayId"]) && recordHasAny(item, ["srcaddr", "sourceAddress"]);
  if (sourceType === "reachability-analyzer") return recordHasAny(item, ["NetworkInsightsAnalysisId", "NetworkInsightsPathId", "NetworkPathFound", "Explanations"]);
  if (sourceType === "network-access-analyzer") return recordHasAny(item, ["NetworkInsightsAccessScopeAnalysisId", "NetworkInsightsAccessScopeId", "NetworkInsightsAccessScopeArn", "Findings"]);
  if (sourceType === "elastic-load-balancing") return recordHasAny(item, ["client", "clientIp"]) && recordHasAny(item, ["resource", "elb", "loadBalancerArn"]);
  if (sourceType === "waf") return recordHasAny(item, ["webaclId", "terminatingRuleId", "httpRequest"]);
  if (sourceType === "cloudfront") return recordHasAny(item, ["date", "timestamp"]) && recordHasAny(item, ["c-ip", "clientIp", "cs-method", "uri"]);
  if (sourceType === "api-gateway") return recordHasAny(item, ["requestId", "routeKey", "resourcePath", "httpMethod"]) && recordHasAny(item, ["status", "statusCode", "responseStatus", "protocol"]);
  if (sourceType === "route53-resolver") return recordHasAny(item, ["query_name", "query_type", "query_type_id"]) && recordHasAny(item, ["srcids", "vpc_id", "instance_id"]);
  if (sourceType === "network-firewall") return recordHasAny(item, ["firewall_name", "availability_zone"]) && recordHasAny(item, ["event", "event_type"]);
  if (sourceType === "guardduty") return recordHasAny(item, ["type", "severity", "service", "resource"]) && recordHasAny(item, ["id", "arn", "accountId"]);
  if (sourceType === "security-hub") return recordHasAny(item, ["SchemaVersion", "ProductArn", "GeneratorId", "Types"]) && recordHasAny(item, ["Id", "AwsAccountId"]);
  if (sourceType === "inspector") return recordHasAny(item, ["findingArn", "awsAccountId", "resources"]) && recordHasAny(item, ["type", "status", "severity"]);
  return false;
}

function extractGenericRecords(content, sourceType) {
  const text = content.toString("utf8");
  let records;
  let parsed;
  try {
    parsed = JSON.parse(text);
    records = recordsFromJson(parsed, sourceType);
  } catch {
    const lines = parseJsonLines(text);
    if (lines) records = lines;
  }
  if (!records && (sourceType === "vpc-flow-logs" || sourceType === "transit-gateway-flow-logs")) {
    records = parseFlowText(text);
  }
  if (!records && sourceType === "cloudfront") records = parseCloudFrontText(text);
  if (!records && (sourceType === "elastic-load-balancing" || sourceType === "api-gateway")) {
    records = parseAccessText(text);
  }
  const validated = (records ?? []).filter((record) => isAwsSourceRecord(record, sourceType));
  if (!validated.length) throw new Error("INVALID_AWS_EVIDENCE_FORMAT");
  return validated;
}

function normalizeGeneric(record, index, source, objectId) {
  const item = recordObject(record);
  const resource = recordObject(item.Resource ?? item.resource);
  const service = recordObject(item.service);
  const payload = JSON.stringify(item);
  if (Buffer.byteLength(payload) > MAX_GENERIC_PAYLOAD_BYTES) {
    throw new Error("AWS_EVIDENCE_RECORD_TOO_LARGE");
  }
  const observedAt = firstRecordValue(item, [
    "eventTime", "timestamp", "time", "updatedAt", "UpdatedAt", "createdAt",
    "CreatedAt", "start", "date", "datetime", "@timestamp",
  ], 100);
  if (observedAt && !Number.isFinite(Date.parse(observedAt)) && !/^\d{10}(?:\d{3})?$/.test(observedAt)) {
    throw new Error("INVALID_AWS_EVIDENCE_TIMESTAMP");
  }
  const accountId = firstRecordValue(item, ["accountId", "account-id", "AwsAccountId", "awsAccountId", "recipientAccountId"], 20)
    || firstRecordValue(resource, ["accountId"], 20);
  const region = firstRecordValue(item, ["region", "awsRegion", "Region", "aws_region"], 50)
    || firstRecordValue(service, ["region"], 50);
  const resources = Array.isArray(item.Resources)
    ? item.Resources
    : Array.isArray(item.resources)
      ? item.resources
      : [];
  const firstResource = recordObject(resources[0]);
  const resourceId = firstRecordValue(firstResource, ["Id", "id", "arn", "resourceArn"], 800)
    || firstRecordValue(item, [
    "resourceId", "resourceArn", "ResourceId", "Arn", "Id", "interface-id",
    "tgw-id", "tgw-attachment-id", "firewall_name", "webaclId", "resource",
  ], 800);
  const resourceType = firstRecordValue(item, ["resourceType", "ResourceType", "type", "Type"], 240);
  const eventName = firstRecordValue(item, [
    "eventName", "eventType", "event_type", "Type", "type", "action",
    "findingStatus", "Status", "query_type", "routeKey", "httpMethod",
  ], 240);
  const disposition = firstRecordValue(item, [
    "action", "Action", "status", "Status", "log-status", "statusCode",
    "responseStatus", "workflowStatus", "RecordState", "findingStatus",
  ], 160);
  const stableId = firstRecordValue(item, [
    "eventID", "eventId", "Id", "id", "findingArn", "requestId", "analysisId",
  ], 500);
  const fingerprint = createHash("sha256")
    .update(`${source.id}|${source.sourceType}|${stableId || objectId}|${index}|${payload}`)
    .digest("hex");
  const normalizedPayload = JSON.stringify({
    source: firstRecordValue(item, ["srcaddr", "pkt-srcaddr", "sourceIPAddress", "client", "clientIp", "sourceAddress", "source_ip", "c-ip"], 500),
    destination: firstRecordValue(item, ["dstaddr", "pkt-dstaddr", "target", "destinationAddress", "destination_ip", "cs-host", "host", "query_name", "resourcePath"], 500),
    aws: item,
  });
  return {
    workspaceId: source.workspaceId,
    fingerprint,
    sourceId: source.id,
    objectId,
    sourceType: source.sourceType,
    evidenceClass: GENERIC_SOURCE_CLASSES.get(source.sourceType),
    observedAt: /^\d{10}$/.test(observedAt)
      ? new Date(Number(observedAt) * 1000).toISOString()
      : /^\d{13}$/.test(observedAt)
        ? new Date(Number(observedAt)).toISOString()
        : observedAt,
    accountId,
    region,
    resourceType,
    resourceId,
    eventName,
    disposition,
    normalizedPayload,
  };
}

async function insertGenericEvidence(source, objectId, records) {
  const evidenceClass = GENERIC_SOURCE_CLASSES.get(source.sourceType);
  if (!evidenceClass) throw new Error("UNSUPPORTED_AWS_EVIDENCE_SOURCE");
  const normalized = records.map((record, index) => normalizeGeneric(record, index, source, objectId));
  const statement = `INSERT INTO aws_evidence_records
    (workspace_id, fingerprint, source_id, raw_object_id, source_type,
     evidence_class, observed_at, account_id, region, resource_type,
     resource_id, event_name, disposition, normalized_payload)
   VALUES (CAST(:workspaceId AS uuid), :fingerprint, CAST(:sourceId AS uuid),
     CAST(:objectId AS uuid), :sourceType, :evidenceClass,
     NULLIF(:observedAt, '')::timestamptz, :accountId, :region, :resourceType,
     :resourceId, :eventName, :disposition, CAST(:normalizedPayload AS jsonb))
   ON CONFLICT DO NOTHING`;
  for (let index = 0; index < normalized.length; index += 25) {
    await rds.send(new BatchExecuteStatementCommand({
      database,
      resourceArn,
      secretArn,
      sql: statement,
      parameterSets: normalized.slice(index, index + 25).map(parameters),
    }));
  }
}

async function insertCloudTrail(source, objectId, events) {
  const statement = `INSERT INTO cloudtrail_events
    (workspace_id, event_id, source_id, raw_object_id, account_id, region,
     security_group_id, event_name, event_time, actor_arn, actor_type,
     source_ip, successful, direction, effect, internet_wide, request_parameters)
   VALUES (CAST(:workspaceId AS uuid), :eventId, CAST(:sourceId AS uuid),
     CAST(:objectId AS uuid), :accountId, :region, :securityGroupId, :eventName,
     CAST(:eventTime AS timestamptz), :actorArn, :actorType,
     NULLIF(:sourceIp, '')::inet, :successful, :direction, :effect,
     :internetWide, CAST(:request AS jsonb))
   ON CONFLICT DO NOTHING`;
  for (let index = 0; index < events.length; index += 250) {
    await rds.send(new BatchExecuteStatementCommand({
      database, resourceArn, secretArn, sql: statement,
      parameterSets: events.slice(index, index + 250).map((event) =>
        parameters({ ...event, workspaceId: source.workspaceId, sourceId: source.id, objectId }),
      ),
    }));
  }
  for (const event of events) {
    await sql(
      `SELECT gatewatch_correlate_cloudtrail_event(
        CAST(:workspaceId AS uuid), :eventId, CAST(:eventTime AS timestamptz)
      )`,
      {
        workspaceId: source.workspaceId,
        eventId: event.eventId,
        eventTime: event.eventTime,
      },
    );
  }
}

async function insertConfig(source, objectId, items) {
  const statement = `INSERT INTO config_items
    (workspace_id, id, source_id, raw_object_id, account_id, region,
     resource_type, resource_id, resource_arn, configuration_state_id,
     capture_time, status, configuration, relationships)
   VALUES (CAST(:workspaceId AS uuid), :id, CAST(:sourceId AS uuid),
     CAST(:objectId AS uuid), :accountId, :region, :resourceType, :resourceId,
     :resourceArn, :configurationStateId, CAST(:captureTime AS timestamptz),
     :status, CAST(:configuration AS jsonb), CAST(:relationships AS jsonb))
   ON CONFLICT DO NOTHING`;
  for (let index = 0; index < items.length; index += 250) {
    await rds.send(new BatchExecuteStatementCommand({
      database, resourceArn, secretArn, sql: statement,
      parameterSets: items.slice(index, index + 250).map((item) =>
        parameters({ ...item, workspaceId: source.workspaceId, sourceId: source.id, objectId }),
      ),
    }));
  }
  for (const item of items.filter(
    (candidate) => candidate.resourceType === "AWS::EC2::SecurityGroup",
  )) {
    await sql(
      `SELECT gatewatch_apply_security_group_config(
        CAST(:workspaceId AS uuid), :accountId, :region, :resourceId,
        CAST(:captureTime AS timestamptz), :configItemId, :status,
        CAST(:configuration AS jsonb)
      )`,
      {
        workspaceId: source.workspaceId,
        accountId: item.accountId,
        region: item.region,
        resourceId: item.resourceId,
        captureTime: item.captureTime,
        configItemId: item.id,
        status: item.status,
        configuration: item.configuration,
      },
    );
    await sql(
      `SELECT gatewatch_correlate_cloudtrail_event(
         workspace_id, event_id, event_time
       )
         FROM cloudtrail_events
        WHERE workspace_id = CAST(:workspaceId AS uuid)
          AND account_id = :accountId
          AND region = :region
          AND security_group_id = :resourceId
          AND successful = true
          AND abs(extract(epoch FROM (
            event_time - CAST(:captureTime AS timestamptz)
          ))) <= 1800`,
      {
        workspaceId: source.workspaceId,
        accountId: item.accountId,
        region: item.region,
        resourceId: item.resourceId,
        captureTime: item.captureTime,
      },
    );
  }
}

async function batchSql(statement, rows, transactionId) {
  for (let index = 0; index < rows.length; index += 200) {
    await rds.send(new BatchExecuteStatementCommand({
      database,
      resourceArn,
      secretArn,
      transactionId,
      sql: statement,
      parameterSets: rows.slice(index, index + 200).map(parameters),
    }));
  }
}

async function defaultWorkspaceId() {
  const result = await sql(
    "SELECT id::text FROM workspaces WHERE slug = 'default' LIMIT 1",
  );
  const value = fieldString(result.records?.[0]?.[0]);
  if (!value) throw new Error("DEFAULT_WORKSPACE_NOT_FOUND");
  return value;
}

async function readEvidenceObject(object) {
  const response = await runtimeS3.send(new GetObjectCommand({
    Bucket: object.bucket,
    Key: object.key,
    VersionId: object.versionId || undefined,
  }));
  const compressed = await bodyBuffer(response.Body);
  const content = object.key.endsWith(".gz")
    ? gunzipSync(compressed, { maxOutputLength: MAX_DECOMPRESSED_BYTES })
    : compressed;
  if (content.length > MAX_DECOMPRESSED_BYTES) {
    throw new Error("DECOMPRESSED_OBJECT_TOO_LARGE");
  }
  return { content, parsed: JSON.parse(content.toString("utf8")) };
}

function integer(value, maximum = 10_000_000) {
  const number = Number(value ?? 0);
  if (!Number.isSafeInteger(number) || number < 0 || number > maximum) {
    throw new Error("INVALID_INVENTORY_COUNT");
  }
  return number;
}

function inventoryPeer(rule) {
  return rule.cidrIpv4
    ?? rule.cidrIpv6
    ?? rule.prefixListId
    ?? rule.referencedGroup?.groupId
    ?? "";
}

function inventoryPeerType(rule) {
  if (rule.cidrIpv4) return "IPv4";
  if (rule.cidrIpv6) return "IPv6";
  if (rule.prefixListId) return "Prefix list";
  if (rule.referencedGroup?.groupId) return "Security group";
  return "Unknown";
}

function validateInventoryShard(value, keyIdentity) {
  if (
    !value
    || value.schemaVersion !== "2.0"
    || value.evidenceType !== "security-group-inventory-shard"
    || value.runId !== keyIdentity.runId
    || value.target?.accountId !== keyIdentity.accountId
    || value.target?.region !== keyIdentity.region
    || !Array.isArray(value.securityGroups)
    || value.securityGroups.length > 20_000
  ) {
    throw new Error("INVALID_INVENTORY_SHARD_SCHEMA");
  }
  const observedAt = String(value.observedAt ?? "");
  if (!Number.isFinite(Date.parse(observedAt))) {
    throw new Error("INVALID_INVENTORY_OBSERVATION_TIME");
  }
  let ruleCount = 0;
  for (const group of value.securityGroups) {
    if (
      !/^sg-[a-zA-Z0-9-]{3,64}$/.test(String(group?.id ?? ""))
      || group.accountId !== keyIdentity.accountId
      || group.region !== keyIdentity.region
      || !Array.isArray(group.rules)
      || group.rules.length > 5_000
      || !Array.isArray(group.resourceAttachments ?? [])
    ) {
      throw new Error("INVALID_SECURITY_GROUP_OBSERVATION");
    }
    ruleCount += group.rules.length;
    if (ruleCount > MAX_RECORDS) throw new Error("INVALID_RECORD_COUNT");
  }
  return value;
}

async function processInventoryShard(object, identity) {
  if (object.size > MAX_COMPRESSED_BYTES) throw new Error("OBJECT_TOO_LARGE");
  const workspaceId = await defaultWorkspaceId();
  const ledger = await sql(
    `INSERT INTO inventory_shard_objects
      (workspace_id, run_id, account_id, region, bucket_name, object_key,
       version_id, etag, checksum_sha256, object_size, status)
     VALUES (CAST(:workspaceId AS uuid), CAST(:runId AS uuid), :accountId,
       :region, :bucket, :key, :versionId, :etag, '', :size, 'processing')
     ON CONFLICT (workspace_id, bucket_name, object_key, version_id) DO NOTHING
     RETURNING object_key`,
    { workspaceId, ...identity, ...object },
  );
  if (!fieldString(ledger.records?.[0]?.[0])) return { duplicate: true };
  try {
    const { content, parsed } = await readEvidenceObject(object);
    const shard = validateInventoryShard(parsed, identity);
    const checksum = createHash("sha256").update(content).digest("hex");
    const observedAt = String(shard.observedAt);
    const accountName = String(shard.target.accountName ?? identity.accountId).slice(0, 160);
    const groupRows = [];
    const ruleRows = [];
    for (const group of shard.securityGroups) {
      groupRows.push({
        workspaceId,
        runId: identity.runId,
        accountId: identity.accountId,
        accountName,
        region: identity.region,
        securityGroupId: String(group.id),
        name: String(group.name ?? "").slice(0, 255),
        description: String(group.description ?? "").slice(0, 2000),
        vpcId: String(group.vpcId ?? "").slice(0, 128),
        isDefault: Boolean(group.isDefault),
        tags: JSON.stringify(group.tags ?? {}),
        inboundRuleCount: integer(group.inboundRuleCount, 100_000),
        outboundRuleCount: integer(group.outboundRuleCount, 100_000),
        publicIngressRuleCount: integer(group.publicIngressRuleCount, 100_000),
        publicEgressRuleCount: integer(group.publicEgressRuleCount, 100_000),
        attachmentCount: integer(group.networkInterfaceAttachmentCount, 1_000_000),
        attachments: JSON.stringify((group.resourceAttachments ?? []).slice(0, 20_000)),
        networkEvidence: JSON.stringify(group.networkEvidence ?? {}),
        observedAt,
        sourceObjectKey: object.key,
      });
      group.rules.forEach((rule, index) => {
        const peer = String(inventoryPeer(rule)).slice(0, 512);
        const signature = `${group.id}|${rule.isEgress}|${rule.protocol}|${rule.fromPort}|${rule.toPort}|${peer}|${index}`;
        ruleRows.push({
          workspaceId,
          runId: identity.runId,
          accountId: identity.accountId,
          region: identity.region,
          securityGroupId: String(group.id),
          ruleId: String(rule.ruleId ?? createHash("sha256").update(signature).digest("hex")).slice(0, 128),
          direction: rule.isEgress ? "Egress" : "Ingress",
          protocol: String(rule.protocol ?? "-1").slice(0, 32),
          fromPort: rule.fromPort ?? "",
          toPort: rule.toPort ?? "",
          peer,
          peerType: inventoryPeerType(rule),
          description: String(rule.description ?? "").slice(0, 2000),
          internetWide: peer === "0.0.0.0/0" || peer === "::/0",
          observedAt,
        });
      });
    }
    await sql(
      `INSERT INTO organization_collection_runs
        (workspace_id, run_id, status, manifest_bucket, manifest_key, started_at)
       VALUES (CAST(:workspaceId AS uuid), CAST(:runId AS uuid), 'running',
         :bucket, :manifestKey, CAST(:observedAt AS timestamptz))
       ON CONFLICT (workspace_id, run_id) DO NOTHING`,
      {
        workspaceId,
        runId: identity.runId,
        bucket: object.bucket,
        manifestKey: `runs/${identity.runId}/manifest.json`,
        observedAt,
      },
    );
    await transaction(async (transactionId) => {
      await batchSql(
        `INSERT INTO security_group_observations
          (workspace_id, run_id, account_id, account_name, region,
           security_group_id, name, description, vpc_id, is_default, tags,
           inbound_rule_count, outbound_rule_count, public_ingress_rule_count,
           public_egress_rule_count, attachment_count, attachments,
           network_evidence, observed_at, source_object_key)
         VALUES (CAST(:workspaceId AS uuid), CAST(:runId AS uuid), :accountId,
           :accountName, :region, :securityGroupId, NULLIF(:name, ''),
           NULLIF(:description, ''), NULLIF(:vpcId, ''), :isDefault,
           CAST(:tags AS jsonb), :inboundRuleCount, :outboundRuleCount,
           :publicIngressRuleCount, :publicEgressRuleCount, :attachmentCount,
           CAST(:attachments AS jsonb), CAST(:networkEvidence AS jsonb),
           CAST(:observedAt AS timestamptz), :sourceObjectKey)
         ON CONFLICT (workspace_id, run_id, account_id, region, security_group_id)
         DO UPDATE SET account_name = excluded.account_name, name = excluded.name,
           description = excluded.description, vpc_id = excluded.vpc_id,
           is_default = excluded.is_default, tags = excluded.tags,
           inbound_rule_count = excluded.inbound_rule_count,
           outbound_rule_count = excluded.outbound_rule_count,
           public_ingress_rule_count = excluded.public_ingress_rule_count,
           public_egress_rule_count = excluded.public_egress_rule_count,
           attachment_count = excluded.attachment_count,
           attachments = excluded.attachments,
           network_evidence = excluded.network_evidence,
           observed_at = excluded.observed_at,
           source_object_key = excluded.source_object_key`,
        groupRows,
        transactionId,
      );
      await batchSql(
        `INSERT INTO security_group_rule_observations
          (workspace_id, run_id, account_id, region, security_group_id,
           rule_id, direction, protocol, from_port, to_port, peer, peer_type,
           description, internet_wide, observed_at)
         VALUES (CAST(:workspaceId AS uuid), CAST(:runId AS uuid), :accountId,
           :region, :securityGroupId, :ruleId, :direction, :protocol,
           NULLIF(:fromPort, '')::integer, NULLIF(:toPort, '')::integer,
           :peer, :peerType, NULLIF(:description, ''), :internetWide,
           CAST(:observedAt AS timestamptz))
         ON CONFLICT (workspace_id, run_id, account_id, region,
                      security_group_id, rule_id)
         DO UPDATE SET direction = excluded.direction,
           protocol = excluded.protocol, from_port = excluded.from_port,
           to_port = excluded.to_port, peer = excluded.peer,
           peer_type = excluded.peer_type, description = excluded.description,
           internet_wide = excluded.internet_wide,
           observed_at = excluded.observed_at`,
        ruleRows,
        transactionId,
      );
      await sql(
        `INSERT INTO organization_collection_targets
          (workspace_id, run_id, account_id, account_name, region, status,
           object_key, checksum_sha256, security_group_count,
           security_group_rule_count, network_interface_count, completed_at)
         VALUES (CAST(:workspaceId AS uuid), CAST(:runId AS uuid), :accountId,
           :accountName, :region, 'succeeded', :objectKey, :checksum,
           :groupCount, :ruleCount, :interfaceCount,
           CAST(:observedAt AS timestamptz))
         ON CONFLICT (workspace_id, run_id, account_id, region)
         DO UPDATE SET status = 'succeeded', object_key = excluded.object_key,
           checksum_sha256 = excluded.checksum_sha256,
           security_group_count = excluded.security_group_count,
           security_group_rule_count = excluded.security_group_rule_count,
           network_interface_count = excluded.network_interface_count,
           completed_at = excluded.completed_at`,
        {
          workspaceId,
          runId: identity.runId,
          accountId: identity.accountId,
          accountName,
          region: identity.region,
          objectKey: object.key,
          checksum,
          groupCount: groupRows.length,
          ruleCount: ruleRows.length,
          interfaceCount: integer(shard.coverage?.networkInterfaceCount, 10_000_000),
          observedAt,
        },
        transactionId,
      );
    });
    await sql(
      `UPDATE inventory_shard_objects
          SET status = 'processed', checksum_sha256 = :checksum,
              processed_at = now()
        WHERE workspace_id = CAST(:workspaceId AS uuid)
          AND bucket_name = :bucket AND object_key = :key
          AND version_id = :versionId`,
      { workspaceId, checksum, ...object },
    );
    return { duplicate: false, groups: groupRows.length, rules: ruleRows.length };
  } catch (error) {
    await sql(
      `UPDATE inventory_shard_objects
          SET status = 'failed', failure_code = :code, processed_at = now()
        WHERE workspace_id = CAST(:workspaceId AS uuid)
          AND bucket_name = :bucket AND object_key = :key
          AND version_id = :versionId`,
      {
        workspaceId,
        code: error instanceof Error ? error.message.slice(0, 120) : "UNKNOWN",
        ...object,
      },
    );
    throw error;
  }
}

function validateCollectionManifest(value, runId) {
  if (
    !value
    || value.schemaVersion !== "2.0"
    || value.evidenceType !== "organization-collection-manifest"
    || value.runId !== runId
    || !["succeeded", "partial", "failed"].includes(value.status)
    || !Array.isArray(value.targets)
    || value.targets.length > 50_000
  ) {
    throw new Error("INVALID_COLLECTION_MANIFEST_SCHEMA");
  }
  return value;
}

async function processCollectionManifest(object, identity) {
  const workspaceId = await defaultWorkspaceId();
  const { content, parsed } = await readEvidenceObject(object);
  const manifest = validateCollectionManifest(parsed, identity.runId);
  const checksum = createHash("sha256").update(content).digest("hex");
  const summary = manifest.summary ?? {};
  await transaction(async (transactionId) => {
    await sql(
      `INSERT INTO organization_collection_runs
        (workspace_id, run_id, status, manifest_bucket, manifest_key,
         manifest_checksum_sha256, accounts_expected, accounts_succeeded,
         accounts_partial, accounts_failed, accounts_incomplete, regions_expected,
         regions_succeeded, regions_failed, regions_incomplete, security_group_count,
         security_group_rule_count, coverage_percent, started_at,
         completed_at, ingested_at)
       VALUES (CAST(:workspaceId AS uuid), CAST(:runId AS uuid), :status,
         :bucket, :key, :checksum, :accountsExpected, :accountsSucceeded,
         :accountsPartial, :accountsFailed, :accountsIncomplete, :regionsExpected,
         :regionsSucceeded, :regionsFailed, :regionsIncomplete, :securityGroupCount,
         :securityGroupRuleCount, :coveragePercent,
         CAST(:startedAt AS timestamptz), CAST(:completedAt AS timestamptz), now())
       ON CONFLICT (workspace_id, run_id) DO UPDATE SET
         status = excluded.status, manifest_bucket = excluded.manifest_bucket,
         manifest_key = excluded.manifest_key,
         manifest_checksum_sha256 = excluded.manifest_checksum_sha256,
         accounts_expected = excluded.accounts_expected,
         accounts_succeeded = excluded.accounts_succeeded,
         accounts_partial = excluded.accounts_partial,
         accounts_failed = excluded.accounts_failed,
         accounts_incomplete = excluded.accounts_incomplete,
         regions_expected = excluded.regions_expected,
         regions_succeeded = excluded.regions_succeeded,
         regions_failed = excluded.regions_failed,
         regions_incomplete = excluded.regions_incomplete,
         security_group_count = excluded.security_group_count,
         security_group_rule_count = excluded.security_group_rule_count,
         coverage_percent = excluded.coverage_percent,
         started_at = excluded.started_at, completed_at = excluded.completed_at,
         ingested_at = now()`,
      {
        workspaceId,
        runId: identity.runId,
        status: manifest.status,
        bucket: object.bucket,
        key: object.key,
        checksum,
        accountsExpected: integer(summary.accountsExpected, 100_000),
        accountsSucceeded: integer(summary.accountsSucceeded, 100_000),
        accountsPartial: integer(summary.accountsPartial, 100_000),
        accountsFailed: integer(summary.accountsFailed, 100_000),
        accountsIncomplete: integer(summary.accountsIncomplete, 100_000),
        regionsExpected: integer(summary.regionsExpected, 1_000_000),
        regionsSucceeded: integer(summary.regionsSucceeded, 1_000_000),
        regionsFailed: integer(summary.regionsFailed, 1_000_000),
        regionsIncomplete: integer(summary.regionsIncomplete, 1_000_000),
        securityGroupCount: integer(summary.securityGroupCount, 100_000_000),
        securityGroupRuleCount: integer(summary.securityGroupRuleCount, 500_000_000),
        coveragePercent: Math.max(0, Math.min(100, Number(manifest.coveragePercent ?? 0))),
        startedAt: String(manifest.startedAt),
        completedAt: String(manifest.completedAt),
      },
      transactionId,
    );
    const targetRows = manifest.targets.map((target) => ({
      workspaceId,
      runId: identity.runId,
      accountId: String(target.accountId ?? ""),
      accountName: String(target.accountName ?? target.accountId ?? "").slice(0, 160),
      region: String(target.region ?? ""),
      status: ["succeeded", "failed", "incomplete"].includes(target.status)
        ? target.status
        : "incomplete",
      objectKey: String(target.objectKey ?? "").slice(0, 1024),
      checksum: String(target.checksumSha256 ?? "").slice(0, 64),
      groupCount: integer(target.securityGroupCount, 100_000),
      ruleCount: integer(target.securityGroupRuleCount, 1_000_000),
      interfaceCount: integer(target.networkInterfaceCount, 10_000_000),
      errorCode: String(target.errorCode ?? "").slice(0, 120),
      completedAt: String(target.completedAt || manifest.completedAt),
    }));
    await batchSql(
      `INSERT INTO organization_collection_targets
        (workspace_id, run_id, account_id, account_name, region, status,
         object_key, checksum_sha256, security_group_count,
         security_group_rule_count, network_interface_count, error_code,
         completed_at)
       VALUES (CAST(:workspaceId AS uuid), CAST(:runId AS uuid), :accountId,
         :accountName, :region, :status, :objectKey, :checksum, :groupCount,
         :ruleCount, :interfaceCount, :errorCode,
         CAST(:completedAt AS timestamptz))
       ON CONFLICT (workspace_id, run_id, account_id, region) DO UPDATE SET
         account_name = excluded.account_name, status = excluded.status,
         object_key = excluded.object_key,
         checksum_sha256 = excluded.checksum_sha256,
         security_group_count = excluded.security_group_count,
         security_group_rule_count = excluded.security_group_rule_count,
         network_interface_count = excluded.network_interface_count,
         error_code = excluded.error_code, completed_at = excluded.completed_at`,
      targetRows,
      transactionId,
    );
  });
  return { duplicate: false, targets: manifest.targets.length };
}

async function processRecord(record) {
  const object = extractS3(record);
  if (object.size > MAX_COMPRESSED_BYTES) throw new Error("OBJECT_TOO_LARGE");
  if (organizationEvidenceBucket && object.bucket === organizationEvidenceBucket) {
    const shardMatch = object.key.match(
      /^runs\/([a-f0-9-]{36})\/shards\/account=([0-9]{12})\/region=([a-z0-9-]+-[0-9])\/inventory\.json\.gz$/,
    );
    if (shardMatch) {
      return processInventoryShard(object, {
        runId: shardMatch[1],
        accountId: shardMatch[2],
        region: shardMatch[3],
      });
    }
    const manifestMatch = object.key.match(
      /^runs\/([a-f0-9-]{36})\/manifest\.json$/,
    );
    if (manifestMatch) {
      return processCollectionManifest(object, { runId: manifestMatch[1] });
    }
    throw new Error("UNSUPPORTED_ORGANIZATION_EVIDENCE_KEY");
  }
  const source = await findSource(object.bucket, object.key);
  const ledger = await sql(
    `INSERT INTO ingested_objects
      (source_id, bucket_name, object_key, version_id, etag, status, object_size)
     VALUES (CAST(:sourceId AS uuid), :bucket, :key, :versionId, :etag, 'processing', :size)
     ON CONFLICT (source_id, object_key, version_id) DO NOTHING
     RETURNING id::text`,
    { sourceId: source.id, ...object },
  );
  const objectId = fieldString(ledger.records?.[0]?.[0]);
  if (!objectId) return { duplicate: true };
  try {
    const s3 = await sourceS3(source);
    const response = await s3.send(new GetObjectCommand({
      Bucket: object.bucket,
      Key: object.key,
      VersionId: object.versionId || undefined,
    }));
    const compressed = await bodyBuffer(response.Body);
    const content = object.key.endsWith(".gz")
      ? gunzipSync(compressed, { maxOutputLength: MAX_DECOMPRESSED_BYTES })
      : compressed;
    if (content.length > MAX_DECOMPRESSED_BYTES) throw new Error("DECOMPRESSED_OBJECT_TOO_LARGE");
    let records;
    if (GENERIC_SOURCE_CLASSES.has(source.sourceType)) {
      records = extractGenericRecords(content, source.sourceType);
    } else {
      const parsed = JSON.parse(content.toString("utf8"));
      records = Array.isArray(parsed)
        ? parsed
        : parsed.Records ?? parsed.configurationItems ?? parsed.ConfigSnapshot ?? [parsed];
    }
    if (!Array.isArray(records) || records.length > MAX_RECORDS) throw new Error("INVALID_RECORD_COUNT");
    if (source.sourceType === "cloudtrail") {
      await insertCloudTrail(source, objectId, records.flatMap(normalizeCloudTrail));
    } else if (source.sourceType === "config-history" || source.sourceType === "config-snapshot") {
      await insertConfig(source, objectId, records.map(normalizeConfig).filter(Boolean));
    } else {
      await insertGenericEvidence(source, objectId, records);
    }
    const checksum = createHash("sha256").update(content).digest("hex");
    await sql(
      `UPDATE ingested_objects SET status = 'processed', record_count = :count,
       checksum_sha256 = :checksum, processed_at = now() WHERE id = CAST(:id AS uuid)`,
      { id: objectId, count: records.length, checksum },
    );
    await sql(
      `UPDATE ingestion_sources SET last_successful_object_at = now(),
       updated_at = now() WHERE id = CAST(:id AS uuid)`,
      { id: source.id },
    );
    if (object.runId) {
      await sql(
        `UPDATE ingestion_runs
            SET processed_objects = processed_objects + 1,
                parsed_records = parsed_records + :records,
                status = CASE
                  WHEN cursor = ''
                   AND processed_objects + failed_objects + 1 >= discovered_objects
                  THEN 'completed'
                  ELSE 'running'
                END,
                completed_at = CASE
                  WHEN cursor = ''
                   AND processed_objects + failed_objects + 1 >= discovered_objects
                  THEN now()
                  ELSE completed_at
                END
          WHERE id = CAST(:id AS uuid)`,
        { id: object.runId, records: records.length },
      );
    }
    return { duplicate: false, records: records.length };
  } catch (error) {
    await sql(
      `UPDATE ingested_objects SET status = 'failed', failure_code = :code,
       failure_detail = :detail, processed_at = now() WHERE id = CAST(:id AS uuid)`,
      {
        id: objectId,
        code: error instanceof Error ? error.message.slice(0, 120) : "UNKNOWN",
        detail: "Object processing failed. See the Lambda request log for the correlated request ID.",
      },
    );
    throw error;
  }
}

export async function handler(event) {
  const failures = [];
  for (const record of event.Records ?? []) {
    try {
      await processRecord(record);
    } catch (error) {
      console.error(JSON.stringify({
        message: "Gatewatch ingestion failed",
        messageId: record.messageId,
        error: error instanceof Error ? error.message : "Unknown error",
      }));
      failures.push({ itemIdentifier: record.messageId });
    }
  }
  return { batchItemFailures: failures };
}
