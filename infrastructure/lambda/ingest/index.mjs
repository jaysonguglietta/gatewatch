import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { AssumeRoleCommand, STSClient } from "@aws-sdk/client-sts";
import {
  BatchExecuteStatementCommand,
  ExecuteStatementCommand,
  RDSDataClient,
} from "@aws-sdk/client-rds-data";

const MAX_COMPRESSED_BYTES = 50 * 1024 * 1024;
const MAX_DECOMPRESSED_BYTES = 256 * 1024 * 1024;
const MAX_RECORDS = 100_000;
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

const rds = new RDSDataClient({});
const sts = new STSClient({});
const database = process.env.DATABASE_NAME;
const resourceArn = process.env.DB_CLUSTER_ARN;
const secretArn = process.env.DB_SECRET_ARN;

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

async function sql(statement, values = {}) {
  return rds.send(
    new ExecuteStatementCommand({
      database,
      resourceArn,
      secretArn,
      sql: statement,
      parameters: parameters(values),
      includeResultMetadata: true,
    }),
  );
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

async function processRecord(record) {
  const object = extractS3(record);
  if (object.size > MAX_COMPRESSED_BYTES) throw new Error("OBJECT_TOO_LARGE");
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
    const parsed = JSON.parse(content.toString("utf8"));
    const records = Array.isArray(parsed)
      ? parsed
      : parsed.Records ?? parsed.configurationItems ?? parsed.ConfigSnapshot ?? [parsed];
    if (!Array.isArray(records) || records.length > MAX_RECORDS) throw new Error("INVALID_RECORD_COUNT");
    if (source.sourceType === "cloudtrail") {
      await insertCloudTrail(source, objectId, records.flatMap(normalizeCloudTrail));
    } else {
      await insertConfig(source, objectId, records.map(normalizeConfig).filter(Boolean));
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
