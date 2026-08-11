import { createHash, randomUUID } from "node:crypto";
import {
  BeginTransactionCommand,
  CommitTransactionCommand,
  ExecuteStatementCommand,
  RDSDataClient,
  RollbackTransactionCommand,
} from "@aws-sdk/client-rds-data";
import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";

const rds = new RDSDataClient({});
const s3 = new S3Client({});
const database = required("DATABASE_NAME");
const resourceArn = required("DB_CLUSTER_ARN");
const secretArn = required("DB_SECRET_ARN");
const workspaceId = required("WORKSPACE_ID");
const archiveBucket = required("AUDIT_ARCHIVE_BUCKET");
const batchSize = boundedInteger(process.env.RETENTION_BATCH_SIZE ?? "500", 1, 5000);
const maxBatches = boundedInteger(process.env.RETENTION_MAX_BATCHES ?? "20", 1, 100);

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`MISSING_${name}`);
  return value;
}

function boundedInteger(value, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error("INVALID_MAINTENANCE_LIMIT");
  }
  return parsed;
}

function parameters(values) {
  return Object.entries(values).map(([name, value]) => ({
    name,
    value: typeof value === "number"
      ? { longValue: value }
      : { stringValue: String(value) },
  }));
}

async function statement(sql, values = {}, transactionId, formatRecordsAs) {
  return rds.send(new ExecuteStatementCommand({
    database,
    resourceArn,
    secretArn,
    sql,
    parameters: parameters(values),
    transactionId,
    formatRecordsAs,
  }));
}

async function transaction(callback) {
  const begun = await rds.send(new BeginTransactionCommand({
    database,
    resourceArn,
    secretArn,
  }));
  if (!begun.transactionId) throw new Error("DATABASE_TRANSACTION_UNAVAILABLE");
  try {
    await statement(
      "SELECT set_config('app.workspace_id', :workspaceId, true)",
      { workspaceId },
      begun.transactionId,
    );
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

async function pendingAuditEvents() {
  return transaction(async (transactionId) => {
    const result = await statement(
      `SELECT event.id::text, event.actor, event.action, event.target_type,
              event.target_id, event.summary, event.metadata, event.created_at
         FROM audit_events event
         LEFT JOIN audit_archive_ledger archive
           ON archive.workspace_id = event.workspace_id
          AND archive.audit_event_id = event.id
        WHERE event.workspace_id = CAST(:workspaceId AS uuid)
          AND archive.audit_event_id IS NULL
        ORDER BY event.created_at, event.id
        LIMIT 1000`,
      { workspaceId },
      transactionId,
      "JSON",
    );
    return JSON.parse(result.formattedRecords ?? "[]");
  });
}

async function archiveAuditEvents(events) {
  if (!events.length) return { archived: 0, key: "" };
  const body = Buffer.from(`${events.map((event) => JSON.stringify(event)).join("\n")}\n`);
  const digest = createHash("sha256").update(body).digest("hex");
  const date = String(events[0].created_at ?? new Date().toISOString()).slice(0, 10);
  const key = `audit/workspace=${workspaceId}/date=${date}/${digest}.jsonl`;
  const archived = await s3.send(new PutObjectCommand({
    Bucket: archiveBucket,
    Key: key,
    Body: body,
    ContentType: "application/x-ndjson",
    ChecksumSHA256: createHash("sha256").update(body).digest("base64"),
    Metadata: {
      "content-sha256": digest,
      "event-count": String(events.length),
      "workspace-id": workspaceId,
    },
  }));
  if (!archived.VersionId) throw new Error("AUDIT_ARCHIVE_VERSION_REQUIRED");

  await transaction(async (transactionId) => {
    for (const event of events) {
      await statement(
        `INSERT INTO audit_archive_ledger
          (workspace_id, audit_event_id, archive_bucket, archive_key,
           archive_version_id, content_sha256)
         VALUES (CAST(:workspaceId AS uuid), CAST(:eventId AS uuid), :bucket,
           :key, :versionId, :digest)
         ON CONFLICT (workspace_id, audit_event_id) DO NOTHING`,
        {
          workspaceId,
          eventId: event.id,
          bucket: archiveBucket,
          key,
          versionId: archived.VersionId,
          digest,
        },
        transactionId,
      );
    }
  });
  return { archived: events.length, key, digest };
}

async function enforceRetention() {
  const batches = [];
  for (let index = 0; index < maxBatches; index += 1) {
    const runId = randomUUID();
    let result;
    try {
      result = await transaction((transactionId) => statement(
        "SELECT gatewatch_apply_retention_batch(CAST(:workspaceId AS uuid), CAST(:runId AS uuid), :batchSize)::text AS counts",
        { workspaceId, runId, batchSize },
        transactionId,
        "JSON",
      ));
    } catch (error) {
      await transaction((transactionId) => statement(
        `INSERT INTO retention_execution_runs
          (id, workspace_id, status, error_code, completed_at)
         VALUES (CAST(:runId AS uuid), CAST(:workspaceId AS uuid), 'failed', :error, now())
         ON CONFLICT (id) DO UPDATE SET status = 'failed', error_code = excluded.error_code,
           completed_at = excluded.completed_at`,
        {
          runId,
          workspaceId,
          error: `${error instanceof Error ? error.name : "Error"}:${error instanceof Error ? error.message : "unknown"}`.slice(0, 500),
        },
        transactionId,
      ));
      throw error;
    }
    const row = JSON.parse(result.formattedRecords ?? "[]")[0] ?? {};
    const counts = JSON.parse(row.counts ?? "{}");
    batches.push({ runId, counts });
    const deleted = Object.values(counts).reduce(
      (total, value) => total + (Number.isFinite(Number(value)) ? Number(value) : 0),
      0,
    );
    if (counts.held || deleted === 0) break;
  }
  return batches;
}

export async function handler() {
  const events = await pendingAuditEvents();
  const archive = await archiveAuditEvents(events);
  const retention = await enforceRetention();
  console.log(JSON.stringify({
    event: "gatewatch.governance_maintenance.completed",
    workspaceId,
    archived: archive.archived,
    retentionBatches: retention.length,
  }));
  return { workspaceId, archive, retention };
}
