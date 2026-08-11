import { ListObjectsV2Command, S3Client } from "@aws-sdk/client-s3";
import { SendMessageBatchCommand, SQSClient } from "@aws-sdk/client-sqs";
import { AssumeRoleCommand, STSClient } from "@aws-sdk/client-sts";
import {
  BeginTransactionCommand,
  CommitTransactionCommand,
  ExecuteStatementCommand,
  RDSDataClient,
  RollbackTransactionCommand,
} from "@aws-sdk/client-rds-data";

const rds = new RDSDataClient({});
const sts = new STSClient({});
const sqs = new SQSClient({});
const database = process.env.DATABASE_NAME;
const resourceArn = process.env.DB_CLUSTER_ARN;
const secretArn = process.env.DB_SECRET_ARN;
const queueUrl = process.env.INGESTION_QUEUE_URL;
const workspaceId = process.env.WORKSPACE_ID;
const SUPPORTED_EVIDENCE_SUFFIXES = [
  ".json",
  ".json.gz",
  ".log",
  ".log.gz",
  ".txt",
  ".txt.gz",
  ".csv",
  ".tsv",
];

if (!database || !resourceArn || !secretArn || !queueUrl || !workspaceId) {
  throw new Error("BACKFILL_RUNTIME_CONFIGURATION_REQUIRED");
}

function parameters(values) {
  return Object.entries(values).map(([name, value]) => ({
    name,
    value: typeof value === "number"
      ? { longValue: value }
      : typeof value === "boolean"
        ? { booleanValue: value }
        : { stringValue: String(value) },
  }));
}

async function transaction(callback) {
  const begun = await rds.send(new BeginTransactionCommand({ database, resourceArn, secretArn }));
  if (!begun.transactionId) throw new Error("DATABASE_TRANSACTION_UNAVAILABLE");
  try {
    await rds.send(new ExecuteStatementCommand({
      database,
      resourceArn,
      secretArn,
      transactionId: begun.transactionId,
      sql: "SELECT set_config('app.workspace_id', :workspaceId, true)",
      parameters: parameters({ workspaceId }),
    }));
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

function fieldString(field) {
  return field?.stringValue ?? "";
}

async function sourceById(sourceId) {
  const result = await transaction((transactionId) =>
    rds.send(new ExecuteStatementCommand({
      database,
      resourceArn,
      secretArn,
      transactionId,
      sql: `SELECT bucket_name, object_prefix, region, role_arn, external_id,
                 backfill_start::text
            FROM ingestion_sources
           WHERE workspace_id = CAST(:workspaceId AS uuid)
             AND id = CAST(:id AS uuid)
             AND status IN ('live', 'backfilling')`,
      parameters: parameters({ workspaceId, id: sourceId }),
    })));
  const row = result.records?.[0];
  if (!row) throw new Error("BACKFILL_SOURCE_NOT_ACTIVE");
  return {
    bucket: fieldString(row[0]),
    prefix: fieldString(row[1]),
    region: fieldString(row[2]),
    roleArn: fieldString(row[3]),
    externalId: fieldString(row[4]),
    startDate: fieldString(row[5]),
  };
}

async function sourceS3(source) {
  const assumed = await sts.send(new AssumeRoleCommand({
    RoleArn: source.roleArn,
    RoleSessionName: `gatewatch-backfill-${Date.now()}`,
    ExternalId: source.externalId || undefined,
    DurationSeconds: 900,
  }));
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

async function enqueue(source, objects, runId) {
  for (let offset = 0; offset < objects.length; offset += 10) {
    const batch = objects.slice(offset, offset + 10);
    const result = await sqs.send(new SendMessageBatchCommand({
      QueueUrl: queueUrl,
      Entries: batch.map((item, index) => ({
        Id: `${offset + index}`,
        MessageBody: JSON.stringify({
          version: "0",
          id: `backfill-${Date.now()}-${offset + index}`,
          "detail-type": "Object Created",
          source: "gatewatch.backfill",
          time: new Date().toISOString(),
          detail: {
            bucket: { name: source.bucket },
            object: {
              key: item.Key,
              size: item.Size ?? 0,
              etag: item.ETag?.replaceAll('"', "") ?? "",
            },
            gatewatch: { runId },
          },
        }),
      })),
    }));
    if (result.Failed?.length) {
      throw new Error(`SQS_BATCH_FAILURE:${result.Failed.map((item) => item.Code).join(",")}`);
    }
  }
}

async function updateRun(runId, discovered, done, cursor) {
  await transaction((transactionId) => rds.send(new ExecuteStatementCommand({
      database,
      resourceArn,
      secretArn,
      transactionId,
      sql: `UPDATE ingestion_runs
             SET discovered_objects = discovered_objects + :discovered,
                 cursor = :cursor,
                 status = CASE WHEN :done THEN 'running' ELSE status END
           WHERE workspace_id = CAST(:workspaceId AS uuid)
             AND id = CAST(:id AS uuid)`,
      parameters: parameters({ workspaceId, discovered, cursor: cursor ?? "", done, id: runId }),
    })));
}

export async function handler(event) {
  const source = await sourceById(event.sourceId);
  const s3 = await sourceS3(source);
  const result = await s3.send(new ListObjectsV2Command({
    Bucket: source.bucket,
    Prefix: source.prefix || undefined,
    ContinuationToken: event.cursor || undefined,
    MaxKeys: 1000,
  }));
  const startTime = source.startDate
    ? new Date(`${source.startDate}T00:00:00Z`).getTime()
    : 0;
  const objects = (result.Contents ?? []).filter(
    (item) =>
      item.Key &&
      (!item.LastModified || item.LastModified.getTime() >= startTime) &&
      SUPPORTED_EVIDENCE_SUFFIXES.some((suffix) => item.Key.toLowerCase().endsWith(suffix)),
  );
  await enqueue(source, objects, event.runId);
  const cursor = result.NextContinuationToken ?? "";
  const done = !cursor;
  await updateRun(event.runId, objects.length, done, cursor);
  return {
    sourceId: event.sourceId,
    runId: event.runId,
    cursor,
    done,
    discovered: objects.length,
  };
}
