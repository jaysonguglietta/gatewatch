import { env } from "cloudflare:workers";
import type { IngestionSource } from "./admin-sources";
import { sourceTypeDefinition } from "./admin-sources";
import { queryAdxSource } from "./azure-data-explorer";
import { parseAwsEvidenceText } from "./aws-evidence-import";
import { canonicalJson, sha256Hex } from "./security-integrity";

const MAX_NORMALIZED_PAYLOAD_BYTES = 64 * 1024;

export type AdxSyncOutcome = {
  runId: string;
  fetched: number;
  normalized: number;
  skipped: number;
  checkpoint: string;
  warnings: string[];
};

type AdxRunType = "continuous" | "backfill" | "retry";

function initialCheckpoint(source: IngestionSource, runType: AdxRunType) {
  if (runType === "backfill" && source.backfillStart && /^\d{4}-\d{2}-\d{2}$/.test(source.backfillStart)) {
    return { timestamp: `${source.backfillStart}T00:00:00.000Z`, cursor: "" };
  }
  if (source.lastSuccessfulObjectAt && Number.isFinite(Date.parse(source.lastSuccessfulObjectAt))) {
    return { timestamp: new Date(source.lastSuccessfulObjectAt).toISOString(), cursor: source.adxCursorValue };
  }
  if (source.backfillStart && /^\d{4}-\d{2}-\d{2}$/.test(source.backfillStart)) {
    return { timestamp: `${source.backfillStart}T00:00:00.000Z`, cursor: "" };
  }
  return { timestamp: new Date(Date.now() - 5 * 60_000).toISOString(), cursor: "" };
}

export async function syncAdxSource(
  source: IngestionSource,
  actor: string,
  runType: AdxRunType = "continuous",
): Promise<AdxSyncOutcome> {
  if (source.provider !== "azure-data-explorer") {
    throw new Error("Only Azure Data Explorer sources can use the ADX synchronizer.");
  }
  if (source.status !== "live" && runType !== "backfill") {
    throw new Error("Activate the Azure Data Explorer source before synchronizing it.");
  }
  if (!source.testSummary?.passed || source.testSummary.mode !== "live") {
    throw new Error("A successful live Azure Data Explorer connection test is required.");
  }

  const runId = `run-${crypto.randomUUID()}`;
  await env.DB.prepare(
    `INSERT INTO ingestion_runs
      (id, source_id, run_type, status, requested_by)
     VALUES (?, ?, ?, 'running', ?)`,
  ).bind(runId, source.id, runType, actor).run();

  try {
    const checkpoint = initialCheckpoint(source, runType);
    const query = await queryAdxSource(source, "sync", checkpoint.timestamp, checkpoint.cursor);
    let normalized: ReturnType<typeof parseAwsEvidenceText>["records"] = [];
    let skipped = query.skippedRows;
    let warnings: string[] = [];
    if (query.records.length) {
      const parsed = parseAwsEvidenceText(JSON.stringify(query.records), source.sourceType);
      normalized = parsed.records.filter((record) =>
        (!source.includedAccounts.length || source.includedAccounts.includes(record.accountId)) &&
        (!source.excludedAccounts.includes(record.accountId)) &&
        (!source.includedRegions.length || source.includedRegions.includes(record.region))
      );
      skipped = parsed.skippedRecords;
      skipped += parsed.records.length - normalized.length;
      warnings = parsed.warnings;
    }

    const statements = [];
    let accepted = 0;
    for (const record of normalized) {
      const payloadObject = {
        source: record.source,
        destination: record.destination,
        summary: record.summary,
        provenance: {
          provider: "azure-data-explorer",
          cluster: source.adxClusterUrl,
          database: source.adxDatabase,
          table: source.adxTable,
        },
        aws: record.raw,
      };
      const normalizedPayload = canonicalJson(payloadObject);
      if (new TextEncoder().encode(normalizedPayload).byteLength > MAX_NORMALIZED_PAYLOAD_BYTES) {
        skipped += 1;
        continue;
      }
      const fingerprint = await sha256Hex(canonicalJson({
        sourceId: source.id,
        sourceType: source.sourceType,
        recordId: record.id,
        observedAt: record.observedAt,
        raw: record.raw,
      }));
      statements.push(
        env.DB.prepare(
          `INSERT INTO aws_evidence_records
            (fingerprint, workspace_id, source_id, raw_object_id, source_type,
             evidence_class, observed_at, account_id, region, resource_type,
             resource_id, event_name, disposition, normalized_payload)
           VALUES (?, 'default', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(fingerprint) DO NOTHING`,
        ).bind(
          fingerprint,
          source.id,
          `adx:${source.adxDatabase}/${source.adxTable}:${fingerprint.slice(0, 24)}`,
          source.sourceType,
          sourceTypeDefinition(source.sourceType).evidenceClass,
          record.observedAt,
          record.accountId,
          record.region,
          "",
          record.resource,
          record.event,
          record.disposition,
          normalizedPayload,
        ),
      );
      accepted += 1;
      if (statements.length === 25) {
        await env.DB.batch(statements.splice(0));
      }
    }
    if (statements.length) await env.DB.batch(statements);

    const nextCheckpoint = query.nextCheckpoint && Number.isFinite(Date.parse(query.nextCheckpoint))
      ? new Date(query.nextCheckpoint).toISOString()
      : checkpoint.timestamp;
    const nextCursor = query.nextCursor || checkpoint.cursor;
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE ingestion_runs SET status = 'completed', discovered_objects = 1,
            processed_objects = 1, parsed_records = ?, finding_changes = 0,
            cursor = ?, completed_at = CURRENT_TIMESTAMP
         WHERE id = ? AND source_id = ?`,
      ).bind(accepted, JSON.stringify({ timestamp: nextCheckpoint, cursor: nextCursor }), runId, source.id),
      env.DB.prepare(
        `UPDATE ingestion_sources SET status = ?,
            last_successful_object_at = ?, adx_cursor_value = ?, updated_at = CURRENT_TIMESTAMP
         WHERE id = ? AND workspace_id = 'default'`,
      ).bind(source.ingestionMode === "backfill" && !query.truncated ? "paused" : "live", nextCheckpoint, nextCursor, source.id),
    ]);
    return {
      runId,
      fetched: query.rowCount,
      normalized: accepted,
      skipped,
      checkpoint: nextCheckpoint,
      warnings,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message.slice(0, 500) : "Azure Data Explorer synchronization failed.";
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE ingestion_runs SET status = 'failed', failed_objects = 1,
            error_summary = ?, completed_at = CURRENT_TIMESTAMP
         WHERE id = ? AND source_id = ?`,
      ).bind(message, runId, source.id),
      env.DB.prepare(
        `UPDATE ingestion_sources SET status = 'degraded', updated_at = CURRENT_TIMESTAMP
         WHERE id = ? AND workspace_id = 'default'`,
      ).bind(source.id),
    ]);
    throw error;
  }
}
