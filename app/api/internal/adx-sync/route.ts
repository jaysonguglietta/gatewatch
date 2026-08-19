import { timingSafeEqual } from "node:crypto";
import { env } from "cloudflare:workers";
import { syncAdxSource, type AdxSyncOutcome } from "../../../../lib/adx-ingestion";
import type { IngestionSource } from "../../../../lib/admin-sources";
import { apiJson, audit, ensureAdminSchema, safeJson } from "../../../../lib/server-admin";

export const runtime = "nodejs";

function authorized(request: Request) {
  const expected = `Bearer ${env.GATEWATCH_AWS_BRIDGE_TOKEN ?? ""}`;
  const actual = request.headers.get("authorization") ?? "";
  const expectedBytes = Buffer.from(expected);
  const actualBytes = Buffer.from(actual);
  return expectedBytes.length > 7
    && actualBytes.length === expectedBytes.length
    && timingSafeEqual(actualBytes, expectedBytes);
}

async function sourceById(id: string) {
  const row = await env.DB.prepare(
    `SELECT id, name, provider, source_type AS sourceType,
            bucket_arn AS bucketArn, bucket_name AS bucketName, region,
            object_prefix AS objectPrefix, role_arn AS roleArn,
            external_id AS externalId, kms_key_arn AS kmsKeyArn,
            organization_id AS organizationId, ingestion_mode AS ingestionMode,
            backfill_start AS backfillStart, included_accounts AS includedAccounts,
            excluded_accounts AS excludedAccounts, included_regions AS includedRegions,
            config_resource_types AS configResourceTypes,
            adx_cluster_url AS adxClusterUrl, adx_database AS adxDatabase,
            adx_table AS adxTable, adx_timestamp_column AS adxTimestampColumn,
            adx_payload_column AS adxPayloadColumn, adx_query_mode AS adxQueryMode,
            adx_batch_size AS adxBatchSize, adx_tenant_id AS adxTenantId,
            adx_client_id AS adxClientId, adx_cursor_value AS adxCursorValue,
            retention_days AS retentionDays, status,
            test_summary AS testSummary, last_tested_at AS lastTestedAt,
            last_successful_object_at AS lastSuccessfulObjectAt,
            created_by AS createdBy, created_at AS createdAt, updated_at AS updatedAt
       FROM ingestion_sources WHERE id = ? AND workspace_id = 'default'`,
  ).bind(id).first<Record<string, unknown>>();
  if (!row) return null;
  return {
    ...row,
    includedAccounts: safeJson(row.includedAccounts, []),
    excludedAccounts: safeJson(row.excludedAccounts, []),
    includedRegions: safeJson(row.includedRegions, []),
    configResourceTypes: safeJson(row.configResourceTypes, []),
    testSummary: safeJson(row.testSummary, undefined),
  } as unknown as IngestionSource;
}

export async function POST(request: Request) {
  if (!authorized(request)) return apiJson({ error: "Authentication is required." }, 401);
  try {
    await ensureAdminSchema();
    const sourceRows = await env.DB.prepare(
      `SELECT id FROM ingestion_sources
       WHERE workspace_id = 'default' AND provider = 'azure-data-explorer'
         AND status = 'live'
       ORDER BY updated_at LIMIT 20`,
    ).all<{ id: string }>();
    const outcomes: Array<AdxSyncOutcome & { sourceId: string }> = [];
    let failed = 0;
    for (let offset = 0; offset < sourceRows.results.length; offset += 5) {
      await Promise.all(sourceRows.results.slice(offset, offset + 5).map(async (item) => {
        const source = await sourceById(item.id);
        if (!source) return;
        try {
          const outcome = await syncAdxSource(source, "gatewatch-adx-scheduler", "continuous");
          outcomes.push({ sourceId: source.id, ...outcome });
          await audit(
            "gatewatch-adx-scheduler",
            "adx.sync.completed",
            "ingestion_run",
            outcome.runId,
            `Scheduled ADX sync imported ${outcome.normalized} normalized records from ${source.name}.`,
            { sourceId: source.id, fetched: outcome.fetched, skipped: outcome.skipped },
          );
        } catch {
          failed += 1;
        }
      }));
    }
    if (failed) {
      console.error(JSON.stringify({ event: "adx_sync_failed", failed, selected: sourceRows.results.length }));
    }
    return apiJson(
      { selected: sourceRows.results.length, completed: outcomes.length, failed, outcomes },
      failed ? 503 : 200,
    );
  } catch {
    console.error(JSON.stringify({ event: "adx_sync_failed", failed: -1 }));
    return apiJson({ error: "Azure Data Explorer synchronization is temporarily unavailable." }, 503);
  }
}
