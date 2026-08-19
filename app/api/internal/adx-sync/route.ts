import { timingSafeEqual } from "node:crypto";
import { env } from "cloudflare:workers";
import { syncAdxSource, type AdxSyncOutcome } from "../../../../lib/adx-ingestion";
import type { IngestionSource } from "../../../../lib/admin-sources";
import { enqueueAdxSources } from "../../../../lib/azure-data-explorer";
import { evaluateAdxFreshness } from "../../../../lib/adx-freshness";
import { HttpInputError, readBoundedJson } from "../../../../lib/http-security";
import { apiJson, audit, auditMany, ensureAdminSchema, safeJson } from "../../../../lib/server-admin";

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
            adx_client_id AS adxClientId, adx_auth_mode AS adxAuthMode,
            adx_schema AS adxSchema, adx_schema_discovered_at AS adxSchemaDiscoveredAt,
            adx_mapping_validated_at AS adxMappingValidatedAt,
            adx_cursor_value AS adxCursorValue, adx_lease_owner AS adxLeaseOwner,
            adx_lease_expires_at AS adxLeaseExpiresAt,
            freshness_sla_minutes AS freshnessSlaMinutes,
            freshness_status AS freshnessStatus, freshness_checked_at AS freshnessCheckedAt,
            freshness_lag_minutes AS freshnessLagMinutes,
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
    adxSchema: safeJson(row.adxSchema, undefined),
  } as unknown as IngestionSource;
}

async function syncOne(sourceId: string) {
  const source = await sourceById(sourceId);
  if (!source || source.provider !== "azure-data-explorer" || !["live", "degraded"].includes(source.status)) {
    return apiJson({ skipped: true, reason: "Source is not active." }, 202);
  }
  try {
    const outcome: AdxSyncOutcome = await syncAdxSource(source, "gatewatch-adx-worker", "continuous");
    await audit(
      "gatewatch-adx-worker",
      "adx.sync.completed",
      "ingestion_run",
      outcome.runId,
      `Distributed ADX sync imported ${outcome.normalized} normalized records from ${source.name}.`,
      { sourceId: source.id, fetched: outcome.fetched, skipped: outcome.skipped },
    );
    return apiJson({ sourceId, outcome });
  } catch (error) {
    if (error instanceof Error && error.message === "ADX_SOURCE_BUSY") {
      return apiJson({ sourceId, skipped: true, reason: "Another worker owns the source lease." }, 202);
    }
    console.error(JSON.stringify({ event: "adx_sync_failed", sourceId }));
    return apiJson({ error: "Azure Data Explorer synchronization failed." }, 503);
  }
}

export async function POST(request: Request) {
  if (!authorized(request)) return apiJson({ error: "Authentication is required." }, 401);
  try {
    await ensureAdminSchema();
    const payload = await readBoundedJson(request, 4_096);
    const sourceId = typeof payload.sourceId === "string" ? payload.sourceId.slice(0, 80) : "";
    if (sourceId) {
      if (!/^src-[a-f0-9-]{36}$/.test(sourceId)) return apiJson({ error: "Source ID is invalid." }, 400);
      return syncOne(sourceId);
    }
    const freshness = await evaluateAdxFreshness();
    if (freshness.breached) {
      // Emitting one aggregate sample per scheduler cycle keeps the CloudWatch
      // alarm in ALARM until every source recovers. Alarm actions still fire
      // only on the CloudWatch state transition.
      console.log(JSON.stringify({ event: "adx_freshness_breached", breached: freshness.breached }));
    }
    for (const transition of freshness.transitions) {
      console.log(JSON.stringify({ event: "adx_freshness_state_changed", ...transition }));
    }
    await auditMany(freshness.transitions.map((transition) => ({
      actor: "gatewatch-adx-scheduler",
      action: `adx.freshness.${transition.to}`,
      targetType: "ingestion_source",
      targetId: transition.sourceId,
      summary: `${transition.sourceName} freshness changed from ${transition.from} to ${transition.to}.`,
      metadata: transition,
    })));
    const sourceRows = await env.DB.prepare(
      `SELECT id FROM ingestion_sources
       WHERE workspace_id = 'default' AND provider = 'azure-data-explorer'
         AND status = 'live'
       ORDER BY updated_at LIMIT 2000`,
    ).all<{ id: string }>();
    const queued = await enqueueAdxSources(sourceRows.results.map((item) => item.id));
    return apiJson({ selected: sourceRows.results.length, queued: queued.queued, freshness });
  } catch (error) {
    if (error instanceof HttpInputError) return apiJson({ error: error.message }, error.status);
    console.error(JSON.stringify({ event: "adx_sync_failed", failed: -1 }));
    return apiJson({ error: "Azure Data Explorer synchronization is temporarily unavailable." }, 503);
  }
}
