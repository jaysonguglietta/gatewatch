import { env } from "cloudflare:workers";
import {
  generateExternalId,
  sourceAccessCloudFormation,
  type IngestionSource,
  validateSourceInput,
} from "../../../../lib/admin-sources";
import { testAwsSource } from "../../../../lib/aws-source-test";
import { syncAdxSource } from "../../../../lib/adx-ingestion";
import {
  configureAdxCredential,
  queryAdxSource,
  removeAdxCredential,
  testAdxSource,
} from "../../../../lib/azure-data-explorer";
import { HttpInputError, readBoundedJson } from "../../../../lib/http-security";
import {
  apiJson,
  audit,
  ensureAdminSchema,
  requireAdmin,
  safeJson,
  sameOrigin,
} from "../../../../lib/server-admin";

type SourceRow = {
  id: string;
  name: string;
  provider: IngestionSource["provider"];
  sourceType: IngestionSource["sourceType"];
  bucketArn: string;
  bucketName: string;
  region: string;
  objectPrefix: string;
  roleArn: string;
  externalId: string;
  kmsKeyArn: string;
  organizationId: string;
  ingestionMode: IngestionSource["ingestionMode"];
  backfillStart: string;
  includedAccounts: string;
  excludedAccounts: string;
  includedRegions: string;
  configResourceTypes: string;
  adxClusterUrl: string;
  adxDatabase: string;
  adxTable: string;
  adxTimestampColumn: string;
  adxPayloadColumn: string;
  adxQueryMode: IngestionSource["adxQueryMode"];
  adxBatchSize: number;
  adxTenantId: string;
  adxClientId: string;
  adxCursorValue: string;
  retentionDays: number;
  status: IngestionSource["status"];
  testSummary: string;
  lastTestedAt: string;
  lastSuccessfulObjectAt: string;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
};

function mapSource(row: SourceRow): IngestionSource {
  return {
    ...row,
    includedAccounts: safeJson(row.includedAccounts, []),
    excludedAccounts: safeJson(row.excludedAccounts, []),
    includedRegions: safeJson(row.includedRegions, []),
    configResourceTypes: safeJson(row.configResourceTypes, []),
    testSummary: safeJson(row.testSummary, undefined),
  };
}

async function sourceById(id: string) {
  const row = await env.DB.prepare(
    `SELECT id, name, provider, source_type AS sourceType, bucket_arn AS bucketArn,
            bucket_name AS bucketName, region, object_prefix AS objectPrefix,
            role_arn AS roleArn, external_id AS externalId,
            kms_key_arn AS kmsKeyArn, organization_id AS organizationId,
            ingestion_mode AS ingestionMode, backfill_start AS backfillStart,
            included_accounts AS includedAccounts,
            excluded_accounts AS excludedAccounts,
            included_regions AS includedRegions,
            config_resource_types AS configResourceTypes,
            adx_cluster_url AS adxClusterUrl, adx_database AS adxDatabase,
            adx_table AS adxTable, adx_timestamp_column AS adxTimestampColumn,
            adx_payload_column AS adxPayloadColumn, adx_query_mode AS adxQueryMode,
            adx_batch_size AS adxBatchSize, adx_tenant_id AS adxTenantId,
            adx_client_id AS adxClientId, adx_cursor_value AS adxCursorValue,
            retention_days AS retentionDays, status,
            test_summary AS testSummary, last_tested_at AS lastTestedAt,
            last_successful_object_at AS lastSuccessfulObjectAt,
            created_by AS createdBy, created_at AS createdAt,
            updated_at AS updatedAt
     FROM ingestion_sources WHERE id = ? AND workspace_id = 'default'`,
  )
    .bind(id)
    .first<SourceRow>();
  return row ? mapSource(row) : null;
}

export async function GET(request: Request) {
  try {
    const auth = await requireAdmin(request);
    if (!auth.user) return apiJson({ error: "Authentication is required." }, 401);
    if (!auth.allowed) return apiJson({ error: "Administrator access is required." }, 403);
    await ensureAdminSchema();
    const [sources, runs, audits, roles, objectStats, settings] = await env.DB.batch([
      env.DB.prepare(
        `SELECT id, name, provider, source_type AS sourceType, bucket_arn AS bucketArn,
                bucket_name AS bucketName, region, object_prefix AS objectPrefix,
                role_arn AS roleArn, external_id AS externalId,
                kms_key_arn AS kmsKeyArn, organization_id AS organizationId,
                ingestion_mode AS ingestionMode, backfill_start AS backfillStart,
                included_accounts AS includedAccounts,
                excluded_accounts AS excludedAccounts,
                included_regions AS includedRegions,
                config_resource_types AS configResourceTypes,
                adx_cluster_url AS adxClusterUrl, adx_database AS adxDatabase,
                adx_table AS adxTable, adx_timestamp_column AS adxTimestampColumn,
                adx_payload_column AS adxPayloadColumn, adx_query_mode AS adxQueryMode,
                adx_batch_size AS adxBatchSize, adx_tenant_id AS adxTenantId,
                adx_client_id AS adxClientId, adx_cursor_value AS adxCursorValue,
                retention_days AS retentionDays, status,
                test_summary AS testSummary, last_tested_at AS lastTestedAt,
                last_successful_object_at AS lastSuccessfulObjectAt,
                created_by AS createdBy, created_at AS createdAt,
                updated_at AS updatedAt
         FROM ingestion_sources WHERE workspace_id = 'default'
         ORDER BY updated_at DESC`,
      ),
      env.DB.prepare(
        `SELECT r.id, r.source_id AS sourceId, s.name AS sourceName,
                r.run_type AS runType, r.status,
                r.discovered_objects AS discoveredObjects,
                r.processed_objects AS processedObjects,
                r.failed_objects AS failedObjects,
                r.parsed_records AS parsedRecords,
                r.finding_changes AS findingChanges,
                r.error_summary AS errorSummary,
                r.requested_by AS requestedBy, r.started_at AS startedAt,
                r.completed_at AS completedAt
         FROM ingestion_runs r
         LEFT JOIN ingestion_sources s ON s.id = r.source_id
         ORDER BY r.started_at DESC LIMIT 50`,
      ),
      env.DB.prepare(
        `SELECT id, actor, action, target_type AS targetType,
                target_id AS targetId, summary, metadata,
                created_at AS createdAt
         FROM audit_events WHERE workspace_id = 'default'
         ORDER BY created_at DESC LIMIT 100`,
      ),
      env.DB.prepare(
        `SELECT email, role, created_by AS createdBy,
                created_at AS createdAt, updated_at AS updatedAt
         FROM user_roles WHERE workspace_id = 'default'
         ORDER BY role, email`,
      ),
      env.DB.prepare(
        `SELECT status, COUNT(*) AS count,
                COALESCE(SUM(object_size), 0) AS totalBytes
         FROM ingested_objects GROUP BY status`,
      ),
      env.DB.prepare(
        `SELECT key, value FROM system_settings
         WHERE workspace_id = 'default' AND key IN ('retention', 'notifications')`,
      ),
    ]);
    const settingValues = Object.fromEntries(
      settings.results.map((item) => [String(item.key), safeJson(item.value, {})]),
    );
    return apiJson({
      currentUser: { email: auth.email, subject: auth.user, role: "admin" },
      sources: (sources.results as unknown as SourceRow[]).map(mapSource),
      runs: runs.results,
      audits: audits.results.map((item) => ({
        ...item,
        metadata: safeJson(item.metadata, {}),
      })),
      roles: roles.results,
      objectStats: objectStats.results,
      settings: settingValues,
      architecture: {
        rawStore: "Amazon S3 / Azure Data Explorer",
        primaryStore: "Aurora PostgreSQL Serverless v2",
        queue: "Amazon SQS",
        workers: "AWS Lambda",
        investigation: "Amazon Athena",
        localStore: "Cloudflare D1 compatibility adapter",
      },
    });
  } catch {
    return apiJson({ error: "Administration data is temporarily unavailable." }, 503);
  }
}

export async function POST(request: Request) {
  try {
    const auth = await requireAdmin(request);
    if (!auth.user) return apiJson({ error: "Authentication is required." }, 401);
    if (!auth.allowed) return apiJson({ error: "Administrator access is required." }, 403);
    if (!sameOrigin(request)) return apiJson({ error: "Origin is not allowed." }, 403);
    await ensureAdminSchema();
    const payload = await readBoundedJson(request, 80_000);
    const action = typeof payload.action === "string" ? payload.action : "";

    if (action === "create") {
      const validated = validateSourceInput(payload.source);
      if (validated.errors.length) {
        return apiJson({ error: validated.errors.join(" "), fields: validated.errors }, 400);
      }
      const id = `src-${crypto.randomUUID()}`;
      const externalId =
        validated.source.externalId || generateExternalId();
      const clientSecret = typeof payload.clientSecret === "string"
        ? payload.clientSecret.slice(0, 2_000)
        : "";
      if (validated.source.provider === "azure-data-explorer" && clientSecret.length < 16) {
        return apiJson({ error: "Enter the Microsoft Entra application client secret. It is sent only to the protected AWS credential bridge." }, 400);
      }
      const pendingSource = {
        ...validated.source,
        id,
        externalId,
        status: "draft" as const,
      };
      if (validated.source.provider === "azure-data-explorer") {
        await configureAdxCredential(pendingSource, clientSecret);
      }
      try {
        await env.DB.prepare(
        `INSERT INTO ingestion_sources
          (id, name, provider, source_type, bucket_arn, bucket_name, region,
           object_prefix, role_arn, external_id, kms_key_arn, organization_id,
           ingestion_mode, backfill_start, included_accounts, excluded_accounts,
           included_regions, config_resource_types, adx_cluster_url, adx_database,
           adx_table, adx_timestamp_column, adx_payload_column, adx_query_mode,
           adx_batch_size, adx_tenant_id, adx_client_id, adx_cursor_value,
           retention_days, status,
           created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?)`,
      )
        .bind(
          id,
          validated.source.name,
          validated.source.provider,
          validated.source.sourceType,
          validated.source.bucketArn,
          validated.source.bucketName,
          validated.source.region,
          validated.source.objectPrefix,
          validated.source.roleArn,
          externalId,
          validated.source.kmsKeyArn,
          validated.source.organizationId,
          validated.source.ingestionMode,
          validated.source.backfillStart,
          JSON.stringify(validated.source.includedAccounts),
          JSON.stringify(validated.source.excludedAccounts),
          JSON.stringify(validated.source.includedRegions),
          JSON.stringify(validated.source.configResourceTypes),
          validated.source.adxClusterUrl,
          validated.source.adxDatabase,
          validated.source.adxTable,
          validated.source.adxTimestampColumn,
          validated.source.adxPayloadColumn,
          validated.source.adxQueryMode,
          validated.source.adxBatchSize,
          validated.source.adxTenantId,
          validated.source.adxClientId,
          validated.source.adxCursorValue,
          validated.source.retentionDays,
          auth.user,
        )
          .run();
      } catch (error) {
        if (validated.source.provider === "azure-data-explorer") {
          await removeAdxCredential(id).catch(() => undefined);
        }
        throw error;
      }
      await audit(
        auth.user,
        "source.created",
        "ingestion_source",
        id,
        `Created ${validated.source.name}.`,
        {
          provider: validated.source.provider,
          sourceType: validated.source.sourceType,
          location: validated.source.provider === "azure-data-explorer"
            ? `${validated.source.adxClusterUrl}/${validated.source.adxDatabase}/${validated.source.adxTable}`
            : validated.source.bucketName,
        },
      );
      return apiJson({ source: await sourceById(id) }, 201);
    }

    const id = typeof payload.id === "string" ? payload.id.slice(0, 80) : "";
    const existing = id ? await sourceById(id) : null;
    if (!existing) return apiJson({ error: "The data source was not found." }, 404);

    if (action === "update") {
      const validated = validateSourceInput(payload.source);
      if (validated.errors.length) {
        return apiJson({ error: validated.errors.join(" "), fields: validated.errors }, 400);
      }
      const clientSecret = typeof payload.clientSecret === "string"
        ? payload.clientSecret.slice(0, 2_000)
        : "";
      const adxIdentityChanged = existing.provider === "azure-data-explorer" && (
        existing.adxTenantId !== validated.source.adxTenantId ||
        existing.adxClientId !== validated.source.adxClientId
      );
      if (validated.source.provider === "azure-data-explorer" && (existing.provider !== "azure-data-explorer" || adxIdentityChanged) && clientSecret.length < 16) {
        return apiJson({ error: "Enter the Microsoft Entra client secret when adding or changing the ADX application identity." }, 400);
      }
      if (validated.source.provider === "azure-data-explorer" && clientSecret) {
        await configureAdxCredential({ ...existing, ...validated.source }, clientSecret);
      }
      await env.DB.prepare(
        `UPDATE ingestion_sources SET
           name = ?, provider = ?, source_type = ?, bucket_arn = ?, bucket_name = ?,
           region = ?, object_prefix = ?, role_arn = ?, external_id = ?,
           kms_key_arn = ?, organization_id = ?, ingestion_mode = ?,
           backfill_start = ?, included_accounts = ?, excluded_accounts = ?,
           included_regions = ?, config_resource_types = ?,
           adx_cluster_url = ?, adx_database = ?, adx_table = ?,
           adx_timestamp_column = ?, adx_payload_column = ?, adx_query_mode = ?,
           adx_batch_size = ?, adx_tenant_id = ?, adx_client_id = ?,
           adx_cursor_value = '', retention_days = ?, status = 'draft', test_summary = '{}',
           last_tested_at = '', last_successful_object_at = '', updated_at = CURRENT_TIMESTAMP
         WHERE id = ? AND workspace_id = 'default'`,
      )
        .bind(
          validated.source.name,
          validated.source.provider,
          validated.source.sourceType,
          validated.source.bucketArn,
          validated.source.bucketName,
          validated.source.region,
          validated.source.objectPrefix,
          validated.source.roleArn,
          validated.source.externalId || existing.externalId,
          validated.source.kmsKeyArn,
          validated.source.organizationId,
          validated.source.ingestionMode,
          validated.source.backfillStart,
          JSON.stringify(validated.source.includedAccounts),
          JSON.stringify(validated.source.excludedAccounts),
          JSON.stringify(validated.source.includedRegions),
          JSON.stringify(validated.source.configResourceTypes),
          validated.source.adxClusterUrl,
          validated.source.adxDatabase,
          validated.source.adxTable,
          validated.source.adxTimestampColumn,
          validated.source.adxPayloadColumn,
          validated.source.adxQueryMode,
          validated.source.adxBatchSize,
          validated.source.adxTenantId,
          validated.source.adxClientId,
          validated.source.retentionDays,
          id,
        )
        .run();
      await audit(
        auth.user,
        "source.updated",
        "ingestion_source",
        id,
        `Updated ${validated.source.name}; live verification is required again.`,
        { previousStatus: existing.status },
      );
      if (existing.provider === "azure-data-explorer" && validated.source.provider !== "azure-data-explorer") {
        await removeAdxCredential(id);
      }
      return apiJson({ source: await sourceById(id) });
    }

    if (action === "test") {
      await env.DB.prepare(
        "UPDATE ingestion_sources SET status = 'testing', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
      ).bind(id).run();
      const result = existing.provider === "azure-data-explorer"
        ? await testAdxSource(existing)
        : await testAwsSource(existing);
      const status = result.passed ? "ready" : result.mode === "configuration-only" ? "draft" : "degraded";
      await env.DB.prepare(
        `UPDATE ingestion_sources
         SET status = ?, test_summary = ?, last_tested_at = ?,
             updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
      )
        .bind(status, JSON.stringify(result), result.testedAt, id)
        .run();
      await audit(
        auth.user,
        "source.tested",
        "ingestion_source",
        id,
        result.passed
          ? `Live connection test passed for ${existing.name}.`
          : result.mode === "configuration-only"
            ? `Configuration validated for ${existing.name}; runtime verification is pending.`
            : `Live connection test failed for ${existing.name}.`,
        { mode: result.mode, passed: result.passed },
      );
      return apiJson({ source: await sourceById(id), test: result });
    }

    if (action === "template") {
      if (existing.provider !== "aws-s3") {
        return apiJson({ error: "IAM templates apply only to AWS S3 sources." }, 409);
      }
      return apiJson({
        filename: `gatewatch-${existing.sourceType}-read-role.json`,
        template: sourceAccessCloudFormation(existing),
      });
    }

    if (action === "activate") {
      if (!existing.testSummary?.passed || existing.testSummary.mode !== "live") {
        return apiJson(
          { error: "A successful live connection test is required before activation." },
          409,
        );
      }
      await env.DB.prepare(
        "UPDATE ingestion_sources SET status = 'live', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
      ).bind(id).run();
      await audit(auth.user, "source.activated", "ingestion_source", id, `Activated ${existing.name}.`);
      return apiJson({ source: await sourceById(id) });
    }

    if (action === "pause" || action === "resume") {
      const status = action === "pause" ? "paused" : existing.testSummary?.passed ? "live" : "draft";
      await env.DB.prepare(
        "UPDATE ingestion_sources SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
      ).bind(status, id).run();
      await audit(auth.user, `source.${action}d`, "ingestion_source", id, `${action === "pause" ? "Paused" : "Resumed"} ${existing.name}.`);
      return apiJson({ source: await sourceById(id) });
    }

    if (action === "backfill") {
      if (!existing.testSummary?.passed || existing.testSummary.mode !== "live") {
        return apiJson(
          { error: "Complete a successful live connection test before starting a backfill." },
          409,
        );
      }
      if (existing.provider === "azure-data-explorer") {
        const outcome = await syncAdxSource(existing, auth.user, "backfill");
        await audit(auth.user, "adx.backfill.completed", "ingestion_run", outcome.runId, `Imported ${outcome.normalized} normalized records from ${existing.name}.`, outcome);
        return apiJson({ outcome, source: await sourceById(id) });
      }
      const runId = `run-${crypto.randomUUID()}`;
      await env.DB.batch([
        env.DB.prepare(
          `INSERT INTO ingestion_runs
            (id, source_id, run_type, status, requested_by)
           VALUES (?, ?, 'backfill', 'queued', ?)`,
        ).bind(runId, id, auth.user),
        env.DB.prepare(
          "UPDATE ingestion_sources SET status = 'backfilling', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        ).bind(id),
      ]);
      await audit(auth.user, "backfill.queued", "ingestion_run", runId, `Queued a backfill for ${existing.name}.`, { sourceId: id });
      return apiJson({ runId, source: await sourceById(id) }, 202);
    }

    if (action === "preview") {
      if (existing.provider !== "azure-data-explorer") {
        return apiJson({ error: "Preview is available for Azure Data Explorer sources." }, 409);
      }
      const preview = await queryAdxSource(existing, "preview");
      await audit(auth.user, "adx.previewed", "ingestion_source", id, `Previewed ${preview.rowCount} bounded rows from ${existing.name}.`);
      return apiJson({ preview });
    }

    if (action === "sync") {
      if (existing.provider !== "azure-data-explorer") {
        return apiJson({ error: "Manual synchronization is available for Azure Data Explorer sources." }, 409);
      }
      const outcome = await syncAdxSource(existing, auth.user, "continuous");
      await audit(auth.user, "adx.sync.completed", "ingestion_run", outcome.runId, `Imported ${outcome.normalized} normalized records from ${existing.name}.`, outcome);
      return apiJson({ outcome, source: await sourceById(id) });
    }

    if (action === "delete") {
      if (existing.status === "live" || existing.status === "backfilling") {
        return apiJson({ error: "Pause the source before deleting it." }, 409);
      }
      if (existing.provider === "azure-data-explorer") {
        await removeAdxCredential(id);
      }
      await env.DB.prepare(
        "DELETE FROM ingestion_sources WHERE id = ? AND workspace_id = 'default'",
      ).bind(id).run();
      await audit(auth.user, "source.deleted", "ingestion_source", id, `Deleted source configuration ${existing.name}. Source logs were not modified.`);
      return apiJson({ deleted: true });
    }

    return apiJson({ error: "Choose a supported administration action." }, 400);
  } catch (error) {
    if (error instanceof HttpInputError) return apiJson({ error: error.message }, error.status);
    return apiJson({ error: "The administration request could not be completed." }, 503);
  }
}
