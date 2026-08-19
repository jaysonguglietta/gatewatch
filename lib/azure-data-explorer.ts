import { env } from "cloudflare:workers";
import type {
  ConnectionCheck,
  ConnectionTestSummary,
  AdxSchemaSnapshot,
  IngestionSource,
} from "./admin-sources";
import { parseAwsEvidenceText } from "./aws-evidence-import";

export type AdxPreview = {
  columns: string[];
  records: Record<string, unknown>[];
  rowCount: number;
  skippedRows: number;
  truncated: boolean;
  nextCheckpoint: string;
  nextCursor: string;
};

export type AdxMappingValidation = {
  passed: boolean;
  queried: number;
  normalized: number;
  skipped: number;
  warnings: string[];
  samples: Array<{
    accountId: string;
    region: string;
    resource: string;
    event: string;
    observedAt: string;
  }>;
};

/** An operator-safe bridge error whose message is suitable for an admin UI. */
export class AdxConnectionError extends Error {}

function bridgeConfigured() {
  return Boolean(env.GATEWATCH_AWS_BRIDGE_URL && env.GATEWATCH_AWS_BRIDGE_TOKEN);
}

async function bridgeRequest<T>(path: string, body: Record<string, unknown>): Promise<T> {
  const baseUrl = env.GATEWATCH_AWS_BRIDGE_URL?.replace(/\/$/, "");
  const token = env.GATEWATCH_AWS_BRIDGE_TOKEN;
  if (!baseUrl || !token) {
    throw new AdxConnectionError("Live ADX inspection requires the deployed AWS bridge. Save the draft and complete verification in the AWS runtime.");
  }
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
    redirect: "error",
    signal: AbortSignal.timeout(30_000),
  });
  const payload = await response.json() as T & { error?: string };
  if (!response.ok) {
    throw new AdxConnectionError(payload.error || "Azure Data Explorer rejected the bounded read-only request.");
  }
  return payload;
}

function sourcePayload(source: IngestionSource) {
  return {
    sourceId: source.id,
    clusterUrl: source.adxClusterUrl,
    database: source.adxDatabase,
    table: source.adxTable,
    timestampColumn: source.adxTimestampColumn,
    payloadColumn: source.adxPayloadColumn,
    queryMode: source.adxQueryMode,
    batchSize: source.adxBatchSize,
    tenantId: source.adxTenantId,
    clientId: source.adxClientId,
    authMode: source.adxAuthMode,
  };
}

export async function configureAdxCredential(
  source: IngestionSource,
  clientSecret: string,
) {
  return bridgeRequest<{ configured: true }>("/adx/config", {
    ...sourcePayload(source),
    tenantId: source.adxTenantId,
    clientId: source.adxClientId,
    clientSecret,
  });
}

export async function removeAdxCredential(sourceId: string) {
  return bridgeRequest<{ removed: boolean }>("/adx/remove", { sourceId });
}

export async function discoverAdxSchema(source: IngestionSource) {
  return bridgeRequest<AdxSchemaSnapshot>("/adx/schema", sourcePayload(source));
}

export async function enqueueAdxSources(sourceIds: string[]) {
  return bridgeRequest<{ queued: number }>("/adx/enqueue", { sourceIds });
}

export async function queryAdxSource(
  source: IngestionSource,
  mode: "preview" | "sync",
  checkpoint = "",
  cursor = "",
) {
  return bridgeRequest<AdxPreview>("/adx/query", {
    ...sourcePayload(source),
    mode,
    checkpoint,
    cursor,
  });
}

export function validateAdxPreview(
  source: IngestionSource,
  preview: AdxPreview,
): AdxMappingValidation {
  if (!preview.records.length) {
    return {
      passed: false,
      queried: preview.rowCount,
      normalized: 0,
      skipped: preview.skippedRows,
      warnings: ["The table returned no sample rows. Mapping cannot be validated until evidence is available."],
      samples: [],
    };
  }
  const parsed = parseAwsEvidenceText(JSON.stringify(preview.records), source.sourceType);
  const skipped = preview.skippedRows + parsed.skippedRecords;
  return {
    passed: parsed.records.length > 0 && skipped === 0,
    queried: preview.rowCount,
    normalized: parsed.records.length,
    skipped,
    warnings: parsed.warnings,
    samples: parsed.records.slice(0, 3).map((record) => ({
      accountId: record.accountId,
      region: record.region,
      resource: record.resource,
      event: record.event,
      observedAt: record.observedAt,
    })),
  };
}

function check(
  key: string,
  label: string,
  status: ConnectionCheck["status"],
  detail: string,
): ConnectionCheck {
  return { key, label, status, detail };
}

export async function testAdxSource(
  source: IngestionSource,
): Promise<ConnectionTestSummary> {
  const testedAt = new Date().toISOString();
  const location = `${source.adxClusterUrl}/${source.adxDatabase}/${source.adxTable}`;
  const configurationChecks: ConnectionCheck[] = [
    check("cluster", "ADX cluster", "passed", source.adxClusterUrl),
    check("location", "Database and table", "passed", `${source.adxDatabase}.${source.adxTable}`),
    check("mapping", "Read-only row mapping", "passed", source.adxQueryMode === "payload-column" ? `JSON from ${source.adxPayloadColumn}` : "Every returned table column"),
    check("checkpoint", "Incremental checkpoint", "passed", source.adxTimestampColumn),
  ];
  if (!bridgeConfigured()) {
    return {
      mode: "configuration-only",
      testedAt,
      passed: false,
      detectedFormat: `Azure Data Explorer · ${source.adxQueryMode}`,
      checks: [
        ...configurationChecks,
        check("runtime", "ADX runtime identity", "pending", "Deploy the AWS bridge and configure the Entra federated trust to perform a live query."),
      ],
    };
  }
  try {
    const schema = await discoverAdxSchema(source);
    const result = await bridgeRequest<AdxPreview>("/adx/test", sourcePayload(source));
    const validation = validateAdxPreview(source, result);
    const columnNames = new Set(schema.columns.map((column) => column.name));
    const mappingColumnsExist = columnNames.has(source.adxTimestampColumn)
      && (source.adxQueryMode !== "payload-column" || columnNames.has(source.adxPayloadColumn));
    const passed = validation.passed && mappingColumnsExist;
    return {
      mode: "live",
      testedAt,
      passed,
      detectedFormat: `Azure Data Explorer · ${source.adxQueryMode}`,
      schema,
      mappingValidation: validation,
      newestObject: {
        key: location,
        size: result.rowCount,
        lastModified: result.nextCheckpoint,
      },
      checks: [
        check("identity", "Microsoft Entra authentication", "passed", source.adxAuthMode === "federated" ? "AWS issued a short-lived workload JWT and Entra exchanged it without a stored client secret." : "A legacy client-secret credential was exchanged for a short-lived token."),
        check("database", "Database viewer access", "passed", source.adxDatabase),
        check("schema", "Schema discovery", schema.columns.length ? "passed" : "failed", `${schema.columns.length} column(s) discovered from ${source.adxTable}.`),
        check("table", "Bounded table query", "passed", `${result.rowCount} preview row(s) returned from ${source.adxTable}.`),
        check("mapping", "AWS evidence mapping", passed ? "passed" : "failed", mappingColumnsExist ? `${validation.normalized} of ${validation.queried} sample row(s) normalized as ${source.sourceType}.` : "One or more mapped columns no longer exist in the live table schema."),
      ],
    };
  } catch (error) {
    return {
      mode: "live",
      testedAt,
      passed: false,
      detectedFormat: `Azure Data Explorer · ${source.adxQueryMode}`,
      checks: [
        ...configurationChecks.slice(0, 2),
        check("adx-access", "Authenticate and query ADX", "failed", error instanceof Error ? error.message.slice(0, 500) : "Azure Data Explorer rejected the connection test."),
      ],
    };
  }
}
