import { env } from "cloudflare:workers";
import type {
  ConnectionCheck,
  ConnectionTestSummary,
  IngestionSource,
} from "./admin-sources";

export type AdxPreview = {
  columns: string[];
  records: Record<string, unknown>[];
  rowCount: number;
  skippedRows: number;
  truncated: boolean;
  nextCheckpoint: string;
  nextCursor: string;
};

function bridgeConfigured() {
  return Boolean(env.GATEWATCH_AWS_BRIDGE_URL && env.GATEWATCH_AWS_BRIDGE_TOKEN);
}

async function bridgeRequest<T>(path: string, body: Record<string, unknown>): Promise<T> {
  const baseUrl = env.GATEWATCH_AWS_BRIDGE_URL?.replace(/\/$/, "");
  const token = env.GATEWATCH_AWS_BRIDGE_TOKEN;
  if (!baseUrl || !token) throw new Error("ADX_RUNTIME_NOT_CONFIGURED");
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
    throw new Error(payload.error || "Azure Data Explorer request failed.");
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
        check("runtime", "ADX runtime credential", "pending", "Deploy the AWS bridge and configure the Microsoft Entra application secret to perform a live query."),
      ],
    };
  }
  try {
    const result = await bridgeRequest<AdxPreview>("/adx/test", sourcePayload(source));
    return {
      mode: "live",
      testedAt,
      passed: true,
      detectedFormat: `Azure Data Explorer · ${source.adxQueryMode}`,
      newestObject: {
        key: location,
        size: result.rowCount,
        lastModified: result.nextCheckpoint,
      },
      checks: [
        check("identity", "Microsoft Entra authentication", "passed", "A client-credential token was issued for the configured cluster."),
        check("database", "Database viewer access", "passed", source.adxDatabase),
        check("table", "Bounded table query", "passed", `${result.rowCount} preview row(s) returned from ${source.adxTable}.`),
        check("mapping", "AWS evidence mapping", "passed", source.adxQueryMode === "payload-column" ? source.adxPayloadColumn : `${result.columns.length} columns`),
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
