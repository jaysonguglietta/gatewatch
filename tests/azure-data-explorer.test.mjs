import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  normalizeAdxClusterUrl,
  validateSourceInput,
  validAdxIdentifier,
} from "../lib/admin-sources.ts";

const source = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

const validSource = {
  name: "Central CloudTrail in ADX",
  provider: "azure-data-explorer",
  sourceType: "cloudtrail",
  ingestionMode: "both",
  backfillStart: "2026-08-01",
  includedAccounts: "111122223333, 444455556666",
  excludedAccounts: "",
  includedRegions: "us-east-1, us-west-2",
  retentionDays: 365,
  adxClusterUrl: "https://securitylogs.eastus.kusto.windows.net",
  adxDatabase: "SecurityLogs",
  adxTable: "CloudTrail",
  adxTimestampColumn: "TimeGenerated",
  adxPayloadColumn: "RawEvent",
  adxQueryMode: "payload-column",
  adxBatchSize: 500,
  adxTenantId: "12345678-1234-4123-8123-1234567890ab",
  adxClientId: "abcdefab-1234-4123-8123-1234567890ab",
  adxClientSecret: "must-never-be-persisted",
  adxAuthMode: "federated",
  freshnessSlaMinutes: 30,
};

test("ADX source validation preserves only non-secret, bounded configuration", () => {
  const result = validateSourceInput(validSource);
  assert.deepEqual(result.errors, []);
  assert.equal(result.source.provider, "azure-data-explorer");
  assert.equal(result.source.adxClusterUrl, validSource.adxClusterUrl);
  assert.equal(result.source.adxDatabase, "SecurityLogs");
  assert.equal(result.source.adxTable, "CloudTrail");
  assert.equal(result.source.adxBatchSize, 500);
  assert.equal(result.source.adxAuthMode, "federated");
  assert.equal(result.source.freshnessSlaMinutes, 30);
  assert.equal("adxClientSecret" in result.source, false);
  assert.deepEqual(result.source.includedAccounts, ["111122223333", "444455556666"]);
});

test("ADX freshness and federation settings fail closed", () => {
  assert.ok(validateSourceInput({ ...validSource, freshnessSlaMinutes: 4 }).errors.some((error) => error.includes("freshness")));
  assert.ok(validateSourceInput({ ...validSource, freshnessSlaMinutes: 10081 }).errors.some((error) => error.includes("freshness")));
  assert.equal(validateSourceInput({ ...validSource, adxAuthMode: "unexpected" }).source.adxAuthMode, "federated");
});

test("ADX cluster validation rejects SSRF-capable and ambiguous endpoints", () => {
  assert.equal(normalizeAdxClusterUrl("http://cluster.eastus.kusto.windows.net"), "");
  assert.equal(normalizeAdxClusterUrl("https://169.254.169.254/"), "");
  assert.equal(normalizeAdxClusterUrl("https://cluster.eastus.kusto.windows.net.attacker.example"), "");
  assert.equal(normalizeAdxClusterUrl("https://user:pass@cluster.eastus.kusto.windows.net"), "");
  assert.equal(normalizeAdxClusterUrl("https://cluster.eastus.kusto.windows.net/path"), "");
  assert.equal(normalizeAdxClusterUrl("https://cluster.eastus.kusto.windows.net?query=x"), "");
  assert.equal(
    normalizeAdxClusterUrl("https://SECURITYLOGS.EASTUS.KUSTO.WINDOWS.NET/"),
    "https://securitylogs.eastus.kusto.windows.net",
  );
});

test("ADX identifiers cannot escape the generated read-only KQL shape", () => {
  assert.equal(validAdxIdentifier("AwsEvidence_2026"), true);
  for (const value of ["Logs | take 100", ".show tables", "Table; drop", "['Table']", "with space", ""]) {
    assert.equal(validAdxIdentifier(value), false, value);
  }
  const result = validateSourceInput({ ...validSource, adxTable: "Logs | invoke attacker()" });
  assert.ok(result.errors.some((error) => error.includes("table")));
});

test("ADX bridge uses parameterized checkpoints, bounded reads, and isolated credentials", () => {
  const bridge = source("infrastructure/aws-web/aws-bridge.mjs");
  assert.match(bridge, /declare query_parameters\(gatewatch_checkpoint:datetime, gatewatch_cursor:string, gatewatch_limit:long\)/);
  assert.match(bridge, /hash_sha256\(tostring\(pack_all\(\)\)\)/);
  assert.match(bridge, /__gatewatch_cursor > gatewatch_cursor/);
  assert.match(bridge, /skippedRows \+= 1/);
  assert.match(bridge, /truncationmaxrecords: limit/);
  assert.match(bridge, /truncationmaxsize: 5 \* 1024 \* 1024/);
  assert.match(bridge, /redirect: "error"/);
  assert.match(bridge, /GATEWATCH_ADX_SECRET_ARN/);
  assert.match(bridge, /GetWebIdentityTokenCommand/);
  assert.match(bridge, /api:\/\/AzureADTokenExchange/);
  assert.match(bridge, /client_assertion_type/);
  assert.match(bridge, /adxAuthority\(source\.clusterUrl, source\.tenantId\)/);
  assert.doesNotMatch(bridge, /adxAuthority\(source\.clusterUrl, credential\.tenantId\)/);
  assert.match(bridge, /table\(\"\$\{source\.table\}\"\) \| getschema/);
  assert.match(bridge, /\/adx\/schema/);
  assert.match(bridge, /SendMessageBatchCommand/);
  assert.match(bridge, /\/adx\/config/);
  assert.match(bridge, /\/adx\/query/);
  assert.doesNotMatch(bridge, /eval\(|new Function\(/);
});

test("ADX scheduler fans out through FIFO SQS and lease-aware Lambda workers", () => {
  const template = source("infrastructure/cloudformation/gatewatch-aws-web.yaml");
  const route = source("app/api/internal/adx-sync/route.ts");
  const sync = source("lib/adx-ingestion.ts");
  assert.match(template, /AzureDataExplorerSyncQueue:/);
  assert.match(template, /FifoQueue: true/);
  assert.match(template, /AzureDataExplorerWorkerEventSource:/);
  assert.match(template, /MaximumConcurrency: 25/);
  assert.match(template, /sts:GetWebIdentityToken/);
  assert.match(template, /sts:IdentityTokenAudience: api:\/\/AzureADTokenExchange/);
  assert.match(route, /LIMIT 2000/);
  assert.match(route, /enqueueAdxSources/);
  assert.match(route, /\["live", "degraded"\]\.includes/);
  assert.match(route, /auditMany/);
  assert.match(sync, /adx_lease_expires_at = datetime\('now', '\+3 minutes'\)/);
  assert.match(sync, /ADX_SOURCE_BUSY/);
});

test("ADX schema discovery, sample validation, and freshness alerts are first-class UI", () => {
  const view = source("app/admin-view.tsx");
  const freshness = source("lib/adx-freshness.ts");
  assert.match(view, /Discover schema/);
  assert.match(view, /adx-schema-columns/);
  assert.match(view, /Validate five sample rows/);
  assert.match(view, /Freshness objective/);
  assert.match(view, /AWS workload identity federation/);
  assert.match(view, /disabled={!wizardStepReady}/);
  assert.match(view, /Enter the Entra tenant and application IDs/);
  assert.match(freshness, /freshness-breach/);
  assert.match(freshness, /updated_at AS updatedAt/);
  assert.match(freshness, /ON CONFLICT\(workspace_id, source_id, alert_type\)/);
  assert.match(freshness, /status = 'resolved'/);
});

test("ADX deployment creates a retained secret and scheduled internal sync", () => {
  const template = source("infrastructure/cloudformation/gatewatch-aws-web.yaml");
  const installer = source("infrastructure/aws-web/install.sh");
  assert.match(template, /AzureDataExplorerCredentialsSecret:/);
  assert.match(template, /DeletionPolicy: Retain/);
  assert.match(template, /ManageAzureDataExplorerCredentials/);
  assert.match(template, /AzureDataExplorerSyncAssociation:/);
  assert.match(template, /api\/internal\/adx-sync/);
  assert.ok(Buffer.byteLength(template) <= 51_200, "web template must remain directly deployable");
  assert.match(installer, /GATEWATCH_ADX_SECRET_ARN/);
});

test("ADX production schema is workspace isolated and migration-managed", () => {
  const migration = source("db/postgres/0007_azure_data_explorer_sources.sql");
  const runner = source("scripts/migrate-aws-platform.mjs");
  assert.match(migration, /CREATE TABLE ingestion_source_checkpoints/);
  assert.match(migration, /ENABLE ROW LEVEL SECURITY/);
  assert.match(migration, /FORCE ROW LEVEL SECURITY/);
  assert.match(migration, /CREATE POLICY workspace_isolation/);
  assert.match(migration, /provider = 'azure-data-explorer'/);
  assert.match(runner, /0007_azure_data_explorer_sources\.sql/);
  const federationMigration = source("db/postgres/0008_adx_federation_scale_freshness.sql");
  assert.match(federationMigration, /CREATE TABLE ingestion_source_alerts/);
  assert.match(federationMigration, /FORCE ROW LEVEL SECURITY/);
  assert.match(federationMigration, /adx_auth_mode/);
  assert.match(runner, /0008_adx_federation_scale_freshness\.sql/);
});

test("ADX administration supports configuration, preview, activation, and sync", () => {
  const view = source("app/admin-view.tsx");
  const route = source("app/api/admin/sources/route.ts");
  assert.match(view, /Azure Data Explorer/);
  assert.match(view, /ADX cluster URL/);
  assert.match(view, /Preview rows/);
  assert.match(view, /Sync now/);
  assert.match(route, /configureAdxCredential/);
  assert.match(route, /queryAdxSource\(existing, "preview"\)/);
  assert.match(route, /syncAdxSource\(existing, auth\.user/);
  assert.match(route, /clientSecret\.slice\(0, 2_000\)/);
  assert.match(route, /error instanceof AdxConnectionError/);
  assert.match(route, /function parseAdxSchema/);
});
