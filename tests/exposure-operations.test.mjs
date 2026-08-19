import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const source = (path) => readFile(new URL(path, root), "utf8");

test("ships the closed-loop exposure operations workspace", async () => {
  const [view, dashboard, model] = await Promise.all([
    source("app/exposure-operations-view.tsx"),
    source("app/security-dashboard.tsx"),
    source("lib/exposure-operations.ts"),
  ]);

  const implementation = `${view}\n${model}`;
  for (const capability of [
    "Command center", "AWS verification", "Attack graph", "Remediation",
    "Owner actions", "Incident mode", "Policies & API",
    "Security Hub", "Reachability Analyzer", "Firewall Manager",
    "Automatic AWS path re-verification", "Extension payloads",
  ]) assert.match(implementation, new RegExp(capability));

  assert.match(dashboard, /Exposure operations/);
  assert.match(model, /confirmedCriticalExposureHours/);
  assert.match(model, /automaticallyReverifiedPercent/);
  assert.match(model, /contradictions/);
  assert.match(model, /rollbackReady/);
});

test("enforces governed operation transitions and separation of duties", async () => {
  const [route, model] = await Promise.all([
    source("app/api/intelligence/route.ts"),
    source("lib/exposure-operations.ts"),
  ]);

  assert.match(route, /operationTransitions/);
  assert.match(route, /operationInitialStatuses/);
  assert.match(route, /must be created in the/);
  assert.match(route, /Transition from/);
  assert.match(route, /Remediation authors cannot approve their own production change/);
  assert.match(route, /A simulated remediation payload is immutable/);
  assert.match(route, /canonicalJson/);
  assert.match(route, /kind === "policy-pack"/);
  assert.match(route, /kind === "extension"/);
  assert.match(model, /"awaiting-approval": \["approved", "draft"\]/);
  assert.doesNotMatch(model, /"awaiting-approval": \[[^\]]*"completed"/);
});

test("models production exposure operations with forced workspace isolation", async () => {
  const [migration, runner] = await Promise.all([
    source("db/postgres/0006_exposure_operations.sql"),
    source("scripts/migrate-aws-platform.mjs"),
  ]);

  for (const table of [
    "exposure_verification_runs", "exposure_correlations", "exposure_graph_edges",
    "exposure_remediation_plans", "exposure_owner_actions", "exposure_incidents",
    "exposure_policy_packs", "exposure_slo_snapshots", "exposure_extensions",
  ]) assert.match(migration, new RegExp(`CREATE TABLE ${table}`));

  assert.match(migration, /approved_by IS NULL OR approved_by <> authored_by/);
  assert.match(migration, /FORCE ROW LEVEL SECURITY/);
  assert.match(migration, /current_setting\(''app\.workspace_id'', true\)/);
  assert.match(migration, /TO gatewatch_ingest/);
  assert.doesNotMatch(migration, /TO gatewatch_runtime_login/);
  assert.match(runner, /0006_exposure_operations\.sql/);
  assert.match(runner, /Migration verification failed/);
});
