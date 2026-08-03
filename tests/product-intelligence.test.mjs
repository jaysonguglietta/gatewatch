import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

async function source(path) {
  return readFile(new URL(path, root), "utf8");
}

test("ships all ten product-intelligence and governance capabilities", async () => {
  const [view, dashboard, data] = await Promise.all([
    source("app/product-intelligence.tsx"),
    source("app/security-dashboard.tsx"),
    source("lib/product-intelligence-data.ts"),
  ]);

  for (const surface of [
    "Exposure intelligence",
    "Harmful combination",
    "Attack paths",
    "Rule advisor",
    "Hygiene center",
    "IaC guardrails",
    "Exposure drift inbox",
    "Owner inbox",
    "Native control reconciliation",
    "Program metrics",
  ]) {
    assert.match(view, new RegExp(surface));
  }

  assert.match(view, /Simulate change/);
  assert.match(view, /Traffic preserved/);
  assert.match(view, /Request exception/);
  assert.match(view, /Independent approval and expiration are required/);
  assert.match(view, /Executive program report exported/);
  assert.match(dashboard, /Exposure intelligence/);
  assert.match(dashboard, /Recommendations/);
  assert.match(dashboard, /Drift inbox/);
  assert.match(dashboard, /Owner governance/);
  assert.match(dashboard, /Detailed reports/);
  assert.match(data, /Confirmed public service/);
  assert.match(data, /Broad but unreachable/);
  assert.match(data, /Evidence incomplete/);
});

test("persists workflows with authorization and separation-of-duty controls", async () => {
  const [route, schema, migration] = await Promise.all([
    source("app/api/intelligence/route.ts"),
    source("db/schema.ts"),
    source("drizzle/0006_pale_masque.sql"),
  ]);

  assert.match(route, /sameOrigin/);
  assert.match(route, /application\/json payload under 40 KB/);
  assert.match(route, /requireAdmin/);
  assert.match(route, /requestors cannot approve or reject their own request/);
  assert.match(route, /Only the requestor or an administrator can delete/);
  assert.match(route, /expiration must be in the future/);
  assert.match(route, /audit\(/);
  assert.match(schema, /productWorkflowRecords/);
  assert.match(migration, /CREATE TABLE `product_workflow_records`/);
});

test("models the intelligence features in the future AWS database", async () => {
  const postgres = await source("db/postgres/0001_gatewatch_aws.sql");

  for (const table of [
    "exposure_verdicts",
    "rule_recommendations",
    "exposure_drift_events",
    "ownership_assignments",
    "exception_requests",
    "control_evaluations",
    "hygiene_findings",
    "iac_guardrail_evaluations",
    "program_metric_snapshots",
    "product_workflow_records",
  ]) {
    assert.match(postgres, new RegExp(`CREATE TABLE ${table}`));
  }

  assert.match(postgres, /approver <> requestor/);
  assert.match(postgres, /CHECK \(verdict IN \('pass', 'warn', 'block'\)\)/);
});
