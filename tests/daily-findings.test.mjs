import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

async function source(path) {
  return readFile(new URL(path, root), "utf8");
}

test("makes the daily findings inbox the default organization-scale workflow", async () => {
  const [dashboard, inbox, catalog, findingsRoute] = await Promise.all([
    source("app/security-dashboard.tsx"),
    source("app/daily-findings-view.tsx"),
    source("lib/daily-findings.ts"),
    source("app/api/findings/route.ts"),
  ]);

  assert.match(dashboard, /useState<View>\("inventory"\)/);
  assert.match(dashboard, /label: "Daily findings"/);
  for (const capability of [
    "Security group exposure triage",
    "Confirmed internet",
    "Evidence incomplete",
    "Internal risk",
    "Fix first",
    "Security group hunts",
    "Describe a hunt",
    "Exposure intelligence",
    "accounts monitored",
    "Save current view",
    "Filters are reflected in the URL",
    "Create follow-up",
    "Acknowledge finding",
    "Accept risk",
    "Notes & history",
    "Exposure path",
    "Remediation",
    "Raw evidence",
    "Bulk findings actions",
    "Create Jira tickets",
    "Security-operations workspace refresh",
  ]) {
    assert.match(`${inbox}\n${await source("app/globals.css")}`, new RegExp(capability));
  }
  assert.match(catalog, /findingFingerprint/);
  assert.match(catalog, /organizationalUnit/);
  assert.match(inbox, /Filter findings by effective internet exposure/);
  assert.match(inbox, /Exposure: internet first/);
  assert.match(inbox, /Exposure: no internet first/);
  assert.match(findingsRoute, /internetExposureForVerdict/);
  assert.match(inbox, /Detailed search/);
  assert.match(inbox, /Search or use arn:, name:, account:, ingress:/);
  assert.match(findingsRoute, /dailyFindingMatchesQuery/);
  assert.match(catalog, /securityGroupArn/);
  for (const capability of [
    "Query builder",
    "Monitor search",
    "Export all results",
    "all correlated AWS evidence",
    "Result intelligence",
    "Why this finding matched",
    "Select all",
    "Guarded bulk operation",
  ]) assert.match(inbox, new RegExp(capability));
  for (const capability of ["resultFacets", "evidenceMatches", "matchReasons", "searchSuggestions", "format"]) {
    assert.match(findingsRoute, new RegExp(capability));
  }
  assert.match(catalog, /accounts: 324/);
  assert.match(inbox, /gatewatch\.findings-density/);
  assert.doesNotMatch(inbox, /localStorage\.(?:getItem|setItem)\(["'][^"']*(?:note|ticket|workflow)/i);
});

test("links findings to Jira without creating duplicate tickets", async () => {
  const [inbox, findingsRoute, jiraRoute, serverAdmin] = await Promise.all([
    source("app/daily-findings-view.tsx"),
    source("app/api/findings/route.ts"),
    source("app/api/jira/issues/route.ts"),
    source("lib/server-admin.ts"),
  ]);

  assert.match(inbox, /One ticket per finding/);
  assert.match(inbox, /already linked and will not create duplicates/);
  assert.match(inbox, /batches of 20 findings or fewer/);
  assert.match(findingsRoute, /jiraIssueKey/);
  assert.match(findingsRoute, /jiraIssueUrl/);
  assert.match(jiraRoute, /finding_jira_links/);
  assert.match(jiraRoute, /existingByFingerprint/);
  assert.match(serverAdmin, /PRAGMA table_info\(finding_jira_links\)/);
  for (const column of ["remote_status", "remote_resolution", "remote_updated_at", "last_synced_at"]) {
    assert.match(serverAdmin, new RegExp(`ALTER TABLE finding_jira_links ADD COLUMN ${column}`));
  }
});

test("persists notes, bulk triage, accepted risk, history, and saved views safely", async () => {
  const [route, schema, migration] = await Promise.all([
    source("app/api/findings/route.ts"),
    source("db/schema.ts"),
    source("drizzle/0007_happy_human_fly.sql"),
  ]);

  assert.match(route, /pageSize/);
  assert.match(route, /slice\(0, 100\)/);
  assert.match(route, /sameOrigin/);
  assert.match(route, /TextEncoder/);
  assert.match(route, /requireAdmin/);
  assert.match(route, /Acknowledgement requires a reason, explanation, and future review date/);
  assert.match(route, /compensating controls/);
  assert.match(route, /finding_events/);
  assert.match(route, /saved_finding_views/);
  assert.match(route, /finding_undo_snapshots/);
  assert.match(route, /finding_workflow_details/);
  assert.match(route, /Refresh or complete evidence/);
  assert.match(route, /audit\(/);
  assert.match(schema, /findingWorkflows/);
  assert.match(schema, /findingEvents/);
  assert.match(schema, /savedFindingViews/);
  assert.match(schema, /findingUndoSnapshots/);
  assert.match(migration, /CREATE TABLE `finding_workflows`/);
  assert.match(migration, /CREATE TABLE `finding_events`/);
  assert.match(migration, /CREATE TABLE `saved_finding_views`/);
});

test("supports fast, explainable, and guarded analyst decisions", async () => {
  const [dashboard, inbox, route, catalog, migration] = await Promise.all([
    source("app/security-dashboard.tsx"),
    source("app/daily-findings-view.tsx"),
    source("app/api/findings/route.ts"),
    source("lib/daily-findings.ts"),
    source("drizzle/0009_heavy_ted_forrester.sql"),
  ]);

  for (const workspace of ["Findings", "Inventory", "Governance", "Reports", "Administration"]) {
    assert.match(dashboard, new RegExp(`label: "${workspace}"`));
  }
  for (const capability of [
    "triage-workspace",
    "security-groups",
    "J/K to review",
    "Decision summary",
    "Why risk is",
    "Exact configuration change",
    "Config timeline",
    "Create a Jira ticket after saving",
    "Remediation evidence",
    "Security team",
  ]) {
    assert.match(inbox, new RegExp(capability));
  }
  assert.match(route, /action === "undo"/);
  assert.match(route, /evidence\.confidence < 70/);
  assert.match(route, /visibility = 'team'/);
  assert.match(catalog, /riskFactors/);
  assert.match(catalog, /changeBefore/);
  assert.match(migration, /CREATE TABLE `finding_undo_snapshots`/);
  assert.match(migration, /CREATE TABLE `saved_finding_view_visibility`/);
});

test("includes the daily workflow in the future Aurora model", async () => {
  const postgres = await source("db/postgres/0001_gatewatch_aws.sql");

  assert.match(postgres, /CREATE TABLE finding_workflows/);
  assert.match(postgres, /CREATE TABLE finding_events/);
  assert.match(postgres, /CREATE TABLE saved_finding_views/);
  assert.match(postgres, /PRIMARY KEY \(workspace_id, fingerprint\)/);
  assert.match(postgres, /saved_finding_views_one_default_idx/);
});
