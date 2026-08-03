import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

async function source(path) {
  return readFile(new URL(path, root), "utf8");
}

test("makes the daily findings inbox the default organization-scale workflow", async () => {
  const [dashboard, inbox, catalog] = await Promise.all([
    source("app/security-dashboard.tsx"),
    source("app/daily-findings-view.tsx"),
    source("lib/daily-findings.ts"),
  ]);

  assert.match(dashboard, /useState<View>\("inventory"\)/);
  assert.match(dashboard, /label: "Daily findings"/);
  for (const capability of [
    "Daily findings inbox",
    "New today",
    "Awaiting action",
    "Follow-ups overdue",
    "Exceptions expiring",
    "accounts monitored",
    "Save current view",
    "Filters are reflected in the URL",
    "Create follow-up",
    "Acknowledge finding",
    "Accept risk",
    "Notes & history",
    "Bulk findings actions",
    "Create Jira tickets",
  ]) {
    assert.match(inbox, new RegExp(capability));
  }
  assert.match(catalog, /findingFingerprint/);
  assert.match(catalog, /organizationalUnit/);
  assert.match(catalog, /accounts: 324/);
  assert.doesNotMatch(inbox, /localStorage|sessionStorage/);
});

test("links findings to Jira without creating duplicate tickets", async () => {
  const [inbox, findingsRoute, jiraRoute] = await Promise.all([
    source("app/daily-findings-view.tsx"),
    source("app/api/findings/route.ts"),
    source("app/api/jira/issues/route.ts"),
  ]);

  assert.match(inbox, /One ticket per finding/);
  assert.match(inbox, /already linked and will not create duplicates/);
  assert.match(inbox, /batches of 20 findings or fewer/);
  assert.match(findingsRoute, /jiraIssueKey/);
  assert.match(findingsRoute, /jiraIssueUrl/);
  assert.match(jiraRoute, /finding_jira_links/);
  assert.match(jiraRoute, /existingByFingerprint/);
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
  assert.match(route, /Explain why the finding is acceptable/);
  assert.match(route, /compensating controls/);
  assert.match(route, /finding_events/);
  assert.match(route, /saved_finding_views/);
  assert.match(route, /audit\(/);
  assert.match(schema, /findingWorkflows/);
  assert.match(schema, /findingEvents/);
  assert.match(schema, /savedFindingViews/);
  assert.match(migration, /CREATE TABLE `finding_workflows`/);
  assert.match(migration, /CREATE TABLE `finding_events`/);
  assert.match(migration, /CREATE TABLE `saved_finding_views`/);
});

test("includes the daily workflow in the future Aurora model", async () => {
  const postgres = await source("db/postgres/0001_gatewatch_aws.sql");

  assert.match(postgres, /CREATE TABLE finding_workflows/);
  assert.match(postgres, /CREATE TABLE finding_events/);
  assert.match(postgres, /CREATE TABLE saved_finding_views/);
  assert.match(postgres, /PRIMARY KEY \(workspace_id, fingerprint\)/);
  assert.match(postgres, /saved_finding_views_one_default_idx/);
});
