import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

async function source(path) {
  return readFile(new URL(path, root), "utf8");
}

test("ships the complete AWS administration workflow", async () => {
  const [view, route, settings, schema, migration, helpers] = await Promise.all([
    source("app/admin-view.tsx"),
    source("app/api/admin/sources/route.ts"),
    source("app/api/admin/settings/route.ts"),
    source("db/schema.ts"),
    source("drizzle/0005_lame_senator_kelly.sql"),
    source("lib/admin-sources.ts"),
  ]);

  assert.match(view, /Add S3 source/);
  assert.match(view, /Test connection/);
  assert.match(view, /Ingestion runs/);
  assert.match(view, /Access & roles/);
  assert.match(view, /Administrative audit log/);
  assert.match(route, /Administrator access is required/);
  assert.match(route, /successful live AWS connection test is required/i);
  assert.match(route, /Raw S3 objects were not modified/);
  assert.match(settings, /You cannot remove your own administrator assignment/);
  assert.match(schema, /ingestionSources/);
  assert.match(schema, /normalizedCloudTrailEvents/);
  assert.match(migration, /CREATE TABLE `ingestion_sources`/);
  assert.match(helpers, /sts:ExternalId/);
  assert.match(helpers, /s3:GetObjectVersion/);
  assert.doesNotMatch(helpers, /AccessKeyId|SecretAccessKey/);
});

test("ships bounded, duplicate-safe AWS ingestion and backfill infrastructure", async () => {
  const [worker, backfill, platform, forwarding, postgres, configParser] =
    await Promise.all([
      source("infrastructure/lambda/ingest/index.mjs"),
      source("infrastructure/lambda/backfill/index.mjs"),
      source("infrastructure/cloudformation/gatewatch-aws-platform.yaml"),
      source(
        "infrastructure/cloudformation/gatewatch-s3-event-forwarding.yaml",
      ),
      source("db/postgres/0001_gatewatch_aws.sql"),
      source("lib/aws-config-import.ts"),
    ]);

  assert.match(worker, /MAX_COMPRESSED_BYTES/);
  assert.match(worker, /maxOutputLength: MAX_DECOMPRESSED_BYTES/);
  assert.match(worker, /ON CONFLICT .* DO NOTHING/s);
  assert.match(worker, /batchItemFailures/);
  assert.match(worker, /gatewatch_apply_security_group_config/);
  assert.match(worker, /gatewatch_correlate_cloudtrail_event/);
  assert.match(backfill, /ContinuationToken/);
  assert.match(backfill, /SendMessageBatchCommand/);
  assert.match(platform, /AWS::RDS::DBCluster/);
  assert.match(platform, /AWS::StepFunctions::StateMachine/);
  assert.match(platform, /ReportBatchItemFailures/);
  assert.match(platform, /maxReceiveCount: 5/);
  assert.match(platform, /EnableHttpEndpoint: true/);
  assert.match(forwarding, /detail-type:/);
  assert.match(forwarding, /Object Created/);
  assert.match(postgres, /PARTITION OF cloudtrail_events DEFAULT/);
  assert.match(postgres, /internet-wide-access/);
  assert.match(configParser, /AWS::EC2::SecurityGroup/);
  assert.match(configParser, /correlateConfigAndCloudTrail/);
});

test("centralizes the local administrator bypass and disables it in production", async () => {
  const [admin, reviews, governance] = await Promise.all([
    source("lib/server-admin.ts"),
    source("app/api/reviews/route.ts"),
    source("app/api/governance/route.ts"),
  ]);
  assert.match(admin, /process\.env\.NODE_ENV !== "production"/);
  assert.match(reviews, /requirePermission/);
  assert.match(governance, /requestUser\(request\)/);
  assert.doesNotMatch(governance, /local-preview@gatewatch/);
});

test("collects resource-level security-group attachment evidence", async () => {
  const [collector, snapshotSchema, inventoryMapper, findingDrawer] =
    await Promise.all([
      source("infrastructure/cloudformation/gatewatch-security-group-collector.yaml"),
      source("infrastructure/cloudformation/gatewatch-security-group-snapshot.schema.json"),
      source("lib/aws-inventory.ts"),
      source("app/daily-findings-view.tsx"),
    ]);

  for (const permission of [
    "ec2:DescribeInstances",
    "rds:DescribeDBInstances",
    "rds:DescribeDBClusters",
    "elasticfilesystem:DescribeMountTargets",
    "elasticfilesystem:DescribeMountTargetSecurityGroups",
  ]) {
    assert.match(collector, new RegExp(permission));
  }
  assert.match(collector, /resourceAttachments/);
  assert.match(collector, /AWS::EC2::Instance/);
  assert.match(collector, /AWS::RDS::DBInstance/);
  assert.match(collector, /AWS::EFS::FileSystem/);
  assert.match(
    collector,
    /"describe_security_group_rules",[\s\S]{0,120}PaginationConfig=\{"PageSize": 100\}/,
  );
  assert.doesNotMatch(collector, /PaginationConfig=\{"PageSize": 1000\}/);
  assert.match(snapshotSchema, /"resourceAttachment"/);
  assert.match(snapshotSchema, /"networkInterfaceId"/);
  assert.match(inventoryMapper, /normalizedAttachmentType/);
  assert.match(findingDrawer, /Attached resources/);
  assert.match(findingDrawer, /No resource tags returned by AWS/);
});

test("keeps Jira credentials server-side and supports duplicate-safe issue creation", async () => {
  const [template, bridge, adminRoute, issueRoute, schema] = await Promise.all([
    source("infrastructure/cloudformation/gatewatch-aws-web.yaml"),
    source("infrastructure/aws-web/aws-bridge.mjs"),
    source("app/api/admin/jira/route.ts"),
    source("app/api/jira/issues/route.ts"),
    source("lib/server-admin.ts"),
  ]);

  assert.match(template, /JiraIntegrationSecret:/);
  assert.match(template, /secretsmanager:PutSecretValue/);
  assert.match(bridge, /\.endsWith\("\.atlassian\.net"\)/);
  assert.match(bridge, /redirect: "error"/);
  assert.match(bridge, /JIRA_FINDINGS_LIMIT/);
  assert.match(bridge, /Configure Jira Cloud in Admin → Integrations/);
  assert.match(bridge, /Browse Projects and Create Issues permissions/);
  assert.match(bridge, /description: jiraDescription\(finding\)/);
  assert.match(adminRoute, /Administrator access is required/);
  assert.doesNotMatch(adminRoute, /apiToken:\s*result/);
  assert.match(issueRoute, /batches of 20 findings or fewer/);
  assert.match(issueRoute, /ON CONFLICT\(fingerprint\) DO NOTHING/);
  assert.match(issueRoute, /jira\.issues_created/);
  assert.match(schema, /CREATE TABLE IF NOT EXISTS finding_jira_links/);
});

test("ships authenticated detailed reporting with CSV injection protection", async () => {
  const [dashboard, reportView, reportRoute, csv] = await Promise.all([
    source("app/security-dashboard.tsx"),
    source("app/reporting-view.tsx"),
    source("app/api/reports/route.ts"),
    source("lib/csv.ts"),
  ]);

  assert.match(dashboard, /Detailed reports/);
  assert.match(reportView, /Export detailed CSV/);
  assert.match(reportView, /Account posture/);
  assert.match(reportView, /Regional concentration/);
  assert.match(reportRoute, /Authentication is required/);
  assert.match(reportRoute, /content-disposition/);
  assert.match(reportRoute, /import \{ csvCell \}/);
  assert.match(csv, /\[=\+\\-@\\t\\r\]/);
  assert.match(reportRoute, /finding_jira_links/);
});
