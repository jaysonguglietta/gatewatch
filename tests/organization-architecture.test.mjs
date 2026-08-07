import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const source = (path) => readFile(new URL(path, root), "utf8");

test("organization collector isolates accounts and stores immutable evidence shards", async () => {
  const [template, worker] = await Promise.all([
    source("infrastructure/cloudformation/gatewatch-organization-collector.yaml"),
    source("infrastructure/lambda/organization-collector/index.py"),
  ]);

  assert.match(template, /ProcessorConfig.*Mode.*DISTRIBUTED/s);
  assert.match(template, /"Catch".*"FinalizeRun"/s);
  assert.match(template, /MaximumAccountConcurrency/);
  assert.match(template, /PointInTimeRecoveryEnabled: true/);
  assert.match(template, /DenyUnencryptedObjectWrites/);
  assert.match(template, /GatewatchSecurityGroupReadRole/);
  assert.doesNotMatch(template, /ec2:(Authorize|Revoke|Modify|Delete)SecurityGroup/);

  assert.match(worker, /def discovery_handler/);
  assert.match(worker, /def worker_handler/);
  assert.match(worker, /def finalizer_handler/);
  assert.match(worker, /accountsIncomplete/);
  assert.match(worker, /else "incomplete"/);
  assert.match(worker, /security-group-inventory-shard/);
  assert.match(worker, /canonical-sha256/);
  assert.match(worker, /ThreadPoolExecutor/);
  assert.match(worker, /"evidenceVersion": 2/);
  assert.match(worker, /has_ipv4_igw_route/);
  assert.match(worker, /publicIpv6AddressCount/);
  assert.match(worker, /direct_ipv4_path_count/);
  assert.match(worker, /item\.get\("SubnetId"\) == subnet_id/);
  assert.doesNotMatch(worker, /authorize_security_group|revoke_security_group|modify_security_group/);
});

test("platform normalizes collector shards and records explicit coverage", async () => {
  const [template, schema, ingest] = await Promise.all([
    source("infrastructure/cloudformation/gatewatch-aws-platform.yaml"),
    source("db/postgres/0001_gatewatch_aws.sql"),
    source("infrastructure/lambda/ingest/index.mjs"),
  ]);

  assert.match(template, /OrganizationEvidenceBucketName/);
  assert.match(template, /runs\/\*\/shards\/account=\*\/region=\*\/inventory\.json\.gz/);
  assert.match(template, /aws:SourceAccount/);
  assert.match(schema, /CREATE TABLE organization_collection_runs/);
  assert.match(schema, /CREATE TABLE organization_collection_targets/);
  assert.match(schema, /CREATE TABLE security_group_observations/);
  assert.match(schema, /CREATE VIEW current_security_groups/);
  assert.match(ingest, /validateInventoryShard/);
  assert.match(ingest, /processCollectionManifest/);
  assert.match(ingest, /BeginTransactionCommand/);
});

test("coverage is an authenticated, first-class operator surface", async () => {
  const [route, panel, bridge] = await Promise.all([
    source("app/api/coverage/route.ts"),
    source("app/organization-coverage-panel.tsx"),
    source("infrastructure/aws-web/aws-bridge.mjs"),
  ]);

  assert.match(route, /requestUser\(request\)/);
  assert.match(panel, /Account collection health/);
  assert.match(panel, /Needs attention/);
  assert.match(panel, /PAGE_SIZE = 25/);
  assert.match(bridge, /ORGANIZATION_MANIFEST_SCHEMA_INVALID/);
});

test("cross-account templates and CSV exports are structure-safe", async () => {
  const [sources, csv] = await Promise.all([
    source("lib/admin-sources.ts"),
    source("lib/csv.ts"),
  ]);

  assert.match(sources, /JSON\.stringify\(template, null, 2\)/);
  assert.match(sources, /16–128 character external ID/);
  assert.doesNotMatch(sources, /return `AWSTemplateFormatVersion/);
  assert.match(csv, /\^\[\\s\]\*\[=\+\\-@\\t\\r\]/);
});

test("web deployment consumes an immutable checksum-verified release", async () => {
  const [template, script, bridge] = await Promise.all([
    source("infrastructure/cloudformation/gatewatch-aws-web.yaml"),
    source("scripts/deploy-aws-web.sh"),
    source("infrastructure/aws-web/aws-bridge.mjs"),
  ]);

  assert.match(template, /ArtifactVersionId/);
  assert.match(template, /ArtifactSha256/);
  assert.match(template, /sha256sum -c -/);
  assert.match(script, /head-object/);
  assert.match(bridge, /timingSafeEqual/);
  assert.match(bridge, /SNAPSHOT_CHECKSUM_MISMATCH/);
});

test("mutating workflows use the centralized permission matrix", async () => {
  const [server, findings, reviews, governance, intelligence, remediations] = await Promise.all([
    source("lib/server-admin.ts"),
    source("app/api/findings/route.ts"),
    source("app/api/reviews/route.ts"),
    source("app/api/governance/route.ts"),
    source("app/api/intelligence/route.ts"),
    source("app/api/remediations/route.ts"),
  ]);

  assert.match(server, /permissionRoles/);
  assert.match(server, /findings\.triage/);
  assert.match(server, /remediation\.write/);
  assert.match(findings, /requirePermission\(request, "findings\.triage"\)/);
  assert.match(reviews, /requirePermission\(request, "reviews\.write"\)/);
  assert.match(governance, /requirePermission\(request, "governance\.write"\)/);
  assert.match(intelligence, /requirePermission\(request, "intelligence\.write"\)/);
  assert.match(remediations, /requirePermission\(request, "remediation\.write"\)/);
});
