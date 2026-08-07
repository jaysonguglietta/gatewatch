import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  accountContextFromGroups,
  defaultRiskWeights,
  isSecurityGroupArn,
  nextMonitorRun,
  scoreRisk,
  securityGroupArn,
  semanticEvidenceKey,
} from "../lib/organization-operations.ts";
import { securityGroups } from "../lib/security-data.ts";
import { recordFingerprint } from "../lib/aws-evidence-batch.ts";

test("creates partition-aware full security-group ARNs and rejects ambiguous identifiers", () => {
  assert.equal(
    securityGroupArn({ accountId: "123456789012", region: "us-gov-west-1", id: "sg-0123456789abcdef0" }),
    "arn:aws-us-gov:ec2:us-gov-west-1:123456789012:security-group/sg-0123456789abcdef0",
  );
  assert.equal(isSecurityGroupArn("arn:aws:ec2:us-east-1:123456789012:security-group/sg-0123456789abcdef0"), true);
  assert.equal(isSecurityGroupArn("sg-0123456789abcdef0"), false);
});

test("builds one organization account row from many security groups", () => {
  const groups = [securityGroups[0], { ...securityGroups[0], id: "sg-second", region: "us-west-2" }];
  const [account] = accountContextFromGroups(groups);
  assert.equal(account.accountId, securityGroups[0].accountId);
  assert.equal(account.groupCount, 2);
  assert.equal(account.regionCount, 2);
});

test("semantic evidence identity joins provider mirrors while preserving fallback isolation", () => {
  const base = { accountId: "123456789012", region: "us-east-1", securityGroupId: "sg-abc123", category: "threat", observedAt: "2026-08-07T14:35:42Z" };
  assert.equal(semanticEvidenceKey({ ...base, providerId: "gd-123" }), "provider:gd-123");
  assert.equal(semanticEvidenceKey({ ...base, observedAt: "2026-08-07T14:35:59Z" }), semanticEvidenceKey(base));
  assert.notEqual(semanticEvidenceKey({ ...base, observedAt: "2026-08-07T14:36:01Z" }), semanticEvidenceKey(base));
});

test("GuardDuty findings mirrored through Security Hub share one canonical event identity", () => {
  const common = { observedAt: "2026-08-07T14:35:42Z", accountId: "123456789012", region: "us-east-1", resource: "sg-abc123", event: "Recon:EC2/PortProbe", disposition: "ACTIVE", source: "", destination: "", summary: "" };
  const guardDuty = recordFingerprint("guardduty", { ...common, id: "finding-123", raw: { id: "finding-123" } });
  const securityHub = recordFingerprint("security-hub", { ...common, id: "arn:aws:securityhub:us-east-1:123456789012:finding/finding-123", raw: { Id: "arn:aws:guardduty:us-east-1:123456789012:detector/example/finding/finding-123", ProductArn: "arn:aws:securityhub:us-east-1::product/aws/guardduty" } });
  assert.equal(guardDuty, securityHub);
});

test("risk weights and recurring schedules are bounded and deterministic", () => {
  assert.equal(scoreRisk({ publicIngress: true, administrativePorts: true }, defaultRiskWeights), 58);
  assert.equal(scoreRisk(Object.fromEntries(Object.keys(defaultRiskWeights).map((key) => [key, true])), defaultRiskWeights), 100);
  assert.equal(nextMonitorRun("hourly", new Date("2026-08-07T10:00:00Z")), "2026-08-07T11:00:00.000Z");
});

test("organization operating plane is durable, authenticated, auditable, and deployed to both data stores", () => {
  const route = readFileSync("app/api/organization-operations/route.ts", "utf8");
  const ui = readFileSync("app/organization-operations-view.tsx", "utf8");
  const d1 = readFileSync("drizzle/0011_charming_beyonder.sql", "utf8");
  const postgres = readFileSync("db/postgres/0002_organization_operations.sql", "utf8");
  assert.match(route, /requestUser\(request\)/);
  assert.match(route, /sameOrigin\(request\)/);
  assert.match(route, /requirePermission/);
  assert.match(route, /await audit/);
  assert.match(route, /evidence_correlation_mappings/);
  assert.match(route, /evidence_monitor_runs/);
  assert.match(route, /evidence_export_jobs/);
  assert.match(route, /CREATE TABLE IF NOT EXISTS aws_evidence_records/);
  assert.match(route, /ALTER TABLE aws_evidence_records ADD COLUMN workspace_id/);
  assert.match(ui, /Account catalog/);
  assert.match(ui, /Correlation workbench/);
  assert.match(ui, /Create governed export/);
  assert.match(ui, /Legal holds/);
  assert.match(d1, /CREATE TABLE `evidence_monitors`/);
  assert.match(postgres, /ENABLE ROW LEVEL SECURITY/);
  assert.match(postgres, /workspace_isolation/);
});
