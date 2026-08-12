import assert from "node:assert/strict";
import test from "node:test";
import {
  buildExposureOverview,
  evidenceChecksForFinding,
  exposureLaneForFinding,
  exposureTruthForFinding,
  groupSecurityGroupFindings,
  remediationPackageForFinding,
  translateNaturalLanguageHunt,
} from "../lib/security-group-triage.ts";

function dailyFinding(overrides = {}) {
  return {
    fingerprint: "gw-v2:payments:public-ssh",
    canonicalResourceKey: "aws:123456789012:us-east-1:vpc-1:security-group:sg-0123",
    securityGroupArn: "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0123",
    securityGroupId: "sg-0123",
    securityGroupName: "prod-payments-api",
    accountId: "123456789012",
    accountName: "Payments Production",
    region: "us-east-1",
    environment: "Production",
    application: "Payments API",
    owner: "Payments Platform",
    service: "Payments API",
    title: "Public SSH reaches production",
    severity: "critical",
    riskScore: 96,
    verdict: "Internet path exists",
    ageDays: 3,
    ruleSummary: "Ingress TCP/22 from 0.0.0.0/0",
    ruleId: "sgr-0123",
    ruleFlows30d: 38,
    pathStatus: "reachable",
    pathSteps: ["Internet", "igw-prod", "public route", "eni-payments"],
    pathReason: "Public route, address, NACL, and SG rule align.",
    trafficAccepted30d: 38,
    trafficCoverage: 100,
    changeApproved: false,
    changeTime: "18 min ago",
    changeEventId: "event-123",
    changeActor: "terraform-ci@payments",
    changeChannel: "Terraform",
    intentStatus: "broader-than-intent",
    intentTicket: "PAY-4812",
    approvedIntent: "Managed operations prefix to TCP 22",
    intentJustification: "Managed administration only.",
    publicRuleCount: 1,
    recommendation: "Restore the managed operations prefix list.",
    projectedRisk: 41,
    attachments: [{ id: "i-123", name: "payments-api-a", type: "EC2", criticality: "Critical", publicAddress: "198.51.100.20", tags: { Environment: "Production" } }],
    evidence: { state: "observed", confidence: 98, sources: ["AWS Config", "VPC Flow Logs", "Reachability Analyzer", "CloudTrail"], limitations: [] },
    status: "new",
    expiresAt: "",
    observationCount: 1,
    ...overrides,
  };
}

const findings = [
  dailyFinding(),
  dailyFinding({ fingerprint: "gw-v2:payments:intent", title: "Deployed access is broader than intent", ruleId: "sgr-0124", riskScore: 89 }),
  dailyFinding({ fingerprint: "gw-v2:internal", canonicalResourceKey: "aws:123456789012:us-east-1:vpc-1:security-group:sg-0456", securityGroupArn: "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0456", securityGroupId: "sg-0456", securityGroupName: "prod-database", verdict: "Internal path confirmed", pathStatus: "blocked", publicRuleCount: 0, attachments: [{ id: "db-1", name: "orders-db", type: "RDS", criticality: "High", tags: {} }], riskScore: 74, projectedRisk: 48 }),
  dailyFinding({ fingerprint: "gw-v2:unknown", canonicalResourceKey: "aws:123456789012:us-west-2:vpc-2:security-group:sg-0789", securityGroupArn: "arn:aws:ec2:us-west-2:123456789012:security-group/sg-0789", securityGroupId: "sg-0789", securityGroupName: "legacy-admin", region: "us-west-2", verdict: "Evidence incomplete", pathStatus: "unknown", pathSteps: [], trafficCoverage: 0, riskScore: 83, projectedRisk: 60 }),
];

test("consolidates contributing signals into one prioritized security-group cluster", () => {
  const clusters = groupSecurityGroupFindings(findings);
  assert.ok(clusters.length < findings.length);
  assert.ok(clusters[0].findings.length > 1);
  assert.equal(clusters[0].key, clusters[0].lead.canonicalResourceKey);
  assert.ok(clusters[0].priorityScore >= clusters.at(-1).priorityScore);
  assert.match(clusters[0].reason, /path|exposure|access/i);
});

test("separates confirmed, unknown, and internal exposure without treating a broad rule as proof", () => {
  const confirmed = findings.find((finding) => finding.verdict === "Internet path exists");
  const internal = findings.find((finding) => finding.verdict === "Internal path confirmed");
  assert.ok(confirmed);
  assert.ok(internal);
  assert.equal(exposureLaneForFinding(confirmed), "confirmed");
  assert.equal(exposureLaneForFinding(internal), "internal");
  const unknown = { ...confirmed, verdict: "Exposure unknown; route evidence incomplete" };
  assert.equal(exposureLaneForFinding(unknown), "unknown");
});

test("builds a five-step exposure truth strip and an evidence readiness checklist", () => {
  const truth = exposureTruthForFinding(findings[0]);
  assert.deepEqual(truth.map((step) => step.key), ["rule", "entry", "path", "traffic", "verdict"]);
  assert.ok(truth.every((step) => step.value));
  const checks = evidenceChecksForFinding(findings[0]);
  assert.deepEqual(checks.map((check) => check.key), ["config", "attachment", "path", "reachability", "flow", "change", "intent"]);
  assert.ok(checks.every((check) => ["complete", "partial", "missing"].includes(check.state)));
});

test("creates exposure matrix, guided-hunt counts, and outcome measures per security group", () => {
  const overview = buildExposureOverview(findings);
  assert.equal(overview.groups, groupSecurityGroupFindings(findings).length);
  assert.equal(overview.lanes.confirmed + overview.lanes.unknown + overview.lanes.internal, overview.groups);
  assert.ok(Object.keys(overview.hunts).length >= 10);
  assert.ok(overview.outcomes.potentialRiskReduction >= 0);
  assert.ok(overview.outcomes.evidenceCompletePercent >= 0 && overview.outcomes.evidenceCompletePercent <= 100);
});

test("translates plain-language hunts into inspectable deterministic query clauses", () => {
  const translation = translateNaturalLanguageHunt("Show production groups with public database access, observed traffic, and no approval in account 123456789012 last 7 days");
  assert.equal(translation.recognized, true);
  for (const clause of ["env:Production", "internet:confirmed", "port:5432", "flows:>0", "approved:false", "account:123456789012", "changed-after:"]) {
    assert.match(translation.query, new RegExp(clause.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.equal(translateNaturalLanguageHunt("something unrelated").recognized, false);
});

test("generates a reviewable remediation package without applying an AWS change", () => {
  const target = findings.find((finding) => /TCP\/22 from 0\.0\.0\.0\/0/.test(finding.ruleSummary));
  assert.ok(target);
  const remediation = remediationPackageForFinding(target);
  assert.match(remediation.cli, /revoke-security-group-ingress/);
  assert.match(remediation.cli, new RegExp(target.securityGroupId));
  assert.match(remediation.cloudFormation, /Approved intent/);
  assert.equal(remediation.verification.length, 3);
});
