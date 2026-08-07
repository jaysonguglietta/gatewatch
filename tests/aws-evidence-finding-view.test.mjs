import assert from "node:assert/strict";
import test from "node:test";

import { canonicalSecurityGroupArn } from "../lib/aws-evidence-batch.ts";
import {
  filterAndSortFindings,
  findingMatchesQuery,
  groupConsolidatedFindings,
} from "../lib/aws-evidence-finding-view.ts";

function finding(index, overrides = {}) {
  const accountId = String(100000000000 + index).padStart(12, "0");
  const region = index % 2 ? "us-east-1" : "eu-west-1";
  const securityGroupId = `sg-${String(index).padStart(12, "0")}`;
  const securityGroupArn = `arn:aws:ec2:${region}:${accountId}:security-group/${securityGroupId}`;
  return {
    key: securityGroupArn,
    securityGroupArn,
    securityGroupId,
    name: `workload-${index}`,
    accountId,
    region,
    severity: index % 4 === 0 ? "critical" : index % 4 === 1 ? "high" : index % 4 === 2 ? "medium" : "low",
    riskScore: index % 100,
    sources: index % 3 ? ["AWS Config snapshot", "VPC Flow Logs"] : ["AWS Config snapshot", "AWS Security Hub findings", "Amazon GuardDuty findings"],
    evidenceClasses: index % 3 ? ["configuration", "observed-traffic"] : ["configuration", "threat-finding"],
    evidence: Array.from({ length: (index % 8) + 1 }, (_, evidenceIndex) => ({
      fingerprint: `${index}-${evidenceIndex}`,
      sourceType: "config-snapshot",
      sourceLabel: "AWS Config snapshot",
      evidenceClass: "configuration",
      fileName: "sample.json",
      correlation: "direct",
      record: { id: `${index}-${evidenceIndex}`, observedAt: "2026-08-07T12:00:00Z", accountId, region, resource: securityGroupId, event: "OK", disposition: "1 network rule", source: "", destination: securityGroupArn, summary: `workload ${index}`, raw: {} },
    })),
    directEvidenceCount: 1,
    relatedEvidenceCount: index % 8,
    firstObservedAt: "2026-08-07T11:00:00Z",
    lastObservedAt: `2026-08-07T12:${String(index % 60).padStart(2, "0")}:00Z`,
    summary: `Consolidated workload ${index}`,
    ...overrides,
  };
}

test("canonical security-group ARNs preserve the observed AWS partition", () => {
  const arn = "arn:aws-us-gov:ec2:us-gov-west-1:123456789012:security-group/sg-0123456789abcdef0";
  assert.equal(canonicalSecurityGroupArn("123456789012", "us-gov-west-1", "sg-0123456789abcdef0", [{ record: { resource: arn, destination: "", raw: {} } }]), arn);
  assert.equal(canonicalSecurityGroupArn("", "us-east-1", "sg-0123456789abcdef0"), "");
});

test("advanced finding search supports field clauses, quotes, ranges, and AND matching", () => {
  const target = finding(44, { name: "payments edge", riskScore: 92, severity: "critical", sources: ["AWS Config snapshot", "AWS Security Hub findings"] });
  assert.equal(findingMatchesQuery(target, `account:${target.accountId} region:${target.region} severity:critical risk:>=90`), true);
  assert.equal(findingMatchesQuery(target, `name:"payments edge" source:"Security Hub"`), true);
  assert.equal(findingMatchesQuery(target, `arn:${target.securityGroupArn} risk:90-95`), true);
  assert.equal(findingMatchesQuery(target, "severity:low"), false);
});

test("filtering, sorting, and grouping remain deterministic for 600 AWS accounts", () => {
  const findings = Array.from({ length: 600 }, (_, index) => finding(index));
  const filtered = filterAndSortFindings(findings, {
    query: "risk:>=75",
    accountId: "",
    region: "us-east-1",
    severity: "",
    source: "AWS Config snapshot",
    evidenceClass: "configuration",
    sort: "risk-desc",
  });
  assert.ok(filtered.length > 0);
  assert.ok(filtered.every((item) => item.region === "us-east-1" && item.riskScore >= 75));
  assert.ok(filtered.every((item, index) => index === 0 || filtered[index - 1].riskScore >= item.riskScore));
  const grouped = groupConsolidatedFindings(filtered, "account-region");
  assert.equal(grouped.length, filtered.length);
  assert.equal(grouped.reduce((sum, group) => sum + group.findings.length, 0), filtered.length);
});
