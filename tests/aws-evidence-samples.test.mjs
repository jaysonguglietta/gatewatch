import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { gunzipSync } from "node:zlib";
import test from "node:test";

import { consolidateAwsEvidence, detectAwsEvidenceText } from "../lib/aws-evidence-batch.ts";
import { securityGroups } from "../lib/security-data.ts";

const sampleDirectory = resolve("samples/aws-evidence-batch");
const manifest = JSON.parse(readFileSync(resolve(sampleDirectory, "manifest.json"), "utf8"));

function sampleText(name) {
  const content = readFileSync(resolve(sampleDirectory, name));
  return name.endsWith(".gz") ? gunzipSync(content).toString("utf8") : content.toString("utf8");
}

test("the mixed AWS evidence sample pack detects every requested source", () => {
  const detected = new Set();
  for (const file of manifest.files) {
    const result = detectAwsEvidenceText(sampleText(file.name), file.name);
    assert.equal(result.sourceType, file.sourceType, file.name);
    detected.add(result.sourceType);
  }
  assert.deepEqual(detected, new Set([
    "config-snapshot",
    "config-history",
    "cloudtrail",
    "vpc-flow-logs",
    "reachability-analyzer",
    "network-access-analyzer",
    "elastic-load-balancing",
    "waf",
    "cloudfront",
    "api-gateway",
    "route53-resolver",
    "network-firewall",
    "guardduty",
    "security-hub",
  ]));
});

test("the sample pack consolidates without repeating intentional duplicates", () => {
  const importedFiles = manifest.files.map((file, index) => {
    const content = readFileSync(resolve(sampleDirectory, file.name));
    const result = detectAwsEvidenceText(sampleText(file.name), file.name);
    return {
      id: `sample-${index}`,
      name: file.name,
      size: content.length,
      digest: createHash("sha256").update(content).digest("hex"),
      status: "imported",
      sourceType: result.sourceType,
      sourceLabel: result.sourceLabel,
      recordCount: result.records.length,
      warningCount: result.warnings.length,
      result,
    };
  });
  const batch = consolidateAwsEvidence(importedFiles, securityGroups);
  const appFinding = batch.findings.find((finding) => finding.securityGroupId === "sg-0a41f2e91b71");
  const edgeFinding = batch.findings.find((finding) => finding.securityGroupId === "sg-0d3c99118aae");

  assert.equal(batch.duplicateRecords, manifest.intentionalDuplicateRecords);
  assert.ok(appFinding, "expected the primary application security-group finding");
  assert.ok(edgeFinding, "expected the edge security-group finding");
  assert.equal(appFinding.securityGroupArn, "arn:aws:ec2:us-east-1:428196730552:security-group/sg-0a41f2e91b71");
  assert.equal(edgeFinding.securityGroupArn, "arn:aws:ec2:us-east-1:428196730552:security-group/sg-0d3c99118aae");
  assert.ok(appFinding.sources.includes("AWS CloudTrail"));
  assert.ok(appFinding.sources.includes("VPC Flow Logs"));
  assert.ok(appFinding.sources.includes("Reachability Analyzer"));
  assert.ok(appFinding.sources.includes("Network Access Analyzer"));
  assert.ok(appFinding.sources.includes("Amazon GuardDuty findings"));
  assert.ok(appFinding.sources.includes("AWS Security Hub findings"));
  assert.ok(edgeFinding.sources.includes("ELB access logs (ALB/NLB)"));
  assert.ok(edgeFinding.sources.includes("AWS WAF logs"));
  assert.ok(edgeFinding.sources.includes("CloudFront access logs"));
  assert.ok(batch.unmatchedRecords.some((item) => item.sourceType === "network-firewall"));
  assert.equal(new Set([...batch.findings.flatMap((finding) => finding.evidence), ...batch.unmatchedRecords].map((item) => item.fingerprint)).size, batch.uniqueRecords);
});

test("the sample manifest checksums match the committed artifacts", () => {
  for (const file of manifest.files) {
    const content = readFileSync(resolve(sampleDirectory, file.name));
    assert.equal(createHash("sha256").update(content).digest("hex"), file.sha256, file.name);
    assert.equal(content.length, file.bytes, file.name);
  }
});
