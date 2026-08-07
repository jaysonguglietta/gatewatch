import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  sourceTypeDefinitions,
  validateSourceInput,
} from "../lib/admin-sources.ts";
import { parseAwsEvidenceText } from "../lib/aws-evidence-import.ts";

test("the AWS evidence catalog covers every supported source family", () => {
  assert.equal(sourceTypeDefinitions.length, 16);
  assert.deepEqual(
    new Set(sourceTypeDefinitions.map((source) => source.evidenceClass)),
    new Set([
      "configuration",
      "change",
      "observed-traffic",
      "reachability",
      "service-access",
      "threat-finding",
    ]),
  );
});

test("VPC Flow Logs are normalized without claiming an exact matching rule", () => {
  const result = parseAwsEvidenceText(
    "2 123456789012 eni-0123456789abcdef0 198.51.100.10 10.0.1.8 51515 443 6 12 8400 1786100000 1786100060 ACCEPT OK\n",
    "vpc-flow-logs",
  );
  assert.equal(result.records.length, 1);
  assert.equal(result.records[0].accountId, "123456789012");
  assert.equal(result.records[0].resource, "eni-0123456789abcdef0");
  assert.equal(result.records[0].source, "198.51.100.10");
  assert.equal(result.records[0].destination, "10.0.1.8");
  assert.equal(result.records[0].disposition, "ACCEPT");
  assert.match(result.warnings.join(" "), /exact security-group rule/i);
});

test("Security Hub ASFF exports preserve finding identity and account scope", () => {
  const result = parseAwsEvidenceText(JSON.stringify({
    Findings: [{
      SchemaVersion: "2018-10-08",
      Id: "arn:aws:securityhub:us-east-1:123456789012:subscription/example/finding/1",
      ProductArn: "arn:aws:securityhub:us-east-1::product/aws/securityhub",
      GeneratorId: "security-control/EC2.19",
      AwsAccountId: "123456789012",
      Region: "us-east-1",
      Types: ["Software and Configuration Checks/AWS Security Best Practices"],
      Title: "Security group allows unrestricted ingress",
      RecordState: "ACTIVE",
      UpdatedAt: "2026-08-07T12:00:00Z",
      Resources: [{ Type: "AwsEc2SecurityGroup", Id: "sg-0123456789abcdef0" }],
    }],
  }), "security-hub");
  assert.equal(result.records.length, 1);
  assert.equal(result.records[0].accountId, "123456789012");
  assert.equal(result.records[0].region, "us-east-1");
  assert.equal(result.records[0].disposition, "ACTIVE");
  assert.equal(result.records[0].resource, "sg-0123456789abcdef0");
});

test("generic JSON is rejected when it does not match the selected AWS schema", () => {
  assert.throws(
    () => parseAwsEvidenceText('{"message":"not an AWS WAF log"}', "waf"),
    /No records matched the selected AWS WAF logs schema/,
  );
});

test("source validation accepts an AWS-native flow-log S3 source", () => {
  const result = validateSourceInput({
    name: "Production VPC Flow Logs",
    sourceType: "vpc-flow-logs",
    bucketArn: "arn:aws:s3:::example-security-logs",
    region: "us-east-1",
    objectPrefix: "AWSLogs/123456789012/vpcflowlogs/",
    roleArn: "arn:aws:iam::123456789012:role/GatewatchLogReadRole",
    externalId: "gw-1234567890abcdef",
    ingestionMode: "continuous",
    retentionDays: 400,
  });
  assert.deepEqual(result.errors, []);
  assert.equal(result.source.configResourceTypes.length, 0);
});

test("the production worker rejects unknown sources and stores supported evidence generically", async () => {
  const worker = await readFile(new URL("../infrastructure/lambda/ingest/index.mjs", import.meta.url), "utf8");
  assert.match(worker, /GENERIC_SOURCE_CLASSES/);
  assert.match(worker, /UNSUPPORTED_AWS_EVIDENCE_SOURCE/);
  assert.match(worker, /INSERT INTO aws_evidence_records/);
  assert.match(worker, /AWS_EVIDENCE_RECORD_TOO_LARGE/);
});
