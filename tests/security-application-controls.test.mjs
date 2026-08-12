import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { csvCell } from "../lib/csv.ts";
import {
  HttpInputError,
  readBoundedJson,
} from "../lib/http-security.ts";
import {
  canonicalJson,
  remediationDigest,
} from "../lib/security-integrity.ts";

const root = new URL("../", import.meta.url);
const source = (path) => readFile(new URL(path, root), "utf8");

test("bounded JSON rejects chunked bodies after the actual byte limit", async () => {
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode('{"value":"'));
      controller.enqueue(new TextEncoder().encode("x".repeat(128)));
      controller.enqueue(new TextEncoder().encode('"}'));
      controller.close();
    },
  });
  const request = new Request("https://gatewatch.example/api/test", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
    duplex: "half",
  });
  await assert.rejects(
    readBoundedJson(request, 32),
    (error) => error instanceof HttpInputError && error.status === 413,
  );
});

test("bounded JSON validates media type, declared length, UTF-8, and syntax", async () => {
  await assert.rejects(
    readBoundedJson(new Request("https://gatewatch.example", {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: "{}",
    }), 32),
    (error) => error instanceof HttpInputError && error.status === 415,
  );
  await assert.rejects(
    readBoundedJson(new Request("https://gatewatch.example", {
      method: "POST",
      headers: { "content-type": "application/json", "content-length": "99" },
      body: "{}",
    }), 32),
    (error) => error instanceof HttpInputError && error.status === 413,
  );
  await assert.rejects(
    readBoundedJson(new Request("https://gatewatch.example", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "not-json",
    }), 32),
    (error) => error instanceof HttpInputError && error.status === 400,
  );
});

test("remediation digests are canonical and approval-bound", async () => {
  assert.equal(
    canonicalJson({ z: 1, a: { y: 2, x: 3 } }),
    canonicalJson({ a: { x: 3, y: 2 }, z: 1 }),
  );
  const baseline = {
    fingerprint: "gw-v2:finding",
    canonicalResourceKey: "aws:123456789012:us-east-1:vpc-1:security-group:sg-1",
    proposedChange: "Replace 0.0.0.0/0 with the approved prefix list.",
    artifactType: "iac-change-request",
    evidenceBefore: { riskScore: 96, sources: ["AWS Config"] },
  };
  const approved = await remediationDigest(baseline);
  assert.match(approved, /^[a-f0-9]{64}$/);
  assert.notEqual(
    approved,
    await remediationDigest({ ...baseline, proposedChange: `${baseline.proposedChange} ` }),
  );
});

test("every CSV export formula prefix is encoded as inert text", () => {
  for (const prefix of ["=", "+", "-", "@", "\t", "\r"]) {
    assert.equal(csvCell(`${prefix}SUM(1,1)`).startsWith("\"'"), true);
  }
});

test("IaC, remediation, AI, and role routes enforce authoritative trust decisions", async () => {
  const [iac, remediation, ai, ui, permissions, governance, jiraSync, organizationRoute] = await Promise.all([
    source("app/api/iac/evaluate/route.ts"),
    source("app/api/remediations/route.ts"),
    source("app/api/ai/analysis/route.ts"),
    source("app/daily-findings-view.tsx"),
    source("lib/server-admin.ts"),
    source("app/api/governance/route.ts"),
    source("app/api/jira/sync/route.ts"),
    source("app/api/organization-operations/route.ts"),
  ]);

  assert.match(iac, /reviewInfrastructureFile/);
  assert.match(iac, /artifactDigest/);
  assert.doesNotMatch(iac, /input\.currentRisk|input\.projectedRisk/);
  assert.match(remediation, /approved_digest/);
  assert.match(remediation, /version = approved_version/);
  assert.match(remediation, /cannot approve their own change/);
  assert.match(ai, /canonicalFindings/);
  assert.doesNotMatch(ai, /input\.findings|input\.finding\b/);
  assert.match(ui, /fingerprints: findings\.map/);
  assert.match(permissions, /"governance\.manage": new Set\(\["admin", "analyst"\]\)/);
  assert.match(permissions, /"governance\.review": new Set\(\["admin", "analyst", "reviewer"\]\)/);
  assert.match(governance, /\["activate", "retire"\]\.includes\(action\)/);
  assert.match(jiraSync, /"integrations\.sync"/);
  assert.match(organizationRoute, /import \{ csvCell \} from "\.\.\/\.\.\/\.\.\/lib\/csv"/);
});

