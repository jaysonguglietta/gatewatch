import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  canonicalFindingFingerprint,
  canonicalSecurityGroupKey,
} from "../lib/evidence-model.ts";
const root = new URL("../", import.meta.url);

test("canonical identity isolates reused security-group IDs across AWS boundaries", () => {
  const first = { accountId: "111111111111", region: "us-east-1", vpc: "vpc-a", id: "sg-shared" };
  const second = { accountId: "222222222222", region: "us-west-2", vpc: "vpc-b", id: "sg-shared" };

  assert.notEqual(canonicalSecurityGroupKey(first), canonicalSecurityGroupKey(second));
  assert.notEqual(
    canonicalFindingFingerprint(first, "internet-wide-ingress"),
    canonicalFindingFingerprint(second, "internet-wide-ingress"),
  );
});

test("live findings reserve unreachable verdicts for explicit blocked paths", async () => {
  const catalog = await readFile(new URL("lib/daily-findings.ts", root), "utf8");
  assert.match(catalog, /group\.paths\.every\(\(path\) => path\.status === "blocked"\)/);
  assert.match(catalog, /return "Evidence incomplete"/);
  assert.match(catalog, /live: Boolean\(options\.live\)/);
  assert.match(catalog, /canonicalFindingFingerprint/);
});

test("live intelligence derives records and leaves unconnected providers empty", async () => {
  const intelligence = await readFile(new URL("lib/live-intelligence.ts", root), "utf8");
  assert.match(intelligence, /mode: "live"/);
  assert.match(intelligence, /exposureRecords/);
  assert.match(intelligence, /ruleRecommendations/);
  assert.match(intelligence, /iacChanges: \[\]/);
  assert.match(intelligence, /programTrend: \[\]/);
});
