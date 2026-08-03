import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { gunzipSync } from "node:zlib";
import { parseCloudTrailText } from "../lib/cloudtrail-import.ts";

const detailedSample = new URL(
  "../samples/cloudtrail-security-groups-detailed-10000.json.gz",
  import.meta.url,
);

test("detailed CloudTrail sample exercises correlation and negative paths", async () => {
  const compressed = await readFile(detailedSample);
  const text = gunzipSync(compressed).toString("utf8");
  const parsed = JSON.parse(text);
  const result = parseCloudTrailText(text);

  assert.equal(parsed.Records.length, 10_000);
  assert.equal(result.totalRecords, 10_000);
  assert.equal(result.events.length, 8_572);
  assert.equal(result.skippedRecords, 1_428);
  assert.equal(result.internetWideChanges, 2_833);
  assert.ok(result.events.some((event) => event.actorType === "AWSService"));
  assert.ok(result.events.some((event) => event.actorType === "FederatedUser"));
  assert.ok(result.events.some((event) => event.errorCode));
  assert.ok(result.events.some((event) => event.cidrs.includes("::/0")));
  assert.ok(result.events.some((event) => event.groupIds.includes("sg-0377cc6c3353a1686")));
  assert.ok(Buffer.byteLength(text) < 50 * 1024 * 1024);
  assert.equal(
    createHash("sha256").update(compressed).digest("hex"),
    "dc8030249bc381798bacaa8e50a23bddda35d85d0741cb99b06b1bf06cd5be75",
  );
});
