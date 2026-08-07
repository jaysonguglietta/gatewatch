import assert from "node:assert/strict";
import test from "node:test";

import {
  compareInternetExposure,
  internetExposureForVerdict,
} from "../lib/finding-exposure.ts";

const finding = (fingerprint, verdict, riskScore) => ({
  fingerprint,
  verdict,
  riskScore,
});

test("maps finding verdicts to explicit internet exposure states", () => {
  assert.equal(internetExposureForVerdict("Internet path exists"), "internet");
  assert.equal(internetExposureForVerdict("Confirmed public service"), "internet");
  assert.equal(internetExposureForVerdict("Broad but unreachable"), "no-internet");
  assert.equal(internetExposureForVerdict("Internal path confirmed"), "no-internet");
  assert.equal(internetExposureForVerdict("Evidence incomplete"), "unknown");
});

test("sorts internet, unknown, and no-internet findings without conflating them", () => {
  const values = [
    finding("blocked", "Broad but unreachable", 90),
    finding("unknown", "Evidence incomplete", 95),
    finding("internet-low", "Internet path exists", 60),
    finding("internet-high", "Confirmed public service", 80),
  ];
  const internetFirst = [...values].sort((left, right) =>
    compareInternetExposure(left, right, "internet"),
  );
  assert.deepEqual(
    internetFirst.map((item) => item.fingerprint),
    ["internet-high", "internet-low", "unknown", "blocked"],
  );
  const noInternetFirst = [...values].sort((left, right) =>
    compareInternetExposure(left, right, "no-internet"),
  );
  assert.deepEqual(
    noInternetFirst.map((item) => item.fingerprint),
    ["blocked", "unknown", "internet-high", "internet-low"],
  );
});
