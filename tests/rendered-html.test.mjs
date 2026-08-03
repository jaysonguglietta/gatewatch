import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("ships the Gatewatch product shell and production metadata", async () => {
  const [
    page,
    dashboard,
    layout,
    hosting,
    packageJson,
    governanceRoute,
    governanceData,
    cloudTrailImport,
    sampleGenerator,
  ] = await Promise.all([
    readFile(new URL("app/page.tsx", root), "utf8"),
    readFile(new URL("app/security-dashboard.tsx", root), "utf8"),
    readFile(new URL("app/layout.tsx", root), "utf8"),
    readFile(new URL(".openai/hosting.json", root), "utf8"),
    readFile(new URL("package.json", root), "utf8"),
    readFile(new URL("app/api/governance/route.ts", root), "utf8"),
    readFile(new URL("lib/governance-data.ts", root), "utf8"),
    readFile(new URL("lib/cloudtrail-import.ts", root), "utf8"),
    readFile(
      new URL("scripts/generate-sample-cloudtrail.mjs", root),
      "utf8",
    ),
  ]);

  assert.match(page, /<SecurityDashboard \/>/);
  assert.match(dashboard, /Find rules that may be too broad\./);
  assert.match(dashboard, /Potentially overbroad rules/);
  assert.match(dashboard, /0\.0\.0\.0\/0 or ::\/0/);
  assert.match(dashboard, /Ingress and egress/);
  assert.match(dashboard, /Priority review queue/);
  assert.match(dashboard, /Follow the path, not the rule\./);
  assert.match(dashboard, /Explainable risk calculation/);
  assert.match(dashboard, /VPC Flow Logs/);
  assert.match(dashboard, /Simulate remediation/);
  assert.match(dashboard, /Export evidence/);
  assert.match(dashboard, /Ask what can reach what\./);
  assert.match(dashboard, /Versioned access policies/);
  assert.match(dashboard, /Protect applications, not rule IDs\./);
  assert.match(dashboard, /Govern access as a campaign\./);
  assert.match(dashboard, /Fix the paths that matter most\./);
  assert.match(dashboard, /Connectivity history/);
  assert.match(dashboard, /Hand off analysis and enforcement safely\./);
  assert.match(dashboard, /Simulation only · no AWS write permission/);
  assert.match(dashboard, /Drag in an AWS CloudTrail log\./);
  assert.match(dashboard, /Your log stays on this device/);
  assert.match(dashboard, /JSON or JSON\.GZ/);
  assert.match(dashboard, /Clear session/);
  assert.match(dashboard, /Page <strong>/);
  assert.match(governanceRoute, /sameOrigin/);
  assert.match(governanceRoute, /access_policies/);
  assert.match(governanceRoute, /recertification_campaigns/);
  assert.match(governanceData, /Production database boundary/);
  assert.match(governanceData, /pathsBroken/);
  assert.match(cloudTrailImport, /AuthorizeSecurityGroupIngress/);
  assert.match(cloudTrailImport, /MAX_DECOMPRESSED_BYTES/);
  assert.match(cloudTrailImport, /50_000/);
  assert.match(sampleGenerator, /const recordCount = 50_000/);
  assert.match(sampleGenerator, /AuthorizeSecurityGroupIngress/);
  assert.match(layout, /Gatewatch — AWS Network Access Governance/);
  assert.match(layout, /\/og-evidence\.png/);
  assert.match(hosting, /"d1": "DB"/);
  assert.match(packageJson, /"name": "gatewatch-security-posture"/);
  assert.doesNotMatch(
    `${page}\n${dashboard}\n${layout}`,
    /codex-preview|react-loading-skeleton/i,
  );
  await access(new URL("public/og-evidence.png", root));
  await access(new URL("drizzle/0000_glamorous_amazoness.sql", root));
  await access(new URL("drizzle/0001_nosy_queen_noir.sql", root));
  await access(new URL("drizzle/0002_dashing_exodus.sql", root));
  await access(new URL("drizzle/0004_amused_stryfe.sql", root));
  await access(
    new URL("samples/cloudtrail-security-groups-50000.json.gz", root),
  );
});
