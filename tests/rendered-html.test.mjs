import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("ships the Gatewatch product shell and production metadata", async () => {
  const [page, dashboard, layout, hosting, packageJson] = await Promise.all([
    readFile(new URL("app/page.tsx", root), "utf8"),
    readFile(new URL("app/security-dashboard.tsx", root), "utf8"),
    readFile(new URL("app/layout.tsx", root), "utf8"),
    readFile(new URL(".openai/hosting.json", root), "utf8"),
    readFile(new URL("package.json", root), "utf8"),
  ]);

  assert.match(page, /<SecurityDashboard \/>/);
  assert.match(dashboard, /Focus on reachable risk\./);
  assert.match(dashboard, /Priority review queue/);
  assert.match(dashboard, /Follow the path, not the rule\./);
  assert.match(dashboard, /Explainable risk calculation/);
  assert.match(dashboard, /VPC Flow Logs/);
  assert.match(dashboard, /Simulate remediation/);
  assert.match(dashboard, /Export evidence/);
  assert.match(layout, /Gatewatch — AWS Security Group Posture/);
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
});
