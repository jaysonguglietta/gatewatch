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
  assert.match(dashboard, /Good morning, Morgan\./);
  assert.match(dashboard, /Priority review queue/);
  assert.match(dashboard, /AWS Config/);
  assert.match(dashboard, /Export report/);
  assert.match(layout, /Gatewatch — AWS Security Group Posture/);
  assert.match(layout, /\/og\.png/);
  assert.match(hosting, /"d1": "DB"/);
  assert.match(packageJson, /"name": "gatewatch-security-posture"/);
  assert.doesNotMatch(
    `${page}\n${dashboard}\n${layout}`,
    /codex-preview|react-loading-skeleton/i,
  );
  await access(new URL("public/og.png", root));
  await access(new URL("drizzle/0000_glamorous_amazoness.sql", root));
});
