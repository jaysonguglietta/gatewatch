import { env } from "cloudflare:workers";
import { findingCatalog, findingCatalogForGroups } from "../../../../lib/daily-findings";
import { configuredAwsInventory, loadAwsInventory } from "../../../../lib/aws-inventory";
import { callJiraBridge } from "../../../../lib/jira-bridge";
import {
  acceptsJson,
  apiJson,
  audit,
  ensureAdminSchema,
  requireAdmin,
  sameOrigin,
} from "../../../../lib/server-admin";
import { cleanText } from "../../../../lib/admin-sources";

type JiraResult = {
  created: Array<{ fingerprint: string; key: string; url: string }>;
  failed: Array<{ fingerprint: string; error: string }>;
  projectKey: string;
};

export async function POST(request: Request) {
  const auth = await requireAdmin(request);
  if (!auth.allowed) return apiJson({ error: "Administrator access is required to create Jira tickets." }, 403);
  if (!sameOrigin(request)) return apiJson({ error: "Origin is not allowed." }, 403);
  if (!acceptsJson(request, 30_000)) return apiJson({ error: "A bounded JSON request is required." }, 415);
  try {
    await ensureAdminSchema();
    const input = (await request.json()) as Record<string, unknown>;
    const fingerprints = [
      ...new Set(
        (Array.isArray(input.fingerprints) ? input.fingerprints : [])
          .map((value) => cleanText(value, 200))
          .filter(Boolean),
      ),
    ];
    if (!fingerprints.length) return apiJson({ error: "Select at least one finding." }, 400);
    if (fingerprints.length > 20) {
      return apiJson({ error: "Create Jira tickets in batches of 20 findings or fewer." }, 400);
    }

    const existingResult = await env.DB.prepare(
      `SELECT fingerprint, issue_key AS issueKey, issue_url AS issueUrl
       FROM finding_jira_links WHERE workspace_id = 'default'`,
    ).all<{ fingerprint: string; issueKey: string; issueUrl: string }>();
    const existingByFingerprint = new Map(
      existingResult.results.map((item) => [item.fingerprint, item]),
    );
    const existing = fingerprints
      .map((fingerprint) => existingByFingerprint.get(fingerprint))
      .filter((item): item is { fingerprint: string; issueKey: string; issueUrl: string } => Boolean(item));
    const pending = fingerprints.filter((fingerprint) => !existingByFingerprint.has(fingerprint));

    const catalog = configuredAwsInventory()
      ? await loadAwsInventory().then((inventory) =>
          findingCatalogForGroups(inventory.groups, {
            live: true,
            snapshotId: inventory.source.snapshotId,
          }),
        )
      : findingCatalog;
    const byFingerprint = new Map(catalog.map((finding) => [finding.fingerprint, finding]));
    const unknown = pending.find((fingerprint) => !byFingerprint.has(fingerprint));
    if (unknown) return apiJson({ error: "One or more selected findings are no longer available." }, 409);

    const result: JiraResult = pending.length
      ? await callJiraBridge<JiraResult>("/jira/issues", "POST", {
          findings: pending.map((fingerprint) => {
            const finding = byFingerprint.get(fingerprint)!;
            return {
              fingerprint: finding.fingerprint,
              title: finding.title,
              securityGroupId: finding.securityGroupId,
              securityGroupName: finding.securityGroupName,
              accountId: finding.accountId,
              accountName: finding.accountName,
              region: finding.region,
              severity: finding.severity,
              riskScore: finding.riskScore,
              ruleSummary: finding.ruleSummary,
              pathSummary: finding.pathSummary,
              owner: finding.owner,
              recommendation: finding.recommendation,
            };
          }),
        })
      : { created: [], failed: [], projectKey: existing[0]?.issueKey.split("-")[0] ?? "" };

    if (result.created.length) {
      await env.DB.batch(
        result.created.flatMap((issue) => [
          env.DB.prepare(
            `INSERT INTO finding_jira_links
              (fingerprint, issue_key, issue_url, created_by)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(fingerprint) DO NOTHING`,
          ).bind(issue.fingerprint, issue.key, issue.url, auth.user),
          env.DB.prepare(
            `UPDATE finding_workflows
             SET ticket_ref = CASE WHEN ticket_ref = '' THEN ? ELSE ticket_ref END,
                 updated_at = CURRENT_TIMESTAMP
             WHERE workspace_id = 'default' AND fingerprint = ?`,
          ).bind(issue.key, issue.fingerprint),
        ]),
      );
    }
    await audit(
      auth.user,
      "jira.issues_created",
      "finding",
      fingerprints.length === 1 ? fingerprints[0] : "bulk",
      `Created ${result.created.length} Jira ticket${result.created.length === 1 ? "" : "s"}; ${existing.length} already linked; ${result.failed.length} failed.`,
      { created: result.created.map((item) => item.key), existing: existing.map((item) => item.issueKey), failed: result.failed.length },
    );
    return apiJson({
      created: result.created,
      existing,
      failed: result.failed,
      projectKey: result.projectKey,
    }, result.failed.length && !result.created.length && !existing.length ? 502 : 200);
  } catch (error) {
    return apiJson({
      error: error instanceof Error ? error.message.slice(0, 240) : "Jira tickets could not be created.",
    }, 502);
  }
}
