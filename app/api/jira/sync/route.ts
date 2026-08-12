import { env } from "cloudflare:workers";
import { callJiraBridge } from "../../../../lib/jira-bridge";
import {
  apiJson,
  audit,
  ensureAdminSchema,
  requirePermission,
  sameOrigin,
} from "../../../../lib/server-admin";

type SyncResult = {
  syncedAt: string;
  issues: Array<{
    key: string;
    status?: string;
    statusCategory?: string;
    resolution?: string;
    updatedAt?: string;
    error?: string;
  }>;
};

async function ensureSyncColumns() {
  const columns = await env.DB.prepare("PRAGMA table_info(finding_jira_links)")
    .all<{ name: string }>();
  const names = new Set(columns.results.map((column) => column.name));
  const changes = [
    ["remote_status", "ALTER TABLE finding_jira_links ADD COLUMN remote_status TEXT NOT NULL DEFAULT ''"],
    ["remote_resolution", "ALTER TABLE finding_jira_links ADD COLUMN remote_resolution TEXT NOT NULL DEFAULT ''"],
    ["remote_updated_at", "ALTER TABLE finding_jira_links ADD COLUMN remote_updated_at TEXT NOT NULL DEFAULT ''"],
    ["last_synced_at", "ALTER TABLE finding_jira_links ADD COLUMN last_synced_at TEXT NOT NULL DEFAULT ''"],
  ];
  for (const [name, statement] of changes) {
    if (!names.has(name)) await env.DB.prepare(statement).run();
  }
}

export async function POST(request: Request) {
  const authorization = await requirePermission(request, "integrations.sync");
  if (!authorization.allowed) return apiJson({ error: "Analyst access is required to synchronize Jira." }, 403);
  if (!sameOrigin(request)) return apiJson({ error: "Origin is not allowed." }, 403);
  try {
    await ensureAdminSchema();
    await ensureSyncColumns();
    const links = await env.DB.prepare(
      `SELECT fingerprint, issue_key AS issueKey
       FROM finding_jira_links WHERE workspace_id = 'default'
       ORDER BY created_at DESC LIMIT 50`,
    ).all<{ fingerprint: string; issueKey: string }>();
    if (!links.results.length) return apiJson({ synced: 0, issues: [] });
    const result = await callJiraBridge<SyncResult>("/jira/sync", "POST", {
      issueKeys: links.results.map((link) => link.issueKey),
    });
    const statements = result.issues
      .filter((issue) => !issue.error)
      .map((issue) =>
        env.DB.prepare(
          `UPDATE finding_jira_links
           SET remote_status = ?, remote_resolution = ?, remote_updated_at = ?,
               last_synced_at = ?
           WHERE workspace_id = 'default' AND issue_key = ?`,
        ).bind(
          issue.status ?? "",
          issue.resolution ?? "",
          issue.updatedAt ?? "",
          result.syncedAt,
          issue.key,
        ),
      );
    if (statements.length) await env.DB.batch(statements);
    await audit(authorization.user, "jira.synced", "jira-cloud", "default", `Synchronized ${statements.length} Jira issues.`);
    return apiJson({
      synced: statements.length,
      failed: result.issues.filter((issue) => issue.error).length,
      issues: result.issues,
      syncedAt: result.syncedAt,
    });
  } catch (error) {
    return apiJson(
      { error: error instanceof Error ? error.message : "Jira synchronization failed." },
      503,
    );
  }
}
