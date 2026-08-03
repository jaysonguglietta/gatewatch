import { env } from "cloudflare:workers";
import { findingCatalogForGroups } from "../../../lib/daily-findings";
import { loadAwsInventory } from "../../../lib/aws-inventory";
import {
  apiJson,
  ensureAdminSchema,
  requestUser,
  safeJson,
} from "../../../lib/server-admin";

type MetricRow = {
  periodStart: string;
  metrics: string;
  evidenceCoverage: number;
  createdAt: string;
};

export async function GET(request: Request) {
  if (!requestUser(request)) {
    return apiJson({ error: "Authentication is required." }, 401);
  }
  try {
    await ensureAdminSchema();
    const inventory = await loadAwsInventory();
    const findings = findingCatalogForGroups(inventory.groups, {
      live: true,
      snapshotId: inventory.source.snapshotId,
    });
    const workflow = await env.DB.prepare(
      `SELECT status, due_at AS dueAt
       FROM finding_workflows WHERE workspace_id = 'default'`,
    ).all<{ status: string; dueAt: string }>();
    const today = new Date().toISOString().slice(0, 10);
    const metrics = {
      securityGroups: inventory.groups.length,
      internetWideRules: inventory.groups.reduce(
        (sum, group) => sum + group.publicRules,
        0,
      ),
      reachableCritical: findings.filter(
        (finding) =>
          finding.severity === "critical" &&
          ["Internet path exists", "Confirmed public service"].includes(finding.verdict),
      ).length,
      evidenceIncomplete: findings.filter(
        (finding) => finding.evidence.state === "incomplete",
      ).length,
      overdue: workflow.results.filter(
        (item) => item.status === "follow-up" && item.dueAt && item.dueAt < today,
      ).length,
      acceptedRisk: workflow.results.filter((item) => item.status === "accepted-risk")
        .length,
      ownedGroups: inventory.groups.filter((group) => group.owner !== "Unassigned").length,
      riskPoints: findings.reduce((sum, finding) => sum + finding.riskScore, 0),
    };
    const periodStart = inventory.source.generatedAt.slice(0, 10);
    await env.DB.prepare(
      `INSERT INTO program_metric_snapshots
        (id, workspace_id, snapshot_id, period_start, metrics,
         evidence_coverage, created_at)
       VALUES (?, 'default', ?, ?, ?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(id) DO UPDATE SET
         metrics = excluded.metrics,
         evidence_coverage = excluded.evidence_coverage`,
    ).bind(
      `default:${inventory.source.snapshotId}`,
      inventory.source.snapshotId,
      periodStart,
      JSON.stringify(metrics),
      inventory.source.coveragePercent,
    ).run();
    const history = await env.DB.prepare(
      `SELECT period_start AS periodStart, metrics, evidence_coverage AS evidenceCoverage,
              created_at AS createdAt
       FROM program_metric_snapshots
       WHERE workspace_id = 'default'
       ORDER BY period_start DESC, created_at DESC
       LIMIT 24`,
    ).all<MetricRow>();
    return apiJson({
      current: metrics,
      source: inventory.source,
      history: history.results.map((row) => ({
        ...row,
        metrics: safeJson(row.metrics, {}),
      })),
    });
  } catch {
    return apiJson({ error: "Program metrics are temporarily unavailable." }, 503);
  }
}
