import { env } from "cloudflare:workers";
import { findingCatalogForGroups, type FindingWorkflowStatus } from "../../../lib/daily-findings";
import { loadAwsInventory } from "../../../lib/aws-inventory";
import { apiJson, ensureAdminSchema, requestUser } from "../../../lib/server-admin";

type WorkflowRow = {
  fingerprint: string;
  status: FindingWorkflowStatus;
  assignee: string;
  dueAt: string;
  expiresAt: string;
};

function counts(values: string[]) {
  return Object.entries(
    values.reduce<Record<string, number>>((result, value) => {
      result[value] = (result[value] ?? 0) + 1;
      return result;
    }, {}),
  )
    .map(([label, count]) => ({ label, count }))
    .sort((left, right) => right.count - left.count || left.label.localeCompare(right.label));
}

function csvCell(value: unknown) {
  const raw = String(value ?? "");
  // Quoting alone does not stop spreadsheet applications from evaluating
  // attacker-controlled names and tags as formulas when the CSV is opened.
  const safe = /^[\s]*[=+\-@\t\r]/.test(raw) ? `'${raw}` : raw;
  return `"${safe.replaceAll('"', '""')}"`;
}

export async function GET(request: Request) {
  const user = requestUser(request);
  if (!user) return apiJson({ error: "Authentication is required." }, 401);
  try {
    await ensureAdminSchema();
    const inventory = await loadAwsInventory();
    const catalog = findingCatalogForGroups(inventory.groups, {
      live: true,
      snapshotId: inventory.source.snapshotId,
    });
    const [workflowResult, jiraResult] = await Promise.all([
      env.DB.prepare(
        `SELECT fingerprint, status, assignee,
                due_at AS dueAt, expires_at AS expiresAt
         FROM finding_workflows WHERE workspace_id = 'default'`,
      ).all<WorkflowRow>(),
      env.DB.prepare(
        `SELECT fingerprint, issue_key AS issueKey, issue_url AS issueUrl
         FROM finding_jira_links WHERE workspace_id = 'default'`,
      ).all<{ fingerprint: string; issueKey: string; issueUrl: string }>(),
    ]);
    const workflow = new Map(workflowResult.results.map((item) => [item.fingerprint, item]));
    const jira = new Map(jiraResult.results.map((item) => [item.fingerprint, item]));
    const findings = catalog.map((finding) => ({
      ...finding,
      status: workflow.get(finding.fingerprint)?.status ?? "new",
      assignee: workflow.get(finding.fingerprint)?.assignee ?? finding.owner,
      dueAt: workflow.get(finding.fingerprint)?.dueAt ?? "",
      expiresAt: workflow.get(finding.fingerprint)?.expiresAt ?? "",
      jiraIssueKey: jira.get(finding.fingerprint)?.issueKey ?? "",
      jiraIssueUrl: jira.get(finding.fingerprint)?.issueUrl ?? "",
    }));

    if (new URL(request.url).searchParams.get("format") === "csv") {
      const rows = [
        ["Finding", "Security group", "Security group ID", "Account", "Account ID", "Region", "Severity", "Risk", "Status", "Assignee", "Rule", "Exposure", "Attachments", "Resource tags", "Jira"],
        ...findings.map((finding) => [
          finding.title,
          finding.securityGroupName,
          finding.securityGroupId,
          finding.accountName,
          finding.accountId,
          finding.region,
          finding.severity,
          finding.riskScore,
          finding.status,
          finding.assignee,
          finding.ruleSummary,
          finding.pathSummary,
          finding.attachments.map((item) => `${item.type}:${item.name}:${item.id}`).join("; "),
          finding.attachments.flatMap((item) => Object.entries(item.tags ?? {}).map(([key, value]) => `${item.id}:${key}=${value}`)).join("; "),
          finding.jiraIssueKey,
        ]),
      ];
      return new Response(rows.map((row) => row.map(csvCell).join(",")).join("\n"), {
        headers: {
          "cache-control": "no-store, private",
          "content-disposition": `attachment; filename="gatewatch-detailed-report-${new Date().toISOString().slice(0, 10)}.csv"`,
          "content-type": "text/csv; charset=utf-8",
          "x-content-type-options": "nosniff",
        },
      });
    }

    const accountMap = new Map<string, { accountId: string; accountName: string; groups: Set<string>; findings: number; critical: number; publicIngress: number; publicEgress: number; attachments: number; maxRisk: number }>();
    for (const group of inventory.groups) {
      const current = accountMap.get(group.accountId) ?? { accountId: group.accountId, accountName: group.accountName, groups: new Set(), findings: 0, critical: 0, publicIngress: 0, publicEgress: 0, attachments: 0, maxRisk: 0 };
      current.groups.add(group.id);
      current.publicIngress += group.rules.filter((rule) => rule.direction === "Ingress" && rule.exposure === "Public").length;
      current.publicEgress += group.rules.filter((rule) => rule.direction === "Egress" && rule.exposure === "Public").length;
      current.attachments += group.attachments.length;
      accountMap.set(group.accountId, current);
    }
    for (const finding of findings) {
      const current = accountMap.get(finding.accountId)!;
      current.findings += 1;
      current.critical += finding.severity === "critical" ? 1 : 0;
      current.maxRisk = Math.max(current.maxRisk, finding.riskScore);
    }
    const byAccount = [...accountMap.values()].map((item) => ({ ...item, groups: item.groups.size })).sort((left, right) => right.maxRisk - left.maxRisk || right.findings - left.findings);
    const byRegion = [...new Set(inventory.groups.map((group) => group.region))].map((region) => {
      const groups = inventory.groups.filter((group) => group.region === region);
      const scopedFindings = findings.filter((finding) => finding.region === region);
      return {
        region,
        groups: groups.length,
        findings: scopedFindings.length,
        publicRules: groups.reduce((sum, group) => sum + group.publicRules, 0),
        maxRisk: Math.max(0, ...scopedFindings.map((finding) => finding.riskScore)),
      };
    }).sort((left, right) => right.maxRisk - left.maxRisk || right.findings - left.findings);
    const today = new Date().toISOString().slice(0, 10);
    return apiJson({
      generatedAt: new Date().toISOString(),
      snapshot: inventory.source,
      summary: {
        findings: findings.length,
        securityGroups: inventory.groups.length,
        accounts: inventory.source.accountCount,
        regions: inventory.source.regionCount,
        critical: findings.filter((item) => item.severity === "critical").length,
        high: findings.filter((item) => item.severity === "high").length,
        publicIngressRules: inventory.groups.reduce((sum, group) => sum + group.rules.filter((rule) => rule.direction === "Ingress" && rule.exposure === "Public").length, 0),
        publicEgressRules: inventory.groups.reduce((sum, group) => sum + group.rules.filter((rule) => rule.direction === "Egress" && rule.exposure === "Public").length, 0),
        attachedResources: inventory.groups.reduce((sum, group) => sum + group.attachments.length, 0),
        awaitingAction: findings.filter((item) => ["new", "reopened"].includes(item.status)).length,
        overdue: findings.filter((item) => item.status === "follow-up" && item.dueAt && item.dueAt < today).length,
        acceptedRisk: findings.filter((item) => item.status === "accepted-risk").length,
        jiraLinked: findings.filter((item) => item.jiraIssueKey).length,
      },
      severity: counts(findings.map((item) => item.severity)),
      workflow: counts(findings.map((item) => item.status)),
      byAccount,
      byRegion,
      resourceTypes: counts(inventory.groups.flatMap((group) => group.attachments.map((item) => item.type))),
      topFindings: findings.sort((left, right) => right.riskScore - left.riskScore).slice(0, 12).map((item) => ({
        fingerprint: item.fingerprint,
        title: item.title,
        securityGroupName: item.securityGroupName,
        accountName: item.accountName,
        region: item.region,
        severity: item.severity,
        riskScore: item.riskScore,
        status: item.status,
        jiraIssueKey: item.jiraIssueKey,
      })),
    });
  } catch (error) {
    console.error("Report generation failed", error instanceof Error ? error.name : "UnknownError");
    return apiJson({ error: "The detailed report is temporarily unavailable." }, 503);
  }
}
