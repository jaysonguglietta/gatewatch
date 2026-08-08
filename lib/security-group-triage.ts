import type { DailyFinding } from "./daily-findings";
import { internetExposureForVerdict } from "./finding-exposure.ts";

export type ExposureLane = "confirmed" | "unknown" | "internal";
export type AssetCriticality = "Critical" | "High" | "Medium" | "Low";
export type EvidenceState = "complete" | "partial" | "missing";

export type ExposureTruthStep = {
  key: "rule" | "entry" | "path" | "traffic" | "verdict";
  label: string;
  value: string;
  state: "danger" | "allowed" | "blocked" | "unknown" | "neutral";
};

export type EvidenceCheck = {
  key: string;
  label: string;
  state: EvidenceState;
  detail: string;
};

export type SecurityGroupExposureCluster = {
  key: string;
  lead: DailyFinding;
  findings: DailyFinding[];
  lane: ExposureLane;
  criticality: AssetCriticality;
  priorityScore: number;
  maxRisk: number;
  projectedRisk: number;
  ruleCount: number;
  attachmentCount: number;
  acceptedFlows: number;
  recurrence: number;
  reason: string;
};

export const guidedSecurityGroupHunts = [
  { id: "public-admin", title: "Public SSH or RDP", description: "Confirmed public paths to remote administration ports.", query: "internet:confirmed AND (port:22 OR port:3389)" },
  { id: "public-database", title: "Public database ports", description: "Confirmed exposure to common database and search ports.", query: "internet:confirmed AND (port:1433 OR port:3306 OR port:5432 OR port:9200 OR port:9300)" },
  { id: "public-development", title: "Public development ports", description: "Internet paths to development servers, dashboards, and alternate web ports.", query: "internet:confirmed AND (port:3000 OR port:5000 OR port:5601 OR port:8080 OR port:8888)" },
  { id: "all-traffic", title: "All protocols or ports", description: "Broad ingress rules that allow an entire protocol or port range.", query: "ingress:All" },
  { id: "ipv6-public", title: "Unrestricted IPv6", description: "Ingress sourced from the full IPv6 internet.", query: "source:\"::/0\"" },
  { id: "accepted-public", title: "Public path with traffic", description: "Confirmed exposure with accepted traffic observations.", query: "internet:confirmed AND flows:>0" },
  { id: "unapproved-change", title: "Unapproved changes", description: "Broad or high-risk access without recorded approval.", query: "approved:false" },
  { id: "internal-lateral", title: "Internal lateral reach", description: "Broad private access to important production resources.", query: "internet:none AND env:Production AND risk:>=70" },
  { id: "default-groups", title: "Default groups in use", description: "Default security groups with attached resources or findings.", query: "name:default" },
  { id: "stale-unused", title: "Stale or unattached", description: "Stale references and groups with no observed attachments.", query: "evidence:stale OR evidence:unattached" },
  { id: "expired-exceptions", title: "Exceptions to review", description: "Accepted exposure that requires expiration or recertification review.", query: "status:accepted-risk" },
  { id: "reopened", title: "Reopened exposure", description: "Previously resolved exposure that returned.", query: "status:reopened" },
  { id: "missing-evidence", title: "Evidence incomplete", description: "Exposure cannot be confirmed because decisive AWS evidence is missing.", query: "internet:unknown" },
] as const;

export type GuidedHuntId = (typeof guidedSecurityGroupHunts)[number]["id"];

const criticalityRank: Record<AssetCriticality, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
};

function highestCriticality(finding: DailyFinding): AssetCriticality {
  return finding.attachments.reduce<AssetCriticality>((highest, attachment) =>
    criticalityRank[attachment.criticality] > criticalityRank[highest]
      ? attachment.criticality
      : highest, "Low");
}

export function exposureLaneForFinding(finding: DailyFinding): ExposureLane {
  const exposure = internetExposureForVerdict(finding.verdict);
  if (exposure === "internet") return "confirmed";
  if (exposure === "unknown") return "unknown";
  return "internal";
}

function recentChange(changeTime: string) {
  if (/min|hour|today|yesterday/i.test(changeTime)) return true;
  const parsed = Date.parse(changeTime);
  return Number.isFinite(parsed) && Date.now() - parsed <= 7 * 24 * 60 * 60 * 1000;
}

function priorityFor(finding: DailyFinding) {
  const lanePoints = { confirmed: 38, unknown: 24, internal: 10 }[exposureLaneForFinding(finding)];
  const assetPoints = { Critical: 24, High: 17, Medium: 10, Low: 4 }[highestCriticality(finding)];
  const flowPoints = Math.min(10, Math.round(Math.log10(Math.max(1, finding.ruleFlows30d + 1)) * 3));
  const governancePoints = (finding.changeApproved ? 0 : 6) + (recentChange(finding.changeTime) ? 4 : 0) + (finding.status === "reopened" ? 5 : 0);
  return Math.min(100, Math.round(finding.riskScore * 0.35 + lanePoints + assetPoints + flowPoints + governancePoints));
}

function clusterReason(cluster: Omit<SecurityGroupExposureCluster, "reason">) {
  const finding = cluster.lead;
  const exposure = cluster.lane === "confirmed"
    ? "a public path is confirmed"
    : cluster.lane === "unknown"
      ? "public exposure cannot be determined from the supplied evidence"
      : "no public path is confirmed, but broad internal access remains";
  const traffic = finding.ruleFlows30d > 0
    ? `${finding.ruleFlows30d.toLocaleString()} matching flows were observed`
    : "no matching traffic was observed";
  const approval = finding.changeApproved ? "the latest change is approved" : "approval for the latest change was not found";
  return `${finding.ruleSummary}; ${exposure}; ${traffic}; ${approval}.`;
}

export function groupSecurityGroupFindings(findings: DailyFinding[]) {
  const grouped = new Map<string, DailyFinding[]>();
  for (const finding of findings) {
    const current = grouped.get(finding.canonicalResourceKey) ?? [];
    current.push(finding);
    grouped.set(finding.canonicalResourceKey, current);
  }
  return [...grouped.entries()].map(([key, items]) => {
    const ordered = [...items].sort((left, right) => priorityFor(right) - priorityFor(left) || right.riskScore - left.riskScore);
    const lead = ordered[0];
    const base = {
      key,
      lead,
      findings: ordered,
      lane: exposureLaneForFinding(lead),
      criticality: ordered.reduce<AssetCriticality>((highest, item) => {
        const next = highestCriticality(item);
        return criticalityRank[next] > criticalityRank[highest] ? next : highest;
      }, "Low"),
      priorityScore: Math.max(...ordered.map(priorityFor)),
      maxRisk: Math.max(...ordered.map((item) => item.riskScore)),
      projectedRisk: Math.min(...ordered.map((item) => item.projectedRisk)),
      ruleCount: new Set(ordered.map((item) => item.ruleId || item.ruleSummary)).size,
      attachmentCount: new Set(ordered.flatMap((item) => item.attachments.map((attachment) => `${attachment.type}:${attachment.id}`))).size,
      acceptedFlows: Math.max(...ordered.map((item) => item.trafficAccepted30d)),
      recurrence: Math.max(...ordered.map((item) => item.observationCount)),
    } satisfies Omit<SecurityGroupExposureCluster, "reason">;
    return { ...base, reason: clusterReason(base) };
  }).sort((left, right) => right.priorityScore - left.priorityScore || left.key.localeCompare(right.key));
}

function publicEntryPoint(finding: DailyFinding) {
  const publicAttachment = finding.attachments.find((attachment) => attachment.publicAddress);
  if (publicAttachment?.type === "ALB") return `Public ALB · ${publicAttachment.name}`;
  if (publicAttachment) return `Public ${publicAttachment.type} · ${publicAttachment.publicAddress}`;
  const internetIndex = finding.pathSteps.findIndex((step) => /internet/i.test(step));
  if (internetIndex >= 0 && finding.pathSteps[internetIndex + 1]) return finding.pathSteps[internetIndex + 1];
  if (exposureLaneForFinding(finding) === "internal") return "Private attachment";
  return "Entry point not supplied";
}

export function exposureTruthForFinding(finding: DailyFinding): ExposureTruthStep[] {
  const lane = exposureLaneForFinding(finding);
  const path = finding.pathSteps.length ? finding.pathSteps.join(" → ") : finding.pathReason;
  return [
    { key: "rule", label: "Effective rule", value: finding.ruleSummary, state: finding.publicRuleCount > 0 ? "danger" : "neutral" },
    { key: "entry", label: "Entry point", value: publicEntryPoint(finding), state: lane === "confirmed" ? "danger" : lane === "unknown" ? "unknown" : "blocked" },
    { key: "path", label: "Network path", value: path, state: finding.pathStatus === "reachable" ? "allowed" : finding.pathStatus === "blocked" ? "blocked" : "unknown" },
    { key: "traffic", label: "Observed traffic", value: finding.ruleFlows30d > 0 ? `${finding.ruleFlows30d.toLocaleString()} matching flows / 30d` : `No matching flows observed · ${finding.trafficCoverage}% coverage`, state: finding.ruleFlows30d > 0 ? "danger" : "neutral" },
    { key: "verdict", label: "Exposure verdict", value: lane === "confirmed" ? "Confirmed internet" : lane === "internal" ? "No internet path confirmed" : "Evidence incomplete", state: lane === "confirmed" ? "danger" : lane === "internal" ? "blocked" : "unknown" },
  ];
}

export function evidenceChecksForFinding(finding: DailyFinding): EvidenceCheck[] {
  const sourceText = finding.evidence.sources.join(" ").toLowerCase();
  const limitationText = finding.evidence.limitations.join(" ").toLowerCase();
  return [
    { key: "config", label: "Deployed rule", state: finding.ruleSummary ? "complete" : "missing", detail: finding.ruleId || finding.ruleSummary || "AWS Config security-group snapshot required" },
    { key: "attachment", label: "Resource attachment", state: finding.attachments.length ? "complete" : "missing", detail: finding.attachments.length ? `${finding.attachments.length} attached resource${finding.attachments.length === 1 ? "" : "s"}` : "ENI or managed-service attachment evidence required" },
    { key: "path", label: "Route and controls", state: finding.pathStatus === "unknown" ? "missing" : finding.pathStatus === "potential" ? "partial" : "complete", detail: finding.pathReason },
    { key: "reachability", label: "Reachability analysis", state: /reachability|network access/.test(sourceText) ? "complete" : /reachability|route|nacl/.test(limitationText) ? "missing" : "partial", detail: /reachability|network access/.test(sourceText) ? "Analyzer result correlated" : "Upload Network Access Analyzer or Reachability Analyzer results" },
    { key: "flow", label: "VPC Flow Logs", state: finding.trafficCoverage >= 90 ? "complete" : finding.trafficCoverage > 0 ? "partial" : "missing", detail: `${finding.trafficCoverage}% coverage · ${finding.trafficAccepted30d.toLocaleString()} accepted flows observed` },
    { key: "change", label: "Change provenance", state: finding.changeEventId ? "complete" : "missing", detail: finding.changeEventId ? `${finding.changeActor} · ${finding.changeChannel}` : "CloudTrail change event required" },
    { key: "intent", label: "Approved intent", state: finding.intentTicket ? "complete" : finding.approvedIntent ? "partial" : "missing", detail: finding.intentTicket ? `${finding.intentTicket} · ${finding.intentStatus.replaceAll("-", " ")}` : "Owner intent or approval ticket required" },
  ];
}

function matchesHunt(finding: DailyFinding, huntId: GuidedHuntId) {
  const lane = exposureLaneForFinding(finding);
  const rule = finding.ruleSummary.toLowerCase();
  const port = (value: number) => new RegExp(`(?:^|[^0-9])${value}(?:[^0-9]|$)`).test(rule);
  if (huntId === "public-admin") return lane === "confirmed" && (port(22) || port(3389));
  if (huntId === "public-database") return lane === "confirmed" && [1433, 3306, 5432, 9200, 9300].some(port);
  if (huntId === "public-development") return lane === "confirmed" && [3000, 5000, 5601, 8080, 8888].some(port);
  if (huntId === "all-traffic") return /^ingress\s+all\//i.test(finding.ruleSummary) || /\/all\s+from/i.test(finding.ruleSummary);
  if (huntId === "ipv6-public") return rule.includes("::/0");
  if (huntId === "accepted-public") return lane === "confirmed" && finding.ruleFlows30d > 0;
  if (huntId === "unapproved-change") return !finding.changeApproved;
  if (huntId === "internal-lateral") return lane === "internal" && finding.environment === "Production" && finding.riskScore >= 70;
  if (huntId === "default-groups") return /(^|[-_])default($|[-_])/i.test(finding.securityGroupName) || finding.securityGroupName.toLowerCase() === "default";
  if (huntId === "stale-unused") return !finding.attachments.length || /stale|unattached|unused/i.test(`${finding.title} ${finding.evidence.limitations.join(" ")}`);
  if (huntId === "expired-exceptions") return finding.status === "accepted-risk";
  if (huntId === "reopened") return finding.status === "reopened";
  return lane === "unknown";
}

export function buildExposureOverview(findings: DailyFinding[]) {
  const clusters = groupSecurityGroupFindings(findings);
  const matrix = { confirmed: { critical: 0, important: 0, standard: 0 }, unknown: { critical: 0, important: 0, standard: 0 }, internal: { critical: 0, important: 0, standard: 0 } };
  for (const cluster of clusters) {
    const column = cluster.criticality === "Critical" ? "critical" : cluster.criticality === "High" ? "important" : "standard";
    matrix[cluster.lane][column] += 1;
  }
  const completeEvidence = clusters.filter((cluster) => evidenceChecksForFinding(cluster.lead).every((check) => check.state === "complete")).length;
  return {
    groups: clusters.length,
    lanes: {
      confirmed: clusters.filter((cluster) => cluster.lane === "confirmed").length,
      unknown: clusters.filter((cluster) => cluster.lane === "unknown").length,
      internal: clusters.filter((cluster) => cluster.lane === "internal").length,
    },
    matrix,
    hunts: Object.fromEntries(guidedSecurityGroupHunts.map((hunt) => [hunt.id, new Set(findings.filter((finding) => matchesHunt(finding, hunt.id)).map((finding) => finding.canonicalResourceKey)).size])),
    outcomes: {
      criticalAssetsExposed: clusters.filter((cluster) => cluster.lane === "confirmed" && cluster.criticality === "Critical").length,
      reopened: clusters.filter((cluster) => cluster.findings.some((finding) => finding.status === "reopened")).length,
      expiringExceptions: clusters.filter((cluster) => cluster.findings.some((finding) => finding.status === "accepted-risk" && Boolean(finding.expiresAt))).length,
      evidenceCompletePercent: clusters.length ? Math.round(completeEvidence / clusters.length * 100) : 100,
      exposureHours: clusters.filter((cluster) => cluster.lane === "confirmed").reduce((sum, cluster) => sum + Math.max(1, cluster.lead.ageDays * 24), 0),
      potentialRiskReduction: clusters.reduce((sum, cluster) => sum + Math.max(0, cluster.maxRisk - cluster.projectedRisk), 0),
    },
  };
}

export function remediationPackageForFinding(finding: DailyFinding) {
  const parsed = finding.ruleSummary.match(/^(Ingress|Egress)\s+(TCP|UDP)\/(\d+)(?:[–-](\d+))?\s+from\s+(.+)$/i);
  const direction = parsed?.[1].toLowerCase() === "egress" ? "egress" : "ingress";
  const protocol = parsed?.[2].toLowerCase() ?? "tcp";
  const fromPort = parsed?.[3] ?? "";
  const toPort = parsed?.[4] ?? fromPort;
  const cidr = parsed?.[5] ?? "";
  const revokeCommand = parsed && /^(?:\d{1,3}\.){3}\d{1,3}\/\d+$|^::\/0$/.test(cidr)
    ? `aws ec2 revoke-security-group-${direction} --dry-run --group-id ${finding.securityGroupId} --region ${finding.region} --ip-permissions '${JSON.stringify([{ IpProtocol: protocol, FromPort: Number(fromPort), ToPort: Number(toPort), IpRanges: cidr.includes(":") ? [] : [{ CidrIp: cidr }], Ipv6Ranges: cidr.includes(":") ? [{ CidrIpv6: cidr }] : [] }])}'`
    : `aws ec2 describe-security-group-rules --region ${finding.region} --filters Name=group-id,Values=${finding.securityGroupId}`;
  return {
    title: `Narrow ${finding.securityGroupName} to approved intent`,
    current: finding.ruleSummary,
    proposed: finding.approvedIntent || finding.recommendation,
    impact: `${finding.attachments.length} attached resource${finding.attachments.length === 1 ? "" : "s"} · ${finding.ruleFlows30d.toLocaleString()} matching flows observed · owner ${finding.owner}`,
    recommendation: finding.recommendation,
    cli: revokeCommand,
    cloudFormation: `# Remove or narrow ${finding.ruleId || "the broad rule"}\n# SecurityGroupId: ${finding.securityGroupId}\n# Approved intent: ${finding.approvedIntent || "Owner validation required"}\n# Validate the replacement rule before deployment.`,
    terraform: `# Replace the rule that produces:\n# ${finding.ruleSummary}\n# security_group_id = \"${finding.securityGroupId}\"\n# approved_intent  = \"${(finding.approvedIntent || "Owner validation required").replaceAll('"', '\\"')}\"`,
    verification: [
      `Re-collect AWS Config for ${finding.securityGroupArn}.`,
      "Run Network Access Analyzer or Reachability Analyzer against the affected path.",
      "Confirm expected traffic remains available and the broad path is absent.",
    ],
  };
}

function isoDaysAgo(days: number) {
  const value = new Date();
  value.setUTCDate(value.getUTCDate() - days);
  return value.toISOString().slice(0, 10);
}

export function translateNaturalLanguageHunt(input: string) {
  const text = input.trim().toLowerCase();
  const clauses: string[] = [];
  const explanations: string[] = [];
  const add = (clause: string, explanation: string) => { if (!clauses.includes(clause)) clauses.push(clause); explanations.push(explanation); };
  if (/prod|production/.test(text)) add("env:Production", "Production environment");
  if (/public|internet[- ]?(facing|exposed|reachable)?/.test(text)) add("internet:confirmed", "Confirmed internet exposure");
  if (/private|internal[- ]only/.test(text)) add("internet:none", "No confirmed public path");
  if (/unknown|missing evidence|incomplete evidence/.test(text)) add("internet:unknown", "Incomplete reachability evidence");
  if (/ssh/.test(text)) add("port:22", "SSH");
  if (/rdp|remote desktop/.test(text)) add("port:3389", "RDP");
  if (/database|postgres|mysql|mssql/.test(text)) add("(port:1433 OR port:3306 OR port:5432)", "Common database ports");
  if (/admin(istration|istrative)? port/.test(text)) add("(port:22 OR port:3389)", "Administrative ports");
  if (/accepted traffic|active traffic|observed traffic|with traffic/.test(text)) add("flows:>0", "Observed matching traffic");
  if (/unapproved|without approval|no approval|no approved|outside approval/.test(text)) add("approved:false", "Approval not found");
  if (/reopened|returned/.test(text)) add("status:reopened", "Reopened finding");
  if (/exception/.test(text)) add("status:accepted-risk", "Accepted-risk workflow");
  const days = Number(text.match(/last\s+(\d{1,3})\s+days?/)?.[1] ?? (/last week|past week/.test(text) ? 7 : 0));
  if (days > 0 && days <= 365) add(`changed-after:${isoDaysAgo(days)}`, `Changed in the last ${days} days`);
  const account = text.match(/\baccount\s+(\d{12})\b/)?.[1];
  if (account) add(`account:${account}`, `AWS account ${account}`);
  return {
    query: clauses.join(" AND "),
    explanations,
    recognized: clauses.length > 0,
  };
}
