import type { ConsolidatedSecurityGroupFinding } from "./aws-evidence-batch.ts";

export type FindingSort =
  | "risk-desc"
  | "evidence-desc"
  | "recent-desc"
  | "account-asc"
  | "arn-asc";

export type FindingGroup =
  | "none"
  | "account"
  | "account-region"
  | "region"
  | "severity"
  | "coverage";

export type FindingFilters = {
  query: string;
  accountId: string;
  region: string;
  severity: string;
  source: string;
  evidenceClass: string;
  sort: FindingSort;
};

export type ConsolidatedFindingGroup = {
  key: string;
  label: string;
  findings: ConsolidatedSecurityGroupFinding[];
  evidenceCount: number;
  highRiskCount: number;
  averageRisk: number;
};

type SearchToken = { field: string; value: string };

function queryTokens(query: string) {
  const tokens: SearchToken[] = [];
  const pattern = /(?:([a-z-]+):)?(?:"([^"]+)"|(\S+))/gi;
  for (const match of query.matchAll(pattern)) {
    tokens.push({ field: (match[1] ?? "any").toLowerCase(), value: (match[2] ?? match[3] ?? "").toLowerCase() });
  }
  return tokens.filter((token) => token.value);
}

function riskMatches(score: number, value: string) {
  const comparison = value.match(/^(>=|<=|>|<)(\d{1,3})$/);
  if (comparison) {
    const expected = Number(comparison[2]);
    if (comparison[1] === ">=") return score >= expected;
    if (comparison[1] === "<=") return score <= expected;
    if (comparison[1] === ">") return score > expected;
    return score < expected;
  }
  const range = value.match(/^(\d{1,3})-(\d{1,3})$/);
  if (range) return score >= Number(range[1]) && score <= Number(range[2]);
  return score === Number(value);
}

export function findingMatchesQuery(finding: ConsolidatedSecurityGroupFinding, query: string) {
  const fields: Record<string, string> = {
    arn: finding.securityGroupArn,
    sg: finding.securityGroupId,
    id: finding.securityGroupId,
    name: finding.name,
    account: finding.accountId,
    acct: finding.accountId,
    region: finding.region,
    severity: finding.severity,
    source: finding.sources.join(" "),
    class: finding.evidenceClasses.join(" "),
    summary: finding.summary,
  };
  const any = [
    ...Object.values(fields),
    finding.evidence.map((item) => `${item.record.event} ${item.record.resource} ${item.record.summary}`).join(" "),
  ].join(" ").toLowerCase();
  return queryTokens(query).every((token) => {
    if (token.field === "risk") return riskMatches(finding.riskScore, token.value);
    if (token.field === "evidence") return riskMatches(finding.evidence.length, token.value);
    if (token.field === "any") return any.includes(token.value);
    const fieldValue = fields[token.field];
    return fieldValue === undefined
      ? any.includes(`${token.field}:${token.value}`)
      : fieldValue.toLowerCase().includes(token.value);
  });
}

export function filterAndSortFindings(
  findings: ConsolidatedSecurityGroupFinding[],
  filters: FindingFilters,
) {
  const filtered = findings.filter((finding) =>
    (!filters.accountId || finding.accountId === filters.accountId)
    && (!filters.region || finding.region === filters.region)
    && (!filters.severity || finding.severity === filters.severity)
    && (!filters.source || finding.sources.includes(filters.source))
    && (!filters.evidenceClass || finding.evidenceClasses.includes(filters.evidenceClass as never))
    && findingMatchesQuery(finding, filters.query),
  );
  return filtered.sort((left, right) => {
    if (filters.sort === "evidence-desc") return right.evidence.length - left.evidence.length || right.riskScore - left.riskScore;
    if (filters.sort === "recent-desc") return right.lastObservedAt.localeCompare(left.lastObservedAt) || right.riskScore - left.riskScore;
    if (filters.sort === "account-asc") return left.accountId.localeCompare(right.accountId) || left.region.localeCompare(right.region) || left.securityGroupId.localeCompare(right.securityGroupId);
    if (filters.sort === "arn-asc") return (left.securityGroupArn || left.key).localeCompare(right.securityGroupArn || right.key);
    return right.riskScore - left.riskScore || right.evidence.length - left.evidence.length;
  });
}

function coverageLabel(finding: ConsolidatedSecurityGroupFinding) {
  if (finding.sources.length >= 6) return "6+ AWS source types";
  if (finding.sources.length >= 3) return "3–5 AWS source types";
  return "1–2 AWS source types";
}

export function groupConsolidatedFindings(
  findings: ConsolidatedSecurityGroupFinding[],
  groupBy: FindingGroup,
) {
  if (groupBy === "none") return [{
    key: "all",
    label: "All findings",
    findings,
    evidenceCount: findings.reduce((sum, finding) => sum + finding.evidence.length, 0),
    highRiskCount: findings.filter((finding) => finding.severity === "critical" || finding.severity === "high").length,
    averageRisk: findings.length ? Math.round(findings.reduce((sum, finding) => sum + finding.riskScore, 0) / findings.length) : 0,
  } satisfies ConsolidatedFindingGroup];
  const groups = new Map<string, ConsolidatedSecurityGroupFinding[]>();
  for (const finding of findings) {
    const label = groupBy === "account"
      ? finding.accountId || "Unknown account"
      : groupBy === "account-region"
        ? `${finding.accountId || "Unknown account"} / ${finding.region || "Unknown Region"}`
        : groupBy === "region"
          ? finding.region || "Unknown Region"
          : groupBy === "severity"
            ? `${finding.severity[0].toUpperCase()}${finding.severity.slice(1)} severity`
            : coverageLabel(finding);
    groups.set(label, [...(groups.get(label) ?? []), finding]);
  }
  return [...groups.entries()].map(([label, groupFindings]) => ({
    key: label,
    label,
    findings: groupFindings,
    evidenceCount: groupFindings.reduce((sum, finding) => sum + finding.evidence.length, 0),
    highRiskCount: groupFindings.filter((finding) => finding.severity === "critical" || finding.severity === "high").length,
    averageRisk: Math.round(groupFindings.reduce((sum, finding) => sum + finding.riskScore, 0) / groupFindings.length),
  })).sort((left, right) => right.highRiskCount - left.highRiskCount || right.averageRisk - left.averageRisk || left.label.localeCompare(right.label));
}
