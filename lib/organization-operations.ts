import type { SecurityGroup } from "./security-data";

export const monitorSchedules = ["hourly", "daily", "weekly"] as const;
export const monitorTriggers = ["enters", "leaves", "severity-change", "coverage-gap", "recurrence"] as const;
export const exportFormats = ["csv", "json", "evidence-package", "parquet"] as const;
export const accountEnvironments = ["Production", "Staging", "Development", "Shared"] as const;

export type RiskWeights = {
  publicIngress: number;
  administrativePorts: number;
  widePorts: number;
  unrestrictedEgress: number;
  attachedWorkload: number;
  staleEvidence: number;
};

export const defaultRiskWeights: RiskWeights = {
  publicIngress: 24,
  administrativePorts: 24,
  widePorts: 12,
  unrestrictedEgress: 10,
  attachedWorkload: 8,
  staleEvidence: 12,
};

export function isSecurityGroupArn(value: string) {
  return /^arn:(aws|aws-us-gov|aws-cn):ec2:[a-z0-9-]+:\d{12}:security-group\/sg-[a-f0-9]+$/i.test(value.trim());
}

export function securityGroupArn(group: Pick<SecurityGroup, "accountId" | "region" | "id">) {
  const partition = group.region.startsWith("us-gov-") ? "aws-us-gov" : group.region.startsWith("cn-") ? "aws-cn" : "aws";
  return `arn:${partition}:ec2:${group.region}:${group.accountId}:security-group/${group.id}`;
}

export function accountContextFromGroups(groups: SecurityGroup[]) {
  const accounts = new Map<string, {
    accountId: string;
    accountName: string;
    environment: string;
    owner: string;
    groupCount: number;
    regionCount: number;
    findingCount: number;
    criticalCount: number;
    lastSeenAt: string;
  }>();
  for (const group of groups) {
    const current = accounts.get(group.accountId) ?? {
      accountId: group.accountId,
      accountName: group.accountName,
      environment: group.environment,
      owner: group.owner || "Unassigned",
      groupCount: 0,
      regionCount: 0,
      findingCount: 0,
      criticalCount: 0,
      lastSeenAt: new Date().toISOString(),
    };
    current.groupCount += 1;
    current.findingCount += group.findings.length;
    current.criticalCount += group.severity === "critical" ? group.findings.length : 0;
    accounts.set(group.accountId, current);
  }
  for (const account of accounts.values()) {
    account.regionCount = new Set(groups.filter((group) => group.accountId === account.accountId).map((group) => group.region)).size;
  }
  return [...accounts.values()].sort((a, b) => a.accountName.localeCompare(b.accountName));
}

export function semanticEvidenceKey(input: {
  providerId?: string;
  accountId: string;
  region: string;
  securityGroupId: string;
  category: string;
  observedAt: string;
}) {
  if (input.providerId?.trim()) return `provider:${input.providerId.trim().toLowerCase()}`;
  const minute = input.observedAt.slice(0, 16);
  return [input.accountId, input.region, input.securityGroupId, input.category.trim().toLowerCase(), minute].join(":");
}

export function scoreRisk(signals: Partial<Record<keyof RiskWeights, boolean>>, weights: RiskWeights = defaultRiskWeights) {
  return Math.min(100, (Object.keys(weights) as Array<keyof RiskWeights>).reduce(
    (score, key) => score + (signals[key] ? weights[key] : 0),
    10,
  ));
}

export function nextMonitorRun(schedule: string, from = new Date()) {
  const next = new Date(from);
  if (schedule === "hourly") next.setUTCHours(next.getUTCHours() + 1);
  else if (schedule === "weekly") next.setUTCDate(next.getUTCDate() + 7);
  else next.setUTCDate(next.getUTCDate() + 1);
  return next.toISOString();
}

export function csvCell(value: unknown) {
  const text = String(value ?? "");
  return /[",\n\r]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}
