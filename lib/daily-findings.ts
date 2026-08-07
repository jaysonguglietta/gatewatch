import {
  securityGroups,
  type ResourceAttachment,
  type RiskFactor,
  type SecurityGroup,
  type Severity,
} from "./security-data";
import {
  canonicalFindingFingerprint,
  canonicalSecurityGroupKey,
  evidenceForGroup,
  evidenceSnapshotJson,
  type EvidenceDescriptor,
} from "./evidence-model";
import { securityGroupArn } from "./organization-operations";

export type FindingWorkflowStatus =
  | "new"
  | "follow-up"
  | "acknowledged"
  | "accepted-risk"
  | "reopened"
  | "resolved";

export type FindingCatalogItem = {
  fingerprint: string;
  legacyFingerprint: string;
  canonicalResourceKey: string;
  securityGroupArn: string;
  findingKey: string;
  title: string;
  securityGroupId: string;
  securityGroupName: string;
  accountId: string;
  accountName: string;
  organization: string;
  organizationalUnit: string;
  region: string;
  environment: string;
  application: string;
  owner: string;
  service: string;
  severity: Severity;
  riskScore: number;
  verdict: string;
  ageDays: number;
  firstSeenAt: string;
  lastObserved: string;
  ruleSummary: string;
  pathSummary: string;
  trafficSummary: string;
  changeSummary: string;
  attachments: ResourceAttachment[];
  recommendation: string;
  vpcId: string;
  approvedIntent: string;
  intentTicket: string;
  policyName: string;
  policyControl: string;
  riskFactors: RiskFactor[];
  projectedRisk: number;
  changeEventId: string;
  changeActor: string;
  changeChannel: string;
  changeTime: string;
  changeBefore: string;
  changeAfter: string;
  changeApproved: boolean;
  evidenceSnapshot: string;
  evidence: EvidenceDescriptor;
};

export type FindingWorkflowState = {
  status: FindingWorkflowStatus;
  assignee: string;
  note: string;
  ticketRef: string;
  dueAt: string;
  expiresAt: string;
  compensatingControls: string[];
  reviewer: string;
  updatedAt: string;
  reasonCode: string;
  nextReviewAt: string;
  approver: string;
  resolutionEvidence: string;
  jiraIssueKey?: string;
  jiraIssueUrl?: string;
  jiraRemoteStatus?: string;
  jiraRemoteResolution?: string;
  jiraLastSyncedAt?: string;
};

export type DailyFinding = FindingCatalogItem & FindingWorkflowState;

const accountHierarchy: Record<string, { organization: string; ou: string }> = {
  "428196730552": {
    organization: "Northstar Financial",
    ou: "Finance & Payments / Production",
  },
  "718345229104": {
    organization: "Northstar Financial",
    ou: "Platform / Shared Services",
  },
  "583047112889": {
    organization: "Northstar Financial",
    ou: "Commerce / Production",
  },
  "912883407601": {
    organization: "Northstar Financial",
    ou: "Data & Analytics / Non-production",
  },
  "100293744720": {
    organization: "Northstar Financial",
    ou: "Engineering / Sandbox",
  },
};

function slug(value: string) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 72);
}

export function findingFingerprint(
  securityGroupId: string,
  finding: string,
) {
  return `gw-v1:${securityGroupId}:${slug(finding)}`;
}

function verdictFor(group: SecurityGroup) {
  const reachable = group.paths.some((path) => path.status === "reachable");
  const blocked =
    group.paths.length > 0 && group.paths.every((path) => path.status === "blocked");
  if (group.publicRules > 0 && reachable) return "Internet path exists";
  if (group.publicRules > 0 && blocked) return "Broad but unreachable";
  if (group.publicRules > 0) return "Evidence incomplete";
  if (reachable) return "Internal path confirmed";
  return "Evidence incomplete";
}

function primaryRule(group: SecurityGroup, findingIndex: number) {
  const findingRules = group.rules.filter((rule) => rule.finding);
  return findingRules[findingIndex % Math.max(findingRules.length, 1)] ?? group.rules[0];
}

function policyFor(group: SecurityGroup, rule: SecurityGroup["rules"][number] | undefined) {
  if (rule?.source === "0.0.0.0/0" || rule?.source === "::/0") {
    return {
      name: "Restrict unrestricted network access",
      control: "GW-SG-001 · CIS AWS 5.2",
    };
  }
  if (group.intent.status === "broader-than-intent") {
    return {
      name: "Deployed access must match approved intent",
      control: "GW-SG-004 · NIST AC-4",
    };
  }
  return {
    name: "Security groups must follow least privilege",
    control: "GW-SG-007 · NIST AC-6",
  };
}

function catalogItem(
  group: SecurityGroup,
  groupIndex: number,
  title: string,
  findingIndex: number,
  options: { live: boolean; snapshotId: string },
): FindingCatalogItem {
  const hierarchy = accountHierarchy[group.accountId] ??
    (options.live
      ? {
          organization: group.accountName || group.accountId,
          ou: "Standalone or organization metadata unavailable",
        }
      : {
          organization: "Northstar Financial",
          ou: "Unclassified accounts",
        });
  const rule = primaryRule(group, findingIndex);
  const demonstrationAge = [0, 1, 3, 7, 14, 31, 63, 92][
    (groupIndex * 2 + findingIndex) % 8
  ];
  const ageDays = options.live ? 0 : demonstrationAge;
  const rawObservedAt = group.rules[0]?.lastObserved ?? new Date().toISOString();
  const firstSeen = options.live
    ? new Date(Number.isNaN(Date.parse(rawObservedAt)) ? new Date().toISOString() : rawObservedAt)
    : new Date(Date.UTC(2026, 6, 30 - Math.min(ageDays, 29)));
  if (!options.live && ageDays > 29) firstSeen.setUTCMonth(firstSeen.getUTCMonth() - 1);
  const reachablePaths = group.paths.filter((path) => path.status === "reachable");
  const observedAt = Number.isNaN(Date.parse(rawObservedAt))
    ? new Date().toISOString()
    : rawObservedAt;
  const evidence = evidenceForGroup(group, options.snapshotId, observedAt);
  const riskScore = Math.max(22, group.riskScore - findingIndex * 7);
  const policy = policyFor(group, rule);

  return {
    fingerprint: canonicalFindingFingerprint(group, title),
    legacyFingerprint: findingFingerprint(group.id, title),
    canonicalResourceKey: canonicalSecurityGroupKey(group),
    securityGroupArn: securityGroupArn(group),
    findingKey: `${group.id}/${slug(title)}`,
    title,
    securityGroupId: group.id,
    securityGroupName: group.name,
    accountId: group.accountId,
    accountName: group.accountName,
    organization: hierarchy.organization,
    organizationalUnit: hierarchy.ou,
    region: group.region,
    environment: group.environment,
    application: group.intent.application,
    owner: group.owner,
    service: group.service,
    severity: findingIndex === 0 ? group.severity : group.riskScore >= 70 ? "high" : "medium",
    riskScore,
    verdict: verdictFor(group),
    ageDays,
    firstSeenAt: firstSeen.toISOString(),
    lastObserved: group.traffic.lastObserved,
    ruleSummary: rule
      ? `${rule.direction} ${rule.protocol}/${rule.ports} from ${rule.source}`
      : `${group.inboundCount} ingress and ${group.outboundCount} egress rules`,
    pathSummary: reachablePaths.length
      ? `${reachablePaths.length} confirmed path${reachablePaths.length === 1 ? "" : "s"}; ${reachablePaths[0].source} → ${reachablePaths[0].destination}`
      : "No confirmed path; route evidence is incomplete or blocked",
    trafficSummary: `${group.traffic.accepted30d.toLocaleString()} accepted flows over 30 days · ${group.traffic.coverage}% coverage`,
    changeSummary: `${group.change.eventName} by ${group.change.actor} through ${group.change.channel} · ${group.change.time}`,
    attachments: group.attachments,
    recommendation: group.recommendation,
    vpcId: group.vpc,
    approvedIntent: group.intent.approvedAccess,
    intentTicket: group.intent.ticket,
    policyName: policy.name,
    policyControl: policy.control,
    riskFactors: group.riskFactors,
    projectedRisk: Math.min(riskScore, group.projectedRisk),
    changeEventId: group.change.eventId,
    changeActor: group.change.actor,
    changeChannel: group.change.channel,
    changeTime: group.change.time,
    changeBefore: group.change.before,
    changeAfter: group.change.after,
    changeApproved: group.change.approved,
    evidenceSnapshot: evidenceSnapshotJson(group, evidence, riskScore),
    evidence,
  };
}

export function findingCatalogForGroups(
  groups: SecurityGroup[],
  options: { live?: boolean; snapshotId?: string } = {},
) {
  return groups.flatMap((group, groupIndex) =>
    group.findings.map((finding, findingIndex) =>
      catalogItem(group, groupIndex, finding, findingIndex, {
        live: Boolean(options.live),
        snapshotId: options.snapshotId ?? group.change.eventId,
      }),
    ),
  );
}

export const findingCatalog: FindingCatalogItem[] =
  findingCatalogForGroups(securityGroups, { live: false, snapshotId: "demonstration" });

export function groupForFinding(finding: Pick<FindingCatalogItem, "securityGroupId">) {
  return securityGroups.find((group) => group.id === finding.securityGroupId);
}

export const organizationCoverage = {
  accounts: 324,
  organizationalUnits: 18,
  regions: 21,
  staleAccounts: 7,
};
