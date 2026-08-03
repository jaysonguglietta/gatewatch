import type { AwsInventory } from "./aws-inventory";
import { canonicalSecurityGroupKey } from "./evidence-model";
import type {
  ControlMapping,
  DriftEvent,
  ExposureRecord,
  HygieneIssue,
  IacChange,
  OwnerQueue,
  RuleRecommendation,
} from "./product-intelligence-data";
import type { SecurityGroup } from "./security-data";

export type ProgramTrendPoint = {
  month: string;
  internetWide: number;
  reachableCritical: number;
  overdue: number;
  riskRemoved: number;
};

export type LiveIntelligence = {
  mode: "live" | "demonstration";
  source: AwsInventory["source"] | null;
  exposureRecords: ExposureRecord[];
  ruleRecommendations: RuleRecommendation[];
  driftEvents: DriftEvent[];
  ownerQueues: OwnerQueue[];
  controlMappings: ControlMapping[];
  hygieneIssues: HygieneIssue[];
  iacChanges: IacChange[];
  programTrend: ProgramTrendPoint[];
};

function administrativeExposure(group: SecurityGroup) {
  return group.rules.some(
    (rule) =>
      rule.direction === "Ingress" &&
      rule.exposure === "Public" &&
      ["22", "3389", "5432", "3306", "1433", "6379", "27017", "All"].includes(
        rule.ports,
      ),
  );
}

function verdict(group: SecurityGroup): ExposureRecord["verdict"] {
  if (!group.publicRules) return "Internal only";
  if (group.paths.some((path) => path.status === "reachable")) {
    return group.traffic.accepted30d > 0
      ? "Confirmed public service"
      : "Internet path exists";
  }
  if (group.paths.length && group.paths.every((path) => path.status === "blocked")) {
    return "Broad but unreachable";
  }
  return "Evidence incomplete";
}

function exposureFor(group: SecurityGroup, source: AwsInventory["source"]): ExposureRecord {
  const exposedRules = group.rules.filter((rule) => rule.exposure === "Public");
  const path = group.paths.find((item) => item.status === "reachable") ?? group.paths[0];
  const publicAddress = group.attachments.find((item) => item.publicAddress)?.publicAddress;
  const toxicSignals = [
    administrativeExposure(group) ? "Internet-wide administration or data service" : "",
    group.attachments.some((item) => item.criticality === "Critical")
      ? "Critical attached workload"
      : "",
    group.owner === "Unassigned" ? "Missing accountable owner" : "",
    group.rules.some((rule) => rule.direction === "Egress" && rule.exposure === "Public")
      ? "Internet-wide egress"
      : "",
    group.publicRules > 2 ? "Multiple internet-wide rules" : "",
  ].filter(Boolean);
  const evidenceCompleteness = [
    group.paths.some((item) => item.status !== "potential"),
    group.traffic.coverage > 0,
    group.changedBy !== "Not available in EC2 inventory",
  ].filter(Boolean).length;
  return {
    id: `exposure:${canonicalSecurityGroupKey(group)}`,
    groupId: group.id,
    groupName: group.name,
    account: group.accountName,
    region: group.region,
    environment: group.environment,
    owner: group.owner,
    application: group.service,
    verdict: verdict(group),
    confidence: Math.min(100, 40 + evidenceCompleteness * 20),
    riskScore: group.riskScore,
    publicAddress: publicAddress ?? "Public-address evidence unavailable",
    ports: exposedRules.map((rule) => `${rule.protocol}/${rule.ports}`).join(", ") || "None",
    routeEvidence: path?.reason ?? "No route evidence is connected.",
    externalEvidence:
      group.traffic.coverage > 0
        ? `${group.traffic.accepted30d.toLocaleString()} accepted flows in 30 days`
        : "Flow Log evidence unavailable",
    lastObserved: source.generatedAt,
    dataClass: "Not classified",
    privilegedIdentity: "Identity evidence unavailable",
    criticalVulnerabilities: group.vulnerabilities.filter(
      (item) => item.highestSeverity === "critical",
    ).length,
    toxicSignals,
    path: path?.hops ?? ["Internet", "Route evidence pending", group.name],
  };
}

function recommendationFor(group: SecurityGroup): RuleRecommendation | null {
  const current = group.rules.find((rule) => rule.exposure === "Public");
  if (!current) return null;
  const observedSources = group.traffic.topTalkers.map((talker) => talker.source).slice(0, 5);
  const proposedRules = observedSources.length
    ? observedSources.map(
        (source) => `${current.direction} ${current.protocol}/${current.ports} ${source}`,
      )
    : [
        `${current.direction} ${current.protocol}/${current.ports} <approved CIDR, prefix list, or security-group reference>`,
      ];
  const trafficEvidence = group.traffic.coverage > 0;
  return {
    id: `recommendation:${canonicalSecurityGroupKey(group)}:${current.id}`,
    groupId: group.id,
    groupName: group.name,
    owner: group.owner,
    application: group.service,
    currentRule: `${current.direction} ${current.protocol}/${current.ports} ${current.source}`,
    proposedRules,
    observationWindow: trafficEvidence ? "30 days" : "Traffic evidence unavailable",
    basis: [
      `${group.publicRules} internet-wide rule${group.publicRules === 1 ? "" : "s"} observed in AWS`,
      trafficEvidence
        ? `${group.traffic.coverage}% Flow Log coverage supports source narrowing`
        : "Owner approval is required because Flow Log evidence is unavailable",
      `${group.attachments.length} attached resource${group.attachments.length === 1 ? "" : "s"} considered`,
    ],
    confidence: trafficEvidence ? Math.min(95, 55 + group.traffic.coverage / 2) : 45,
    riskBefore: group.riskScore,
    riskAfter: group.projectedRisk,
    pathsRemoved: group.paths.filter((path) => path.status !== "blocked").length,
    trafficPreserved: trafficEvidence ? 99 : 0,
    rollback: `Restore rule ${current.id} from the evidence snapshot if verification detects lost approved traffic.`,
  };
}

function hygieneFor(group: SecurityGroup): HygieneIssue[] {
  const result: HygieneIssue[] = [];
  if (!group.attachments.length) {
    result.push({
      id: `hygiene:unused:${canonicalSecurityGroupKey(group)}`,
      type: "Unused group",
      resource: group.name,
      account: group.accountName,
      count: 1,
      impact: "No attached workload was present in the current snapshot.",
      recommendation: "Confirm the group is unreferenced before scheduling deletion.",
    });
  }
  if (group.owner === "Unassigned") {
    result.push({
      id: `hygiene:owner:${canonicalSecurityGroupKey(group)}`,
      type: "Missing ownership",
      resource: group.name,
      account: group.accountName,
      count: 1,
      impact: "Findings cannot be routed to an accountable team.",
      recommendation: "Add an Owner or Team tag or configure an ownership rule.",
    });
  }
  const duplicateCount = group.rules.length - new Set(
    group.rules.map((rule) =>
      [rule.direction, rule.protocol, rule.ports, rule.source].join("|"),
    ),
  ).size;
  if (duplicateCount > 0) {
    result.push({
      id: `hygiene:duplicate:${canonicalSecurityGroupKey(group)}`,
      type: "Duplicate rule",
      resource: group.name,
      account: group.accountName,
      count: duplicateCount,
      impact: "Duplicate permissions increase review noise and quota consumption.",
      recommendation: "Remove duplicate rules through the owning IaC repository.",
    });
  }
  return result;
}

export function deriveLiveIntelligence(inventory: AwsInventory): LiveIntelligence {
  const groups = inventory.groups;
  const exposureRecords = groups
    .filter((group) => group.publicRules > 0)
    .map((group) => exposureFor(group, inventory.source))
    .sort((left, right) => right.riskScore - left.riskScore);
  const ruleRecommendations = groups
    .map(recommendationFor)
    .filter((item): item is RuleRecommendation => Boolean(item))
    .sort((left, right) => right.riskBefore - left.riskBefore);
  const hygieneIssues = groups.flatMap(hygieneFor);
  const ownerMap = new Map<string, SecurityGroup[]>();
  for (const group of groups.filter((item) => item.findings.length)) {
    const owner = group.owner || "Unassigned";
    ownerMap.set(owner, [...(ownerMap.get(owner) ?? []), group]);
  }
  const ownerQueues: OwnerQueue[] = [...ownerMap.entries()].map(([owner, owned]) => ({
    id: `owner:${encodeURIComponent(owner.toLowerCase())}`,
    owner,
    email: owner === "Unassigned" ? "unassigned" : "Resolved through identity directory when connected",
    application: [...new Set(owned.map((group) => group.service))].join(", "),
    openFindings: owned.reduce((sum, group) => sum + group.findings.length, 0),
    critical: owned.filter((group) => group.severity === "critical").length,
    overdue: 0,
    dueDate: "Not assigned",
    risk: Math.max(...owned.map((group) => group.riskScore)),
    oldestAge: 0,
    coverage: Math.round(
      owned.reduce((sum, group) => sum + group.traffic.coverage, 0) / owned.length,
    ),
  }));
  const affected = exposureRecords.length;
  const controlMappings: ControlMapping[] = [
    {
      id: "EC2.19",
      title: "Security groups should not allow unrestricted access to high-risk ports",
      framework: ["AWS FSBP", "CIS AWS"],
      nativeResult: affected ? "Failed" : "Passed",
      gatewatchResult: exposureRecords.some((item) => item.riskScore >= 85)
        ? "Critical"
        : affected
          ? "High"
          : "Aligned",
      affected,
      explanation: "Gatewatch separates broad configuration from verified reachability and evidence completeness.",
    },
  ];
  return {
    mode: "live",
    source: inventory.source,
    exposureRecords,
    ruleRecommendations,
    driftEvents: groups
      .filter((group) => group.changedBy !== "Not available in EC2 inventory")
      .map((group) => ({
        id: `drift:${group.change.eventId}:${canonicalSecurityGroupKey(group)}`,
        groupId: group.id,
        groupName: group.name,
        occurredAt: group.change.time,
        actor: group.change.actor,
        actorType: "CloudTrail identity",
        channel: group.change.channel,
        eventName: group.change.eventName,
        summary: group.change.after,
        previousRule: group.change.before,
        currentRule: group.change.after,
        riskDelta: group.riskScore,
        severity: group.severity,
        reason: group.change.approved ? "Approved change" : "No approval evidence is linked",
        owner: group.owner,
        ticket: group.intent.ticket || "No ticket found",
        recurrence: 1,
      })),
    ownerQueues,
    controlMappings,
    hygieneIssues,
    iacChanges: [],
    programTrend: [],
  };
}
