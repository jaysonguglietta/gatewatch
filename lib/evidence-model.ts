import type { SecurityGroup } from "./security-data";

export type EvidenceState =
  | "observed"
  | "inferred"
  | "simulated"
  | "incomplete"
  | "stale"
  | "unavailable";

export type EvidenceDescriptor = {
  state: EvidenceState;
  confidence: number;
  observedAt: string;
  sources: string[];
  limitations: string[];
  snapshotId: string;
};

function component(value: string) {
  return encodeURIComponent(value.trim().toLowerCase() || "unknown");
}

export function canonicalSecurityGroupKey(
  group: Pick<SecurityGroup, "accountId" | "region" | "vpc" | "id">,
) {
  return [
    "aws",
    component(group.accountId),
    component(group.region),
    component(group.vpc),
    "security-group",
    component(group.id),
  ].join(":");
}

export function canonicalFindingFingerprint(
  group: Pick<SecurityGroup, "accountId" | "region" | "vpc" | "id">,
  findingKey: string,
) {
  return `gw-v2:${canonicalSecurityGroupKey(group)}:${component(findingKey)}`;
}

export function evidenceForGroup(
  group: SecurityGroup,
  snapshotId: string,
  observedAt: string,
): EvidenceDescriptor {
  const hasReachability = group.paths.some((path) => path.status !== "potential");
  const hasTraffic = group.traffic.coverage > 0;
  const hasChangeActor = group.changedBy !== "Not available in EC2 inventory";
  const limitations = [
    !hasReachability ? "Route and reachability evidence is not connected." : "",
    !hasTraffic ? "VPC Flow Log coverage is unavailable." : "",
    !hasChangeActor ? "CloudTrail actor attribution is pending." : "",
  ].filter(Boolean);
  const sources = [
    "EC2 security-group inventory",
    ...(hasReachability ? ["Network reachability"] : []),
    ...(hasTraffic ? ["VPC Flow Logs"] : []),
    ...(hasChangeActor ? ["CloudTrail"] : []),
  ];
  return {
    state: limitations.length ? "incomplete" : "observed",
    confidence: Math.max(35, 100 - limitations.length * 20),
    observedAt,
    sources,
    limitations,
    snapshotId,
  };
}

export function evidenceSnapshotJson(
  group: SecurityGroup,
  evidence: EvidenceDescriptor,
  riskScore = group.riskScore,
) {
  return JSON.stringify({
    schemaVersion: "2.0",
    canonicalResourceKey: canonicalSecurityGroupKey(group),
    accountId: group.accountId,
    region: group.region,
    vpcId: group.vpc,
    securityGroupId: group.id,
    riskScore,
    reachablePaths: group.paths.filter((path) => path.status === "reachable").length,
    potentialPaths: group.paths.filter((path) => path.status === "potential").length,
    flows30d: group.traffic.accepted30d,
    trafficCoverage: group.traffic.coverage,
    evidence,
  });
}
