import { env } from "cloudflare:workers";
import type {
  SecurityGroup,
  SecurityRule,
  Severity,
} from "./security-data";
import {
  assessNetworkExposure,
  networkExposureRiskAdjustment,
  type NetworkExposureEvidence,
} from "./network-exposure";

type SnapshotRule = {
  ruleId: string | null;
  isEgress: boolean;
  protocol: string;
  fromPort: number | null;
  toPort: number | null;
  cidrIpv4: string | null;
  cidrIpv6: string | null;
  prefixListId: string | null;
  referencedGroup: { groupId?: string | null } | null;
  description: string | null;
};

type SnapshotGroup = {
  accountId: string;
  accountName: string;
  region: string;
  id: string;
  name: string | null;
  description: string | null;
  vpcId: string | null;
  isDefault: boolean;
  tags: Record<string, string>;
  inboundRuleCount: number;
  outboundRuleCount: number;
  publicIngressRuleCount: number;
  publicEgressRuleCount: number;
  networkInterfaceAttachmentCount: number;
  networkInterfaceTypes: Record<string, number>;
  resourceAttachments?: SnapshotAttachment[];
  networkEvidence?: SnapshotNetworkEvidence;
  observedAt: string;
  rules: SnapshotRule[];
};

type SnapshotAttachment = {
  resourceId: string;
  resourceName: string | null;
  resourceType: string;
  resourceArn: string | null;
  networkInterfaceId: string | null;
  description: string | null;
  privateIpAddress: string | null;
  publicIpAddress: string | null;
  subnetId?: string | null;
  vpcId?: string | null;
  tags: Record<string, string>;
};

type SnapshotNetworkEvidence = NetworkExposureEvidence & {
  state: "configured-internet-path" | "blocked" | "incomplete";
};

type Snapshot = {
  schemaVersion: string;
  snapshotId: string;
  generatedAt: string;
  complete: boolean;
  errors: unknown[];
  summary: {
    accountsExpected: number;
    accountsAuthenticated: number;
    regionsExpected: number;
    regionsScanned: number;
    securityGroupCount: number;
    securityGroupRuleCount: number;
    errorCount: number;
  };
  securityGroups: SnapshotGroup[];
};

export type AwsInventory = {
  groups: SecurityGroup[];
  source: {
    mode: "aws";
    snapshotId: string;
    generatedAt: string;
    complete: boolean;
    accountCount: number;
    accountsExpected: number;
    regionCount: number;
    regionsExpected: number;
    groupCount: number;
    ruleCount: number;
    errorCount: number;
    coveragePercent: number;
    freshnessMinutes: number;
  };
};

const MAX_SNAPSHOT_BYTES = 25 * 1024 * 1024;
const CACHE_MILLISECONDS = 60_000;
let cache: { expiresAt: number; inventory: AwsInventory } | null = null;

function clean(value: unknown, fallback: string, max = 240) {
  return typeof value === "string" && value.trim()
    ? value.trim().slice(0, max)
    : fallback;
}

function publicPeer(rule: SnapshotRule) {
  return rule.cidrIpv4 === "0.0.0.0/0" || rule.cidrIpv6 === "::/0";
}

function peerFor(rule: SnapshotRule) {
  return (
    rule.cidrIpv4 ??
    rule.cidrIpv6 ??
    rule.prefixListId ??
    rule.referencedGroup?.groupId ??
    "Unknown peer"
  );
}

function portsFor(rule: SnapshotRule) {
  if (rule.protocol === "-1" || rule.fromPort === null || rule.toPort === null) {
    return "All";
  }
  return rule.fromPort === rule.toPort
    ? String(rule.fromPort)
    : `${rule.fromPort}–${rule.toPort}`;
}

function protocolFor(protocol: string) {
  if (protocol === "-1") return "All";
  if (protocol === "6") return "TCP";
  if (protocol === "17") return "UDP";
  if (protocol === "1" || protocol === "58") return "ICMP";
  return protocol.toUpperCase();
}

function isAdministrative(rule: SnapshotRule) {
  if (rule.isEgress || !publicPeer(rule)) return false;
  if (rule.protocol === "-1") return true;
  const from = rule.fromPort ?? -1;
  const to = rule.toPort ?? from;
  return [22, 3389, 5985, 5986, 5432, 3306, 1433, 6379, 27017].some(
    (port) => from <= port && to >= port,
  );
}

function widePortRange(rule: SnapshotRule) {
  return (
    !rule.isEgress &&
    publicPeer(rule) &&
    rule.fromPort !== null &&
    rule.toPort !== null &&
    rule.toPort - rule.fromPort >= 100
  );
}

function riskFor(group: SnapshotGroup) {
  const publicIngress = group.rules.filter(
    (rule) => !rule.isEgress && publicPeer(rule),
  );
  const publicEgress = group.rules.filter(
    (rule) => rule.isEgress && publicPeer(rule),
  );
  const admin = publicIngress.filter(isAdministrative).length;
  const allIngress = publicIngress.filter((rule) => rule.protocol === "-1").length;
  const broadPorts = publicIngress.filter(widePortRange).length;
  const allEgress = publicEgress.some((rule) => rule.protocol === "-1");
  const attached = group.networkInterfaceAttachmentCount > 0;
  const exposure = publicIngress.map((rule) =>
    assessNetworkExposure({
      evidence: group.networkEvidence,
      attachments: group.resourceAttachments,
      attachmentCount: group.networkInterfaceAttachmentCount,
      addressFamily: rule.cidrIpv6 === "::/0" ? "IPv6" : "IPv4",
    }),
  );

  if (!publicIngress.length && !publicEgress.length) return 18;
  const score =
    28 +
    Math.min(24, publicIngress.length * 8) +
    Math.min(24, admin * 18) +
    Math.min(24, allIngress * 20) +
    Math.min(12, broadPorts * 8) +
    (allEgress ? 10 : 0) +
    (attached && publicIngress.length ? 8 : 0);
  const pathAdjustment = networkExposureRiskAdjustment(exposure, attached);
  const minimum = attached && publicIngress.length ? 45 : 30;
  return Math.max(minimum, Math.min(100, score - pathAdjustment));
}

function severityFor(score: number): Severity {
  if (score >= 85) return "critical";
  if (score >= 70) return "high";
  if (score >= 45) return "medium";
  return "low";
}

function environmentFor(tags: Record<string, string>): SecurityGroup["environment"] {
  const value = clean(
    tags.Environment ?? tags.environment ?? tags.Env ?? tags.env,
    "Shared",
    40,
  ).toLowerCase();
  if (value.includes("prod")) return "Production";
  if (value.includes("stag") || value.includes("test")) return "Staging";
  if (value.includes("dev") || value.includes("sandbox")) return "Development";
  return "Shared";
}

function attachmentType(group: SnapshotGroup) {
  const names = Object.keys(group.networkInterfaceTypes).join(" ").toLowerCase();
  if (names.includes("lambda")) return "Lambda" as const;
  if (names.includes("rds")) return "RDS" as const;
  if (names.includes("load") || names.includes("elb")) return "ALB" as const;
  return "EC2" as const;
}

function normalizedAttachmentType(value: string) {
  const normalized = value.toLowerCase();
  if (normalized.includes("elasticfilesystem") || normalized === "efs") return "EFS" as const;
  if (normalized.includes("rds")) return "RDS" as const;
  if (normalized.includes("loadbalanc") || normalized.includes("elb")) return "ALB" as const;
  if (normalized.includes("elasticache")) return "ElastiCache" as const;
  if (normalized.includes("sagemaker")) return "SageMaker" as const;
  if (normalized.includes("lambda")) return "Lambda" as const;
  if (normalized.includes("instance") || normalized === "ec2") return "EC2" as const;
  return "Network interface" as const;
}

function findingsFor(group: SnapshotGroup) {
  const findings: string[] = [];
  const publicIngress = group.rules.filter(
    (rule) => !rule.isEgress && publicPeer(rule),
  );
  const publicEgress = group.rules.filter(
    (rule) => rule.isEgress && publicPeer(rule),
  );
  if (publicIngress.some((rule) => rule.protocol === "-1")) {
    findings.push("All ingress traffic allows an internet-wide source");
  }
  if (publicIngress.some(isAdministrative)) {
    findings.push("Administrative or data-service ports allow internet-wide sources");
  }
  if (publicIngress.some(widePortRange)) {
    findings.push("A wide ingress port range allows internet-wide sources");
  }
  if (publicIngress.length) {
    findings.push(
      `${publicIngress.length} ingress rule${publicIngress.length === 1 ? "" : "s"} allow 0.0.0.0/0 or ::/0`,
    );
  }
  if (publicEgress.some((rule) => rule.protocol === "-1")) {
    findings.push("All egress traffic is allowed to the internet");
  } else if (publicEgress.length) {
    findings.push(
      `${publicEgress.length} egress rule${publicEgress.length === 1 ? "" : "s"} allow an internet-wide destination`,
    );
  }
  if (!group.networkInterfaceAttachmentCount && findings.length) {
    findings.push("No attached network interface was observed; confirm whether this group is unused");
  }
  return findings.slice(0, 6);
}

function mapRule(rule: SnapshotRule, index: number, observedAt: string): SecurityRule {
  const source = peerFor(rule);
  const isPublic = publicPeer(rule);
  const finding = isAdministrative(rule)
    ? "Administrative or data-service port permits internet-wide sources"
    : widePortRange(rule)
      ? "Wide port range permits internet-wide sources"
      : isPublic && rule.protocol === "-1"
        ? "All traffic permits an internet-wide peer"
        : undefined;
  return {
    id: rule.ruleId ?? `rule-${index + 1}`,
    direction: rule.isEgress ? "Egress" : "Ingress",
    protocol: protocolFor(rule.protocol),
    ports: portsFor(rule),
    source,
    sourceLabel:
      source === "0.0.0.0/0"
        ? "Anywhere IPv4"
        : source === "::/0"
          ? "Anywhere IPv6"
          : rule.referencedGroup
            ? "Referenced security group"
            : rule.prefixListId
              ? "Managed prefix list"
              : "CIDR range",
    exposure: isPublic ? "Public" : rule.referencedGroup ? "Referenced" : "Private",
    lastObserved: observedAt,
    flows30d: 0,
    finding,
  };
}

function mapGroup(group: SnapshotGroup, snapshot: Snapshot): SecurityGroup {
  const findings = findingsFor(group);
  const riskScore = riskFor(group);
  const publicRules = group.publicIngressRuleCount + group.publicEgressRuleCount;
  const mappedRules = group.rules.map((rule, index) =>
    mapRule(rule, index, group.observedAt),
  );
  const publicIngress = group.rules.filter(
    (rule) => !rule.isEgress && publicPeer(rule),
  );
  const owner = clean(
    group.tags.Owner ?? group.tags.owner ?? group.tags.Team ?? group.tags.team,
    "Unassigned",
    100,
  );
  const service = clean(
    group.tags.Application ?? group.tags.application ?? group.tags.Service ?? group.tags.service,
    group.name ?? group.id,
    120,
  );
  const groupName = clean(group.name, group.id, 160);
  const exposureAssessments = publicIngress.map((rule) =>
    assessNetworkExposure({
      evidence: group.networkEvidence,
      attachments: group.resourceAttachments,
      attachmentCount: group.networkInterfaceAttachmentCount,
      addressFamily: rule.cidrIpv6 === "::/0" ? "IPv6" : "IPv4",
    }),
  );
  const effectiveExposure = exposureAssessments.some(
    (assessment) => assessment.status === "reachable",
  )
    ? "A direct internet path is configured."
    : exposureAssessments.some((assessment) => assessment.status === "potential")
      ? "Internet-path evidence is incomplete; risk was only slightly reduced."
      : "No current direct internet path is configured; the rule remains broadly permissive to connected networks.";

  return {
    id: group.id,
    name: groupName,
    accountId: group.accountId,
    accountName: clean(group.accountName, group.accountId, 160),
    environment: environmentFor(group.tags),
    region: group.region,
    vpc: clean(group.vpcId, "EC2-Classic or unavailable", 160),
    owner,
    service,
    description: clean(group.description, "No security-group description provided.", 500),
    inboundCount: group.inboundRuleCount,
    outboundCount: group.outboundRuleCount,
    publicRules,
    riskScore,
    projectedRisk: Math.max(12, riskScore - Math.min(45, publicRules * 10)),
    severity: severityFor(riskScore),
    defaultStatus: findings.length ? "needs-review" : "approved",
    lastChanged: "CloudTrail attribution pending",
    lastReviewed: "Never",
    changedBy: "Not available in EC2 inventory",
    findings,
    rules: mappedRules,
    attachments: group.resourceAttachments?.length
      ? group.resourceAttachments.map((attachment) => ({
          id: clean(attachment.resourceId, attachment.networkInterfaceId ?? "Unknown resource", 240),
          name: clean(attachment.resourceName, attachment.resourceId, 240),
          type: normalizedAttachmentType(attachment.resourceType),
          criticality: riskScore >= 85 ? "Critical" : riskScore >= 70 ? "High" : "Medium",
          publicAddress: clean(attachment.publicIpAddress, "", 80) || undefined,
          privateAddress: clean(attachment.privateIpAddress, "", 80) || undefined,
          networkInterfaceId: clean(attachment.networkInterfaceId, "", 120) || undefined,
          subnetId: clean(attachment.subnetId, "", 120) || undefined,
          vpcId: clean(attachment.vpcId, "", 120) || undefined,
          description: clean(attachment.description, "", 500) || undefined,
          arn: clean(attachment.resourceArn, "", 600) || undefined,
          tags: attachment.tags ?? {},
        }))
      : group.networkInterfaceAttachmentCount
        ? [
            {
              id: `${group.id}-attachments`,
              name: `${group.networkInterfaceAttachmentCount} attached network interface${group.networkInterfaceAttachmentCount === 1 ? "" : "s"}`,
              type: attachmentType(group),
              criticality: riskScore >= 85 ? "Critical" : riskScore >= 70 ? "High" : "Medium",
              description: "Attachment details were not included in this older inventory snapshot.",
              tags: {},
            },
          ]
        : [],
    paths: publicIngress.slice(0, 3).map((rule, index) => {
      const network = group.networkEvidence;
      const addressFamily = rule.cidrIpv6 === "::/0" ? "IPv6" : "IPv4";
      const assessment = assessNetworkExposure({
        evidence: network,
        attachments: group.resourceAttachments,
        attachmentCount: group.networkInterfaceAttachmentCount,
        addressFamily,
      });
      const status = assessment.status;
      const routeHop = network?.routeTableIds.length
        ? `Internet gateway route (${network.routeTableIds.join(", ")})`
        : "Route evidence pending";
      const subnetHop = network?.subnetIds.length
        ? `Subnet ${network.subnetIds.join(", ")}`
        : "Subnet evidence pending";
      const blockerHop = assessment.classification === "no-internet-route"
        ? "No internet-gateway route"
        : assessment.classification === "no-public-address"
          ? `No public ${addressFamily} address`
          : assessment.classification === "network-acl-blocked"
            ? "Network ACL blocks ingress"
            : assessment.classification === "unattached"
              ? "No attached workload"
              : "Network prerequisites do not form one path";
      return {
        id: `${group.id}-public-${index}`,
        direction: "Ingress" as const,
        source: "Internet",
        destination: groupName,
        service: `${protocolFor(rule.protocol)} ${portsFor(rule)}`,
        status,
        confidence: "Medium" as const,
        reason: assessment.reason,
        hops: status === "blocked"
          ? ["Internet", blockerHop, groupName]
          : ["Internet", routeHop, subnetHop, groupName],
      };
    }),
    traffic: {
      coverage: 0,
      accepted30d: 0,
      rejected30d: 0,
      lastObserved: group.observedAt,
      topTalkers: [],
    },
    intent: {
      status: "undocumented",
      application: service,
      owner,
      approvedAccess: "No approved access policy has been recorded.",
      justification: "Inventory was collected from the deployed AWS configuration.",
      ticket: "",
    },
    vulnerabilities: [],
    riskFactors: [
      {
        key: "broad-ingress",
        label: "Internet-wide ingress",
        points: Math.min(30, group.publicIngressRuleCount * 10),
        maxPoints: 30,
        evidence: `${group.publicIngressRuleCount} internet-wide ingress rule(s) observed.`,
      },
      {
        key: "sensitive-ports",
        label: "Sensitive services",
        points: Math.min(25, publicIngress.filter(isAdministrative).length * 20),
        maxPoints: 25,
        evidence: `${publicIngress.filter(isAdministrative).length} administrative or data-service rule(s) permit internet-wide sources.`,
      },
      {
        key: "attachment",
        label: "Attached resources",
        points: group.networkInterfaceAttachmentCount ? 15 : 0,
        maxPoints: 15,
        evidence: `${group.networkInterfaceAttachmentCount} network interface attachment(s) observed.`,
      },
      {
        key: "egress",
        label: "Internet-wide egress",
        points: Math.min(20, group.publicEgressRuleCount * 5),
        maxPoints: 20,
        evidence: `${group.publicEgressRuleCount} internet-wide egress rule(s) observed.`,
      },
      {
        key: "evidence",
        label: "Effective exposure",
        points: exposureAssessments.some((assessment) => assessment.status === "reachable")
          ? 20
          : exposureAssessments.some((assessment) => assessment.status === "potential")
            ? 10
            : 4,
        maxPoints: 20,
        evidence: effectiveExposure,
      },
    ],
    change: {
      eventId: snapshot.snapshotId,
      eventName: "EC2 inventory observation",
      actor: "Gatewatch collector",
      channel: "Automation",
      time: snapshot.generatedAt,
      sourceIp: "AWS control plane",
      approved: false,
      before: "Previous snapshot retained in versioned S3 storage",
      after: `${group.inboundRuleCount} ingress and ${group.outboundRuleCount} egress rules observed`,
    },
    recommendation: findings.length
      ? "Confirm business intent, validate effective reachability, and replace internet-wide access with the narrowest approved CIDR, prefix list, or security-group reference."
      : "No internet-wide rule was observed. Continue monitoring for configuration drift.",
  };
}

function assertSnapshot(value: unknown): Snapshot {
  if (!value || typeof value !== "object") throw new Error("INVALID_SNAPSHOT");
  const snapshot = value as Partial<Snapshot>;
  if (
    snapshot.schemaVersion !== "1.0" ||
    !Array.isArray(snapshot.securityGroups) ||
    !snapshot.summary ||
    typeof snapshot.snapshotId !== "string" ||
    typeof snapshot.generatedAt !== "string"
  ) {
    throw new Error("INVALID_SNAPSHOT_SCHEMA");
  }
  return snapshot as Snapshot;
}

export function configuredAwsInventory() {
  return Boolean(
    env.GATEWATCH_SNAPSHOT_BUCKET &&
      env.GATEWATCH_AWS_BRIDGE_URL &&
      env.GATEWATCH_AWS_BRIDGE_TOKEN,
  );
}

export async function loadAwsInventory(force = false): Promise<AwsInventory> {
  if (!force && cache && cache.expiresAt > Date.now()) return cache.inventory;
  const bridgeUrl = clean(env.GATEWATCH_AWS_BRIDGE_URL, "", 500).replace(
    /\/$/,
    "",
  );
  const bridgeToken = clean(env.GATEWATCH_AWS_BRIDGE_TOKEN, "", 500);
  if (!bridgeUrl || !bridgeToken) {
    throw new Error("AWS_INVENTORY_NOT_CONFIGURED");
  }
  const response = await fetch(`${bridgeUrl}/inventory`, {
    headers: { authorization: `Bearer ${bridgeToken}` },
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error("AWS_INVENTORY_BRIDGE_FAILED");
  const body = await response.text();
  if (!body || new TextEncoder().encode(body).byteLength > MAX_SNAPSHOT_BYTES) {
    throw new Error("AWS_INVENTORY_INVALID_BODY");
  }
  const snapshot = assertSnapshot(JSON.parse(body));
  const inventory: AwsInventory = {
    groups: snapshot.securityGroups.map((group) => mapGroup(group, snapshot)),
    source: {
      mode: "aws",
      snapshotId: snapshot.snapshotId,
      generatedAt: snapshot.generatedAt,
      complete: snapshot.complete,
      accountCount: snapshot.summary.accountsAuthenticated,
      accountsExpected: snapshot.summary.accountsExpected,
      regionCount: snapshot.summary.regionsScanned,
      regionsExpected: snapshot.summary.regionsExpected,
      groupCount: snapshot.summary.securityGroupCount,
      ruleCount: snapshot.summary.securityGroupRuleCount,
      errorCount: snapshot.summary.errorCount,
      coveragePercent: Math.max(
        0,
        Math.min(
          100,
          Math.round(
            ((snapshot.summary.accountsAuthenticated /
              Math.max(1, snapshot.summary.accountsExpected) +
              snapshot.summary.regionsScanned /
                Math.max(1, snapshot.summary.regionsExpected)) /
              2) *
              100,
          ),
        ),
      ),
      freshnessMinutes: Math.max(
        0,
        Math.round((Date.now() - Date.parse(snapshot.generatedAt)) / 60_000),
      ),
    },
  };
  cache = { expiresAt: Date.now() + CACHE_MILLISECONDS, inventory };
  return inventory;
}
