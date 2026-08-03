export type ExposureVerdict =
  | "Confirmed public service"
  | "Internet path exists"
  | "Internal only"
  | "Broad but unreachable"
  | "Evidence incomplete";

export type ExposureRecord = {
  id: string;
  groupId: string;
  groupName: string;
  account: string;
  region: string;
  environment: string;
  owner: string;
  application: string;
  verdict: ExposureVerdict;
  confidence: number;
  riskScore: number;
  publicAddress: string;
  ports: string;
  routeEvidence: string;
  externalEvidence: string;
  lastObserved: string;
  dataClass: string;
  privilegedIdentity: string;
  criticalVulnerabilities: number;
  toxicSignals: string[];
  path: string[];
};

export type RuleRecommendation = {
  id: string;
  groupId: string;
  groupName: string;
  owner: string;
  application: string;
  currentRule: string;
  proposedRules: string[];
  observationWindow: string;
  basis: string[];
  confidence: number;
  riskBefore: number;
  riskAfter: number;
  pathsRemoved: number;
  trafficPreserved: number;
  rollback: string;
};

export type DriftEvent = {
  id: string;
  groupId: string;
  groupName: string;
  occurredAt: string;
  actor: string;
  actorType: string;
  channel: string;
  eventName: string;
  summary: string;
  previousRule: string;
  currentRule: string;
  riskDelta: number;
  severity: "critical" | "high" | "medium" | "low";
  reason: string;
  owner: string;
  ticket: string;
  recurrence: number;
};

export type OwnerQueue = {
  id: string;
  owner: string;
  email: string;
  application: string;
  openFindings: number;
  critical: number;
  overdue: number;
  dueDate: string;
  risk: number;
  oldestAge: number;
  coverage: number;
};

export type ExceptionSeed = {
  id: string;
  subjectId: string;
  groupName: string;
  owner: string;
  status: "approved" | "requested" | "rejected" | "revoked" | "expired";
  expiresAt: string;
  ticketRef: string;
  justification: string;
  compensatingControls: string[];
  approver: string;
};

export type ControlMapping = {
  id: string;
  title: string;
  framework: string[];
  nativeResult: "Passed" | "Failed" | "Not enabled";
  gatewatchResult: "Critical" | "High" | "Medium" | "Aligned";
  affected: number;
  explanation: string;
};

export type HygieneIssue = {
  id: string;
  type:
    | "Unused group"
    | "Default group"
    | "Duplicate rule"
    | "Shadowed rule"
    | "Stale reference"
    | "Missing ownership"
    | "Quota pressure";
  resource: string;
  account: string;
  count: number;
  impact: string;
  recommendation: string;
};

export type IacChange = {
  id: string;
  repository: string;
  pullRequest: string;
  author: string;
  environment: string;
  proposedChange: string;
  projectedRisk: number;
  currentRisk: number;
  verdict: "Block" | "Review" | "Pass";
  policy: string;
  evidence: string[];
};

export const exposureRecords: ExposureRecord[] = [
  {
    id: "exposure-payments-ssh",
    groupId: "sg-0a41f2e91b71",
    groupName: "prod-payments-api",
    account: "Payments Production",
    region: "us-east-1",
    environment: "Production",
    owner: "Payments Platform",
    application: "Payment Authorization API",
    verdict: "Confirmed public service",
    confidence: 99,
    riskScore: 96,
    publicAddress: "203.0.113.41",
    ports: "TCP/22, TCP/443",
    routeEvidence: "Internet Gateway → public subnet → ENI",
    externalEvidence: "SSH banner observed 11 minutes ago",
    lastObserved: "11 min ago",
    dataClass: "PCI payment data",
    privilegedIdentity: "PaymentsRuntimeRole · 18 unused permissions",
    criticalVulnerabilities: 3,
    toxicSignals: [
      "Internet-wide SSH",
      "Critical workload vulnerabilities",
      "Privileged instance role",
      "PCI data path",
    ],
    path: ["Internet", "igw-prod", "rtb-public-a", "eni-payments-a", "payments-api-a"],
  },
  {
    id: "exposure-shared-bastion",
    groupId: "sg-04bc18a21e7d",
    groupName: "shared-admin-access",
    account: "Shared Services",
    region: "us-east-1",
    environment: "Shared",
    owner: "Cloud Operations",
    application: "Administrative Access",
    verdict: "Confirmed public service",
    confidence: 98,
    riskScore: 89,
    publicAddress: "198.51.100.44",
    ports: "TCP/22, TCP/3389",
    routeEvidence: "Internet Gateway → public subnet → bastion ENI",
    externalEvidence: "SSH service observed; RDP port closed at scan time",
    lastObserved: "27 min ago",
    dataClass: "Administrative control plane",
    privilegedIdentity: "BastionSessionRole · least privilege",
    criticalVulnerabilities: 0,
    toxicSignals: ["Internet-wide administration", "Cross-account reach", "Shared blast radius"],
    path: ["Internet", "igw-shared", "rtb-admin", "eni-bastion", "shared-bastion-01"],
  },
  {
    id: "exposure-customer-db",
    groupId: "sg-09dd82c742ad",
    groupName: "prod-customer-db",
    account: "Customer Data Production",
    region: "us-east-1",
    environment: "Production",
    owner: "Data Reliability",
    application: "Customer Profile Store",
    verdict: "Internet path exists",
    confidence: 94,
    riskScore: 78,
    publicAddress: "Via internet-facing ALB path",
    ports: "TCP/5432",
    routeEvidence: "Internet → ALB → application tier → database group",
    externalEvidence: "No direct public listener; transitive path confirmed",
    lastObserved: "2 hr ago",
    dataClass: "Restricted customer PII",
    privilegedIdentity: "RDS monitoring role only",
    criticalVulnerabilities: 1,
    toxicSignals: ["Sensitive data", "Transitive public path", "Broad application-tier source"],
    path: ["Internet", "prod-public-alb", "payments-api", "sg-prod-customer-db", "customer-profile-primary"],
  },
  {
    id: "exposure-order-workers",
    groupId: "sg-022a71c3bafd",
    groupName: "legacy-order-workers",
    account: "Commerce Production",
    region: "us-west-2",
    environment: "Production",
    owner: "Unassigned",
    application: "Legacy Order Processing",
    verdict: "Internal only",
    confidence: 91,
    riskScore: 73,
    publicAddress: "None",
    ports: "All traffic",
    routeEvidence: "Reachable from 11 internal VPC CIDRs through Transit Gateway",
    externalEvidence: "No internet route or public address",
    lastObserved: "36 min ago",
    dataClass: "Internal order metadata",
    privilegedIdentity: "LegacyWorkerRole · administrator-like permissions",
    criticalVulnerabilities: 2,
    toxicSignals: ["All-traffic rule", "Privileged workload role", "Missing owner"],
    path: ["Corporate network", "Transit Gateway", "orders-vpc", "worker subnet", "order-worker-01"],
  },
  {
    id: "exposure-analytics",
    groupId: "sg-087ad315301f",
    groupName: "stg-analytics-notebooks",
    account: "Analytics Staging",
    region: "us-east-2",
    environment: "Staging",
    owner: "Analytics Engineering",
    application: "Fraud Research",
    verdict: "Broad but unreachable",
    confidence: 88,
    riskScore: 61,
    publicAddress: "None",
    ports: "TCP/8888",
    routeEvidence: "No route from an Internet Gateway, VPN, or peered production VPC",
    externalEvidence: "Network scan not applicable",
    lastObserved: "No accepted flows in 90 days",
    dataClass: "Synthetic research data",
    privilegedIdentity: "SageMakerExecutionRole · scoped",
    criticalVulnerabilities: 0,
    toxicSignals: ["Internet-wide rule exists", "No effective route"],
    path: ["No effective path"],
  },
  {
    id: "exposure-sandbox",
    groupId: "sg-0611a2fb089c",
    groupName: "dev-integration-sandbox",
    account: "Engineering Sandbox",
    region: "us-west-2",
    environment: "Development",
    owner: "Developer Experience",
    application: "Integration Hub",
    verdict: "Evidence incomplete",
    confidence: 62,
    riskScore: 42,
    publicAddress: "Dynamic",
    ports: "TCP/3000–3010",
    routeEvidence: "Public subnet detected; network-interface inventory is 81% complete",
    externalEvidence: "External scanning is not enabled for this account",
    lastObserved: "Flow Logs unavailable",
    dataClass: "Non-production",
    privilegedIdentity: "IntegrationSandboxRole · unknown usage",
    criticalVulnerabilities: 0,
    toxicSignals: ["Partial collection", "Wide development port range"],
    path: ["Internet", "unknown route coverage", "development subnet"],
  },
];

export const ruleRecommendations: RuleRecommendation[] = [
  {
    id: "rec-payments-ssh",
    groupId: "sg-0a41f2e91b71",
    groupName: "prod-payments-api",
    owner: "Payments Platform",
    application: "Payment Authorization API",
    currentRule: "Ingress TCP/22 from 0.0.0.0/0",
    proposedRules: ["Ingress TCP/22 from 198.51.100.0/24 · Corporate VPN"],
    observationWindow: "90 days",
    basis: ["100% of 4,281 accepted sessions came through corporate VPN", "No partner or automation source observed", "VPN prefix is registered to Cloud Operations"],
    confidence: 98,
    riskBefore: 96,
    riskAfter: 54,
    pathsRemoved: 18,
    trafficPreserved: 100,
    rollback: "Restore rule sgr-0f91 from the signed evidence export.",
  },
  {
    id: "rec-bastion-rdp",
    groupId: "sg-04bc18a21e7d",
    groupName: "shared-admin-access",
    owner: "Cloud Operations",
    application: "Administrative Access",
    currentRule: "Ingress TCP/3389 from 0.0.0.0/0",
    proposedRules: ["Remove TCP/3389 rule", "Retain TCP/22 from 198.51.100.0/24"],
    observationWindow: "180 days",
    basis: ["Zero accepted RDP flows", "SSM Session Manager is enabled", "Port closed in three external scans"],
    confidence: 96,
    riskBefore: 89,
    riskAfter: 47,
    pathsRemoved: 24,
    trafficPreserved: 100,
    rollback: "Reapply the versioned Terraform rule through SEC-2418.",
  },
  {
    id: "rec-db-source",
    groupId: "sg-09dd82c742ad",
    groupName: "prod-customer-db",
    owner: "Data Reliability",
    application: "Customer Profile Store",
    currentRule: "Ingress TCP/5432 from 10.0.0.0/8",
    proposedRules: ["Ingress TCP/5432 from sg-0a41f2e91b71 · payments-api", "Ingress TCP/5432 from sg-0f71d94a2c0e · customer-workers"],
    observationWindow: "60 days",
    basis: ["Only two source security groups generated accepted traffic", "Removes 16.7 million possible IPv4 addresses", "Application manifest confirms both dependencies"],
    confidence: 93,
    riskBefore: 78,
    riskAfter: 31,
    pathsRemoved: 31,
    trafficPreserved: 99.98,
    rollback: "Restore the 10.0.0.0/8 rule for 30 minutes under emergency change policy.",
  },
  {
    id: "rec-orders-all",
    groupId: "sg-022a71c3bafd",
    groupName: "legacy-order-workers",
    owner: "Unassigned",
    application: "Legacy Order Processing",
    currentRule: "Egress all traffic to 0.0.0.0/0",
    proposedRules: ["Egress TCP/443 to pl-63a5400a · S3", "Egress TCP/443 to vpce-0c92 · SQS", "Egress UDP/53 to VPC resolver"],
    observationWindow: "30 days",
    basis: ["Observed destinations are S3, SQS, and Route 53 Resolver", "No arbitrary internet destinations observed", "Flow coverage is 94%"],
    confidence: 86,
    riskBefore: 73,
    riskAfter: 39,
    pathsRemoved: 9,
    trafficPreserved: 99.6,
    rollback: "Temporarily restore egress with a one-hour expiring exception.",
  },
];

export const driftEvents: DriftEvent[] = [
  {
    id: "drift-7f7a",
    groupId: "sg-0a41f2e91b71",
    groupName: "prod-payments-api",
    occurredAt: "2026-07-30T14:42:00Z",
    actor: "AWSReservedSSO_NetworkAdmin/m.lee",
    actorType: "AssumedRole",
    channel: "AWS Console",
    eventName: "AuthorizeSecurityGroupIngress",
    summary: "Opened SSH to the internet outside the approved Terraform workflow.",
    previousRule: "TCP/22 from 198.51.100.0/24",
    currentRule: "TCP/22 from 0.0.0.0/0",
    riskDelta: 42,
    severity: "critical",
    reason: "New internet-wide administration path",
    owner: "Payments Platform",
    ticket: "No ticket found",
    recurrence: 2,
  },
  {
    id: "drift-209c",
    groupId: "sg-04bc18a21e7d",
    groupName: "shared-admin-access",
    occurredAt: "2026-07-30T11:18:00Z",
    actor: "arn:aws:iam::111122223333:role/BreakGlassNetwork",
    actorType: "AssumedRole",
    channel: "AWS CLI",
    eventName: "AuthorizeSecurityGroupIngress",
    summary: "Added public RDP during an incident; emergency window has expired.",
    previousRule: "No TCP/3389 rule",
    currentRule: "TCP/3389 from 0.0.0.0/0",
    riskDelta: 28,
    severity: "high",
    reason: "Expired emergency change remains active",
    owner: "Cloud Operations",
    ticket: "INC-8841",
    recurrence: 1,
  },
  {
    id: "drift-d8c1",
    groupId: "sg-09dd82c742ad",
    groupName: "prod-customer-db",
    occurredAt: "2026-07-29T21:04:00Z",
    actor: "arn:aws:sts::444455556666:assumed-role/TerraformPipeline/prod",
    actorType: "AssumedRole",
    channel: "Terraform Cloud",
    eventName: "ModifySecurityGroupRules",
    summary: "Expanded database source from application group to 10.0.0.0/8.",
    previousRule: "TCP/5432 from sg-0a41f2e91b71",
    currentRule: "TCP/5432 from 10.0.0.0/8",
    riskDelta: 19,
    severity: "high",
    reason: "Approved pipeline, but proposed state violates application intent",
    owner: "Data Reliability",
    ticket: "PR-1842",
    recurrence: 3,
  },
  {
    id: "drift-1a29",
    groupId: "sg-0611a2fb089c",
    groupName: "dev-integration-sandbox",
    occurredAt: "2026-07-29T15:33:00Z",
    actor: "arn:aws:iam::777788889999:user/dev-sandbox",
    actorType: "IAMUser",
    channel: "AWS Console",
    eventName: "AuthorizeSecurityGroupIngress",
    summary: "Added development ports without an expiration date.",
    previousRule: "TCP/3000 from corporate VPN",
    currentRule: "TCP/3000–3010 from 0.0.0.0/0",
    riskDelta: 12,
    severity: "medium",
    reason: "Wide port expansion from a long-lived IAM user",
    owner: "Developer Experience",
    ticket: "No ticket found",
    recurrence: 1,
  },
];

export const ownerQueues: OwnerQueue[] = [
  { id: "owner-payments", owner: "Payments Platform", email: "payments-platform@example.com", application: "Payment Authorization API", openFindings: 8, critical: 3, overdue: 2, dueDate: "2026-08-01", risk: 96, oldestAge: 19, coverage: 100 },
  { id: "owner-cloudops", owner: "Cloud Operations", email: "cloud-operations@example.com", application: "Administrative Access", openFindings: 6, critical: 1, overdue: 1, dueDate: "2026-08-03", risk: 89, oldestAge: 12, coverage: 98 },
  { id: "owner-data", owner: "Data Reliability", email: "data-reliability@example.com", application: "Customer Profile Store", openFindings: 4, critical: 0, overdue: 0, dueDate: "2026-08-05", risk: 78, oldestAge: 7, coverage: 100 },
  { id: "owner-unassigned", owner: "Unassigned", email: "security@example.com", application: "Legacy Order Processing", openFindings: 5, critical: 0, overdue: 3, dueDate: "2026-07-29", risk: 73, oldestAge: 46, coverage: 94 },
  { id: "owner-analytics", owner: "Analytics Engineering", email: "analytics@example.com", application: "Fraud Research", openFindings: 2, critical: 0, overdue: 0, dueDate: "2026-08-12", risk: 61, oldestAge: 5, coverage: 87 },
];

export const exceptionSeeds: ExceptionSeed[] = [
  {
    id: "exception-bastion",
    subjectId: "sg-04bc18a21e7d",
    groupName: "shared-admin-access",
    owner: "Cloud Operations",
    status: "approved",
    expiresAt: "2026-08-02",
    ticketRef: "INC-8841",
    justification: "Temporary emergency administration access during identity-provider recovery.",
    compensatingControls: ["24×7 session recording", "Break-glass MFA", "Source alerting"],
    approver: "Security Duty Manager",
  },
  {
    id: "exception-sandbox",
    subjectId: "sg-0611a2fb089c",
    groupName: "dev-integration-sandbox",
    owner: "Developer Experience",
    status: "requested",
    expiresAt: "2026-08-15",
    ticketRef: "DEVX-1922",
    justification: "Short-lived partner interoperability testing across rotating addresses.",
    compensatingControls: ["Non-production account", "Synthetic data only", "Daily owner review"],
    approver: "Pending",
  },
  {
    id: "exception-legacy",
    subjectId: "sg-022a71c3bafd",
    groupName: "legacy-order-workers",
    owner: "Unassigned",
    status: "expired",
    expiresAt: "2026-07-26",
    ticketRef: "SEC-2190",
    justification: "Migration dependency required broad internal reach.",
    compensatingControls: ["Flow monitoring"],
    approver: "Former Commerce Director",
  },
];

export const controlMappings: ControlMapping[] = [
  { id: "EC2.18", title: "Unrestricted incoming traffic only on authorized ports", framework: ["AWS FSBP", "NIST AC-4", "PCI DSS 1.3.1"], nativeResult: "Failed", gatewatchResult: "Critical", affected: 4, explanation: "Gatewatch confirms two of the four failures have an effective internet path; one exposes PCI workloads." },
  { id: "EC2.19", title: "No unrestricted access to high-risk ports", framework: ["AWS FSBP", "NIST SC-7", "CIS"], nativeResult: "Failed", gatewatchResult: "Critical", affected: 2, explanation: "TCP/22 and TCP/3389 are externally reachable; service evidence is available for SSH." },
  { id: "EC2.2", title: "Default security groups restrict all traffic", framework: ["AWS FSBP", "CIS", "NIST CM-7"], nativeResult: "Failed", gatewatchResult: "Medium", affected: 3, explanation: "Three default groups contain rules; none is attached to a production workload." },
  { id: "EC2.22", title: "Unused security groups should be removed", framework: ["AWS Control Tower"], nativeResult: "Failed", gatewatchResult: "Medium", affected: 17, explanation: "Eleven groups have never been attached; six were detached more than 90 days ago." },
  { id: "EC2.43", title: "Security groups should be tagged", framework: ["AWS FSBP custom"], nativeResult: "Not enabled", gatewatchResult: "High", affected: 9, explanation: "Missing owner and application tags prevent automatic assignment for five active findings." },
];

export const hygieneIssues: HygieneIssue[] = [
  { id: "hygiene-unused", type: "Unused group", resource: "17 security groups", account: "4 accounts", count: 17, impact: "Inventory noise and accidental future reuse", recommendation: "Delete groups detached for more than 90 days after owner confirmation." },
  { id: "hygiene-default", type: "Default group", resource: "3 VPC default groups", account: "Shared + Development", count: 3, impact: "Implicit same-group communication remains available", recommendation: "Remove ingress and egress rules from default groups." },
  { id: "hygiene-duplicate", type: "Duplicate rule", resource: "prod-payments-api", account: "Payments Production", count: 4, impact: "Review complexity with no additional access", recommendation: "Collapse equivalent IPv4 rules and retain the versioned rule ID." },
  { id: "hygiene-shadowed", type: "Shadowed rule", resource: "shared-admin-access", account: "Shared Services", count: 2, impact: "Narrow VPN rules are ineffective while /0 rules exist", recommendation: "Remove public rules before evaluating the intended VPN rules." },
  { id: "hygiene-stale", type: "Stale reference", resource: "sg-0fd2-deleted-app", account: "Commerce Production", count: 6, impact: "References no longer describe a valid application dependency", recommendation: "Remove stale references and update the application manifest." },
  { id: "hygiene-owner", type: "Missing ownership", resource: "9 active security groups", account: "3 accounts", count: 9, impact: "Five findings cannot be routed to an accountable team", recommendation: "Apply Owner and Application tags from the proposed mapping." },
  { id: "hygiene-quota", type: "Quota pressure", resource: "analytics-shared-egress", account: "Analytics Production", count: 58, impact: "Rule count is within two entries of the configured quota", recommendation: "Replace 21 service CIDRs with managed prefix lists." },
];

export const iacChanges: IacChange[] = [
  { id: "iac-1842", repository: "cloud-platform/network-live", pullRequest: "#1842", author: "r.patel", environment: "Production", proposedChange: "Expand PostgreSQL source from application SG to 10.0.0.0/8", projectedRisk: 78, currentRisk: 31, verdict: "Block", policy: "DATA-DB-01 · Databases accept only application security groups", evidence: ["31 new reachable paths", "Restricted customer PII", "No exception reference"] },
  { id: "iac-991", repository: "payments/runtime-infra", pullRequest: "#991", author: "a.chen", environment: "Production", proposedChange: "Add corporate VPN TCP/22 rule and remove 0.0.0.0/0", projectedRisk: 54, currentRisk: 96, verdict: "Pass", policy: "ADMIN-02 · Administration originates from approved VPN", evidence: ["42-point risk reduction", "100% observed traffic preserved", "SEC-2418 linked"] },
  { id: "iac-522", repository: "developer-experience/sandbox", pullRequest: "#522", author: "l.morgan", environment: "Development", proposedChange: "Open TCP/3000–3010 for 14 days", projectedRisk: 47, currentRisk: 42, verdict: "Review", policy: "DEV-04 · Public development access requires expiration", evidence: ["Non-production", "Synthetic data", "Exception expiration supplied"] },
];

export const programTrend = [
  { month: "Feb", internetWide: 64, reachableCritical: 19, overdue: 31, riskRemoved: 8 },
  { month: "Mar", internetWide: 59, reachableCritical: 18, overdue: 27, riskRemoved: 14 },
  { month: "Apr", internetWide: 53, reachableCritical: 15, overdue: 24, riskRemoved: 21 },
  { month: "May", internetWide: 47, reachableCritical: 13, overdue: 19, riskRemoved: 28 },
  { month: "Jun", internetWide: 39, reachableCritical: 10, overdue: 14, riskRemoved: 37 },
  { month: "Jul", internetWide: 34, reachableCritical: 7, overdue: 9, riskRemoved: 46 },
];
