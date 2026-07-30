export type Severity = "critical" | "high" | "medium" | "low";
export type ReviewStatus =
  | "needs-review"
  | "in-review"
  | "approved"
  | "remediate"
  | "exception";

export type RiskFactor = {
  key: string;
  label: string;
  points: number;
  maxPoints: number;
  evidence: string;
};

export type SecurityRule = {
  id: string;
  direction: "Ingress" | "Egress";
  protocol: string;
  ports: string;
  source: string;
  sourceLabel: string;
  exposure: "Public" | "Private" | "Referenced";
  lastObserved: string;
  flows30d: number;
  finding?: string;
};

export type ResourceAttachment = {
  id: string;
  name: string;
  type: "EC2" | "ALB" | "RDS" | "ElastiCache" | "SageMaker" | "Lambda";
  criticality: "Critical" | "High" | "Medium" | "Low";
  publicAddress?: string;
};

export type ConnectivityPath = {
  id: string;
  direction: "Ingress" | "Egress";
  source: string;
  destination: string;
  service: string;
  status: "reachable" | "potential" | "blocked";
  confidence: "High" | "Medium";
  reason: string;
  hops: string[];
};

export type TrafficEvidence = {
  coverage: number;
  accepted30d: number;
  rejected30d: number;
  lastObserved: string;
  topTalkers: { source: string; service: string; flows: number }[];
};

export type RuleIntent = {
  status: "matched" | "broader-than-intent" | "undocumented" | "temporary";
  application: string;
  owner: string;
  approvedAccess: string;
  justification: string;
  ticket: string;
  expiresAt?: string;
};

export type VulnerabilityContext = {
  resource: string;
  cves: number;
  highestSeverity: Severity;
  exploitable: boolean;
  internetReachable: boolean;
  summary: string;
};

export type ChangeEvidence = {
  eventId: string;
  eventName: string;
  actor: string;
  channel: "Terraform" | "Console" | "AWS service" | "Automation";
  time: string;
  sourceIp: string;
  approved: boolean;
  before: string;
  after: string;
};

export type SecurityGroup = {
  id: string;
  name: string;
  accountId: string;
  accountName: string;
  environment: "Production" | "Staging" | "Development" | "Shared";
  region: string;
  vpc: string;
  owner: string;
  service: string;
  description: string;
  inboundCount: number;
  outboundCount: number;
  publicRules: number;
  riskScore: number;
  projectedRisk: number;
  severity: Severity;
  defaultStatus: ReviewStatus;
  lastChanged: string;
  lastReviewed: string;
  changedBy: string;
  findings: string[];
  rules: SecurityRule[];
  attachments: ResourceAttachment[];
  paths: ConnectivityPath[];
  traffic: TrafficEvidence;
  intent: RuleIntent;
  vulnerabilities: VulnerabilityContext[];
  riskFactors: RiskFactor[];
  change: ChangeEvidence;
  recommendation: string;
};

export const securityGroups: SecurityGroup[] = [
  {
    id: "sg-0a41f2e91b71",
    name: "prod-payments-api",
    accountId: "428196730552",
    accountName: "Payments Production",
    environment: "Production",
    region: "us-east-1",
    vpc: "vpc-prod-core",
    owner: "Payments Platform",
    service: "Payments API",
    description: "Load balancer and service access for the card authorization API.",
    inboundCount: 7,
    outboundCount: 2,
    publicRules: 2,
    riskScore: 96,
    projectedRisk: 41,
    severity: "critical",
    defaultStatus: "needs-review",
    lastChanged: "18 min ago",
    lastReviewed: "Never",
    changedBy: "terraform-ci@payments",
    findings: [
      "Public SSH reaches 3 production instances",
      "Deployed access is broader than approved intent",
      "Critical Inspector findings are reachable",
      "No prior recertification",
    ],
    rules: [
      { id: "sgr-8f29", direction: "Ingress", protocol: "TCP", ports: "22", source: "0.0.0.0/0", sourceLabel: "Anywhere IPv4", exposure: "Public", lastObserved: "11 days ago", flows30d: 38, finding: "Administrative port exposed publicly" },
      { id: "sgr-8f30", direction: "Ingress", protocol: "TCP", ports: "443", source: "0.0.0.0/0", sourceLabel: "Anywhere IPv4", exposure: "Public", lastObserved: "2 min ago", flows30d: 284110 },
      { id: "sgr-8f31", direction: "Ingress", protocol: "TCP", ports: "8443", source: "sg-0d3c99118aae", sourceLabel: "prod-public-alb", exposure: "Referenced", lastObserved: "2 min ago", flows30d: 281906 },
      { id: "sgr-8f32", direction: "Egress", protocol: "All", ports: "All", source: "0.0.0.0/0", sourceLabel: "Anywhere IPv4", exposure: "Public", lastObserved: "4 min ago", flows30d: 9132, finding: "No destination restriction" },
    ],
    attachments: [
      { id: "i-02aa9e6f3", name: "payments-api-a", type: "EC2", criticality: "Critical" },
      { id: "i-07cc1b8d2", name: "payments-api-b", type: "EC2", criticality: "Critical" },
      { id: "i-091a04fc8", name: "payments-api-c", type: "EC2", criticality: "Critical" },
    ],
    paths: [
      { id: "path-pay-ssh", direction: "Ingress", source: "Internet", destination: "payments-api-a/b/c", service: "TCP 22", status: "reachable", confidence: "High", reason: "Public route, public addresses, permissive NACL, and SG rule all align.", hops: ["Internet", "igw-prod", "rtb-public-a", "eni-payments ×3", "payments-api"] },
      { id: "path-pay-https", direction: "Ingress", source: "Internet", destination: "prod-public-alb", service: "TCP 443 → 8443", status: "reachable", confidence: "High", reason: "Expected application path matches approved intent.", hops: ["Internet", "prod-public-alb", "sg reference", "payments-api"] },
      { id: "path-pay-egress", direction: "Egress", source: "payments-api", destination: "Internet", service: "All traffic", status: "potential", confidence: "Medium", reason: "SG permits all egress through NAT; destination use varies by workload.", hops: ["payments-api", "nat-prod-a", "igw-prod", "Internet"] },
    ],
    traffic: {
      coverage: 100,
      accepted30d: 293280,
      rejected30d: 1842,
      lastObserved: "2 min ago",
      topTalkers: [
        { source: "prod-public-alb", service: "TCP 8443", flows: 281906 },
        { source: "198.51.100.27", service: "TCP 22", flows: 21 },
        { source: "203.0.113.88", service: "TCP 22", flows: 17 },
      ],
    },
    intent: {
      status: "broader-than-intent",
      application: "Payments API",
      owner: "Payments Platform",
      approvedAccess: "prod-public-alb → TCP 8443; managed endpoints → TCP 443",
      justification: "Public payment authorization through the managed application load balancer.",
      ticket: "PAY-4812",
    },
    vulnerabilities: [
      { resource: "payments-api-a", cves: 3, highestSeverity: "critical", exploitable: true, internetReachable: true, summary: "OpenSSH and glibc findings; TCP 22 is reachable from the internet." },
      { resource: "payments-api-b/c", cves: 4, highestSeverity: "high", exploitable: false, internetReachable: true, summary: "Reachable workload findings without known exploitation." },
    ],
    riskFactors: [
      { key: "reachability", label: "Internet reachability", points: 30, maxPoints: 30, evidence: "Confirmed route to 3 critical EC2 instances on TCP 22." },
      { key: "vulnerability", label: "Vulnerability context", points: 24, maxPoints: 25, evidence: "One reachable critical finding with known exploitability." },
      { key: "intent", label: "Policy drift", points: 20, maxPoints: 20, evidence: "SSH and unrestricted egress are not in PAY-4812." },
      { key: "usage", label: "Observed use", points: 12, maxPoints: 15, evidence: "38 accepted SSH flows in the last 30 days." },
      { key: "governance", label: "Governance", points: 10, maxPoints: 10, evidence: "The group has never been reviewed." },
    ],
    change: {
      eventId: "2c32ee08-9dca-4a90-88f1-8af30a52d202",
      eventName: "AuthorizeSecurityGroupIngress",
      actor: "terraform-ci@payments",
      channel: "Terraform",
      time: "18 min ago",
      sourceIp: "10.8.14.22",
      approved: false,
      before: "TCP 22 from 10.8.0.0/16",
      after: "TCP 22 from 0.0.0.0/0",
    },
    recommendation: "Restore SSH to the managed operations prefix list and restrict egress to approved VPC endpoints and HTTPS destinations.",
  },
  {
    id: "sg-04bc18a21e7d",
    name: "shared-admin-access",
    accountId: "718345229104",
    accountName: "Shared Services",
    environment: "Shared",
    region: "us-east-1",
    vpc: "vpc-shared-services",
    owner: "Cloud Operations",
    service: "Operations access",
    description: "Administrative access paths used by the central operations team.",
    inboundCount: 12,
    outboundCount: 1,
    publicRules: 3,
    riskScore: 89,
    projectedRisk: 36,
    severity: "critical",
    defaultStatus: "in-review",
    lastChanged: "2 hours ago",
    lastReviewed: "46 days ago",
    changedBy: "alice.chen@example.com",
    findings: ["Public RDP reaches a bastion host", "Rule modified outside IaC", "Recertification is overdue"],
    rules: [
      { id: "sgr-2c10", direction: "Ingress", protocol: "TCP", ports: "3389", source: "0.0.0.0/0", sourceLabel: "Anywhere IPv4", exposure: "Public", lastObserved: "Never", flows30d: 0, finding: "Remote desktop exposed publicly" },
      { id: "sgr-2c11", direction: "Ingress", protocol: "TCP", ports: "22", source: "pl-0f921-vpn", sourceLabel: "Corporate VPN prefix list", exposure: "Private", lastObserved: "16 min ago", flows30d: 1204 },
      { id: "sgr-2c12", direction: "Ingress", protocol: "TCP", ports: "5985–5986", source: "10.0.0.0/8", sourceLabel: "Internal network", exposure: "Private", lastObserved: "8 days ago", flows30d: 84 },
      { id: "sgr-2c13", direction: "Egress", protocol: "TCP", ports: "443", source: "0.0.0.0/0", sourceLabel: "HTTPS destinations", exposure: "Public", lastObserved: "19 min ago", flows30d: 1832 },
    ],
    attachments: [
      { id: "i-0bb82ca3", name: "shared-bastion-01", type: "EC2", criticality: "High", publicAddress: "198.51.100.44" },
    ],
    paths: [
      { id: "path-admin-rdp", direction: "Ingress", source: "Internet", destination: "shared-bastion-01", service: "TCP 3389", status: "reachable", confidence: "High", reason: "The bastion has a public address and a default route through igw-shared.", hops: ["Internet", "igw-shared", "rtb-shared-public", "eni-bastion", "shared-bastion-01"] },
      { id: "path-admin-ssh", direction: "Ingress", source: "Corporate VPN", destination: "shared-bastion-01", service: "TCP 22", status: "reachable", confidence: "High", reason: "Approved operations path through Transit Gateway.", hops: ["Corporate VPN", "tgw-core", "shared-bastion-01"] },
    ],
    traffic: {
      coverage: 100,
      accepted30d: 3120,
      rejected30d: 42411,
      lastObserved: "16 min ago",
      topTalkers: [
        { source: "Corporate VPN", service: "TCP 22", flows: 1204 },
        { source: "10.31.8.0/24", service: "TCP 5985", flows: 84 },
      ],
    },
    intent: {
      status: "undocumented",
      application: "Shared administration",
      owner: "Cloud Operations",
      approvedAccess: "Corporate VPN → TCP 22; admin zone → WinRM",
      justification: "Central access for break-glass and fleet operations.",
      ticket: "OPS-773",
    },
    vulnerabilities: [
      { resource: "shared-bastion-01", cves: 2, highestSeverity: "high", exploitable: false, internetReachable: true, summary: "Publicly reachable host with two high-severity package findings." },
    ],
    riskFactors: [
      { key: "reachability", label: "Internet reachability", points: 30, maxPoints: 30, evidence: "Confirmed public route to TCP 3389." },
      { key: "vulnerability", label: "Vulnerability context", points: 18, maxPoints: 25, evidence: "Two high findings on the reachable bastion." },
      { key: "intent", label: "Policy drift", points: 20, maxPoints: 20, evidence: "RDP is not part of the approved access model." },
      { key: "usage", label: "Observed use", points: 11, maxPoints: 15, evidence: "No accepted RDP flows were observed in 30 days." },
      { key: "governance", label: "Governance", points: 10, maxPoints: 10, evidence: "Console change and overdue review increase uncertainty." },
    ],
    change: {
      eventId: "7120b1fe-ef01-42ae-9b55-3df68f31fe3a",
      eventName: "AuthorizeSecurityGroupIngress",
      actor: "alice.chen@example.com",
      channel: "Console",
      time: "2 hours ago",
      sourceIp: "203.0.113.17",
      approved: false,
      before: "No RDP rule",
      after: "TCP 3389 from 0.0.0.0/0",
    },
    recommendation: "Remove the unused RDP rule and preserve the VPN-to-SSH path as the approved administrative route.",
  },
  {
    id: "sg-09dd82c742ad",
    name: "prod-customer-db",
    accountId: "428196730552",
    accountName: "Payments Production",
    environment: "Production",
    region: "us-west-2",
    vpc: "vpc-prod-data",
    owner: "Data Reliability",
    service: "Customer database",
    description: "PostgreSQL access for the production customer profile cluster.",
    inboundCount: 5,
    outboundCount: 1,
    publicRules: 0,
    riskScore: 78,
    projectedRisk: 43,
    severity: "high",
    defaultStatus: "needs-review",
    lastChanged: "Yesterday",
    lastReviewed: "92 days ago",
    changedBy: "AWSServiceRoleForRDS",
    findings: ["Database access spans the entire private address space", "Reachable from 41 unintended workloads", "Review is overdue"],
    rules: [
      { id: "sgr-ff11", direction: "Ingress", protocol: "TCP", ports: "5432", source: "10.0.0.0/8", sourceLabel: "All private networks", exposure: "Private", lastObserved: "Yesterday", flows30d: 19221, finding: "CIDR is broader than application subnets" },
      { id: "sgr-ff12", direction: "Ingress", protocol: "TCP", ports: "5432", source: "sg-0a41f2e91b71", sourceLabel: "prod-payments-api", exposure: "Referenced", lastObserved: "4 min ago", flows30d: 180441 },
      { id: "sgr-ff13", direction: "Egress", protocol: "TCP", ports: "443", source: "pl-aws-services", sourceLabel: "AWS managed services", exposure: "Private", lastObserved: "Yesterday", flows30d: 220 },
    ],
    attachments: [
      { id: "db-customer-primary", name: "customer-profile-primary", type: "RDS", criticality: "Critical" },
      { id: "db-customer-reader", name: "customer-profile-reader", type: "RDS", criticality: "Critical" },
    ],
    paths: [
      { id: "path-db-app", direction: "Ingress", source: "prod-payments-api", destination: "customer-profile cluster", service: "TCP 5432", status: "reachable", confidence: "High", reason: "Expected SG-to-SG application path.", hops: ["payments-api", "sg reference", "customer-profile"] },
      { id: "path-db-broad", direction: "Ingress", source: "41 private workloads", destination: "customer-profile cluster", service: "TCP 5432", status: "potential", confidence: "High", reason: "10.0.0.0/8 overlaps routed application, analytics, and shared-services networks.", hops: ["Routed private networks", "tgw-core", "vpc-prod-data", "customer-profile"] },
    ],
    traffic: {
      coverage: 96,
      accepted30d: 199882,
      rejected30d: 2230,
      lastObserved: "4 min ago",
      topTalkers: [
        { source: "prod-payments-api", service: "TCP 5432", flows: 180441 },
        { source: "analytics-etl", service: "TCP 5432", flows: 19221 },
      ],
    },
    intent: {
      status: "broader-than-intent",
      application: "Customer Profile",
      owner: "Data Reliability",
      approvedAccess: "prod-payments-api and analytics-etl → TCP 5432",
      justification: "Application queries and approved overnight analytics extraction.",
      ticket: "DATA-2201",
    },
    vulnerabilities: [
      { resource: "customer-profile cluster", cves: 1, highestSeverity: "medium", exploitable: false, internetReachable: false, summary: "One medium engine finding; private reachability is broader than necessary." },
    ],
    riskFactors: [
      { key: "reachability", label: "Private blast radius", points: 25, maxPoints: 30, evidence: "41 unintended workloads can potentially reach PostgreSQL." },
      { key: "vulnerability", label: "Vulnerability context", points: 10, maxPoints: 25, evidence: "One medium database finding." },
      { key: "intent", label: "Policy drift", points: 20, maxPoints: 20, evidence: "10.0.0.0/8 exceeds the two approved consumers." },
      { key: "usage", label: "Observed use", points: 13, maxPoints: 15, evidence: "Two legitimate talkers account for current traffic." },
      { key: "governance", label: "Governance", points: 10, maxPoints: 10, evidence: "The 90-day recertification is overdue." },
    ],
    change: {
      eventId: "dd140ab0-8fd9-4ab7-8015-bd4b2fc21117",
      eventName: "AuthorizeSecurityGroupIngress",
      actor: "AWSServiceRoleForRDS",
      channel: "AWS service",
      time: "Yesterday",
      sourceIp: "rds.amazonaws.com",
      approved: true,
      before: "TCP 5432 from prod-payments-api",
      after: "TCP 5432 from prod-payments-api and 10.0.0.0/8",
    },
    recommendation: "Replace 10.0.0.0/8 with security-group references for payments and analytics workloads.",
  },
  {
    id: "sg-022a71c3bafd",
    name: "legacy-order-workers",
    accountId: "583047112889",
    accountName: "Commerce Production",
    environment: "Production",
    region: "eu-west-1",
    vpc: "vpc-commerce",
    owner: "Unassigned",
    service: "Legacy order processing",
    description: "Worker fleet access for the legacy order processing application.",
    inboundCount: 9,
    outboundCount: 4,
    publicRules: 1,
    riskScore: 73,
    projectedRisk: 29,
    severity: "high",
    defaultStatus: "needs-review",
    lastChanged: "6 days ago",
    lastReviewed: "Never",
    changedBy: "arn:aws:iam::583047112889:user/ops-legacy",
    findings: ["No accountable owner", "All-protocol lateral access", "No observed ingress for 60 days", "Unrestricted internet egress"],
    rules: [
      { id: "sgr-bc82", direction: "Ingress", protocol: "All", ports: "All", source: "sg-022a71c3bafd", sourceLabel: "Self reference", exposure: "Referenced", lastObserved: "63 days ago", flows30d: 0, finding: "Unrestricted lateral traffic" },
      { id: "sgr-bc83", direction: "Ingress", protocol: "TCP", ports: "22", source: "10.44.0.0/16", sourceLabel: "Operations subnet", exposure: "Private", lastObserved: "67 days ago", flows30d: 0 },
      { id: "sgr-bc84", direction: "Egress", protocol: "All", ports: "All", source: "0.0.0.0/0", sourceLabel: "Anywhere IPv4", exposure: "Public", lastObserved: "62 days ago", flows30d: 0, finding: "No destination restriction" },
    ],
    attachments: [
      { id: "i-legacy-01", name: "order-worker-01", type: "EC2", criticality: "Medium" },
      { id: "i-legacy-02", name: "order-worker-02", type: "EC2", criticality: "Medium" },
    ],
    paths: [
      { id: "path-legacy-lateral", direction: "Ingress", source: "order-worker peers", destination: "order-worker fleet", service: "All traffic", status: "potential", confidence: "Medium", reason: "Self-reference permits lateral traffic, but no flows were observed in the covered period.", hops: ["order-worker peers", "self-referencing SG", "order-worker fleet"] },
      { id: "path-legacy-egress", direction: "Egress", source: "order-worker fleet", destination: "Internet", service: "All traffic", status: "potential", confidence: "Medium", reason: "A NAT route exists; no recent flows were observed.", hops: ["order-worker fleet", "nat-commerce", "Internet"] },
    ],
    traffic: {
      coverage: 92,
      accepted30d: 0,
      rejected30d: 12,
      lastObserved: "62 days ago",
      topTalkers: [],
    },
    intent: {
      status: "undocumented",
      application: "Legacy Order Processing",
      owner: "Unassigned",
      approvedAccess: "No current access manifest",
      justification: "Original deployment predates centralized change records.",
      ticket: "None",
    },
    vulnerabilities: [
      { resource: "order-worker fleet", cves: 7, highestSeverity: "high", exploitable: true, internetReachable: false, summary: "Dormant instances include exploitable packages and retain outbound access." },
    ],
    riskFactors: [
      { key: "reachability", label: "Lateral reachability", points: 15, maxPoints: 30, evidence: "All-protocol self-reference is present." },
      { key: "vulnerability", label: "Vulnerability context", points: 22, maxPoints: 25, evidence: "Seven findings, including an exploitable high." },
      { key: "intent", label: "Unknown intent", points: 18, maxPoints: 20, evidence: "No manifest, ticket, or accountable owner." },
      { key: "usage", label: "Observed use", points: 8, maxPoints: 15, evidence: "No accepted flows in the last 60 days." },
      { key: "governance", label: "Governance", points: 10, maxPoints: 10, evidence: "The group has never been reviewed." },
    ],
    change: {
      eventId: "9fb05be4-2c68-49e8-89d8-5a19e2a6a7c4",
      eventName: "ModifySecurityGroupRules",
      actor: "ops-legacy",
      channel: "Console",
      time: "6 days ago",
      sourceIp: "198.51.100.18",
      approved: false,
      before: "Self-reference TCP 8080",
      after: "Self-reference all protocols and ports",
    },
    recommendation: "Confirm decommissioning with Commerce, then remove the group and detach its dormant instances through the normal change process.",
  },
  {
    id: "sg-087ad315301f",
    name: "stg-analytics-notebooks",
    accountId: "912883407601",
    accountName: "Data Platform",
    environment: "Staging",
    region: "us-east-2",
    vpc: "vpc-analytics-stg",
    owner: "Analytics Engineering",
    service: "Notebook workspaces",
    description: "Interactive staging notebooks for analytics development.",
    inboundCount: 4,
    outboundCount: 3,
    publicRules: 1,
    riskScore: 61,
    projectedRisk: 34,
    severity: "medium",
    defaultStatus: "remediate",
    lastChanged: "3 days ago",
    lastReviewed: "12 days ago",
    changedBy: "sagemaker.amazonaws.com",
    findings: ["Public office CIDR bypasses the private access path", "Broad S3 and internet egress"],
    rules: [
      { id: "sgr-7a01", direction: "Ingress", protocol: "TCP", ports: "8888", source: "203.0.113.0/24", sourceLabel: "Office network", exposure: "Public", lastObserved: "3 days ago", flows30d: 43, finding: "Public CIDR bypasses private access path" },
      { id: "sgr-7a02", direction: "Ingress", protocol: "TCP", ports: "443", source: "sg-0ff19a22", sourceLabel: "stg-notebook-proxy", exposure: "Referenced", lastObserved: "5 hours ago", flows30d: 4102 },
      { id: "sgr-7a03", direction: "Egress", protocol: "TCP", ports: "443", source: "0.0.0.0/0", sourceLabel: "HTTPS destinations", exposure: "Public", lastObserved: "1 hour ago", flows30d: 10912 },
    ],
    attachments: [
      { id: "sm-nb-01", name: "fraud-research-notebook", type: "SageMaker", criticality: "Medium" },
    ],
    paths: [
      { id: "path-nb-office", direction: "Ingress", source: "Office network", destination: "fraud-research-notebook", service: "TCP 8888", status: "potential", confidence: "Medium", reason: "Public CIDR and route align; the notebook endpoint is not directly assigned a public IP.", hops: ["Office network", "igw-analytics", "notebook endpoint"] },
      { id: "path-nb-proxy", direction: "Ingress", source: "stg-notebook-proxy", destination: "fraud-research-notebook", service: "TCP 443", status: "reachable", confidence: "High", reason: "Expected private proxy path.", hops: ["Developer VPN", "notebook proxy", "sg reference", "notebook"] },
    ],
    traffic: {
      coverage: 88,
      accepted30d: 15057,
      rejected30d: 904,
      lastObserved: "1 hour ago",
      topTalkers: [
        { source: "stg-notebook-proxy", service: "TCP 443", flows: 4102 },
        { source: "Office network", service: "TCP 8888", flows: 43 },
      ],
    },
    intent: {
      status: "temporary",
      application: "Analytics Workbench",
      owner: "Analytics Engineering",
      approvedAccess: "Developer VPN → notebook proxy → TCP 443",
      justification: "Temporary office access during proxy certificate migration.",
      ticket: "DATA-3018",
      expiresAt: "2026-08-12",
    },
    vulnerabilities: [],
    riskFactors: [
      { key: "reachability", label: "Potential public path", points: 18, maxPoints: 30, evidence: "Office CIDR can reach the notebook endpoint path." },
      { key: "vulnerability", label: "Vulnerability context", points: 0, maxPoints: 25, evidence: "No active Inspector findings." },
      { key: "intent", label: "Temporary exception", points: 14, maxPoints: 20, evidence: "The office access exception expires Aug 12." },
      { key: "usage", label: "Observed use", points: 9, maxPoints: 15, evidence: "43 direct notebook flows in 30 days." },
      { key: "governance", label: "Governance", points: 8, maxPoints: 10, evidence: "A remediation decision is already recorded." },
    ],
    change: {
      eventId: "1c0e6fb9-8595-40af-8370-54291d43d4c8",
      eventName: "AuthorizeSecurityGroupIngress",
      actor: "sagemaker.amazonaws.com",
      channel: "AWS service",
      time: "3 days ago",
      sourceIp: "sagemaker.amazonaws.com",
      approved: true,
      before: "Proxy-only TCP 443",
      after: "Proxy TCP 443 and office TCP 8888",
    },
    recommendation: "Remove the direct notebook rule when DATA-3018 expires and route all sessions through the private proxy.",
  },
  {
    id: "sg-0d3c99118aae",
    name: "prod-public-alb",
    accountId: "428196730552",
    accountName: "Payments Production",
    environment: "Production",
    region: "us-east-1",
    vpc: "vpc-prod-core",
    owner: "Edge Platform",
    service: "Public load balancer",
    description: "Public HTTPS entry point for production payment services.",
    inboundCount: 3,
    outboundCount: 4,
    publicRules: 2,
    riskScore: 38,
    projectedRisk: 34,
    severity: "low",
    defaultStatus: "approved",
    lastChanged: "8 days ago",
    lastReviewed: "8 days ago",
    changedBy: "terraform-ci@edge",
    findings: ["Expected public exposure; monitoring remains enabled"],
    rules: [
      { id: "sgr-11d1", direction: "Ingress", protocol: "TCP", ports: "443", source: "0.0.0.0/0", sourceLabel: "Anywhere IPv4", exposure: "Public", lastObserved: "1 min ago", flows30d: 884103 },
      { id: "sgr-11d2", direction: "Ingress", protocol: "TCP", ports: "443", source: "::/0", sourceLabel: "Anywhere IPv6", exposure: "Public", lastObserved: "4 min ago", flows30d: 99381 },
      { id: "sgr-11d3", direction: "Egress", protocol: "TCP", ports: "8443", source: "sg-0a41f2e91b71", sourceLabel: "prod-payments-api", exposure: "Referenced", lastObserved: "2 min ago", flows30d: 281906 },
    ],
    attachments: [
      { id: "alb-payments", name: "prod-payments-alb", type: "ALB", criticality: "High", publicAddress: "dualstack.payments.example.com" },
    ],
    paths: [
      { id: "path-alb-public", direction: "Ingress", source: "Internet", destination: "prod-payments-alb", service: "TCP 443", status: "reachable", confidence: "High", reason: "Approved public entry point with WAF and TLS policy.", hops: ["Internet", "AWS WAF", "prod-payments-alb"] },
      { id: "path-alb-api", direction: "Egress", source: "prod-payments-alb", destination: "prod-payments-api", service: "TCP 8443", status: "reachable", confidence: "High", reason: "Approved SG reference to the application tier.", hops: ["prod-payments-alb", "sg reference", "prod-payments-api"] },
    ],
    traffic: {
      coverage: 100,
      accepted30d: 1269202,
      rejected30d: 381108,
      lastObserved: "1 min ago",
      topTalkers: [
        { source: "CloudFront edge", service: "TCP 443", flows: 841301 },
        { source: "Direct clients", service: "TCP 443", flows: 142183 },
      ],
    },
    intent: {
      status: "matched",
      application: "Payments Edge",
      owner: "Edge Platform",
      approvedAccess: "Internet → TCP 443; ALB → payments API TCP 8443",
      justification: "Public TLS entry point protected by AWS WAF.",
      ticket: "EDGE-1198",
    },
    vulnerabilities: [],
    riskFactors: [
      { key: "reachability", label: "Expected public exposure", points: 18, maxPoints: 30, evidence: "Internet reachability is intentional and WAF-protected." },
      { key: "vulnerability", label: "Vulnerability context", points: 0, maxPoints: 25, evidence: "No directly attached compute findings." },
      { key: "intent", label: "Policy alignment", points: 0, maxPoints: 20, evidence: "Actual and approved access match." },
      { key: "usage", label: "Observed use", points: 10, maxPoints: 15, evidence: "Expected high-volume production traffic." },
      { key: "governance", label: "Governance", points: 10, maxPoints: 10, evidence: "Approved eight days ago; continuous monitoring retained." },
    ],
    change: {
      eventId: "71c4c7aa-743f-472a-8567-a295f90c13de",
      eventName: "ModifySecurityGroupRules",
      actor: "terraform-ci@edge",
      channel: "Terraform",
      time: "8 days ago",
      sourceIp: "10.8.10.11",
      approved: true,
      before: "IPv4 TCP 443",
      after: "IPv4 and IPv6 TCP 443",
    },
    recommendation: "No access change recommended. Continue WAF monitoring and quarterly recertification.",
  },
  {
    id: "sg-0611a2fb089c",
    name: "dev-integration-sandbox",
    accountId: "100293744720",
    accountName: "Engineering Sandbox",
    environment: "Development",
    region: "us-west-2",
    vpc: "vpc-dev-sandbox",
    owner: "Developer Experience",
    service: "Integration testing",
    description: "Ephemeral integration services for developer testing.",
    inboundCount: 8,
    outboundCount: 2,
    publicRules: 0,
    riskScore: 42,
    projectedRisk: 24,
    severity: "medium",
    defaultStatus: "exception",
    lastChanged: "12 days ago",
    lastReviewed: "21 days ago",
    changedBy: "sandbox-provisioner",
    findings: ["Temporary high-port exception expires Aug 12"],
    rules: [
      { id: "sgr-1240", direction: "Ingress", protocol: "TCP", ports: "3000–3999", source: "10.20.0.0/16", sourceLabel: "Developer VPN", exposure: "Private", lastObserved: "Yesterday", flows30d: 901, finding: "Temporary broad port range" },
      { id: "sgr-1241", direction: "Egress", protocol: "TCP", ports: "443", source: "0.0.0.0/0", sourceLabel: "HTTPS destinations", exposure: "Public", lastObserved: "Yesterday", flows30d: 3301 },
    ],
    attachments: [
      { id: "fn-integration-hub", name: "integration-hub", type: "Lambda", criticality: "Low" },
    ],
    paths: [
      { id: "path-dev-vpn", direction: "Ingress", source: "Developer VPN", destination: "integration-hub", service: "TCP 3000–3999", status: "reachable", confidence: "High", reason: "Temporary private test path.", hops: ["Developer VPN", "tgw-dev", "integration-hub"] },
    ],
    traffic: {
      coverage: 81,
      accepted30d: 4202,
      rejected30d: 83,
      lastObserved: "Yesterday",
      topTalkers: [
        { source: "Developer VPN", service: "TCP 3000–3999", flows: 901 },
      ],
    },
    intent: {
      status: "temporary",
      application: "Integration Sandbox",
      owner: "Developer Experience",
      approvedAccess: "Developer VPN → TCP 3000–3999",
      justification: "Temporary compatibility testing across ephemeral service ports.",
      ticket: "DX-842",
      expiresAt: "2026-08-12",
    },
    vulnerabilities: [],
    riskFactors: [
      { key: "reachability", label: "Private reachability", points: 8, maxPoints: 30, evidence: "Restricted to the developer VPN." },
      { key: "vulnerability", label: "Vulnerability context", points: 0, maxPoints: 25, evidence: "No active Inspector findings." },
      { key: "intent", label: "Temporary exception", points: 12, maxPoints: 20, evidence: "Broad port range expires Aug 12." },
      { key: "usage", label: "Observed use", points: 12, maxPoints: 15, evidence: "901 accepted test flows in 30 days." },
      { key: "governance", label: "Governance", points: 10, maxPoints: 10, evidence: "Documented exception is approaching expiry." },
    ],
    change: {
      eventId: "9ee8a87d-4b9f-47db-96fe-7a9ce48b65d6",
      eventName: "CreateSecurityGroup",
      actor: "sandbox-provisioner",
      channel: "Automation",
      time: "12 days ago",
      sourceIp: "10.20.2.19",
      approved: true,
      before: "No security group",
      after: "Developer VPN TCP 3000–3999",
    },
    recommendation: "Allow the exception to expire, then replace the port range with the specific services observed during testing.",
  },
  {
    id: "sg-0b471ea290c4",
    name: "prod-cache-cluster",
    accountId: "583047112889",
    accountName: "Commerce Production",
    environment: "Production",
    region: "eu-west-1",
    vpc: "vpc-commerce",
    owner: "Commerce Runtime",
    service: "Redis cache",
    description: "Application access to the primary commerce Redis cluster.",
    inboundCount: 2,
    outboundCount: 1,
    publicRules: 0,
    riskScore: 26,
    projectedRisk: 22,
    severity: "low",
    defaultStatus: "approved",
    lastChanged: "28 days ago",
    lastReviewed: "28 days ago",
    changedBy: "terraform-ci@commerce",
    findings: [],
    rules: [
      { id: "sgr-ee09", direction: "Ingress", protocol: "TCP", ports: "6379", source: "sg-07719cc2", sourceLabel: "prod-commerce-api", exposure: "Referenced", lastObserved: "3 min ago", flows30d: 441901 },
      { id: "sgr-ee10", direction: "Egress", protocol: "TCP", ports: "443", source: "10.44.12.9/32", sourceLabel: "PrivateLink endpoint", exposure: "Private", lastObserved: "2 days ago", flows30d: 141 },
    ],
    attachments: [
      { id: "cache-primary", name: "commerce-redis-primary", type: "ElastiCache", criticality: "High" },
    ],
    paths: [
      { id: "path-cache-api", direction: "Ingress", source: "prod-commerce-api", destination: "commerce-redis-primary", service: "TCP 6379", status: "reachable", confidence: "High", reason: "Expected SG reference; no broader route is allowed.", hops: ["prod-commerce-api", "sg reference", "commerce-redis-primary"] },
    ],
    traffic: {
      coverage: 100,
      accepted30d: 442042,
      rejected30d: 17,
      lastObserved: "3 min ago",
      topTalkers: [
        { source: "prod-commerce-api", service: "TCP 6379", flows: 441901 },
      ],
    },
    intent: {
      status: "matched",
      application: "Commerce Runtime",
      owner: "Commerce Runtime",
      approvedAccess: "prod-commerce-api → TCP 6379",
      justification: "Application session and catalog cache.",
      ticket: "COM-1802",
    },
    vulnerabilities: [],
    riskFactors: [
      { key: "reachability", label: "Private reachability", points: 8, maxPoints: 30, evidence: "Only the commerce API SG can reach Redis." },
      { key: "vulnerability", label: "Vulnerability context", points: 0, maxPoints: 25, evidence: "No active vulnerability findings." },
      { key: "intent", label: "Policy alignment", points: 0, maxPoints: 20, evidence: "Actual access matches COM-1802." },
      { key: "usage", label: "Observed use", points: 8, maxPoints: 15, evidence: "Traffic is active and attributable to the intended consumer." },
      { key: "governance", label: "Governance", points: 10, maxPoints: 10, evidence: "Approved 28 days ago." },
    ],
    change: {
      eventId: "72ae2bb3-177d-4c04-9de0-22cb06b490fb",
      eventName: "ModifySecurityGroupRules",
      actor: "terraform-ci@commerce",
      channel: "Terraform",
      time: "28 days ago",
      sourceIp: "10.44.2.14",
      approved: true,
      before: "Commerce subnet TCP 6379",
      after: "Commerce API SG TCP 6379",
    },
    recommendation: "No immediate change recommended. Retain the SG reference and scheduled recertification.",
  },
];

export const activity = securityGroups
  .map((group) => ({
    ...group.change,
    group: group.name,
    groupId: group.id,
    tone: group.change.approved
      ? ("positive" as const)
      : group.severity === "critical"
        ? ("critical" as const)
        : ("warning" as const),
  }))
  .sort((a, b) => Number(a.approved) - Number(b.approved));

export const weeklyExposure = [22, 20, 24, 19, 17, 18, 15, 14];
export const weeklyLabels = ["Jun 8", "Jun 15", "Jun 22", "Jun 29", "Jul 6", "Jul 13", "Jul 20", "Jul 27"];

export const policyChecks = [
  "Public administrative access",
  "Unrestricted ingress or egress",
  "IPv6 public exposure",
  "Broad private CIDR",
  "Stale security-group reference",
  "Missing accountable owner",
  "Expired exception",
  "Overdue recertification",
  "Out-of-workflow change",
  "Actual access exceeds intent",
  "Unused rule candidate",
  "Reachable vulnerability",
];
