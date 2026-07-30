export type Severity = "critical" | "high" | "medium" | "low";
export type ReviewStatus =
  | "needs-review"
  | "in-review"
  | "approved"
  | "remediate"
  | "exception";

export type SecurityRule = {
  id: string;
  direction: "Ingress" | "Egress";
  protocol: string;
  ports: string;
  source: string;
  sourceLabel: string;
  exposure: "Public" | "Private" | "Referenced";
  finding?: string;
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
  severity: Severity;
  defaultStatus: ReviewStatus;
  lastChanged: string;
  lastReviewed: string;
  changedBy: string;
  findings: string[];
  rules: SecurityRule[];
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
    severity: "critical",
    defaultStatus: "needs-review",
    lastChanged: "18 min ago",
    lastReviewed: "Never",
    changedBy: "terraform-ci@payments",
    findings: ["SSH open to the internet", "Unrestricted outbound access", "Not reviewed"],
    rules: [
      { id: "sgr-8f29", direction: "Ingress", protocol: "TCP", ports: "22", source: "0.0.0.0/0", sourceLabel: "Anywhere IPv4", exposure: "Public", finding: "Administrative port exposed publicly" },
      { id: "sgr-8f30", direction: "Ingress", protocol: "TCP", ports: "443", source: "0.0.0.0/0", sourceLabel: "Anywhere IPv4", exposure: "Public" },
      { id: "sgr-8f31", direction: "Ingress", protocol: "TCP", ports: "8443", source: "sg-02ab19d3", sourceLabel: "prod-public-alb", exposure: "Referenced" },
      { id: "sgr-8f32", direction: "Egress", protocol: "All", ports: "All", source: "0.0.0.0/0", sourceLabel: "Anywhere IPv4", exposure: "Public", finding: "No destination restriction" },
    ],
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
    severity: "critical",
    defaultStatus: "in-review",
    lastChanged: "2 hours ago",
    lastReviewed: "46 days ago",
    changedBy: "alice.chen@example.com",
    findings: ["RDP open to the internet", "Rule modified outside IaC", "Review overdue"],
    rules: [
      { id: "sgr-2c10", direction: "Ingress", protocol: "TCP", ports: "3389", source: "0.0.0.0/0", sourceLabel: "Anywhere IPv4", exposure: "Public", finding: "Remote desktop exposed publicly" },
      { id: "sgr-2c11", direction: "Ingress", protocol: "TCP", ports: "22", source: "198.51.100.0/24", sourceLabel: "Corporate VPN", exposure: "Private" },
      { id: "sgr-2c12", direction: "Ingress", protocol: "TCP", ports: "5985–5986", source: "10.0.0.0/8", sourceLabel: "Internal network", exposure: "Private" },
      { id: "sgr-2c13", direction: "Egress", protocol: "All", ports: "All", source: "0.0.0.0/0", sourceLabel: "Anywhere IPv4", exposure: "Public" },
    ],
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
    publicRules: 1,
    riskScore: 78,
    severity: "high",
    defaultStatus: "needs-review",
    lastChanged: "Yesterday",
    lastReviewed: "92 days ago",
    changedBy: "AWSServiceRoleForRDS",
    findings: ["Database port has broad CIDR", "Review overdue"],
    rules: [
      { id: "sgr-ff11", direction: "Ingress", protocol: "TCP", ports: "5432", source: "10.0.0.0/8", sourceLabel: "All private networks", exposure: "Private", finding: "CIDR is broader than application subnets" },
      { id: "sgr-ff12", direction: "Ingress", protocol: "TCP", ports: "5432", source: "sg-0a41f2e9", sourceLabel: "prod-payments-api", exposure: "Referenced" },
      { id: "sgr-ff13", direction: "Egress", protocol: "TCP", ports: "443", source: "0.0.0.0/0", sourceLabel: "AWS APIs", exposure: "Public" },
    ],
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
    severity: "high",
    defaultStatus: "needs-review",
    lastChanged: "6 days ago",
    lastReviewed: "Never",
    changedBy: "arn:aws:iam::583047112889:user/ops-legacy",
    findings: ["No owner tag", "Unused for 60 days", "All traffic between peers"],
    rules: [
      { id: "sgr-bc82", direction: "Ingress", protocol: "All", ports: "All", source: "sg-022a71c3bafd", sourceLabel: "Self reference", exposure: "Referenced", finding: "Unrestricted lateral traffic" },
      { id: "sgr-bc83", direction: "Ingress", protocol: "TCP", ports: "22", source: "10.44.0.0/16", sourceLabel: "Operations subnet", exposure: "Private" },
      { id: "sgr-bc84", direction: "Egress", protocol: "All", ports: "All", source: "0.0.0.0/0", sourceLabel: "Anywhere IPv4", exposure: "Public" },
    ],
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
    severity: "medium",
    defaultStatus: "remediate",
    lastChanged: "3 days ago",
    lastReviewed: "12 days ago",
    changedBy: "sagemaker.amazonaws.com",
    findings: ["Jupyter port exposed to office CIDR", "Broad S3 egress"],
    rules: [
      { id: "sgr-7a01", direction: "Ingress", protocol: "TCP", ports: "8888", source: "203.0.113.0/24", sourceLabel: "Office network", exposure: "Public", finding: "Public CIDR bypasses private access path" },
      { id: "sgr-7a02", direction: "Ingress", protocol: "TCP", ports: "443", source: "sg-0ff19a22", sourceLabel: "stg-notebook-proxy", exposure: "Referenced" },
      { id: "sgr-7a03", direction: "Egress", protocol: "TCP", ports: "443", source: "0.0.0.0/0", sourceLabel: "HTTPS destinations", exposure: "Public" },
    ],
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
    severity: "low",
    defaultStatus: "approved",
    lastChanged: "8 days ago",
    lastReviewed: "8 days ago",
    changedBy: "terraform-ci@edge",
    findings: ["Public exposure is expected"],
    rules: [
      { id: "sgr-11d1", direction: "Ingress", protocol: "TCP", ports: "443", source: "0.0.0.0/0", sourceLabel: "Anywhere IPv4", exposure: "Public" },
      { id: "sgr-11d2", direction: "Ingress", protocol: "TCP", ports: "443", source: "::/0", sourceLabel: "Anywhere IPv6", exposure: "Public" },
      { id: "sgr-11d3", direction: "Egress", protocol: "TCP", ports: "8443", source: "sg-0a41f2e91b71", sourceLabel: "prod-payments-api", exposure: "Referenced" },
    ],
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
    severity: "medium",
    defaultStatus: "exception",
    lastChanged: "12 days ago",
    lastReviewed: "21 days ago",
    changedBy: "sandbox-provisioner",
    findings: ["Temporary exception expires Aug 12"],
    rules: [
      { id: "sgr-1240", direction: "Ingress", protocol: "TCP", ports: "3000–3999", source: "10.20.0.0/16", sourceLabel: "Developer VPN", exposure: "Private" },
      { id: "sgr-1241", direction: "Egress", protocol: "TCP", ports: "443", source: "0.0.0.0/0", sourceLabel: "HTTPS destinations", exposure: "Public" },
    ],
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
    severity: "low",
    defaultStatus: "approved",
    lastChanged: "28 days ago",
    lastReviewed: "28 days ago",
    changedBy: "terraform-ci@commerce",
    findings: [],
    rules: [
      { id: "sgr-ee09", direction: "Ingress", protocol: "TCP", ports: "6379", source: "sg-07719cc2", sourceLabel: "prod-commerce-api", exposure: "Referenced" },
      { id: "sgr-ee10", direction: "Egress", protocol: "TCP", ports: "443", source: "10.44.12.9/32", sourceLabel: "PrivateLink endpoint", exposure: "Private" },
    ],
  },
];

export const activity = [
  { action: "AuthorizeSecurityGroupIngress", group: "prod-payments-api", actor: "terraform-ci@payments", time: "18 min ago", tone: "critical" },
  { action: "RevokeSecurityGroupIngress", group: "shared-admin-access", actor: "alice.chen@example.com", time: "2 hours ago", tone: "positive" },
  { action: "AuthorizeSecurityGroupEgress", group: "prod-customer-db", actor: "AWSServiceRoleForRDS", time: "Yesterday", tone: "warning" },
  { action: "Review marked approved", group: "prod-public-alb", actor: "Morgan Lee", time: "8 days ago", tone: "positive" },
];

export const weeklyExposure = [22, 20, 24, 19, 17, 18, 15, 14];
export const weeklyLabels = ["Jun 8", "Jun 15", "Jun 22", "Jun 29", "Jul 6", "Jul 13", "Jul 20", "Jul 27"];
