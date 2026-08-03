import type { Severity } from "./security-data";

export type AccessScope = {
  id: string;
  name: string;
  description: string;
  owner: string;
  version: number;
  status: "active" | "draft" | "attention";
  destination: string;
  allowedSources: string[];
  deniedConditions: string[];
  services: string[];
  findings: number;
  lastEvaluated: string;
  yaml: string;
};

export type ApplicationRecord = {
  id: string;
  name: string;
  description: string;
  owner: string;
  technicalOwner: string;
  repository: string;
  environment: "Production" | "Staging" | "Development" | "Shared";
  tier: "Crown jewel" | "Business critical" | "Important" | "Standard";
  dataClassification: "Restricted" | "Confidential" | "Internal";
  compliance: string[];
  securityGroupIds: string[];
  dependencies: { name: string; service: string; authorized: boolean }[];
  riskScore: number;
  reachablePaths: number;
  protection: number;
  tags: string[];
};

export type RemediationAction = {
  id: string;
  title: string;
  securityGroupId: string;
  application: string;
  severity: Severity;
  confidence: "High" | "Medium";
  pathsBroken: number;
  assetsProtected: number;
  legitimateFlowsPreserved: number;
  currentRisk: number;
  projectedRisk: number;
  effort: "Low" | "Medium";
  change: string;
  rationale: string;
  safeguards: string[];
  artifact: string;
};

export type Campaign = {
  id: string;
  name: string;
  description: string;
  owner: string;
  dueDate: string;
  status: "active" | "scheduled" | "complete";
  scope: string;
  total: number;
  completed: number;
  escalations: number;
  evidenceCoverage: number;
  reviewers: { name: string; team: string; assigned: number; complete: number }[];
};

export type ConnectivityEvent = {
  id: string;
  date: string;
  time: string;
  groupId: string;
  application: string;
  actor: string;
  channel: string;
  title: string;
  summary: string;
  pathsBefore: number;
  pathsAfter: number;
  riskBefore: number;
  riskAfter: number;
  authorization: "Approved" | "Not found" | "Expired";
  ticket: string;
};

export type AwsHandoff = {
  id: string;
  name: string;
  category: "Analyze" | "Enforce" | "Publish" | "Change";
  description: string;
  mode: "Read only" | "Approval required";
  readiness: "Ready" | "Needs configuration";
  output: string;
  prerequisites: string[];
};

export const accessScopes: AccessScope[] = [
  {
    id: "scope-prod-database",
    name: "Production database boundary",
    description:
      "Only approved production application tiers may reach restricted databases.",
    owner: "Cloud Security",
    version: 7,
    status: "attention",
    destination: "Environment=Production, DataClassification=Restricted",
    allowedSources: ["Application tier", "Database operations"],
    deniedConditions: ["Internet gateway in path", "Environment=Development"],
    services: ["TCP 5432", "TCP 3306"],
    findings: 2,
    lastEvaluated: "4 min ago",
    yaml: `name: production-database-boundary
destination:
  tags:
    Environment: production
    DataClassification: restricted
services:
  - tcp/5432
  - tcp/3306
allowed_sources:
  - role: application-tier
  - team: database-operations
denied_paths:
  - internet_gateway: true
  - source_environment: development
owner: cloud-security
review_period_days: 90`,
  },
  {
    id: "scope-public-management",
    name: "No public management access",
    description:
      "Administrative ports must terminate on managed access services, never public IP space.",
    owner: "Cloud Operations",
    version: 12,
    status: "attention",
    destination: "All managed compute",
    allowedSources: ["AWS Systems Manager", "Operations prefix list"],
    deniedConditions: ["0.0.0.0/0", "::/0", "Internet gateway in path"],
    services: ["TCP 22", "TCP 3389", "TCP 5985–5986"],
    findings: 3,
    lastEvaluated: "4 min ago",
    yaml: `name: no-public-management-access
destination:
  resource_types: [ec2, rds, redshift]
services:
  - tcp/22
  - tcp/3389
  - tcp/5985-5986
allowed_sources:
  - aws_service: systems-manager
  - prefix_list: operations-managed
denied_sources:
  - 0.0.0.0/0
  - ::/0
owner: cloud-operations`,
  },
  {
    id: "scope-prod-egress",
    name: "Production egress allowlist",
    description:
      "Production workloads use approved endpoints and explicit HTTPS destinations.",
    owner: "Platform Engineering",
    version: 4,
    status: "draft",
    destination: "Environment=Production",
    allowedSources: ["Approved VPC endpoints", "HTTPS proxy"],
    deniedConditions: ["All protocols to 0.0.0.0/0"],
    services: ["TCP 443", "DNS via resolver"],
    findings: 4,
    lastEvaluated: "Draft preview",
    yaml: `name: production-egress-allowlist
source:
  tags:
    Environment: production
allowed_destinations:
  - resource: approved-vpc-endpoints
  - service: https-egress-proxy
denied_access:
  protocol: all
  destination: 0.0.0.0/0
owner: platform-engineering
mode: preview`,
  },
  {
    id: "scope-environment-separation",
    name: "Development to production separation",
    description:
      "Development resources cannot initiate connections to production applications.",
    owner: "Security Architecture",
    version: 9,
    status: "active",
    destination: "Environment=Production",
    allowedSources: ["Environment=Production", "Shared approved services"],
    deniedConditions: ["Environment=Development"],
    services: ["All"],
    findings: 0,
    lastEvaluated: "4 min ago",
    yaml: `name: development-production-separation
destination:
  tags:
    Environment: production
exclude_sources:
  tags:
    Environment: development
allowed_sources:
  - environment: production
  - tag:
      SharedServiceApproved: "true"
services: [all]
owner: security-architecture`,
  },
];

export const applications: ApplicationRecord[] = [
  {
    id: "app-payments",
    name: "Payments Platform",
    description:
      "Card authorization, payment capture, and restricted transaction processing.",
    owner: "Avery Chen",
    technicalOwner: "Payments Platform",
    repository: "github.com/acme/payments-platform",
    environment: "Production",
    tier: "Crown jewel",
    dataClassification: "Restricted",
    compliance: ["PCI DSS", "SOX"],
    securityGroupIds: ["sg-0a41f2e91b71", "sg-0d3c99118aae"],
    dependencies: [
      { name: "Payments Edge", service: "TCP 8443", authorized: true },
      { name: "Aurora ledger", service: "TCP 5432", authorized: true },
      { name: "Internet egress", service: "All traffic", authorized: false },
    ],
    riskScore: 96,
    reachablePaths: 4,
    protection: 62,
    tags: ["Application=Payments", "DataClassification=Restricted", "Tier=0"],
  },
  {
    id: "app-customer-data",
    name: "Customer Data Platform",
    description:
      "Customer profile storage and enrichment used by support and marketing systems.",
    owner: "Priya Nair",
    technicalOwner: "Data Platform",
    repository: "github.com/acme/customer-data",
    environment: "Production",
    tier: "Business critical",
    dataClassification: "Confidential",
    compliance: ["SOC 2", "CCPA"],
    securityGroupIds: ["sg-08ee42b1ca70"],
    dependencies: [
      { name: "Customer API", service: "TCP 5432", authorized: true },
      { name: "Shared administration", service: "TCP 22", authorized: false },
    ],
    riskScore: 84,
    reachablePaths: 2,
    protection: 71,
    tags: ["Application=CustomerData", "DataClassification=Confidential"],
  },
  {
    id: "app-analytics",
    name: "Analytics Workbench",
    description:
      "Research notebooks and managed analytics services for fraud-model development.",
    owner: "Noah Williams",
    technicalOwner: "Analytics Engineering",
    repository: "github.com/acme/analytics-workbench",
    environment: "Staging",
    tier: "Important",
    dataClassification: "Confidential",
    compliance: ["SOC 2"],
    securityGroupIds: ["sg-0e42f90b3c61"],
    dependencies: [
      { name: "Notebook proxy", service: "TCP 443", authorized: true },
      { name: "Office network", service: "TCP 8888", authorized: true },
    ],
    riskScore: 67,
    reachablePaths: 1,
    protection: 79,
    tags: ["Application=Analytics", "Environment=Staging"],
  },
  {
    id: "app-developer-platform",
    name: "Developer Platform",
    description:
      "Shared administrative access and ephemeral integration environments.",
    owner: "Morgan Lee",
    technicalOwner: "Developer Experience",
    repository: "github.com/acme/platform-foundations",
    environment: "Shared",
    tier: "Business critical",
    dataClassification: "Internal",
    compliance: ["SOC 2"],
    securityGroupIds: ["sg-04bc18a21e7d", "sg-0611a2fb089c"],
    dependencies: [
      { name: "Operations network", service: "TCP 22", authorized: true },
      { name: "Production VPCs", service: "TCP 3389", authorized: false },
      { name: "Developer VPN", service: "TCP 3000–3999", authorized: true },
    ],
    riskScore: 89,
    reachablePaths: 3,
    protection: 58,
    tags: ["Application=DeveloperPlatform", "SharedService=true"],
  },
];

export const remediations: RemediationAction[] = [
  {
    id: "rem-payments-ssh",
    title: "Restore managed SSH boundary",
    securityGroupId: "sg-0a41f2e91b71",
    application: "Payments Platform",
    severity: "critical",
    confidence: "High",
    pathsBroken: 17,
    assetsProtected: 3,
    legitimateFlowsPreserved: 99.99,
    currentRisk: 96,
    projectedRisk: 41,
    effort: "Low",
    change:
      "Replace public TCP 22 with the operations managed prefix list and retain ALB-to-API TCP 8443.",
    rationale:
      "This removes the highest-leverage public administration choke point while preserving the approved application path.",
    safeguards: [
      "38 SSH flows require operations-owner confirmation",
      "Systems Manager readiness verified on all three instances",
      "Rollback rule generated with a 30-minute validity window",
    ],
    artifact: "Terraform pull request",
  },
  {
    id: "rem-shared-admin",
    title: "Remove cross-environment admin path",
    securityGroupId: "sg-04bc18a21e7d",
    application: "Developer Platform",
    severity: "critical",
    confidence: "High",
    pathsBroken: 11,
    assetsProtected: 9,
    legitimateFlowsPreserved: 100,
    currentRisk: 89,
    projectedRisk: 46,
    effort: "Medium",
    change:
      "Replace broad production VPC CIDRs with explicit operations security-group references.",
    rationale:
      "Nine production assets share this transitive access path. One scoped change breaks eleven lateral movement paths.",
    safeguards: [
      "No accepted RDP flows observed in 90 days",
      "Operations jump hosts retain explicit access",
      "Two application owners must approve the shared-service change",
    ],
    artifact: "Firewall Manager policy proposal",
  },
  {
    id: "rem-customer-db",
    title: "Constrain database source identity",
    securityGroupId: "sg-08ee42b1ca70",
    application: "Customer Data Platform",
    severity: "high",
    confidence: "High",
    pathsBroken: 6,
    assetsProtected: 2,
    legitimateFlowsPreserved: 100,
    currentRisk: 84,
    projectedRisk: 37,
    effort: "Low",
    change:
      "Replace the shared-services CIDR with the customer API security-group reference on TCP 5432.",
    rationale:
      "Observed database traffic originates from one approved application tier; the CIDR grants unnecessary reachability.",
    safeguards: [
      "90-day flow evidence covers both database ENIs",
      "Disaster-recovery source is retained",
      "Connection-test plan included",
    ],
    artifact: "Terraform pull request",
  },
  {
    id: "rem-notebook",
    title: "Retire expiring notebook bypass",
    securityGroupId: "sg-0e42f90b3c61",
    application: "Analytics Workbench",
    severity: "medium",
    confidence: "Medium",
    pathsBroken: 2,
    assetsProtected: 1,
    legitimateFlowsPreserved: 99.7,
    currentRisk: 67,
    projectedRisk: 31,
    effort: "Low",
    change:
      "Remove office TCP 8888 after the exception expires and require the private notebook proxy.",
    rationale:
      "The temporary path is still used occasionally, so removal is scheduled after certificate migration rather than immediate.",
    safeguards: [
      "Exception DATA-3018 expires Aug 12",
      "43 direct flows need migration confirmation",
      "Private proxy health check is required before change",
    ],
    artifact: "Scheduled change request",
  },
];

export const campaigns: Campaign[] = [
  {
    id: "camp-q3-prod",
    name: "Q3 production access recertification",
    description:
      "Application owners attest production ingress, egress, and cross-environment access.",
    owner: "Cloud Security",
    dueDate: "2026-08-21",
    status: "active",
    scope: "Environment=Production",
    total: 28,
    completed: 19,
    escalations: 2,
    evidenceCoverage: 98,
    reviewers: [
      { name: "Avery Chen", team: "Payments", assigned: 8, complete: 5 },
      { name: "Priya Nair", team: "Data Platform", assigned: 7, complete: 7 },
      { name: "Elena García", team: "Cloud Operations", assigned: 9, complete: 5 },
      { name: "Marcus Reed", team: "Edge Platform", assigned: 4, complete: 2 },
    ],
  },
  {
    id: "camp-exceptions",
    name: "Expiring access exceptions",
    description:
      "Revalidate or close temporary access before the approved expiration date.",
    owner: "Security Governance",
    dueDate: "2026-08-12",
    status: "active",
    scope: "Exception expires within 30 days",
    total: 6,
    completed: 4,
    escalations: 1,
    evidenceCoverage: 94,
    reviewers: [
      { name: "Noah Williams", team: "Analytics", assigned: 3, complete: 2 },
      { name: "Morgan Lee", team: "Developer Experience", assigned: 3, complete: 2 },
    ],
  },
  {
    id: "camp-pci",
    name: "PCI segmentation evidence",
    description:
      "Quarterly proof that payment boundaries match approved access contracts.",
    owner: "GRC",
    dueDate: "2026-09-15",
    status: "scheduled",
    scope: "Compliance=PCI DSS",
    total: 14,
    completed: 0,
    escalations: 0,
    evidenceCoverage: 100,
    reviewers: [
      { name: "Avery Chen", team: "Payments", assigned: 9, complete: 0 },
      { name: "Marcus Reed", team: "Edge Platform", assigned: 5, complete: 0 },
    ],
  },
];

export const connectivityEvents: ConnectivityEvent[] = [
  {
    id: "evt-20260730-pay",
    date: "Jul 30",
    time: "11:42 EDT",
    groupId: "sg-0a41f2e91b71",
    application: "Payments Platform",
    actor: "terraform-ci@payments",
    channel: "Terraform",
    title: "Public SSH path appeared",
    summary:
      "TCP 22 changed from the operations network to 0.0.0.0/0, exposing three production instances.",
    pathsBefore: 2,
    pathsAfter: 19,
    riskBefore: 44,
    riskAfter: 96,
    authorization: "Not found",
    ticket: "PAY-4812",
  },
  {
    id: "evt-20260728-shared",
    date: "Jul 28",
    time: "16:08 EDT",
    groupId: "sg-04bc18a21e7d",
    application: "Developer Platform",
    actor: "elena.garcia@example.com",
    channel: "Console",
    title: "Production CIDR added to shared administration",
    summary:
      "A console change enabled transitive administration paths to nine production assets.",
    pathsBefore: 4,
    pathsAfter: 15,
    riskBefore: 53,
    riskAfter: 89,
    authorization: "Not found",
    ticket: "No approval",
  },
  {
    id: "evt-20260722-db",
    date: "Jul 22",
    time: "09:14 EDT",
    groupId: "sg-08ee42b1ca70",
    application: "Customer Data Platform",
    actor: "database-automation",
    channel: "Automation",
    title: "Database recovery path enabled",
    summary:
      "An approved recovery source was attached, adding one temporary TCP 5432 path.",
    pathsBefore: 2,
    pathsAfter: 3,
    riskBefore: 70,
    riskAfter: 84,
    authorization: "Approved",
    ticket: "DATA-2941",
  },
  {
    id: "evt-20260717-notebook",
    date: "Jul 17",
    time: "14:31 EDT",
    groupId: "sg-0e42f90b3c61",
    application: "Analytics Workbench",
    actor: "sagemaker.amazonaws.com",
    channel: "AWS service",
    title: "Temporary notebook path renewed",
    summary:
      "The office access exception was extended while the private proxy certificate migration continues.",
    pathsBefore: 1,
    pathsAfter: 2,
    riskBefore: 48,
    riskAfter: 67,
    authorization: "Approved",
    ticket: "DATA-3018",
  },
];

export const awsHandoffs: AwsHandoff[] = [
  {
    id: "naa",
    name: "Network Access Analyzer",
    category: "Analyze",
    description:
      "Generate a scoped AWS analysis definition from a Gatewatch access contract.",
    mode: "Read only",
    readiness: "Ready",
    output: "Network access scope JSON",
    prerequisites: ["Delegated read role", "Scope-supported resource types"],
  },
  {
    id: "reachability",
    name: "Reachability Analyzer",
    category: "Analyze",
    description:
      "Create a point-to-point analysis request and preserve the returned hop evidence.",
    mode: "Read only",
    readiness: "Ready",
    output: "Analysis request JSON",
    prerequisites: ["Source and destination ENIs", "Regional analyzer access"],
  },
  {
    id: "firewall-manager",
    name: "AWS Firewall Manager",
    category: "Enforce",
    description:
      "Translate approved organization guardrails into a common security-group policy proposal.",
    mode: "Approval required",
    readiness: "Needs configuration",
    output: "Policy proposal JSON",
    prerequisites: ["Organizations delegated administrator", "Explicit remediation opt-in"],
  },
  {
    id: "security-hub",
    name: "AWS Security Hub",
    category: "Publish",
    description:
      "Publish enriched Gatewatch evidence using the AWS Security Finding Format.",
    mode: "Approval required",
    readiness: "Ready",
    output: "ASFF finding batch",
    prerequisites: ["Security Hub enabled", "Finding provider permission"],
  },
  {
    id: "terraform",
    name: "Terraform",
    category: "Change",
    description:
      "Generate a reviewable least-privilege patch with evidence, tests, and rollback guidance.",
    mode: "Approval required",
    readiness: "Ready",
    output: "Pull-request patch",
    prerequisites: ["Repository mapping", "Application-owner approval"],
  },
];

export const accessQueryExamples = [
  "Can the internet reach production compute?",
  "Can development reach production?",
  "Which groups allow unrestricted outbound access?",
  "What changed this week that created a public path?",
];
