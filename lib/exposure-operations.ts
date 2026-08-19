export type OperationKind =
  | "verification-run"
  | "exposure-correlation"
  | "remediation-plan"
  | "owner-action"
  | "incident"
  | "policy-pack"
  | "extension"
  | "evidence-gap";

export type OperationRecord = {
  id: string;
  kind: OperationKind;
  subjectId: string;
  status: string;
  owner: string;
  note: string;
  ticketRef: string;
  expiresAt: string;
  payload: Record<string, unknown>;
  createdBy?: string;
  updatedBy?: string;
  createdAt?: string;
  updatedAt?: string;
};

export type ExposureGraphNode = {
  id: string;
  label: string;
  type: "boundary" | "network" | "control" | "workload" | "identity" | "data";
  risk: number;
};

export type ExposureGraphEdge = {
  from: string;
  to: string;
  label: string;
  observed: boolean;
};

export const operationStatuses: Record<OperationKind, readonly string[]> = {
  "verification-run": ["queued", "running", "verified", "unreachable", "inconclusive", "failed"],
  "exposure-correlation": ["open", "confirmed", "reconciled", "dismissed"],
  "remediation-plan": ["draft", "simulated", "awaiting-approval", "approved", "executing", "verifying", "completed", "rolled-back", "failed"],
  "owner-action": ["open", "accepted", "blocked", "completed", "overdue"],
  incident: ["open", "investigating", "contained", "resolved"],
  "policy-pack": ["draft", "monitor", "enforced", "disabled"],
  extension: ["enabled", "disabled", "error"],
  "evidence-gap": ["open", "collecting", "resolved", "accepted"],
};

export const operationInitialStatuses: Record<OperationKind, string> = {
  "verification-run": "queued",
  "exposure-correlation": "open",
  "remediation-plan": "draft",
  "owner-action": "open",
  incident: "open",
  "policy-pack": "draft",
  extension: "disabled",
  "evidence-gap": "open",
};

export const operationTransitions: Record<OperationKind, Record<string, readonly string[]>> = {
  "verification-run": {
    queued: ["running", "failed"], running: ["verified", "unreachable", "inconclusive", "failed"],
    verified: ["queued"], unreachable: ["queued"], inconclusive: ["queued"], failed: ["queued"],
  },
  "exposure-correlation": { open: ["confirmed", "reconciled", "dismissed"], confirmed: ["reconciled", "dismissed"], reconciled: ["open"], dismissed: ["open"] },
  "remediation-plan": {
    draft: ["simulated", "failed"], simulated: ["awaiting-approval", "draft"],
    "awaiting-approval": ["approved", "draft"], approved: ["executing", "draft"],
    executing: ["verifying", "failed", "rolled-back"], verifying: ["completed", "failed", "rolled-back"],
    completed: ["verifying"], failed: ["draft", "rolled-back"], "rolled-back": ["draft"],
  },
  "owner-action": { open: ["accepted", "blocked", "overdue"], accepted: ["completed", "blocked", "overdue"], blocked: ["accepted", "overdue"], overdue: ["accepted", "completed"], completed: ["open"] },
  incident: { open: ["investigating"], investigating: ["contained", "resolved"], contained: ["resolved", "investigating"], resolved: ["open"] },
  "policy-pack": { draft: ["monitor", "disabled"], monitor: ["enforced", "draft", "disabled"], enforced: ["monitor", "disabled"], disabled: ["draft", "monitor"] },
  extension: { enabled: ["disabled", "error"], disabled: ["enabled"], error: ["enabled", "disabled"] },
  "evidence-gap": { open: ["collecting", "accepted"], collecting: ["resolved", "open"], resolved: ["open"], accepted: ["open"] },
};

export const graphNodes: ExposureGraphNode[] = [
  { id: "internet", label: "Internet", type: "boundary", risk: 100 },
  { id: "igw", label: "Production IGW", type: "network", risk: 82 },
  { id: "route", label: "Public route", type: "network", risk: 78 },
  { id: "sg", label: "prod-payments-api", type: "control", risk: 96 },
  { id: "eni", label: "Payments ENI", type: "workload", risk: 91 },
  { id: "role", label: "PaymentsRuntimeRole", type: "identity", risk: 86 },
  { id: "data", label: "PCI payment store", type: "data", risk: 94 },
];

export const graphEdges: ExposureGraphEdge[] = [
  { from: "internet", to: "igw", label: "public ingress", observed: true },
  { from: "igw", to: "route", label: "0.0.0.0/0", observed: true },
  { from: "route", to: "sg", label: "TCP/22 and 443", observed: true },
  { from: "sg", to: "eni", label: "attached", observed: true },
  { from: "eni", to: "role", label: "instance profile", observed: false },
  { from: "role", to: "data", label: "permitted data access", observed: false },
];

export const operationSeeds: OperationRecord[] = [
  { id: "verify:sg-0a41f2e91b71", kind: "verification-run", subjectId: "arn:aws:ec2:us-east-1:111122223333:security-group/sg-0a41f2e91b71", status: "queued", owner: "Network Security", note: "Confirm the Internet-to-ENI TCP/22 path with Reachability Analyzer.", ticketRef: "SEC-1842", expiresAt: "", payload: { analyzer: "Reachability Analyzer", protocol: "TCP", port: 22, automaticRerun: true, evidence: "AWS configuration model" } },
  { id: "correlate:sg-0a41f2e91b71", kind: "exposure-correlation", subjectId: "arn:aws:ec2:us-east-1:111122223333:security-group/sg-0a41f2e91b71", status: "open", owner: "Cloud Detection", note: "Security Hub exposure and GuardDuty traits agree with Gatewatch's public-path verdict.", ticketRef: "SEC-1842", expiresAt: "", payload: { providers: ["Gatewatch", "Security Hub", "GuardDuty", "Inspector"], traits: 6, agreements: 4, contradictions: 1, blastRadius: 8 } },
  { id: "remediate:sg-0a41f2e91b71", kind: "remediation-plan", subjectId: "arn:aws:ec2:us-east-1:111122223333:security-group/sg-0a41f2e91b71", status: "draft", owner: "Payments Platform", note: "Replace Internet-wide SSH with the approved administration prefix list.", ticketRef: "PAY-4921", expiresAt: "", payload: { mode: "pull-request", pathsRemoved: 3, trafficPreserved: 99, rollbackReady: true, canaryAccounts: 2 } },
  { id: "owner:payments", kind: "owner-action", subjectId: "Payments Platform", status: "open", owner: "Payments Platform", note: "Review two confirmed paths before the production exposure SLO is breached.", ticketRef: "PAY-4921", expiresAt: "2026-08-22", payload: { findings: 2, critical: 1, slaHoursRemaining: 18 } },
  { id: "incident:guardduty-payments", kind: "incident", subjectId: "guardduty:111122223333:sample-finding", status: "open", owner: "Cloud Incident Response", note: "Suspicious workload activity intersects a confirmed public path and privileged runtime role.", ticketRef: "INC-260819-04", expiresAt: "", payload: { affectedPaths: 3, lateralTargets: 7, evidencePreserved: true, severity: "critical" } },
  { id: "policy:public-admin", kind: "policy-pack", subjectId: "policy/public-administration", status: "draft", owner: "Cloud Governance", note: "Deny public administration ports unless an approved expiring exception exists.", ticketRef: "POL-17", expiresAt: "", payload: { version: 3, scope: "Production OUs", violations: 4, enforcement: "Firewall Manager audit" } },
  { id: "extension:cmdb", kind: "extension", subjectId: "extension/cmdb-context", status: "disabled", owner: "Platform Integrations", note: "Signed enrichment endpoint for application, owner, and crown-jewel context.", ticketRef: "INT-88", expiresAt: "", payload: { schemaVersion: "1.0", authentication: "AWS SigV4", lastDelivery: "Never" } },
  { id: "gap:flowlogs-commerce", kind: "evidence-gap", subjectId: "arn:aws:ec2:us-west-2:444455556666:vpc/vpc-commerce", status: "open", owner: "Commerce Platform", note: "Flow Log coverage is missing for two subnets; exposure remains configuration-confirmed but usage is unknown.", ticketRef: "COM-733", expiresAt: "2026-08-24", payload: { missing: ["VPC Flow Logs"], affectedFindings: 9, collectionAction: "Enable rejected and accepted traffic logs" } },
];

export const exposureSlo = {
  confirmedCriticalExposureHours: 126,
  targetHours: 72,
  medianValidationMinutes: 14,
  medianRemediationHours: 31,
  automaticallyReverifiedPercent: 68,
  reopenRatePercent: 7,
  evidenceReadyPercent: 91,
  ownerSlaPercent: 84,
};

export function executiveNarrative(records: OperationRecord[]) {
  const openIncidents = records.filter((item) => item.kind === "incident" && item.status !== "resolved").length;
  const waiting = records.filter((item) => item.kind === "remediation-plan" && ["simulated", "awaiting-approval"].includes(item.status)).length;
  const gaps = records.filter((item) => item.kind === "evidence-gap" && item.status !== "resolved").length;
  return `${openIncidents} active incident path${openIncidents === 1 ? "" : "s"}, ${waiting} simulated remediation${waiting === 1 ? "" : "s"} awaiting progression, and ${gaps} unresolved evidence gap${gaps === 1 ? "" : "s"}. Confirmed critical exposure is above its 72-hour objective; prioritize the shared administration choke point first.`;
}
