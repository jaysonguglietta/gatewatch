# Exposure operations

## Purpose

Exposure Operations closes the gap between identifying a broad security-group
rule and proving that risk was safely removed. It coordinates AWS-native path
verification, provider-finding correlation, graph investigation, controlled
remediation, owner action, incident response, policy enforcement, outcome SLOs,
and enrichment extensions.

Gatewatch remains the deterministic correlation and workflow authority. Amazon
Bedrock can explain an evidence package but cannot create a verification result,
approve a change, alter an exposure verdict, or execute remediation.

## User workflow

1. Open **Findings → Exposure operations**.
2. Review confirmed critical-exposure hours and the operational narrative.
3. Start an AWS Reachability Analyzer or Network Access Analyzer verification.
4. Compare Gatewatch evidence with Security Hub Exposure, GuardDuty, Inspector,
   and other contributing traits. Contradictions stay explicit.
5. Inspect the resource graph and select the safest shared choke point.
6. Simulate an advisory, pull-request, or Firewall Manager remediation.
7. Submit the immutable plan for independent approval.
8. Canary the change, execute it through the configured delivery adapter, and
   automatically rerun path verification.
9. Complete owner work only after verification succeeds. A failed or
   inconclusive check keeps the work open or triggers rollback.

## State machines

The application and API share explicit, deny-by-default transitions:

- verification: `queued → running → verified | unreachable | inconclusive | failed`;
- correlation: `open → confirmed → reconciled | dismissed`;
- remediation: `draft → simulated → awaiting-approval → approved → executing → verifying → completed`;
- owner action: `open → accepted → completed`, with blocked and overdue branches;
- incident: `open → investigating → contained → resolved`;
- policy pack: `draft → monitor → enforced`, with reversible disablement;
- evidence gap: `open → collecting → resolved`.

Unsupported jumps return `409`. Remediation authors cannot approve their own
production plan. Approval, execution, enforcement, rollback, and extension
activation require administrator authorization and emit audit events.

## AWS integration contracts

### Verification adapters

A production verification worker assumes a workspace-bound, read-only network
analysis role. It constructs endpoints from the stored finding—not
client-submitted AWS identifiers—then creates and polls the AWS analysis. The
analysis ARN, status, bounded result, and evidence references are stored in
`exposure_verification_runs`.

The UI presents an explicit queued lifecycle when that worker is not connected.
It never fabricates a successful analysis.

### Security Hub exposure correlation

Provider findings are deduplicated by workspace, provider, and provider finding
ID. Traits, agreements, contradictions, and blast-radius resources are retained
separately from Gatewatch's deterministic verdict. Mirrored GuardDuty findings
use their provider identity so Security Hub delivery does not create duplicate
daily work.

### Remediation adapters

The delivery modes share one immutable simulation and approval record:

- **Advisory** exports exact before/after guidance only.
- **Pull request** sends a digest-bound change to an approved repository adapter.
- **Firewall Manager** promotes a versioned policy from monitor to a canary scope
  and then to its approved organization scope.

Firewall Manager-managed resources require an ownership tag so a repository
adapter and Firewall Manager never compete over the same rule. Every plan
contains rollback material and enters `verifying` after delivery. Completion is
unavailable until a fresh AWS verification confirms the expected path result.

## Attack graph

`exposure_graph_edges` stores workspace-scoped, evidence-referenced relations
between Internet boundaries, gateways, routes, NACLs, security groups, ENIs,
workloads, identities, and protected data. Observed and configured relationships
remain distinct. Choke-point rank combines paths removed, attached criticality,
approved traffic preservation, confidence, and rollback readiness.

The graph does not claim exploitation. It shows a potential path supported by
recorded AWS evidence and labels unsupported or stale segments.

## Owner and incident workflows

The owner portal is a constrained view of assigned applications. Owners can
accept work, document a blocker, complete verified work, or request an exception.
They cannot change deterministic risk or approve their own exception.

Incident mode correlates an active threat signal with the current exposure
graph, snapshots the path, and links a legal hold when configured. Containment
prioritizes the lowest-blast-radius choke point and retains the before, change,
and post-change evidence chain.

## Outcome measurement

`exposure_slo_snapshots` records confirmed critical-exposure hours, median
validation and remediation time, automatic re-verification, and reopen rate.
The primary objective is confirmed critical-exposure hours. Raw finding counts
remain diagnostic because suppression can reduce them without improving safety.

## Extension boundary

Extensions may enrich application, owner, business criticality, data
classification, and ticket context. Registrations are schema-versioned,
workspace-bound, rate-limited, and authenticated with AWS SigV4 or an approved
workload identity. Extension data cannot alter reachability, reduce severity,
approve workflows, or invoke AWS mutations. Secrets are referenced by Secrets
Manager ARN and never stored in rows, audit details, or browser payloads.

## Production isolation and current boundary

Migration `0006_exposure_operations.sql` adds nine UUID-workspace-scoped tables;
every table enables and forces PostgreSQL RLS. The migration runner fails closed
unless every public relation containing `workspace_id` has both RLS flags set.

The workspace, durable transitions, approval rules, graph, metrics, and schema
are implemented. Live execution still requires deploying the AWS verification
worker and selected remediation adapter with customer-approved roles and scopes.
Until configured, these operations remain visibly queued or in monitor mode.
