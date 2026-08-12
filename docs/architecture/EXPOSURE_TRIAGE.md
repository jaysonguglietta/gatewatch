# Exposure triage architecture

Gatewatch's exposure triage is a deterministic presentation and prioritization
layer over normalized AWS evidence. It does not replace the evidence ledger or
invent reachability when AWS records are incomplete.

## Three phases

### Phase 1 — Fix First

`groupSecurityGroupFindings` consolidates finding records by canonical resource
key, which includes partition, account, Region, VPC context, and security-group
ID. A cluster receives one exposure lane and priority score from:

- confirmed/unknown/internal exposure state;
- highest attached-resource criticality;
- finding risk and projected reduction;
- matching Flow Log observations;
- recent, unapproved, and reopened changes.

The full security-group ARN remains visible. Guided hunts use the same bounded
field query grammar as advanced search.

### Phase 2 — Decision-first investigation

The decisive claim is shown as five separate facts: effective rule, public or
private entry point, route/control path, observed traffic, and final verdict.
The evidence-readiness checklist reports deployed rule, attachment, path,
analyzer, Flow Log, CloudTrail, and approved-intent coverage independently.

This separation prevents two unsafe shortcuts: treating a broad CIDR as proof
of reachability, or treating an empty Flow Log window as proof of safety.

### Phase 3 — Scale, remediate, and measure

The exposure-criticality matrix provides a stable drill-down across the three
lanes. Security outcomes track confirmed critical assets, aggregate exposure
hours, recurrence, exceptions, evidence readiness, and projected risk reduction.
The remediation package contains current/proposed access, affected-resource and
traffic context, copyable CLI/IaC guidance, and post-change verification steps.
It is intentionally review-only.

## Code boundaries

- `lib/security-group-triage.ts` owns deterministic grouping, prioritization,
  hunts, path truth, evidence readiness, remediation packages, and hunt translation.
- `lib/daily-finding-query.ts` owns parsing and matching the transparent query.
- `app/api/findings/route.ts` applies server-side filtering, global group priority,
  pagination, and complete-set exposure aggregation.
- `app/daily-findings-view.tsx` renders the interaction model; it does not decide
  reachability or authorization.

## Safety properties

- Terminal workflow changes are still permission-, origin-, freshness-, and
  evidence-gated by the API.
- Query translation runs locally and only emits supported deterministic clauses.
- Remediation output is never executed by the application.
- Duplicate source signals remain preserved in evidence while daily work is
  consolidated to one security-group cluster.
