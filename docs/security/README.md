# Gatewatch security documentation

This directory contains the production security baseline for Gatewatch. It is
intended for maintainers, cloud-security engineers, application reviewers,
auditors, and operators who approve deployment into AWS environments.

## Current security posture

The July 31, 2026 adversarial review found no confirmed unauthenticated remote
code execution, SQL injection, direct SSRF, or exposed credential, but identified
high-risk identity, authorization, artifact, isolation, and governance gaps.
The August 12 remediation integrates fixes and blocking regression tests for the
sanitized public findings, including individual MFA-backed identity, central
authorization, immutable approvals, a private production AWS runtime, forced
RLS, external immutable audit, enforced retention, and signed release artifacts.

The August 9 Bedrock review found no confirmed AI-specific path to AWS mutation,
authorization bypass, code execution, or secret disclosure. The advisory path is
minimized, schema constrained, citation/verdict checked, Guardrail protected,
budgeted, cached, audited, and unable to execute changes. It does not reduce the
inherited shared-identity and compatibility-runtime blockers.

Gatewatch remains **pre-production for authoritative multi-account governance**
until the attested main artifact passes the target-AWS acceptance suite. Code and
CI completion alone do not satisfy the release gate.

## Document set

| Document | Purpose |
|---|---|
| [Threat model](THREAT_MODEL.md) | Architecture, trust boundaries, assets, attackers, and abuse cases |
| [Adversarial security audit](SECURITY_AUDIT_2026-07-31.md) | Evidence-backed findings, exploit scenarios, and fixes |
| [Remediation roadmap](REMEDIATION_ROADMAP.md) | Priorities, work packages, dependencies, and acceptance criteria |
| [Security test plan](SECURITY_TEST_PLAN.md) | Automated and manual validation required before production |
| [August 3 implementation update](SECURITY_UPDATE_2026-08-03.md) | Implemented controls, evidence, residual work, and remaining release blockers |
| [August 9 Bedrock security review](SECURITY_UPDATE_2026-08-09.md) | AI trust boundaries, adversarial findings, exploit chains, controls, residual risk, and tests |
| [August 11 remediation update](SECURITY_UPDATE_2026-08-11.md) | Sanitized application, AWS edge, data-governance, and CI remediation status |
| [August 12 remediation update](SECURITY_UPDATE_2026-08-12.md) | Integrated controls, release evidence, residual exception, and target-AWS gate |
| [Aurora recovery drill](AURORA_RESTORE_DRILL.md) | Change-controlled point-in-time restore and evidence procedure |
| [Time-bounded exceptions](SECURITY_EXCEPTIONS.md) | Owned, path-scoped exceptions with compensating controls and automatic expiry |
| [Repository security policy](../../SECURITY.md) | Private reporting and secret-handling expectations |

## How to use these documents

1. Create tracked engineering work for every open high and medium finding.
2. Link each change to its finding ID, such as `GW-03`.
3. Add a behavioral regression test before marking a finding remediated.
4. Have a reviewer independent from the implementer validate high-severity fixes.
5. Update the dated audit instead of silently deleting historical findings.
6. Repeat the threat model after identity, tenancy, ingestion, or deployment
   architecture changes.

## Security release gate

A production release is blocked if any of these are true:

- an open Critical or High finding affects the deployed path;
- authentication does not provide unique, revocable identities and MFA for admins;
- an API action lacks an explicit role and state-transition authorization test;
- a release artifact or snapshot can be consumed without integrity verification;
- cross-account IAM has not been validated with Access Analyzer and a permission boundary;
- end-to-end TLS, edge logging, abuse controls, backup restoration, or secret
  rotation have not been demonstrated in the target AWS environment.
