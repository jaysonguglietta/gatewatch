# Gatewatch security documentation

This directory contains the production security baseline for Gatewatch. It is
intended for maintainers, cloud-security engineers, application reviewers,
auditors, and operators who approve deployment into AWS environments.

## Current security posture

The July 31, 2026 adversarial review found no confirmed unauthenticated remote
code execution, SQL injection, direct SSRF, or exposed credential. It did find
five high-severity issues that must be resolved before Gatewatch is used as an
authoritative governance system across hundreds of AWS accounts:

1. The AWS deployment gives all operators one shared administrator identity.
2. Several mutation APIs do not consistently enforce the application role model.
3. Exception decisions can bypass authorization through workflow type confusion.
4. Generated cross-account CloudFormation is vulnerable to validated YAML injection.
5. Deployment artifacts are executed as root without verifying the expected
   checksum or immutable S3 object version.

The August 3 architecture round implemented or materially mitigated the
generated-template injection, artifact integrity, CSV formula, snapshot checksum,
workflow type-confusion, and evidence-message binding risks. These are not
closed until independently validated in AWS. Shared identity, complete central
authorization, production runtime isolation, origin TLS/abuse controls, immutable
audit, enforced retention, and database RLS remain production blockers.

Gatewatch should be treated as **pre-production for authoritative multi-account
governance** until the priority-zero exit criteria are met.

## Document set

| Document | Purpose |
|---|---|
| [Threat model](THREAT_MODEL.md) | Architecture, trust boundaries, assets, attackers, and abuse cases |
| [Adversarial security audit](SECURITY_AUDIT_2026-07-31.md) | Evidence-backed findings, exploit scenarios, and fixes |
| [Remediation roadmap](REMEDIATION_ROADMAP.md) | Priorities, work packages, dependencies, and acceptance criteria |
| [Security test plan](SECURITY_TEST_PLAN.md) | Automated and manual validation required before production |
| [August 3 implementation update](SECURITY_UPDATE_2026-08-03.md) | Implemented controls, evidence, residual work, and remaining release blockers |
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
