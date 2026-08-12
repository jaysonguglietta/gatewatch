# Security remediation update — August 12, 2026

This sanitized update records the engineering and release-gate status for
[GitHub issue #2](https://github.com/jaysonguglietta/gatewatch/issues/2). It
does not disclose account IDs, live endpoints, credentials, or customer data.

## Implemented controls

- Individual Cognito OIDC identities, mandatory TOTP MFA, PKCE, short tokens,
  revocation, and immutable subject-to-role binding replace shared human auth.
- Central default-deny authorization, server-authoritative IaC evaluation,
  digest-bound remediation approval, canonical AI evidence, bounded streaming
  requests, and formula-safe CSV exports close client trust boundaries.
- CloudFront WAF, managed and route-specific rate limits, TLS 1.2+, retained
  access logs, an internal ALB CloudFront VPC origin, private application
  subnets, no public instance address, IMDS isolation, and separate workload
  roles harden the AWS runtime.
- The final runtime is a standalone non-root container with a read-only
  filesystem, dropped capabilities, bounded resources, no package manager, and
  only production dependencies. CI scans the exact ARM64 image, publishes an
  SBOM, and signs main-branch provenance.
- Forced PostgreSQL RLS, non-owner workload roles, append-only audit records,
  atomic outbox delivery to a compliance Object Lock archive, scheduled
  legal-hold-aware retention, deletion protection, 35-day Aurora recovery, and
  a documented restore drill provide governance controls.
- Secret history scanning, CodeQL, production dependency scanning,
  CloudFormation linting, IaC scanning, final-image scanning, and regression
  tests are blocking pull-request gates.

## Verification evidence

- The integrated local suite passed lint, TypeScript, both production builds,
  CloudFormation linting, shell and JavaScript syntax checks, and 110 tests.
- AWS CloudFormation `ValidateTemplate` accepted the web template in
  `us-east-1`.
- GitHub repository analysis passed Gitleaks, CodeQL, dependency, IaC, and final
  ARM64 image gates. The final-image gate initially found vulnerable npm tooling;
  npm was removed from the runtime and the rebuilt image passed.
- The only accepted IaC exception is `SEC-EX-001`: TCP/443 egress from private
  workloads for AWS and approved SaaS dependencies. It is path-scoped, has
  compensating controls, and automatically expires on 2026-11-12.

## Release status

The code-level remediation is complete. Production closure still requires the
attested `main` artifact to be deployed to the target AWS account and the
post-deployment identity, TLS, WAF, direct-origin denial, audit delivery,
retention, backup/restore, and secret-rotation checks to produce retained
evidence. The issue must remain open until that evidence is recorded.
