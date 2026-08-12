# Security update — August 11, 2026

This public update records remediation engineering for the sanitized findings in
[GitHub issue #2](https://github.com/jaysonguglietta/gatewatch/issues/2). It does
not contain live account identifiers, endpoints, credentials, exploitation
instructions, or customer evidence.

## Review branches

- **Application trust boundaries:** server-side IaC evaluation from uploaded
  artifacts, digest-bound immutable remediation approval, corrected permission
  separation, streaming request limits, canonical AI inputs, and one formula-safe
  CSV path.
- **AWS identity and edge:** named Cognito users, mandatory TOTP MFA, PKCE,
  revocation and short-lived tokens, WAF managed rules and rate limiting, viewer
  and origin TLS, CloudFront-only origin access, edge logging, separate secrets,
  scoped KMS access, and a minimized digest-pinned runtime image.
- **Data governance:** forced RLS on every workspace table, non-owner ingestion
  and maintenance database users, append-only audit rows, compliance Object Lock
  archives, scheduled legal-hold-aware retention, Aurora recovery controls, and
  pinned secret/SAST/dependency/IaC CI gates. Follow-up review remediation adds
  a dedicated rotating queue CMK, least-privilege producer/consumer KMS access,
  audit-archive server access logging, and active X-Ray tracing for every
  platform Lambda.

## Verification completed in development

- AWS CloudFormation accepted the modified web and platform templates through
  `ValidateTemplate` in `us-east-1`.
- Lint, TypeScript, production build, shell/JavaScript syntax, diff checks, and
  the full local test suite passed on the respective review branches.
- Production dependency audit reported no vulnerability at the configured High
  threshold during the connected validation run.

## Release status

The findings are **not closed by this update**. The branches require independent
review and merge. The final release gate also requires deployment to an isolated
AWS environment and retained evidence for OIDC revocation, MFA, direct-origin
denial, TLS, WAF, final-image scanning, database cross-workspace tests, audit
immutability, legal holds, retention idempotency, backup restoration, role
least-privilege, and alert delivery.

The current vinext AWS adapter still starts its generated workerd bundle through
Wrangler local mode. The review branch removes build-only dependencies and the
inspector from the final image, but a native production AWS adapter remains a
time-bounded runtime-hardening item and must not be represented as closed.
