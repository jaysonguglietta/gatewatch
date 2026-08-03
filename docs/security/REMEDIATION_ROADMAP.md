# Gatewatch security remediation roadmap

**Baseline:** Adversarial audit dated July 31, 2026  
**Goal:** Make Gatewatch safe to operate as an authoritative daily security-group
governance service across hundreds of AWS accounts

## Status model

- **Open:** No effective fix has been merged and deployed.
- **In progress:** A tracked implementation exists but has not passed independent validation.
- **Mitigated:** A temporary control materially reduces exposure; permanent work remains.
- **Remediated:** Code, tests, deployment, and independent validation are complete.
- **Accepted:** A named owner approved documented residual risk with an expiration date.

Do not close a finding because code was written. Closure requires the acceptance
criteria below and evidence from the target AWS environment.

## Priority 0: block production expansion

### P0.1 Individual identity and session security — GW-01

**Outcome:** Every action maps to a unique, revocable person or workload.

Work:

- integrate Cognito, IAM Identity Center/OIDC, or an approved enterprise provider;
- validate signed token issuer, audience, expiry, subject, and MFA/authentication context;
- replace trusted raw identity headers with verified server-side claims;
- provision roles by immutable subject, not display email alone;
- remove the permanent bootstrap-admin path;
- add login and administrator-action throttling;
- implement logout, session expiry, revocation, and emergency user disablement;
- rotate and retire the shared Basic Auth credential.

Acceptance criteria:

- two users produce different immutable actor IDs in audit records;
- a viewer receives `403` for every privileged direct API request;
- administrator login requires MFA;
- revoked/expired/wrong-audience tokens fail closed;
- spoofed identity headers cannot change application identity;
- no shared human credential remains in Secrets Manager or Nginx.

### P0.2 Central authorization and workflow transitions — GW-02, GW-03

**Outcome:** Roles, ownership, workspace, separation of duties, and state transitions
are enforced in one server-side policy layer.

Work:

- create named permissions for every route action;
- define an explicit workflow transition matrix;
- load stored records before authorization;
- make kind, subject, creator, and workspace immutable;
- add optimistic concurrency or expected-state updates;
- enforce independent exception approval;
- generate audit events inside the same transaction as state changes where possible.

Acceptance criteria:

- role × action integration tests cover every mutation;
- the GW-03 cross-kind proof returns `403` or `409` without changing the row;
- requestors cannot approve their own exception through any route;
- foreign-workspace and foreign-owner identifiers do not disclose or modify records;
- invalid or skipped transitions are rejected consistently.

### P0.3 Safe cross-account template generation — GW-04

**Outcome:** User input cannot change the structure or permission scope of generated IAM.

Work:

- disable the download action until fixed;
- construct a typed CloudFormation object and serialize it as YAML or JSON;
- strictly validate external IDs, prefixes, partitions, ARNs, regions, and names;
- apply a source-account permission boundary;
- include a generated-policy summary and exact access scope for operator review;
- run `cfn-lint` and IAM Access Analyzer in CI.

Acceptance criteria:

- the original administrator-policy injection proof is rejected;
- newline, quote, comment, anchor, tag, and Unicode-control payloads are rejected;
- normalized generated IAM contains only the expected role, trust, and read actions;
- Access Analyzer reports no public, cross-organization, write, or privilege-management access.

### P0.4 Verified deployment artifacts — GW-05

**Outcome:** Production executes only an immutable, verified release.

Work:

- build in CI, not on the production host;
- publish a minimal image to ECR by digest;
- generate an SBOM and provenance attestation;
- sign the image or artifact;
- pin the exact digest or S3 version in CloudFormation;
- verify signature and checksum before use;
- restrict artifact writes to the release role and enable immutable retention where appropriate.

Acceptance criteria:

- modified bytes, mutable tags, wrong S3 versions, and unsigned releases are rejected;
- the production host has no package-manager or source-build requirement;
- CloudTrail identifies the single approved release principal for artifact writes;
- rollback uses a previously signed digest.

## Priority 1: harden the deployed service

### P1.1 Production runtime and workload isolation — GW-06

- replace `wrangler dev` with the production server/runtime;
- use a pinned multi-stage image without development packages;
- separate web and integration bridge into ECS/Fargate tasks;
- assign separate task roles with exact resource ARNs;
- block IMDS and remove direct metadata credential code;
- enable read-only root filesystem, non-root user, capability drop,
  `no-new-privileges`, resource limits, health checks, and controlled egress.

Exit criteria: each task can perform only its documented AWS actions; IMDS is
unreachable; a final-image scan has no unresolved Critical or High reachable issue.

### P1.2 End-to-end transport protection — GW-07

- introduce an ALB or TLS-enabled origin with an ACM/private certificate;
- set CloudFront origin protocol to `https-only`;
- prefer a private subnet and CloudFront VPC origin or private ALB;
- remove public addressing where the selected architecture permits it.

Exit criteria: plaintext origin traffic fails, invalid certificates fail, and a
packet capture confirms TLS for credentials and application data.

### P1.3 Abuse prevention and bounded parsing — GW-08

- use one streaming bounded-body helper for all APIs;
- define route-specific byte, depth, item, and execution-time limits;
- add AWS WAF managed rules and rate-based rules;
- rate-limit authentication, refresh, report, source-test, and Jira actions;
- add per-user and workspace quotas plus alarms.

Exit criteria: chunked/missing-length and oversized requests fail safely; sustained
tests do not exhaust memory; abusive traffic produces `429` and an alert.

### P1.4 Safe reports — GW-09

- centralize CSV encoding;
- neutralize formula prefixes after leading whitespace;
- add UTF-8/BOM behavior tests where Excel support is required;
- consider typed XLSX output for high-value reports.

Exit criteria: adversarial values remain literal in Excel, LibreOffice, and Google Sheets.

### P1.5 Evidence authenticity — GW-10

- version-pin snapshot and manifest retrieval;
- verify SHA-256 before JSON parsing;
- sign manifests using a separately controlled asymmetric KMS key;
- validate the complete snapshot schema and maximum collection sizes;
- expose signature, snapshot ID, source version, and completeness in the UI.

Exit criteria: altered, unsigned, mismatched, stale, malformed, and excessive
snapshots fail closed and create an operational alert.

## Priority 2: governance and operational assurance

### P2.1 Enforced retention — GW-11

- define data-classification and retention requirements per table;
- model legal holds;
- implement scheduled, idempotent, batched deletion;
- emit immutable purge counts and failure alerts;
- reconcile S3 source retention separately from normalized data.

Exit criteria: automated tests prove exact handling of expired, active, and held data.

### P2.2 Immutable security telemetry — GW-12

- standardize structured security-event fields;
- enable CloudFront, WAF, ALB/Nginx, application, CloudTrail, and database audit sources;
- centralize logs in a security account;
- archive critical audit events in Object Lock storage;
- prohibit application roles from deleting or rewriting the archive;
- alert on authentication failures, role changes, accepted risk, source changes,
  secret access, artifact changes, and cross-account assumptions.

Exit criteria: every privileged action is attributable and correlated, and a
compromised application role cannot erase its security history.

### P2.3 Secret lifecycle

- rotate Jira, origin/service, database, and emergency credentials;
- design zero-downtime dual-version rotation;
- use customer-managed KMS keys where required;
- alert on secret reads outside expected workload roles;
- test emergency revocation and integration recovery.

Exit criteria: scheduled and emergency rotations complete without credential
disclosure or unplanned downtime.

### P2.4 Response hardening — GW-15

- remove absolute build paths and software version headers;
- add a tested CSP and Permissions Policy;
- inventory every public response header;
- add automated header and source-map checks to CI.

## Priority 3: future Aurora ingestion gate

### P3.1 Database tenant isolation — GW-13

- create non-owner application and ingestion roles;
- enable and force PostgreSQL row-level security;
- set workspace context per transaction;
- deny table access outside approved views/procedures;
- enable deletion protection, explicit PITR retention, and restore drills.

Exit criteria: cross-workspace tests fail even when application SQL omits a
workspace predicate, and runtime roles cannot disable RLS.

### P3.2 Message provenance and run binding — GW-14

- bind every object and run update to source plus workspace;
- separate internal backfill messages from organization-origin messages;
- validate EventBridge source, account, bucket, prefix, object version, and expected schema;
- sign or otherwise authenticate internal message attributes;
- constrain queue policies with exact role, organization, and source conditions.

Exit criteria: crafted cross-source or cross-workspace messages are rejected and audited.

## Continuous release controls

Every release should include:

- lockfile-based dependency installation;
- production-image software composition analysis;
- SBOM generation and retention;
- secret scanning and push protection;
- SAST and custom authorization checks;
- `cfn-lint`, policy validation, and IaC security scanning;
- container and Lambda package scanning;
- behavioral security integration tests;
- signed release provenance and immutable deployment reference;
- post-deployment identity, TLS, WAF, logging, backup, and least-privilege smoke tests.

## Suggested evidence for finding closure

- pull request and commit implementing the fix;
- regression test demonstrating the former exploit fails;
- deployment identifier and target environment;
- screenshots or machine-readable output with secrets redacted;
- IAM Access Analyzer, WAF, dependency, container, or IaC scan result as relevant;
- independent reviewer and review date;
- residual risk, owner, and expiration if the finding is accepted rather than remediated.

