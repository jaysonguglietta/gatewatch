# Gatewatch security test plan

## Organization collection and evidence integrity

- Deploy to a test OU containing successful, denied, opted-out-Region, empty,
  and high-resource-count accounts.
- Prove one denied member account produces an explicit failed account/target and
  does not stop successful account shards.
- Replay the same S3 event and confirm the object ledger and observation counts
  remain unchanged.
- Change run ID, account ID, Region, schema version, evidence type, observation
  time, group ID, or key path independently and confirm ingestion fails closed.
- Test compressed bombs, oversized manifests, excessive groups/rules/attachments,
  and missing `Content-Length`/event size hints.
- Modify canonical shard bytes and prove checksum validation fails.
- Attempt SQS delivery from another EventBridge rule/account and prove the queue
  policy denies it.
- Use IAM Access Analyzer on the StackSet member role, evidence bucket, KMS key,
  queue, and Lambda roles.
- Confirm no collector role has EC2, IAM, Organizations, S3, KMS, or database
  write permissions beyond its documented central resources.

## Coverage correctness

- Compare Organizations active account count to manifest `accountsExpected`.
- Compare per-account enabled Regions to manifest targets after allowlist rules.
- Confirm Coverage search, `Needs attention`, `Failed`, pagination, empty state,
  legacy transition, retry, and stale-manifest behavior.
- Remove a previously collected account's role and prove the current UI retains
  its last observation while marking the new run incomplete/stale.

## Bedrock AI analyst tests

- Put prompt instructions, XML-like role tags, Unicode controls, markdown, and
  remediation commands in security-group names, tags, owner, intent, and actor fields.
- Confirm raw `evidenceSnapshot`, uploaded log bodies, credentials, and unrelated
  findings never appear in the compact Bedrock request.
- Require every accepted claim reference to exist in the submitted fact IDs.
- Mutate the model's deterministic verdict, mode, schema version, extra property,
  query field, confidence, action approval flag, and output length independently;
  confirm validation fails and deterministic fallback is returned.
- Confirm Guardrail intervention, timeout, access denial, throttling, malformed
  JSON, missing text output, and disabled service all preserve core findings.
- Send more than 25 findings, 60 KB to the route, 96 KB to the bridge, and 64 KB
  from a mock model; confirm each boundary fails closed.
- Race more than 100 requests for one actor and 500 for a workspace; confirm the
  atomic counters prevent overrun and cached requests do not consume reservations.
- Verify viewer/reviewer denial, analyst access, same-origin enforcement, feedback
  ownership, cache expiry, audit attribution, and generic public errors.
- Verify the workload role can invoke only the approved inference profile/model
  destinations and stack Guardrail, and cannot invoke an unrelated model.
- Render hostile model text and remediation blocks; confirm React escapes them and
  no control offers automatic execution.
- Disable Bedrock through CloudFormation and confirm deterministic daily findings,
  search, triage, reporting, and remediation continue unchanged.

**Version:** 1.0  
**Baseline:** July 31, 2026 adversarial audit  
**Purpose:** Convert the threat model and findings into repeatable release gates

## Test principles

- Test server behavior, not the presence of security-related strings in source.
- Use least-privilege test identities for every role and workload.
- Run destructive tests only in an isolated AWS test account with synthetic data.
- Never place production credentials or customer CloudTrail data in fixtures.
- Make every fixed vulnerability a permanent regression test.
- Fail closed when identity, authorization context, evidence integrity, or source
  provenance is missing or ambiguous.

## Test environments

### Local integration

Use deterministic mock identities, a temporary database, synthetic AWS snapshots,
malicious upload fixtures, and a local Jira stub. Local tests cover route behavior,
state transitions, parsers, exports, and schema validation.

### AWS security test environment

Use dedicated Gatewatch, source, and adversary accounts inside a non-production
organization. Deploy the same CloudFormation and images intended for production.
Enable CloudTrail, WAF, CloudFront, workload, and database logging before testing.

### Analyst endpoint validation

Use isolated spreadsheet and browser test systems for CSV and client-side attacks.
Do not open malicious fixtures on ordinary workstations.

## Authentication tests

| ID | Test | Expected result |
|---|---|---|
| AUTH-001 | Request every route without identity | `401` or redirect; no data or state change |
| AUTH-002 | Send viewer-controlled identity headers through CloudFront | Header is removed; identity is unchanged |
| AUTH-003 | Token with invalid signature | Rejected before application access |
| AUTH-004 | Correct signature, wrong issuer or audience | Rejected |
| AUTH-005 | Expired, revoked, disabled-user token | Rejected |
| AUTH-006 | Administrator without required MFA context | Privileged access denied |
| AUTH-007 | Repeated failed login attempts | Rate-limited and alerted |
| AUTH-008 | Logout or emergency revocation | Existing session becomes unusable within policy |
| AUTH-009 | Two users perform actions | Distinct immutable subjects appear in audit records |

## Authorization matrix

Create an executable matrix for every route and action. At minimum:

| Capability | Viewer | Reviewer | Administrator |
|---|---:|---:|---:|
| Read findings and reports | Allow | Allow | Allow |
| Save personal view | Allow | Allow | Allow |
| Add review note | Deny or explicitly define | Allow | Allow |
| Mark follow-up/acknowledged | Deny or explicitly define | Allow | Allow |
| Approve accepted risk | Deny | Deny | Allow with independent approver |
| Create governance policy/campaign | Deny | Deny | Allow |
| Configure AWS source or Jira | Deny | Deny | Allow |
| Assign or remove roles | Deny | Deny | Allow with self-lockout protection |

For each allowed action, test ownership and workspace. For each denied action,
call the API directly and verify no database or audit-state mutation occurs.

## Workflow and business-logic tests

### Required GW-03 regression

1. Create an exception as user A.
2. Attempt to update the ID as `recommendation` using user B.
3. Attempt approval as user A.
4. Attempt to change immutable subject and kind fields.
5. Attempt a stale concurrent update.

Expected: all unauthorized or inconsistent operations fail without changing the
stored exception. The authorized transition creates one audit event containing the
old and new state.

Additional cases:

- skip required states;
- reopen a resolved finding while preserving history;
- use an ID belonging to another user or workspace;
- mix authorized and unauthorized records in one bulk request;
- repeat a request to test idempotency;
- omit justification, ticket, controls, expiry, or independent approval;
- approve expired or already revoked risk;
- create duplicate Jira tickets through races and retries.

## Input-validation and parser tests

### JSON request bodies

- missing, negative, nonnumeric, and misleading `Content-Length`;
- chunked and HTTP/2 request bodies;
- one byte below, at, and above every route limit;
- deeply nested arrays/objects and extremely long keys;
- duplicate JSON keys and unexpected primitive types;
- invalid UTF-8, null bytes, control characters, and confusable Unicode;
- large batches, duplicate identifiers, and empty arrays.

Expected: byte limits are based on consumed bytes, parsers remain within memory and
time budgets, and responses reveal no stack trace or secret.

### CloudTrail and AWS Config

- valid single object, array, `Records`, Config history, and snapshot formats;
- malformed and truncated JSON/GZIP;
- GZIP bomb and maximum decompressed size;
- maximum record count and excessive nested collections;
- missing account, region, event time, security-group ID, and rule values;
- unsuccessful AWS events that must not change current state;
- delayed, duplicated, and out-of-order records;
- malicious actor, tag, resource name, source IP, and error strings;
- unknown schema version and mixed formats.

Expected: invalid evidence is quarantined or rejected, unsuccessful API calls do
not alter state, and error messages are bounded and non-sensitive.

### Generated CloudFormation

Test every user-controlled value with:

- quotes, newlines, carriage returns, tabs, null and escape characters;
- YAML comments, anchors, aliases, tags, block scalars, and document separators;
- attempted `ManagedPolicyArns`, trust-policy, resource, output, and condition injection;
- partition, ARN, role-name, region, external-ID, and S3-prefix boundary values.

Expected: invalid values are rejected before generation. Valid output parses to an
exact expected object and passes `cfn-lint` and IAM Access Analyzer.

## Output and browser tests

- Formula prefixes `=`, `+`, `-`, `@`, tab, and carriage return with and without
  leading whitespace in every CSV field.
- Quotes, commas, newlines, RTL markers, and long Unicode in reports.
- HTML/script payloads in every AWS, Jira, note, owner, and uploaded-log field.
- CSP enforcement, frame blocking, MIME sniffing, referrer behavior, and permissions policy.
- Response headers and source maps for absolute paths, usernames, secrets, and software versions.

Expected: spreadsheet values remain literal, HTML is encoded, CSP reports no
unexpected execution, and production responses disclose no local path.

## Jira and outbound request tests

- HTTP, non-Atlassian, lookalike, user-info, path, query, fragment, IPv4, IPv6,
  localhost, metadata, and redirect URLs;
- DNS failure, timeout, oversized response, malformed JSON, and rate-limit response;
- missing or rotated token;
- ticket payload with adversarial names, notes, and evidence;
- repeated and concurrent creation for the same fingerprint;
- more than the configured bulk limit.

Expected: only canonical HTTPS Atlassian origins are contacted, redirects fail,
credentials never appear in errors/logs/responses, and duplicates are prevented.

## Infrastructure and IAM tests

### Edge and network

- direct public-IP and public-DNS requests from non-CloudFront sources;
- missing and forged origin token;
- plaintext CloudFront-to-origin connection after TLS migration;
- invalid, expired, or mismatched origin certificate;
- disallowed methods, oversized requests, common managed-rule payloads, and rate bursts;
- IPv4 and IPv6 coverage.

Expected: only the intended edge reaches the origin over TLS; WAF blocks or rates
abuse and logs the decision.

### Workload identity

- query IMDS from web and bridge tasks;
- use each task role to call every AWS action in and outside its policy;
- attempt to read another component's secret;
- attempt to assume roles outside the exact configured source allowlist;
- test source role access outside the configured bucket and prefix;
- test KMS decrypt without the expected service and encryption context.

Expected: IMDS is unreachable and every out-of-scope action is denied.

### Artifact integrity

- overwrite the logical release name with different bytes;
- deploy the wrong S3 version or image digest;
- alter the checksum, signature, SBOM, or provenance;
- include absolute, parent-traversal, or symlink archive entries;
- revoke the signing key;
- roll back to an older signed but disallowed release.

Expected: deployment fails before extraction or execution and produces an alert.

### Snapshot integrity

- change one byte after manifest creation;
- pair a valid snapshot with another manifest;
- use an old, deleted, incomplete, unsigned, or wrong-account version;
- exceed schema collection limits while remaining below the byte limit;
- modify both snapshot and unsigned checksum as a malicious writer.

Expected: only the exact signed and version-pinned snapshot is accepted.

## Multi-tenant and database tests

Before Aurora production deployment:

- execute queries with correct, wrong, missing, empty, and malformed workspace context;
- attempt cross-workspace access through every table, view, function, and batch API;
- verify database roles cannot disable or bypass RLS;
- test owner/superuser behavior separately from runtime roles;
- send source events carrying another workspace or run ID;
- verify Data API transaction context cannot leak between requests;
- confirm TLS requirements, credential rotation, deletion protection, PITR, and restore.

Expected: database-enforced isolation holds even if application SQL omits a
workspace predicate.

## Availability and resilience tests

- sustained WAF-approved load at expected and abusive rates;
- expensive report and refresh concurrency;
- Jira latency and throttling;
- S3/STS/Secrets Manager/Aurora transient failures;
- poisoned SQS message retry and DLQ behavior;
- duplicate, delayed, and out-of-order events;
- container, EC2 task, Availability Zone, and database failover;
- EFS, S3 version, and Aurora point-in-time restoration.

Measure p50/p95/p99 latency, memory, CPU, queue age, error rate, recovery time, and
data loss. Define alert thresholds before production.

## Audit and retention tests

- successful and failed login;
- role assignment/removal and denied authorization;
- source/Jira configuration and secret rotation;
- finding and exception state changes;
- artifact and infrastructure changes;
- cross-account role assumption;
- retention purge and legal-hold override;
- attempted audit deletion by the application role.

Expected: events contain immutable actor, request/correlation ID, source, target,
old/new state, result, and time. The application cannot rewrite the central archive.

Execute the Aurora governance regression with two synthetic workspaces and the
actual non-owner login secrets:

1. Create expired, current, held, and unheld records for both workspaces.
2. Test correct, wrong, missing, empty, and malformed workspace settings as each
   workload role. Access outside the selected workspace must fail closed.
3. Attempt to disable RLS, change ownership, set `row_security=off`, update or
   delete an audit event, and truncate the table. Every attempt must fail.
4. Run governance maintenance twice. Held/current rows must remain, eligible
   rows must be removed only in bounded batches, and retries must be idempotent.
5. Deny S3 `PutObject` and prove no unarchived audit row is purged.
6. Verify each archived version's SHA-256 and NDJSON count against the ledger.
7. Attempt archive deletion and retention reduction with every workload role;
   compliance Object Lock must deny both.

## Automated release gates

Required on every pull request:

- format, lint, type check, unit and integration tests;
- role/authorization matrix and known-exploit regressions;
- production dependency and final-image scan;
- secret scan;
- SAST;
- `cfn-lint`, IAM validation, and IaC security scan;
- malicious parser and export fixtures;
- SBOM generation.

Required before deployment:

- signed artifact/image and verified provenance;
- no unresolved Critical or High deployed-path finding;
- approved dependency exceptions with owner and expiration;
- isolated AWS integration test;
- backup and rollback readiness.

Required after deployment:

- unique identity and role smoke tests;
- TLS and direct-origin denial;
- WAF and logging verification;
- workload least-privilege and IMDS denial;
- snapshot signature validation;
- alert delivery and on-call acknowledgement;
- release digest matches the approved artifact.

## Evidence retention

Store machine-readable test output, deployed template, image digest, SBOM,
provenance, security scans, Access Analyzer results, restore evidence, reviewer, and
date with the release record. Redact credentials and customer data before attaching
evidence to GitHub.
