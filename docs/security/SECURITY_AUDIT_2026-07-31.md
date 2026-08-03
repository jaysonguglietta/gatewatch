# Gatewatch adversarial security audit

**Assessment date:** July 31, 2026  
**Assessment type:** Source review, infrastructure review, dependency audit, deployed-configuration validation, and targeted exploit validation  
**Assessment posture:** Hostile Internet, untrusted authenticated users, malicious inputs, compromised clients, and compromised AWS member accounts  
**Change policy:** Read-only; the assessment did not modify source code or AWS resources

## Executive summary

The assessment found five High, eight Medium, and two Low findings. No confirmed
Critical issue, unauthenticated remote code execution, SQL injection, direct SSRF,
or exposed secret was identified.

The application is not ready to become an authoritative governance control across
hundreds of accounts. Shared administrator authentication, inconsistent API
authorization, an exception-approval bypass, generated-template injection, and an
unverified root deployment path create material integrity and cross-account risk.

### Prioritized findings

| ID | Finding | Severity | Confidence | Status |
|---|---|---:|---:|---|
| GW-01 | Shared Basic Auth collapses identity and RBAC | High | High | Open; deployed path |
| GW-02 | Mutation APIs do not consistently enforce roles | High | High | Open; deployed path |
| GW-03 | Exception workflow type-confusion bypass | High | High | Open; deployed path |
| GW-04 | Cross-account CloudFormation YAML injection | High | High | Open; exploit validated |
| GW-05 | Deployment artifact is not verified before root execution | High | Medium | Open; conditional on artifact write |
| GW-06 | Development runtime and broad instance-role blast radius | Medium | High | Open; deployed path |
| GW-07 | CloudFront-to-origin traffic uses plaintext HTTP | Medium | High | Open; deployed path |
| GW-08 | Missing abuse controls and bypassable body-size checks | Medium | High/Medium | Open; deployed path |
| GW-09 | CSV formula injection in multiple exports | Medium | High | Open; deployed path |
| GW-10 | Snapshot checksum is produced but not verified | Medium | High | Open; deployed path |
| GW-11 | Configurable retention is not enforced | Medium | High | Open; deployed path |
| GW-12 | Security audit trail is incomplete and mutable | Medium | High | Open; deployed path |
| GW-13 | Aurora lacks database-enforced tenant isolation | Medium | High | Open; future stack |
| GW-14 | Ingestion run ID is trusted without source binding | Low | Medium | Open; future stack |
| GW-15 | Filesystem path disclosure and missing HTML CSP | Low | High | Open; deployed path |

## Methodology and scope

The review covered all human-authored application routes, libraries, runtime and
deployment code, CloudFormation, Lambda handlers, database schemas, tests, and
dependency manifests. Generated lockfiles and migrations were reviewed through
targeted inspection and software-composition analysis.

Validation included:

- route-by-route authentication and authorization tracing;
- attacker-controlled data-flow analysis;
- SQL, command, URL, template, path, file, and output-sink review;
- AWS IAM, network, encryption, logging, secrets, backup, and deployment review;
- a local executable proof for generated CloudFormation injection;
- read-only inspection of the live CloudFront, EC2, S3, EFS, Secrets Manager, and
  deployed stack configuration;
- full and production-only npm dependency audits;
- application lint, build, and test execution.

The current deployed architecture uses CloudFront, a public EC2 custom origin,
Nginx Basic Auth, a web container, an AWS/Jira bridge container, encrypted EFS,
and an encrypted/versioned snapshot bucket. The Aurora/SQS ingestion platform was
not deployed at the assessment date and is labeled accordingly.

## Detailed findings

### GW-01: Shared Basic Auth collapses identity and RBAC

**Severity:** High  
**Confidence:** High  
**Affected components:** `WebAuthenticationSecret`, Nginx configuration in
`infrastructure/aws-web/install.sh`, `requireAdmin()` in `lib/server-admin.ts`

**Description and evidence**

CloudFormation creates one fixed `gatewatch-admin` username with one generated
password. Nginx authenticates every operator as that user and injects
`gatewatch-admin@gatewatch.local`. The same identity is configured as the bootstrap
administrator and is always accepted by `requireAdmin()`.

The role table shown in the application therefore does not correspond to distinct
AWS-deployed users. MFA, per-user revocation, meaningful session control, and
individual attribution are absent. The live secret had no configured rotation.

**Exploitation scenario**

Anyone who learns the shared password obtains the same administrator identity as
the legitimate operators. The attacker can change configuration, approve risk,
read security evidence, configure Jira, and use configured cross-account sources.

**Impact**

Application account takeover, loss of accountability, unauthorized security
decisions, and potential cross-account data access.

**Recommended fix**

Use Cognito, IAM Identity Center/OIDC, or an equivalent signed identity layer.
Validate issuer, audience, signature, expiration, and immutable subject. Map users
to roles server-side, require MFA for administrators, and remove the permanent
bootstrap-admin exception after initial provisioning.

**Validation**

Test two distinct identities, role revocation, token expiration, wrong issuer and
audience, missing MFA, direct identity-header spoofing, and login throttling.

**Classification:** CWE-287, CWE-284; OWASP A07:2021, A01:2021.

### GW-02: Mutation APIs do not consistently enforce roles

**Severity:** High  
**Confidence:** High  
**Affected components:** `app/api/reviews`, `app/api/governance`,
`app/api/findings`, `app/api/intelligence`

**Description and evidence**

Several POST routes require only an authenticated identity, not the viewer,
reviewer, or administrator role presented in the UI. An authenticated caller can
set review status to approved, exception, or remediate; create policies and
campaigns; and alter most finding or intelligence workflow states. Only selected
accepted-risk and intelligence transitions call `requireAdmin()`.

**Exploitation scenario**

After per-user login is introduced, a viewer calls APIs directly and performs
actions that the UI hides or disables.

**Impact**

Unauthorized policy and finding state changes, forged approvals, and loss of
workflow integrity.

**Recommended fix**

Define a central, default-deny permission matrix and enforce a named permission
before every read or mutation. Authorization must not depend on UI controls.

**Validation**

Add behavioral role-by-route-by-action tests for viewer, reviewer, administrator,
disabled user, and unassigned user.

**Classification:** CWE-862, CWE-863; OWASP A01:2021.

### GW-03: Exception workflow type-confusion bypass

**Severity:** High  
**Confidence:** High  
**Affected component:** `POST /api/intelligence`

**Description and evidence**

Authorization and separation-of-duty checks use the client-supplied `kind`. The
upsert conflict clause preserves the stored row's `kind` and `subject_id` while
updating status, owner, note, ticket, expiration, payload, and updater.

**Exploitation scenario**

An authenticated user obtains an exception ID, submits the same ID as a less
privileged workflow kind, and chooses a status valid for that false kind. The
authorization checks skip exception approval while the database preserves the
original exception type and applies the new state.

**Impact**

Unauthorized exception decisions and bypass of requestor/approver separation.

**Recommended fix**

Load the existing record first. Authorize from its stored workspace, kind, owner,
creator, and state. Treat identity fields as immutable and use expected-state or
version conditions for updates.

**Validation**

Test cross-kind upserts, foreign record ownership, self-approval, invalid state
transitions, and concurrent stale updates.

**Classification:** CWE-863, CWE-841; OWASP A01:2021, A04:2021.

### GW-04: Cross-account CloudFormation YAML injection

**Severity:** High  
**Confidence:** High  
**Affected component:** `sourceAccessCloudFormation()` in `lib/admin-sources.ts`

**Description and evidence**

Administrative values are trimmed and truncated but can retain quotes and newlines.
They are inserted directly into a YAML template. A local proof demonstrated that
an external ID containing the following value creates valid YAML and adds an AWS
managed administrator policy to the generated source role:

```text
x"
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AdministratorAccess
      #
```

The parsed role contained `arn:aws:iam::aws:policy/AdministratorAccess` under
`ManagedPolicyArns`.

**Exploitation scenario**

A compromised Gatewatch admin exports a supposedly read-only template. A source
account operator deploys it. The trusted Gatewatch source role receives
administrator permissions and remains assumable by the Gatewatch runtime.

**Impact**

Cross-account privilege escalation and possible compromise of monitored accounts.

**Recommended fix**

Generate a typed object and serialize it with a maintained YAML or JSON library.
Apply strict allowlists to every interpolated IAM, external ID, prefix, region, and
ARN value. Reject control characters and unexpected whitespace.

**Validation**

Parse adversarial generated templates and assert an exact normalized IAM document.
Run `cfn-lint`, IAM Access Analyzer, and permission-boundary tests.

**Classification:** CWE-74; OWASP A03:2021.

### GW-05: Deployment artifact is not verified before root execution

**Severity:** High  
**Confidence:** Medium  
**Affected components:** `scripts/deploy-aws-web.sh`, SSM deployment association

**Description and evidence**

The uploader calculates SHA-256 and embeds it in the key, but the EC2 host neither
pins the S3 version nor checks the hash. SSM downloads the ZIP, extracts it as root,
and runs `install.sh` as root. The archive is not checked for unsafe entries.

**Exploitation scenario**

A principal with artifact-bucket write access replaces a known key before a
deployment rerun. The host executes the substituted installation script as root.

**Impact**

Persistent host compromise, runtime-secret theft, and cross-account role abuse.

**Recommended fix**

Pin the object version and expected digest. Verify before extraction. Reject
absolute paths, parent traversal, and symlinks. Prefer a signed ECR image digest
with build provenance over building source on the server.

**Validation**

Attempt a replaced object, wrong version, wrong checksum, malicious archive entry,
unsigned image, and altered build provenance. All must fail before execution.

**Classification:** CWE-494, CWE-829; OWASP A08:2021.

### GW-06: Development runtime and broad instance-role blast radius

**Severity:** Medium  
**Confidence:** High

Production installs development dependencies and runs `wrangler dev --local`.
Containers lack a read-only root filesystem, capability drops, no-new-privileges,
and resource limits. They can reach IMDS, and application code intentionally reads
instance credentials. One EC2 role reads and updates sensitive integration data and
can assume broadly named cross-account source roles.

Use a production runtime, pinned multi-stage image, separate ECS/Fargate tasks,
separate least-privilege task roles, blocked IMDS, and hardened container settings.
Validate permissions from inside each workload.

**Classification:** CWE-250, CWE-269; OWASP A05:2021, A08:2021.

### GW-07: CloudFront-to-origin traffic uses plaintext HTTP

**Severity:** Medium  
**Confidence:** High

The viewer connection uses HTTPS, but the custom origin policy is `http-only` and
Nginx listens on port 80. Basic credentials, the origin token, and application data
cross the CloudFront-to-EC2 connection without TLS.

Terminate TLS at an ALB or Nginx, configure `https-only`, and prefer a private VPC
origin. Validate invalid-certificate and plaintext failures.

**Classification:** CWE-319; OWASP A02:2021.

### GW-08: Missing abuse controls and bypassable body-size checks

**Severity:** Medium  
**Confidence:** High for absent controls; Medium for transport-dependent length bypass

Several routes trust `Content-Length`; missing length is treated as zero before the
unbounded `request.json()` call. Nginx allows 30 MB. The live distribution had no
WAF, rate rules, or centrally observable authentication throttling.

Use one streaming bounded-body parser for all routes, cap JSON depth and collection
counts, reduce origin limits, and add route-aware WAF and application rate limits.

**Classification:** CWE-400, CWE-770, CWE-307; OWASP A04:2021.

### GW-09: CSV formula injection in multiple exports

**Severity:** Medium  
**Confidence:** High

Several client-side exports quote CSV values but do not neutralize spreadsheet
formula prefixes. Attacker-controlled CloudTrail fields, AWS names/tags, owners,
notes, and ticket references can reach these exports. The detailed server report
already contains the correct defensive pattern.

Centralize CSV encoding and prefix values beginning, including after whitespace,
with `=`, `+`, `-`, `@`, tab, or carriage return. Prefer typed XLSX output where
appropriate.

**Classification:** CWE-1236; OWASP A03:2021.

### GW-10: Snapshot checksum is produced but not verified

**Severity:** Medium  
**Confidence:** High

The collector writes SHA-256 into a manifest, but the bridge retrieves only
`exports/latest.json`. The application performs shallow top-level validation and
does not check the manifest, signature, exact version, or complete schema.

Retrieve version-pinned evidence and a signed manifest, verify before parsing, and
apply complete schema and collection limits.

**Classification:** CWE-345, CWE-20; OWASP A08:2021.

### GW-11: Configurable retention is not enforced

**Severity:** Medium  
**Confidence:** High

The UI promises normalized-row deletion, legal holds, and audited purges. The API
only saves numeric settings; no cleanup scheduler, deletion queries, hold model, or
purge audit implementation exists.

Implement table-specific, idempotent retention jobs and legal holds, or change the
UI so it does not claim enforcement. Validate expired, current, and held records.

**Classification:** CWE-459; OWASP A04:2021.

### GW-12: Security audit trail is incomplete and mutable

**Severity:** Medium  
**Confidence:** High

The shared user destroys attribution. Some workflows use separate mutable event
tables, governance creation is not centrally audited, edge access logging is
disabled, Nginx authentication events are not shipped centrally, and application
audit rows reside beside mutable application state.

Send structured events to an independent append-only destination with immutable
subject, request ID, source, result, and old/new state. Enable CloudFront, WAF, and
authentication logging and alarms.

**Classification:** CWE-778; OWASP A09:2021.

### GW-13: Future Aurora lacks database-enforced tenant isolation

**Severity:** Medium  
**Confidence:** High  
**Deployment:** Future stack, not currently deployed

Tables include `workspace_id`, but there is no PostgreSQL row-level-security policy.
Runtime Lambdas receive the Aurora administrator secret. A missing predicate or
compromised function can access all workspaces. Explicit deletion protection and
backup-retention policy are also absent.

Use non-owner runtime roles, enable and force RLS, bind workspace context in each
transaction, and remove master credentials from application functions. Add
deletion protection and tested PITR.

**Classification:** CWE-284, CWE-266; OWASP A01:2021.

### GW-14: Future ingestion run ID is trusted without source binding

**Severity:** Low  
**Confidence:** Medium  
**Deployment:** Future stack, not currently deployed

The ingestion handler accepts `runId` from the SQS/EventBridge envelope and updates
the run using only that ID. It does not require the run to belong to the resolved
source and workspace.

Bind updates to run, source, and workspace. Use an internal backfill queue or signed
server-generated attributes. Test cross-source and cross-workspace run IDs.

**Classification:** CWE-639, CWE-345; OWASP A01:2021.

### GW-15: Filesystem path disclosure and missing HTML CSP

**Severity:** Low  
**Confidence:** High

An authenticated live response exposed an absolute development filesystem path in
a font preload header and disclosed the Nginx version. HTML responses lack CSP,
although no exploitable XSS sink was identified.

Emit only relative production assets, disable server version tokens, and add a
tested nonce- or hash-based CSP and Permissions Policy.

**Classification:** CWE-200, CWE-693; OWASP A05:2021.

## Combined-risk scenarios

### Generated-template account escalation

1. Steal or brute-force the shared administrator credential.
2. Insert the YAML payload into a source configuration.
3. Export the generated read-only template.
4. A source-account operator deploys the template.
5. The role gains administrator permission while trusting Gatewatch.
6. Gatewatch or a compromised runtime assumes that role.

### Artifact-to-cross-account compromise

1. Compromise an artifact writer or deployment workstation.
2. Replace an existing S3 artifact key.
3. Trigger the SSM association.
4. The instance executes substituted code as root.
5. The attacker steals instance credentials and runtime secrets.
6. Configured source roles are assumed from the compromised runtime.

### Governance suppression

1. Authenticate as a non-administrator.
2. Obtain an exception record ID.
3. Submit an update with a false workflow type.
4. Authorization checks evaluate the false type.
5. The database preserves the exception type but changes its state.

### Analyst workstation attack

1. Put a spreadsheet formula in an AWS tag, CloudTrail actor, or uploaded event.
2. Cause it to appear in a CSV report.
3. An analyst opens the report in a spreadsheet application.
4. The application evaluates the formula or performs an external request.

## Dependency and configuration results

| Scope | Known vulnerabilities at assessment time |
|---|---:|
| Root production-only dependency tree | 0 |
| Full root tree | 13: 9 High, 4 Moderate |
| Ingest Lambda production dependencies | 0 |
| Backfill Lambda production dependencies | 0 |

The full-tree results matter because the production image installs development
packages. No SBOM, artifact signature, provenance attestation, CI security gate,
SAST, secret scan, or infrastructure scan was present in the repository.

## Positive controls observed

- Reviewed SQL uses bound parameters.
- No `eval`, unsafe command execution, `dangerouslySetInnerHTML`, or obvious
  path-traversal endpoint was found.
- Jira requires HTTPS, is restricted to `.atlassian.net`, rejects embedded
  credentials and unexpected URL components, blocks redirects, and bounds time
  and response size.
- Browser and Lambda ingestion enforce compressed, decompressed, and record limits.
- Snapshot S3 has encryption, versioning, transport enforcement, and public-access blocking.
- EBS and EFS are encrypted; IMDSv2 is required.
- Origin ingress is restricted to the AWS CloudFront origin prefix list.
- Public forged identity-header requests remained unauthorized during validation.

## Verification completed

- `npm run lint`: passed.
- `npm test`: build passed; 15 of 15 tests passed.
- Root `npm audit --omit=dev`: zero findings.
- Ingest and backfill Lambda production audits: zero findings.
- CloudFormation injection proof: successful before remediation.

Existing security tests largely assert that relevant strings are present in source
code. They do not execute the authorization and workflow behavior and therefore did
not detect GW-02 or GW-03.

## Open questions

1. Which principals can write or overwrite the artifact bucket?
2. Will production use Cognito, Identity Center, or another OIDC provider?
3. Is the application permanently single-tenant or expected to host organizations?
4. Does accepted risk require two independent approvers?
5. Are logs exported to a central account outside the reviewed stack?
6. What retention and legal-hold rules apply to CloudTrail identities and notes?
7. Will every source role use an organization-managed permission boundary?
8. Has an actual EFS recovery point and restore been tested?
9. Who can invoke the future backfill Lambda or send directly to its queue?
10. Which customer-managed KMS and secret-rotation requirements apply?
