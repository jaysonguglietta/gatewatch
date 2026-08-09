# Bedrock analyst adversarial security review — August 9, 2026

## 1. Executive summary

The Bedrock addition is designed as a bounded advisory layer over Gatewatch's
deterministic security-group evidence. No confirmed Bedrock-specific path to AWS
mutation, authorization bypass, code execution, SSRF, cross-account evidence
access, or secret disclosure was found in the implemented path. The strongest
controls are backend-only inference, minimized evidence packages, a strict double-
validated schema, evidence-reference and verdict checks, versioned prompt-attack
Guardrails, scoped IAM, atomic budgets, caching, and deterministic fallback.

The release does not close inherited production risks. Shared Basic authentication
remains a High-severity accountability/access risk. The current EC2 compatibility
runtime also concentrates application, bridge, and AWS permissions and lacks the
target production isolation, origin TLS, WAF, and Aurora RLS described elsewhere.
These are deployment blockers for a hostile multi-tenant environment, not reasons
to weaken the new AI controls.

## 2. System overview and trust boundaries

Assets are normalized AWS posture, account topology, findings/decisions, Bedrock
request packages, generated analysis, usage/audit rows, bridge token, instance
role, and Guardrail/model configuration. Entry points are `GET/POST
/api/ai/analysis` and private bridge `/bedrock/status` and `/bedrock/analyze`.
Attacker-controlled inputs include HTTP bodies, natural-language questions, every
AWS-derived string, and the model response. The browser-to-route, route-to-bridge,
bridge-to-Bedrock, model-to-validator, and compatibility-store boundaries are
independent validation points.

## 3. Threat model

- Internet attackers target shared credentials, request flooding, origin bypass,
  dependencies, and response disclosure.
- Authenticated analysts try direct API calls, synthetic finding submissions,
  budget exhaustion, cache pollution, and business-logic bypass.
- Compromised AWS accounts place prompt injections in resource metadata and try
  to influence findings from another account.
- A compromised model or dependency returns malicious JSON, code, citations,
  instructions, or excessive output.
- A compromised EC2 workload tries to steal the bridge token/instance role or
  invoke unauthorized Bedrock models.

Likely chains are shared-password compromise → analyst API access → evidence
disclosure, or application/container compromise → instance role → S3/Secrets/
Bedrock actions. Prompt injection alone should terminate at the schema/verdict/
citation controls or deterministic fallback.

## 4. Attack surface inventory

| Surface | Principal controls |
|---|---|
| AI web route | Authentication, `intelligence.write`, same origin, 60 KB, 25 findings, schema validation, audit |
| Natural-language hunt | 500 characters, deterministic query parser, visible query |
| Evidence packaging | field allowlist, length/control normalization, no raw snapshot, injection warning |
| Private bridge | loopback listener, bearer token, 96 KB body, mode/schema allowlist, generic errors |
| Bedrock | approved inference profile, versioned Guardrail, strict structured output, low variance |
| Model response | 64 KB, JSON parse, exact keys, bounded values, citation/verdict/query checks |
| Persistence | evidence-hash cache, actor feedback, daily usage, audit metadata |
| UI | React text rendering, explicit AI/fallback labels, no execution control |

## 5. Prioritized findings

### GW-AI-01 — Shared Basic authentication remains the production identity boundary

- **Severity:** High; **confidence:** High; **status:** Confirmed inherited risk
- **Affected:** `gatewatch-aws-web.yaml`, Nginx/runtime authentication, all AI and
  non-AI authenticated routes.
- **Description/evidence:** the current deployment maps a shared Basic credential
  to one trusted application identity. AI route authorization is correctly server
  enforced, but cannot attribute or revoke individual users behind that credential.
- **Exploitation:** a leaked/reused credential gives an attacker analyst/admin
  access and the ability to inspect posture, invoke Bedrock, and perform existing
  authorized workflows.
- **Impact:** evidence disclosure, unauditable decisions, budget abuse, and broader
  application compromise.
- **Fix:** replace Basic auth with OIDC Authorization Code + PKCE, MFA, short-lived
  signed sessions, immutable subject-to-role mapping, revocation, login throttling,
  and per-user audit. Keep central permissions.
- **Validation:** credential-stuffing tests, revoked-session test, role matrix,
  unique actor audit, and direct-origin denial.
- **CWE/OWASP:** CWE-287; OWASP A07 Identification and Authentication Failures.

### GW-AI-02 — Compatibility runtime concentrates web, bridge, and AWS privileges

- **Severity:** Medium; **confidence:** High; **status:** Confirmed design gap
- **Affected:** `infrastructure/aws-web/aws-bridge.mjs`, EC2 instance role and
  container deployment in `gatewatch-aws-web.yaml`.
- **Description/evidence:** the bridge is bearer protected and loopback only, and
  Bedrock resources are scoped. However, workloads share an EC2 trust domain and
  instance role that also reaches snapshot/Jira functions.
- **Exploitation:** server-side code execution in the web/bridge host could read
  environment/service credentials or use instance permissions directly.
- **Impact:** snapshot disclosure, Jira token access, model abuse, and persistence
  within the Gatewatch account; monitored roles remain read-only.
- **Fix:** move to separate non-root ECS/Fargate tasks or equivalent, separate task
  roles, read-only filesystems, blocked IMDS, TLS-authenticated service networking,
  egress policy, and signed immutable images.
- **Validation:** task-role negative tests, IMDS denial, container escape review,
  bridge reachability from untrusted tasks, and image provenance verification.
- **CWE/OWASP:** CWE-250; OWASP A05 Security Misconfiguration.

### GW-AI-03 — Analysis accepts an analyst-supplied normalized finding package

- **Severity:** Low; **confidence:** High; **status:** Confirmed bounded integrity gap
- **Affected:** `app/api/ai/analysis/route.ts` `validFinding` and POST analysis.
- **Description/evidence:** authorized clients submit the normalized finding used
  for advisory analysis; the server reshapes and bounds it but does not rehydrate
  the fingerprint from authoritative current storage. The response cannot mutate
  findings or AWS, and budgets/audit constrain abuse.
- **Exploitation:** an analyst can submit synthetic posture text, receive an AI
  answer, and create a misleading cached/audited analysis ID.
- **Impact:** low-integrity advisory output and avoidable model spend, not a change
  to deterministic findings or another user's decision.
- **Fix:** in the Aurora/API migration, accept fingerprints and query current
  workspace-scoped findings server-side; bind cache input to snapshot/version.
- **Validation:** tamper every client finding field and confirm the server uses the
  database value; reject wrong workspace/stale fingerprints.
- **CWE/OWASP:** CWE-602; OWASP A04 Insecure Design.

### GW-AI-04 — AI records use the transitional single-workspace compatibility store

- **Severity:** Medium in multi-tenant deployment, Low in current single workspace;
  **confidence:** High; **status:** Known deployment limitation
- **Affected:** route-created D1 tables and `db/postgres/0004_bedrock_ai_analyst.sql`.
- **Description/evidence:** current queries use workspace `default`. PostgreSQL
  models workspace IDs but this migration does not independently add RLS policies.
- **Exploitation:** deploying the compatibility path as multi-tenant could allow
  an omitted predicate elsewhere to mix analysis/usage/feedback records.
- **Impact:** cross-tenant metadata/output disclosure and budget interference.
- **Fix:** keep the current deployment single-workspace. Before multi-tenancy,
  require transaction workspace context and FORCE RLS for all AI tables using the
  central PostgreSQL policies; rehydrate findings under the same context.
- **Validation:** missing/wrong/empty workspace tests under the runtime DB role.
- **CWE/OWASP:** CWE-862; OWASP A01 Broken Access Control.

## 6. Combined-risk scenarios

The highest practical chain is GW-AI-01 plus GW-AI-02: stolen shared credentials
provide application access; an independent server dependency flaw could then turn
that foothold into the combined instance role. OIDC/WAF reduces entry likelihood;
separate tasks/roles reduces blast radius. GW-AI-03 plus GW-AI-04 matters only if
the compatibility deployment is incorrectly expanded to multi-tenancy.

## 7. Dependency and configuration risks

`@aws-sdk/client-bedrock-runtime` is versioned in the lockfile. Production
dependency audit must remain zero; current development-tool advisories must not be
misrepresented as deployed runtime findings. CloudFormation validation, cfn-lint,
IAM Access Analyzer, SBOM/signing, image scan, Guardrail version output, and a
negative unrelated-model invocation test are release evidence.

## 8. Secure design gaps

Residual defense-in-depth work is individual identity, WAF/rate limiting at the
edge, TLS to origin, isolated task roles, centralized immutable audit, enforced
retention/legal hold, Aurora RLS, and server rehydration of finding fingerprints.
Model invocation logging should retain metadata, not full prompts/outputs, unless
an approved encrypted data-retention policy explicitly requires content logging.

## 9. Remediation roadmap

1. **Before hostile production:** OIDC/MFA, WAF, origin TLS, direct-origin denial,
   signed images, non-root isolated task roles, and immutable audit.
2. **Before multi-tenancy:** Aurora server-side finding lookup, FORCE RLS on all AI
   tables, workspace-bound caches/budgets, and cross-tenant integration tests.
3. **Continuous:** feedback evaluation, adversarial fixtures, Access Analyzer,
   dependency/SBOM scanning, cost/latency alarms, and quarterly Guardrail review.

## 10. Security test plan

The executable regressions are in `tests/ai-security-analyst.test.mjs`; the full
hostile service and AWS integration matrix is in `SECURITY_TEST_PLAN.md`. Release
requires schema/citation/verdict mutation tests, prompt-injection fixtures, atomic
budget concurrency, role denial, scoped-IAM negatives, deterministic failure, and
rendering tests.

## 11. Open questions and assumptions

- Current deployment is intentionally single-workspace and access restricted.
- AWS Bedrock data-processing/retention settings must match the customer's policy.
- The approved US inference profile is permitted for all evidence classifications.
- The target OIDC provider, WAF rules, audit account, and ECS/Fargate runtime are
  not yet selected/deployed.
- No automated training, model-driven decision, or AWS mutation is authorized.
