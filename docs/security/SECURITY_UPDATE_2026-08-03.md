# Security implementation update — August 3, 2026

This addendum preserves the July 31 audit as a historical baseline. “Implemented”
below means code and regression coverage exist on the current branch; it does
not mean the finding is closed. High-severity closure still requires deployment
evidence and independent validation under the roadmap acceptance criteria.

## Implemented in this architecture round

| Finding | Code status | Evidence | Residual work |
|---|---|---|---|
| GW-02 inconsistent mutation roles | Materially improved | Central named permission matrix is enforced by findings, reviews, governance, intelligence, and remediation mutations; admin routes remain admin-only | Complete every route/action and role × action integration tests; move identity to immutable OIDC subject |
| GW-03 workflow type confusion | Implemented before this round | Existing record is loaded; stored kind/subject are immutable; self-approval check uses stored creator | Central transition matrix and role/action integration tests |
| GW-04 generated-template injection | Implemented | `sourceAccessCloudFormation` builds a typed object and JSON serializes it; external ID/prefix controls added | Run cfn-lint and Access Analyzer in CI/target account; independent exploit replay |
| GW-05 mutable artifact | Materially mitigated | Web stack requires exact S3 VersionId and SHA-256; installer verifies before unzip | Signed image/provenance, non-root immutable runtime, release-only artifact writer |
| GW-09 CSV formula injection | Implemented | All client/server exports use `lib/csv.ts` formula neutralization | Cross-application Excel/LibreOffice/Sheets validation |
| GW-10 unverified snapshot | Implemented for legacy read path | Bridge retrieves manifest first and constant-time verifies SHA-256, snapshot ID, and completeness | Asymmetric KMS manifest signatures and version-pinned snapshot references |
| GW-14 message provenance | Materially improved | Exact evidence bucket/key grammar, EventBridge rule ARN/source account queue policy, schema/account/Region/run binding, duplicate ledger | Signed internal message attributes and workspace/source cryptographic binding |

## New collection-plane controls

- One service-managed StackSet role with EC2 `Describe*` permissions only.
- Separate discovery, worker, finalizer, and ingestion IAM roles.
- Step Functions Distributed Map isolates member-account failures.
- Per-account/Region target health prevents missing evidence from appearing clean.
- KMS encryption, TLS-only bucket access, versioning, checksums, retained evidence,
  and DynamoDB point-in-time recovery.
- Bounded compressed/decompressed bytes, groups, rules, attachments, manifest
  targets, and database batches.
- Transactional observation/target writes and duplicate-safe object ledgers.

## New analyst-workflow controls

- Structured disposition reasons are server allowlisted by outcome; arbitrary
  client reason strings are rejected.
- Acknowledgement, accepted risk, and resolution require current observed
  evidence at or above the confidence threshold. Live evidence must also be
  complete and no more than 24 hours old.
- Accepted risk remains administrator-only, time-bound, ticket-linked, and
  protected by compensating controls. Expired decisions return to the reopened queue.
- Resolution requires explicit remediation evidence and automatically reopens
  when a later organization observation detects the finding again.
- Bulk sizes, dates, notes, fingerprints, and saved-view filters are bounded and
  revalidated by the API. Jira writes require the findings-triage permission and
  remain duplicate safe.
- Team saved views are owner controlled; a shared view cannot become another
  user's default or be deleted by a non-owner.
- Undo restores only an actor-bound server snapshot through an opaque token.
  Snapshots expire after five minutes and expired rows are cleaned during triage.

## Production blockers that remain

1. GW-01: replace shared Basic Auth with individual OIDC identities, MFA, expiry,
   revocation, and immutable identity subjects.
2. GW-02: apply one named permission and state-transition policy to every API
   mutation and complete role × action tests.
3. GW-05/GW-06: build a signed minimal production image in CI; remove source
   build and root Docker operation on the EC2 host; separate workload roles.
4. GW-07/GW-08: TLS to origin, WAF, streaming request limits, quotas, and rate controls.
5. GW-11/GW-12/GW-13: enforced retention/legal hold, immutable centralized audit,
   non-owner database roles, forced RLS, deletion protection, and restore drills.

Gatewatch remains pre-production for authoritative organization governance until
these items are independently validated.
