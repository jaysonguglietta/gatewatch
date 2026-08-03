# Gatewatch AWS ingestion product brief

## Target users

- Cloud security and network-security administrators
- Security analysts investigating overly broad security-group rules
- Application owners completing access reviews
- Auditors requiring evidence lineage and decision history

## Core problem

AWS security-group configuration, change identity, ownership, and review evidence
are fragmented across AWS Config, CloudTrail, resource relationships, and
governance workflows. Gatewatch turns those inputs into a current, explainable
review queue with special emphasis on `0.0.0.0/0`, `::/0`, all-traffic rules,
broad CIDRs, and wide port ranges.

## Primary workflows

1. An administrator configures a read-only S3 evidence source.
2. Gatewatch validates role assumption, prefix listing, object reading, and KMS access.
3. A historical backfill and continuous object ingestion populate normalized state.
4. Config items confirm current security-group rules and resource relationships.
5. CloudTrail events attribute successful changes to actors and delivery channels.
6. Analysts review findings, record decisions, and export evidence.
7. Analysts acknowledge understood exposure with a durable explanatory note or
   assign an owner and due date for follow-up.
8. Administrators approve time-bound accepted risk with compensating controls,
   ticket linkage, and expiration.
9. Stable finding fingerprints preserve history when a finding resolves or reopens.
10. Gatewatch proposes least-privilege rules and explains their simulated impact.
11. Owners accept SLA-bound queues or request independently approved exceptions.
12. CI evaluates proposed IaC changes before AWS deployment.
13. Administrators monitor lag, retries, quarantine, retention, access, and audit history.

## Main views

- Broad access and explainable findings
- Default daily findings inbox with bulk triage and server pagination
- Organization, OU, account, region, owner, and saved-view scoping
- Finding investigation drawer with notes and append-only decision history
- Effective exposure and attack-path intelligence
- Least-privilege recommendations, hygiene, and IaC guardrails
- Exposure drift inbox with CloudTrail provenance
- Owner inbox, expiring exceptions, and native-control reconciliation
- Security-program outcome metrics
- Access explorer and path evidence
- Reviews, applications, policies, campaigns, and remediation
- CloudTrail local import
- Coverage and confidence boundaries
- Admin overview, data sources, ingestion runs, access, retention, and audit

## Key data models

`ingestion_sources`, `ingestion_runs`, `ingested_objects`, `cloudtrail_events`,
`config_items`, `aws_resources`, `security_group_rule_versions`, `findings`,
`exposure_verdicts`, `rule_recommendations`, `exposure_drift_events`,
`ownership_assignments`, `exception_requests`, `control_evaluations`,
`hygiene_findings`, `iac_guardrail_evaluations`, `program_metric_snapshots`,
`finding_workflows`, `finding_events`, `saved_finding_views`,
`finding_observations`, `resource_reviews`, `resource_review_events`,
`access_policy_versions`, `campaign_items`, `remediation_requests`,
`integration_deliveries`, `verification_runs`, `finding_jira_links`,
`product_workflow_records`, `user_roles`, and `audit_events`.

## Important edge cases

- S3 deliveries are duplicated, delayed, and out of event-time order.
- A successful CloudTrail request may precede Config confirmation.
- Failed CloudTrail API calls must not update current state.
- Config configuration may be a JSON-encoded string.
- Source buckets may use customer-managed KMS keys.
- Object decompression can exceed the compressed-size safety boundary.
- Prefixes can contain multiple accounts, regions, and delivery formats.
- Relationship data can be incomplete or indirect.
- Security-group IDs can be reused across accounts and regions; workflow keys
  must include account, region, VPC, and resource identity.
- A paused or unverified source cannot start a backfill.
- Broad rules can be unreachable because routing or public-address evidence is absent.
- Stale evidence must lower confidence instead of silently producing a definitive verdict.
- An exception requestor must not approve or reject their own request.
- A failed workflow write must not present a success toast or optimistic status.
- IaC enforcement changes require an administrator; evaluation remains read-only.
- The same finding can disappear and reopen without losing notes or ownership.
- Bulk actions are capped and must produce one auditable event per finding.
- Acknowledgement documents analyst judgment but does not suppress monitoring.
- Accepted risk requires justification, a ticket, compensating controls, and expiration.

## Assumptions

- Raw evidence remains in a customer-controlled S3 bucket.
- AWS access uses STS and dedicated read-only roles; long-lived access keys are prohibited.
- Aurora PostgreSQL is the AWS production system of record for normalized data.
- The current D1 implementation remains a local/Sites compatibility adapter.
- Authentication is provided by the hosting identity layer now and Cognito or
  IAM Identity Center in the future AWS deployment.

## Done for this version

- Complete local Admin workflow and durable configuration schema
- Real AWS-capable connection test with a safe configuration-only local state
- Least-privilege cross-account IAM template generation
- Config parser and CloudTrail/Config correlation library
- Idempotent bounded AWS ingestion worker with partial-batch failure reporting
- Aurora production schema, SQS/DLQ, Lambda, KMS, alarms, and event forwarding IaC
- Operational views for sources, runs, roles, retention, and audit history
- Effective-exposure verdicts and prioritized attack paths
- Simulated least-privilege recommendations and rule-hygiene workflows
- New-exposure drift triage with durable dispositions
- Owner SLA queues and independently governed, expiring exceptions
- Native control mapping, IaC pre-change decisions, and program outcome reporting
- Aurora domain tables for intelligence, governance, guardrails, and metrics
- Daily inbox, organization scope, shareable filters, and saved views
- Finding-level notes, bulk follow-up, acknowledgement, accepted risk, and history
- Stable finding identity and reopening-ready workflow state
- Live route, subnet, public-address, and NACL evidence from the AWS collector
- Durable policy previews and activation, evidence-backed campaign decisions,
  remediation approval and post-change verification
- Bidirectional Jira status reconciliation, CI evaluation intake, and a
  notification outbox with an explicit delivery-adapter boundary
- Historical snapshot metrics and SHA-256-manifested auditor evidence packages
