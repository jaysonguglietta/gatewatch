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

1. A central collector discovers selected organization OUs and distributes one
   isolated worker per account with bounded Region fan-out.
2. Successful account/Region scans write immutable, checksummed evidence shards;
   failed targets remain explicit in the run manifest and Coverage view.
3. An administrator configures read-only AWS-native configuration, change,
   traffic, network-analysis, service-access, and managed-finding sources.
4. Gatewatch validates role assumption, prefix listing, bounded object reading,
   and KMS access.
5. Continuous events and historical backfills populate normalized Aurora state.
6. Live APIs confirm current security groups, rules, attachments, routes, NACLs,
   and public addresses.
7. Config items provide history and CloudTrail attributes successful changes to
   actors and delivery channels.
8. Analysts confirm collection coverage, review findings, and export evidence.
9. Analysts work a keyboard-driven split queue, review correlated evidence,
   assign follow-up, acknowledge understood exposure, or resolve remediated rules.
10. Administrators approve time-bound accepted risk with compensating controls,
   ticket linkage, and expiration.
11. Stable finding fingerprints preserve history when a finding resolves or reopens.
12. Gatewatch proposes least-privilege rules and explains their simulated impact.
13. Owners accept SLA-bound queues or request independently approved exceptions.
14. CI evaluates proposed IaC changes before AWS deployment.
15. Administrators monitor lag, retries, quarantine, retention, access, and audit history.

## Main views

- Broad access and explainable findings
- Default split-pane daily review workspace with keyboard navigation,
  auto-advance, undo, bulk triage, and server pagination
- Finding and security-group-cluster queue modes with density and field controls
- Organization, OU, account, region, owner, and saved-view scoping
- Persistent finding investigation pane with risk factors, exact before/after
  configuration, attached resources, AWS deep links, and decision history
- Five top-level workspaces: Findings, Inventory, Governance, Reports, and Administration
- Effective exposure and attack-path intelligence
- Least-privilege recommendations, hygiene, and IaC guardrails
- Exposure drift inbox with CloudTrail provenance
- Owner inbox, expiring exceptions, and native-control reconciliation
- Security-program outcome metrics
- Access explorer and path evidence
- Reviews, applications, policies, campaigns, and remediation
- CloudTrail local import
- Coverage and confidence boundaries
- Organization run health with searchable account status, Region failure counts,
  freshness, evidence lineage, and explicit partial collection
- Admin overview, data sources, ingestion runs, access, retention, and audit

## Key data models

`ingestion_sources`, `ingestion_runs`, `ingested_objects`, `cloudtrail_events`,
`organization_collection_runs`, `organization_collection_targets`,
`inventory_shard_objects`, `security_group_observations`,
`security_group_rule_observations`,
`config_items`, `aws_evidence_records`, `aws_resources`,
`security_group_rule_versions`, `findings`,
`exposure_verdicts`, `rule_recommendations`, `exposure_drift_events`,
`ownership_assignments`, `exception_requests`, `control_evaluations`,
`hygiene_findings`, `iac_guardrail_evaluations`, `program_metric_snapshots`,
`finding_workflows`, `finding_workflow_details`, `finding_events`,
`finding_decision_details`, `finding_undo_snapshots`, `saved_finding_views`,
`saved_finding_view_visibility`,
`finding_observations`, `resource_reviews`, `resource_review_events`,
`access_policy_versions`, `campaign_items`, `remediation_requests`,
`integration_deliveries`, `verification_runs`, `finding_jira_links`,
`product_workflow_records`, `user_roles`, and `audit_events`.

## Important edge cases

- S3 deliveries are duplicated, delayed, and out of event-time order.
- Organization manifests and their shard events can arrive in either order.
- One account can fail role assumption while every other account succeeds.
- Region opt-in differs by account; an unavailable Region must remain an explicit
  coverage gap rather than being interpreted as a clean scan.
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
- Acknowledgement and resolution are blocked when evidence is stale, incomplete,
  inferred, or below the confidence threshold; follow-up remains available.
- Mixed bulk selections inherit the strictest evidence and approval constraint.
- Shared team views cannot become another analyst's personal default or be deleted
  by a non-owner.
- Undo snapshots are actor-bound, expire after five minutes, and are never trusted
  from client-supplied workflow state.

## Assumptions

- Raw evidence remains in a customer-controlled S3 bucket.
- AWS access uses STS and dedicated read-only roles; long-lived access keys are prohibited.
- Aurora PostgreSQL is the AWS production system of record for normalized data.
- Collection uses Step Functions Distributed Map, one worker per account,
  bounded per-account Region concurrency, and immutable S3 account/Region shards.
- The current D1 implementation remains a local/Sites compatibility adapter.
- Authentication is provided by the hosting identity layer now and Cognito or
  IAM Identity Center in the future AWS deployment.

## Done for this version

- Complete local Admin workflow and durable configuration schema
- Organization discovery, service-managed member read-role StackSet, distributed
  account workers, per-Region shards, DynamoDB coverage state, and run manifests
- Authenticated Coverage API and a searchable/paginated 500-account operator view
- Aurora shard/run/target observation schema and duplicate-safe atomic normalization
- Structured JSON cross-account CloudFormation generation, formula-safe CSV,
  snapshot checksum verification, and version/checksum-pinned web artifacts
- Real AWS-capable connection test with a safe configuration-only local state
- Least-privilege cross-account IAM template generation
- Config parser and CloudTrail/Config correlation library
- AWS-native evidence catalog, local validation, and a bounded generic evidence
  ledger for Flow Logs, path analyses, service logs, and managed findings
- Idempotent bounded AWS ingestion worker with partial-batch failure reporting
- Aurora production schema, SQS/DLQ, Lambda, KMS, alarms, and event forwarding IaC
- Operational views for sources, runs, roles, retention, and audit history
- Effective-exposure verdicts and prioritized attack paths
- Simulated least-privilege recommendations and rule-hygiene workflows
- New-exposure drift triage with durable dispositions
- Owner SLA queues and independently governed, expiring exceptions
- Native control mapping, IaC pre-change decisions, and program outcome reporting
- Aurora domain tables for intelligence, governance, guardrails, and metrics
- Daily split-pane inbox, organization scope, personal queue, shareable URL
  filters, and personal or team saved views
- Finding-level structured reasons, notes, bulk follow-up, acknowledgement,
  accepted risk, resolution, evidence gates, server-backed undo, and history
- Explainable risk factors, projected reduction, policy mapping, exact change
  comparison, attached-resource context, and direct AWS evidence links
- Security-group clustering, compact/comfortable density, selectable queue fields,
  keyboard shortcuts, auto-advance, and review-session progress
- Stable finding identity and reopening-ready workflow state
- Live route, subnet, public-address, and NACL evidence from the AWS collector
- Durable policy previews and activation, evidence-backed campaign decisions,
  remediation approval and post-change verification
- Bidirectional Jira status reconciliation, CI evaluation intake, and a
  notification outbox with an explicit delivery-adapter boundary
- Historical snapshot metrics and SHA-256-manifested auditor evidence packages
