# Gatewatch AWS architecture

Gatewatch separates collection, immutable evidence, normalization, and analyst
workflows so a failure in one AWS account cannot hide the posture of the rest of
the organization. The design targets 500+ accounts, a small analyst team, bursty
collection, and low idle cost.

## Documents

| Document | Purpose |
|---|---|
| [Organization-scale architecture](ORGANIZATION_SCALE_ARCHITECTURE.md) | Components, trust boundaries, evidence hierarchy, and design decisions |
| [Data pipeline and model](DATA_PIPELINE_AND_MODEL.md) | Shard contracts, ingestion behavior, Aurora entities, identity, and query patterns |
| [AWS deployment guide](AWS_DEPLOYMENT_GUIDE.md) | Prerequisites, packaging, stack order, parameters, validation, and rollback |
| [Organization operations](ORGANIZATION_OPERATIONS.md) | Account context, correlation, monitors, exports, retention, legal holds, scoring, and operational limits |
| [Bedrock AI security analyst](BEDROCK_AI_ANALYST.md) | Advisory AI workflows, evidence boundary, schema, IAM, guardrails, budgets, audit, and failure behavior |
| [Exposure operations](EXPOSURE_OPERATIONS.md) | AWS path verification, provider correlation, attack graph, guarded remediation, owner/incident workflows, SLOs, policies, and extensions |
| [Azure Data Explorer source](AZURE_DATA_EXPLORER.md) | Passwordless Entra federation, schema/mapping validation, bounded KQL, leased queue workers, freshness SLAs, checkpoints, and operations |
| [Operations runbook](OPERATIONS_RUNBOOK.md) | Daily checks, partial runs, failed accounts, replay, incident handling, and recovery |
| [Cost and capacity](COST_AND_CAPACITY.md) | Cost drivers, concurrency controls, capacity assumptions, and scaling signals |
| [Migration plan](MIGRATION_PLAN.md) | Safe transition from the legacy aggregate snapshot to sharded evidence and Aurora |

## Diagram sources

The Mermaid sources under [`diagrams/`](diagrams/) are intentionally text based,
reviewable in pull requests, and rendered directly by GitHub:

- [`system-context.mmd`](diagrams/system-context.mmd)
- [`collection-sequence.mmd`](diagrams/collection-sequence.mmd)
- [`trust-boundaries.mmd`](diagrams/trust-boundaries.mmd)
- [`data-model.mmd`](diagrams/data-model.mmd)

## Architecture decision summary

1. **Live AWS APIs are the current-state authority.** AWS Config supplies history,
   CloudTrail supplies actor/change attribution, route/NACL/public-address data
   supplies configured reachability, and Flow Logs supply observed use.
2. **Collection is distributed by account.** Step Functions Distributed Map
   isolates failures and caps organization-wide concurrency. Each account worker
   uses bounded regional fan-out.
3. **Evidence is immutable and sharded.** A successful account/Region scan writes
   one compressed, checksummed, KMS-encrypted S3 object. No function creates a
   500-account in-memory payload.
4. **Coverage is data, not a footnote.** DynamoDB records every run, account, and
   Region target. The final manifest includes successes and failures; the UI
   never interprets missing evidence as a passing result.
5. **Aurora stores normalized/queryable state, not raw logs.** S3 remains the
   evidence system of record. PostgreSQL stores lineage, observations, rules,
   findings, and human decisions.
6. **The browser queries bounded APIs.** The target API uses pagination and
   database filters. Loading the organization into one browser response is a
   transitional compatibility path only.
