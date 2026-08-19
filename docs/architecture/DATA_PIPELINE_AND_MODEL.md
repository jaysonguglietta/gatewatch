# Data pipeline and model

## Canonical identities

Never identify a resource with only `sg-...`. Security-group identifiers are
unique only within an account/Region context. The canonical external identity
is the full AWS ARN:

```text
arn:<partition>:ec2:<region>:<account-id>:security-group/<security-group-id>
```

The partition is preserved from observed AWS evidence (`aws`, `aws-us-gov`, or
`aws-cn`). Gatewatch synthesizes an ARN only when a validated 12-digit account,
Region, and security-group ID are all present; otherwise it marks the ARN as
unresolved. VPC is retained as separate configuration context. An observation
is additionally scoped by `workspace_id` and `run_id`. Finding fingerprints
include the canonical resource identity plus the normalized rule or policy
signature so state survives repeated observations and reopens.

## Shard contract

Top-level inventory shard fields:

| Field | Meaning |
|---|---|
| `schemaVersion` | `2.0` |
| `evidenceType` | `security-group-inventory-shard` |
| `runId` | UUID shared by the organization run |
| `observedAt` | UTC time used for every observation in the shard |
| `target` | Account, name, Region, and target ID |
| `coverage` | Group/rule/ENI/route/subnet/NACL/IGW counts |
| `securityGroups` | Normalized groups, rules, attachments, tags, and network evidence |

The raw shard is authoritative. Normalized rows can be rebuilt from S3.
Network evidence version 2 records IPv4 and IPv6 IGW routes separately, public
address counts, NACL evidence, and per-ENI direct-path counts. Consumers must
derive exposure from these raw prerequisites and must not trust the legacy
aggregate `state` field by itself.

## Data flow

S3 sources arrive through object events. Azure Data Explorer sources use a
timestamp checkpoint and a five-minute dispatcher that publishes source IDs to
an SQS FIFO queue. Up to 25 Lambda workers call the private source sync endpoint;
atomic per-source leases prevent scheduled and manual overlap. Both paths emit
the same bounded `aws_evidence_records` model, source lineage, and stable
fingerprints. ADX checkpoints combine the source timestamp with a deterministic
SHA-256 row hash so equal-timestamp batches resume without gaps; neither path is
allowed to overwrite raw evidence.

```mermaid
sequenceDiagram
  autonumber
  participant Schedule as EventBridge
  participant SFN as Step Functions
  participant Discovery as Discovery Lambda
  participant Worker as Account worker
  participant Member as Member account APIs
  participant S3 as Evidence S3
  participant DDB as Run-state DynamoDB
  participant Queue as SQS
  participant Ingest as Ingestion Lambda
  participant DB as Aurora PostgreSQL

  Schedule->>SFN: start execution
  SFN->>Discovery: discover selected OUs
  Discovery->>S3: put targets.json
  Discovery->>DDB: run + pending accounts
  SFN->>Worker: distributed item per account
  Worker->>Member: STS AssumeRole + EC2 Describe APIs
  loop enabled Regions (bounded)
    Worker->>S3: put inventory.json.gz
    Worker->>DDB: succeeded/failed target
    S3-->>Queue: Object Created via EventBridge
    Queue->>Ingest: object reference
    Ingest->>S3: bounded read + checksum
    Ingest->>DB: atomic normalized observations
  end
  SFN->>DDB: query run state through finalizer
  SFN->>S3: immutable manifest + latest pointer
  S3-->>Queue: manifest event
  Ingest->>DB: finalize run and coverage
```

For ADX, the AWS bridge exchanges a five-minute AWS workload assertion for a
short-lived Entra token. Legacy sources can temporarily use an isolated
per-source Secrets Manager entry. The bridge discovers the table schema and
executes generated read-only KQL, returning at most 1,000 rows/5 MB. The
application validates five mapped samples through the selected AWS parser,
then validates every synchronized record shape, applies account/Region scope,
inserts duplicate-safe normalized evidence, and only then advances the source
checkpoint. Preview and schema queries never persist rows. A scheduled freshness
evaluator compares the newest successful event-time checkpoint to the source
objective and maintains one open or resolved alert per source.

## PostgreSQL entities

```mermaid
erDiagram
  WORKSPACES ||--o{ ORGANIZATION_COLLECTION_RUNS : owns
  ORGANIZATION_COLLECTION_RUNS ||--o{ ORGANIZATION_COLLECTION_TARGETS : contains
  ORGANIZATION_COLLECTION_RUNS ||--o{ SECURITY_GROUP_OBSERVATIONS : captures
  SECURITY_GROUP_OBSERVATIONS ||--o{ SECURITY_GROUP_RULE_OBSERVATIONS : contains
  WORKSPACES ||--o{ INVENTORY_SHARD_OBJECTS : ingests
  WORKSPACES ||--o{ FINDINGS : evaluates
  FINDINGS ||--o| FINDING_WORKFLOWS : triaged_as
  FINDING_WORKFLOWS ||--o{ FINDING_EVENTS : records
  FINDING_WORKFLOWS ||--o| FINDING_JIRA_LINKS : tracks

  ORGANIZATION_COLLECTION_RUNS {
    uuid workspace_id PK
    uuid run_id PK
    text status
    numeric coverage_percent
    timestamptz completed_at
  }
  ORGANIZATION_COLLECTION_TARGETS {
    uuid run_id PK
    text account_id PK
    text region PK
    text status
    text object_key
    text checksum_sha256
  }
  SECURITY_GROUP_OBSERVATIONS {
    uuid run_id PK
    text account_id PK
    text region PK
    text security_group_id PK
    jsonb tags
    jsonb attachments
    jsonb network_evidence
  }
  SECURITY_GROUP_RULE_OBSERVATIONS {
    text security_group_id PK
    text rule_id PK
    text direction
    text peer
    boolean internet_wide
  }
```

### Raw evidence and ledgers

- `inventory_shard_objects` provides duplicate detection, checksum, status, and
  failure code for each S3 key/version.
- `ingested_objects` performs the same role for CloudTrail and Config sources.
- Raw objects are not copied into PostgreSQL.
- The browser batch importer uses SHA-256 file hashes to prevent importing an
  identical file twice in one session. Stable normalized-record fingerprints
  suppress repeated evidence across files; Config history and snapshot records
  share one fingerprint family so the same configuration item is counted once.
- Consolidated findings use the full security-group ARN as the canonical key
  when resolvable and retain `account_id + region + security_group_id` as the
  explicit unresolved fallback. Direct security-group references, Config relationships, and
  known inventory attachments are the only accepted correlation paths.
  Unmatched records remain visible and do not affect a group's risk score.

### Observations and current views

- `security_group_observations` stores group identity, tags, attachment evidence,
  counts, and network evidence for one run.
- `security_group_rule_observations` stores individual normalized peers and an
  explicit `internet_wide` flag.
- `current_security_groups` and `current_security_group_rules` select the newest
  usable observation without deleting historical rows.

### Attribution and history

- `config_items` stores normalized AWS Config items and resource history.
- `cloudtrail_events` stores only security-group-relevant management events.
- `aws_evidence_records` stores bounded normalized fields and the original AWS
  record payload for Flow Logs, network analyses, service access logs, and
  managed security findings. Its evidence class prevents observed traffic,
  static reachability, service access, and threat findings from being conflated.
- `security_group_rule_versions` provides valid-from/valid-to state.
- `gatewatch_correlate_cloudtrail_event` connects a successful change to a rule
  observation within a bounded time window.

### Human governance

`finding_workflows`, `finding_events`, `resource_reviews`, exception records,
Jira links, campaigns, remediation requests, and audit events are durable human
state. Re-normalizing AWS evidence must never delete this history.

## Idempotency and ordering

- S3 and EventBridge are at-least-once; object ledgers use key plus version.
- Shards and manifests may arrive in either order.
- A run placeholder is created when the first shard arrives.
- A manifest upsert finalizes counts without invalidating late shard writes.
- Observation primary keys include run ID, making replay safe.
- Current views order by source observation time, not ingestion time.

## Retention

Recommended starting policy:

| Data | Default | Rationale |
|---|---:|---|
| Immutable S3 run evidence | 400 days | Year-over-year audit and incident lookback |
| Step Functions result objects | 30 days | Debugging only |
| CloudTrail/Config normalized history | 400 days | Match evidence window |
| Current observations | Indefinite while resource exists | Daily posture |
| Human review and audit decisions | Policy-defined, usually 3–7 years | Governance evidence |
| Application logs | 90 days hot, longer in security archive | Operational and incident response |

Retention requires scheduled database maintenance and legal-hold semantics before
multi-tenant production; changing an admin setting alone is not a purge control.
