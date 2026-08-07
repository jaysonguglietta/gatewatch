# Gatewatch

Gatewatch is an AWS security-group access dashboard focused on identifying
rules that may be too broad. Its primary inventory highlights `0.0.0.0/0`,
`::/0`, broad CIDRs, all-traffic permissions, and wide port ranges across
ingress and egress. It correlates those rules with policy intent,
effective connectivity, VPC Flow Log usage, CloudTrail provenance, attached
resources, and vulnerability context.

## Product surfaces

- A server-paginated, split-pane **Daily Findings Workspace** with keyboard
  triage, auto-advance, server-backed undo, session progress, clustering, and
  new/overdue/expiring/reopened workload counters
- Organization, OU, account, region, environment, owner, severity, and workflow
  scoping designed for hundreds of AWS accounts, plus shareable URL filters and
  personal queues, shareable URL filters, and personal or team saved views
- Finding-level follow-up, acknowledgement, accepted-risk, and resolution
  workflows with structured reasons, evidence freshness gates, bulk guardrails,
  mandatory rationale, owners, review dates, tickets, compensating controls,
  expiration, evidence snapshots, and append-only history
- A persistent investigation pane with effective rules, explainable risk,
  policy mapping, exact before/after change, attached resources, AWS deep links,
  remediation guidance, notes, and the complete decision timeline
- Five task-oriented workspaces—Findings, Inventory, Governance, Reports, and
  Administration—with contextual navigation to every existing capability
- Rule-level broad-access overview with search, direction/category filters, and
  CSV export
- Effective-exposure verdicts that distinguish a syntactically broad rule from
  a confirmed Internet path, internal-only reachability, unreachable exposure,
  or incomplete evidence
- Attack-path prioritization that combines reachability, sensitive data,
  privileged identities, vulnerable workloads, and practical choke points
- Least-privilege rule recommendations with observed-traffic basis, projected
  path reduction, traffic-preservation confidence, approval, dismissal, and
  rollback guidance
- A CloudTrail and Config-backed exposure-drift inbox with actor, delivery
  channel, before/after rule evidence, recurrence, and disposition workflows
- Owner work queues with SLA, evidence coverage, accountable application
  context, and durable acceptance state
- Expiring exception requests with compensating controls, ticket linkage,
  independent approval, rejection, revocation, and self-approval prevention
- AWS Security Hub/native-control reconciliation with Gatewatch evidence and
  policy-specific discrepancy explanations
- A rule-hygiene center for unused groups, duplicate rules, stale references,
  ineffective egress, and quota pressure
- Pre-change IaC guardrails with pass/warn/block verdicts, projected risk,
  read-only PR evidence, and administrator-controlled enforcement mode
- Executive program metrics for exposure reduction, reachable critical assets,
  remediation speed, workflow adoption, evidence coverage, and CSV reporting
- Posture context ranked by reachable risk
- Explainable findings inventory with search, filters, and CSV export
- Interactive connectivity paths with traffic and attachment evidence
- Deterministic "can X reach Y?" access questions with saved investigations
- Versioned access policies with human-readable intent and YAML export
- Application, owner, data-classification, and crown-jewel context
- Choke-point remediation ranked by paths eliminated and traffic preserved
- Recertification campaigns with reviewer progress and evidence packages
- Point-in-time connectivity history with path and risk diffs
- Mixed-batch drag-and-drop import for AWS JSON, JSON.GZ, JSONL, and text logs.
  Gatewatch auto-detects 16 AWS evidence types, suppresses duplicate files and
  records, correlates inventory and Config relationships, and produces one
  consolidated finding per account, Region, and security group
- Dry-run handoffs for Network Access Analyzer, Reachability Analyzer, Firewall
  Manager, Security Hub, and Terraform
- Durable review decisions, ticket references, evidence snapshots, and
  expiring exceptions
- CloudTrail before/after change evidence and delivery-channel attribution
- Read-only remediation simulation with transparent risk factors
- Collection coverage for Config, CloudTrail, Flow Logs, Inspector, Security
  Hub, and Terraform access manifests
- Organization-scale collection health with explicit run, account, and
  account/Region status, attention filters, and pagination for 500+ accounts
- Administrator configuration for CloudTrail and AWS Config S3 sources,
  including prefix-scoped IAM role templates, live-capable STS/S3 verification,
  historical backfill controls, ingestion health, roles, retention, and audit
- AWS production foundations for Aurora PostgreSQL Serverless v2, bounded and
  idempotent SQS/Lambda ingestion, Step Functions backfills, dead-letter
  handling, KMS encryption, and operational alarms
- Step Functions Distributed Map collection with service-managed read-role
  StackSets, immutable account/Region evidence shards, and explicit manifests

When the AWS snapshot binding is configured, inventory, findings, exposure
verdicts, ownership queues, recommendations, collection coverage, and program
metrics are derived from that snapshot. Without the binding, the application
uses an explicitly labeled demonstration dataset; demonstration records are
never presented as live evidence.

The trust layer uses account-, region-, VPC-, and resource-scoped keys,
persists first/last observation and reopen history, and records the source,
limitations, confidence, and snapshot identity behind each finding. The
collector includes route-table, internet-gateway, public-address, subnet, and
broad NACL evidence. A configured network path does not claim that a service
is listening or that a connection succeeded without traffic evidence.

## Local development

Prerequisites: Node.js `>=22.13.0`.

```bash
npm install
npm run dev
```

Useful checks:

```bash
npm run build
npm run lint
node --test tests/rendered-html.test.mjs
```

The analyst workflow and decision controls are documented in
[`docs/SECURITY_ANALYST_WORKSPACE.md`](docs/SECURITY_ANALYST_WORKSPACE.md).

Review decisions are persisted through the configured Cloudflare D1 `DB`
binding. Stable finding fingerprints, current analyst workflow, append-only
notes/history, and saved views are stored separately so repeated observations
do not create duplicate daily work. Recommendations, drift dispositions, owner
tasks, exceptions, hygiene actions, and IaC guardrail modes use the same durable
platform. Custom access policies, recertification campaigns, administrator
source configuration, local ingestion ledgers, roles, retention settings, and
audit events also use that compatibility store. Remediation requests, approval,
post-change verification, Jira reconciliation, IaC evaluations, notification
outbox entries, historical metrics, and auditor evidence packages are durable
as well. Schema changes live in
`db/schema.ts` and generated migrations are stored in `drizzle/`.

The AWS target uses Aurora PostgreSQL rather than copying raw logs into a
transactional database. The production schema is
`db/postgres/0001_gatewatch_aws.sql`. Raw objects remain in the configured S3
bucket; normalized events, configuration items, traffic observations, network
analyses, service access, managed findings, current rule versions, findings,
and evidence references are stored in Aurora.

The current-state authority is the distributed EC2 inventory collector. AWS
Config supplies configuration history, CloudTrail supplies actor/change
attribution, route/NACL/public-address evidence supplies configured
reachability, and Flow Logs supply observed use. These claims remain separate.

## AWS administration and infrastructure

Open **Admin config** in the application navigation to:

- Add S3 prefixes for CloudTrail, Config, VPC and Transit Gateway Flow Logs,
  Reachability Analyzer, Network Access Analyzer, ELB, WAF, CloudFront,
  API Gateway, Route 53 Resolver, Network Firewall, GuardDuty, Security Hub,
  and Inspector evidence
- Generate a least-privilege cross-account read-role template
- Validate source structure locally and perform live STS/S3 tests when an AWS
  runtime identity is present
- Gate activation and backfills on a successful live connection test
- Review ingestion runs and administrative audit history
- Manage application roles and normalized-data retention
- Configure Jira reconciliation and notification routing

Notification routing writes retryable, auditable outbox records. An email or
webhook delivery worker must be connected in the AWS runtime before those
records are sent externally; the UI labels this boundary rather than claiming
delivery.

CI systems can submit bounded pre-change evaluations to
`POST /api/iac/evaluate` with `Authorization: Bearer <token>` after a
32-character-or-longer `GATEWATCH_IAC_WEBHOOK_TOKEN` is configured. Interactive
requests continue to use the hosting identity and same-origin protection.

No AWS access keys are accepted or stored. Local development deliberately
reports “AWS runtime verification pending” because it does not have a Gatewatch
application role. Connection activation becomes available only after the
deployed runtime successfully assumes the configured source role, lists the
prefix, and performs a bounded object read.

AWS deployment assets are under `infrastructure/`:

- `cloudformation/gatewatch-aws-platform.yaml` — Aurora, KMS, SQS/DLQ,
  ingestion and backfill workers, Step Functions, and alarms
- `cloudformation/gatewatch-organization-collector.yaml` — Organizations
  discovery, read-role StackSet, Distributed Map workers, DynamoDB coverage,
  and immutable S3 shards/manifests
- `cloudformation/gatewatch-s3-event-forwarding.yaml` — prefix-filtered S3
  Object Created forwarding through EventBridge
- `lambda/organization-collector/` — discovery, account worker, and finalizer handlers
- `lambda/ingest/` — duplicate-safe, size-bounded AWS-native evidence worker
- `lambda/backfill/` — paginated historical discovery and enqueue worker

### Personal AWS deployment

The personal-account collector can be deployed independently of the current
Sites-hosted application runtime. It uses the named `personal` AWS CLI profile,
creates only read-only collection infrastructure, runs once each day at 12:00
UTC, and performs an initial collection after the stack is ready:

```bash
./scripts/deploy-aws-personal.sh
```

The script deploys the `gatewatch-personal-sg-collector` stack in the profile's
configured Region. Set `AWS_PROFILE`, `AWS_REGION`, or `GATEWATCH_STACK_NAME`
to override those safe defaults. It never reads or copies credentials into the
application package.

### Organization deployment

Deploy the distributed collector from an Organizations management account or
registered StackSets delegated administrator:

```bash
export AWS_PROFILE=personal
export GATEWATCH_ORGANIZATION_TARGET_IDS=r-abcd
export GATEWATCH_STACKSET_CALL_AS=SELF
./scripts/deploy-aws-organization.sh
```

Use `GATEWATCH_REGION_ALLOW_LIST` and `GATEWATCH_EXCLUDED_ACCOUNT_IDS` to scope
the rollout. The script validates the template, uploads a content-addressed
Lambda artifact, deploys the stack, and starts the initial collection.

Deploy the complete authenticated web dashboard after the collector is ready:

```bash
./scripts/deploy-aws-web.sh
```

The web stack packages the current source into a private, encrypted,
versioned artifact bucket; runs the application on an SSM-managed ARM instance;
stores the D1 compatibility database on an encrypted, automatically backed-up
EFS filesystem; and
publishes only a CloudFront HTTPS endpoint. The origin accepts traffic only
from the AWS-managed CloudFront prefix list and requires a separate generated
origin secret. The user credential is generated in Secrets Manager and is
never written to the application package or CloudFormation output.

The CloudFormation templates are source artifacts only; this repository does
not automatically deploy them. Package the Lambda directories, upload the
versioned zip files to a private artifact bucket, then provide those keys to the
platform stack. Apply the PostgreSQL migration before activating any source.

Architecture decisions, diagrams, deployment order, data contracts, capacity
guidance, migration, and operational response are documented in
[`docs/architecture`](docs/architecture/README.md).

AWS handoffs are deliberately dry-run artifacts in this version. They contain
no credentials and cannot modify AWS. The future AWS deployment should use
scoped cross-account roles, separate analysis permissions from enforcement,
and require explicit approval for each write integration.

Imported AWS files are parsed in the browser and retained only for the current
application session. A selection may contain up to 30 mixed files and a session
up to 60 files, with a 150 MB compressed batch limit. Each file is limited to
25 MB compressed, 50 MB decompressed, and 50,000 records. SHA-256 file hashes
and stable record fingerprints suppress exact duplicates; AWS Config
relationships and live inventory correlate indirect evidence. Evidence without
a defensible security-group relationship remains in an explicit unmatched queue
instead of being guessed into a finding. Original files are never uploaded or
persisted.

A deterministic 50,000-record synthetic CloudTrail log is included at
`samples/cloudtrail-security-groups-50000.json.gz`. Regenerate it with
`npm run sample:cloudtrail`.

The detailed workflows, trust boundaries, edge cases, and completion criteria
for the AWS ingestion round are documented in `docs/PRODUCT_BRIEF.md`.
