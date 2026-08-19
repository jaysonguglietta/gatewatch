# Gatewatch

Gatewatch is an AWS security-group access dashboard focused on identifying
rules that may be too broad. Its primary inventory highlights `0.0.0.0/0`,
`::/0`, broad CIDRs, all-traffic permissions, and wide port ranges across
ingress and egress. It correlates those rules with policy intent,
effective connectivity, VPC Flow Log usage, CloudTrail provenance, attached
resources, and vulnerability context.

## Product surfaces

- A closed-loop **Exposure Operations** workspace that coordinates AWS-native
  reachability verification, Security Hub exposure-trait reconciliation,
  attack-graph choke points, three-mode remediation delivery, automatic
  re-verification, owner actions, incident paths, policy packs, extension
  governance, executive narratives, and confirmed-exposure SLOs

- An **Organization Operations** plane for AWS Organizations account metadata,
  regional evidence-health heatmaps, temporal finding state, reversible evidence
  correlation, recurring monitors, governed exports, retention, legal holds, and
  versioned risk scoring

- A server-paginated, split-pane **Daily Findings Workspace** with keyboard
  triage, auto-advance, server-backed undo, session progress, clustering, and
  new/overdue/expiring/reopened workload counters
- An exposure-first **Fix First** queue that consolidates contributing records
  into one security-group work item, ranks confirmed public paths ahead of
  evidence gaps and internal-only risk, and keeps the full ARN visible
- Guided hunts for public administration/database/development ports, IPv6,
  all-traffic rules, active public traffic, unapproved changes, internal lateral
  reach, default groups, stale groups, exceptions, recurrence, and missing evidence
- A transparent plain-language hunt assistant that produces an inspectable,
  editable structured query rather than an opaque model decision
- An optional Amazon Bedrock analyst for evidence-cited finding explanations,
  daily digests, cluster briefs, natural-language hunt translation, and
  review-only remediation drafts. A versioned Guardrail, strict JSON schema,
  citation checks, atomic daily budgets, seven-day cache, feedback, and a
  deterministic fallback keep AI output advisory and auditable
- Organization, OU, account, region, environment, owner, severity, workflow, and
  effective-internet exposure
  scoping designed for hundreds of AWS accounts, plus shareable URL filters and
  internet/no-internet sorting, personal queues, and personal or team saved views
- Field-aware Daily Findings search across full security-group ARN, group ID/name,
  account ID/name, Region, VPC, ingress/egress rule, protocol, port, source CIDR,
  ownership, attached resources and tags, evidence state, workflow, and numeric
  risk/confidence/age comparisons, plus intent, approval ticket, change approval,
  Flow Log coverage, observed flows, rule ID, and attached-asset criticality
- A visual query composer with field/value autocomplete, `AND`/`OR`/`NOT`
  expressions, parentheses, history and recurrence predicates, matched-clause
  explanations, dynamic result facets, correlated raw-evidence scope, monitored
  searches, complete-result exports, and guarded search-backed bulk workflows
- Finding-level follow-up, acknowledgement, accepted-risk, and resolution
  workflows with structured reasons, evidence freshness gates, bulk guardrails,
  mandatory rationale, owners, review dates, tickets, compensating controls,
  expiration, evidence snapshots, and append-only history
- A persistent investigation pane with effective rules, explainable risk,
  a five-step exposure truth strip, evidence-readiness checklist, policy mapping,
  exact before/after change, blast radius, AWS deep links, remediation package,
  raw normalized evidence, notes, and the complete decision timeline
- Exposure-by-criticality matrix and security outcome measures for confirmed
  critical assets, exposure hours, reopened groups, tracked exceptions,
  decision-ready evidence, and potential risk reduction
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
- Local multi-file IaC security review for CloudFormation YAML/JSON and
  Terraform HCL/JSON. Gatewatch consolidates inline and standalone rules by
  proposed security group, reports exact file/resource/line evidence, evaluates
  public-path signals, searches and filters results, and exports review-ready CSV
  without executing templates, Terraform, providers, modules, or external data
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
  ARN-identified consolidated finding per account, Region, and security group,
  with field-aware search, account/Region/source filters, grouping, sorting,
  pagination, and filtered CSV export for organization-scale review
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
- Administrator configuration for AWS evidence in S3 or Azure Data Explorer,
  including prefix-scoped IAM templates, database/table selection, bounded row
  previews, live connection verification, checkpointed synchronization,
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
Conversely, zero observed flows never proves a path is safe: Gatewatch presents
Flow Logs as corroborating usage evidence and bases exposure on route, attachment,
public-address, network-control, and reachability evidence.

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
The static IaC parsing and safety model is documented in
[`docs/architecture/IAC_SECURITY_REVIEW.md`](docs/architecture/IAC_SECURITY_REVIEW.md).
The Bedrock data boundary, model controls, IAM policy, failure behavior, and
operating procedure are documented in
[`docs/architecture/BEDROCK_AI_ANALYST.md`](docs/architecture/BEDROCK_AI_ANALYST.md).
The ADX credential boundary, fixed KQL shape, mapping, checkpoint, and operating
procedure are documented in
[`docs/architecture/AZURE_DATA_EXPLORER.md`](docs/architecture/AZURE_DATA_EXPLORER.md).

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
transactional database. Apply the production migrations in filename order from
`db/postgres/`: `0001_gatewatch_aws.sql` creates the evidence base and
`0002_organization_operations.sql` adds the organization operating plane and
workspace isolation, and `0003_finding_search.sql` adds the bounded search,
temporal-history, and JSONB/trigram indexes used by the organization-scale
findings workflow. `0004_bedrock_ai_analyst.sql` adds model analysis, feedback,
and daily usage records without copying raw evidence. `0005_security_governance.sql`
adds forced tenant isolation, immutable audit archival, retention, and legal
holds. `0006_exposure_operations.sql` adds verification runs, provider
correlations, graph edges, remediation plans, owner actions, incidents, policy
packs, outcome SLOs, and enrichment extensions. `0007_azure_data_explorer_sources.sql`
adds provider-aware ADX metadata and a
forced-RLS checkpoint table. Raw objects remain in the configured S3 bucket or ADX table;
normalized events, configuration items, traffic observations, network
analyses, service access, managed findings, current rule versions, findings,
and evidence references are stored in Aurora.

The migration runner fails closed unless every public relation containing a
`workspace_id` column has both row-level security enabled and forced.

Open **Reports → Organization operations** to manage account context, inspect
regional evidence health and finding lifecycle state, resolve evidence to a
canonical security-group ARN, create recurring monitors and governed exports,
and administer retention, legal holds, and versioned risk scoring. Operational
details and role boundaries are documented in
[`docs/architecture/ORGANIZATION_OPERATIONS.md`](docs/architecture/ORGANIZATION_OPERATIONS.md).

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
- Add an Azure Data Explorer source by choosing the AWS evidence type, cluster,
  database, table, timestamp column, and complete-row or JSON payload mapping
- Store a dedicated Entra application credential in the isolated AWS bridge,
  test database viewer access, preview five rows, and activate five-minute polling
- Generate a least-privilege cross-account read-role template
- Validate source structure locally and perform live STS/S3 tests when an AWS
  runtime identity is present
- Gate activation and backfills on a successful live connection test
- Review ingestion runs and administrative audit history
- Manage application roles and normalized-data retention
- Configure Jira reconciliation and notification routing
- Inspect the Bedrock analyst model, Guardrail version, availability, personal
  and workspace usage budgets, and the immutable human-approval boundary

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

ADX client secrets are likewise never stored in the application database. The
deployed AWS bridge writes a separate credential entry to a retained Secrets
Manager secret, obtains a short-lived Entra token, and executes only generated,
parameterized, bounded read queries. Local development reports runtime
verification pending until that bridge is available.

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

The ready-to-upload mixed evidence pack at `samples/aws-evidence-batch/`
contains 14 synthetic AWS files spanning Config, CloudTrail, VPC Flow Logs,
network analysis, service access, GuardDuty, and Security Hub. Upload the 14
numbered files together; `manifest.json` documents checksums and expected
consolidation behavior. Regenerate and verify the pack with
`npm run sample:aws-evidence`.

The detailed workflows, trust boundaries, edge cases, and completion criteria
for the AWS ingestion round are documented in `docs/PRODUCT_BRIEF.md`.
