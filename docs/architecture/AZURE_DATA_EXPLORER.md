# Azure Data Explorer log source

Gatewatch can read AWS security evidence from an Azure Data Explorer (ADX)
table and feed it into the same normalized evidence model used by S3 imports.
The connector is designed for central security teams that keep AWS logs from
hundreds of accounts in ADX while Gatewatch remains deployed in AWS.

## Administrator workflow

1. Open **Administration → Data sources → Add log source**.
2. Choose **Azure Data Explorer** and the AWS evidence type represented by the
   rows.
3. Enter the HTTPS cluster URL, database, table, tenant ID, and application ID.
4. Keep **AWS workload federation** selected unless migrating a legacy source.
5. Select **Discover schema**. Gatewatch reads the table schema and offers
   timestamp and payload columns as autocomplete choices.
6. Choose complete-row or payload-column mapping. Select **Validate five sample
   rows** and review the normalized samples and rejected-row reasons.
7. Set a 5–10,080 minute freshness objective, test the connection, activate the
   source, and run its initial synchronization.

New sources cannot activate until live schema discovery and sample-record
validation succeed. This fail-closed rule prevents a syntactically valid source
from silently polling the wrong table or producing no usable AWS evidence.

## Passwordless Entra federation

Gatewatch uses AWS IAM outbound identity federation to remove the Entra client
secret from new sources. The AWS bridge asks its regional STS endpoint for a
five-minute, RS256-signed workload token with audience
`api://AzureADTokenExchange`, then exchanges that assertion at the configured
tenant's Microsoft identity platform endpoint for an ADX access token. Neither
token is written to the application database, Secrets Manager, browser, or
logs.

### One-time AWS account setup

Outbound identity federation is an account-level AWS IAM setting. Enable it in
the account that hosts Gatewatch and retain the returned issuer URL:

```bash
aws iam enable-outbound-web-identity-federation --profile personal
```

If it is already enabled, retrieve the current issuer with:

```bash
aws iam get-outbound-web-identity-federation-info --profile personal
```

The web stack grants only its bridge runtime role `sts:GetWebIdentityToken`,
restricts the audience to `api://AzureADTokenExchange`, and caps token lifetime
at 300 seconds. The API is called through regional STS; AWS does not support it
on the global STS endpoint.

### Microsoft Entra trust

Create a dedicated Entra application and grant its service principal `viewer`
access only to the selected ADX database. In **App registrations → Certificates
& secrets → Federated credentials**, add an **Other issuer** credential with
these exact, case-sensitive values:

| Entra field | Gatewatch value |
|---|---|
| Issuer | AWS account issuer URL returned above |
| Subject | `AzureDataExplorerFederatedSubject` CloudFormation output (the bridge runtime role ARN) |
| Audience | `AzureDataExplorerFederatedAudience` output: `api://AzureADTokenExchange` |

Wildcards are not supported. A trust can be created with a mistyped subject but
will fail only during token exchange, so copy the stack outputs rather than
retyping the ARN. Microsoft can take several minutes to propagate a newly added
federated credential.

Legacy client-secret authentication remains available only for migration. Its
credential stays in the retained `AzureDataExplorerCredentialsSecret`, never
the application database. Edit a legacy source, select workload federation,
complete the Entra trust, and test it; saving the change removes that source's
stored secret. Do not add a new secret to recover a federation failure.

## Schema discovery and mapping

Gatewatch executes a fixed, read-only `getschema` query and stores the bounded
column names/types, discovery time, and schema fingerprint. It does not accept
arbitrary KQL or management commands. The mapping wizard uses the discovered
columns to autocomplete fields and suggests conventional timestamp and payload
names without saving until the administrator confirms them.

**Complete row** converts all returned columns into one JSON record. Gatewatch
adds a normalized `timestamp` field when the configured timestamp column uses a
source-specific name such as `TimeGenerated`.

**Payload column** projects the timestamp and selected dynamic, JSON, or string
column, then parses that value as the chosen AWS evidence type. Non-object or
malformed JSON is rejected and counted; Gatewatch does not guess it into a
finding.

Sample validation reads at most five rows, runs the real server-side AWS parser,
and reports accepted/rejected counts plus sanitized rejection reasons. A schema
or mapping change clears the prior validation and checkpoint so activation
requires a fresh live test. For best results, retain the original AWS field
names from CloudTrail, Config, VPC Flow Logs, Security Hub ASFF, GuardDuty, or
the other supported formats.

## Query and network security

Generated queries use identifiers restricted to letters, numbers, and
underscores. Checkpoint and row-limit values use declared KQL parameters. The
connector also enforces:

- HTTPS Microsoft Kusto hostnames only, with no URL credentials, custom ports,
  paths, query strings, fragments, redirects, or caller-selected OAuth hosts;
- authority hosts selected from the validated public, US Government, or China
  cloud Kusto suffix;
- 20-second ADX server timeout, 25-second network timeout, 5 MB response limit,
  1,000-row maximum, and 64 KB normalized payload maximum;
- bounded JSON parsing, account/Region filters, and SHA-256 fingerprints;
- compound timestamp plus stable row-hash checkpoints, preventing gaps when a
  full batch contains equal timestamps;
- checkpoint advancement only after normalized writes and malformed-row
  accounting complete;
- degraded source state and an audited failed run on synchronization failure.

Private Link clusters require DNS and network routing from Gatewatch to the
validated Kusto hostname. The allowlist deliberately rejects arbitrary private
hosts and proxy URLs.

## Horizontal polling

The five-minute scheduler is a dispatcher, not a worker. Each cycle evaluates
freshness and enqueues up to 2,000 active source IDs into an encrypted FIFO SQS
queue. A Lambda event-source mapping processes sources with up to 25 concurrent
workers. Per-source FIFO message groups preserve order, while an atomic
three-minute source lease prevents duplicate manual and scheduled work from
running concurrently.

Messages retry five times and then move to a retained FIFO dead-letter queue.
CloudWatch alarms cover dead-letter messages and a queue whose oldest message
remains above ten minutes. A busy lease returns HTTP 202 and leaves the source
checkpoint unchanged. To raise concurrency, review ADX throttling, Lambda
regional capacity, database write capacity, and cross-cloud transfer before
changing both `ReservedConcurrentExecutions` and event-source
`MaximumConcurrency`.

## Freshness objectives and alerts

Each source has a freshness objective from 5 minutes to 7 days. Gatewatch
compares the newest successfully normalized source event time with the current
time:

| State | Meaning |
|---|---|
| Unknown | No successful checkpoint exists yet |
| Healthy | Lag is below 80% of the objective |
| Warning | Lag is at least 80% but has not exceeded the objective |
| Breached | Lag exceeds the objective |

A breach opens one deduplicated, high-severity source alert. Continuing breach
checks update that alert rather than creating duplicates; recovery resolves it.
State transitions are audited once. While any source remains breached, each
scheduler cycle emits one aggregate `adx_freshness_breached` metric sample so
the CloudWatch alarm stays in ALARM; CloudWatch actions still run only when its
state changes. The source card shows state, lag, SLA, and open-alert summary.

Freshness represents event-time progress, not merely a successful empty query.
An empty or stalled table therefore breaches even if ADX remains reachable. A
newly activated source that never establishes a checkpoint is measured from its
activation/update time and also breaches after the objective. A historical
backfill may remain warning or breached until its checkpoint catches up with
current event time.

## Operations

- **Discover schema** refreshes column metadata without persisting evidence.
- **Validate five sample rows** exercises the selected mapping and AWS parser.
- **Preview** reads five rows without persisting them.
- **Sync now** reads after the last checkpoint and invokes the same leased,
  duplicate-safe pipeline as scheduled work.
- **Pause** stops dispatch without deleting configuration or evidence.
- **Delete** requires a paused source and removes its legacy secret entry, if
  one exists. It never modifies the ADX table.

Monitor source freshness, ingestion runs, the SQS queue and dead-letter queue,
application logs, `adx_sync_failed`, and `adx_freshness_breached`. A degraded
source must pass schema, mapping, authentication, viewer-access, and bounded
query checks before reactivation.

## Capacity and constraints

- One dispatch selects at most 2,000 active sources; additional sources wait for
  the next five-minute cycle.
- Each source query returns at most 1,000 rows or 5 MB. Sustained full batches
  mean the source is not catching up and should be partitioned or rescheduled
  after capacity review.
- One Entra application currently supports a maximum of 20 federated identity
  credentials. Gatewatch uses one credential for the bridge role, so many ADX
  sources in the same AWS deployment can share that trust while maintaining
  independent table mappings and checkpoints.
- ADX evidence enriches search and correlation; deployed security-group state
  remains authoritative from the AWS inventory collector.

Official references: [AWS outbound identity federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound_getting_started.html),
[Microsoft Entra federated credential trust](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust), and
[ADX table schema inspection](https://learn.microsoft.com/en-us/kusto/management/show-table-schema-command?view=azure-data-explorer).
