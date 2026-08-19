# Azure Data Explorer log source

Gatewatch can read AWS security evidence from an Azure Data Explorer (ADX)
table and feed it into the same normalized evidence model used by S3 imports.
The connector is intended for organizations that centralize multi-account AWS
logs in ADX while keeping Gatewatch deployed in AWS.

## User workflow

1. Open **Administration → Data sources → Add log source**.
2. Choose **Azure Data Explorer** and select the AWS evidence type represented
   by the rows.
3. Enter the HTTPS cluster URL, database, table, timestamp column, and mapping.
4. Enter a dedicated Microsoft Entra tenant ID, application ID, and client
   secret. The authenticated application endpoint immediately relays the secret
   to the isolated AWS bridge, where it is stored in
   the retained `AzureDataExplorerCredentialsSecret`; it is never stored in the
   application database or returned by an API.
5. Test the connection, preview five bounded rows, activate the source, and run
   an initial synchronization. Active sources poll every five minutes.

The Entra service principal needs only ADX database `viewer` access. Grant it at
database scope, not cluster administrator scope. Microsoft documents the
application registration and database role command in [Microsoft Entra
application registration for Kusto](https://learn.microsoft.com/en-us/kusto/access-control/provision-entra-id-app?view=azure-data-explorer).

## Source model

Each source records:

- provider and AWS evidence type;
- cluster origin, database, and table;
- timestamp column used as an incremental checkpoint;
- whole-row or dynamic/JSON payload-column mapping;
- 10–1,000 row batch limit;
- optional AWS account and Region filters;
- backfill start, retention, test result, source health, and checkpoint;
- non-secret Entra tenant and application IDs.

The production PostgreSQL model additionally provides
`ingestion_source_checkpoints`, with workspace-scoped leases and cursor state
for horizontally scaled workers. Migration `0007_azure_data_explorer_sources.sql`
forces row-level security on that table.

## Query and network security

Gatewatch does not accept arbitrary KQL. It generates one fixed read-only query
from identifiers that contain only letters, numbers, and underscores. Incremental
checkpoint and row-limit values use declared KQL query parameters, following
[Microsoft's query-parameter guidance](https://learn.microsoft.com/en-us/kusto/query/query-parameters-statement?view=microsoft-fabric).

The connector also enforces:

- HTTPS cluster origins on Microsoft Kusto domains only;
- no URL credentials, ports, paths, query strings, fragments, redirects, or
  caller-selected OAuth hosts;
- public, US Government, and China cloud authority selection derived from the
  validated cluster suffix;
- client-credential OAuth performed only inside the AWS bridge;
- 20-second ADX server timeout, 25-second network timeout, 5 MB response limit,
  and maximum 1,000 rows;
- bounded JSON parsing and 64 KB normalized payloads;
- source/account/Region filters and SHA-256 record fingerprints;
- compound timestamp plus stable row-hash checkpoints, so a full batch does not
  skip later rows sharing the same timestamp;
- checkpoint advancement only after the bounded batch's normalized writes and
  malformed-row accounting complete;
- degraded source state and an audited failed run when a sync fails.

The application database stores no access token or client secret. Access tokens
are held only for the duration of one bridge request.

## Mapping modes

**Complete row** converts the ADX result columns into one JSON record. Gatewatch
adds a normalized `timestamp` field when the configured timestamp column uses a
source-specific name such as `TimeGenerated`.

**Payload column** projects only the timestamp and selected dynamic/JSON column,
then parses that payload as the chosen AWS evidence type. Non-object or malformed
JSON payloads are skipped and counted rather than guessed into findings.

For best results, the row or payload should retain the original AWS field names
used by CloudTrail, Config, VPC Flow Logs, Security Hub ASFF, GuardDuty, or the
other supported formats.

## Operations

- **Preview** reads five rows without persisting them.
- **Sync now** reads after the last successful timestamp, normalizes records,
  suppresses duplicates, and updates the source checkpoint.
- **Scheduled sync** calls the private `/api/internal/adx-sync` endpoint every
  five minutes using the bridge bearer secret. The endpoint is inaccessible to
  ordinary authenticated browser sessions.
- **Backfill** starts at the configured date and uses the same bounded pipeline;
  a backfill-only source pauses automatically when it reaches the end.
- **Pause** prevents scheduled synchronization without deleting configuration
  or source data.
- **Delete** requires the source to be paused and removes its individual
  credential entry. It never changes the ADX table.

Monitor ingestion runs, source status, application logs, and `adx_sync_failed`
events. A degraded source must pass a new live test before it is reactivated.

## Known constraints

- The current scheduler processes at most 20 active ADX sources per invocation.
- Private Link clusters require DNS and network routing from the Gatewatch
  private subnet to the validated Kusto hostname.
- ADX evidence enriches search and correlation; current deployed security-group
  state remains authoritative from the AWS inventory collector.
