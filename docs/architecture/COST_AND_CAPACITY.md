# Cost and capacity

## Workload assumptions

- 500–1,000 AWS accounts.
- 4–20 enabled Regions per account, with a recommended explicit Region allowlist.
- Collection every six hours plus on-demand incident runs.
- Two or three interactive analysts for a few sessions per day.
- High raw evidence volume, low interactive request volume.

## Why this design is efficient

- Lambda and Step Functions consume capacity only during collection.
- S3 is the low-cost authoritative store for compressed evidence.
- DynamoDB on-demand handles bursty run-state writes without provisioned idle capacity.
- SQS buffers object bursts so Aurora ingestion is independent of collection speed.
- Aurora Serverless v2 can use a low minimum capacity for the small analyst team,
  while scaling during ingestion/query bursts.
- The UI queries normalized/paginated rows instead of repeatedly transferring a
  large aggregate JSON file.

## Main cost drivers

| Driver | Scaling unit | Control |
|---|---|---|
| EC2 API calls | Accounts × enabled Regions × resource pages | Region allowlist, collection interval |
| Lambda | Account workers × duration/memory | Account/Region concurrency, efficient pagination |
| Step Functions | Account child executions | Collection frequency and scope |
| S3 | Shard bytes × retention + requests | Gzip, lifecycle, no duplicated raw DB copy |
| DynamoDB | Run/target writes | On-demand, TTL for operational state |
| SQS/Lambda ingestion | Shards and source objects | Batch size, reserved concurrency |
| Aurora | Minimum ACU + ingestion/query bursts + I/O | Serverless bounds, indexes, pagination |
| CloudWatch | Log bytes and retention | Structured concise logs, 90-day hot retention |
| NAT/data transfer | Workloads placed behind NAT | Prefer VPC endpoints where justified |
| Bedrock analysis | Input/output tokens on uncached analyst requests | Nova 2 Lite, compact evidence, 4,000-token output cap, seven-day cache, per-user/workspace daily budgets |
| Azure Data Explorer | Query frequency, scanned extents, returned rows, cross-cloud egress | Five-minute dispatch, timestamp predicate, 1,000-row/5 MB cap, source filters |
| ADX worker queue | Active sources, Lambda duration, retries, DLQ retention | FIFO message group per source, 25 concurrent workers, atomic source leases |

## Capacity controls

Starting values:

- account worker reserved concurrency: `100`;
- per-account Region concurrency: `4`;
- ingestion reserved concurrency: `10`;
- SQS batch size: `10`;
- collection schedule: every `6 hours`;
- evidence retention: `400 days`;
- worker memory: `1536 MB`, timeout `15 minutes`.
- ADX dispatcher limit: `2,000` active sources per cycle;
- ADX worker reserved/max concurrency: `25`;
- ADX source lease: `3 minutes`;
- default ADX freshness objective: `30 minutes`.

Increase account concurrency only after checking EC2 API throttling, Lambda
regional concurrency, KMS request rates, and Step Functions Map Run metrics.
Increasing concurrency reduces wall-clock time but not the total API work.

Bedrock starts with 100 uncached requests per user and 500 per workspace per UTC
day. The API atomically reserves capacity before inference, so parallel requests
cannot exceed a counter. Cache hits are free of the application request budget.
Track actual input/output tokens in `ai_usage_daily` and price them against the
current Bedrock Nova 2 Lite rates in the deployment Region; do not hard-code a
dollar estimate because service and cross-Region pricing can change.

## Scaling signals

Scale or optimize when:

- a full run approaches its next scheduled start;
- more than 1% of targets fail from throttling;
- the SQS oldest-message age exceeds 15 minutes twice;
- Aurora CPU/ACU stays at its maximum during ingestion;
- paginated findings queries exceed the interactive latency objective;
- manifests approach the 8 MB application limit;
- one account worker regularly approaches 15 minutes.
- an ADX source repeatedly returns a full batch, indicating checkpoint lag;
- ADX query duration, throttling, or cross-cloud transfer grows unexpectedly.
- ADX FIFO age exceeds ten minutes or any job reaches the dead-letter queue;
- source freshness enters warning at 80% or breaches its configured objective.

At very large scale, write a compact coverage summary plus paginated target
manifests instead of increasing the 8 MB limit.

Daily Findings exposes a stable `after` cursor alongside the existing numbered
pages so the Aurora-backed runtime can use keyset pagination without changing
the client contract. Migration `db/postgres/0003_finding_search.sql` adds queue,
temporal, trigram, JSONB, resource-tag, and normalized-evidence indexes. Query
input is limited to 500 characters, 40 clauses, and five nested Boolean groups;
universal evidence evaluation reads at most 500 recent normalized records per
request. Use query latency, rows examined, and facet-cardinality telemetry to
decide when to route free-text predicates to OpenSearch rather than enabling
unbounded scans.

## Cost estimation method

Before production, run a representative 25-account pilot and record:

1. worker duration/memory per account and Region;
2. shard compressed bytes per group/rule/attachment;
3. S3 requests and retained bytes;
4. Step Functions child executions;
5. SQS messages and ingestion duration;
6. Aurora ACU-hours and Data API calls;
7. CloudWatch log ingestion.

Multiply by real account/Region/resource distributions—not merely account count.
Recalculate using the AWS Pricing Calculator in the intended Region before
approval, because service prices and free-tier terms change.
