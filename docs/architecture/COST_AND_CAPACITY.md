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

## Capacity controls

Starting values:

- account worker reserved concurrency: `100`;
- per-account Region concurrency: `4`;
- ingestion reserved concurrency: `10`;
- SQS batch size: `10`;
- collection schedule: every `6 hours`;
- evidence retention: `400 days`;
- worker memory: `1536 MB`, timeout `15 minutes`.

Increase account concurrency only after checking EC2 API throttling, Lambda
regional concurrency, KMS request rates, and Step Functions Map Run metrics.
Increasing concurrency reduces wall-clock time but not the total API work.

## Scaling signals

Scale or optimize when:

- a full run approaches its next scheduled start;
- more than 1% of targets fail from throttling;
- the SQS oldest-message age exceeds 15 minutes twice;
- Aurora CPU/ACU stays at its maximum during ingestion;
- paginated findings queries exceed the interactive latency objective;
- manifests approach the 8 MB application limit;
- one account worker regularly approaches 15 minutes.

At very large scale, write a compact coverage summary plus paginated target
manifests instead of increasing the 8 MB limit.

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
