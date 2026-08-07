# AWS deployment guide

This guide describes the target stack order. The scripts package and deploy
infrastructure but do not copy local AWS credentials into Gatewatch.

## Prerequisites

- AWS Organizations with all features enabled.
- CloudFormation StackSets trusted access enabled.
- A management account deployment (`SELF`) or registered delegated admin
  (`DELEGATED_ADMIN`).
- AWS CLI v2 and an authenticated profile with MFA/session credentials.
- Node.js 22.13+, `zip`, `jq`, and `shasum` locally.
- VPC and at least two private subnets for Aurora when deploying the platform.
- A reviewed organization root/OU allowlist and account exclusion list.

Do not use a profile affected by an identity-policy explicit deny that blocks
the required deployment APIs. An explicit deny cannot be overridden by adding
an allow policy.

## Stack order

```mermaid
flowchart TD
  A["1. Organization collector"] --> B["2. PostgreSQL migration"]
  B --> C["3. AWS data platform"]
  C --> D["4. Identity and web runtime"]
  D --> E["5. AWS-native evidence sources"]
  E --> F["6. Evidence correlation and Jira"]
  F --> G["7. Production validation and release gate"]
```

## 1. Deploy the organization collector

Set the target root or OUs explicitly:

```bash
export AWS_PROFILE=personal
export AWS_REGION=us-east-1
export GATEWATCH_ORGANIZATION_TARGET_IDS=r-abcd
export GATEWATCH_STACKSET_CALL_AS=SELF
export GATEWATCH_REGION_ALLOW_LIST=us-east-1,us-east-2,us-west-2,eu-west-1
./scripts/deploy-aws-organization.sh
```

For a delegated administrator, use `DELEGATED_ADMIN`. The deployment script:

1. packages only `index.py`;
2. calculates SHA-256 and uses a content-addressed S3 key;
3. validates the CloudFormation template;
4. deploys the read-role StackSet and central collection resources;
5. starts an initial Step Functions execution.

Record these outputs:

- `EvidenceBucketName`
- `EvidenceKeyArn`
- `CollectionStateMachineArn`
- `CollectionRunTableName`

## 2. Apply the PostgreSQL schema

Apply the migrations in filename order through a controlled migration identity:

1. [`0001_gatewatch_aws.sql`](../../db/postgres/0001_gatewatch_aws.sql) creates
   the ingestion, inventory, finding, workflow, and evidence base.
2. [`0002_organization_operations.sql`](../../db/postgres/0002_organization_operations.sql)
   creates account context, correlation mappings, monitors and runs, export
   jobs, retention, legal holds, risk policies, and semantic event provenance.

The second migration enables row-level security on every organization-operations
table. Each application transaction must set `app.workspace_id`; a missing or
incorrect workspace context therefore fails closed. The Lambda runtime must not
own tables or have schema-administration privileges.

## 3. Deploy the data platform

Package `infrastructure/lambda/ingest` and `backfill` with lockfile-based
installs. Pass the organization evidence bucket and key outputs to
`gatewatch-aws-platform.yaml`:

```text
OrganizationEvidenceBucketName=<collector EvidenceBucketName>
OrganizationEvidenceKeyArn=<collector EvidenceKeyArn>
```

The platform creates the EventBridge rule that forwards only canonical shard
and run-manifest object keys to SQS. Confirm the queue policy source ARN and
source account after deployment.

## 4. Deploy the transitional web stack

For the existing small-team web path:

```bash
./scripts/deploy-aws-web.sh
```

The script uploads a content-addressed release to a versioned bucket, captures
the exact S3 VersionId, and passes both VersionId and SHA-256 to CloudFormation.
The SSM installer downloads that version and verifies the digest before unzip or
execution.

This web stack still uses a shared Basic Auth administrator and an HTTP origin.
It is suitable only as a transitional, access-restricted environment. Before
authoritative multi-account governance, replace it with individual OIDC/MFA,
TLS to the origin, separate web/bridge task roles, WAF/rate limiting, and a
production runtime as described in the security roadmap.

## 5. Connect AWS-native evidence

- Prefer an organization trail delivered to a central log-archive bucket.
- Prefer an organization Config aggregator/history source.
- Add VPC and Transit Gateway Flow Logs as observed-traffic evidence.
- Add Reachability Analyzer and Network Access Analyzer exports as static path
  evidence, without treating them as proof that traffic occurred.
- Add ELB, WAF, CloudFront, API Gateway, Route 53 Resolver, and Network Firewall
  logs only where those services are in the protected path.
- Add GuardDuty, Security Hub, and Inspector findings as threat enrichment, not
  as the source of truth for security-group configuration or reachability.
- Use a dedicated `GatewatchLogReadRole` per source account/bucket.
- Generate the template from Admin, review the JSON policy, and validate it with
  IAM Access Analyzer before deployment.
- Activate a source only after live STS, list, bounded read, and KMS tests pass.

## Validation checklist

- [ ] StackSet instances are current for every selected account.
- [ ] A newly added OU account receives the member role automatically.
- [ ] Initial run manifest lists every expected account.
- [ ] Failed accounts/Regions appear in Coverage and do not disappear from totals.
- [ ] Every successful target has an S3 key and SHA-256.
- [ ] Duplicate S3 events do not create duplicate observation rows.
- [ ] Malformed or excessive shards reach the DLQ without partial rows.
- [ ] The platform queue cannot be written by an unapproved principal/rule.
- [ ] Artifact checksum/version mismatch causes web deployment to fail.
- [ ] Snapshot checksum mismatch causes `/api/aws-inventory` to fail closed.
- [ ] Administrator and workflow audit events identify unique users (required
  after OIDC implementation).
- [ ] `app.workspace_id` is set on every Aurora application transaction and a
  cross-workspace query is rejected by row-level security.
- [ ] Account catalog changes appear in findings facets and groupings.
- [ ] Revoked correlation mappings are excluded from reprocessing.
- [ ] Monitor transitions create durable runs and notification outbox entries.
- [ ] Active legal holds prevent matching evidence and export deletion.
- [ ] Active risk-policy weights change finding scores deterministically.

## Rollback

- Roll back application code by deploying a previously approved artifact
  VersionId and digest.
- Do not delete the evidence bucket, KMS key, run table, or Aurora during rollback.
- Disable the schedule to stop new collection while preserving historical runs.
- Pause ingestion event-source mapping if a parser defect is suspected; do not
  purge the queue until objects can be replayed.
- Restore Aurora to a separate cluster for validation before promoting a restore.
