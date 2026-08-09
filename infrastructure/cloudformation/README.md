# Gatewatch AWS collection infrastructure

## Choose the collector intentionally

| Template | Intended scope | Output |
|---|---|---|
| `gatewatch-security-group-collector.yaml` | Personal, development, or small account sets | One complete `exports/latest.json` compatibility snapshot |
| `gatewatch-organization-collector.yaml` | Production organization collection at 500+ accounts | Immutable account/Region shards, a run manifest, and explicit coverage |

Do not use the aggregate organization mode as the authoritative production path
for hundreds of accounts. Use the Distributed Map collector and normalize its
shards through `gatewatch-aws-platform.yaml`. The aggregate collector remains a
backward-compatible single-account source during migration.

See [`docs/architecture`](../../docs/architecture/README.md) for architecture,
deployment order, diagrams, data contracts, capacity guidance, and runbooks.

## AWS web and Bedrock analyst

`gatewatch-aws-web.yaml` deploys the current CloudFront/EC2 web runtime. It also
creates a versioned Bedrock Guardrail with a high-strength prompt-attack input
filter and grants the instance role access only to the approved US Nova 2 Lite
inference profile, its three US destination model ARNs, and that Guardrail.

`BedrockEnabled` defaults to `true`. `BedrockModelId` is allowlisted to
`us.amazon.nova-2-lite-v1:0`. Set `BedrockEnabled=false` to retain the complete
deterministic application while disabling inference. Do not replace the scoped
Bedrock resources with `*`. See
[`BEDROCK_AI_ANALYST.md`](../../docs/architecture/BEDROCK_AI_ANALYST.md) for the
data boundary, validation contract, budgets, and failure procedure.

## Legacy aggregate collector

This CloudFormation deployment produces a normalized, point-in-time inventory
of EC2 security groups and their individual rules. It is deliberately
read-only: no component can create, modify, or delete a security group.

The stable application input is:

```text
s3://<generated-bucket>/exports/latest.json
```

Only a complete collection replaces `latest.json`. Partial runs are retained
under `snapshots/YYYY/MM/DD/` with their errors, but cannot silently replace the
last known-good export.

## Architecture

```text
EventBridge schedule
        |
        v
Collector Lambda ---- assume role ----> selected member accounts
        |                                  |
        |                                  +-- EC2 DescribeSecurityGroups
        |                                  +-- EC2 DescribeSecurityGroupRules
        |                                  +-- EC2 DescribeNetworkInterfaces
        v
KMS-encrypted, versioned S3 bucket
        |
        +-- exports/latest.json
        +-- manifests/latest.json
        +-- snapshots/YYYY/MM/DD/*.json.gz
```

Organization mode also creates a service-managed CloudFormation StackSet. The
StackSet deploys `GatewatchSecurityGroupReadRole` to the selected organization
root or OUs and automatically covers accounts subsequently added to those OUs.

## What the stack creates

- A Python Lambda collector with adaptive AWS SDK retries, bounded parallelism,
  reserved concurrency, X-Ray tracing, and a 14-minute timeout.
- A least-privilege Lambda execution role.
- In organization mode, a service-managed StackSet containing the cross-account
  read role.
- A private, versioned S3 bucket using a rotating customer-managed KMS key.
- A configurable EventBridge reconciliation schedule.
- An encrypted SQS dead-letter queue for failed asynchronous invocations.
- CloudWatch operational metrics and alarms.
- An optional encrypted SNS email notification topic.

## Prerequisites

All deployments require:

- AWS CLI credentials for the deployment account.
- Permission to create IAM, Lambda, KMS, S3, EventBridge, SQS, SNS, CloudWatch,
  and CloudFormation resources.
- `CAPABILITY_NAMED_IAM` acknowledgement.

Organization mode additionally requires:

- AWS Organizations with all features enabled.
- Trusted access enabled between CloudFormation StackSets and Organizations.
- Deployment from either:
  - the Organizations management account with `StackSetCallAs=SELF`; or
  - a registered CloudFormation StackSets delegated administrator with
    `StackSetCallAs=DELEGATED_ADMIN`.
- One or more organization root/OU IDs.

CloudFormation does not deploy service-managed StackSet instances to the
Organizations management account. When the collector runs from a delegated
administrator, it therefore excludes the management account automatically and
records that exclusion in `source.excludedAccounts`. To collect the management
account, deploy this stack there with `CollectionScope=single-account` or deploy
organization mode from the management account itself.

## Deploy: single account

From the repository root:

```bash
aws cloudformation deploy \
  --region us-east-1 \
  --stack-name gatewatch-sg-collector \
  --template-file infrastructure/cloudformation/gatewatch-security-group-collector.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    CollectionScope=single-account \
    RegionAllowList=us-east-1,us-east-2,us-west-2,eu-west-1
```

Leave `RegionAllowList` empty to scan every Region enabled in the account.

## Deploy: legacy organization mode

First identify the desired root or OU:

```bash
aws organizations list-roots
aws organizations list-organizational-units-for-parent --parent-id r-abcd
```

Deploy from a registered delegated administrator:

```bash
aws cloudformation deploy \
  --region us-east-1 \
  --stack-name gatewatch-sg-collector \
  --template-file infrastructure/cloudformation/gatewatch-security-group-collector.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    CollectionScope=organization \
    OrganizationTargetIds=r-abcd \
    StackSetCallAs=DELEGATED_ADMIN \
    RegionAllowList=us-east-1,us-east-2,us-west-2,eu-west-1 \
    AlarmEmail=security-operations@example.com
```

For multiple targets, provide a comma-separated value:

```text
OrganizationTargetIds=ou-abcd-12345678,ou-abcd-87654321
```

Use `ExcludedAccountIds=111122223333,444455556666` for accounts that must not be
queried. Exclusions appear in snapshot metadata so coverage cannot be
mistakenly reported as complete for the entire organization.

## Deploy: distributed organization collector

The supported 500+ account path packages the Python artifact and deploys the
separate Distributed Map template:

```bash
export AWS_PROFILE=personal
export AWS_REGION=us-east-1
export GATEWATCH_ORGANIZATION_TARGET_IDS=r-abcd
export GATEWATCH_STACKSET_CALL_AS=SELF
export GATEWATCH_REGION_ALLOW_LIST=us-east-1,us-east-2,us-west-2,eu-west-1
./scripts/deploy-aws-organization.sh
```

The stack writes one shard per successful account/Region under
`runs/<run-id>/shards/`, records target health in DynamoDB, and publishes
`runs/<run-id>/manifest.json` plus `manifests/latest.json`. It never builds a
single organization-wide snapshot.

## Run the first collection

The schedule will invoke the collector automatically. To collect immediately:

```bash
FUNCTION_NAME="$(aws cloudformation describe-stacks \
  --stack-name gatewatch-sg-collector \
  --query 'Stacks[0].Outputs[?OutputKey==`CollectorFunctionArn`].OutputValue' \
  --output text)"

aws lambda invoke \
  --function-name "$FUNCTION_NAME" \
  --cli-binary-format raw-in-base64-out \
  --payload '{"trigger":"manual"}' \
  gatewatch-collection-result.json
```

The invocation result includes the snapshot ID, completeness, counts, and S3
object key. In strict mode, an incomplete run returns a Lambda error after
writing its partial historical snapshot.

## Download the application input

Get the bucket name:

```bash
BUCKET_NAME="$(aws cloudformation describe-stacks \
  --stack-name gatewatch-sg-collector \
  --query 'Stacks[0].Outputs[?OutputKey==`SnapshotBucketName`].OutputValue' \
  --output text)"
```

Download and validate the latest complete snapshot:

```bash
aws s3 cp \
  "s3://${BUCKET_NAME}/exports/latest.json" \
  gatewatch-security-groups.json

npx ajv-cli validate \
  -s infrastructure/cloudformation/gatewatch-security-group-snapshot.schema.json \
  -d gatewatch-security-groups.json
```

The application should reject input unless:

- `schemaVersion` is supported.
- `complete` is `true`.
- `snapshotId` has not already been imported.
- The SHA-256 digest matches `manifests/latest.json`.
- Every `resourceKey` is unique.
- Every account and Region is authorized for this Gatewatch deployment.

The resource identity is:

```text
partition:accountId:region:securityGroupId
```

Do not key reviews or findings only by `sg-...`; security-group IDs are not a
safe cross-account, cross-Region application key.

## Snapshot contents

Top-level fields:

- `schemaVersion`, `snapshotId`, and timestamps.
- `complete`, collection scope, region allowlist, and explicit/implicit
  exclusions.
- Expected/authenticated account counts and expected/scanned Region counts.
- Errors with account and Region context.
- Normalized security groups.

Each security group contains:

- Composite resource key, ARN, account, Region, VPC, name, description, and
  tags.
- Stable `configurationHash` that excludes the observation timestamp.
- Ingress/egress and public-rule counts.
- Optional network-interface attachment and interface-type counts.
- Individual rules with rule IDs, direction, protocol, ports, IPv4/IPv6 CIDRs,
  prefix lists, referenced security groups, descriptions, and tags.

The collector intentionally does not calculate Gatewatch severity, risk score,
review status, or findings. Those are application policy outputs and should be
calculated after schema validation and normalization.

## Security and operational behavior

- There are no long-lived AWS access keys.
- Member trust policies name the exact collector role and constrain the STS
  session name.
- Member permissions contain only EC2 `Describe*` actions used by collection.
- The S3 bucket blocks all public access and denies non-TLS requests.
- Snapshot objects use a customer-managed KMS key and S3 Bucket Keys.
- The output bucket and KMS key are retained when the stack is deleted to avoid
  accidental evidence loss. Delete them separately after applying your
  retention and evidence-handling policy.
- Historical snapshots are compressed; the stable `latest.json` export is
  uncompressed for straightforward application ingestion.
- A failed or incomplete scan never replaces `latest.json`.
- Network-interface scanning may be the most expensive API operation in large
  accounts. Set `IncludeNetworkInterfaceUsage=false` if attachment counts are
  not required.
- When network-interface usage is enabled, each security group also includes
  resource-level attachment evidence. EC2 instances, RDS databases and
  clusters, and EFS file systems include their AWS resource identity, resolved
  name, tags, interface context, and available private/public addresses.
- AWS-managed interfaces that cannot be resolved to a parent service remain in
  the snapshot as network-interface attachments with their description and
  tags, so the dashboard does not silently hide an association.
- For large organizations, deploy `gatewatch-organization-collector.yaml`; do
  not solve the aggregate payload/time limit solely by increasing parallelism.

## Known boundaries

- This legacy template is a live-state inventory, not an AWS Config or CloudTrail history
  collector.
- It does not identify the IAM principal that last changed a rule. Add
  organization CloudTrail ingestion for reliable attribution.
- Security-group references are collected, but relationships to higher-level
  resources are represented only by aggregate network-interface usage counts.
- The current Gatewatch application still needs a server-side import endpoint
  or controlled file-upload workflow for this schema. Do not parse or trust the
  snapshot solely in browser code.
- CloudFormation service-managed StackSets cannot deploy the read role to the
  Organizations management account from a delegated administrator deployment.
