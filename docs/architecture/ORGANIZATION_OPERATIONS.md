# Organization operations

Organization Operations is Gatewatch's operating plane for central security
teams managing evidence from hundreds of AWS accounts. Daily Findings remains
the investigation queue; this workspace manages the organizational context and
automation that shape that queue.

## Operator workflow

1. Open **Reports → Organization operations** and select **Sync accounts**.
2. Enrich discovered accounts with organizational unit, environment, business
   unit, and accountable owner.
3. Review the coverage heatmap and finding lifecycle for stale, partial, new,
   recurring, reopened, or resolved evidence.
4. Resolve ambiguous resource identifiers in the correlation workbench. Every
   mapping requires a full security-group ARN, confidence, and rationale.
5. Save recurring queries as monitors and choose their grouping, cadence,
   transition trigger, visibility, and delivery destination.
6. Create governed point-in-time or scheduled exports.
7. Administer the versioned risk policy, retention windows, and legal holds.

## Data and trust boundaries

- Customer-controlled S3 remains authoritative for raw AWS logs.
- D1 stores hosted-product workflow state; its migration is
  `drizzle/0011_charming_beyonder.sql`.
- Aurora stores the production operating model through
  `db/postgres/0002_organization_operations.sql`.
- Every API request requires an authenticated user. Mutations also require
  same-origin JSON, a bounded 50 KB body, and an authorized role.
- Account, retention, legal-hold, and scoring changes require an administrator.
- Correlation and monitor changes require an analyst, reviewer, or administrator.
- Personal monitors can only be modified by their owner or an administrator;
  team monitors can be evaluated by authorized analysts.
- All mutations write an audit event. Destructive controls require confirmation.
- Aurora organization-operation tables enforce workspace isolation with
  row-level security and require `app.workspace_id` on each transaction.

## Identity and correlation

The canonical security-group identity is the full ARN:

```text
arn:<partition>:ec2:<region>:<account-id>:security-group/<group-id>
```

This prevents a reused `sg-…` identifier from colliding across accounts,
Regions, or AWS partitions. Direct security-group evidence, inventory attachment
relationships, and analyst-approved mappings converge on that identity.
Mappings are superseded when replaced and can be revoked.

GuardDuty findings mirrored through Security Hub use the provider finding ID as
their semantic event identity. Gatewatch counts the event once while retaining
both source records in its provenance.

## Monitors and notifications

Monitors persist an advanced query plus account, organizational-unit,
environment, region, owner, or severity grouping. Hourly, daily, and weekly
schedules are supported. Each run records total matches and the number entering
or leaving the result set. Transitions enter the existing notification outbox
when the configured policy allows the event and severity.

The monitor scheduler and external email or webhook sender are AWS worker
responsibilities. Creating and manually running monitors is available now;
external delivery is not claimed until that worker succeeds.

## Exports

One-time CSV, JSON, and auditor evidence packages can be completed and downloaded
by the application. Scheduled and Parquet requests create durable queued jobs
for the production AWS export worker. The job records scope, format, schedule,
requestor, row count, completion state, expiration, and artifact checksum.

Until the worker is connected, queued jobs remain visibly queued and their
download control is disabled with an explanation. They are never mislabeled as
complete.

## Retention and legal holds

Retention is independently configurable for raw evidence, normalized evidence,
audit history, and generated exports. Values are constrained to 7–3,650 days.
An active legal hold overrides ordinary deletion for its workspace, account,
security-group ARN, finding fingerprint, or export scope. Releasing a hold is
an administrative, confirmed, audited action.

Policy records are authoritative inputs to lifecycle workers. S3 lifecycle
rules and Aurora deletion jobs must consult active holds before removing data.

## Risk scoring

Risk policies version weights for public ingress, administrative ports, wide
port ranges, unrestricted egress, attached workloads, and stale evidence. Only
one Aurora policy can be active per workspace. Activating a policy retires the
previous version, and the findings API applies active weights to server-side
ranking, severity facets, and pagination.

## Validation and deployment

Run before release:

```bash
npm test
npm run lint
npx tsc --noEmit
git diff --check
```

Deploy the AWS web runtime with the intended named profile:

```bash
AWS_PROFILE=personal AWS_REGION=us-east-1 ./scripts/deploy-aws-web.sh
```

Current production endpoints:

- AWS: `https://d1jl70qr8qlhuj.cloudfront.net`
- Private Sites: `https://gatewatch-cloud-posture.jayson-guglietta.chatgpt.site`

Both endpoints require authentication. An unauthenticated HTTP 401 is expected,
not a health failure.
