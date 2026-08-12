# Aurora recovery drill

Run this quarterly in an isolated AWS test VPC with synthetic data. Restoring a
cluster creates billable resources. Use a separately approved operator role; no
application workload role should have restore or delete permissions.

## Preconditions

- Record the source cluster ARN, approved restore timestamp, workspace UUID,
  migration commit, operator, ticket, and expected row counts.
- Confirm `DeletionProtection=true`, `BackupRetentionPeriod=35`, encryption,
  and a current `LatestRestorableTime` with `describe-db-clusters`.
- Confirm the Object Lock audit archive is versioned and its default retention is
  `COMPLIANCE` for the approved duration.

## Drill

1. Restore to a new identifier with `restore-db-cluster-to-point-in-time`. Never
   restore over the source cluster.
2. Place the restored cluster in isolated database subnets with no inbound
   security-group rules and enable the Data API only for the validation window.
3. Apply no new migrations. Query through a temporary read-only validation
   principal and compare workspace, source, observation, finding, workflow,
   audit, legal-hold, archive-ledger, and retention-run counts to the recorded
   source snapshot.
4. Test one SHA-256-selected Object Lock archive against its ledger record.
5. Verify runtime roles remain non-owner, non-superuser, and non-`BYPASSRLS` and
   that missing/wrong workspace contexts fail closed.
6. Record recovery time, recovery point, discrepancies, logs, and approver. Treat
   any unexplained difference as a failed drill and block release.
7. After evidence is approved, delete only the isolated restored cluster through
   the change-controlled cleanup process and retain its final snapshot according
   to policy.

Do not weaken source deletion protection, Object Lock retention, RLS, or audit
triggers to make a drill pass.
