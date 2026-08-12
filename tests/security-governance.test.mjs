import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const source = (path) => readFile(new URL(path, root), "utf8");

test("constrains secret-scan exceptions to exact synthetic analyzer IDs and paths", async () => {
  const config = await source(".gitleaks.toml");

  assert.match(config, /useDefault = true/);
  assert.match(config, /condition = "AND"/);
  assert.match(config, /id = "generic-api-key"/);
  assert.match(config, /\^nisa-0a41f2e91b71\$/);
  assert.match(config, /\^nis-0a41f2e91b71\$/);
  assert.doesNotMatch(config, /commits\s*=/);
  assert.doesNotMatch(config, /samples\/\.\*/);
});

test("forces tenant isolation and keeps runtime database roles non-owner", async () => {
  const [migration, platform, ingest, backfill] = await Promise.all([
    source("db/postgres/0005_security_governance.sql"),
    source("infrastructure/cloudformation/gatewatch-aws-platform.yaml"),
    source("infrastructure/lambda/ingest/index.mjs"),
    source("infrastructure/lambda/backfill/index.mjs"),
  ]);

  assert.match(migration, /ALTER TABLE public\.%I FORCE ROW LEVEL SECURITY/);
  assert.match(migration, /current_setting\(''app\.workspace_id'', true\)/);
  assert.match(migration, /NOBYPASSRLS/);
  assert.match(migration, /REVOKE CREATE ON SCHEMA public FROM PUBLIC/);
  assert.match(platform, /gatewatch_runtime_login/);
  assert.match(platform, /gatewatch_maintenance_login/);
  assert.match(platform, /DB_SECRET_ARN: !Ref RuntimeDatabaseSecret/);
  assert.match(platform, /DB_SECRET_ARN: !Ref MaintenanceDatabaseSecret/);
  assert.doesNotMatch(platform, /DB_SECRET_ARN: !GetAtt DatabaseCluster\.MasterUserSecret/);
  assert.match(ingest, /set_config\('app\.workspace_id', :workspaceId, true\)/);
  assert.match(backfill, /set_config\('app\.workspace_id', :workspaceId, true\)/);
  assert.match(backfill, /WHERE workspace_id = CAST\(:workspaceId AS uuid\)/);
});

test("makes audit history append-only and archives before retention deletion", async () => {
  const [migration, worker, platform] = await Promise.all([
    source("db/postgres/0005_security_governance.sql"),
    source("infrastructure/lambda/governance-maintenance/index.mjs"),
    source("infrastructure/cloudformation/gatewatch-aws-platform.yaml"),
  ]);

  assert.match(migration, /audit_events_append_only/);
  assert.match(migration, /audit history is append-only/);
  assert.match(migration, /JOIN audit_archive_ledger archive/);
  assert.match(migration, /app\.retention_authorized/);
  assert.match(worker, /pendingAuditEvents/);
  assert.match(worker, /PutObjectCommand/);
  assert.match(worker, /AUDIT_ARCHIVE_VERSION_REQUIRED/);
  assert.match(worker, /gatewatch_apply_retention_batch/);
  assert.match(platform, /ObjectLockEnabled: true/);
  assert.match(platform, /Mode: COMPLIANCE/);
  assert.match(platform, /ReservedConcurrentExecutions: 1/);
  assert.doesNotMatch(
    platform.match(/Sid: AppendAuditArchive[\s\S]*?Resource: !Sub[^\n]*/)?.[0] ?? "",
    /s3:DeleteObject/,
  );
});

test("adds deletion protection, recoverable backups, managed master credentials, and maintenance alarms", async () => {
  const platform = await source("infrastructure/cloudformation/gatewatch-aws-platform.yaml");

  assert.match(platform, /BackupRetentionPeriod: 35/);
  assert.match(platform, /DeletionProtection: true/);
  assert.match(platform, /DeletionPolicy: Snapshot/);
  assert.match(platform, /ManageMasterUserPassword: true/);
  assert.match(platform, /GovernanceMaintenanceDeadLetterQueue/);
  assert.match(platform, /MaximumRetryAttempts: 6/);
  assert.match(platform, /GovernanceMaintenanceAlarm/);
  assert.match(platform, /PlatformKeyArn:[\s\S]*Value: !GetAtt PlatformKey\.Arn/);
  assert.match(platform, /WorkspaceId:[\s\S]*Value: !Ref WorkspaceId/);
});

test("encrypts queues with a dedicated CMK and enables audit access logging and Lambda tracing", async () => {
  const [platform, forwarding, collector] = await Promise.all([
    source("infrastructure/cloudformation/gatewatch-aws-platform.yaml"),
    source("infrastructure/cloudformation/gatewatch-s3-event-forwarding.yaml"),
    source("infrastructure/cloudformation/gatewatch-security-group-collector.yaml"),
  ]);

  assert.doesNotMatch(platform, /KmsMasterKeyId: alias\/aws\/sqs/);
  assert.doesNotMatch(platform, /SqsManagedSseEnabled/);
  assert.equal(
    [...platform.matchAll(/KmsMasterKeyId: !GetAtt QueueKey\.Arn/g)].length,
    3,
  );
  assert.match(platform, /QueueKey:[\s\S]*Description: !Sub Gatewatch \$\{EnvironmentName\} queue encryption/);
  assert.match(platform, /AuditAccessLogBucket:/);
  assert.match(platform, /SSEAlgorithm: AES256/);
  assert.match(platform, /LoggingConfiguration:[\s\S]*DestinationBucketName: !Ref AuditAccessLogBucket/);
  assert.match(platform, /Service: logging\.s3\.amazonaws\.com/);
  assert.equal([...platform.matchAll(/TracingConfig:\n\s+Mode: Active/g)].length, 4);
  assert.equal([...platform.matchAll(/xray:PutTraceSegments/g)].length, 3);
  assert.match(platform, /Service: events\.amazonaws\.com[\s\S]*kms:GenerateDataKey/);
  assert.match(platform, /QueueKeyArn:[\s\S]*Value: !GetAtt QueueKey\.Arn/);
  assert.match(forwarding, /GatewatchIngestionQueueKeyArn:/);
  assert.match(forwarding, /kms:GenerateDataKey/);
  assert.match(collector, /CollectorMessagingKey:[\s\S]*EnableKeyRotation: true/);
  assert.match(collector, /InvocationDeadLetterQueue:[\s\S]*KmsMasterKeyId: !GetAtt CollectorMessagingKey\.Arn/);
  assert.match(collector, /CollectorAlarmTopic:[\s\S]*KmsMasterKeyId: !GetAtt CollectorMessagingKey\.Arn/);
  assert.doesNotMatch(collector, /KmsMasterKeyId: alias\/aws\/sns/);
});

test("pins CI actions and gates secrets, SAST, dependencies, and IaC", async () => {
  const workflow = await source(".github/workflows/ci.yml");

  assert.doesNotMatch(workflow, /uses: [^\n]+@(v\d+|master)\s*$/m);
  assert.match(workflow, /gitleaks\/gitleaks-action@[a-f0-9]{40}/);
  assert.match(workflow, /github\/codeql-action\/analyze@[a-f0-9]{40}/);
  assert.match(workflow, /aquasecurity\/trivy-action@[a-f0-9]{40}/);
  assert.equal((workflow.match(/limit-severities-for-sarif: true/g) ?? []).length, 2);
  assert.equal((workflow.match(/format: table/g) ?? []).length, 2);
  assert.equal((workflow.match(/skip-dirs: samples\/iac-review/g) ?? []).length, 2);
  assert.equal((workflow.match(/trivyignores: \.trivyignore\.yaml/g) ?? []).length, 2);
  assert.match(workflow, /Gate repository secrets and IaC[\s\S]*exit-code: "1"/);
  assert.match(workflow, /npm audit --omit=dev --audit-level=high/);
  assert.match(workflow, /cfn-lint/);
});
