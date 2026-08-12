import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const source = (path) => readFile(new URL(path, root), "utf8");

test("requires immutable OIDC subject and binds roles after verified login", async () => {
  const [server, installer, settings, sources] = await Promise.all([
    source("lib/server-admin.ts"),
    source("infrastructure/aws-web/install.sh"),
    source("app/api/admin/settings/route.ts"),
    source("app/api/admin/sources/route.ts"),
  ]);

  assert.match(server, /oai-authenticated-user-id/);
  assert.match(server, /return requestIdentity\(request\)\.subject/);
  assert.match(server, /WHERE workspace_id = 'default' AND subject = \?/);
  assert.match(server, /user_roles_subject_idx/);
  assert.match(server, /SELECT COUNT\(\*\) AS count FROM user_roles/);
  assert.doesNotMatch(server, /GATEWATCH_BOOTSTRAP_ADMIN_EMAIL\.toLowerCase\(\) === user/);
  assert.match(installer, /OAUTH2_PROXY_USER_ID_CLAIM=sub/);
  assert.match(settings, /email === auth\.email/);
  assert.match(sources, /subject: auth\.user/);
});

test("commits local audit and retryable archive outbox atomically", async () => {
  const [server, route, template] = await Promise.all([
    source("lib/server-admin.ts"),
    source("app/api/internal/audit-outbox/route.ts"),
    source("infrastructure/cloudformation/gatewatch-aws-web.yaml"),
  ]);

  assert.match(server, /CREATE TABLE IF NOT EXISTS audit_archive_outbox/);
  assert.match(server, /await env\.DB\.batch\(\[/);
  assert.match(server, /INSERT INTO audit_archive_outbox/);
  assert.match(server, /next_attempt_at/);
  assert.match(server, /AbortSignal\.timeout\(8_000\)/);
  assert.match(server, /archive_version_id/);
  assert.match(server, /actorSubject: actor/);
  assert.match(server, /RETURNING event_id AS eventId/);
  assert.match(server, /next_attempt_at = datetime\('now', '\+2 minutes'\)/);
  assert.match(route, /timingSafeEqual/);
  assert.match(route, /deliverAuditOutbox\(50\)/);
  assert.match(route, /audit_outbox_delivery_failed/);
  assert.match(template, /AuditOutboxDeliveryAssociation:/);
  assert.match(template, /ScheduleExpression: rate\(5 minutes\)/);
  assert.match(template, /AuditOutboxFailureMetric:/);
  assert.match(template, /AuditOutboxFailureAlarm:/);
});

test("archives application audit through a bounded write-only bridge", async () => {
  const [bridge, template, deploy] = await Promise.all([
    source("infrastructure/aws-web/aws-bridge.mjs"),
    source("infrastructure/cloudformation/gatewatch-aws-web.yaml"),
    source("scripts/deploy-aws-web.sh"),
  ]);

  assert.match(bridge, /request\.url === "\/audit\/events"/);
  assert.match(bridge, /AUDIT_EVENT_TOO_LARGE/);
  assert.match(bridge, /PutObjectCommand/);
  assert.match(bridge, /new S3Client\(\{ region, credentials \}\)/);
  assert.match(bridge, /AUDIT_ARCHIVE_VERSION_REQUIRED/);
  assert.match(bridge, /audit\/application\/workspace=/);
  assert.match(template, /Sid: AppendApplicationAuditArchive[\s\S]*Action: s3:PutObject/);
  assert.doesNotMatch(
    template.match(/Sid: AppendApplicationAuditArchive[\s\S]*?Sid: EncryptApplicationAuditArchive/)?.[0] ?? "",
    /s3:(Get|Delete)/,
  );
  assert.match(template, /Action: kms:GenerateDataKey/);
  assert.match(deploy, /AuditArchiveBucketName/);
  assert.match(deploy, /PlatformKeyArn/);
  assert.match(deploy, /WorkspaceId/);
});
