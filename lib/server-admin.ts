import { env } from "cloudflare:workers";
import { cleanText } from "./admin-sources";

export type ApplicationRole = "admin" | "analyst" | "reviewer" | "viewer";
export type Permission =
  | "administration.manage"
  | "findings.triage"
  | "reviews.write"
  | "governance.write"
  | "intelligence.write"
  | "remediation.write";

const permissionRoles: Record<Permission, ReadonlySet<ApplicationRole>> = {
  "administration.manage": new Set(["admin"]),
  "findings.triage": new Set(["admin", "analyst", "reviewer"]),
  "reviews.write": new Set(["admin", "analyst", "reviewer"]),
  "governance.write": new Set(["admin", "analyst", "reviewer"]),
  "intelligence.write": new Set(["admin", "analyst", "reviewer"]),
  "remediation.write": new Set(["admin", "analyst"]),
};

export function apiJson(body: Record<string, unknown>, status = 200) {
  return Response.json(body, {
    status,
    headers: {
      "cache-control": "no-store, private",
      "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
    },
  });
}

export function requestUser(request: Request) {
  return requestIdentity(request).subject;
}

export function requestIdentity(request: Request) {
  const email = cleanText(
    request.headers.get("oai-authenticated-user-email"),
    254,
  ).toLowerCase();
  const subject = cleanText(
    request.headers.get("oai-authenticated-user-id"),
    255,
  );
  if (email && /^[A-Za-z0-9:_-]{8,255}$/.test(subject)) {
    return { subject, email };
  }
  const hostname = new URL(request.url).hostname;
  const localDevelopment =
    typeof process !== "undefined" && process.env.NODE_ENV !== "production";
  const local = (
    localDevelopment &&
    ["localhost", "127.0.0.1"].includes(hostname)
  )
    ? "local-admin@gatewatch"
    : "";
  return { subject: local, email: local };
}

export async function requireAdmin(request: Request) {
  return requirePermission(request, "administration.manage");
}

export async function requirePermission(
  request: Request,
  permission: Permission,
) {
  const identity = requestIdentity(request);
  const user = identity.subject;
  if (!user) return { user: "", email: "", role: null, permission, allowed: false };
  const hostname = new URL(request.url).hostname;
  if (
    typeof process !== "undefined" &&
    process.env.NODE_ENV !== "production" &&
    ["localhost", "127.0.0.1"].includes(hostname)
  ) {
    return { user, email: identity.email, role: "admin" as const, permission, allowed: true };
  }
  await ensureAdminSchema();
  let result = await env.DB.prepare(
    `SELECT role FROM user_roles
      WHERE workspace_id = 'default' AND subject = ?`,
  )
    .bind(user)
    .first<{ role: string }>();
  if (!result) {
    const legacy = await env.DB.prepare(
      `SELECT role FROM user_roles
        WHERE workspace_id = 'default' AND email = ? AND subject = ''`,
    ).bind(identity.email).first<{ role: string }>();
    if (legacy) {
      await env.DB.prepare(
        `UPDATE user_roles SET subject = ?, updated_at = CURRENT_TIMESTAMP
          WHERE workspace_id = 'default' AND email = ? AND subject = ''`,
      ).bind(user, identity.email).run();
      result = legacy;
    }
  }
  if (
    !result &&
    env.GATEWATCH_BOOTSTRAP_ADMIN_EMAIL?.toLowerCase() === identity.email
  ) {
    const count = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM user_roles WHERE workspace_id = 'default'",
    ).first<{ count: number }>();
    if (Number(count?.count ?? 0) === 0) {
      await env.DB.prepare(
        `INSERT INTO user_roles (email, subject, role, created_by)
         VALUES (?, ?, 'admin', ?)`,
      ).bind(identity.email, user, user).run();
      result = { role: "admin" };
    }
  }
  const role = ["admin", "analyst", "reviewer", "viewer"].includes(result?.role ?? "")
    ? (result?.role as ApplicationRole)
    : "viewer";
  return {
    user,
    email: identity.email,
    role,
    permission,
    allowed: permissionRoles[permission].has(role),
  };
}

export function sameOrigin(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  try {
    return new URL(origin).host === new URL(request.url).host;
  } catch {
    return false;
  }
}

export function acceptsJson(request: Request, maxBytes = 50_000) {
  const length = Number(request.headers.get("content-length") ?? "0");
  return (
    length <= maxBytes &&
    request.headers.get("content-type")?.startsWith("application/json")
  );
}

export async function ensureAdminSchema() {
  await env.DB.batch([
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS ingestion_sources (
        id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL DEFAULT 'default',
        name TEXT NOT NULL,
        source_type TEXT NOT NULL,
        bucket_arn TEXT NOT NULL,
        bucket_name TEXT NOT NULL,
        region TEXT NOT NULL,
        object_prefix TEXT NOT NULL DEFAULT '',
        role_arn TEXT NOT NULL,
        external_id TEXT NOT NULL,
        kms_key_arn TEXT NOT NULL DEFAULT '',
        organization_id TEXT NOT NULL DEFAULT '',
        ingestion_mode TEXT NOT NULL DEFAULT 'continuous',
        backfill_start TEXT NOT NULL DEFAULT '',
        included_accounts TEXT NOT NULL DEFAULT '[]',
        excluded_accounts TEXT NOT NULL DEFAULT '[]',
        included_regions TEXT NOT NULL DEFAULT '[]',
        config_resource_types TEXT NOT NULL DEFAULT '[]',
        retention_days INTEGER NOT NULL DEFAULT 365,
        status TEXT NOT NULL DEFAULT 'draft',
        test_summary TEXT NOT NULL DEFAULT '{}',
        last_tested_at TEXT NOT NULL DEFAULT '',
        last_successful_object_at TEXT NOT NULL DEFAULT '',
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
    ),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS ingestion_runs (
        id TEXT PRIMARY KEY,
        source_id TEXT NOT NULL,
        run_type TEXT NOT NULL,
        status TEXT NOT NULL,
        discovered_objects INTEGER NOT NULL DEFAULT 0,
        processed_objects INTEGER NOT NULL DEFAULT 0,
        failed_objects INTEGER NOT NULL DEFAULT 0,
        parsed_records INTEGER NOT NULL DEFAULT 0,
        finding_changes INTEGER NOT NULL DEFAULT 0,
        cursor TEXT NOT NULL DEFAULT '',
        error_summary TEXT NOT NULL DEFAULT '',
        requested_by TEXT NOT NULL,
        started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        completed_at TEXT NOT NULL DEFAULT ''
      )`,
    ),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS ingested_objects (
        id TEXT PRIMARY KEY,
        source_id TEXT NOT NULL,
        bucket_name TEXT NOT NULL,
        object_key TEXT NOT NULL,
        version_id TEXT NOT NULL DEFAULT '',
        etag TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL,
        object_size INTEGER NOT NULL DEFAULT 0,
        record_count INTEGER NOT NULL DEFAULT 0,
        checksum TEXT NOT NULL DEFAULT '',
        failure_code TEXT NOT NULL DEFAULT '',
        failure_detail TEXT NOT NULL DEFAULT '',
        first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        processed_at TEXT NOT NULL DEFAULT ''
      )`,
    ),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS audit_events (
        id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL DEFAULT 'default',
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        summary TEXT NOT NULL,
        metadata TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
    ),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS audit_archive_outbox (
        event_id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL DEFAULT 'default',
        payload TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_error TEXT NOT NULL DEFAULT '',
        delivered_at TEXT NOT NULL DEFAULT '',
        archive_version_id TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
    ),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS user_roles (
        email TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL DEFAULT 'default',
        subject TEXT NOT NULL DEFAULT '',
        role TEXT NOT NULL DEFAULT 'viewer',
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
    ),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS system_settings (
        key TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL DEFAULT 'default',
        value TEXT NOT NULL,
        updated_by TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
    ),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS finding_jira_links (
        fingerprint TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL DEFAULT 'default',
        issue_key TEXT NOT NULL,
        issue_url TEXT NOT NULL,
        remote_status TEXT NOT NULL DEFAULT '',
        remote_resolution TEXT NOT NULL DEFAULT '',
        remote_updated_at TEXT NOT NULL DEFAULT '',
        last_synced_at TEXT NOT NULL DEFAULT '',
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
    ),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS finding_observations (
        id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL DEFAULT 'default',
        fingerprint TEXT NOT NULL,
        legacy_fingerprint TEXT NOT NULL DEFAULT '',
        canonical_resource_key TEXT NOT NULL,
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        last_snapshot_id TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'active',
        observation_count INTEGER NOT NULL DEFAULT 1,
        resolved_at TEXT NOT NULL DEFAULT '',
        evidence_snapshot TEXT NOT NULL DEFAULT '{}'
      )`,
    ),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS resource_reviews (
        resource_key TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL DEFAULT 'default',
        security_group_id TEXT NOT NULL,
        account_id TEXT NOT NULL,
        region TEXT NOT NULL,
        vpc_id TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL,
        assignee TEXT NOT NULL,
        reviewer TEXT NOT NULL,
        note TEXT NOT NULL DEFAULT '',
        ticket_ref TEXT NOT NULL DEFAULT '',
        expires_at TEXT NOT NULL DEFAULT '',
        evidence_snapshot TEXT NOT NULL DEFAULT '{}',
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
    ),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS resource_review_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        workspace_id TEXT NOT NULL DEFAULT 'default',
        resource_key TEXT NOT NULL,
        security_group_id TEXT NOT NULL,
        status TEXT NOT NULL,
        assignee TEXT NOT NULL,
        reviewer TEXT NOT NULL,
        note TEXT NOT NULL,
        ticket_ref TEXT NOT NULL DEFAULT '',
        expires_at TEXT NOT NULL DEFAULT '',
        evidence_snapshot TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
    ),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS access_policy_versions (
        id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL DEFAULT 'default',
        policy_id TEXT NOT NULL,
        version INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'draft',
        yaml TEXT NOT NULL,
        evaluation TEXT NOT NULL DEFAULT '{}',
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
    ),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS campaign_items (
        id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL DEFAULT 'default',
        campaign_id TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        owner TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        decision TEXT NOT NULL DEFAULT '',
        note TEXT NOT NULL DEFAULT '',
        evidence_snapshot TEXT NOT NULL DEFAULT '{}',
        decided_by TEXT NOT NULL DEFAULT '',
        decided_at TEXT NOT NULL DEFAULT ''
      )`,
    ),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS remediation_requests (
        id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL DEFAULT 'default',
        fingerprint TEXT NOT NULL,
        canonical_resource_key TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'draft',
        proposed_change TEXT NOT NULL,
        artifact_type TEXT NOT NULL DEFAULT 'json',
        external_ref TEXT NOT NULL DEFAULT '',
        evidence_before TEXT NOT NULL DEFAULT '{}',
        evidence_after TEXT NOT NULL DEFAULT '{}',
        requested_by TEXT NOT NULL,
        approved_by TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
    ),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS integration_deliveries (
        id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL DEFAULT 'default',
        integration TEXT NOT NULL,
        event_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        attempts INTEGER NOT NULL DEFAULT 0,
        payload TEXT NOT NULL DEFAULT '{}',
        last_error TEXT NOT NULL DEFAULT '',
        next_attempt_at TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
    ),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS verification_runs (
        id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL DEFAULT 'default',
        remediation_id TEXT NOT NULL,
        snapshot_id TEXT NOT NULL,
        status TEXT NOT NULL,
        result TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
    ),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS program_metric_snapshots (
        id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL DEFAULT 'default',
        snapshot_id TEXT NOT NULL,
        period_start TEXT NOT NULL,
        metrics TEXT NOT NULL DEFAULT '{}',
        evidence_coverage INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
    ),
    env.DB.prepare(
      `CREATE UNIQUE INDEX IF NOT EXISTS finding_jira_links_issue_unique
       ON finding_jira_links (workspace_id, issue_key)`,
    ),
    env.DB.prepare(
      `CREATE UNIQUE INDEX IF NOT EXISTS finding_observations_workspace_fingerprint_unique
       ON finding_observations (workspace_id, fingerprint)`,
    ),
    env.DB.prepare(
      `CREATE INDEX IF NOT EXISTS finding_observations_resource_state_idx
       ON finding_observations (workspace_id, canonical_resource_key, state)`,
    ),
    env.DB.prepare(
      `CREATE INDEX IF NOT EXISTS resource_reviews_group_idx
       ON resource_reviews (workspace_id, account_id, region, security_group_id)`,
    ),
    env.DB.prepare(
      `CREATE INDEX IF NOT EXISTS resource_review_events_history_idx
       ON resource_review_events (workspace_id, resource_key, created_at)`,
    ),
    env.DB.prepare(
      `CREATE INDEX IF NOT EXISTS access_policy_versions_policy_idx
       ON access_policy_versions (workspace_id, policy_id, version)`,
    ),
    env.DB.prepare(
      `CREATE INDEX IF NOT EXISTS campaign_items_campaign_status_idx
       ON campaign_items (workspace_id, campaign_id, status)`,
    ),
    env.DB.prepare(
      `CREATE INDEX IF NOT EXISTS remediation_requests_queue_idx
       ON remediation_requests (workspace_id, status, updated_at)`,
    ),
    env.DB.prepare(
      `CREATE INDEX IF NOT EXISTS integration_deliveries_queue_idx
       ON integration_deliveries (workspace_id, status, next_attempt_at)`,
    ),
    env.DB.prepare(
      `CREATE INDEX IF NOT EXISTS verification_runs_remediation_idx
       ON verification_runs (workspace_id, remediation_id, created_at)`,
    ),
    env.DB.prepare(
      `CREATE INDEX IF NOT EXISTS program_metric_snapshots_period_idx
       ON program_metric_snapshots (workspace_id, period_start)`,
    ),
    env.DB.prepare(
      `CREATE UNIQUE INDEX IF NOT EXISTS ingested_objects_identity_unique
       ON ingested_objects (source_id, object_key, version_id)`,
    ),
    env.DB.prepare(
      `CREATE INDEX IF NOT EXISTS ingestion_runs_source_started_idx
       ON ingestion_runs (source_id, started_at)`,
    ),
    env.DB.prepare(
      `CREATE INDEX IF NOT EXISTS audit_events_workspace_created_idx
       ON audit_events (workspace_id, created_at)`,
    ),
  ]);

  // Runtime schema initialization must also upgrade databases created by older
  // releases. CREATE TABLE IF NOT EXISTS preserves those tables unchanged, so
  // add newly introduced Jira reconciliation fields explicitly and safely.
  const jiraColumns = await env.DB.prepare(
    "PRAGMA table_info(finding_jira_links)",
  ).all<{ name: string }>();
  const existingJiraColumns = new Set(
    jiraColumns.results.map((column) => column.name),
  );
  const jiraColumnMigrations = [
    ["remote_status", "ALTER TABLE finding_jira_links ADD COLUMN remote_status TEXT NOT NULL DEFAULT ''"],
    ["remote_resolution", "ALTER TABLE finding_jira_links ADD COLUMN remote_resolution TEXT NOT NULL DEFAULT ''"],
    ["remote_updated_at", "ALTER TABLE finding_jira_links ADD COLUMN remote_updated_at TEXT NOT NULL DEFAULT ''"],
    ["last_synced_at", "ALTER TABLE finding_jira_links ADD COLUMN last_synced_at TEXT NOT NULL DEFAULT ''"],
  ] as const;
  for (const [column, statement] of jiraColumnMigrations) {
    if (existingJiraColumns.has(column)) continue;
    try {
      await env.DB.prepare(statement).run();
    } catch (error) {
      // Concurrent cold starts may both observe the old table. Ignore only the
      // benign race where the other request has already added this column.
      if (!(error instanceof Error) || !/duplicate column name/i.test(error.message)) {
        throw error;
      }
    }
  }
  const existingRoleColumns = new Set(
    (
      await env.DB.prepare("PRAGMA table_info(user_roles)").all<{
        name: string;
      }>()
    ).results.map((column) => column.name),
  );
  if (!existingRoleColumns.has("subject")) {
    try {
      await env.DB.prepare(
        "ALTER TABLE user_roles ADD COLUMN subject TEXT NOT NULL DEFAULT ''",
      ).run();
    } catch (error) {
      if (!(error instanceof Error) || !/duplicate column name/i.test(error.message)) {
        throw error;
      }
    }
  }
  await env.DB.prepare(
    `CREATE UNIQUE INDEX IF NOT EXISTS user_roles_subject_idx
       ON user_roles(workspace_id, subject) WHERE subject <> ''`,
  ).run();
}

async function deliverAuditOutbox(limit = 20) {
  const bridgeUrl = cleanText(env.GATEWATCH_AWS_BRIDGE_URL, 500).replace(/\/$/, "");
  const bridgeToken = cleanText(env.GATEWATCH_AWS_BRIDGE_TOKEN, 500);
  if (!bridgeUrl || !bridgeToken) return;
  const pending = await env.DB.prepare(
    `SELECT event_id AS eventId, payload
       FROM audit_archive_outbox
      WHERE delivered_at = '' AND next_attempt_at <= CURRENT_TIMESTAMP
      ORDER BY created_at
      LIMIT ?`,
  ).bind(Math.max(1, Math.min(50, limit))).all<{ eventId: string; payload: string }>();
  for (const item of pending.results) {
    try {
      const response = await fetch(`${bridgeUrl}/audit/events`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${bridgeToken}`,
          "content-type": "application/json",
        },
        body: item.payload,
        signal: AbortSignal.timeout(8_000),
      });
      const responseText = await response.text();
      if (responseText.length > 4_096) throw new Error("AUDIT_ARCHIVE_RESPONSE_TOO_LARGE");
      const body = JSON.parse(responseText) as { versionId?: string };
      if (!response.ok || !body.versionId) throw new Error("AUDIT_ARCHIVE_REJECTED");
      await env.DB.prepare(
        `UPDATE audit_archive_outbox
            SET delivered_at = CURRENT_TIMESTAMP, archive_version_id = ?,
                last_error = ''
          WHERE event_id = ? AND delivered_at = ''`,
      ).bind(body.versionId.slice(0, 1024), item.eventId).run();
    } catch (error) {
      await env.DB.prepare(
        `UPDATE audit_archive_outbox
            SET attempts = attempts + 1,
                next_attempt_at = datetime('now', '+' || min(3600, (attempts + 1) * 30) || ' seconds'),
                last_error = ?
          WHERE event_id = ? AND delivered_at = ''`,
      ).bind(
        error instanceof Error ? error.name.slice(0, 120) : "Error",
        item.eventId,
      ).run();
    }
  }
}

export async function audit(
  actor: string,
  action: string,
  targetType: string,
  targetId: string,
  summary: string,
  metadata: Record<string, unknown> = {},
) {
  await ensureAdminSchema();
  const id = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  const metadataJson = JSON.stringify(metadata);
  const boundedMetadata = metadataJson.length <= 8_000
    ? metadata
    : { truncated: true, originalBytes: metadataJson.length };
  const event = {
    schemaVersion: "1.0",
    id,
    workspaceId: "default",
    actorSubject: actor,
    action,
    targetType,
    targetId,
    summary: summary.slice(0, 800),
    metadata: boundedMetadata,
    createdAt,
  };
  const payload = JSON.stringify(event);
  await env.DB.batch([
    env.DB.prepare(
    `INSERT INTO audit_events
      (id, actor, action, target_type, target_id, summary, metadata, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      id,
      actor,
      action,
      targetType,
      targetId,
      summary.slice(0, 800),
      JSON.stringify(boundedMetadata),
      createdAt,
    ),
    env.DB.prepare(
      `INSERT INTO audit_archive_outbox (event_id, payload, created_at)
       VALUES (?, ?, ?)`,
    ).bind(id, payload, createdAt),
  ]);
  await deliverAuditOutbox().catch(() => undefined);
}

export type NotificationPolicy = {
  enabled: boolean;
  minimumSeverity: "critical" | "high" | "medium" | "low";
  events: string[];
  recipients: string[];
  digest: "immediate" | "daily";
};

const severityRank = { low: 1, medium: 2, high: 3, critical: 4 } as const;

export async function queueNotification(
  eventType: string,
  targetId: string,
  severity: keyof typeof severityRank,
  payload: Record<string, unknown>,
) {
  const row = await env.DB.prepare(
    "SELECT value FROM system_settings WHERE key = 'notifications' AND workspace_id = 'default'",
  ).first<{ value: string }>();
  const policy = safeJson<NotificationPolicy | null>(row?.value, null);
  if (
    !policy?.enabled ||
    !policy.events.includes(eventType) ||
    severityRank[severity] < severityRank[policy.minimumSeverity]
  ) {
    return null;
  }
  const id = crypto.randomUUID();
  await env.DB.prepare(
    `INSERT INTO integration_deliveries
      (id, workspace_id, integration, event_type, target_id, status,
       payload, next_attempt_at)
     VALUES (?, 'default', 'notification', ?, ?, 'pending', ?, CURRENT_TIMESTAMP)`,
  )
    .bind(
      id,
      eventType,
      targetId,
      JSON.stringify({ severity, recipients: policy.recipients, digest: policy.digest, ...payload }).slice(0, 20_000),
    )
    .run();
  return id;
}

export function safeJson<T>(value: unknown, fallback: T): T {
  if (typeof value !== "string") return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}
