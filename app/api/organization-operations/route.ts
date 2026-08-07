import { env } from "cloudflare:workers";
import { configuredAwsInventory, loadAwsInventory } from "../../../lib/aws-inventory";
import {
  accountContextFromGroups,
  accountEnvironments,
  csvCell,
  defaultRiskWeights,
  exportFormats,
  isSecurityGroupArn,
  monitorSchedules,
  monitorTriggers,
  nextMonitorRun,
  securityGroupArn,
} from "../../../lib/organization-operations";
import { securityGroups, type SecurityGroup } from "../../../lib/security-data";
import { cleanText } from "../../../lib/admin-sources";
import {
  apiJson,
  audit,
  ensureAdminSchema,
  requestUser,
  requirePermission,
  queueNotification,
  safeJson,
  sameOrigin,
} from "../../../lib/server-admin";

type JsonBody = Record<string, unknown>;
type AccountRow = {
  accountId: string; accountName: string; organizationalUnit: string; environment: string;
  businessUnit: string; owner: string; tags: string; status: string; lastSeenAt: string; updatedAt: string;
};

const groupByOptions = new Set(["account", "organizational-unit", "environment", "region", "owner", "severity"]);
const legalHoldScopes = new Set(["workspace", "account", "security-group", "finding", "export"]);

async function ensureSchema() {
  await ensureAdminSchema();
  await env.DB.batch([
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS aws_account_catalog (
      account_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL DEFAULT 'default', account_name TEXT NOT NULL,
      organizational_unit TEXT NOT NULL DEFAULT 'Unassigned', environment TEXT NOT NULL DEFAULT 'Shared',
      business_unit TEXT NOT NULL DEFAULT 'Unassigned', owner TEXT NOT NULL DEFAULT 'Unassigned', tags TEXT NOT NULL DEFAULT '{}',
      status TEXT NOT NULL DEFAULT 'active', last_seen_at TEXT NOT NULL DEFAULT '', updated_by TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`),
    env.DB.prepare(`CREATE INDEX IF NOT EXISTS aws_account_catalog_context_idx ON aws_account_catalog (workspace_id, organizational_unit, environment)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS evidence_correlation_mappings (
      id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL DEFAULT 'default', source_identifier TEXT NOT NULL,
      security_group_arn TEXT NOT NULL, confidence INTEGER NOT NULL DEFAULT 100, reason TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active', created_by TEXT NOT NULL, revoked_by TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`),
    env.DB.prepare(`CREATE INDEX IF NOT EXISTS evidence_correlation_source_idx ON evidence_correlation_mappings (workspace_id, source_identifier, status)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS evidence_monitors (
      id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL DEFAULT 'default', name TEXT NOT NULL, query TEXT NOT NULL DEFAULT '',
      filters TEXT NOT NULL DEFAULT '{}', group_by TEXT NOT NULL DEFAULT 'account', schedule TEXT NOT NULL DEFAULT 'daily',
      trigger_mode TEXT NOT NULL DEFAULT 'enters', destinations TEXT NOT NULL DEFAULT '[]', visibility TEXT NOT NULL DEFAULT 'personal',
      owner TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', last_run_at TEXT NOT NULL DEFAULT '', next_run_at TEXT NOT NULL DEFAULT '',
      last_match_count INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS evidence_monitor_runs (
      id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL DEFAULT 'default', monitor_id TEXT NOT NULL, status TEXT NOT NULL,
      match_count INTEGER NOT NULL DEFAULT 0, entered_count INTEGER NOT NULL DEFAULT 0, exited_count INTEGER NOT NULL DEFAULT 0,
      summary TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS evidence_export_jobs (
      id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL DEFAULT 'default', name TEXT NOT NULL, format TEXT NOT NULL,
      scope TEXT NOT NULL DEFAULT '{}', schedule TEXT NOT NULL DEFAULT 'once', status TEXT NOT NULL DEFAULT 'queued',
      row_count INTEGER NOT NULL DEFAULT 0, checksum TEXT NOT NULL DEFAULT '', requested_by TEXT NOT NULL,
      expires_at TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, completed_at TEXT NOT NULL DEFAULT '')`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS evidence_retention_policies (
      workspace_id TEXT PRIMARY KEY DEFAULT 'default', raw_evidence_days INTEGER NOT NULL DEFAULT 400,
      normalized_evidence_days INTEGER NOT NULL DEFAULT 365, audit_days INTEGER NOT NULL DEFAULT 2555,
      export_days INTEGER NOT NULL DEFAULT 30, updated_by TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS evidence_legal_holds (
      id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL DEFAULT 'default', name TEXT NOT NULL, scope_type TEXT NOT NULL,
      scope_value TEXT NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', requested_by TEXT NOT NULL,
      released_by TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, released_at TEXT NOT NULL DEFAULT '')`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS risk_score_policies (
      id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL DEFAULT 'default', name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'draft',
      weights TEXT NOT NULL DEFAULT '{}', thresholds TEXT NOT NULL DEFAULT '{}', created_by TEXT NOT NULL, updated_by TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS semantic_evidence_events (
      fingerprint TEXT PRIMARY KEY, workspace_id TEXT NOT NULL DEFAULT 'default', canonical_event_id TEXT NOT NULL,
      provider_id TEXT NOT NULL DEFAULT '', source_type TEXT NOT NULL, security_group_arn TEXT NOT NULL,
      observed_at TEXT NOT NULL, provenance TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`),
  ]);
}

async function inventory() {
  if (configuredAwsInventory()) return loadAwsInventory();
  return { groups: securityGroups, source: { complete: true, generatedAt: new Date().toISOString(), coveragePercent: 100 } };
}

function jsonError(error: unknown, fallback: string) {
  if (error instanceof SyntaxError) return apiJson({ error: "Request body must be valid JSON." }, 400);
  return apiJson({ error: fallback }, 503);
}

function strings(value: unknown, maxItems = 10) {
  if (!Array.isArray(value)) return [];
  return value.slice(0, maxItems).map((item) => cleanText(item, 160)).filter(Boolean);
}

async function boundedJson(request: Request) {
  if (!request.headers.get("content-type")?.startsWith("application/json")) {
    throw new Response(JSON.stringify({ error: "Content-Type must be application/json." }), { status: 415 });
  }
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (declared > 50_000) throw new Response(JSON.stringify({ error: "The request is too large." }), { status: 413 });
  const text = await request.text();
  if (new TextEncoder().encode(text).byteLength > 50_000) throw new Response(JSON.stringify({ error: "The request is too large." }), { status: 413 });
  return JSON.parse(text) as JsonBody;
}

function matchesQuery(group: SecurityGroup, query: string) {
  if (!query) return true;
  return [group.id, group.name, group.accountId, group.accountName, group.region, group.owner, group.environment, ...group.findings]
    .join(" ").toLowerCase().includes(query.toLowerCase());
}

function exportBody(groups: SecurityGroup[], format: string) {
  const rows = groups.map((group) => ({
    securityGroupArn: securityGroupArn(group), accountId: group.accountId, accountName: group.accountName,
    region: group.region, securityGroupId: group.id, name: group.name, environment: group.environment,
    owner: group.owner, severity: group.severity, riskScore: group.riskScore, findings: group.findings,
  }));
  if (format === "csv") {
    const header = ["securityGroupArn", "accountId", "accountName", "region", "securityGroupId", "name", "environment", "owner", "severity", "riskScore", "findings"];
    return { contentType: "text/csv; charset=utf-8", extension: "csv", body: [header.join(","), ...rows.map((row) => header.map((key) => csvCell(key === "findings" ? row.findings.join(" | ") : row[key as keyof typeof row])).join(","))].join("\n") };
  }
  return { contentType: "application/json; charset=utf-8", extension: "json", body: JSON.stringify({ schemaVersion: "1.0", generatedAt: new Date().toISOString(), groups: rows }, null, 2) };
}

export async function GET(request: Request) {
  try {
    const user = requestUser(request);
    if (!user) return apiJson({ error: "Authentication is required." }, 401);
    await ensureSchema();
    const url = new URL(request.url);
    const downloadId = cleanText(url.searchParams.get("download"), 80);
    if (downloadId) {
      const job = await env.DB.prepare(`SELECT name, format, scope, status FROM evidence_export_jobs WHERE id = ? AND workspace_id = 'default'`).bind(downloadId).first<{ name: string; format: string; scope: string; status: string }>();
      if (!job) return apiJson({ error: "Export job was not found." }, 404);
      if (job.status !== "complete") return apiJson({ error: "This export is still being prepared by the worker." }, 409);
      const data = await inventory();
      const scope = safeJson<{ query?: string }>(job.scope, {});
      const output = exportBody(data.groups.filter((group) => matchesQuery(group, scope.query ?? "")), job.format);
      return new Response(output.body, { headers: {
        "content-type": output.contentType,
        "content-disposition": `attachment; filename="gatewatch-${downloadId}.${output.extension}"`,
        "cache-control": "no-store, private", "x-content-type-options": "nosniff",
      }});
    }

    const data = await inventory();
    const derived = accountContextFromGroups(data.groups);
    const [accountResult, mappingResult, monitorResult, runResult, exportResult, retention, holdResult, riskResult, observations, evidence] = await Promise.all([
      env.DB.prepare(`SELECT account_id AS accountId, account_name AS accountName, organizational_unit AS organizationalUnit,
        environment, business_unit AS businessUnit, owner, tags, status, last_seen_at AS lastSeenAt, updated_at AS updatedAt
        FROM aws_account_catalog WHERE workspace_id = 'default' ORDER BY account_name LIMIT 2000`).all<AccountRow>(),
      env.DB.prepare(`SELECT id, source_identifier AS sourceIdentifier, security_group_arn AS securityGroupArn, confidence, reason,
        status, created_by AS createdBy, revoked_by AS revokedBy, created_at AS createdAt, updated_at AS updatedAt
        FROM evidence_correlation_mappings WHERE workspace_id = 'default' ORDER BY updated_at DESC LIMIT 500`).all<Record<string, unknown>>(),
      env.DB.prepare(`SELECT id, name, query, filters, group_by AS groupBy, schedule, trigger_mode AS triggerMode, destinations,
        visibility, owner, status, last_run_at AS lastRunAt, next_run_at AS nextRunAt, last_match_count AS lastMatchCount,
        created_at AS createdAt, updated_at AS updatedAt FROM evidence_monitors WHERE workspace_id = 'default' ORDER BY updated_at DESC LIMIT 250`).all<Record<string, unknown>>(),
      env.DB.prepare(`SELECT id, monitor_id AS monitorId, status, match_count AS matchCount, entered_count AS enteredCount,
        exited_count AS exitedCount, summary, created_at AS createdAt FROM evidence_monitor_runs WHERE workspace_id = 'default' ORDER BY created_at DESC LIMIT 100`).all<Record<string, unknown>>(),
      env.DB.prepare(`SELECT id, name, format, scope, schedule, status, row_count AS rowCount, checksum, requested_by AS requestedBy,
        expires_at AS expiresAt, created_at AS createdAt, completed_at AS completedAt FROM evidence_export_jobs
        WHERE workspace_id = 'default' ORDER BY created_at DESC LIMIT 100`).all<Record<string, unknown>>(),
      env.DB.prepare(`SELECT raw_evidence_days AS rawEvidenceDays, normalized_evidence_days AS normalizedEvidenceDays,
        audit_days AS auditDays, export_days AS exportDays, updated_by AS updatedBy, updated_at AS updatedAt
        FROM evidence_retention_policies WHERE workspace_id = 'default'`).first<Record<string, unknown>>(),
      env.DB.prepare(`SELECT id, name, scope_type AS scopeType, scope_value AS scopeValue, reason, status,
        requested_by AS requestedBy, released_by AS releasedBy, created_at AS createdAt, released_at AS releasedAt
        FROM evidence_legal_holds WHERE workspace_id = 'default' ORDER BY created_at DESC LIMIT 100`).all<Record<string, unknown>>(),
      env.DB.prepare(`SELECT id, name, status, weights, thresholds, created_by AS createdBy, updated_by AS updatedBy,
        created_at AS createdAt, updated_at AS updatedAt FROM risk_score_policies WHERE workspace_id = 'default' ORDER BY updated_at DESC LIMIT 50`).all<Record<string, unknown>>(),
      env.DB.prepare(`SELECT state, COUNT(*) AS count, SUM(CASE WHEN observation_count > 1 THEN 1 ELSE 0 END) AS recurring,
        MIN(first_seen_at) AS earliest, MAX(last_seen_at) AS latest FROM finding_observations WHERE workspace_id = 'default' GROUP BY state`).all<Record<string, unknown>>(),
      env.DB.prepare(`SELECT r.source_id AS sourceId, r.account_id AS accountId, COUNT(*) AS recordCount, MAX(r.observed_at) AS latest
        FROM aws_evidence_records r
        LEFT JOIN evidence_correlation_mappings m ON m.workspace_id = r.workspace_id
          AND m.source_identifier = r.resource_id AND m.status = 'active'
        WHERE r.workspace_id = 'default' AND r.resource_id NOT LIKE 'sg-%' AND m.id IS NULL
        GROUP BY r.source_id, r.account_id ORDER BY recordCount DESC LIMIT 1000`).all<Record<string, unknown>>(),
    ]);
    const persisted = new Map(accountResult.results.map((row) => [row.accountId, row]));
    const accounts = derived.map((item) => {
      const saved = persisted.get(item.accountId);
      return { ...item, ...(saved ?? {}), tags: safeJson(saved?.tags, {}), regionCount: item.regionCount, groupCount: item.groupCount,
        findingCount: item.findingCount, criticalCount: item.criticalCount };
    });
    const regionHeatmap = [...new Set(data.groups.map((group) => group.region))].sort().map((region) => ({
      region,
      accounts: new Set(data.groups.filter((group) => group.region === region).map((group) => group.accountId)).size,
      groups: data.groups.filter((group) => group.region === region).length,
      findings: data.groups.filter((group) => group.region === region).reduce((sum, group) => sum + group.findings.length, 0),
    }));
    return apiJson({
      generatedAt: new Date().toISOString(), source: data.source,
      summary: { accounts: accounts.length, organizationalUnits: new Set(accounts.map((item) => item.organizationalUnit)).size,
        activeMappings: mappingResult.results.filter((item) => item.status === "active").length,
        activeMonitors: monitorResult.results.filter((item) => item.status === "active").length,
        queuedExports: exportResult.results.filter((item) => item.status !== "complete").length,
        activeLegalHolds: holdResult.results.filter((item) => item.status === "active").length },
      accounts, mappings: mappingResult.results,
      monitors: monitorResult.results.map((item) => ({ ...item, filters: safeJson(item.filters, {}), destinations: safeJson(item.destinations, []) })),
      monitorRuns: runResult.results.map((item) => ({ ...item, summary: safeJson(item.summary, {}) })),
      exports: exportResult.results.map((item) => ({ ...item, scope: safeJson(item.scope, {}) })),
      retention: retention ?? { rawEvidenceDays: 400, normalizedEvidenceDays: 365, auditDays: 2555, exportDays: 30 },
      legalHolds: holdResult.results,
      riskPolicies: riskResult.results.map((item) => ({ ...item, weights: safeJson(item.weights, defaultRiskWeights), thresholds: safeJson(item.thresholds, { critical: 85, high: 70, medium: 45 }) })),
      temporal: observations.results,
      evidenceHealth: evidence.results,
      regionHeatmap,
      capabilities: { parquetWorker: false, durableExports: true, crossSourceDedup: true, accountCatalog: true },
      currentUser: user,
    });
  } catch (error) {
    return jsonError(error, "Organization operations data is temporarily unavailable.");
  }
}

export async function POST(request: Request) {
  try {
    const user = requestUser(request);
    if (!user) return apiJson({ error: "Authentication is required." }, 401);
    if (!sameOrigin(request)) return apiJson({ error: "Origin is not allowed." }, 403);
    if (!request.headers.get("content-type")?.startsWith("application/json")) return apiJson({ error: "Send an application/json request." }, 415);
    await ensureSchema();
    const body = await boundedJson(request);
    const action = cleanText(body.action, 50);
    const adminActions = new Set(["sync-accounts", "account-update", "retention-update", "hold-create", "hold-release", "risk-policy-save", "risk-policy-activate"]);
    const permission = await requirePermission(request, adminActions.has(action) ? "administration.manage" : "intelligence.write");
    if (!permission.allowed) return apiJson({ error: adminActions.has(action) ? "Administrator access is required." : "Analyst access is required." }, 403);

    if (action === "sync-accounts") {
      const data = await inventory();
      const accounts = accountContextFromGroups(data.groups);
      for (let offset = 0; offset < accounts.length; offset += 80) {
        await env.DB.batch(accounts.slice(offset, offset + 80).map((account) => env.DB.prepare(`INSERT INTO aws_account_catalog
            (account_id, account_name, environment, owner, last_seen_at, updated_by)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(account_id) DO UPDATE SET account_name = excluded.account_name, last_seen_at = excluded.last_seen_at,
              updated_by = excluded.updated_by, updated_at = CURRENT_TIMESTAMP`)
          .bind(account.accountId, account.accountName, account.environment, account.owner, account.lastSeenAt, user)));
      }
      await audit(user, "account.catalog.sync", "workspace", "default", `Synchronized ${accounts.length} AWS accounts.`);
      return apiJson({ synced: accounts.length });
    }

    if (action === "account-update") {
      const accountId = cleanText(body.accountId, 12);
      const environment = cleanText(body.environment, 30);
      if (!/^\d{12}$/.test(accountId) || !accountEnvironments.includes(environment as never)) return apiJson({ error: "Choose a valid AWS account and environment." }, 400);
      const fields = {
        accountName: cleanText(body.accountName, 120), organizationalUnit: cleanText(body.organizationalUnit, 180),
        businessUnit: cleanText(body.businessUnit, 120), owner: cleanText(body.owner, 160),
      };
      if (!fields.accountName || !fields.organizationalUnit || !fields.businessUnit || !fields.owner) return apiJson({ error: "Account name, OU, business unit, and owner are required." }, 400);
      const tags = typeof body.tags === "object" && body.tags && !Array.isArray(body.tags) ? JSON.stringify(body.tags).slice(0, 8000) : "{}";
      await env.DB.prepare(`INSERT INTO aws_account_catalog
        (account_id, account_name, organizational_unit, environment, business_unit, owner, tags, updated_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(account_id) DO UPDATE SET account_name = excluded.account_name, organizational_unit = excluded.organizational_unit,
          environment = excluded.environment, business_unit = excluded.business_unit, owner = excluded.owner, tags = excluded.tags,
          updated_by = excluded.updated_by, updated_at = CURRENT_TIMESTAMP`)
        .bind(accountId, fields.accountName, fields.organizationalUnit, environment, fields.businessUnit, fields.owner, tags, user).run();
      await audit(user, "account.catalog.update", "aws-account", accountId, `Updated organization context for AWS account ${accountId}.`);
      return apiJson({ updated: true });
    }

    if (action === "mapping-save") {
      const sourceIdentifier = cleanText(body.sourceIdentifier, 240);
      const arn = cleanText(body.securityGroupArn, 240);
      const reason = cleanText(body.reason, 800);
      const confidence = Math.max(1, Math.min(100, Number(body.confidence) || 0));
      if (sourceIdentifier.length < 3 || !isSecurityGroupArn(arn) || reason.length < 8) return apiJson({ error: "Provide a source identifier, full security-group ARN, and an audit reason." }, 400);
      await env.DB.prepare(`UPDATE evidence_correlation_mappings SET status = 'superseded', revoked_by = ?, updated_at = CURRENT_TIMESTAMP
        WHERE workspace_id = 'default' AND source_identifier = ? AND status = 'active'`).bind(user, sourceIdentifier).run();
      const id = crypto.randomUUID();
      await env.DB.prepare(`INSERT INTO evidence_correlation_mappings
        (id, source_identifier, security_group_arn, confidence, reason, created_by) VALUES (?, ?, ?, ?, ?, ?)`)
        .bind(id, sourceIdentifier, arn, confidence, reason, user).run();
      await audit(user, "evidence.correlation.map", "correlation-mapping", id, `Mapped ${sourceIdentifier} to ${arn}.`, { confidence });
      return apiJson({ created: true, id }, 201);
    }

    if (action === "mapping-revoke") {
      const id = cleanText(body.id, 80);
      const result = await env.DB.prepare(`UPDATE evidence_correlation_mappings SET status = 'revoked', revoked_by = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND workspace_id = 'default' AND status = 'active'`).bind(user, id).run() as { meta?: { changes?: number } };
      if (!result.meta?.changes) return apiJson({ error: "Active mapping was not found." }, 404);
      await audit(user, "evidence.correlation.revoke", "correlation-mapping", id, "Revoked an analyst evidence mapping.");
      return apiJson({ revoked: true });
    }

    if (action === "monitor-save") {
      const name = cleanText(body.name, 120); const query = cleanText(body.query, 160);
      const schedule = cleanText(body.schedule, 20); const triggerMode = cleanText(body.triggerMode, 30);
      const groupBy = cleanText(body.groupBy, 30); const visibility = body.visibility === "team" ? "team" : "personal";
      if (name.length < 3 || !monitorSchedules.includes(schedule as never) || !monitorTriggers.includes(triggerMode as never) || !groupByOptions.has(groupBy)) return apiJson({ error: "Provide a monitor name and supported schedule, trigger, and grouping." }, 400);
      const id = cleanText(body.id, 80) || crypto.randomUUID();
      const destinations = strings(body.destinations, 5);
      if (body.id) {
        const existing = await env.DB.prepare(`SELECT owner FROM evidence_monitors WHERE id = ? AND workspace_id = 'default'`).bind(id).first<{ owner: string }>();
        if (!existing) return apiJson({ error: "Monitor was not found." }, 404);
        if (existing.owner !== user && permission.role !== "admin") return apiJson({ error: "Only the owner or an administrator can edit this monitor." }, 403);
      }
      await env.DB.prepare(`INSERT INTO evidence_monitors
        (id, name, query, filters, group_by, schedule, trigger_mode, destinations, visibility, owner, next_run_at)
        VALUES (?, ?, ?, '{}', ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET name = excluded.name, query = excluded.query, group_by = excluded.group_by,
          schedule = excluded.schedule, trigger_mode = excluded.trigger_mode, destinations = excluded.destinations,
          visibility = excluded.visibility, updated_at = CURRENT_TIMESTAMP`)
        .bind(id, name, query, groupBy, schedule, triggerMode, JSON.stringify(destinations), visibility, user, nextMonitorRun(schedule)).run();
      await audit(user, "monitor.save", "evidence-monitor", id, `${body.id ? "Updated" : "Created"} monitor ${name}.`);
      return apiJson({ saved: true, id }, body.id ? 200 : 201);
    }

    if (action === "monitor-status") {
      const id = cleanText(body.id, 80); const status = body.status === "active" ? "active" : "paused";
      const result = await env.DB.prepare(`UPDATE evidence_monitors SET status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND workspace_id = 'default' AND (owner = ? OR ? = 'admin')`).bind(status, id, user, permission.role).run() as { meta?: { changes?: number } };
      if (!result.meta?.changes) return apiJson({ error: "Monitor was not found." }, 404);
      await audit(user, "monitor.status", "evidence-monitor", id, `Changed monitor status to ${status}.`);
      return apiJson({ updated: true });
    }

    if (action === "monitor-delete") {
      const id = cleanText(body.id, 80);
      const result = await env.DB.prepare(`DELETE FROM evidence_monitors WHERE id = ? AND workspace_id = 'default'
        AND (owner = ? OR ? = 'admin')`).bind(id, user, permission.role).run() as { meta?: { changes?: number } };
      if (!result.meta?.changes) return apiJson({ error: "Monitor was not found." }, 404);
      await audit(user, "monitor.delete", "evidence-monitor", id, "Deleted an evidence monitor.");
      return apiJson({ deleted: true });
    }

    if (action === "monitor-run") {
      const id = cleanText(body.id, 80);
      const monitor = await env.DB.prepare(`SELECT query, schedule, last_match_count AS lastMatchCount FROM evidence_monitors
        WHERE id = ? AND workspace_id = 'default' AND (owner = ? OR visibility = 'team' OR ? = 'admin')`).bind(id, user, permission.role).first<{ query: string; schedule: string; lastMatchCount: number }>();
      if (!monitor) return apiJson({ error: "Monitor was not found." }, 404);
      const data = await inventory(); const matches = data.groups.filter((group) => matchesQuery(group, monitor.query));
      const entered = Math.max(0, matches.length - monitor.lastMatchCount); const exited = Math.max(0, monitor.lastMatchCount - matches.length);
      const runId = crypto.randomUUID(); const now = new Date().toISOString();
      await env.DB.batch([
        env.DB.prepare(`INSERT INTO evidence_monitor_runs (id, monitor_id, status, match_count, entered_count, exited_count, summary)
          VALUES (?, ?, 'complete', ?, ?, ?, ?)`).bind(runId, id, matches.length, entered, exited, JSON.stringify({ query: monitor.query, snapshotGeneratedAt: data.source.generatedAt })),
        env.DB.prepare(`UPDATE evidence_monitors SET last_run_at = ?, next_run_at = ?, last_match_count = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
          .bind(now, nextMonitorRun(monitor.schedule), matches.length, id),
      ]);
      if (entered || exited) {
        await queueNotification("monitor-transition", id, entered ? "high" : "medium", {
          monitorId: id, query: monitor.query, matchCount: matches.length, entered, exited,
        });
      }
      await audit(user, "monitor.run", "evidence-monitor", id, `Monitor matched ${matches.length} security groups.`, { entered, exited });
      return apiJson({ completed: true, matches: matches.length, entered, exited });
    }

    if (action === "export-create") {
      const format = cleanText(body.format, 30); const name = cleanText(body.name, 120); const query = cleanText(body.query, 160);
      const schedule = ["once", "daily", "weekly", "monthly"].includes(String(body.schedule)) ? String(body.schedule) : "once";
      if (!exportFormats.includes(format as never) || name.length < 3) return apiJson({ error: "Choose an export name and supported format." }, 400);
      const data = await inventory(); const rows = data.groups.filter((group) => matchesQuery(group, query));
      const id = crypto.randomUUID(); const workerRequired = format === "parquet" || schedule !== "once";
      const status = workerRequired ? "queued" : "complete"; const completedAt = workerRequired ? "" : new Date().toISOString();
      const expires = new Date(); expires.setUTCDate(expires.getUTCDate() + 30);
      await env.DB.prepare(`INSERT INTO evidence_export_jobs
        (id, name, format, scope, schedule, status, row_count, requested_by, expires_at, completed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .bind(id, name, format, JSON.stringify({ query }), schedule, status, rows.length, user, expires.toISOString(), completedAt).run();
      await audit(user, "export.create", "evidence-export", id, `Created ${format} export ${name}.`, { schedule, rowCount: rows.length });
      return apiJson({ created: true, id, status }, 201);
    }

    if (action === "retention-update") {
      const values = [body.rawEvidenceDays, body.normalizedEvidenceDays, body.auditDays, body.exportDays].map(Number);
      if (values.some((value) => !Number.isInteger(value) || value < 7 || value > 3650)) return apiJson({ error: "Retention values must be whole days between 7 and 3,650." }, 400);
      await env.DB.prepare(`INSERT INTO evidence_retention_policies
        (workspace_id, raw_evidence_days, normalized_evidence_days, audit_days, export_days, updated_by)
        VALUES ('default', ?, ?, ?, ?, ?)
        ON CONFLICT(workspace_id) DO UPDATE SET raw_evidence_days = excluded.raw_evidence_days,
          normalized_evidence_days = excluded.normalized_evidence_days, audit_days = excluded.audit_days,
          export_days = excluded.export_days, updated_by = excluded.updated_by, updated_at = CURRENT_TIMESTAMP`)
        .bind(...values, user).run();
      await audit(user, "retention.update", "workspace", "default", "Updated evidence retention policy.");
      return apiJson({ updated: true });
    }

    if (action === "hold-create") {
      const id = crypto.randomUUID(); const name = cleanText(body.name, 120); const scopeType = cleanText(body.scopeType, 30);
      const scopeValue = cleanText(body.scopeValue, 240); const reason = cleanText(body.reason, 800);
      if (name.length < 3 || !legalHoldScopes.has(scopeType) || !scopeValue || reason.length < 8) return apiJson({ error: "Provide a name, scope, value, and legal-hold reason." }, 400);
      await env.DB.prepare(`INSERT INTO evidence_legal_holds (id, name, scope_type, scope_value, reason, requested_by) VALUES (?, ?, ?, ?, ?, ?)`)
        .bind(id, name, scopeType, scopeValue, reason, user).run();
      await audit(user, "legal-hold.create", "legal-hold", id, `Created legal hold ${name}.`, { scopeType, scopeValue });
      return apiJson({ created: true, id }, 201);
    }

    if (action === "hold-release") {
      const id = cleanText(body.id, 80);
      const result = await env.DB.prepare(`UPDATE evidence_legal_holds SET status = 'released', released_by = ?, released_at = CURRENT_TIMESTAMP
        WHERE id = ? AND workspace_id = 'default' AND status = 'active'`).bind(user, id).run() as { meta?: { changes?: number } };
      if (!result.meta?.changes) return apiJson({ error: "Active legal hold was not found." }, 404);
      await audit(user, "legal-hold.release", "legal-hold", id, "Released a legal hold.");
      return apiJson({ released: true });
    }

    if (action === "risk-policy-save" || action === "risk-policy-activate") {
      const id = cleanText(body.id, 80) || crypto.randomUUID(); const name = cleanText(body.name, 120);
      const incoming = typeof body.weights === "object" && body.weights ? body.weights as Record<string, unknown> : {};
      const weights = Object.fromEntries(Object.entries(defaultRiskWeights).map(([key, fallback]) => [key, Math.max(0, Math.min(50, Number(incoming[key]) || fallback))]));
      const thresholds = typeof body.thresholds === "object" && body.thresholds ? body.thresholds : { critical: 85, high: 70, medium: 45 };
      if (name.length < 3) return apiJson({ error: "Risk policy name must have at least three characters." }, 400);
      if (action === "risk-policy-activate") await env.DB.prepare(`UPDATE risk_score_policies SET status = 'retired', updated_by = ?, updated_at = CURRENT_TIMESTAMP WHERE workspace_id = 'default' AND status = 'active'`).bind(user).run();
      const status = action === "risk-policy-activate" ? "active" : "draft";
      await env.DB.prepare(`INSERT INTO risk_score_policies (id, name, status, weights, thresholds, created_by, updated_by)
        VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET name = excluded.name, status = excluded.status,
          weights = excluded.weights, thresholds = excluded.thresholds, updated_by = excluded.updated_by, updated_at = CURRENT_TIMESTAMP`)
        .bind(id, name, status, JSON.stringify(weights), JSON.stringify(thresholds), user, user).run();
      await audit(user, `risk-policy.${status}`, "risk-score-policy", id, `${status === "active" ? "Activated" : "Saved"} risk policy ${name}.`);
      return apiJson({ saved: true, id, status });
    }

    return apiJson({ error: "Choose a supported organization operations action." }, 400);
  } catch (error) {
    if (error instanceof Response) return new Response(error.body, { status: error.status, headers: { "content-type": "application/json", "cache-control": "no-store, private", "x-content-type-options": "nosniff" } });
    return jsonError(error, "The organization operation could not be saved.");
  }
}
