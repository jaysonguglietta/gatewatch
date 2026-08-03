import { env } from "cloudflare:workers";
import {
  findingCatalog,
  findingCatalogForGroups,
  organizationCoverage,
  type FindingCatalogItem,
  type DailyFinding,
  type FindingWorkflowState,
  type FindingWorkflowStatus,
} from "../../../lib/daily-findings";
import {
  configuredAwsInventory,
  loadAwsInventory,
} from "../../../lib/aws-inventory";
import {
  apiJson,
  audit,
  ensureAdminSchema,
  requestUser,
  requireAdmin,
  safeJson,
  sameOrigin,
} from "../../../lib/server-admin";
import { cleanText } from "../../../lib/admin-sources";

const userStatuses = new Set<FindingWorkflowStatus>([
  "follow-up",
  "acknowledged",
  "accepted-risk",
]);

type WorkflowRow = {
  fingerprint: string;
  status: FindingWorkflowStatus;
  assignee: string;
  note: string;
  ticketRef: string;
  dueAt: string;
  expiresAt: string;
  compensatingControls: string;
  reviewer: string;
  updatedAt: string;
};

type JiraLinkRow = {
  fingerprint: string;
  jiraIssueKey: string;
  jiraIssueUrl: string;
  jiraRemoteStatus: string;
  jiraRemoteResolution: string;
  jiraLastSyncedAt: string;
};

type ObservationRow = {
  fingerprint: string;
  firstSeenAt: string;
  lastSeenAt: string;
  state: "active" | "reopened" | "resolved";
  observationCount: number;
};

function dateOffset(days: number) {
  const value = new Date();
  value.setUTCDate(value.getUTCDate() + days);
  return value.toISOString().slice(0, 10);
}

function defaultWorkflow(
  owner: string,
  index: number,
  includeDemonstrationState = true,
): FindingWorkflowState {
  const baseline: FindingWorkflowState = {
    status: "new",
    assignee: owner || "Unassigned",
    note: "",
    ticketRef: "",
    dueAt: "",
    expiresAt: "",
    compensatingControls: [],
    reviewer: "",
    updatedAt: "",
  };
  if (includeDemonstrationState && index === 2) {
    return {
      ...baseline,
      status: "follow-up",
      assignee: "Payments Platform",
      note: "Confirm the intended source groups and submit a narrowing change.",
      ticketRef: "SEC-2381",
      dueAt: dateOffset(-1),
      reviewer: "security-operations@gatewatch",
      updatedAt: new Date().toISOString(),
    };
  }
  if (includeDemonstrationState && index === 3) {
    return {
      ...baseline,
      status: "acknowledged",
      note: "The public listener is the approved application entry point; downstream access remains restricted.",
      reviewer: "security-operations@gatewatch",
      updatedAt: new Date().toISOString(),
    };
  }
  if (includeDemonstrationState && index === 4) {
    return {
      ...baseline,
      status: "accepted-risk",
      note: "Temporary administrative exposure is required during the managed migration window.",
      ticketRef: "RISK-184",
      expiresAt: dateOffset(7),
      compensatingControls: ["MFA required", "Session recording", "Daily Flow Log review"],
      reviewer: "cloud-security-admin@gatewatch",
      updatedAt: new Date().toISOString(),
    };
  }
  if (includeDemonstrationState && index === 5) {
    return {
      ...baseline,
      status: "reopened",
      note: "The previously removed exposure returned in the latest AWS Config observation.",
      reviewer: "gatewatch-system",
      updatedAt: new Date().toISOString(),
    };
  }
  return baseline;
}

async function ensureSchema() {
  await ensureAdminSchema();
  await env.DB.batch([
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS finding_workflows (
        fingerprint TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL DEFAULT 'default',
        security_group_id TEXT NOT NULL,
        finding_key TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'new',
        assignee TEXT NOT NULL DEFAULT 'Unassigned',
        note TEXT NOT NULL DEFAULT '',
        ticket_ref TEXT NOT NULL DEFAULT '',
        due_at TEXT NOT NULL DEFAULT '',
        expires_at TEXT NOT NULL DEFAULT '',
        compensating_controls TEXT NOT NULL DEFAULT '[]',
        evidence_snapshot TEXT NOT NULL DEFAULT '',
        reviewer TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
    ),
    env.DB.prepare(
      `CREATE INDEX IF NOT EXISTS finding_workflows_queue_idx
       ON finding_workflows (workspace_id, status, updated_at)`,
    ),
    env.DB.prepare(
      `CREATE INDEX IF NOT EXISTS finding_workflows_group_idx
       ON finding_workflows (workspace_id, security_group_id)`,
    ),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS finding_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fingerprint TEXT NOT NULL,
        workspace_id TEXT NOT NULL DEFAULT 'default',
        event_type TEXT NOT NULL,
        from_status TEXT NOT NULL DEFAULT '',
        to_status TEXT NOT NULL,
        actor TEXT NOT NULL,
        assignee TEXT NOT NULL DEFAULT 'Unassigned',
        note TEXT NOT NULL DEFAULT '',
        ticket_ref TEXT NOT NULL DEFAULT '',
        due_at TEXT NOT NULL DEFAULT '',
        expires_at TEXT NOT NULL DEFAULT '',
        compensating_controls TEXT NOT NULL DEFAULT '[]',
        evidence_snapshot TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
    ),
    env.DB.prepare(
      `CREATE INDEX IF NOT EXISTS finding_events_history_idx
       ON finding_events (workspace_id, fingerprint, created_at)`,
    ),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS saved_finding_views (
        id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL DEFAULT 'default',
        owner TEXT NOT NULL,
        name TEXT NOT NULL,
        filters TEXT NOT NULL DEFAULT '{}',
        is_default INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
    ),
    env.DB.prepare(
      `CREATE INDEX IF NOT EXISTS saved_finding_views_owner_idx
       ON saved_finding_views (workspace_id, owner, updated_at)`,
    ),
  ]);
}

function workflowFromRow(row: WorkflowRow): FindingWorkflowState {
  return {
    ...row,
    compensatingControls: safeJson<string[]>(row.compensatingControls, []),
  };
}

function isPast(date: string) {
  return Boolean(date && date < new Date().toISOString().slice(0, 10));
}

function mergeFindings(
  catalog: FindingCatalogItem[],
  rows: WorkflowRow[],
  jiraLinks: JiraLinkRow[],
  observations: ObservationRow[],
  includeDemonstrationState: boolean,
): DailyFinding[] {
  const byFingerprint = new Map(
    rows.map((row) => [row.fingerprint, workflowFromRow(row)]),
  );
  const jiraByFingerprint = new Map(
    jiraLinks.map((link) => [link.fingerprint, link]),
  );
  const observationByFingerprint = new Map(
    observations.map((observation) => [observation.fingerprint, observation]),
  );
  return catalog.map((finding, index) => {
    const workflow =
      byFingerprint.get(finding.fingerprint) ??
      byFingerprint.get(finding.legacyFingerprint);
    const jira =
      jiraByFingerprint.get(finding.fingerprint) ??
      jiraByFingerprint.get(finding.legacyFingerprint);
    const observation = observationByFingerprint.get(finding.fingerprint);
    const firstSeenAt = observation?.firstSeenAt ?? finding.firstSeenAt;
    const ageDays = Math.max(
      0,
      Math.floor((Date.now() - Date.parse(firstSeenAt)) / 86_400_000),
    );
    const defaultState = defaultWorkflow(
      finding.owner,
      index,
      includeDemonstrationState,
    );
    return {
      ...finding,
      firstSeenAt,
      ageDays,
      ...(workflow ?? {
        ...defaultState,
        status:
          observation?.state === "reopened"
            ? "reopened"
            : defaultState.status,
      }),
      jiraIssueKey: jira?.jiraIssueKey,
      jiraIssueUrl: jira?.jiraIssueUrl,
      jiraRemoteStatus: jira?.jiraRemoteStatus,
      jiraRemoteResolution: jira?.jiraRemoteResolution,
      jiraLastSyncedAt: jira?.jiraLastSyncedAt,
    };
  });
}

async function syncObservations(
  catalog: FindingCatalogItem[],
  snapshotId: string,
  observedAt: string,
) {
  const now = Number.isNaN(Date.parse(observedAt))
    ? new Date().toISOString()
    : observedAt;
  for (let offset = 0; offset < catalog.length; offset += 80) {
    const statements = catalog.slice(offset, offset + 80).map((finding) =>
      env.DB.prepare(
        `INSERT INTO finding_observations
          (id, workspace_id, fingerprint, legacy_fingerprint,
           canonical_resource_key, first_seen_at, last_seen_at,
           last_snapshot_id, state, observation_count, resolved_at,
           evidence_snapshot)
         VALUES (?, 'default', ?, ?, ?, ?, ?, ?, 'active', 1, '', ?)
         ON CONFLICT(workspace_id, fingerprint) DO UPDATE SET
           last_seen_at = excluded.last_seen_at,
           last_snapshot_id = excluded.last_snapshot_id,
           state = CASE
             WHEN finding_observations.state = 'resolved' THEN 'reopened'
             ELSE finding_observations.state
           END,
           observation_count = finding_observations.observation_count + CASE
             WHEN finding_observations.last_snapshot_id <> excluded.last_snapshot_id THEN 1
             ELSE 0
           END,
           resolved_at = '',
           evidence_snapshot = excluded.evidence_snapshot`,
      ).bind(
        `default:${finding.fingerprint}`,
        finding.fingerprint,
        finding.legacyFingerprint,
        finding.canonicalResourceKey,
        now,
        now,
        snapshotId,
        finding.evidenceSnapshot,
      ),
    );
    if (statements.length) await env.DB.batch(statements);
  }
  await env.DB.prepare(
    `UPDATE finding_observations
     SET state = 'resolved', resolved_at = ?, last_seen_at = last_seen_at
     WHERE workspace_id = 'default'
       AND last_snapshot_id <> ?
       AND state <> 'resolved'`,
  ).bind(now, snapshotId).run();
}

async function currentCatalog() {
  if (!configuredAwsInventory()) {
    return {
      catalog: findingCatalog,
      coverage: organizationCoverage,
      live: false,
      source: {
        mode: "demonstration",
        snapshotId: "demonstration",
        generatedAt: "",
        complete: false,
        coveragePercent: 0,
        freshnessMinutes: 0,
      },
    };
  }
  const inventory = await loadAwsInventory();
  return {
    catalog: findingCatalogForGroups(inventory.groups, {
      live: true,
      snapshotId: inventory.source.snapshotId,
    }),
    coverage: {
      accounts: inventory.source.accountCount,
      organizationalUnits: 0,
      regions: inventory.source.regionCount,
      staleAccounts: inventory.source.complete ? 0 : inventory.source.errorCount,
    },
    live: true,
    source: inventory.source,
  };
}

async function parseBoundedJson(request: Request) {
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.startsWith("application/json")) {
    throw new Response(
      JSON.stringify({ error: "Content-Type must be application/json." }),
      { status: 415, headers: { "content-type": "application/json" } },
    );
  }
  const declaredLength = Number(request.headers.get("content-length") ?? "0");
  if (declaredLength > 50_000) {
    throw new Response(JSON.stringify({ error: "The request is too large." }), {
      status: 413,
      headers: { "content-type": "application/json" },
    });
  }
  const body = await request.text();
  if (new TextEncoder().encode(body).byteLength > 50_000) {
    throw new Response(JSON.stringify({ error: "The request is too large." }), {
      status: 413,
      headers: { "content-type": "application/json" },
    });
  }
  return JSON.parse(body) as Record<string, unknown>;
}

export async function GET(request: Request) {
  try {
    const user = requestUser(request);
    if (!user) return apiJson({ error: "Authentication is required." }, 401);
    await ensureSchema();
    const current = await currentCatalog();
    const catalog = current.catalog;
    if (current.live) {
      await syncObservations(
        catalog,
        current.source.snapshotId,
        current.source.generatedAt,
      );
    }
    const url = new URL(request.url);
    const historyFingerprint = cleanText(
      url.searchParams.get("history"),
      180,
    );
    if (historyFingerprint) {
      const result = await env.DB.prepare(
        `SELECT id, event_type AS eventType, from_status AS fromStatus,
                to_status AS toStatus, actor, assignee, note,
                ticket_ref AS ticketRef, due_at AS dueAt,
                expires_at AS expiresAt,
                compensating_controls AS compensatingControls,
                created_at AS createdAt
         FROM finding_events
         WHERE workspace_id = 'default' AND fingerprint = ?
         ORDER BY created_at DESC, id DESC
         LIMIT 200`,
      ).bind(historyFingerprint).all<Record<string, unknown>>();
      return apiJson({
        events: result.results.map((event) => ({
          ...event,
          compensatingControls: safeJson(event.compensatingControls, []),
        })),
      });
    }

    const [workflowResult, savedViewResult, jiraLinkResult, observationResult] = await Promise.all([
      env.DB.prepare(
        `SELECT fingerprint, status, assignee, note,
                ticket_ref AS ticketRef, due_at AS dueAt,
                expires_at AS expiresAt,
                compensating_controls AS compensatingControls,
                reviewer, updated_at AS updatedAt
         FROM finding_workflows
         WHERE workspace_id = 'default'
         ORDER BY updated_at DESC
         LIMIT 2000`,
      ).all<WorkflowRow>(),
      env.DB.prepare(
        `SELECT id, name, filters, is_default AS isDefault,
                created_at AS createdAt, updated_at AS updatedAt
         FROM saved_finding_views
         WHERE workspace_id = 'default' AND owner = ?
         ORDER BY is_default DESC, name ASC
         LIMIT 100`,
      ).bind(user).all<Record<string, unknown>>(),
      env.DB.prepare(
        `SELECT fingerprint, issue_key AS jiraIssueKey,
                issue_url AS jiraIssueUrl,
                remote_status AS jiraRemoteStatus,
                remote_resolution AS jiraRemoteResolution,
                last_synced_at AS jiraLastSyncedAt
         FROM finding_jira_links
         WHERE workspace_id = 'default'`,
      ).all<JiraLinkRow>(),
      env.DB.prepare(
        `SELECT fingerprint, first_seen_at AS firstSeenAt,
                last_seen_at AS lastSeenAt, state,
                observation_count AS observationCount
         FROM finding_observations
         WHERE workspace_id = 'default'`,
      ).all<ObservationRow>(),
    ]);
    const all = mergeFindings(
      catalog,
      workflowResult.results,
      jiraLinkResult.results,
      observationResult.results,
      !current.live,
    );
    const query = cleanText(url.searchParams.get("q"), 160).toLowerCase();
    const severity = cleanText(url.searchParams.get("severity"), 20);
    const status = cleanText(url.searchParams.get("status"), 30);
    const ou = cleanText(url.searchParams.get("ou"), 120);
    const account = cleanText(url.searchParams.get("account"), 20);
    const region = cleanText(url.searchParams.get("region"), 30);
    const owner = cleanText(url.searchParams.get("owner"), 120);
    const environment = cleanText(url.searchParams.get("environment"), 30);
    const sort = cleanText(url.searchParams.get("sort"), 30) || "risk";

    const scoped = all.filter(
      (finding) =>
        (!ou || finding.organizationalUnit === ou) &&
        (!account || finding.accountId === account) &&
        (!region || finding.region === region) &&
        (!owner || finding.assignee === owner || finding.owner === owner) &&
        (!environment || finding.environment === environment),
    );
    const stats = {
      newToday: scoped.filter(
        (finding) =>
          ["new", "reopened"].includes(finding.status) && finding.ageDays <= 1,
      ).length,
      awaitingAction: scoped.filter((finding) =>
        ["new", "reopened"].includes(finding.status),
      ).length,
      overdue: scoped.filter(
        (finding) => finding.status === "follow-up" && isPast(finding.dueAt),
      ).length,
      expiringSoon: scoped.filter((finding) => {
        if (finding.status !== "accepted-risk" || !finding.expiresAt) return false;
        const remaining =
          (Date.parse(finding.expiresAt) - Date.now()) / (24 * 60 * 60 * 1000);
        return remaining >= 0 && remaining <= 14;
      }).length,
      reopened: scoped.filter((finding) => finding.status === "reopened").length,
      staleAccounts: current.coverage.staleAccounts,
    };
    const filtered = scoped.filter((finding) => {
      const searchText = [
        finding.title,
        finding.securityGroupName,
        finding.securityGroupId,
        finding.accountId,
        finding.accountName,
        finding.application,
        finding.owner,
        finding.assignee,
        finding.ruleSummary,
      ]
        .join(" ")
        .toLowerCase();
      return (
        (!query || searchText.includes(query)) &&
        (!severity || finding.severity === severity) &&
        (!status ||
          (status === "open"
            ? finding.status !== "resolved"
            : finding.status === status))
      );
    });
    filtered.sort((a, b) => {
      if (sort === "age") return b.ageDays - a.ageDays;
      if (sort === "account") return a.accountName.localeCompare(b.accountName);
      if (sort === "updated") {
        return (b.updatedAt || b.firstSeenAt).localeCompare(
          a.updatedAt || a.firstSeenAt,
        );
      }
      return b.riskScore - a.riskScore;
    });
    const pageSize = Math.min(
      100,
      Math.max(10, Number(url.searchParams.get("pageSize") ?? 25) || 25),
    );
    const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
    const page = Math.min(
      pageCount,
      Math.max(1, Number(url.searchParams.get("page") ?? 1) || 1),
    );
    const start = (page - 1) * pageSize;
    const accounts = Array.from(
      new Map(
        catalog.map((finding) => [
          finding.accountId,
          { id: finding.accountId, name: finding.accountName },
        ]),
      ).values(),
    ).sort((a, b) => a.name.localeCompare(b.name));

    return apiJson({
      items: filtered.slice(start, start + pageSize),
      total: filtered.length,
      page,
      pageSize,
      pageCount,
      stats,
      coverage: current.coverage,
      facets: {
        organizationalUnits: [...new Set(catalog.map((item) => item.organizationalUnit))].sort(),
        accounts,
        regions: [...new Set(catalog.map((item) => item.region))].sort(),
        owners: [...new Set(catalog.map((item) => item.owner))].sort(),
      },
      savedViews: savedViewResult.results.map((view) => ({
        ...view,
        isDefault: Boolean(view.isDefault),
        filters: safeJson(view.filters, {}),
      })),
      source: current.source,
    });
  } catch {
    return apiJson({ error: "The daily findings inbox is temporarily unavailable." }, 503);
  }
}

export async function POST(request: Request) {
  try {
    const user = requestUser(request);
    if (!user) return apiJson({ error: "Authentication is required." }, 401);
    if (!sameOrigin(request)) return apiJson({ error: "Origin is not allowed." }, 403);
    await ensureSchema();
    const input = await parseBoundedJson(request);
    const catalog = (await currentCatalog()).catalog;
    const action = cleanText(input.action, 30);

    if (action === "save-view") {
      const name = cleanText(input.name, 80);
      const filters =
        input.filters && typeof input.filters === "object" ? input.filters : {};
      const serializedFilters = JSON.stringify(filters);
      if (name.length < 3 || serializedFilters.length > 4_000) {
        return apiJson({ error: "Use a view name of at least three characters and valid filters." }, 400);
      }
      const id = cleanText(input.id, 100) || `view-${crypto.randomUUID()}`;
      const isDefault = Boolean(input.isDefault);
      const statements = [];
      if (isDefault) {
        statements.push(
          env.DB.prepare(
            `UPDATE saved_finding_views SET is_default = 0, updated_at = CURRENT_TIMESTAMP
             WHERE workspace_id = 'default' AND owner = ?`,
          ).bind(user),
        );
      }
      statements.push(
        env.DB.prepare(
          `INSERT INTO saved_finding_views
            (id, owner, name, filters, is_default, updated_at)
           VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
           ON CONFLICT(id) DO UPDATE SET
             name = excluded.name,
             filters = excluded.filters,
             is_default = excluded.is_default,
             updated_at = CURRENT_TIMESTAMP
           WHERE saved_finding_views.owner = excluded.owner`,
        ).bind(id, user, name, serializedFilters, isDefault ? 1 : 0),
      );
      await env.DB.batch(statements);
      await audit(user, "finding_view.saved", "saved_finding_view", id, `Saved findings view ${name}.`, { isDefault });
      return apiJson({ saved: true, id }, 201);
    }

    if (action === "delete-view") {
      const id = cleanText(input.id, 100);
      const result = (await env.DB.prepare(
        `DELETE FROM saved_finding_views
         WHERE id = ? AND workspace_id = 'default' AND owner = ?`,
      ).bind(id, user).run()) as { meta?: { changes?: number } };
      if (!result.meta?.changes) return apiJson({ error: "The saved view was not found." }, 404);
      await audit(user, "finding_view.deleted", "saved_finding_view", id, "Deleted saved findings view.", {});
      return apiJson({ deleted: true });
    }

    if (action !== "triage") {
      return apiJson({ error: "Choose a supported findings action." }, 400);
    }
    const rawFingerprints = Array.isArray(input.fingerprints)
      ? input.fingerprints
      : [input.fingerprint];
    const fingerprints = [
      ...new Set(rawFingerprints.map((value) => cleanText(value, 180)).filter(Boolean)),
    ].slice(0, 100);
    const status = cleanText(input.status, 30) as FindingWorkflowStatus;
    const assignee = cleanText(input.assignee, 120) || "Unassigned";
    const note = cleanText(input.note, 2_000);
    const ticketRef = cleanText(input.ticketRef, 160);
    const dueAt = cleanText(input.dueAt, 20);
    const expiresAt = cleanText(input.expiresAt, 20);
    const compensatingControls = Array.isArray(input.compensatingControls)
      ? input.compensatingControls
          .map((value) => cleanText(value, 240))
          .filter(Boolean)
          .slice(0, 20)
      : [];
    if (!fingerprints.length || !userStatuses.has(status)) {
      return apiJson({ error: "Choose findings and a supported triage outcome." }, 400);
    }
    const catalogById = new Map(
      catalog.map((finding) => [finding.fingerprint, finding]),
    );
    const unknown = fingerprints.find((fingerprint) => !catalogById.has(fingerprint));
    if (unknown) return apiJson({ error: "One or more findings are no longer available." }, 409);
    const today = new Date().toISOString().slice(0, 10);
    if (status === "follow-up" && (note.length < 6 || !dueAt || dueAt < today)) {
      return apiJson({ error: "Follow-up requires an assignee, a note, and a current or future due date." }, 400);
    }
    if (status === "acknowledged" && note.length < 12) {
      return apiJson({ error: "Explain why the finding is acceptable using at least 12 characters." }, 400);
    }
    if (
      status === "accepted-risk" &&
      (note.length < 12 ||
        !ticketRef ||
        !/^\d{4}-\d{2}-\d{2}$/.test(expiresAt) ||
        expiresAt <= today ||
        compensatingControls.length === 0)
    ) {
      return apiJson(
        { error: "Accepted risk requires justification, a ticket, a future expiration, and compensating controls." },
        400,
      );
    }
    if (status === "accepted-risk") {
      const authorization = await requireAdmin(request);
      if (!authorization.allowed) {
        return apiJson({ error: "An administrator must approve accepted risk." }, 403);
      }
    }
    const currentResult = await env.DB.prepare(
      `SELECT fingerprint, status FROM finding_workflows
       WHERE workspace_id = 'default'`,
    ).all<{ fingerprint: string; status: string }>();
    const currentStatuses = new Map(
      currentResult.results.map((row) => [row.fingerprint, row.status]),
    );
    const controlsJson = JSON.stringify(compensatingControls);
    const statements = fingerprints.flatMap((fingerprint) => {
      const finding = catalogById.get(fingerprint)!;
      const fromStatus = currentStatuses.get(fingerprint) ?? "new";
      return [
        env.DB.prepare(
          `INSERT INTO finding_workflows
            (fingerprint, security_group_id, finding_key, status, assignee, note,
             ticket_ref, due_at, expires_at, compensating_controls,
             evidence_snapshot, reviewer, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
           ON CONFLICT(fingerprint) DO UPDATE SET
             status = excluded.status,
             assignee = excluded.assignee,
             note = excluded.note,
             ticket_ref = excluded.ticket_ref,
             due_at = excluded.due_at,
             expires_at = excluded.expires_at,
             compensating_controls = excluded.compensating_controls,
             evidence_snapshot = excluded.evidence_snapshot,
             reviewer = excluded.reviewer,
             updated_at = CURRENT_TIMESTAMP`,
        ).bind(
          fingerprint,
          finding.securityGroupId,
          finding.findingKey,
          status,
          assignee,
          note,
          ticketRef,
          dueAt,
          expiresAt,
          controlsJson,
          finding.evidenceSnapshot,
          user,
        ),
        env.DB.prepare(
          `INSERT INTO finding_events
            (fingerprint, event_type, from_status, to_status, actor, assignee,
             note, ticket_ref, due_at, expires_at, compensating_controls,
             evidence_snapshot)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        ).bind(
          fingerprint,
          fingerprints.length > 1 ? "bulk-triage" : "triage",
          fromStatus,
          status,
          user,
          assignee,
          note,
          ticketRef,
          dueAt,
          expiresAt,
          controlsJson,
          finding.evidenceSnapshot,
        ),
      ];
    });
    await env.DB.batch(statements);
    await audit(
      user,
      `finding.${status}`,
      "finding",
      fingerprints.length === 1 ? fingerprints[0] : "bulk",
      `${status} applied to ${fingerprints.length} finding${fingerprints.length === 1 ? "" : "s"}.`,
      { count: fingerprints.length, assignee, ticketRef, dueAt, expiresAt },
    );
    return apiJson({ updated: fingerprints.length });
  } catch (error) {
    if (error instanceof Response) return error;
    if (error instanceof SyntaxError) {
      return apiJson({ error: "Request body must be valid JSON." }, 400);
    }
    return apiJson({ error: "The findings workflow could not be saved." }, 503);
  }
}
