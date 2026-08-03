import { env } from "cloudflare:workers";
import { requireAdmin, requirePermission } from "../../../lib/server-admin";

type ReviewInput = {
  resourceKey?: unknown;
  securityGroupId?: unknown;
  accountId?: unknown;
  region?: unknown;
  vpcId?: unknown;
  status?: unknown;
  assignee?: unknown;
  note?: unknown;
  ticketRef?: unknown;
  expiresAt?: unknown;
  evidenceSnapshot?: unknown;
};

const validStatuses = new Set([
  "needs-review",
  "in-review",
  "approved",
  "remediate",
  "exception",
]);

function json(
  body: Record<string, unknown>,
  status = 200,
) {
  return Response.json(body, {
    status,
    headers: {
      "cache-control": "no-store, private",
      "x-content-type-options": "nosniff",
    },
  });
}

function reviewerFor(request: Request) {
  const email = cleanText(
    request.headers.get("oai-authenticated-user-email"),
    254,
  ).toLowerCase();
  if (email) return email;
  const hostname = new URL(request.url).hostname;
  return (
    typeof process !== "undefined" &&
    process.env.NODE_ENV !== "production" &&
    ["localhost", "127.0.0.1"].includes(hostname)
  )
    ? "local-preview@gatewatch"
    : "";
}

function sameOrigin(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  try {
    return new URL(origin).host === new URL(request.url).host;
  } catch {
    return false;
  }
}

async function ensureSchema() {
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS security_group_reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      security_group_id TEXT NOT NULL UNIQUE,
      status TEXT NOT NULL DEFAULT 'needs-review',
      assignee TEXT NOT NULL DEFAULT 'Unassigned',
      reviewer TEXT NOT NULL DEFAULT '',
      note TEXT NOT NULL DEFAULT '',
      ticket_ref TEXT NOT NULL DEFAULT '',
      expires_at TEXT NOT NULL DEFAULT '',
      evidence_snapshot TEXT NOT NULL DEFAULT '',
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`,
  ).run();

  const columns = await env.DB.prepare(
    "PRAGMA table_info(security_group_reviews)",
  ).all<{ name: string }>();
  const columnNames = new Set(columns.results.map((column) => column.name));
  const missingColumns = [
    ["ticket_ref", "ALTER TABLE security_group_reviews ADD COLUMN ticket_ref TEXT NOT NULL DEFAULT ''"],
    ["expires_at", "ALTER TABLE security_group_reviews ADD COLUMN expires_at TEXT NOT NULL DEFAULT ''"],
    ["evidence_snapshot", "ALTER TABLE security_group_reviews ADD COLUMN evidence_snapshot TEXT NOT NULL DEFAULT ''"],
    ["reviewer", "ALTER TABLE security_group_reviews ADD COLUMN reviewer TEXT NOT NULL DEFAULT ''"],
  ].filter(([name]) => !columnNames.has(name));

  for (const [, statement] of missingColumns) {
    await env.DB.prepare(statement).run();
  }

  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS security_group_review_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      security_group_id TEXT NOT NULL,
      status TEXT NOT NULL,
      assignee TEXT NOT NULL,
      reviewer TEXT NOT NULL DEFAULT '',
      note TEXT NOT NULL,
      ticket_ref TEXT NOT NULL DEFAULT '',
      expires_at TEXT NOT NULL DEFAULT '',
      evidence_snapshot TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`,
  ).run();
  const eventColumns = await env.DB.prepare(
    "PRAGMA table_info(security_group_review_events)",
  ).all<{ name: string }>();
  if (!eventColumns.results.some((column) => column.name === "reviewer")) {
    await env.DB.prepare(
      "ALTER TABLE security_group_review_events ADD COLUMN reviewer TEXT NOT NULL DEFAULT ''",
    ).run();
  }
  await env.DB.prepare(
    `CREATE INDEX IF NOT EXISTS security_group_review_events_group_idx
     ON security_group_review_events (security_group_id, created_at)`,
  ).run();
  await env.DB.batch([
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS resource_reviews (
        resource_key TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL DEFAULT 'default',
        security_group_id TEXT NOT NULL,
        account_id TEXT NOT NULL,
        region TEXT NOT NULL,
        vpc_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'needs-review',
        assignee TEXT NOT NULL DEFAULT 'Unassigned',
        reviewer TEXT NOT NULL DEFAULT '',
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
      `CREATE INDEX IF NOT EXISTS resource_review_events_history_idx
       ON resource_review_events (workspace_id, resource_key, created_at)`,
    ),
  ]);
}

function cleanText(value: unknown, maxLength: number) {
  return typeof value === "string" ? value.trim().slice(0, maxLength) : "";
}

export async function GET(request: Request) {
  try {
    if (!reviewerFor(request)) {
      return json({ error: "Authentication is required." }, 401);
    }
    await ensureSchema();
    const [result, legacy] = await env.DB.batch([
      env.DB.prepare(
      `SELECT resource_key AS resourceKey, security_group_id AS securityGroupId,
              account_id AS accountId, region, vpc_id AS vpcId,
              status, assignee, reviewer,
              note,
              ticket_ref AS ticketRef, expires_at AS expiresAt,
              evidence_snapshot AS evidenceSnapshot,
              updated_at AS updatedAt
       FROM resource_reviews
       WHERE workspace_id = 'default'
       ORDER BY updated_at DESC`,
      ),
      env.DB.prepare(
        `SELECT security_group_id AS resourceKey,
                security_group_id AS securityGroupId, '' AS accountId,
                '' AS region, '' AS vpcId, status, assignee, reviewer, note,
                ticket_ref AS ticketRef, expires_at AS expiresAt,
                evidence_snapshot AS evidenceSnapshot,
                updated_at AS updatedAt
         FROM security_group_reviews
         ORDER BY updated_at DESC`,
      ),
    ]);

    return json({ reviews: [...result.results, ...legacy.results] });
  } catch {
    return json({ error: "Review records are temporarily unavailable." }, 503);
  }
}

export async function POST(request: Request) {
  try {
    const reviewer = reviewerFor(request);
    if (!reviewer) {
      return json({ error: "Authentication is required." }, 401);
    }
    if (!sameOrigin(request)) {
      return json({ error: "Origin is not allowed." }, 403);
    }
    const permission = await requirePermission(request, "reviews.write");
    if (!permission.allowed) {
      return json({ error: "Analyst or reviewer access is required to change reviews." }, 403);
    }
    const contentLength = Number(request.headers.get("content-length") ?? "0");
    if (contentLength > 20_000) {
      return json({ error: "The review payload is too large." }, 413);
    }
    if (!request.headers.get("content-type")?.startsWith("application/json")) {
      return json({ error: "Content-Type must be application/json." }, 415);
    }
    const payload = (await request.json()) as ReviewInput;
    const resourceKey = cleanText(payload.resourceKey, 600);
    const securityGroupId = cleanText(payload.securityGroupId, 80);
    const accountId = cleanText(payload.accountId, 20);
    const region = cleanText(payload.region, 40);
    const vpcId = cleanText(payload.vpcId, 120);
    const status = cleanText(payload.status, 30);
    const assignee = cleanText(payload.assignee, 80) || "Unassigned";
    const note = cleanText(payload.note, 1200);
    const ticketRef = cleanText(payload.ticketRef, 120);
    const expiresAt = cleanText(payload.expiresAt, 20);
    if (status === "exception") {
      const authorization = await requireAdmin(request);
      if (!authorization.allowed) {
        return json({ error: "Administrator approval is required for an exception." }, 403);
      }
    }
    const evidenceSnapshot = cleanText(payload.evidenceSnapshot, 1000);

    if (!/^sg-[a-zA-Z0-9-]+$/.test(securityGroupId)) {
      return json({ error: "A valid security group ID is required." }, 400);
    }
    if (
      !resourceKey.startsWith("aws:") ||
      !/^\d{12}$/.test(accountId) ||
      !/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(region) ||
      !vpcId
    ) {
      return json({ error: "Canonical account, region, VPC, and resource identity are required." }, 400);
    }

    if (!validStatuses.has(status)) {
      return json({ error: "Choose a valid review status." }, 400);
    }

    if (
      ["approved", "exception", "remediate"].includes(status) &&
      note.length < 12
    ) {
      return json(
        { error: "A decision rationale of at least 12 characters is required." },
        400,
      );
    }

    if (
      ["approved", "exception", "remediate"].includes(status) &&
      !ticketRef
    ) {
      return json(
        { error: "A ticket or pull request reference is required." },
        400,
      );
    }

    if (
      status === "exception" &&
      !/^\d{4}-\d{2}-\d{2}$/.test(expiresAt)
    ) {
      return json(
        { error: "Accepted exceptions require a valid expiration date." },
        400,
      );
    }
    if (
      status === "exception" &&
      expiresAt <= new Date().toISOString().slice(0, 10)
    ) {
      return json(
        { error: "The exception expiration date must be in the future." },
        400,
      );
    }

    await ensureSchema();
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO resource_reviews
          (resource_key, workspace_id, security_group_id, account_id, region, vpc_id,
           status, assignee, reviewer, note, ticket_ref, expires_at,
           evidence_snapshot, updated_at)
         VALUES (?, 'default', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
         ON CONFLICT(resource_key) DO UPDATE SET
           status = excluded.status,
           assignee = excluded.assignee,
           reviewer = excluded.reviewer,
           note = excluded.note,
           ticket_ref = excluded.ticket_ref,
           expires_at = excluded.expires_at,
           evidence_snapshot = excluded.evidence_snapshot,
           updated_at = CURRENT_TIMESTAMP`,
      ).bind(
        resourceKey,
        securityGroupId,
        accountId,
        region,
        vpcId,
        status,
        assignee,
        reviewer,
        note,
        ticketRef,
        expiresAt,
        evidenceSnapshot,
      ),
      env.DB.prepare(
        `INSERT INTO resource_review_events
          (workspace_id, resource_key, security_group_id, status, assignee, reviewer,
           note, ticket_ref, expires_at,
           evidence_snapshot, created_at)
         VALUES ('default', ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
      ).bind(
        resourceKey,
        securityGroupId,
        status,
        assignee,
        reviewer,
        note,
        ticketRef,
        expiresAt,
        evidenceSnapshot,
      ),
    ]);

    const review = await env.DB.prepare(
      `SELECT resource_key AS resourceKey, security_group_id AS securityGroupId,
              account_id AS accountId, region, vpc_id AS vpcId,
              status, assignee, reviewer,
              note,
              ticket_ref AS ticketRef, expires_at AS expiresAt,
              evidence_snapshot AS evidenceSnapshot,
              updated_at AS updatedAt
       FROM resource_reviews
       WHERE workspace_id = 'default' AND resource_key = ?`,
    )
      .bind(resourceKey)
      .first();

    return json({ review }, 201);
  } catch (error) {
    if (error instanceof SyntaxError) {
      return json({ error: "Request body must be valid JSON." }, 400);
    }
    return json({ error: "The review could not be saved. Try again." }, 503);
  }
}
