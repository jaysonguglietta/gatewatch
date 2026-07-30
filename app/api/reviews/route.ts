import { env } from "cloudflare:workers";

type ReviewInput = {
  securityGroupId?: unknown;
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
  return ["localhost", "127.0.0.1"].includes(hostname)
    ? "local-preview@gatewatch"
    : "";
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
    const result = await env.DB.prepare(
      `SELECT security_group_id AS securityGroupId, status, assignee, reviewer,
              note,
              ticket_ref AS ticketRef, expires_at AS expiresAt,
              evidence_snapshot AS evidenceSnapshot,
              updated_at AS updatedAt
       FROM security_group_reviews
       ORDER BY updated_at DESC`,
    ).all();

    return json({ reviews: result.results });
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
    const contentLength = Number(request.headers.get("content-length") ?? "0");
    if (contentLength > 20_000) {
      return json({ error: "The review payload is too large." }, 413);
    }
    const payload = (await request.json()) as ReviewInput;
    const securityGroupId = cleanText(payload.securityGroupId, 80);
    const status = cleanText(payload.status, 30);
    const assignee = cleanText(payload.assignee, 80) || "Unassigned";
    const note = cleanText(payload.note, 1200);
    const ticketRef = cleanText(payload.ticketRef, 120);
    const expiresAt = cleanText(payload.expiresAt, 20);
    const evidenceSnapshot = cleanText(payload.evidenceSnapshot, 1000);

    if (!/^sg-[a-zA-Z0-9-]+$/.test(securityGroupId)) {
      return json({ error: "A valid security group ID is required." }, 400);
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
        `INSERT INTO security_group_reviews
          (security_group_id, status, assignee, reviewer, note, ticket_ref, expires_at,
           evidence_snapshot, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
         ON CONFLICT(security_group_id) DO UPDATE SET
           status = excluded.status,
           assignee = excluded.assignee,
           reviewer = excluded.reviewer,
           note = excluded.note,
           ticket_ref = excluded.ticket_ref,
           expires_at = excluded.expires_at,
           evidence_snapshot = excluded.evidence_snapshot,
           updated_at = CURRENT_TIMESTAMP`,
      ).bind(
        securityGroupId,
        status,
        assignee,
        reviewer,
        note,
        ticketRef,
        expiresAt,
        evidenceSnapshot,
      ),
      env.DB.prepare(
        `INSERT INTO security_group_review_events
          (security_group_id, status, assignee, reviewer, note, ticket_ref, expires_at,
           evidence_snapshot, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
      ).bind(
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
      `SELECT security_group_id AS securityGroupId, status, assignee, reviewer,
              note,
              ticket_ref AS ticketRef, expires_at AS expiresAt,
              evidence_snapshot AS evidenceSnapshot,
              updated_at AS updatedAt
       FROM security_group_reviews
       WHERE security_group_id = ?`,
    )
      .bind(securityGroupId)
      .first();

    return json({ review }, 201);
  } catch (error) {
    if (error instanceof SyntaxError) {
      return json({ error: "Request body must be valid JSON." }, 400);
    }
    return json({ error: "The review could not be saved. Try again." }, 503);
  }
}
