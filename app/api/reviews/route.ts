import { env } from "cloudflare:workers";

type ReviewInput = {
  securityGroupId?: unknown;
  status?: unknown;
  assignee?: unknown;
  note?: unknown;
};

const validStatuses = new Set([
  "needs-review",
  "in-review",
  "approved",
  "remediate",
  "exception",
]);

async function ensureSchema() {
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS security_group_reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      security_group_id TEXT NOT NULL UNIQUE,
      status TEXT NOT NULL DEFAULT 'needs-review',
      assignee TEXT NOT NULL DEFAULT 'Unassigned',
      note TEXT NOT NULL DEFAULT '',
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`,
  ).run();
}

function cleanText(value: unknown, maxLength: number) {
  return typeof value === "string" ? value.trim().slice(0, maxLength) : "";
}

export async function GET() {
  try {
    await ensureSchema();
    const result = await env.DB.prepare(
      `SELECT security_group_id AS securityGroupId, status, assignee, note,
              updated_at AS updatedAt
       FROM security_group_reviews
       ORDER BY updated_at DESC`,
    ).all();

    return Response.json({ reviews: result.results });
  } catch {
    return Response.json(
      { error: "Review records are temporarily unavailable." },
      { status: 503 },
    );
  }
}

export async function POST(request: Request) {
  try {
    const payload = (await request.json()) as ReviewInput;
    const securityGroupId = cleanText(payload.securityGroupId, 80);
    const status = cleanText(payload.status, 30);
    const assignee = cleanText(payload.assignee, 80) || "Unassigned";
    const note = cleanText(payload.note, 1200);

    if (!/^sg-[a-zA-Z0-9-]+$/.test(securityGroupId)) {
      return Response.json(
        { error: "A valid security group ID is required." },
        { status: 400 },
      );
    }

    if (!validStatuses.has(status)) {
      return Response.json(
        { error: "Choose a valid review status." },
        { status: 400 },
      );
    }

    await ensureSchema();
    await env.DB.prepare(
      `INSERT INTO security_group_reviews
        (security_group_id, status, assignee, note, updated_at)
       VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(security_group_id) DO UPDATE SET
         status = excluded.status,
         assignee = excluded.assignee,
         note = excluded.note,
         updated_at = CURRENT_TIMESTAMP`,
    )
      .bind(securityGroupId, status, assignee, note)
      .run();

    const review = await env.DB.prepare(
      `SELECT security_group_id AS securityGroupId, status, assignee, note,
              updated_at AS updatedAt
       FROM security_group_reviews
       WHERE security_group_id = ?`,
    )
      .bind(securityGroupId)
      .first();

    return Response.json({ review }, { status: 201 });
  } catch (error) {
    if (error instanceof SyntaxError) {
      return Response.json({ error: "Request body must be valid JSON." }, { status: 400 });
    }
    return Response.json(
      { error: "The review could not be saved. Try again." },
      { status: 503 },
    );
  }
}
