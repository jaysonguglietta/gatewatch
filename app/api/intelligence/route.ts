import { env } from "cloudflare:workers";
import { HttpInputError, readBoundedJson } from "../../../lib/http-security";
import {
  apiJson,
  audit,
  ensureAdminSchema,
  requireAdmin,
  requirePermission,
  requestUser,
  sameOrigin,
  safeJson,
} from "../../../lib/server-admin";
import { cleanText } from "../../../lib/admin-sources";
import { operationInitialStatuses, operationTransitions } from "../../../lib/exposure-operations";
import { canonicalJson } from "../../../lib/security-integrity";

const kinds = new Set([
  "recommendation",
  "drift",
  "owner-task",
  "exception",
  "iac-guardrail",
  "hygiene",
  "verification-run",
  "exposure-correlation",
  "remediation-plan",
  "owner-action",
  "incident",
  "policy-pack",
  "extension",
  "evidence-gap",
]);

const statuses: Record<string, Set<string>> = {
  recommendation: new Set([
    "proposed",
    "validating",
    "approved",
    "implemented",
    "dismissed",
  ]),
  drift: new Set(["new", "investigating", "expected", "remediate", "closed"]),
  "owner-task": new Set(["open", "accepted", "blocked", "completed"]),
  exception: new Set(["requested", "approved", "rejected", "revoked", "expired"]),
  "iac-guardrail": new Set(["enabled", "disabled", "monitor"]),
  hygiene: new Set(["open", "scheduled", "resolved", "accepted"]),
  "verification-run": new Set(["queued", "running", "verified", "unreachable", "inconclusive", "failed"]),
  "exposure-correlation": new Set(["open", "confirmed", "reconciled", "dismissed"]),
  "remediation-plan": new Set(["draft", "simulated", "awaiting-approval", "approved", "executing", "verifying", "completed", "rolled-back", "failed"]),
  "owner-action": new Set(["open", "accepted", "blocked", "completed", "overdue"]),
  incident: new Set(["open", "investigating", "contained", "resolved"]),
  "policy-pack": new Set(["draft", "monitor", "enforced", "disabled"]),
  extension: new Set(["enabled", "disabled", "error"]),
  "evidence-gap": new Set(["open", "collecting", "resolved", "accepted"]),
};

async function ensureSchema() {
  await ensureAdminSchema();
  await env.DB.batch([
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS product_workflow_records (
        id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL DEFAULT 'default',
        kind TEXT NOT NULL,
        subject_id TEXT NOT NULL,
        status TEXT NOT NULL,
        owner TEXT NOT NULL DEFAULT 'Unassigned',
        note TEXT NOT NULL DEFAULT '',
        ticket_ref TEXT NOT NULL DEFAULT '',
        expires_at TEXT NOT NULL DEFAULT '',
        payload TEXT NOT NULL DEFAULT '{}',
        created_by TEXT NOT NULL,
        updated_by TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
    ),
    env.DB.prepare(
      `CREATE INDEX IF NOT EXISTS product_workflows_kind_status_idx
       ON product_workflow_records (workspace_id, kind, status)`,
    ),
    env.DB.prepare(
      `CREATE INDEX IF NOT EXISTS product_workflows_subject_idx
       ON product_workflow_records (workspace_id, subject_id)`,
    ),
  ]);
}

export async function GET(request: Request) {
  try {
    const user = requestUser(request);
    if (!user) return apiJson({ error: "Authentication is required." }, 401);
    await ensureSchema();
    const today = new Date().toISOString().slice(0, 10);
    await env.DB.prepare(
      `UPDATE product_workflow_records
       SET status = 'expired', updated_by = 'gatewatch-system',
           updated_at = CURRENT_TIMESTAMP
       WHERE workspace_id = 'default' AND kind = 'exception'
         AND status = 'approved' AND expires_at <> '' AND expires_at < ?`,
    ).bind(today).run();
    const result = await env.DB.prepare(
      `SELECT id, kind, subject_id AS subjectId, status, owner, note,
              ticket_ref AS ticketRef, expires_at AS expiresAt, payload,
              created_by AS createdBy, updated_by AS updatedBy,
              created_at AS createdAt, updated_at AS updatedAt
       FROM product_workflow_records
       WHERE workspace_id = 'default'
       ORDER BY updated_at DESC
       LIMIT 1000`,
    ).all();
    return apiJson({
      records: result.results.map((record) => ({
        ...record,
        payload: safeJson(record.payload, {}),
      })),
    });
  } catch {
    return apiJson({ error: "Product workflows are temporarily unavailable." }, 503);
  }
}

export async function POST(request: Request) {
  try {
    const user = requestUser(request);
    if (!user) return apiJson({ error: "Authentication is required." }, 401);
    if (!sameOrigin(request)) return apiJson({ error: "Origin is not allowed." }, 403);
    const permission = await requirePermission(request, "intelligence.write");
    if (!permission.allowed) {
      return apiJson({ error: "Analyst or reviewer access is required to change intelligence workflows." }, 403);
    }
    const input = await readBoundedJson(request, 40_000);
    const action = cleanText(input.action, 20);
    const id = cleanText(input.id, 100);
    await ensureSchema();

    if (action === "delete") {
      const existing = await env.DB.prepare(
        `SELECT id, kind, subject_id AS subjectId, created_by AS createdBy
         FROM product_workflow_records
         WHERE id = ? AND workspace_id = 'default'`,
      ).bind(id).first<{ id: string; kind: string; subjectId: string; createdBy: string }>();
      if (!existing) return apiJson({ error: "The workflow record was not found." }, 404);
      if (existing.kind !== "exception") {
        return apiJson({ error: "Only exception requests can be deleted." }, 409);
      }
      if (existing.createdBy !== user) {
        const authorization = await requireAdmin(request);
        if (!authorization.allowed) {
          return apiJson({ error: "Only the requestor or an administrator can delete this exception." }, 403);
        }
      }
      await env.DB.prepare(
        "DELETE FROM product_workflow_records WHERE id = ? AND workspace_id = 'default'",
      ).bind(id).run();
      await audit(
        user,
        "exception.deleted",
        "product_workflow",
        id,
        `Deleted draft exception ${id}.`,
        { subjectId: existing.subjectId },
      );
      return apiJson({ deleted: true });
    }

    if (action !== "upsert") {
      return apiJson({ error: "Choose a supported workflow action." }, 400);
    }
    const kind = cleanText(input.kind, 30);
    const subjectId = cleanText(input.subjectId, 160);
    const status = cleanText(input.status, 30);
    const owner = cleanText(input.owner, 120) || "Unassigned";
    const note = cleanText(input.note, 2_000);
    const ticketRef = cleanText(input.ticketRef, 160);
    const expiresAt = cleanText(input.expiresAt, 20);
    const payload =
      input.payload && typeof input.payload === "object"
        ? JSON.stringify(input.payload).slice(0, 20_000)
        : "{}";

    const existingRecord = await env.DB.prepare(
      `SELECT kind, subject_id AS subjectId, status, payload,
              created_by AS createdBy, updated_at AS updatedAt
       FROM product_workflow_records
       WHERE id = ? AND workspace_id = 'default'`,
    ).bind(id).first<{
      kind: string;
      subjectId: string;
      status: string;
      createdBy: string;
      updatedAt: string;
      payload: string;
    }>();

    if (!id || !kinds.has(kind) || !subjectId || !statuses[kind]?.has(status)) {
      return apiJson({ error: "The workflow record is invalid." }, 400);
    }
    if (kind === "exception" && status === "expired") {
      return apiJson({ error: "Exception expiry is controlled by Gatewatch and cannot be set by a client." }, 409);
    }
    if (
      existingRecord &&
      (existingRecord.kind !== kind || existingRecord.subjectId !== subjectId)
    ) {
      return apiJson(
        { error: "Workflow kind and subject identity cannot be changed after creation." },
        409,
      );
    }
    const initialStatus = operationInitialStatuses[kind as keyof typeof operationInitialStatuses];
    if (!existingRecord && initialStatus && status !== initialStatus) {
      return apiJson(
        { error: `${kind} must be created in the ${initialStatus} state.` },
        409,
      );
    }
    const governedTransitions = operationTransitions[kind as keyof typeof operationTransitions];
    if (
      existingRecord &&
      governedTransitions &&
      existingRecord.status !== status &&
      !governedTransitions[existingRecord.status]?.includes(status)
    ) {
      return apiJson(
        { error: `Transition from ${existingRecord.status} to ${status} is not allowed for ${kind}.` },
        409,
      );
    }
    if (
      kind === "remediation-plan" &&
      existingRecord &&
      existingRecord.status !== "draft" &&
      canonicalJson(safeJson(existingRecord.payload, {})) !== canonicalJson(safeJson(payload, {}))
    ) {
      return apiJson(
        { error: "A simulated remediation payload is immutable; return it to draft before changing content." },
        409,
      );
    }
    if (
      kind === "exception" &&
      ["requested", "approved"].includes(status) &&
      (!ticketRef || note.length < 12 || !/^\d{4}-\d{2}-\d{2}$/.test(expiresAt))
    ) {
      return apiJson(
        { error: "Exceptions require a ticket, expiration date, and a meaningful justification." },
        400,
      );
    }
    if (
      kind === "exception" &&
      ["requested", "approved"].includes(status) &&
      expiresAt <= new Date().toISOString().slice(0, 10)
    ) {
      return apiJson({ error: "Exception expiration must be in the future." }, 400);
    }
    if (
      kind === "iac-guardrail" ||
      (kind === "remediation-plan" && ["approved", "executing", "completed", "rolled-back"].includes(status)) ||
      (kind === "policy-pack" && ["enforced", "disabled"].includes(status)) ||
      (kind === "extension" && (status === "enabled" || Boolean(existingRecord))) ||
      (kind === "exception" && ["approved", "rejected", "revoked"].includes(status))
    ) {
      const authorization = await requireAdmin(request);
      if (!authorization.allowed) {
        return apiJson(
          { error: "An administrator is required for this governance decision." },
          403,
        );
      }
    }
    if (
      kind === "remediation-plan" &&
      status === "approved" &&
      existingRecord?.createdBy === user
    ) {
      return apiJson(
        { error: "Remediation authors cannot approve their own production change." },
        409,
      );
    }
    if (kind === "exception" && ["approved", "rejected"].includes(status)) {
      if (existingRecord?.createdBy === user) {
        return apiJson(
          { error: "Exception requestors cannot approve or reject their own request." },
          409,
        );
      }
    }

    await env.DB.prepare(
      `INSERT INTO product_workflow_records
        (id, kind, subject_id, status, owner, note, ticket_ref, expires_at,
         payload, created_by, updated_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         status = excluded.status,
         owner = excluded.owner,
         note = excluded.note,
         ticket_ref = excluded.ticket_ref,
         expires_at = excluded.expires_at,
         payload = excluded.payload,
         updated_by = excluded.updated_by,
         updated_at = CURRENT_TIMESTAMP`,
    )
      .bind(
        id,
        kind,
        subjectId,
        status,
        owner,
        note,
        ticketRef,
        expiresAt,
        payload,
        user,
        user,
      )
      .run();
    await audit(
      user,
      `${kind}.${status}`,
      "product_workflow",
      id,
      `Set ${kind} ${subjectId} to ${status}.`,
      { owner, ticketRef, expiresAt },
    );
    const record = await env.DB.prepare(
      `SELECT id, kind, subject_id AS subjectId, status, owner, note,
              ticket_ref AS ticketRef, expires_at AS expiresAt, payload,
              created_by AS createdBy, updated_by AS updatedBy,
              created_at AS createdAt, updated_at AS updatedAt
       FROM product_workflow_records WHERE id = ?`,
    ).bind(id).first<Record<string, unknown>>();
    return apiJson({
      record: record
        ? { ...record, payload: safeJson(record.payload, {}) }
        : null,
    });
  } catch (error) {
    if (error instanceof HttpInputError) return apiJson({ error: error.message }, error.status);
    return apiJson({ error: "The workflow could not be saved." }, 503);
  }
}
