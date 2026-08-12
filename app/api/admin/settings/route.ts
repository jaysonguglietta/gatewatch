import { env } from "cloudflare:workers";
import { HttpInputError, readBoundedJson } from "../../../../lib/http-security";
import {
  apiJson,
  audit,
  ensureAdminSchema,
  requireAdmin,
  sameOrigin,
} from "../../../../lib/server-admin";

const roles = new Set(["admin", "analyst", "reviewer", "viewer"]);
const notificationEvents = new Set([
  "remediation.created",
  "remediation.approved",
  "remediation.verification-failed",
]);

export async function POST(request: Request) {
  try {
    const auth = await requireAdmin(request);
    if (!auth.user) return apiJson({ error: "Authentication is required." }, 401);
    if (!auth.allowed) return apiJson({ error: "Administrator access is required." }, 403);
    if (!sameOrigin(request)) return apiJson({ error: "Origin is not allowed." }, 403);
    await ensureAdminSchema();
    const payload = await readBoundedJson(request, 20_000);
    const action = typeof payload.action === "string" ? payload.action : "";

    if (action === "set-role") {
      const email =
        typeof payload.email === "string"
          ? payload.email.trim().toLowerCase().slice(0, 254)
          : "";
      const role = typeof payload.role === "string" ? payload.role : "";
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !roles.has(role)) {
        return apiJson({ error: "Enter a valid email and supported role." }, 400);
      }
      await env.DB.prepare(
        `INSERT INTO user_roles
          (email, role, created_by)
         VALUES (?, ?, ?)
         ON CONFLICT(email) DO UPDATE SET
           role = excluded.role,
           updated_at = CURRENT_TIMESTAMP`,
      ).bind(email, role, auth.user).run();
      await audit(auth.user, "role.updated", "user", email, `Assigned the ${role} role to ${email}.`);
      return apiJson({ role: { email, role } });
    }

    if (action === "remove-role") {
      const email =
        typeof payload.email === "string"
          ? payload.email.trim().toLowerCase().slice(0, 254)
          : "";
      if (email === auth.email) {
        return apiJson({ error: "You cannot remove your own administrator assignment." }, 409);
      }
      await env.DB.prepare(
        "DELETE FROM user_roles WHERE email = ? AND workspace_id = 'default'",
      ).bind(email).run();
      await audit(auth.user, "role.removed", "user", email, `Removed the Gatewatch role for ${email}.`);
      return apiJson({ removed: true });
    }

    if (action === "retention") {
      const eventDays = Math.min(3650, Math.max(30, Math.trunc(Number(payload.eventDays) || 365)));
      const auditDays = Math.min(3650, Math.max(365, Math.trunc(Number(payload.auditDays) || 2555)));
      const evidenceDays = Math.min(3650, Math.max(90, Math.trunc(Number(payload.evidenceDays) || 730)));
      const value = JSON.stringify({ eventDays, auditDays, evidenceDays });
      await env.DB.prepare(
        `INSERT INTO system_settings (key, value, updated_by)
         VALUES ('retention', ?, ?)
         ON CONFLICT(key) DO UPDATE SET
           value = excluded.value,
           updated_by = excluded.updated_by,
           updated_at = CURRENT_TIMESTAMP`,
      ).bind(value, auth.user).run();
      await audit(auth.user, "retention.updated", "system_setting", "retention", "Updated normalized data retention.", { eventDays, auditDays, evidenceDays });
      return apiJson({ retention: { eventDays, auditDays, evidenceDays } });
    }

    if (action === "notifications") {
      const enabled = payload.enabled === true;
      const minimumSeverity = typeof payload.minimumSeverity === "string"
        && ["critical", "high", "medium", "low"].includes(payload.minimumSeverity)
        ? payload.minimumSeverity
        : "high";
      const digest = payload.digest === "daily" ? "daily" : "immediate";
      const events = Array.isArray(payload.events)
        ? [...new Set(payload.events.filter((value): value is string => typeof value === "string" && notificationEvents.has(value)))].slice(0, 10)
        : [];
      const recipients = Array.isArray(payload.recipients)
        ? [...new Set(payload.recipients
            .filter((value): value is string => typeof value === "string")
            .map((value) => value.trim().toLowerCase())
            .filter((value) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)))]
            .slice(0, 20)
        : [];
      if (enabled && (!events.length || !recipients.length)) {
        return apiJson({ error: "Enabled notifications require at least one event and recipient." }, 400);
      }
      const value = JSON.stringify({ enabled, minimumSeverity, events, recipients, digest });
      await env.DB.prepare(
        `INSERT INTO system_settings (key, value, updated_by)
         VALUES ('notifications', ?, ?)
         ON CONFLICT(key) DO UPDATE SET
           value = excluded.value,
           updated_by = excluded.updated_by,
           updated_at = CURRENT_TIMESTAMP`,
      ).bind(value, auth.user).run();
      await audit(auth.user, "notifications.updated", "system_setting", "notifications", "Updated notification routing policy.", { enabled, minimumSeverity, events, recipientCount: recipients.length, digest });
      return apiJson({ notifications: { enabled, minimumSeverity, events, recipients, digest } });
    }

    return apiJson({ error: "Choose a supported settings action." }, 400);
  } catch (error) {
    if (error instanceof HttpInputError) return apiJson({ error: error.message }, error.status);
    return apiJson({ error: "Settings could not be updated." }, 503);
  }
}
