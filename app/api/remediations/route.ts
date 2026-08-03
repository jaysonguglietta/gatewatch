import { env } from "cloudflare:workers";
import { canonicalSecurityGroupKey } from "../../../lib/evidence-model";
import { loadAwsInventory } from "../../../lib/aws-inventory";
import {
  acceptsJson,
  apiJson,
  audit,
  ensureAdminSchema,
  queueNotification,
  requestUser,
  requireAdmin,
  safeJson,
  sameOrigin,
} from "../../../lib/server-admin";
import { cleanText } from "../../../lib/admin-sources";

export async function GET(request: Request) {
  if (!requestUser(request)) return apiJson({ error: "Authentication is required." }, 401);
  await ensureAdminSchema();
  const [requests, verifications, deliveries] = await env.DB.batch([
    env.DB.prepare(
      `SELECT id, fingerprint, canonical_resource_key AS canonicalResourceKey,
              status, proposed_change AS proposedChange,
              artifact_type AS artifactType, external_ref AS externalRef,
              evidence_before AS evidenceBefore, evidence_after AS evidenceAfter,
              requested_by AS requestedBy, approved_by AS approvedBy,
              created_at AS createdAt, updated_at AS updatedAt
       FROM remediation_requests WHERE workspace_id = 'default'
       ORDER BY updated_at DESC LIMIT 500`,
    ),
    env.DB.prepare(
      `SELECT id, remediation_id AS remediationId, snapshot_id AS snapshotId,
              status, result, created_at AS createdAt
       FROM verification_runs WHERE workspace_id = 'default'
       ORDER BY created_at DESC LIMIT 500`,
    ),
    env.DB.prepare(
      `SELECT id, integration, event_type AS eventType, target_id AS targetId,
              status, attempts, last_error AS lastError,
              next_attempt_at AS nextAttemptAt, created_at AS createdAt
       FROM integration_deliveries WHERE workspace_id = 'default'
       ORDER BY created_at DESC LIMIT 500`,
    ),
  ]);
  return apiJson({
    requests: requests.results.map((item) => ({
      ...item,
      evidenceBefore: safeJson(item.evidenceBefore, {}),
      evidenceAfter: safeJson(item.evidenceAfter, {}),
    })),
    verifications: verifications.results.map((item) => ({
      ...item,
      result: safeJson(item.result, {}),
    })),
    deliveries: deliveries.results,
  });
}

export async function POST(request: Request) {
  const user = requestUser(request);
  if (!user) return apiJson({ error: "Authentication is required." }, 401);
  if (!sameOrigin(request)) return apiJson({ error: "Origin is not allowed." }, 403);
  if (!acceptsJson(request, 40_000)) {
    return apiJson({ error: "Send an application/json payload under 40 KB." }, 415);
  }
  try {
    const input = (await request.json()) as Record<string, unknown>;
    const action = cleanText(input.action, 30);
    const id = cleanText(input.id, 160);
    await ensureAdminSchema();

    if (action === "create") {
      const fingerprint = cleanText(input.fingerprint, 600);
      const canonicalResourceKey = cleanText(input.canonicalResourceKey, 600);
      const proposedChange = cleanText(input.proposedChange, 4_000);
      const evidenceBefore =
        input.evidenceBefore && typeof input.evidenceBefore === "object"
          ? JSON.stringify(input.evidenceBefore).slice(0, 20_000)
          : "{}";
      if (!id || !fingerprint || !canonicalResourceKey.startsWith("aws:") || proposedChange.length < 12) {
        return apiJson({ error: "Complete the remediation identity and proposed change." }, 400);
      }
      const deliveryId = crypto.randomUUID();
      await env.DB.batch([
        env.DB.prepare(
          `INSERT INTO remediation_requests
            (id, workspace_id, fingerprint, canonical_resource_key, status,
             proposed_change, artifact_type, evidence_before, requested_by)
           VALUES (?, 'default', ?, ?, 'draft', ?, 'iac-change-request', ?, ?)
           ON CONFLICT(id) DO UPDATE SET
             proposed_change = excluded.proposed_change,
             evidence_before = excluded.evidence_before,
             updated_at = CURRENT_TIMESTAMP`,
        ).bind(id, fingerprint, canonicalResourceKey, proposedChange, evidenceBefore, user),
        env.DB.prepare(
          `INSERT INTO integration_deliveries
            (id, workspace_id, integration, event_type, target_id, status,
             payload, next_attempt_at)
           VALUES (?, 'default', 'iac', 'remediation.created', ?, 'pending', ?, CURRENT_TIMESTAMP)`,
        ).bind(deliveryId, id, JSON.stringify({ id, fingerprint, canonicalResourceKey, proposedChange })),
      ]);
      await audit(user, "remediation.created", "remediation", id, `Created remediation ${id}.`, { canonicalResourceKey });
      await queueNotification("remediation.created", id, "high", {
        actor: user,
        canonicalResourceKey,
        summary: proposedChange,
      });
      return apiJson({ record: { id, status: "draft", deliveryId } }, 201);
    }

    if (action === "approve") {
      const authorization = await requireAdmin(request);
      if (!authorization.allowed) return apiJson({ error: "Administrator approval is required." }, 403);
      const result = await env.DB.prepare(
        `UPDATE remediation_requests
         SET status = 'approved', approved_by = ?, updated_at = CURRENT_TIMESTAMP
         WHERE id = ? AND workspace_id = 'default' AND status = 'draft'`,
      ).bind(user, id).run();
      if (!result.meta.changes) return apiJson({ error: "A draft remediation was not found." }, 409);
      await audit(user, "remediation.approved", "remediation", id, `Approved remediation ${id}.`);
      await queueNotification("remediation.approved", id, "high", { actor: user });
      return apiJson({ record: { id, status: "approved", approvedBy: user } });
    }

    if (action === "verify") {
      const remediation = await env.DB.prepare(
        `SELECT id, canonical_resource_key AS canonicalResourceKey,
                evidence_before AS evidenceBefore
         FROM remediation_requests WHERE id = ? AND workspace_id = 'default'`,
      ).bind(id).first<{ id: string; canonicalResourceKey: string; evidenceBefore: string }>();
      if (!remediation) return apiJson({ error: "The remediation was not found." }, 404);
      const inventory = await loadAwsInventory(true);
      const group = inventory.groups.find(
        (candidate) => canonicalSecurityGroupKey(candidate) === remediation.canonicalResourceKey,
      );
      const before = safeJson<Record<string, unknown>>(remediation.evidenceBefore, {});
      const currentRisk = group?.riskScore ?? 0;
      const previousRisk = Number(before.riskScore ?? before.risk ?? 0);
      const status = !group || currentRisk < previousRisk ? "passed" : "needs-review";
      const verificationId = crypto.randomUUID();
      const verification = {
        resourcePresent: Boolean(group),
        previousRisk,
        currentRisk,
        publicRules: group?.publicRules ?? 0,
        verifiedAt: new Date().toISOString(),
      };
      await env.DB.batch([
        env.DB.prepare(
          `INSERT INTO verification_runs
            (id, workspace_id, remediation_id, snapshot_id, status, result)
           VALUES (?, 'default', ?, ?, ?, ?)`,
        ).bind(verificationId, id, inventory.source.snapshotId, status, JSON.stringify(verification)),
        env.DB.prepare(
          `UPDATE remediation_requests
           SET status = ?, evidence_after = ?, updated_at = CURRENT_TIMESTAMP
           WHERE id = ? AND workspace_id = 'default'`,
        ).bind(status === "passed" ? "verified" : "verification-failed", JSON.stringify(verification), id),
      ]);
      await audit(user, "remediation.verified", "remediation", id, `Verification ${status} for ${id}.`, verification);
      if (status !== "passed") {
        await queueNotification("remediation.verification-failed", id, "critical", {
          actor: user,
          verification,
        });
      }
      return apiJson({ verification: { id: verificationId, status, result: verification } });
    }

    return apiJson({ error: "Choose a supported remediation action." }, 400);
  } catch (error) {
    if (error instanceof SyntaxError) return apiJson({ error: "Request body must be valid JSON." }, 400);
    return apiJson({ error: "The remediation workflow could not be completed." }, 503);
  }
}
