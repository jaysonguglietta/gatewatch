import { env } from "cloudflare:workers";
import { canonicalSecurityGroupKey } from "../../../lib/evidence-model";
import { loadAwsInventory } from "../../../lib/aws-inventory";
import { HttpInputError, readBoundedJson } from "../../../lib/http-security";
import {
  canonicalJson,
  remediationDigest,
} from "../../../lib/security-integrity";
import {
  apiJson,
  audit,
  ensureAdminSchema,
  queueNotification,
  requestUser,
  requireAdmin,
  requirePermission,
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
              version, content_digest AS contentDigest,
              approved_version AS approvedVersion,
              approved_digest AS approvedDigest, locked_at AS lockedAt,
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
  const permission = await requirePermission(request, "remediation.write");
  if (!permission.allowed) {
    return apiJson({ error: "Analyst access is required to change remediation records." }, 403);
  }
  try {
    const input = await readBoundedJson(request, 40_000);
    const action = cleanText(input.action, 30);
    const id = cleanText(input.id, 160);
    await ensureAdminSchema();

    if (action === "create") {
      const fingerprint = cleanText(input.fingerprint, 600);
      const canonicalResourceKey = cleanText(input.canonicalResourceKey, 600);
      const proposedChange = cleanText(input.proposedChange, 4_000);
      const evidenceValue = input.evidenceBefore && typeof input.evidenceBefore === "object"
        ? input.evidenceBefore
        : {};
      const evidenceBefore = canonicalJson(evidenceValue);
      const artifactType = "iac-change-request";
      if (!/^rem-[a-zA-Z0-9:_-]{1,140}$/.test(id) || !fingerprint || !canonicalResourceKey.startsWith("aws:") || proposedChange.length < 12 || evidenceBefore.length > 20_000) {
        return apiJson({ error: "Complete the remediation identity and proposed change." }, 400);
      }
      const contentDigest = await remediationDigest({
        fingerprint,
        canonicalResourceKey,
        proposedChange,
        artifactType,
        evidenceBefore: evidenceValue,
      });
      const existing = await env.DB.prepare(
        `SELECT fingerprint, canonical_resource_key AS canonicalResourceKey,
                status, version, content_digest AS contentDigest
         FROM remediation_requests WHERE id = ? AND workspace_id = 'default'`,
      ).bind(id).first<{
        fingerprint: string;
        canonicalResourceKey: string;
        status: string;
        version: number;
        contentDigest: string;
      }>();
      if (existing && (existing.fingerprint !== fingerprint || existing.canonicalResourceKey !== canonicalResourceKey)) {
        return apiJson({ error: "A remediation identity cannot be changed after creation." }, 409);
      }
      if (existing?.status !== undefined && existing.status !== "draft") {
        return apiJson({ error: "Approved or completed remediations are immutable; create a new versioned request." }, 409);
      }
      if (existing?.contentDigest === contentDigest) {
        return apiJson({ record: { id, status: "draft", version: existing.version, contentDigest, idempotent: true } });
      }
      const version = existing ? existing.version + 1 : 1;
      const deliveryId = crypto.randomUUID();
      const statements = existing
        ? [env.DB.prepare(
          `UPDATE remediation_requests
           SET proposed_change = ?, evidence_before = ?, artifact_type = ?,
               version = ?, content_digest = ?, approved_version = 0,
               approved_digest = '', approved_by = '', locked_at = '',
               updated_at = CURRENT_TIMESTAMP
           WHERE id = ? AND workspace_id = 'default' AND status = 'draft'`,
        ).bind(proposedChange, evidenceBefore, artifactType, version, contentDigest, id)]
        : [env.DB.prepare(
          `INSERT INTO remediation_requests
            (id, workspace_id, fingerprint, canonical_resource_key, status,
             proposed_change, artifact_type, evidence_before, requested_by,
             version, content_digest)
           VALUES (?, 'default', ?, ?, 'draft', ?, ?, ?, ?, ?, ?)`,
        ).bind(id, fingerprint, canonicalResourceKey, proposedChange, artifactType, evidenceBefore, user, version, contentDigest)];
      statements.push(
        env.DB.prepare(
          `INSERT INTO integration_deliveries
            (id, workspace_id, integration, event_type, target_id, status,
             payload, next_attempt_at)
           VALUES (?, 'default', 'iac', 'remediation.created', ?, 'pending', ?, CURRENT_TIMESTAMP)`,
        ).bind(deliveryId, id, canonicalJson({ id, version, contentDigest, fingerprint, canonicalResourceKey, proposedChange })),
      );
      await env.DB.batch(statements);
      await audit(user, existing ? "remediation.revised" : "remediation.created", "remediation", id, `${existing ? "Revised" : "Created"} remediation ${id}.`, { canonicalResourceKey, version, contentDigest });
      await queueNotification("remediation.created", id, "high", {
        actor: user,
        canonicalResourceKey,
        summary: proposedChange,
      });
      return apiJson({ record: { id, status: "draft", version, contentDigest, deliveryId } }, existing ? 200 : 201);
    }

    if (action === "approve") {
      const authorization = await requireAdmin(request);
      if (!authorization.allowed) return apiJson({ error: "Administrator approval is required." }, 403);
      const remediation = await env.DB.prepare(
        `SELECT requested_by AS requestedBy, fingerprint,
                canonical_resource_key AS canonicalResourceKey,
                proposed_change AS proposedChange, artifact_type AS artifactType,
                evidence_before AS evidenceBefore, version,
                content_digest AS contentDigest
         FROM remediation_requests
         WHERE id = ? AND workspace_id = 'default' AND status = 'draft'`,
      ).bind(id).first<{
        requestedBy: string;
        fingerprint: string;
        canonicalResourceKey: string;
        proposedChange: string;
        artifactType: string;
        evidenceBefore: string;
        version: number;
        contentDigest: string;
      }>();
      if (!remediation) return apiJson({ error: "A draft remediation was not found." }, 409);
      if (remediation.requestedBy === user) {
        return apiJson({ error: "Remediation requestors cannot approve their own change." }, 409);
      }
      const calculatedDigest = await remediationDigest({
        fingerprint: remediation.fingerprint,
        canonicalResourceKey: remediation.canonicalResourceKey,
        proposedChange: remediation.proposedChange,
        artifactType: remediation.artifactType,
        evidenceBefore: safeJson(remediation.evidenceBefore, {}),
      });
      if (remediation.contentDigest && remediation.contentDigest !== calculatedDigest) {
        return apiJson({ error: "The remediation content failed its integrity check." }, 409);
      }
      const result = await env.DB.prepare(
        `UPDATE remediation_requests
         SET status = 'approved', approved_by = ?, content_digest = ?,
             approved_version = version, approved_digest = ?,
             locked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
         WHERE id = ? AND workspace_id = 'default' AND status = 'draft'
           AND version = ? AND (content_digest = ? OR content_digest = '')`,
      ).bind(user, calculatedDigest, calculatedDigest, id, remediation.version, remediation.contentDigest).run() as { meta?: { changes?: number } };
      if (!result.meta?.changes) return apiJson({ error: "A draft remediation was not found." }, 409);
      const deliveryId = crypto.randomUUID();
      await env.DB.prepare(
        `INSERT INTO integration_deliveries
          (id, workspace_id, integration, event_type, target_id, status, payload, next_attempt_at)
         VALUES (?, 'default', 'iac', 'remediation.approved', ?, 'pending', ?, CURRENT_TIMESTAMP)`,
      ).bind(deliveryId, id, canonicalJson({ id, version: remediation.version, contentDigest: calculatedDigest, approvedBy: user })).run();
      await audit(user, "remediation.approved", "remediation", id, `Approved remediation ${id}.`, { version: remediation.version, contentDigest: calculatedDigest });
      await queueNotification("remediation.approved", id, "high", { actor: user, version: remediation.version, contentDigest: calculatedDigest });
      return apiJson({ record: { id, status: "approved", approvedBy: user, version: remediation.version, contentDigest: calculatedDigest, deliveryId } });
    }

    if (action === "verify") {
      const remediation = await env.DB.prepare(
        `SELECT id, canonical_resource_key AS canonicalResourceKey,
                evidence_before AS evidenceBefore, status, version,
                content_digest AS contentDigest,
                approved_version AS approvedVersion,
                approved_digest AS approvedDigest
         FROM remediation_requests WHERE id = ? AND workspace_id = 'default'`,
      ).bind(id).first<{ id: string; canonicalResourceKey: string; evidenceBefore: string; status: string; version: number; contentDigest: string; approvedVersion: number; approvedDigest: string }>();
      if (!remediation) return apiJson({ error: "The remediation was not found." }, 404);
      if (remediation.status !== "approved" || remediation.version !== remediation.approvedVersion || !remediation.approvedDigest || remediation.contentDigest !== remediation.approvedDigest) {
        return apiJson({ error: "Only an unchanged, digest-bound approved remediation can be verified." }, 409);
      }
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
           WHERE id = ? AND workspace_id = 'default'
             AND status = 'approved' AND version = approved_version
             AND content_digest = approved_digest`,
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
    if (error instanceof HttpInputError) return apiJson({ error: error.message }, error.status);
    return apiJson({ error: "The remediation workflow could not be completed." }, 503);
  }
}
