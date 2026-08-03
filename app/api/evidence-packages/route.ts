import { env } from "cloudflare:workers";
import { findingCatalogForGroups } from "../../../lib/daily-findings";
import { loadAwsInventory } from "../../../lib/aws-inventory";
import { ensureAdminSchema, requestUser, safeJson } from "../../../lib/server-admin";

function attachment(body: unknown, filename: string) {
  return new Response(JSON.stringify(body, null, 2), {
    headers: {
      "cache-control": "no-store, private",
      "content-disposition": `attachment; filename="${filename}"`,
      "content-type": "application/json; charset=utf-8",
      "x-content-type-options": "nosniff",
    },
  });
}

async function sha256(value: unknown) {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function GET(request: Request) {
  const user = requestUser(request);
  if (!user) return Response.json({ error: "Authentication is required." }, { status: 401 });
  try {
    await ensureAdminSchema();
    const inventory = await loadAwsInventory();
    const findings = findingCatalogForGroups(inventory.groups, {
      live: true,
      snapshotId: inventory.source.snapshotId,
    });
    const [workflow, reviews, audits] = await Promise.all([
      env.DB.prepare(
        `SELECT fingerprint, status, assignee, note, ticket_ref AS ticketRef,
                due_at AS dueAt, expires_at AS expiresAt, reviewer,
                updated_at AS updatedAt
         FROM finding_workflows WHERE workspace_id = 'default'`,
      ).all(),
      env.DB.prepare(
        `SELECT resource_key AS resourceKey, security_group_id AS securityGroupId,
                account_id AS accountId, region, vpc_id AS vpcId,
                status, assignee, reviewer,
                note, ticket_ref AS ticketRef, expires_at AS expiresAt,
                evidence_snapshot AS evidenceSnapshot, updated_at AS updatedAt
         FROM resource_reviews
         UNION ALL
         SELECT 'legacy:' || legacy.security_group_id AS resourceKey,
                legacy.security_group_id AS securityGroupId,
                '' AS accountId, '' AS region, '' AS vpcId,
                legacy.status, legacy.assignee, legacy.reviewer,
                legacy.note, legacy.ticket_ref AS ticketRef,
                legacy.expires_at AS expiresAt,
                legacy.evidence_snapshot AS evidenceSnapshot,
                legacy.updated_at AS updatedAt
         FROM security_group_reviews AS legacy
         WHERE NOT EXISTS (
           SELECT 1 FROM resource_reviews AS canonical
           WHERE canonical.security_group_id = legacy.security_group_id
         )`,
      ).all(),
      env.DB.prepare(
        `SELECT actor, action, target_type AS targetType, target_id AS targetId,
                summary, metadata, created_at AS createdAt
         FROM audit_events WHERE workspace_id = 'default'
         ORDER BY created_at DESC LIMIT 1000`,
      ).all(),
    ]);
    const packageBodyCore = {
      schemaVersion: "1.0",
      packageType: "Gatewatch auditor evidence package",
      generatedAt: new Date().toISOString(),
      generatedBy: user,
      source: inventory.source,
      manifest: {
        securityGroups: inventory.groups.length,
        findings: findings.length,
        workflowRecords: workflow.results.length,
        reviews: reviews.results.length,
        auditEvents: audits.results.length,
      },
      findings,
      workflows: workflow.results,
      reviews: reviews.results.map((review) => ({
        ...review,
        evidenceSnapshot: safeJson(review.evidenceSnapshot, review.evidenceSnapshot),
      })),
      auditEvents: audits.results.map((event) => ({
        ...event,
        metadata: safeJson(event.metadata, {}),
      })),
      limitations: [
        inventory.source.complete
          ? "The AWS snapshot reports complete collection."
          : "The AWS snapshot is partial; review collection errors before relying on negative conclusions.",
        "Raw AWS objects remain in the customer-controlled source bucket and are referenced by snapshot identity.",
      ],
    };
    const packageBody = {
      ...packageBodyCore,
      integrity: {
        algorithm: "SHA-256",
        scope: "UTF-8 JSON serialization of this package without the integrity field",
        digest: await sha256(packageBodyCore),
      },
    };
    return attachment(
      packageBody,
      `gatewatch-auditor-evidence-${new Date().toISOString().slice(0, 10)}.json`,
    );
  } catch {
    return Response.json(
      { error: "The auditor evidence package could not be generated." },
      { status: 503 },
    );
  }
}
