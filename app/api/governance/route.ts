import { env } from "cloudflare:workers";
import { findingCatalogForGroups } from "../../../lib/daily-findings";
import { loadAwsInventory } from "../../../lib/aws-inventory";
import { ensureAdminSchema, requireAdmin, requirePermission } from "../../../lib/server-admin";

type GovernanceInput = {
  kind?: unknown;
  record?: unknown;
};

type InputRecord = Record<string, unknown>;

function json(body: Record<string, unknown>, status = 200) {
  return Response.json(body, {
    status,
    headers: {
      "cache-control": "no-store, private",
      "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
      "x-content-type-options": "nosniff",
    },
  });
}

function cleanText(value: unknown, maxLength: number) {
  return typeof value === "string" ? value.trim().slice(0, maxLength) : "";
}

function parseJson(value: unknown) {
  if (typeof value !== "string") return {};
  try {
    return JSON.parse(value) as Record<string, unknown>;
  } catch {
    return { parseError: "Stored evaluation is not valid JSON." };
  }
}

function authenticatedUser(request: Request) {
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
  await ensureAdminSchema();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS access_policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT NOT NULL,
      owner TEXT NOT NULL,
      destination TEXT NOT NULL,
      service TEXT NOT NULL,
      yaml TEXT NOT NULL,
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS recertification_campaigns (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT NOT NULL,
      owner TEXT NOT NULL,
      scope TEXT NOT NULL,
      due_date TEXT NOT NULL,
      total INTEGER NOT NULL DEFAULT 0,
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE INDEX IF NOT EXISTS recertification_campaigns_due_idx
     ON recertification_campaigns (due_date, updated_at)`,
  ).run();
}

export async function GET(request: Request) {
  try {
    if (!authenticatedUser(request)) {
      return json({ error: "Authentication is required." }, 401);
    }
    await ensureSchema();
    const [policies, campaigns, versions, campaignItems] = await env.DB.batch([
      env.DB.prepare(
        `SELECT id, name, description, owner, destination, service, yaml,
                created_by AS createdBy, created_at AS createdAt,
                updated_at AS updatedAt
         FROM access_policies
         ORDER BY updated_at DESC`,
      ),
      env.DB.prepare(
        `SELECT campaign.id, campaign.name, campaign.description, campaign.owner,
                campaign.scope, campaign.due_date AS dueDate, campaign.total,
                campaign.created_by AS createdBy,
                campaign.created_at AS createdAt,
                campaign.updated_at AS updatedAt,
                SUM(CASE WHEN item.status = 'complete' THEN 1 ELSE 0 END) AS completed,
                SUM(CASE WHEN item.status = 'overdue' THEN 1 ELSE 0 END) AS escalations
         FROM recertification_campaigns campaign
         LEFT JOIN campaign_items item
           ON item.workspace_id = 'default' AND item.campaign_id = campaign.id
         GROUP BY campaign.id
         ORDER BY due_date ASC`,
      ),
      env.DB.prepare(
        `SELECT id, policy_id AS policyId, version, status, yaml, evaluation,
                created_by AS createdBy, created_at AS createdAt
         FROM access_policy_versions
         WHERE workspace_id = 'default'
         ORDER BY policy_id, version DESC`,
      ),
      env.DB.prepare(
        `SELECT id, campaign_id AS campaignId, fingerprint, owner, status,
                decision, note, evidence_snapshot AS evidenceSnapshot,
                decided_by AS decidedBy, decided_at AS decidedAt
         FROM campaign_items
         WHERE workspace_id = 'default'
         ORDER BY campaign_id, owner, id`,
      ),
    ]);
    return json({
      policies: policies.results,
      campaigns: campaigns.results,
      versions: versions.results.map((version) => ({
        ...version,
        evaluation: parseJson(version.evaluation),
      })),
      campaignItems: campaignItems.results,
    });
  } catch {
    return json({ error: "Governance records are temporarily unavailable." }, 503);
  }
}

export async function POST(request: Request) {
  try {
    const user = authenticatedUser(request);
    if (!user) return json({ error: "Authentication is required." }, 401);
    if (!sameOrigin(request)) return json({ error: "Origin is not allowed." }, 403);
    const permission = await requirePermission(request, "governance.write");
    if (!permission.allowed) {
      return json({ error: "Analyst or reviewer access is required to change governance records." }, 403);
    }

    const contentLength = Number(request.headers.get("content-length") ?? "0");
    if (contentLength > 30_000) {
      return json({ error: "The governance payload is too large." }, 413);
    }
    if (!request.headers.get("content-type")?.startsWith("application/json")) {
      return json({ error: "Content-Type must be application/json." }, 415);
    }

    const payload = (await request.json()) as GovernanceInput;
    const kind = cleanText(payload.kind, 20);
    const record =
      payload.record && typeof payload.record === "object"
        ? (payload.record as InputRecord)
        : {};
    await ensureSchema();

    if (kind === "policy") {
      const id = cleanText(record.id, 80);
      const name = cleanText(record.name, 120);
      const description = cleanText(record.description, 500);
      const owner = cleanText(record.owner, 120);
      const destination = cleanText(record.destination, 300);
      const service = cleanText(record.service, 120);
      const yaml = cleanText(record.yaml, 8_000);
      if (!/^scope-[a-zA-Z0-9-]+$/.test(id)) {
        return json({ error: "A valid policy ID is required." }, 400);
      }
      if (name.length < 5 || !owner || !destination || !service || !yaml) {
        return json({ error: "Complete every required policy field." }, 400);
      }
      await env.DB.batch([
        env.DB.prepare(
        `INSERT INTO access_policies
          (id, name, description, owner, destination, service, yaml, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
        .bind(id, name, description, owner, destination, service, yaml, user),
        env.DB.prepare(
          `INSERT INTO access_policy_versions
            (id, workspace_id, policy_id, version, status, yaml, evaluation, created_by)
           VALUES (?, 'default', ?, 1, 'draft', ?, '{}', ?)`,
        ).bind(`${id}:v1`, id, yaml, user),
      ]);
      return json(
        {
          record: {
            id,
            name,
            description,
            owner,
            destination,
            service,
            yaml,
          },
        },
        201,
      );
    }

    if (kind === "campaign") {
      const id = cleanText(record.id, 80);
      const name = cleanText(record.name, 120);
      const description = cleanText(record.description, 500);
      const owner = cleanText(record.owner, 120);
      const scope = cleanText(record.scope, 300);
      const dueDate = cleanText(record.dueDate, 20);
      if (!/^camp-[a-zA-Z0-9-]+$/.test(id)) {
        return json({ error: "A valid campaign ID is required." }, 400);
      }
      if (
        name.length < 6 ||
        !owner ||
        !scope ||
        !/^\d{4}-\d{2}-\d{2}$/.test(dueDate)
      ) {
        return json({ error: "Complete every required campaign field." }, 400);
      }
      const inventory = await loadAwsInventory();
      const allFindings = findingCatalogForGroups(inventory.groups, {
        live: true,
        snapshotId: inventory.source.snapshotId,
      });
      const scopeParts = scope.split("=").map((value) => value.trim());
      const supportedScope = scopeParts.length === 2 && ["environment", "account", "owner"]
        .includes(scopeParts[0].toLowerCase()) && Boolean(scopeParts[1]);
      if (!supportedScope) {
        return json({ error: "Campaign scopes must use Environment, Account, or Owner with an exact value." }, 400);
      }
      const scoped = allFindings.filter((finding) => {
        const [field, value] = scopeParts;
        if (field.toLowerCase() === "environment") return finding.environment === value;
        if (field.toLowerCase() === "account") return finding.accountId === value;
        if (field.toLowerCase() === "owner") return finding.owner === value;
        return false;
      }).slice(0, 10_000);
      const total = scoped.length;
      if (!total) {
        return json({ error: "The campaign scope does not match any current findings." }, 409);
      }
      await env.DB.prepare(
        `INSERT INTO recertification_campaigns
          (id, name, description, owner, scope, due_date, total, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
        .bind(id, name, description, owner, scope, dueDate, total, user)
        .run();
      for (let offset = 0; offset < scoped.length; offset += 80) {
        await env.DB.batch(scoped.slice(offset, offset + 80).map((finding) =>
          env.DB.prepare(
            `INSERT INTO campaign_items
              (id, workspace_id, campaign_id, fingerprint, owner, status,
               evidence_snapshot)
             VALUES (?, 'default', ?, ?, ?, 'pending', ?)`,
          ).bind(
            `${id}:${finding.fingerprint}`,
            id,
            finding.fingerprint,
            finding.owner,
            finding.evidenceSnapshot,
          ),
        ));
      }
      return json(
        {
          record: {
            id,
            name,
            description,
            owner,
            scope,
            dueDate,
            total,
          },
        },
        201,
      );
    }

    if (kind === "policy-action") {
      const policyId = cleanText(record.policyId, 80);
      const action = cleanText(record.action, 30);
      if (!policyId || !["preview", "activate", "retire"].includes(action)) {
        return json({ error: "Choose a valid policy action." }, 400);
      }
      const policy = await env.DB.prepare(
        `SELECT id, destination, service, yaml
         FROM access_policies WHERE id = ?`,
      ).bind(policyId).first<{ id: string; destination: string; service: string; yaml: string }>();
      if (!policy) return json({ error: "The policy was not found." }, 404);
      const version = await env.DB.prepare(
        `SELECT id, version, status FROM access_policy_versions
         WHERE workspace_id = 'default' AND policy_id = ?
         ORDER BY version DESC LIMIT 1`,
      ).bind(policyId).first<{ id: string; version: number; status: string }>();
      if (!version) return json({ error: "The policy version was not found." }, 404);
      if (action === "activate") {
        const authorization = await requireAdmin(request);
        if (!authorization.allowed) {
          return json({ error: "Administrator approval is required to activate a policy." }, 403);
        }
        if (version.status !== "previewed") {
          return json({ error: "Run a current AWS preview before activation." }, 409);
        }
      }
      let evaluation: Record<string, unknown> = {};
      if (action === "preview") {
        const inventory = await loadAwsInventory();
        const destinationValue = policy.destination.split("=").at(-1)?.trim().toLowerCase() ?? "";
        const matched = inventory.groups.filter((group) =>
          [group.environment, group.service, group.name, group.accountName]
            .join(" ")
            .toLowerCase()
            .includes(destinationValue),
        );
        evaluation = {
          evaluatedAt: new Date().toISOString(),
          snapshotId: inventory.source.snapshotId,
          matchedResources: matched.length,
          violations: matched.reduce((sum, group) => sum + group.findings.length, 0),
          resourceKeys: matched.map((group) => `${group.accountId}:${group.region}:${group.vpc}:${group.id}`),
        };
      }
      const status = action === "activate" ? "active" : action === "retire" ? "retired" : "previewed";
      await env.DB.prepare(
        `UPDATE access_policy_versions
         SET status = ?, evaluation = ?
         WHERE id = ? AND workspace_id = 'default'`,
      ).bind(status, JSON.stringify(evaluation), version.id).run();
      return json({ record: { policyId, version: version.version, status, evaluation } });
    }

    if (kind === "campaign-decision") {
      const itemId = cleanText(record.itemId, 220);
      const decision = cleanText(record.decision, 30);
      const note = cleanText(record.note, 1200);
      if (!itemId || !["attest", "remove", "escalate"].includes(decision) || note.length < 8) {
        return json({ error: "A valid campaign decision and explanatory note are required." }, 400);
      }
      if (["remove", "escalate"].includes(decision)) {
        const authorization = await requireAdmin(request);
        if (!authorization.allowed) {
          return json({ error: "Administrator approval is required to remove or escalate access." }, 403);
        }
      }
      const status = decision === "escalate" ? "overdue" : "complete";
      const result = await env.DB.prepare(
        `UPDATE campaign_items
         SET status = ?, decision = ?, note = ?, decided_by = ?,
             decided_at = CURRENT_TIMESTAMP
         WHERE id = ? AND workspace_id = 'default'`,
      ).bind(status, decision, note, user, itemId).run();
      if (!result.meta.changes) return json({ error: "The campaign item was not found." }, 404);
      return json({ record: { itemId, status, decision, decidedBy: user } });
    }

    return json({ error: "Choose a supported governance record type." }, 400);
  } catch (error) {
    if (error instanceof SyntaxError) {
      return json({ error: "Request body must be valid JSON." }, 400);
    }
    return json({ error: "The governance record could not be saved." }, 503);
  }
}
