import { deriveLiveIntelligence } from "../../../../lib/live-intelligence";
import { loadAwsInventory } from "../../../../lib/aws-inventory";
import { env } from "cloudflare:workers";
import { apiJson, ensureAdminSchema, requestUser, safeJson } from "../../../../lib/server-admin";
import type { IacChange } from "../../../../lib/product-intelligence-data";

export async function GET(request: Request) {
  if (!requestUser(request)) {
    return apiJson({ error: "Authentication is required." }, 401);
  }
  try {
    const inventory = await loadAwsInventory();
    await ensureAdminSchema();
    const evaluations = await env.DB.prepare(
      `SELECT payload FROM integration_deliveries
       WHERE workspace_id = 'default' AND integration = 'iac'
         AND event_type = 'iac.evaluation'
       ORDER BY created_at DESC LIMIT 100`,
    ).all<{ payload: string }>();
    const intelligence = deriveLiveIntelligence(inventory);
    intelligence.iacChanges = evaluations.results
      .map((row) => safeJson<IacChange | null>(row.payload, null))
      .filter((item): item is IacChange => Boolean(item));
    return apiJson({ intelligence });
  } catch {
    return apiJson(
      { error: "Live intelligence is unavailable until AWS evidence is connected." },
      503,
    );
  }
}
