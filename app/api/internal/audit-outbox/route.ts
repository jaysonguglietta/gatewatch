import { timingSafeEqual } from "node:crypto";
import { env } from "cloudflare:workers";
import { apiJson, deliverAuditOutbox } from "../../../../lib/server-admin";

export const runtime = "nodejs";

function authorized(request: Request) {
  const expected = `Bearer ${env.GATEWATCH_AWS_BRIDGE_TOKEN ?? ""}`;
  const actual = request.headers.get("authorization") ?? "";
  const expectedBytes = Buffer.from(expected);
  const actualBytes = Buffer.from(actual);
  return expectedBytes.length > 7
    && actualBytes.length === expectedBytes.length
    && timingSafeEqual(actualBytes, expectedBytes);
}

export async function POST(request: Request) {
  if (!authorized(request)) return apiJson({ error: "Authentication is required." }, 401);
  try {
    const outcome = await deliverAuditOutbox(50);
    if (outcome.failed > 0) {
      console.error(JSON.stringify({
        event: "audit_outbox_delivery_failed",
        failed: outcome.failed,
        selected: outcome.selected,
      }));
    }
    return apiJson(outcome, outcome.failed > 0 ? 503 : 200);
  } catch {
    console.error(JSON.stringify({ event: "audit_outbox_delivery_failed", failed: -1 }));
    return apiJson({ error: "Audit delivery is temporarily unavailable." }, 503);
  }
}
