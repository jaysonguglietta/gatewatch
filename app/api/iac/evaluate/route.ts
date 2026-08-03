import { env } from "cloudflare:workers";
import { cleanText } from "../../../../lib/admin-sources";
import {
  acceptsJson,
  apiJson,
  audit,
  ensureAdminSchema,
  requestUser,
  sameOrigin,
} from "../../../../lib/server-admin";

async function tokenMatches(request: Request) {
  const configured = env.GATEWATCH_IAC_WEBHOOK_TOKEN ?? "";
  const supplied = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "") ?? "";
  if (configured.length < 32 || supplied.length !== configured.length) return false;
  const [expected, actual] = await Promise.all(
    [configured, supplied].map((value) =>
      crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
    ),
  );
  const left = new Uint8Array(expected);
  const right = new Uint8Array(actual);
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

export async function POST(request: Request) {
  const browserUser = requestUser(request);
  const webhookAuthenticated = await tokenMatches(request);
  if (!browserUser && !webhookAuthenticated) {
    return apiJson({ error: "A hosting identity or valid CI bearer token is required." }, 401);
  }
  if (browserUser && !webhookAuthenticated && !sameOrigin(request)) {
    return apiJson({ error: "Origin is not allowed." }, 403);
  }
  const user = browserUser || "iac-webhook";
  if (!acceptsJson(request, 30_000)) {
    return apiJson({ error: "Send an application/json payload under 30 KB." }, 415);
  }
  try {
    const input = (await request.json()) as Record<string, unknown>;
    const repository = cleanText(input.repository, 240);
    const pullRequest = cleanText(input.pullRequest, 80);
    const author = cleanText(input.author, 160);
    const environment = cleanText(input.environment, 80);
    const proposedChange = cleanText(input.proposedChange, 2_000);
    const policy = cleanText(input.policy, 240) || "Gatewatch baseline";
    const currentRisk = Math.max(0, Math.min(100, Number(input.currentRisk) || 0));
    const projectedRisk = Math.max(0, Math.min(100, Number(input.projectedRisk) || 0));
    if (!repository || !pullRequest || !author || proposedChange.length < 12) {
      return apiJson({ error: "Repository, pull request, author, and proposed change are required." }, 400);
    }
    const verdict =
      projectedRisk >= Math.max(70, currentRisk + 10)
        ? "Block"
        : projectedRisk > currentRisk
          ? "Review"
          : "Pass";
    const id = `iac:${crypto.randomUUID()}`;
    const evaluation = {
      id,
      repository,
      pullRequest,
      author,
      environment,
      proposedChange,
      projectedRisk,
      currentRisk,
      verdict,
      policy,
      evidence: [
        `Risk delta: ${projectedRisk - currentRisk}`,
        `Policy: ${policy}`,
        `Evaluated by ${user}`,
      ],
    };
    await ensureAdminSchema();
    await env.DB.prepare(
      `INSERT INTO integration_deliveries
        (id, workspace_id, integration, event_type, target_id, status,
         attempts, payload, next_attempt_at)
       VALUES (?, 'default', 'iac', 'iac.evaluation', ?, 'evaluated', 1, ?, '')`,
    ).bind(id, `${repository}:${pullRequest}`, JSON.stringify(evaluation)).run();
    await audit(user, "iac.evaluated", "pull-request", `${repository}:${pullRequest}`, `IaC evaluation returned ${verdict}.`, { currentRisk, projectedRisk, policy });
    return apiJson({ evaluation }, 201);
  } catch (error) {
    if (error instanceof SyntaxError) return apiJson({ error: "Request body must be valid JSON." }, 400);
    return apiJson({ error: "The IaC evaluation could not be completed." }, 503);
  }
}
