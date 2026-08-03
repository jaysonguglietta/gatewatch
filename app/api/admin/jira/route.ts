import { audit, acceptsJson, apiJson, requireAdmin, sameOrigin } from "../../../../lib/server-admin";
import { callJiraBridge, type JiraStatus } from "../../../../lib/jira-bridge";
import { cleanText } from "../../../../lib/admin-sources";

function configuration(input: Record<string, unknown>) {
  return {
    baseUrl: cleanText(input.baseUrl, 400),
    email: cleanText(input.email, 254),
    apiToken: cleanText(input.apiToken, 1000),
    projectKey: cleanText(input.projectKey, 20).toUpperCase(),
    issueType: cleanText(input.issueType, 80) || "Task",
  };
}

export async function GET(request: Request) {
  const auth = await requireAdmin(request);
  if (!auth.allowed) return apiJson({ error: "Administrator access is required." }, 403);
  try {
    const status = await callJiraBridge<JiraStatus>("/jira/status");
    return apiJson({ ...status });
  } catch {
    return apiJson({
      configured: false,
      available: false,
      error: "Jira configuration is unavailable until the AWS runtime update is deployed.",
    }, 503);
  }
}

export async function POST(request: Request) {
  const auth = await requireAdmin(request);
  if (!auth.allowed) return apiJson({ error: "Administrator access is required." }, 403);
  if (!sameOrigin(request)) return apiJson({ error: "Origin is not allowed." }, 403);
  if (!acceptsJson(request, 10_000)) return apiJson({ error: "A bounded JSON request is required." }, 415);
  try {
    const input = (await request.json()) as Record<string, unknown>;
    const action = cleanText(input.action, 20);
    if (!new Set(["test", "save"]).has(action)) {
      return apiJson({ error: "Choose test or save." }, 400);
    }
    const result = await callJiraBridge<JiraStatus>(
      action === "test" ? "/jira/test" : "/jira/config",
      "POST",
      configuration(input),
    );
    await audit(
      auth.user,
      action === "test" ? "jira.tested" : "jira.configured",
      "integration",
      "jira-cloud",
      action === "test"
        ? `Tested Jira Cloud project ${result.projectKey}.`
        : `Configured Jira Cloud project ${result.projectKey}.`,
      { baseUrl: result.baseUrl, projectKey: result.projectKey, issueType: result.issueType },
    );
    return apiJson({ ...result });
  } catch (error) {
    return apiJson({
      error: error instanceof Error ? error.message.slice(0, 240) : "Jira configuration failed.",
    }, 502);
  }
}
