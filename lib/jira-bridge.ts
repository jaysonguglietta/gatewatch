import { env } from "cloudflare:workers";

export type JiraStatus = {
  configured: boolean;
  baseUrl: string;
  email: string;
  projectKey: string;
  issueType: string;
  displayName: string;
  projectName: string;
  issueTypes: string[];
  lastTestedAt: string;
  tokenStored: boolean;
  passed?: boolean;
};

function bridgeConfiguration() {
  const url = env.GATEWATCH_AWS_BRIDGE_URL?.replace(/\/$/, "");
  const token = env.GATEWATCH_AWS_BRIDGE_TOKEN;
  if (!url || !token || !env.GATEWATCH_JIRA_SECRET_ARN) {
    throw new Error("Jira integration requires the deployed AWS runtime.");
  }
  return { url, token };
}

export async function callJiraBridge<T>(
  path: string,
  method: "GET" | "POST" = "GET",
  body?: Record<string, unknown>,
): Promise<T> {
  const bridge = bridgeConfiguration();
  const response = await fetch(`${bridge.url}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${bridge.token}`,
      ...(body ? { "content-type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(method === "GET" ? 10_000 : 45_000),
  });
  const payload = (await response.json()) as T & { error?: string };
  if (!response.ok) {
    throw new Error(payload.error ?? "The private AWS integration bridge failed.");
  }
  return payload;
}
