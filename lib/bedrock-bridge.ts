import { env } from "cloudflare:workers";
import type { AiAnalysisMode, AiSecurityAnalysis } from "./ai-security-analyst";

export type BedrockBridgeResult = {
  analysis: AiSecurityAnalysis;
  modelId: string;
  usage: { inputTokens: number; outputTokens: number; latencyMs: number };
  guardrail: { configured: boolean; action: string; traceId: string };
};

function bridgeConfiguration() {
  const url = env.GATEWATCH_AWS_BRIDGE_URL?.replace(/\/$/, "");
  const token = env.GATEWATCH_AWS_BRIDGE_TOKEN;
  if (!url || !token || env.GATEWATCH_BEDROCK_ENABLED !== "true") {
    throw new Error("BEDROCK_NOT_CONFIGURED");
  }
  return { url, token };
}

export async function callBedrockBridge(input: {
  mode: AiAnalysisMode;
  system: string;
  prompt: string;
  schema: Record<string, unknown>;
}): Promise<BedrockBridgeResult> {
  const bridge = bridgeConfiguration();
  const response = await fetch(`${bridge.url}/bedrock/analyze`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${bridge.token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(input),
    signal: AbortSignal.timeout(90_000),
  });
  const payload = (await response.json()) as BedrockBridgeResult & { error?: string };
  if (!response.ok) throw new Error(payload.error ?? "BEDROCK_BRIDGE_FAILED");
  return payload;
}

export async function bedrockBridgeStatus() {
  try {
    const bridge = bridgeConfiguration();
    const response = await fetch(`${bridge.url}/bedrock/status`, {
      headers: { authorization: `Bearer ${bridge.token}` },
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error("BEDROCK_STATUS_FAILED");
    return await response.json() as {
      enabled: boolean;
      modelId: string;
      region: string;
      guardrailConfigured: boolean;
      guardrailVersion: string;
    };
  } catch {
    return { enabled: false, modelId: "", region: "", guardrailConfigured: false, guardrailVersion: "" };
  }
}
