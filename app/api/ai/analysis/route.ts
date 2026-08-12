import { env } from "cloudflare:workers";
import {
  AI_PROMPT_VERSION,
  AI_SCHEMA_VERSION,
  MAX_AI_FINDINGS,
  MAX_AI_REQUEST_BYTES,
  aiSecurityAnalysisJsonSchema,
  buildAiEvidencePackage,
  buildAiPrompt,
  deterministicAiFallback,
  validateAiSecurityAnalysis,
  type AiAnalysisEnvelope,
  type AiAnalysisMode,
  type AiSecurityAnalysis,
} from "../../../../lib/ai-security-analyst";
import { callBedrockBridge, bedrockBridgeStatus } from "../../../../lib/bedrock-bridge";
import {
  findingCatalogForGroups,
  type DailyFinding,
} from "../../../../lib/daily-findings";
import { loadAwsInventory } from "../../../../lib/aws-inventory";
import { HttpInputError, readBoundedJson } from "../../../../lib/http-security";
import { translateNaturalLanguageHunt } from "../../../../lib/security-group-triage";
import {
  apiJson,
  audit,
  ensureAdminSchema,
  requestUser,
  requirePermission,
  safeJson,
  sameOrigin,
} from "../../../../lib/server-admin";

const allowedModes = new Set<AiAnalysisMode>(["finding", "hunt", "digest", "cluster", "remediation"]);
const dailyUserLimit = 100;
const dailyWorkspaceLimit = 500;
const cacheDays = 7;

type AnalysisRow = {
  id: string;
  fingerprint: string;
  mode: AiAnalysisMode;
  evidenceHash: string;
  source: "bedrock" | "deterministic";
  modelId: string;
  resultJson: string;
  inputTokens: number;
  outputTokens: number;
  latencyMs: number;
  guardrailAction: string;
  guardrailTraceId: string;
  generatedAt: string;
  expiresAt: string;
};

async function ensureSchema() {
  await ensureAdminSchema();
  await env.DB.batch([
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS ai_analyses (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL DEFAULT 'default',
      fingerprint TEXT NOT NULL DEFAULT '',
      mode TEXT NOT NULL,
      evidence_hash TEXT NOT NULL,
      prompt_version TEXT NOT NULL,
      schema_version TEXT NOT NULL,
      source TEXT NOT NULL,
      model_id TEXT NOT NULL DEFAULT '',
      result_json TEXT NOT NULL,
      input_tokens INTEGER NOT NULL DEFAULT 0,
      output_tokens INTEGER NOT NULL DEFAULT 0,
      latency_ms INTEGER NOT NULL DEFAULT 0,
      guardrail_action TEXT NOT NULL DEFAULT '',
      guardrail_trace_id TEXT NOT NULL DEFAULT '',
      generated_by TEXT NOT NULL,
      generated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      expires_at TEXT NOT NULL
    )`),
    env.DB.prepare(`CREATE UNIQUE INDEX IF NOT EXISTS ai_analyses_cache_idx ON ai_analyses (workspace_id, mode, evidence_hash, prompt_version)`),
    env.DB.prepare(`CREATE INDEX IF NOT EXISTS ai_analyses_finding_idx ON ai_analyses (workspace_id, fingerprint, generated_at)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS ai_feedback (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL DEFAULT 'default',
      analysis_id TEXT NOT NULL,
      rating TEXT NOT NULL,
      reason TEXT NOT NULL DEFAULT '',
      actor TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(workspace_id, analysis_id, actor)
    )`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS ai_usage_daily (
      workspace_id TEXT NOT NULL DEFAULT 'default',
      usage_date TEXT NOT NULL,
      actor TEXT NOT NULL,
      requests INTEGER NOT NULL DEFAULT 0,
      input_tokens INTEGER NOT NULL DEFAULT 0,
      output_tokens INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY(workspace_id, usage_date, actor)
    )`),
  ]);
}

async function sha256(value: string) {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function canonicalFindings(value: unknown) {
  const raw = Array.isArray(value) ? value : value ? [value] : [];
  const fingerprints = [...new Set(
    raw.map((item) => String(item ?? "").trim().slice(0, 200)).filter(Boolean),
  )].slice(0, MAX_AI_FINDINGS + 1);
  if (!fingerprints.length || fingerprints.length > MAX_AI_FINDINGS) return null;

  const inventory = await loadAwsInventory();
  const catalog = findingCatalogForGroups(inventory.groups, {
    live: true,
    snapshotId: inventory.source.snapshotId,
  });
  const byFingerprint = new Map<string, DailyFinding>();
  for (const finding of catalog) {
    const canonical: DailyFinding = {
      ...finding,
      status: "new",
      assignee: finding.owner || "Unassigned",
      note: "",
      ticketRef: "",
      dueAt: "",
      expiresAt: "",
      compensatingControls: [],
      reviewer: "",
      updatedAt: finding.lastObserved,
      reasonCode: "",
      nextReviewAt: "",
      approver: "",
      resolutionEvidence: "",
      lastSeenAt: finding.lastObserved,
      observationCount: 1,
      observationState: "active",
    };
    byFingerprint.set(finding.fingerprint, canonical);
    byFingerprint.set(finding.legacyFingerprint, canonical);
  }
  const findings = fingerprints.map((fingerprint) => byFingerprint.get(fingerprint));
  return findings.every(Boolean) ? findings as DailyFinding[] : [];
}

function fallbackHunt(question: string, finding: DailyFinding): AiSecurityAnalysis {
  const translated = translateNaturalLanguageHunt(question);
  const base = deterministicAiFallback("hunt", finding, translated.query);
  return validateAiSecurityAnalysis({
    ...base,
    title: translated.recognized ? "Transparent search translation" : "Search needs clarification",
    executiveSummary: translated.recognized ? `Gatewatch translated the request into ${translated.explanations.join(", ")}.` : "The deterministic translator could not identify enough supported search concepts.",
    whyItMatters: "The generated query remains visible and is evaluated by Gatewatch's deterministic search engine.",
    confidence: translated.recognized ? 95 : 25,
    confidenceRationale: translated.recognized ? "Every generated clause maps to an existing Gatewatch query field." : "No supported deterministic clauses were recognized.",
    deterministicVerdict: "Search translation only",
    claims: [],
    evidenceGaps: translated.recognized ? ["Review the generated clauses before running the search."] : ["Add an environment, exposure state, port, account, workflow state, or time window."],
    recommendedActions: translated.recognized ? [{ priority: "now", action: "Review and run the visible deterministic query.", reason: "Natural language never bypasses the query parser.", requiresApproval: true }] : [],
    searchQuery: translated.query,
  }, "hunt");
}

function fallbackFor(mode: AiAnalysisMode, findings: DailyFinding[], question: string) {
  const first = findings[0];
  if (mode === "hunt") return fallbackHunt(question, first);
  const base = deterministicAiFallback(mode, first);
  if (mode !== "digest" && mode !== "cluster") return base;
  const confirmed = findings.filter((item) => item.pathStatus === "reachable").length;
  return validateAiSecurityAnalysis({
    ...base,
    title: mode === "digest" ? `Daily exposure digest · ${findings.length} findings` : `Security-group pattern review · ${findings.length} findings`,
    executiveSummary: `${findings.length} findings were reviewed; ${confirmed} have a deterministically confirmed reachable path. Highest risk is ${Math.max(...findings.map((item) => item.riskScore))}/100.`,
    whyItMatters: "This fallback preserves deterministic prioritization while Bedrock is unavailable.",
    deterministicVerdict: "Multiple deterministic verdicts; inspect each finding.",
  }, mode);
}

function envelope(row: AnalysisRow, cacheHit: boolean, guardrailConfigured: boolean): AiAnalysisEnvelope {
  return {
    id: row.id,
    cacheHit,
    source: row.source,
    modelId: row.modelId,
    promptVersion: AI_PROMPT_VERSION,
    evidenceHash: row.evidenceHash,
    generatedAt: row.generatedAt,
    expiresAt: row.expiresAt,
    usage: { inputTokens: row.inputTokens, outputTokens: row.outputTokens, latencyMs: row.latencyMs },
    guardrail: { configured: guardrailConfigured, action: row.guardrailAction, traceId: row.guardrailTraceId },
    analysis: validateAiSecurityAnalysis(safeJson(row.resultJson, {}), row.mode),
  };
}

async function usageFor(user: string) {
  const [personal, workspace] = await Promise.all([
    env.DB.prepare(`SELECT requests, input_tokens AS inputTokens, output_tokens AS outputTokens FROM ai_usage_daily WHERE workspace_id = 'default' AND usage_date = date('now') AND actor = ?`).bind(user).first<{ requests: number; inputTokens: number; outputTokens: number }>(),
    env.DB.prepare(`SELECT requests FROM ai_usage_daily WHERE workspace_id = 'default' AND usage_date = date('now') AND actor = '__workspace__'`).first<{ requests: number }>(),
  ]);
  return { personal: personal ?? { requests: 0, inputTokens: 0, outputTokens: 0 }, workspaceRequests: workspace?.requests ?? 0 };
}

async function reserveUsage(user: string) {
  const personal = await env.DB.prepare(`INSERT INTO ai_usage_daily (usage_date, actor, requests) VALUES (date('now'), ?, 1) ON CONFLICT(workspace_id, usage_date, actor) DO UPDATE SET requests = requests + 1, updated_at = CURRENT_TIMESTAMP WHERE requests < ?`).bind(user, dailyUserLimit).run() as { meta: { changes?: unknown } };
  if (Number(personal.meta.changes) !== 1) return false;
  const workspace = await env.DB.prepare(`INSERT INTO ai_usage_daily (usage_date, actor, requests) VALUES (date('now'), '__workspace__', 1) ON CONFLICT(workspace_id, usage_date, actor) DO UPDATE SET requests = requests + 1, updated_at = CURRENT_TIMESTAMP WHERE requests < ?`).bind(dailyWorkspaceLimit).run() as { meta: { changes?: unknown } };
  return Number(workspace.meta.changes) === 1;
}

export async function GET(request: Request) {
  try {
    const user = requestUser(request);
    if (!user) return apiJson({ error: "Authentication is required." }, 401);
    await ensureSchema();
    const url = new URL(request.url);
    const fingerprint = (url.searchParams.get("fingerprint") ?? "").slice(0, 200);
    const mode = (url.searchParams.get("mode") ?? "finding") as AiAnalysisMode;
    const [status, usage] = await Promise.all([bedrockBridgeStatus(), usageFor(user)]);
    if (!fingerprint || !allowedModes.has(mode)) return apiJson({ status, usage, limits: { personal: dailyUserLimit, workspace: dailyWorkspaceLimit }, promptVersion: AI_PROMPT_VERSION, schemaVersion: AI_SCHEMA_VERSION });
    const row = await env.DB.prepare(`SELECT id, fingerprint, mode, evidence_hash AS evidenceHash, source, model_id AS modelId, result_json AS resultJson, input_tokens AS inputTokens, output_tokens AS outputTokens, latency_ms AS latencyMs, guardrail_action AS guardrailAction, guardrail_trace_id AS guardrailTraceId, generated_at AS generatedAt, expires_at AS expiresAt FROM ai_analyses WHERE workspace_id = 'default' AND fingerprint = ? AND mode = ? AND expires_at > datetime('now') ORDER BY generated_at DESC LIMIT 1`).bind(fingerprint, mode).first<AnalysisRow>();
    return apiJson({ status, usage, limits: { personal: dailyUserLimit, workspace: dailyWorkspaceLimit }, analysis: row ? envelope(row, true, status.guardrailConfigured) : null });
  } catch {
    return apiJson({ error: "AI analyst status is temporarily unavailable." }, 503);
  }
}

export async function POST(request: Request) {
  try {
    const permission = await requirePermission(request, "intelligence.write");
    if (!permission.allowed) return apiJson({ error: "Analyst access is required for AI analysis." }, 403);
    if (!sameOrigin(request)) return apiJson({ error: "Origin is not allowed." }, 403);
    await ensureSchema();
    const input = await readBoundedJson(request, MAX_AI_REQUEST_BYTES);
    const action = String(input.action ?? "analyze");
    if (action === "feedback") {
      const analysisId = String(input.analysisId ?? "").slice(0, 100);
      const rating = String(input.rating ?? "");
      const reason = String(input.reason ?? "").replace(/[\u0000-\u001F\u007F]/g, " ").trim().slice(0, 1_000);
      if (!analysisId || !["useful", "incorrect", "incomplete"].includes(rating)) return apiJson({ error: "Choose a valid AI feedback rating." }, 400);
      const exists = await env.DB.prepare(`SELECT id FROM ai_analyses WHERE workspace_id = 'default' AND id = ?`).bind(analysisId).first<{ id: string }>();
      if (!exists) return apiJson({ error: "The AI analysis was not found." }, 404);
      const id = `aif-${(await sha256(`${analysisId}|${permission.user}`)).slice(0, 24)}`;
      await env.DB.prepare(`INSERT INTO ai_feedback (id, analysis_id, rating, reason, actor) VALUES (?, ?, ?, ?, ?) ON CONFLICT(workspace_id, analysis_id, actor) DO UPDATE SET rating = excluded.rating, reason = excluded.reason, created_at = CURRENT_TIMESTAMP`).bind(id, analysisId, rating, reason, permission.user).run();
      await audit(permission.user, "ai.feedback.recorded", "ai_analysis", analysisId, `Recorded ${rating} AI feedback.`, { rating });
      return apiJson({ saved: true });
    }
    const mode = String(input.mode ?? "finding") as AiAnalysisMode;
    if (!allowedModes.has(mode)) return apiJson({ error: "Choose a supported AI analysis mode." }, 400);
    const findings = await canonicalFindings(input.fingerprints ?? input.fingerprint);
    if (findings === null) return apiJson({ error: `Provide between 1 and ${MAX_AI_FINDINGS} finding fingerprints.` }, 400);
    if (!findings.length) return apiJson({ error: "One or more findings are no longer present in the canonical Gatewatch inventory." }, 409);
    const question = String(input.question ?? "").replace(/[\u0000-\u001F\u007F]/g, " ").trim().slice(0, 500);
    if (mode === "hunt" && !question) return apiJson({ error: "Describe the security-group hunt to translate." }, 400);
    const status = await bedrockBridgeStatus();
    const packages = findings.map(buildAiEvidencePackage);
    const evidenceHash = await sha256(JSON.stringify({ mode, packages, question, promptVersion: AI_PROMPT_VERSION, modelId: status.modelId, guardrailVersion: status.guardrailVersion }));
    const cached = await env.DB.prepare(`SELECT id, fingerprint, mode, evidence_hash AS evidenceHash, source, model_id AS modelId, result_json AS resultJson, input_tokens AS inputTokens, output_tokens AS outputTokens, latency_ms AS latencyMs, guardrail_action AS guardrailAction, guardrail_trace_id AS guardrailTraceId, generated_at AS generatedAt, expires_at AS expiresAt FROM ai_analyses WHERE workspace_id = 'default' AND mode = ? AND evidence_hash = ? AND prompt_version = ? AND expires_at > datetime('now') LIMIT 1`).bind(mode, evidenceHash, AI_PROMPT_VERSION).first<AnalysisRow>();
    if (cached) return apiJson({ analysis: envelope(cached, true, status.guardrailConfigured) });
    if (!await reserveUsage(permission.user)) return apiJson({ error: "The daily AI analysis budget is exhausted. Deterministic findings remain available." }, 429);
    const started = Date.now();
    let source: "bedrock" | "deterministic" = "deterministic";
    let modelId = "deterministic-gatewatch";
    let modelUsage = { inputTokens: 0, outputTokens: 0, latencyMs: 0 };
    let guardrail = { configured: status.guardrailConfigured, action: "not-invoked", traceId: "" };
    let analysis: AiSecurityAnalysis;
    try {
      const prompt = buildAiPrompt(mode, packages, question);
      const result = await callBedrockBridge({ mode, ...prompt, schema: aiSecurityAnalysisJsonSchema as unknown as Record<string, unknown> });
      analysis = validateAiSecurityAnalysis(result.analysis, mode);
      const validRefs = new Set(packages.flatMap((item) => item.facts.map((fact) => fact.id)));
      if (analysis.claims.some((claim) => claim.evidenceRefs.some((reference) => !validRefs.has(reference)))) throw new Error("AI_EVIDENCE_REFERENCE_INVALID");
      if (packages.length === 1 && mode !== "hunt" && analysis.deterministicVerdict !== packages[0].deterministic.verdict) throw new Error("AI_DETERMINISTIC_VERDICT_CHANGED");
      source = "bedrock";
      modelId = result.modelId;
      modelUsage = result.usage;
      guardrail = result.guardrail;
    } catch (error) {
      console.warn("Bedrock analysis fell back to deterministic guidance", error instanceof Error ? error.message : "unknown");
      analysis = fallbackFor(mode, findings, question);
      modelUsage.latencyMs = Date.now() - started;
      guardrail.action = "fallback";
    }
    const id = `aia-${evidenceHash.slice(0, 24)}`;
    const fingerprint = mode === "finding" || mode === "remediation" ? findings[0].fingerprint.slice(0, 200) : "";
    const generatedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + (source === "bedrock" ? cacheDays * 86_400_000 : 5 * 60_000)).toISOString();
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO ai_analyses (id, fingerprint, mode, evidence_hash, prompt_version, schema_version, source, model_id, result_json, input_tokens, output_tokens, latency_ms, guardrail_action, guardrail_trace_id, generated_by, generated_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET source = excluded.source, model_id = excluded.model_id, result_json = excluded.result_json, input_tokens = excluded.input_tokens, output_tokens = excluded.output_tokens, latency_ms = excluded.latency_ms, guardrail_action = excluded.guardrail_action, guardrail_trace_id = excluded.guardrail_trace_id, generated_by = excluded.generated_by, generated_at = excluded.generated_at, expires_at = excluded.expires_at`).bind(id, fingerprint, mode, evidenceHash, AI_PROMPT_VERSION, AI_SCHEMA_VERSION, source, modelId, JSON.stringify(analysis), modelUsage.inputTokens, modelUsage.outputTokens, modelUsage.latencyMs, guardrail.action, guardrail.traceId, permission.user, generatedAt, expiresAt),
      env.DB.prepare(`UPDATE ai_usage_daily SET input_tokens = input_tokens + ?, output_tokens = output_tokens + ?, updated_at = CURRENT_TIMESTAMP WHERE workspace_id = 'default' AND usage_date = date('now') AND actor = ?`).bind(modelUsage.inputTokens, modelUsage.outputTokens, permission.user),
    ]);
    await audit(permission.user, "ai.analysis.generated", "ai_analysis", id, `Generated ${mode} analysis using ${source}.`, { fingerprint, source, modelId, evidenceHash: evidenceHash.slice(0, 16), inputTokens: modelUsage.inputTokens, outputTokens: modelUsage.outputTokens, guardrailAction: guardrail.action });
    const row: AnalysisRow = { id, fingerprint, mode, evidenceHash, source, modelId, resultJson: JSON.stringify(analysis), inputTokens: modelUsage.inputTokens, outputTokens: modelUsage.outputTokens, latencyMs: modelUsage.latencyMs, guardrailAction: guardrail.action, guardrailTraceId: guardrail.traceId, generatedAt, expiresAt };
    return apiJson({ analysis: envelope(row, false, guardrail.configured) });
  } catch (error) {
    if (error instanceof HttpInputError) return apiJson({ error: error.message }, error.status);
    console.error("AI analysis request failed", error instanceof Error ? error.name : "UnknownError");
    return apiJson({ error: "AI analysis could not be completed. Deterministic findings remain available." }, 503);
  }
}
