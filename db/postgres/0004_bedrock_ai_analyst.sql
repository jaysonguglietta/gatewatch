CREATE TABLE IF NOT EXISTS ai_analyses (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL DEFAULT 'default',
  fingerprint TEXT NOT NULL DEFAULT '',
  mode TEXT NOT NULL CHECK (mode IN ('finding', 'hunt', 'digest', 'cluster', 'remediation')),
  evidence_hash TEXT NOT NULL,
  prompt_version TEXT NOT NULL,
  schema_version TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('bedrock', 'deterministic')),
  model_id TEXT NOT NULL DEFAULT '',
  result_json JSONB NOT NULL,
  input_tokens INTEGER NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
  output_tokens INTEGER NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
  latency_ms INTEGER NOT NULL DEFAULT 0 CHECK (latency_ms >= 0),
  guardrail_action TEXT NOT NULL DEFAULT '',
  guardrail_trace_id TEXT NOT NULL DEFAULT '',
  generated_by TEXT NOT NULL,
  generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ai_analyses_cache_idx ON ai_analyses (workspace_id, mode, evidence_hash, prompt_version);
CREATE INDEX IF NOT EXISTS ai_analyses_finding_idx ON ai_analyses (workspace_id, fingerprint, generated_at DESC);

CREATE TABLE IF NOT EXISTS ai_feedback (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL DEFAULT 'default',
  analysis_id TEXT NOT NULL REFERENCES ai_analyses(id) ON DELETE CASCADE,
  rating TEXT NOT NULL CHECK (rating IN ('useful', 'incorrect', 'incomplete')),
  reason TEXT NOT NULL DEFAULT '',
  actor TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, analysis_id, actor)
);

CREATE TABLE IF NOT EXISTS ai_usage_daily (
  workspace_id TEXT NOT NULL DEFAULT 'default',
  usage_date DATE NOT NULL,
  actor TEXT NOT NULL,
  requests INTEGER NOT NULL DEFAULT 0 CHECK (requests >= 0),
  input_tokens BIGINT NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
  output_tokens BIGINT NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (workspace_id, usage_date, actor)
);
