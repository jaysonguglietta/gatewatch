-- Organization-scale operating model. Raw evidence remains in customer-owned S3;
-- these tables hold searchable business context, analyst decisions, schedules,
-- export lineage, and governance controls.

CREATE TABLE aws_account_catalog (
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  account_id text NOT NULL CHECK (account_id ~ '^\d{12}$'),
  account_name text NOT NULL,
  organizational_unit text NOT NULL DEFAULT 'Unassigned',
  environment text NOT NULL DEFAULT 'Shared',
  business_unit text NOT NULL DEFAULT 'Unassigned',
  owner text NOT NULL DEFAULT 'Unassigned',
  tags jsonb NOT NULL DEFAULT '{}',
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'closed')),
  last_seen_at timestamptz,
  updated_by text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, account_id)
);
CREATE INDEX aws_account_catalog_context_idx ON aws_account_catalog (workspace_id, organizational_unit, environment, business_unit);

CREATE TABLE evidence_correlation_mappings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  source_identifier text NOT NULL,
  security_group_arn text NOT NULL,
  confidence smallint NOT NULL CHECK (confidence BETWEEN 1 AND 100),
  reason text NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'superseded')),
  created_by text NOT NULL,
  revoked_by text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX evidence_correlation_active_source_idx ON evidence_correlation_mappings (workspace_id, source_identifier) WHERE status = 'active';
CREATE INDEX evidence_correlation_group_idx ON evidence_correlation_mappings (workspace_id, security_group_arn, status);

CREATE TABLE evidence_monitors (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  name text NOT NULL,
  query text NOT NULL DEFAULT '',
  filters jsonb NOT NULL DEFAULT '{}',
  group_by text NOT NULL DEFAULT 'account',
  schedule text NOT NULL CHECK (schedule IN ('hourly', 'daily', 'weekly')),
  trigger_mode text NOT NULL CHECK (trigger_mode IN ('enters', 'leaves', 'severity-change', 'coverage-gap', 'recurrence')),
  destinations jsonb NOT NULL DEFAULT '[]',
  visibility text NOT NULL DEFAULT 'personal' CHECK (visibility IN ('personal', 'team')),
  owner text NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused')),
  last_run_at timestamptz,
  next_run_at timestamptz,
  last_match_count integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX evidence_monitors_schedule_idx ON evidence_monitors (workspace_id, status, next_run_at);

CREATE TABLE evidence_monitor_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  monitor_id uuid NOT NULL REFERENCES evidence_monitors(id) ON DELETE CASCADE,
  status text NOT NULL CHECK (status IN ('running', 'complete', 'failed')),
  match_count integer NOT NULL DEFAULT 0,
  entered_count integer NOT NULL DEFAULT 0,
  exited_count integer NOT NULL DEFAULT 0,
  summary jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX evidence_monitor_runs_monitor_idx ON evidence_monitor_runs (workspace_id, monitor_id, created_at DESC);

CREATE TABLE evidence_export_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  name text NOT NULL,
  format text NOT NULL CHECK (format IN ('csv', 'json', 'evidence-package', 'parquet')),
  scope jsonb NOT NULL DEFAULT '{}',
  schedule text NOT NULL DEFAULT 'once' CHECK (schedule IN ('once', 'daily', 'weekly', 'monthly')),
  status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'complete', 'failed')),
  row_count integer NOT NULL DEFAULT 0,
  checksum text NOT NULL DEFAULT '',
  storage_key text NOT NULL DEFAULT '',
  requested_by text NOT NULL,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);
CREATE INDEX evidence_export_jobs_queue_idx ON evidence_export_jobs (workspace_id, status, created_at);

CREATE TABLE evidence_retention_policies (
  workspace_id uuid PRIMARY KEY REFERENCES workspaces(id),
  raw_evidence_days integer NOT NULL DEFAULT 400 CHECK (raw_evidence_days BETWEEN 7 AND 3650),
  normalized_evidence_days integer NOT NULL DEFAULT 365 CHECK (normalized_evidence_days BETWEEN 7 AND 3650),
  audit_days integer NOT NULL DEFAULT 2555 CHECK (audit_days BETWEEN 7 AND 3650),
  export_days integer NOT NULL DEFAULT 30 CHECK (export_days BETWEEN 7 AND 3650),
  updated_by text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE evidence_legal_holds (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  name text NOT NULL,
  scope_type text NOT NULL CHECK (scope_type IN ('workspace', 'account', 'security-group', 'finding', 'export')),
  scope_value text NOT NULL,
  reason text NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'released')),
  requested_by text NOT NULL,
  released_by text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  released_at timestamptz
);
CREATE INDEX evidence_legal_holds_status_idx ON evidence_legal_holds (workspace_id, status, created_at);

CREATE TABLE risk_score_policies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  name text NOT NULL,
  status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'retired')),
  weights jsonb NOT NULL DEFAULT '{}',
  thresholds jsonb NOT NULL DEFAULT '{}',
  created_by text NOT NULL,
  updated_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX risk_score_policy_active_idx ON risk_score_policies (workspace_id) WHERE status = 'active';

CREATE TABLE semantic_evidence_events (
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  fingerprint text NOT NULL,
  canonical_event_id text NOT NULL,
  provider_id text NOT NULL DEFAULT '',
  source_type text NOT NULL,
  security_group_arn text NOT NULL,
  observed_at timestamptz NOT NULL,
  provenance jsonb NOT NULL DEFAULT '[]',
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, fingerprint)
);
CREATE INDEX semantic_evidence_canonical_idx ON semantic_evidence_events (workspace_id, canonical_event_id);
CREATE INDEX semantic_evidence_group_time_idx ON semantic_evidence_events (workspace_id, security_group_arn, observed_at DESC);

ALTER TABLE aws_account_catalog ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_correlation_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_monitors ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_monitor_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_export_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_retention_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_legal_holds ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_score_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE semantic_evidence_events ENABLE ROW LEVEL SECURITY;

-- Application roles must set app.workspace_id on every transaction. These
-- policies make a missed workspace predicate fail closed in Aurora.
DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'aws_account_catalog', 'evidence_correlation_mappings', 'evidence_monitors',
    'evidence_monitor_runs', 'evidence_export_jobs', 'evidence_retention_policies',
    'evidence_legal_holds', 'risk_score_policies', 'semantic_evidence_events'
  ] LOOP
    EXECUTE format('CREATE POLICY workspace_isolation ON %I USING (workspace_id = current_setting(''app.workspace_id'', true)::uuid) WITH CHECK (workspace_id = current_setting(''app.workspace_id'', true)::uuid)', table_name);
  END LOOP;
END $$;
