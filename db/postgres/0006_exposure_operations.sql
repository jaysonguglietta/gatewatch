-- Closed-loop exposure verification, correlation, remediation and outcomes.

CREATE TABLE exposure_verification_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  finding_fingerprint text NOT NULL,
  security_group_arn text NOT NULL,
  analyzer text NOT NULL CHECK (analyzer IN ('reachability-analyzer', 'network-access-analyzer')),
  protocol text NOT NULL DEFAULT 'TCP',
  destination_port integer CHECK (destination_port BETWEEN 0 AND 65535),
  status text NOT NULL CHECK (status IN ('queued','running','verified','unreachable','inconclusive','failed')),
  aws_analysis_arn text NOT NULL DEFAULT '',
  result_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  requested_by text NOT NULL,
  requested_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  UNIQUE (workspace_id, id)
);

CREATE TABLE exposure_correlations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  finding_fingerprint text NOT NULL,
  security_group_arn text NOT NULL,
  provider_finding_id text NOT NULL,
  provider text NOT NULL,
  traits jsonb NOT NULL DEFAULT '[]'::jsonb,
  agreements jsonb NOT NULL DEFAULT '[]'::jsonb,
  contradictions jsonb NOT NULL DEFAULT '[]'::jsonb,
  blast_radius jsonb NOT NULL DEFAULT '[]'::jsonb,
  observed_at timestamptz NOT NULL,
  UNIQUE (workspace_id, provider, provider_finding_id)
);

CREATE TABLE exposure_graph_edges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  finding_fingerprint text NOT NULL,
  source_arn text NOT NULL,
  destination_arn text NOT NULL,
  relationship_type text NOT NULL,
  evidence_class text NOT NULL,
  observed boolean NOT NULL DEFAULT false,
  evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
  first_observed_at timestamptz NOT NULL,
  last_observed_at timestamptz NOT NULL,
  UNIQUE (workspace_id, finding_fingerprint, source_arn, destination_arn, relationship_type)
);

CREATE TABLE exposure_remediation_plans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  finding_fingerprint text NOT NULL,
  security_group_arn text NOT NULL,
  mode text NOT NULL CHECK (mode IN ('advisory','pull-request','firewall-manager')),
  status text NOT NULL CHECK (status IN ('draft','simulated','awaiting-approval','approved','executing','verifying','completed','rolled-back','failed')),
  proposed_change jsonb NOT NULL,
  simulation_result jsonb NOT NULL DEFAULT '{}'::jsonb,
  rollback_plan jsonb NOT NULL,
  authored_by text NOT NULL,
  approved_by text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (approved_by IS NULL OR approved_by <> authored_by)
);

CREATE TABLE exposure_owner_actions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  finding_fingerprint text NOT NULL,
  owner_subject text NOT NULL,
  status text NOT NULL CHECK (status IN ('open','accepted','blocked','completed','overdue')),
  due_at timestamptz NOT NULL,
  response_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE exposure_incidents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  source_finding_id text NOT NULL,
  status text NOT NULL CHECK (status IN ('open','investigating','contained','resolved')),
  severity text NOT NULL CHECK (severity IN ('critical','high','medium','low')),
  graph_snapshot jsonb NOT NULL,
  evidence_hold_id uuid,
  owner_subject text NOT NULL,
  opened_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz,
  UNIQUE (workspace_id, source_finding_id)
);

CREATE TABLE exposure_policy_packs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  policy_key text NOT NULL,
  version integer NOT NULL CHECK (version > 0),
  status text NOT NULL CHECK (status IN ('draft','monitor','enforced','disabled')),
  scope_json jsonb NOT NULL,
  policy_json jsonb NOT NULL,
  firewall_manager_policy_arn text NOT NULL DEFAULT '',
  created_by text NOT NULL,
  approved_by text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, policy_key, version),
  CHECK (approved_by IS NULL OR approved_by <> created_by)
);

CREATE TABLE exposure_slo_snapshots (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  measured_at timestamptz NOT NULL,
  scope_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  confirmed_critical_exposure_hours numeric(16,2) NOT NULL CHECK (confirmed_critical_exposure_hours >= 0),
  median_validation_minutes numeric(16,2) NOT NULL CHECK (median_validation_minutes >= 0),
  median_remediation_hours numeric(16,2) NOT NULL CHECK (median_remediation_hours >= 0),
  automatically_reverified_percent numeric(5,2) NOT NULL CHECK (automatically_reverified_percent BETWEEN 0 AND 100),
  reopen_rate_percent numeric(5,2) NOT NULL CHECK (reopen_rate_percent BETWEEN 0 AND 100),
  UNIQUE (workspace_id, measured_at, scope_json)
);

CREATE TABLE exposure_extensions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  extension_key text NOT NULL,
  schema_version text NOT NULL,
  status text NOT NULL CHECK (status IN ('enabled','disabled','error')),
  endpoint_secret_arn text NOT NULL DEFAULT '',
  allowed_enrichment_fields jsonb NOT NULL DEFAULT '[]'::jsonb,
  last_delivery_at timestamptz,
  last_error text NOT NULL DEFAULT '',
  UNIQUE (workspace_id, extension_key)
);

CREATE INDEX exposure_verification_finding_idx ON exposure_verification_runs (workspace_id, finding_fingerprint, requested_at DESC);
CREATE INDEX exposure_correlation_group_idx ON exposure_correlations (workspace_id, security_group_arn, observed_at DESC);
CREATE INDEX exposure_graph_finding_idx ON exposure_graph_edges (workspace_id, finding_fingerprint);
CREATE INDEX exposure_remediation_status_idx ON exposure_remediation_plans (workspace_id, status, updated_at DESC);
CREATE INDEX exposure_owner_due_idx ON exposure_owner_actions (workspace_id, status, due_at);
CREATE INDEX exposure_incident_status_idx ON exposure_incidents (workspace_id, status, severity);
CREATE INDEX exposure_slo_time_idx ON exposure_slo_snapshots (workspace_id, measured_at DESC);

DO $gatewatch$
DECLARE target record;
BEGIN
  FOR target IN
    SELECT unnest(ARRAY[
      'exposure_verification_runs', 'exposure_correlations', 'exposure_graph_edges',
      'exposure_remediation_plans', 'exposure_owner_actions', 'exposure_incidents',
      'exposure_policy_packs', 'exposure_slo_snapshots', 'exposure_extensions'
    ]) AS table_name
  LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', target.table_name);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', target.table_name);
    EXECUTE format(
      'CREATE POLICY workspace_isolation ON public.%I USING (workspace_id = NULLIF(current_setting(''app.workspace_id'', true), '''')::uuid) WITH CHECK (workspace_id = NULLIF(current_setting(''app.workspace_id'', true), '''')::uuid)',
      target.table_name
    );
  END LOOP;
END $gatewatch$;

GRANT SELECT, INSERT, UPDATE ON
  exposure_verification_runs, exposure_correlations, exposure_graph_edges
TO gatewatch_ingest;

GRANT SELECT, INSERT, UPDATE, DELETE ON
  exposure_verification_runs, exposure_correlations, exposure_graph_edges,
  exposure_remediation_plans, exposure_owner_actions, exposure_incidents,
  exposure_policy_packs, exposure_slo_snapshots, exposure_extensions
TO gatewatch_maintenance;

COMMENT ON TABLE exposure_verification_runs IS 'AWS-native reachability verification lifecycle; no client-supplied result is authoritative.';
COMMENT ON TABLE exposure_remediation_plans IS 'Four-eyes remediation workflow with simulation, rollback and post-change verification.';
COMMENT ON TABLE exposure_extensions IS 'Enrichment-only extension registrations; extension data cannot alter deterministic exposure verdicts.';
