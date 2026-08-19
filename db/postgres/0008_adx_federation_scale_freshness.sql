-- Secretless ADX federation, schema validation, distributed worker leases, and
-- source freshness alerts. Existing ADX sources remain on the legacy credential
-- mode until an administrator explicitly converts and retests them.

ALTER TABLE ingestion_sources
  ADD COLUMN IF NOT EXISTS adx_auth_mode text NOT NULL DEFAULT 'client-secret',
  ADD COLUMN IF NOT EXISTS adx_schema jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS adx_schema_discovered_at timestamptz,
  ADD COLUMN IF NOT EXISTS adx_mapping_validated_at timestamptz,
  ADD COLUMN IF NOT EXISTS freshness_sla_minutes integer NOT NULL DEFAULT 30,
  ADD COLUMN IF NOT EXISTS freshness_status text NOT NULL DEFAULT 'unknown',
  ADD COLUMN IF NOT EXISTS freshness_checked_at timestamptz,
  ADD COLUMN IF NOT EXISTS freshness_lag_minutes integer NOT NULL DEFAULT 0;

ALTER TABLE ingestion_sources
  ALTER COLUMN adx_auth_mode SET DEFAULT 'federated',
  ADD CONSTRAINT ingestion_sources_adx_auth_mode_check
    CHECK (adx_auth_mode IN ('federated', 'client-secret')),
  ADD CONSTRAINT ingestion_sources_freshness_sla_check
    CHECK (freshness_sla_minutes BETWEEN 5 AND 10080),
  ADD CONSTRAINT ingestion_sources_freshness_status_check
    CHECK (freshness_status IN ('unknown', 'healthy', 'warning', 'breached')),
  ADD CONSTRAINT ingestion_sources_freshness_lag_check
    CHECK (freshness_lag_minutes >= 0);

CREATE TABLE ingestion_source_alerts (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  source_id uuid NOT NULL REFERENCES ingestion_sources(id) ON DELETE CASCADE,
  alert_type text NOT NULL CHECK (alert_type IN ('freshness-breach')),
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
  severity text NOT NULL DEFAULT 'high' CHECK (severity IN ('critical', 'high', 'medium', 'low')),
  summary text NOT NULL,
  first_observed_at timestamptz NOT NULL DEFAULT now(),
  last_observed_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz,
  UNIQUE (workspace_id, source_id, alert_type)
);

CREATE INDEX ingestion_source_alerts_status_idx
  ON ingestion_source_alerts (workspace_id, status, last_observed_at DESC);

ALTER TABLE ingestion_source_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ingestion_source_alerts FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_isolation ON ingestion_source_alerts
  USING (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid)
  WITH CHECK (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE ON ingestion_source_alerts TO gatewatch_ingest;
GRANT SELECT, INSERT, UPDATE, DELETE ON ingestion_source_alerts TO gatewatch_maintenance;
