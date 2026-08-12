-- Indexed search support for the organization-scale Daily Findings workspace.
-- The application query parser remains bounded and parameterized; these indexes
-- keep identity, queue, temporal, and free-text predicates interactive as the
-- normalized Aurora dataset grows.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS findings_workspace_priority_idx
  ON findings (workspace_id, status, severity, risk_score DESC, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS findings_workspace_changed_idx
  ON findings (workspace_id, last_seen_at DESC, first_seen_at DESC);

CREATE INDEX IF NOT EXISTS findings_title_trgm_idx
  ON findings USING gin (title gin_trgm_ops);

CREATE INDEX IF NOT EXISTS findings_evidence_gin_idx
  ON findings USING gin (evidence jsonb_path_ops);

CREATE INDEX IF NOT EXISTS aws_resources_name_trgm_idx
  ON aws_resources USING gin (name gin_trgm_ops)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS aws_resources_tags_gin_idx
  ON aws_resources USING gin (tags jsonb_path_ops)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS aws_evidence_universal_search_idx
  ON aws_evidence_records
  (workspace_id, observed_at DESC, account_id, region, resource_id);

CREATE INDEX IF NOT EXISTS finding_observations_temporal_idx
  ON finding_observations
  (workspace_id, state, last_seen_at DESC, observation_count DESC);
