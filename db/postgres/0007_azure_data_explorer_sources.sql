-- Azure Data Explorer source metadata and durable polling checkpoints.
-- Microsoft Entra client secrets remain in AWS Secrets Manager and are never
-- persisted in PostgreSQL.

ALTER TABLE ingestion_sources
  ADD COLUMN IF NOT EXISTS provider text NOT NULL DEFAULT 'aws-s3',
  ADD COLUMN IF NOT EXISTS adx_cluster_url text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS adx_database text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS adx_table text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS adx_timestamp_column text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS adx_payload_column text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS adx_query_mode text NOT NULL DEFAULT 'whole-row',
  ADD COLUMN IF NOT EXISTS adx_batch_size integer NOT NULL DEFAULT 500,
  ADD COLUMN IF NOT EXISTS adx_tenant_id text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS adx_client_id text NOT NULL DEFAULT '';

ALTER TABLE ingestion_sources
  DROP CONSTRAINT IF EXISTS ingestion_sources_source_type_check;

ALTER TABLE ingestion_sources
  ADD CONSTRAINT ingestion_sources_source_type_check CHECK (source_type IN (
    'cloudtrail', 'config-history', 'config-snapshot', 'vpc-flow-logs',
    'transit-gateway-flow-logs', 'reachability-analyzer',
    'network-access-analyzer', 'elastic-load-balancing', 'waf', 'cloudfront',
    'api-gateway', 'route53-resolver', 'network-firewall', 'guardduty',
    'security-hub', 'inspector'
  )),
  ADD CONSTRAINT ingestion_sources_provider_check CHECK (provider IN ('aws-s3', 'azure-data-explorer')),
  ADD CONSTRAINT ingestion_sources_adx_query_mode_check CHECK (adx_query_mode IN ('whole-row', 'payload-column')),
  ADD CONSTRAINT ingestion_sources_adx_batch_size_check CHECK (adx_batch_size BETWEEN 10 AND 1000),
  ADD CONSTRAINT ingestion_sources_provider_fields_check CHECK (
    (provider = 'aws-s3' AND bucket_arn <> '' AND bucket_name <> '' AND role_arn <> '')
    OR
    (provider = 'azure-data-explorer' AND adx_cluster_url <> '' AND adx_database <> ''
      AND adx_table <> '' AND adx_timestamp_column <> '' AND adx_tenant_id <> ''
      AND adx_client_id <> '' AND (adx_query_mode <> 'payload-column' OR adx_payload_column <> ''))
  );

CREATE INDEX IF NOT EXISTS ingestion_sources_provider_status_idx
  ON ingestion_sources (workspace_id, provider, status, updated_at DESC);

CREATE TABLE ingestion_source_checkpoints (
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  source_id uuid NOT NULL REFERENCES ingestion_sources(id) ON DELETE CASCADE,
  checkpoint_time timestamptz NOT NULL,
  cursor_tiebreaker text NOT NULL DEFAULT '',
  lease_owner text NOT NULL DEFAULT '',
  lease_expires_at timestamptz,
  last_row_count integer NOT NULL DEFAULT 0 CHECK (last_row_count >= 0),
  last_success_at timestamptz,
  last_error_code text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, source_id)
);

CREATE INDEX ingestion_source_checkpoints_due_idx
  ON ingestion_source_checkpoints (workspace_id, lease_expires_at, updated_at);

ALTER TABLE ingestion_source_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE ingestion_source_checkpoints FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_isolation ON ingestion_source_checkpoints
  USING (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid)
  WITH CHECK (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE ON ingestion_source_checkpoints TO gatewatch_ingest;
GRANT SELECT, INSERT, UPDATE, DELETE ON ingestion_source_checkpoints TO gatewatch_maintenance;
