-- Security governance controls for the authoritative Aurora data plane.
-- Apply as the migration owner, then connect application workloads with a
-- separately provisioned LOGIN role that is a member of one of the NOLOGIN
-- roles below. Never grant a workload role ownership or BYPASSRLS.

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

-- These ingestion tables were originally tenant-scoped only through source_id.
-- Materialize workspace_id so database policy, indexes, and incident queries do
-- not depend on every join preserving that transitive relationship.
ALTER TABLE ingestion_runs ADD COLUMN IF NOT EXISTS workspace_id uuid;
UPDATE ingestion_runs run
   SET workspace_id = source.workspace_id
  FROM ingestion_sources source
 WHERE run.source_id = source.id AND run.workspace_id IS NULL;
ALTER TABLE ingestion_runs ALTER COLUMN workspace_id SET NOT NULL;

ALTER TABLE ingested_objects ADD COLUMN IF NOT EXISTS workspace_id uuid;
UPDATE ingested_objects object
   SET workspace_id = source.workspace_id
  FROM ingestion_sources source
 WHERE object.source_id = source.id AND object.workspace_id IS NULL;
ALTER TABLE ingested_objects ALTER COLUMN workspace_id SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ingestion_runs_workspace_fk') THEN
    ALTER TABLE ingestion_runs ADD CONSTRAINT ingestion_runs_workspace_fk
      FOREIGN KEY (workspace_id) REFERENCES workspaces(id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ingested_objects_workspace_fk') THEN
    ALTER TABLE ingested_objects ADD CONSTRAINT ingested_objects_workspace_fk
      FOREIGN KEY (workspace_id) REFERENCES workspaces(id);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS ingestion_runs_workspace_started_idx
  ON ingestion_runs (workspace_id, started_at DESC);
CREATE INDEX IF NOT EXISTS ingested_objects_workspace_status_idx
  ON ingested_objects (workspace_id, status, first_seen_at DESC);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gatewatch_app') THEN
    CREATE ROLE gatewatch_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gatewatch_ingest') THEN
    CREATE ROLE gatewatch_ingest NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gatewatch_maintenance') THEN
    CREATE ROLE gatewatch_maintenance NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
END $$;

CREATE TABLE retention_execution_runs (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  status text NOT NULL CHECK (status IN ('running', 'succeeded', 'failed')),
  deleted_counts jsonb NOT NULL DEFAULT '{}',
  error_code text NOT NULL DEFAULT '',
  started_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);
CREATE INDEX retention_execution_runs_workspace_idx
  ON retention_execution_runs (workspace_id, started_at DESC);

CREATE TABLE audit_archive_ledger (
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  audit_event_id uuid NOT NULL REFERENCES audit_events(id) ON DELETE CASCADE,
  archive_bucket text NOT NULL,
  archive_key text NOT NULL,
  archive_version_id text NOT NULL,
  content_sha256 text NOT NULL CHECK (content_sha256 ~ '^[a-f0-9]{64}$'),
  archived_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, audit_event_id)
);

-- FORCE prevents table owners from accidentally bypassing policies. Superusers
-- and BYPASSRLS roles remain prohibited for every workload by deployment policy.
DO $$
DECLARE target record;
BEGIN
  FOR target IN
    SELECT c.relname AS table_name
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_attribute a ON a.attrelid = c.oid
     WHERE n.nspname = 'public'
       AND c.relkind IN ('r', 'p')
       AND a.attname = 'workspace_id'
       AND NOT a.attisdropped
  LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', target.table_name);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', target.table_name);
    EXECUTE format('DROP POLICY IF EXISTS workspace_isolation ON public.%I', target.table_name);
    EXECUTE format(
      'CREATE POLICY workspace_isolation ON public.%I USING (workspace_id = NULLIF(current_setting(''app.workspace_id'', true), '''')::uuid) WITH CHECK (workspace_id = NULLIF(current_setting(''app.workspace_id'', true), '''')::uuid)',
      target.table_name
    );
  END LOOP;
END $$;

CREATE OR REPLACE FUNCTION gatewatch_reject_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF current_setting('app.retention_authorized', true) IS DISTINCT FROM 'true' THEN
    RAISE EXCEPTION 'audit history is append-only' USING ERRCODE = '42501';
  END IF;
  RETURN OLD;
END $$;

DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events;
CREATE TRIGGER audit_events_append_only
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION gatewatch_reject_audit_mutation();

-- One bounded, idempotent purge batch. Workspace-wide holds stop the complete
-- batch. Account and security-group holds preserve matching normalized evidence.
-- Audit rows are eligible only after an Object Lock archive ledger entry exists.
CREATE OR REPLACE FUNCTION gatewatch_apply_retention_batch(
  p_workspace_id uuid,
  p_run_id uuid,
  p_batch_size integer DEFAULT 500
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  policy record;
  removed integer;
  counts jsonb := '{}'::jsonb;
BEGIN
  IF p_batch_size < 1 OR p_batch_size > 5000 THEN
    RAISE EXCEPTION 'retention batch size must be between 1 and 5000';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(p_workspace_id::text, 0));
  PERFORM set_config('app.workspace_id', p_workspace_id::text, true);
  PERFORM set_config('app.retention_authorized', 'true', true);

  INSERT INTO retention_execution_runs (id, workspace_id, status)
  VALUES (p_run_id, p_workspace_id, 'running')
  ON CONFLICT (id) DO NOTHING;

  IF EXISTS (
    SELECT 1 FROM evidence_legal_holds
     WHERE workspace_id = p_workspace_id AND status = 'active'
       AND scope_type = 'workspace'
  ) THEN
    UPDATE retention_execution_runs
       SET status = 'succeeded', deleted_counts = '{"held":true}', completed_at = now()
     WHERE id = p_run_id AND workspace_id = p_workspace_id;
    RETURN '{"held":true,"deleted":0}'::jsonb;
  END IF;

  SELECT * INTO policy FROM evidence_retention_policies
   WHERE workspace_id = p_workspace_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'retention policy is required before enforcement';
  END IF;

  WITH doomed AS (
    SELECT event.tableoid, event.ctid
      FROM cloudtrail_events event
     WHERE event.workspace_id = p_workspace_id
       AND event.event_time < now() - make_interval(days => policy.normalized_evidence_days)
       AND NOT EXISTS (
         SELECT 1 FROM evidence_legal_holds hold
          WHERE hold.workspace_id = p_workspace_id AND hold.status = 'active'
            AND ((hold.scope_type = 'account' AND hold.scope_value = event.account_id)
              OR (hold.scope_type = 'security-group' AND hold.scope_value LIKE '%' || event.security_group_id))
       )
     LIMIT p_batch_size
  )
  DELETE FROM cloudtrail_events event USING doomed
   WHERE event.tableoid = doomed.tableoid AND event.ctid = doomed.ctid;
  GET DIAGNOSTICS removed = ROW_COUNT;
  counts := counts || jsonb_build_object('cloudtrail_events', removed);

  WITH doomed AS (
    SELECT item.tableoid, item.ctid
      FROM config_items item
     WHERE item.workspace_id = p_workspace_id
       AND item.capture_time < now() - make_interval(days => policy.normalized_evidence_days)
       AND NOT EXISTS (
         SELECT 1 FROM evidence_legal_holds hold
          WHERE hold.workspace_id = p_workspace_id AND hold.status = 'active'
            AND ((hold.scope_type = 'account' AND hold.scope_value = item.account_id)
              OR (hold.scope_type = 'security-group' AND hold.scope_value LIKE '%' || item.resource_id))
       )
     LIMIT p_batch_size
  )
  DELETE FROM config_items item USING doomed
   WHERE item.tableoid = doomed.tableoid AND item.ctid = doomed.ctid;
  GET DIAGNOSTICS removed = ROW_COUNT;
  counts := counts || jsonb_build_object('config_items', removed);

  WITH doomed AS (
    SELECT evidence.ctid
      FROM aws_evidence_records evidence
     WHERE evidence.workspace_id = p_workspace_id
       AND evidence.observed_at < now() - make_interval(days => policy.normalized_evidence_days)
       AND NOT EXISTS (
         SELECT 1 FROM evidence_legal_holds hold
          WHERE hold.workspace_id = p_workspace_id AND hold.status = 'active'
            AND hold.scope_type = 'account' AND hold.scope_value = evidence.account_id
       )
     LIMIT p_batch_size
  )
  DELETE FROM aws_evidence_records evidence USING doomed WHERE evidence.ctid = doomed.ctid;
  GET DIAGNOSTICS removed = ROW_COUNT;
  counts := counts || jsonb_build_object('aws_evidence_records', removed);

  WITH doomed AS (
    SELECT event.ctid
      FROM semantic_evidence_events event
     WHERE event.workspace_id = p_workspace_id
       AND event.observed_at < now() - make_interval(days => policy.normalized_evidence_days)
       AND NOT EXISTS (
         SELECT 1 FROM evidence_legal_holds hold
          WHERE hold.workspace_id = p_workspace_id AND hold.status = 'active'
            AND ((hold.scope_type = 'account' AND hold.scope_value = event.account_id)
              OR (hold.scope_type = 'security-group' AND hold.scope_value = event.security_group_arn))
       )
     LIMIT p_batch_size
  )
  DELETE FROM semantic_evidence_events event USING doomed WHERE event.ctid = doomed.ctid;
  GET DIAGNOSTICS removed = ROW_COUNT;
  counts := counts || jsonb_build_object('semantic_evidence_events', removed);

  WITH doomed AS (
    SELECT rule.tableoid, rule.ctid
      FROM security_group_rule_observations rule
     WHERE rule.workspace_id = p_workspace_id
       AND rule.observed_at < now() - make_interval(days => policy.normalized_evidence_days)
       AND NOT EXISTS (
         SELECT 1 FROM evidence_legal_holds hold
          WHERE hold.workspace_id = p_workspace_id AND hold.status = 'active'
            AND ((hold.scope_type = 'account' AND hold.scope_value = rule.account_id)
              OR (hold.scope_type = 'security-group' AND hold.scope_value LIKE '%' || rule.security_group_id))
       )
     LIMIT p_batch_size
  )
  DELETE FROM security_group_rule_observations rule USING doomed
   WHERE rule.tableoid = doomed.tableoid AND rule.ctid = doomed.ctid;
  GET DIAGNOSTICS removed = ROW_COUNT;
  counts := counts || jsonb_build_object('security_group_rule_observations', removed);

  WITH doomed AS (
    SELECT observation.tableoid, observation.ctid
      FROM security_group_observations observation
     WHERE observation.workspace_id = p_workspace_id
       AND observation.observed_at < now() - make_interval(days => policy.normalized_evidence_days)
       AND NOT EXISTS (
         SELECT 1 FROM evidence_legal_holds hold
          WHERE hold.workspace_id = p_workspace_id AND hold.status = 'active'
            AND ((hold.scope_type = 'account' AND hold.scope_value = observation.account_id)
              OR (hold.scope_type = 'security-group' AND hold.scope_value LIKE '%' || observation.security_group_id))
       )
     LIMIT p_batch_size
  )
  DELETE FROM security_group_observations observation USING doomed
   WHERE observation.tableoid = doomed.tableoid AND observation.ctid = doomed.ctid;
  GET DIAGNOSTICS removed = ROW_COUNT;
  counts := counts || jsonb_build_object('security_group_observations', removed);

  WITH doomed AS (
    SELECT object.tableoid, object.ctid
      FROM inventory_shard_objects object
     WHERE object.workspace_id = p_workspace_id
       AND object.first_seen_at < now() - make_interval(days => policy.raw_evidence_days)
       AND NOT EXISTS (
         SELECT 1 FROM evidence_legal_holds hold
          WHERE hold.workspace_id = p_workspace_id AND hold.status = 'active'
            AND hold.scope_type = 'account' AND hold.scope_value = object.account_id
       )
     LIMIT p_batch_size
  )
  DELETE FROM inventory_shard_objects object USING doomed
   WHERE object.tableoid = doomed.tableoid AND object.ctid = doomed.ctid;
  GET DIAGNOSTICS removed = ROW_COUNT;
  counts := counts || jsonb_build_object('inventory_shard_objects', removed);

  WITH doomed AS (
    SELECT object.tableoid, object.ctid
      FROM ingested_objects object
     WHERE object.workspace_id = p_workspace_id
       AND object.first_seen_at < now() - make_interval(days => policy.raw_evidence_days)
       AND NOT EXISTS (SELECT 1 FROM cloudtrail_events event WHERE event.raw_object_id = object.id)
       AND NOT EXISTS (SELECT 1 FROM config_items item WHERE item.raw_object_id = object.id)
       AND NOT EXISTS (SELECT 1 FROM aws_evidence_records evidence WHERE evidence.raw_object_id = object.id)
     LIMIT p_batch_size
  )
  DELETE FROM ingested_objects object USING doomed
   WHERE object.tableoid = doomed.tableoid AND object.ctid = doomed.ctid;
  GET DIAGNOSTICS removed = ROW_COUNT;
  counts := counts || jsonb_build_object('ingested_objects', removed);

  WITH doomed AS (
    SELECT event.ctid
      FROM audit_events event
      JOIN audit_archive_ledger archive
        ON archive.workspace_id = event.workspace_id AND archive.audit_event_id = event.id
     WHERE event.workspace_id = p_workspace_id
       AND event.created_at < now() - make_interval(days => policy.audit_days)
     LIMIT p_batch_size
  )
  DELETE FROM audit_events event USING doomed WHERE event.ctid = doomed.ctid;
  GET DIAGNOSTICS removed = ROW_COUNT;
  counts := counts || jsonb_build_object('audit_events', removed);

  WITH doomed AS (
    SELECT job.ctid
      FROM evidence_export_jobs job
     WHERE job.workspace_id = p_workspace_id
       AND job.created_at < now() - make_interval(days => policy.export_days)
       AND NOT EXISTS (
         SELECT 1 FROM evidence_legal_holds hold
          WHERE hold.workspace_id = p_workspace_id AND hold.status = 'active'
            AND hold.scope_type = 'export' AND hold.scope_value = job.id::text
       )
     LIMIT p_batch_size
  )
  DELETE FROM evidence_export_jobs job USING doomed WHERE job.ctid = doomed.ctid;
  GET DIAGNOSTICS removed = ROW_COUNT;
  counts := counts || jsonb_build_object('evidence_export_jobs', removed);

  UPDATE retention_execution_runs
     SET status = 'succeeded', deleted_counts = counts, completed_at = now()
   WHERE id = p_run_id AND workspace_id = p_workspace_id;
  RETURN counts;
EXCEPTION WHEN OTHERS THEN
  UPDATE retention_execution_runs
     SET status = 'failed', error_code = left(SQLSTATE || ':' || SQLERRM, 500), completed_at = now()
   WHERE id = p_run_id AND workspace_id = p_workspace_id;
  RAISE;
END $$;

GRANT USAGE ON SCHEMA public TO gatewatch_app, gatewatch_ingest, gatewatch_maintenance;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM gatewatch_app, gatewatch_ingest, gatewatch_maintenance;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM gatewatch_app, gatewatch_ingest, gatewatch_maintenance;
GRANT SELECT, UPDATE ON ingestion_sources TO gatewatch_ingest;
GRANT SELECT, INSERT, UPDATE ON
  ingestion_runs,
  ingested_objects,
  organization_collection_runs,
  organization_collection_targets,
  inventory_shard_objects,
  security_group_observations,
  security_group_rule_observations,
  cloudtrail_events,
  config_items,
  aws_evidence_records,
  aws_resources,
  security_group_rule_versions,
  findings
TO gatewatch_ingest;
GRANT SELECT ON audit_events, audit_archive_ledger, evidence_retention_policies,
  evidence_legal_holds, retention_execution_runs TO gatewatch_maintenance;
GRANT INSERT, UPDATE ON retention_execution_runs, audit_archive_ledger TO gatewatch_maintenance;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO gatewatch_ingest;
GRANT EXECUTE ON FUNCTION gatewatch_apply_security_group_config(uuid, text, text, text, timestamptz, text, text, jsonb) TO gatewatch_ingest;
GRANT EXECUTE ON FUNCTION gatewatch_correlate_cloudtrail_event(uuid, text, timestamptz) TO gatewatch_ingest;
REVOKE ALL ON FUNCTION gatewatch_apply_retention_batch(uuid, uuid, integer) FROM PUBLIC, gatewatch_app, gatewatch_ingest;
GRANT EXECUTE ON FUNCTION gatewatch_apply_retention_batch(uuid, uuid, integer) TO gatewatch_maintenance;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM gatewatch_app, gatewatch_ingest, gatewatch_maintenance;

ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM PUBLIC;
