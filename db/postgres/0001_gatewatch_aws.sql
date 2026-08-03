-- Gatewatch AWS production schema (Aurora PostgreSQL 15+).
-- Raw CloudTrail and Config objects remain in S3. This schema stores normalized
-- records, current state, evidence lineage, and administration workflows.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE workspaces (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug text NOT NULL UNIQUE,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE ingestion_sources (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  name text NOT NULL,
  source_type text NOT NULL CHECK (source_type IN ('cloudtrail', 'config-history', 'config-snapshot')),
  bucket_arn text NOT NULL,
  bucket_name text NOT NULL,
  region text NOT NULL,
  object_prefix text NOT NULL DEFAULT '',
  role_arn text NOT NULL,
  external_id text NOT NULL,
  kms_key_arn text,
  organization_id text,
  ingestion_mode text NOT NULL CHECK (ingestion_mode IN ('continuous', 'backfill', 'both')),
  backfill_start date,
  included_accounts jsonb NOT NULL DEFAULT '[]',
  excluded_accounts jsonb NOT NULL DEFAULT '[]',
  included_regions jsonb NOT NULL DEFAULT '[]',
  config_resource_types jsonb NOT NULL DEFAULT '[]',
  retention_days integer NOT NULL DEFAULT 365 CHECK (retention_days BETWEEN 30 AND 3650),
  status text NOT NULL DEFAULT 'draft',
  test_summary jsonb NOT NULL DEFAULT '{}',
  last_tested_at timestamptz,
  last_successful_object_at timestamptz,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, name)
);

CREATE INDEX ingestion_sources_bucket_prefix_idx
  ON ingestion_sources (bucket_name, object_prefix);

CREATE TABLE ingestion_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id uuid NOT NULL REFERENCES ingestion_sources(id),
  run_type text NOT NULL CHECK (run_type IN ('continuous', 'backfill', 'retry', 'reconcile')),
  status text NOT NULL,
  discovered_objects bigint NOT NULL DEFAULT 0,
  processed_objects bigint NOT NULL DEFAULT 0,
  failed_objects bigint NOT NULL DEFAULT 0,
  parsed_records bigint NOT NULL DEFAULT 0,
  finding_changes bigint NOT NULL DEFAULT 0,
  cursor text,
  error_summary text,
  requested_by text NOT NULL,
  started_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);

CREATE INDEX ingestion_runs_source_started_idx
  ON ingestion_runs (source_id, started_at DESC);

CREATE TABLE ingested_objects (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id uuid NOT NULL REFERENCES ingestion_sources(id),
  bucket_name text NOT NULL,
  object_key text NOT NULL,
  version_id text NOT NULL DEFAULT '',
  etag text NOT NULL DEFAULT '',
  status text NOT NULL,
  object_size bigint NOT NULL DEFAULT 0,
  record_count integer NOT NULL DEFAULT 0,
  checksum_sha256 text,
  failure_code text,
  failure_detail text,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  processed_at timestamptz,
  UNIQUE (source_id, object_key, version_id)
);

CREATE INDEX ingested_objects_source_status_idx
  ON ingested_objects (source_id, status);

-- Organization collector state. Raw immutable shards remain authoritative in
-- S3; these tables make current inventory, run health, and coverage queryable
-- without loading an organization-wide snapshot into an application process.
CREATE TABLE organization_collection_runs (
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  run_id uuid NOT NULL,
  status text NOT NULL CHECK (status IN ('running', 'succeeded', 'partial', 'failed')),
  manifest_bucket text NOT NULL,
  manifest_key text NOT NULL,
  manifest_checksum_sha256 text NOT NULL DEFAULT '',
  accounts_expected integer NOT NULL DEFAULT 0,
  accounts_succeeded integer NOT NULL DEFAULT 0,
  accounts_partial integer NOT NULL DEFAULT 0,
  accounts_failed integer NOT NULL DEFAULT 0,
  accounts_incomplete integer NOT NULL DEFAULT 0,
  regions_expected integer NOT NULL DEFAULT 0,
  regions_succeeded integer NOT NULL DEFAULT 0,
  regions_failed integer NOT NULL DEFAULT 0,
  regions_incomplete integer NOT NULL DEFAULT 0,
  security_group_count integer NOT NULL DEFAULT 0,
  security_group_rule_count integer NOT NULL DEFAULT 0,
  coverage_percent numeric(5,2) NOT NULL DEFAULT 0,
  started_at timestamptz NOT NULL,
  completed_at timestamptz,
  ingested_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, run_id)
);

CREATE INDEX organization_collection_runs_latest_idx
  ON organization_collection_runs (workspace_id, completed_at DESC);

CREATE TABLE organization_collection_targets (
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  run_id uuid NOT NULL,
  account_id text NOT NULL,
  account_name text NOT NULL,
  region text NOT NULL,
  status text NOT NULL CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'incomplete')),
  object_key text NOT NULL DEFAULT '',
  checksum_sha256 text NOT NULL DEFAULT '',
  security_group_count integer NOT NULL DEFAULT 0,
  security_group_rule_count integer NOT NULL DEFAULT 0,
  network_interface_count integer NOT NULL DEFAULT 0,
  error_code text NOT NULL DEFAULT '',
  completed_at timestamptz,
  PRIMARY KEY (workspace_id, run_id, account_id, region),
  FOREIGN KEY (workspace_id, run_id)
    REFERENCES organization_collection_runs(workspace_id, run_id)
    DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX organization_collection_targets_health_idx
  ON organization_collection_targets (workspace_id, status, account_id, region);

CREATE TABLE inventory_shard_objects (
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  run_id uuid NOT NULL,
  account_id text NOT NULL,
  region text NOT NULL,
  bucket_name text NOT NULL,
  object_key text NOT NULL,
  version_id text NOT NULL DEFAULT '',
  etag text NOT NULL DEFAULT '',
  checksum_sha256 text NOT NULL,
  object_size bigint NOT NULL,
  status text NOT NULL CHECK (status IN ('processing', 'processed', 'failed')),
  failure_code text NOT NULL DEFAULT '',
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  processed_at timestamptz,
  PRIMARY KEY (workspace_id, bucket_name, object_key, version_id)
);

CREATE INDEX inventory_shard_objects_run_status_idx
  ON inventory_shard_objects (workspace_id, run_id, status);

CREATE TABLE security_group_observations (
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  run_id uuid NOT NULL,
  account_id text NOT NULL,
  account_name text NOT NULL,
  region text NOT NULL,
  security_group_id text NOT NULL,
  name text,
  description text,
  vpc_id text,
  is_default boolean NOT NULL DEFAULT false,
  tags jsonb NOT NULL DEFAULT '{}',
  inbound_rule_count integer NOT NULL DEFAULT 0,
  outbound_rule_count integer NOT NULL DEFAULT 0,
  public_ingress_rule_count integer NOT NULL DEFAULT 0,
  public_egress_rule_count integer NOT NULL DEFAULT 0,
  attachment_count integer NOT NULL DEFAULT 0,
  attachments jsonb NOT NULL DEFAULT '[]',
  network_evidence jsonb NOT NULL DEFAULT '{}',
  observed_at timestamptz NOT NULL,
  source_object_key text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (
    workspace_id, run_id, account_id, region, security_group_id
  )
);

CREATE INDEX security_group_observations_resource_latest_idx
  ON security_group_observations
  (workspace_id, account_id, region, security_group_id, observed_at DESC);

CREATE INDEX security_group_observations_public_ingress_idx
  ON security_group_observations
  (workspace_id, public_ingress_rule_count DESC, attachment_count DESC)
  WHERE public_ingress_rule_count > 0;

CREATE TABLE security_group_rule_observations (
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  run_id uuid NOT NULL,
  account_id text NOT NULL,
  region text NOT NULL,
  security_group_id text NOT NULL,
  rule_id text NOT NULL,
  direction text NOT NULL CHECK (direction IN ('Ingress', 'Egress')),
  protocol text NOT NULL,
  from_port integer,
  to_port integer,
  peer text NOT NULL,
  peer_type text NOT NULL,
  description text,
  internet_wide boolean NOT NULL DEFAULT false,
  observed_at timestamptz NOT NULL,
  PRIMARY KEY (
    workspace_id, run_id, account_id, region, security_group_id, rule_id
  )
);

CREATE INDEX security_group_rule_observations_broad_latest_idx
  ON security_group_rule_observations
  (workspace_id, internet_wide, direction, observed_at DESC)
  WHERE internet_wide = true;

CREATE VIEW current_security_groups AS
SELECT DISTINCT ON (
  observation.workspace_id,
  observation.account_id,
  observation.region,
  observation.security_group_id
)
  observation.*
FROM security_group_observations observation
JOIN organization_collection_runs run
  ON run.workspace_id = observation.workspace_id
 AND run.run_id = observation.run_id
WHERE run.status IN ('succeeded', 'partial')
ORDER BY
  observation.workspace_id,
  observation.account_id,
  observation.region,
  observation.security_group_id,
  observation.observed_at DESC;

CREATE VIEW current_security_group_rules AS
SELECT DISTINCT ON (
  observation.workspace_id,
  observation.account_id,
  observation.region,
  observation.security_group_id,
  observation.rule_id
)
  observation.*
FROM security_group_rule_observations observation
JOIN organization_collection_runs run
  ON run.workspace_id = observation.workspace_id
 AND run.run_id = observation.run_id
WHERE run.status IN ('succeeded', 'partial')
ORDER BY
  observation.workspace_id,
  observation.account_id,
  observation.region,
  observation.security_group_id,
  observation.rule_id,
  observation.observed_at DESC;

CREATE TABLE cloudtrail_events (
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  event_id text NOT NULL,
  source_id uuid NOT NULL REFERENCES ingestion_sources(id),
  raw_object_id uuid NOT NULL REFERENCES ingested_objects(id),
  account_id text NOT NULL,
  region text NOT NULL,
  security_group_id text NOT NULL DEFAULT '',
  event_name text NOT NULL,
  event_time timestamptz NOT NULL,
  actor_arn text,
  actor_type text,
  source_ip inet,
  successful boolean NOT NULL,
  direction text,
  effect text,
  internet_wide boolean NOT NULL DEFAULT false,
  request_parameters jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, event_id, event_time)
) PARTITION BY RANGE (event_time);

CREATE INDEX cloudtrail_events_group_time_idx
  ON cloudtrail_events (workspace_id, security_group_id, event_time DESC);

CREATE TABLE cloudtrail_events_default
  PARTITION OF cloudtrail_events DEFAULT;

CREATE TABLE config_items (
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  id text NOT NULL,
  source_id uuid NOT NULL REFERENCES ingestion_sources(id),
  raw_object_id uuid NOT NULL REFERENCES ingested_objects(id),
  account_id text NOT NULL,
  region text NOT NULL,
  resource_type text NOT NULL,
  resource_id text NOT NULL,
  resource_arn text,
  configuration_state_id text,
  capture_time timestamptz NOT NULL,
  status text NOT NULL,
  configuration jsonb NOT NULL,
  relationships jsonb NOT NULL DEFAULT '[]',
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, id, capture_time)
) PARTITION BY RANGE (capture_time);

CREATE INDEX config_items_resource_capture_idx
  ON config_items (workspace_id, resource_id, capture_time DESC);

CREATE TABLE config_items_default
  PARTITION OF config_items DEFAULT;

CREATE TABLE aws_resources (
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  account_id text NOT NULL,
  region text NOT NULL,
  resource_type text NOT NULL,
  resource_id text NOT NULL,
  resource_arn text,
  name text,
  tags jsonb NOT NULL DEFAULT '{}',
  current_configuration jsonb NOT NULL DEFAULT '{}',
  configuration_capture_time timestamptz,
  deleted_at timestamptz,
  PRIMARY KEY (workspace_id, account_id, region, resource_type, resource_id)
);

CREATE TABLE security_group_rule_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  account_id text NOT NULL,
  region text NOT NULL,
  security_group_id text NOT NULL,
  direction text NOT NULL CHECK (direction IN ('Ingress', 'Egress')),
  protocol text NOT NULL,
  from_port integer,
  to_port integer,
  peer text NOT NULL,
  peer_type text NOT NULL,
  description text,
  internet_wide boolean NOT NULL DEFAULT false,
  broadness_category text,
  valid_from timestamptz NOT NULL,
  valid_to timestamptz,
  config_item_id text NOT NULL,
  UNIQUE (
    workspace_id, account_id, region, security_group_id, direction,
    protocol, from_port, to_port, peer, valid_from
  )
);

CREATE INDEX security_group_rules_current_broad_idx
  ON security_group_rule_versions
  (workspace_id, internet_wide, direction, security_group_id)
  WHERE valid_to IS NULL;

CREATE TABLE findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  security_group_id text NOT NULL,
  rule_version_id uuid REFERENCES security_group_rule_versions(id),
  policy_key text NOT NULL,
  severity text NOT NULL,
  risk_score integer NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  status text NOT NULL,
  title text NOT NULL,
  explanation text NOT NULL,
  evidence jsonb NOT NULL,
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  resolved_at timestamptz,
  UNIQUE (workspace_id, security_group_id, policy_key, rule_version_id)
);

CREATE TABLE audit_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  actor text NOT NULL,
  action text NOT NULL,
  target_type text NOT NULL,
  target_id text NOT NULL,
  summary text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_events_workspace_created_idx
  ON audit_events (workspace_id, created_at DESC);

-- Product intelligence and governance records. Derived evidence is recomputable
-- from normalized AWS data; human decisions and workflow history are durable.
CREATE TABLE exposure_verdicts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  security_group_id text NOT NULL,
  verdict text NOT NULL CHECK (verdict IN (
    'confirmed-public-service', 'internet-path-exists', 'internal-only',
    'broad-but-unreachable', 'evidence-incomplete'
  )),
  confidence integer NOT NULL CHECK (confidence BETWEEN 0 AND 100),
  risk_score integer NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  route_evidence jsonb NOT NULL DEFAULT '{}',
  external_evidence jsonb NOT NULL DEFAULT '{}',
  toxic_signals jsonb NOT NULL DEFAULT '[]',
  evaluated_at timestamptz NOT NULL DEFAULT now(),
  evidence_fresh_until timestamptz,
  UNIQUE (workspace_id, security_group_id)
);

CREATE INDEX exposure_verdicts_priority_idx
  ON exposure_verdicts (workspace_id, risk_score DESC, verdict);

CREATE TABLE rule_recommendations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  security_group_id text NOT NULL,
  status text NOT NULL CHECK (status IN (
    'proposed', 'validating', 'approved', 'implemented', 'dismissed'
  )),
  current_rule jsonb NOT NULL,
  proposed_rules jsonb NOT NULL,
  recommendation_basis jsonb NOT NULL DEFAULT '[]',
  confidence integer NOT NULL CHECK (confidence BETWEEN 0 AND 100),
  risk_before integer NOT NULL CHECK (risk_before BETWEEN 0 AND 100),
  risk_after integer NOT NULL CHECK (risk_after BETWEEN 0 AND 100),
  paths_removed integer NOT NULL DEFAULT 0,
  traffic_preserved numeric(5,2),
  observation_window tstzrange,
  rollback_plan text NOT NULL,
  owner text NOT NULL,
  ticket_ref text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX rule_recommendations_queue_idx
  ON rule_recommendations (workspace_id, status, risk_before DESC);

CREATE TABLE exposure_drift_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  security_group_id text NOT NULL,
  cloudtrail_event_id text,
  status text NOT NULL CHECK (status IN (
    'new', 'investigating', 'expected', 'remediate', 'closed'
  )),
  severity text NOT NULL,
  risk_delta integer NOT NULL,
  before_state jsonb NOT NULL DEFAULT '{}',
  after_state jsonb NOT NULL DEFAULT '{}',
  actor_arn text,
  delivery_channel text,
  recurrence_count integer NOT NULL DEFAULT 1,
  owner text NOT NULL DEFAULT 'Unassigned',
  ticket_ref text,
  occurred_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX exposure_drift_queue_idx
  ON exposure_drift_events (workspace_id, status, severity, occurred_at DESC);

CREATE TABLE ownership_assignments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  subject_type text NOT NULL,
  subject_id text NOT NULL,
  owner text NOT NULL,
  source text NOT NULL,
  confidence integer NOT NULL CHECK (confidence BETWEEN 0 AND 100),
  verified_at timestamptz,
  UNIQUE (workspace_id, subject_type, subject_id)
);

CREATE TABLE exception_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  subject_id text NOT NULL,
  status text NOT NULL CHECK (status IN (
    'requested', 'approved', 'rejected', 'revoked', 'expired'
  )),
  requestor text NOT NULL,
  approver text,
  owner text NOT NULL,
  justification text NOT NULL,
  compensating_controls jsonb NOT NULL DEFAULT '[]',
  ticket_ref text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (approver IS NULL OR approver <> requestor)
);

CREATE INDEX exception_requests_expiry_idx
  ON exception_requests (workspace_id, status, expires_at);

CREATE TABLE control_evaluations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  control_framework text NOT NULL,
  control_id text NOT NULL,
  resource_id text NOT NULL,
  native_status text NOT NULL,
  gatewatch_status text NOT NULL,
  evidence jsonb NOT NULL DEFAULT '{}',
  evaluated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, control_framework, control_id, resource_id)
);

CREATE TABLE hygiene_findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  resource_id text NOT NULL,
  finding_type text NOT NULL,
  status text NOT NULL CHECK (status IN ('open', 'scheduled', 'resolved', 'accepted')),
  impact text NOT NULL,
  recommendation text NOT NULL,
  owner text NOT NULL DEFAULT 'Unassigned',
  ticket_ref text,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX hygiene_findings_queue_idx
  ON hygiene_findings (workspace_id, status, finding_type);

CREATE TABLE iac_guardrail_evaluations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  repository text NOT NULL,
  change_ref text NOT NULL,
  commit_sha text NOT NULL,
  verdict text NOT NULL CHECK (verdict IN ('pass', 'warn', 'block')),
  enforcement_mode text NOT NULL CHECK (enforcement_mode IN ('disabled', 'monitor', 'enabled')),
  policy_key text NOT NULL,
  current_risk integer NOT NULL CHECK (current_risk BETWEEN 0 AND 100),
  projected_risk integer NOT NULL CHECK (projected_risk BETWEEN 0 AND 100),
  evidence jsonb NOT NULL DEFAULT '{}',
  evaluated_at timestamptz NOT NULL DEFAULT now(),
  decided_by text,
  UNIQUE (workspace_id, repository, commit_sha, policy_key)
);

CREATE TABLE program_metric_snapshots (
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  captured_at timestamptz NOT NULL,
  internet_wide_rules integer NOT NULL,
  reachable_critical_assets integer NOT NULL,
  overdue_findings integer NOT NULL,
  mean_time_to_remediate_hours numeric(12,2),
  approved_iac_change_percent numeric(5,2),
  risk_points_removed integer NOT NULL DEFAULT 0,
  effective_paths_eliminated integer NOT NULL DEFAULT 0,
  evidence_coverage_percent numeric(5,2),
  dimensions jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY (workspace_id, captured_at)
);

CREATE TABLE product_workflow_records (
  id text PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  kind text NOT NULL,
  subject_id text NOT NULL,
  status text NOT NULL,
  owner text NOT NULL DEFAULT 'Unassigned',
  note text NOT NULL DEFAULT '',
  ticket_ref text NOT NULL DEFAULT '',
  expires_at timestamptz,
  payload jsonb NOT NULL DEFAULT '{}',
  created_by text NOT NULL,
  updated_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX product_workflow_queue_idx
  ON product_workflow_records (workspace_id, kind, status, updated_at DESC);

-- Daily analyst workflow. The fingerprint is generated from the normalized
-- finding signature so the same issue retains identity across observations,
-- disappears as resolved, and can later reopen with its history intact.
CREATE TABLE finding_workflows (
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  fingerprint text NOT NULL,
  finding_id uuid REFERENCES findings(id),
  security_group_id text NOT NULL,
  finding_key text NOT NULL,
  status text NOT NULL CHECK (status IN (
    'new', 'follow-up', 'acknowledged', 'accepted-risk', 'reopened', 'resolved'
  )),
  assignee text NOT NULL DEFAULT 'Unassigned',
  note text NOT NULL DEFAULT '',
  ticket_ref text,
  due_at timestamptz,
  expires_at timestamptz,
  compensating_controls jsonb NOT NULL DEFAULT '[]',
  reason_code text NOT NULL DEFAULT '',
  next_review_at timestamptz,
  approver text NOT NULL DEFAULT '',
  resolution_evidence text NOT NULL DEFAULT '',
  evidence_snapshot jsonb NOT NULL DEFAULT '{}',
  reviewer text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, fingerprint)
);

CREATE INDEX finding_workflows_daily_queue_idx
  ON finding_workflows (workspace_id, status, due_at, updated_at DESC);

CREATE INDEX finding_workflows_security_group_idx
  ON finding_workflows (workspace_id, security_group_id);

CREATE TABLE finding_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  fingerprint text NOT NULL,
  event_type text NOT NULL,
  from_status text,
  to_status text NOT NULL,
  actor text NOT NULL,
  assignee text NOT NULL DEFAULT 'Unassigned',
  note text NOT NULL DEFAULT '',
  ticket_ref text,
  due_at timestamptz,
  expires_at timestamptz,
  compensating_controls jsonb NOT NULL DEFAULT '[]',
  reason_code text NOT NULL DEFAULT '',
  next_review_at timestamptz,
  approver text NOT NULL DEFAULT '',
  resolution_evidence text NOT NULL DEFAULT '',
  evidence_snapshot jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (workspace_id, fingerprint)
    REFERENCES finding_workflows(workspace_id, fingerprint)
);

CREATE INDEX finding_events_history_idx
  ON finding_events (workspace_id, fingerprint, created_at DESC);

CREATE TABLE saved_finding_views (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  owner text NOT NULL,
  name text NOT NULL,
  filters jsonb NOT NULL DEFAULT '{}',
  visibility text NOT NULL DEFAULT 'personal'
    CHECK (visibility IN ('personal', 'team')),
  is_default boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, owner, name)
);

CREATE UNIQUE INDEX saved_finding_views_one_default_idx
  ON saved_finding_views (workspace_id, owner)
  WHERE is_default = true;

-- Short-lived, actor-bound snapshots make high-throughput keyboard triage
-- reversible without trusting state returned by a client.
CREATE TABLE finding_undo_snapshots (
  token uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  actor text NOT NULL,
  state jsonb NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX finding_undo_snapshots_expiry_idx
  ON finding_undo_snapshots (workspace_id, actor, expires_at);

-- Canonical review identity prevents identically named security groups in
-- different accounts, regions, or VPCs from sharing workflow state.
CREATE TABLE resource_reviews (
  resource_key text PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  security_group_id text NOT NULL,
  account_id text NOT NULL,
  region text NOT NULL,
  vpc_id text NOT NULL,
  status text NOT NULL,
  assignee text NOT NULL DEFAULT 'Unassigned',
  reviewer text NOT NULL,
  note text NOT NULL DEFAULT '',
  ticket_ref text,
  expires_at timestamptz,
  evidence_snapshot jsonb NOT NULL DEFAULT '{}',
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX resource_reviews_workspace_status_idx
  ON resource_reviews (workspace_id, status, updated_at DESC);

CREATE TABLE resource_review_events (
  id bigserial PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  resource_key text NOT NULL REFERENCES resource_reviews(resource_key),
  security_group_id text NOT NULL,
  status text NOT NULL,
  assignee text NOT NULL,
  reviewer text NOT NULL,
  note text NOT NULL,
  ticket_ref text,
  expires_at timestamptz,
  evidence_snapshot jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX resource_review_events_history_idx
  ON resource_review_events (workspace_id, resource_key, created_at DESC);

CREATE TABLE finding_observations (
  id text PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  fingerprint text NOT NULL,
  legacy_fingerprint text NOT NULL DEFAULT '',
  canonical_resource_key text NOT NULL,
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  last_snapshot_id text NOT NULL,
  state text NOT NULL CHECK (state IN ('active', 'reopened', 'resolved')),
  observation_count integer NOT NULL DEFAULT 1,
  resolved_at timestamptz,
  evidence_snapshot jsonb NOT NULL DEFAULT '{}',
  UNIQUE (workspace_id, fingerprint)
);

CREATE INDEX finding_observations_resource_state_idx
  ON finding_observations (workspace_id, canonical_resource_key, state);

CREATE TABLE finding_jira_links (
  fingerprint text PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  issue_key text NOT NULL,
  issue_url text NOT NULL,
  remote_status text NOT NULL DEFAULT '',
  remote_resolution text NOT NULL DEFAULT '',
  remote_updated_at timestamptz,
  last_synced_at timestamptz,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, issue_key)
);

CREATE TABLE access_policies (
  id text PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  name text NOT NULL,
  description text NOT NULL,
  owner text NOT NULL,
  destination text NOT NULL,
  service text NOT NULL,
  yaml text NOT NULL,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE access_policy_versions (
  id text PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  policy_id text NOT NULL REFERENCES access_policies(id),
  version integer NOT NULL,
  status text NOT NULL DEFAULT 'draft',
  yaml text NOT NULL,
  evaluation jsonb NOT NULL DEFAULT '{}',
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, policy_id, version)
);

CREATE TABLE recertification_campaigns (
  id text PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  name text NOT NULL,
  description text NOT NULL,
  owner text NOT NULL,
  scope text NOT NULL,
  due_date date NOT NULL,
  total integer NOT NULL DEFAULT 0,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE campaign_items (
  id text PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  campaign_id text NOT NULL REFERENCES recertification_campaigns(id),
  fingerprint text NOT NULL,
  owner text NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  decision text NOT NULL DEFAULT '',
  note text NOT NULL DEFAULT '',
  evidence_snapshot jsonb NOT NULL DEFAULT '{}',
  decided_by text,
  decided_at timestamptz
);

CREATE INDEX campaign_items_campaign_status_idx
  ON campaign_items (workspace_id, campaign_id, status);

CREATE TABLE remediation_requests (
  id text PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  fingerprint text NOT NULL,
  canonical_resource_key text NOT NULL,
  status text NOT NULL DEFAULT 'draft',
  proposed_change text NOT NULL,
  artifact_type text NOT NULL DEFAULT 'json',
  external_ref text,
  evidence_before jsonb NOT NULL DEFAULT '{}',
  evidence_after jsonb NOT NULL DEFAULT '{}',
  requested_by text NOT NULL,
  approved_by text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE integration_deliveries (
  id text PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  integration text NOT NULL,
  event_type text NOT NULL,
  target_id text NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  attempts integer NOT NULL DEFAULT 0,
  payload jsonb NOT NULL DEFAULT '{}',
  last_error text,
  next_attempt_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX integration_deliveries_queue_idx
  ON integration_deliveries (workspace_id, status, next_attempt_at);

CREATE TABLE verification_runs (
  id text PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  remediation_id text NOT NULL REFERENCES remediation_requests(id),
  snapshot_id text NOT NULL,
  status text NOT NULL,
  result jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX verification_runs_remediation_idx
  ON verification_runs (workspace_id, remediation_id, created_at DESC);

CREATE OR REPLACE FUNCTION gatewatch_apply_security_group_config(
  p_workspace_id uuid,
  p_account_id text,
  p_region text,
  p_security_group_id text,
  p_capture_time timestamptz,
  p_config_item_id text,
  p_status text,
  p_configuration jsonb
) RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
  inserted_count integer := 0;
  next_capture_time timestamptz;
BEGIN
  SELECT min(capture_time)
    INTO next_capture_time
    FROM config_items
   WHERE workspace_id = p_workspace_id
     AND account_id = p_account_id
     AND region = p_region
     AND resource_type = 'AWS::EC2::SecurityGroup'
     AND resource_id = p_security_group_id
     AND capture_time > p_capture_time;

  UPDATE security_group_rule_versions
     SET valid_to = p_capture_time
   WHERE workspace_id = p_workspace_id
     AND account_id = p_account_id
     AND region = p_region
     AND security_group_id = p_security_group_id
     AND valid_to IS NULL
     AND valid_from < p_capture_time;

  UPDATE findings finding
     SET status = 'resolved',
         last_seen_at = p_capture_time,
         resolved_at = p_capture_time
    FROM security_group_rule_versions rule_version
   WHERE finding.rule_version_id = rule_version.id
     AND finding.workspace_id = p_workspace_id
     AND rule_version.valid_to = p_capture_time
     AND rule_version.security_group_id = p_security_group_id;

  IF p_status IN ('ResourceDeleted', 'ResourceNotRecorded') THEN
    RETURN 0;
  END IF;

  WITH permissions AS (
    SELECT 'Ingress'::text AS direction, permission
      FROM jsonb_array_elements(
        COALESCE(p_configuration->'ipPermissions', p_configuration->'IpPermissions', '[]'::jsonb)
      ) permission
    UNION ALL
    SELECT 'Egress'::text AS direction, permission
      FROM jsonb_array_elements(
        COALESCE(p_configuration->'ipPermissionsEgress', p_configuration->'IpPermissionsEgress', '[]'::jsonb)
      ) permission
  ),
  peers AS (
    SELECT direction, permission,
           COALESCE(peer->>'cidrIp', peer->>'CidrIp') AS peer,
           'IPv4'::text AS peer_type,
           COALESCE(peer->>'description', peer->>'Description', '') AS description
      FROM permissions
      CROSS JOIN LATERAL jsonb_array_elements(
        COALESCE(permission->'ipRanges', permission->'IpRanges', '[]'::jsonb)
      ) peer
    UNION ALL
    SELECT direction, permission,
           COALESCE(peer->>'cidrIpv6', peer->>'CidrIpv6'),
           'IPv6',
           COALESCE(peer->>'description', peer->>'Description', '')
      FROM permissions
      CROSS JOIN LATERAL jsonb_array_elements(
        COALESCE(permission->'ipv6Ranges', permission->'Ipv6Ranges', '[]'::jsonb)
      ) peer
    UNION ALL
    SELECT direction, permission,
           COALESCE(peer->>'groupId', peer->>'GroupId'),
           'Security group',
           COALESCE(peer->>'description', peer->>'Description', '')
      FROM permissions
      CROSS JOIN LATERAL jsonb_array_elements(
        COALESCE(permission->'userIdGroupPairs', permission->'UserIdGroupPairs', '[]'::jsonb)
      ) peer
    UNION ALL
    SELECT direction, permission,
           COALESCE(peer->>'prefixListId', peer->>'PrefixListId'),
           'Prefix list',
           COALESCE(peer->>'description', peer->>'Description', '')
      FROM permissions
      CROSS JOIN LATERAL jsonb_array_elements(
        COALESCE(permission->'prefixListIds', permission->'PrefixListIds', '[]'::jsonb)
      ) peer
  ),
  inserted AS (
    INSERT INTO security_group_rule_versions (
      workspace_id, account_id, region, security_group_id, direction,
      protocol, from_port, to_port, peer, peer_type, description,
      internet_wide, broadness_category, valid_from, valid_to, config_item_id
    )
    SELECT
      p_workspace_id, p_account_id, p_region, p_security_group_id, direction,
      CASE
        WHEN COALESCE(permission->>'ipProtocol', permission->>'IpProtocol') = '-1'
          THEN 'All'
        ELSE COALESCE(permission->>'ipProtocol', permission->>'IpProtocol', 'All')
      END,
      NULLIF(COALESCE(permission->>'fromPort', permission->>'FromPort'), '')::integer,
      NULLIF(COALESCE(permission->>'toPort', permission->>'ToPort'), '')::integer,
      peer, peer_type, description,
      peer IN ('0.0.0.0/0', '::/0'),
      CASE
        WHEN peer IN ('0.0.0.0/0', '::/0') THEN 'Internet-wide'
        WHEN COALESCE(permission->>'ipProtocol', permission->>'IpProtocol') = '-1'
          THEN 'All traffic'
        WHEN peer_type IN ('IPv4', 'IPv6')
          AND split_part(peer, '/', 2) ~ '^[0-9]+$'
          AND split_part(peer, '/', 2)::integer <= 16 THEN 'Broad CIDR'
        WHEN NULLIF(COALESCE(permission->>'toPort', permission->>'ToPort'), '')::integer
           - NULLIF(COALESCE(permission->>'fromPort', permission->>'FromPort'), '')::integer >= 100
          THEN 'Wide port range'
        ELSE NULL
      END,
      p_capture_time, next_capture_time, p_config_item_id
      FROM peers
     WHERE peer IS NOT NULL AND peer <> ''
    ON CONFLICT DO NOTHING
    RETURNING id, direction, protocol, from_port, to_port, peer,
              internet_wide, broadness_category
  )
  INSERT INTO findings (
    workspace_id, security_group_id, rule_version_id, policy_key, severity,
    risk_score, status, title, explanation, evidence, first_seen_at,
    last_seen_at, resolved_at
  )
  SELECT
    p_workspace_id, p_security_group_id, id,
    CASE
      WHEN internet_wide THEN 'internet-wide-access'
      WHEN broadness_category = 'All traffic' THEN 'all-traffic'
      WHEN broadness_category = 'Broad CIDR' THEN 'broad-cidr'
      ELSE 'wide-port-range'
    END,
    CASE
      WHEN internet_wide AND direction = 'Ingress' THEN 'critical'
      WHEN internet_wide THEN 'high'
      ELSE 'medium'
    END,
    CASE
      WHEN internet_wide AND direction = 'Ingress' THEN 90
      WHEN internet_wide THEN 75
      WHEN broadness_category = 'All traffic' THEN 70
      WHEN broadness_category = 'Broad CIDR' THEN 55
      ELSE 45
    END,
    CASE WHEN next_capture_time IS NULL THEN 'needs-review' ELSE 'resolved' END,
    broadness_category || ' ' || lower(direction) || ' rule',
    CASE
      WHEN internet_wide AND direction = 'Ingress'
        THEN 'Any internet address can initiate traffic allowed by this rule.'
      WHEN internet_wide
        THEN 'The rule allows traffic to any internet address.'
      WHEN broadness_category = 'All traffic'
        THEN 'The rule does not restrict protocol or port.'
      ELSE 'The rule spans a broad network or port range.'
    END,
    jsonb_build_object(
      'configItemId', p_config_item_id,
      'configCaptureTime', p_capture_time,
      'accountId', p_account_id,
      'region', p_region,
      'direction', direction,
      'protocol', protocol,
      'fromPort', from_port,
      'toPort', to_port,
      'peer', peer,
      'cloudTrailStatus', 'awaiting-or-unattributed'
    ),
    p_capture_time,
    COALESCE(next_capture_time, p_capture_time),
    next_capture_time
  FROM inserted
  WHERE broadness_category IS NOT NULL
  ON CONFLICT DO NOTHING;

  GET DIAGNOSTICS inserted_count = ROW_COUNT;
  RETURN inserted_count;
END;
$$;

CREATE OR REPLACE FUNCTION gatewatch_correlate_cloudtrail_event(
  p_workspace_id uuid,
  p_event_id text,
  p_event_time timestamptz
) RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
  correlated_count integer := 0;
BEGIN
  UPDATE findings finding
     SET evidence = finding.evidence || jsonb_build_object(
       'cloudTrailEventId', event.event_id,
       'cloudTrailEventTime', event.event_time,
       'actorArn', event.actor_arn,
       'sourceIp', host(event.source_ip),
       'cloudTrailStatus', 'confirmed'
     )
    FROM security_group_rule_versions rule_version,
         cloudtrail_events event
   WHERE finding.rule_version_id = rule_version.id
     AND finding.workspace_id = p_workspace_id
     AND event.workspace_id = p_workspace_id
     AND event.event_id = p_event_id
     AND event.event_time = p_event_time
     AND event.successful = true
     AND event.security_group_id = rule_version.security_group_id
     AND event.account_id = rule_version.account_id
     AND event.region = rule_version.region
     AND abs(extract(epoch FROM (rule_version.valid_from - event.event_time))) <= 1800;

  GET DIAGNOSTICS correlated_count = ROW_COUNT;
  RETURN correlated_count;
END;
$$;

-- Monthly partitions can be created ahead of time for predictable vacuum and
-- retention behavior. Default partitions keep ingestion available if a
-- maintenance job is delayed.

INSERT INTO workspaces (slug, name)
VALUES ('default', 'Gatewatch')
ON CONFLICT (slug) DO NOTHING;
