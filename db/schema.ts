import { sql } from "drizzle-orm";
import { index, integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

export const securityGroupReviews = sqliteTable("security_group_reviews", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  securityGroupId: text("security_group_id").notNull().unique(),
  status: text("status").notNull().default("needs-review"),
  assignee: text("assignee").notNull().default("Unassigned"),
  reviewer: text("reviewer").notNull().default(""),
  note: text("note").notNull().default(""),
  ticketRef: text("ticket_ref").notNull().default(""),
  expiresAt: text("expires_at").notNull().default(""),
  evidenceSnapshot: text("evidence_snapshot").notNull().default(""),
  updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
});

export const securityGroupReviewEvents = sqliteTable(
  "security_group_review_events",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    securityGroupId: text("security_group_id").notNull(),
    status: text("status").notNull(),
    assignee: text("assignee").notNull(),
    reviewer: text("reviewer").notNull().default(""),
    note: text("note").notNull(),
    ticketRef: text("ticket_ref").notNull().default(""),
    expiresAt: text("expires_at").notNull().default(""),
    evidenceSnapshot: text("evidence_snapshot").notNull().default(""),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("security_group_review_events_group_idx").on(
      table.securityGroupId,
      table.createdAt,
    ),
  ],
);

export const resourceReviews = sqliteTable(
  "resource_reviews",
  {
    resourceKey: text("resource_key").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    securityGroupId: text("security_group_id").notNull(),
    accountId: text("account_id").notNull(),
    region: text("region").notNull(),
    vpcId: text("vpc_id").notNull(),
    status: text("status").notNull().default("needs-review"),
    assignee: text("assignee").notNull().default("Unassigned"),
    reviewer: text("reviewer").notNull().default(""),
    note: text("note").notNull().default(""),
    ticketRef: text("ticket_ref").notNull().default(""),
    expiresAt: text("expires_at").notNull().default(""),
    evidenceSnapshot: text("evidence_snapshot").notNull().default("{}"),
    updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("resource_reviews_workspace_status_idx").on(
      table.workspaceId,
      table.status,
      table.updatedAt,
    ),
  ],
);

export const resourceReviewEvents = sqliteTable(
  "resource_review_events",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    workspaceId: text("workspace_id").notNull().default("default"),
    resourceKey: text("resource_key").notNull(),
    securityGroupId: text("security_group_id").notNull(),
    status: text("status").notNull(),
    assignee: text("assignee").notNull(),
    reviewer: text("reviewer").notNull(),
    note: text("note").notNull(),
    ticketRef: text("ticket_ref").notNull().default(""),
    expiresAt: text("expires_at").notNull().default(""),
    evidenceSnapshot: text("evidence_snapshot").notNull().default("{}"),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("resource_review_events_history_idx").on(
      table.workspaceId,
      table.resourceKey,
      table.createdAt,
    ),
  ],
);

export const findingWorkflows = sqliteTable(
  "finding_workflows",
  {
    fingerprint: text("fingerprint").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    securityGroupId: text("security_group_id").notNull(),
    findingKey: text("finding_key").notNull(),
    status: text("status").notNull().default("new"),
    assignee: text("assignee").notNull().default("Unassigned"),
    note: text("note").notNull().default(""),
    ticketRef: text("ticket_ref").notNull().default(""),
    dueAt: text("due_at").notNull().default(""),
    expiresAt: text("expires_at").notNull().default(""),
    compensatingControls: text("compensating_controls").notNull().default("[]"),
    evidenceSnapshot: text("evidence_snapshot").notNull().default(""),
    reviewer: text("reviewer").notNull(),
    updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("finding_workflows_queue_idx").on(
      table.workspaceId,
      table.status,
      table.updatedAt,
    ),
    index("finding_workflows_group_idx").on(
      table.workspaceId,
      table.securityGroupId,
    ),
  ],
);

export const findingEvents = sqliteTable(
  "finding_events",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    fingerprint: text("fingerprint").notNull(),
    workspaceId: text("workspace_id").notNull().default("default"),
    eventType: text("event_type").notNull(),
    fromStatus: text("from_status").notNull().default(""),
    toStatus: text("to_status").notNull(),
    actor: text("actor").notNull(),
    assignee: text("assignee").notNull().default("Unassigned"),
    note: text("note").notNull().default(""),
    ticketRef: text("ticket_ref").notNull().default(""),
    dueAt: text("due_at").notNull().default(""),
    expiresAt: text("expires_at").notNull().default(""),
    compensatingControls: text("compensating_controls").notNull().default("[]"),
    evidenceSnapshot: text("evidence_snapshot").notNull().default(""),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("finding_events_history_idx").on(
      table.workspaceId,
      table.fingerprint,
      table.createdAt,
    ),
  ],
);

export const findingWorkflowDetails = sqliteTable(
  "finding_workflow_details",
  {
    fingerprint: text("fingerprint").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    reasonCode: text("reason_code").notNull().default(""),
    nextReviewAt: text("next_review_at").notNull().default(""),
    approver: text("approver").notNull().default(""),
    resolutionEvidence: text("resolution_evidence").notNull().default(""),
    updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("finding_workflow_details_workspace_idx").on(
      table.workspaceId,
      table.updatedAt,
    ),
  ],
);

export const findingDecisionDetails = sqliteTable(
  "finding_decision_details",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    fingerprint: text("fingerprint").notNull(),
    workspaceId: text("workspace_id").notNull().default("default"),
    status: text("status").notNull(),
    reasonCode: text("reason_code").notNull().default(""),
    nextReviewAt: text("next_review_at").notNull().default(""),
    approver: text("approver").notNull().default(""),
    resolutionEvidence: text("resolution_evidence").notNull().default(""),
    actor: text("actor").notNull(),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("finding_decision_details_history_idx").on(
      table.workspaceId,
      table.fingerprint,
      table.createdAt,
    ),
  ],
);

export const findingUndoSnapshots = sqliteTable(
  "finding_undo_snapshots",
  {
    token: text("token").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    actor: text("actor").notNull(),
    state: text("state").notNull(),
    expiresAt: text("expires_at").notNull(),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [index("finding_undo_snapshots_expiry_idx").on(table.expiresAt)],
);

export const savedFindingViews = sqliteTable(
  "saved_finding_views",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    owner: text("owner").notNull(),
    name: text("name").notNull(),
    filters: text("filters").notNull().default("{}"),
    isDefault: integer("is_default", { mode: "boolean" }).notNull().default(false),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
    updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("saved_finding_views_owner_idx").on(
      table.workspaceId,
      table.owner,
      table.updatedAt,
    ),
  ],
);

export const savedFindingViewVisibility = sqliteTable(
  "saved_finding_view_visibility",
  {
    viewId: text("view_id").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    visibility: text("visibility").notNull().default("personal"),
    createdBy: text("created_by").notNull(),
    updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("saved_finding_view_visibility_idx").on(
      table.workspaceId,
      table.visibility,
    ),
  ],
);

export const accessPolicies = sqliteTable("access_policies", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  description: text("description").notNull(),
  owner: text("owner").notNull(),
  destination: text("destination").notNull(),
  service: text("service").notNull(),
  yaml: text("yaml").notNull(),
  createdBy: text("created_by").notNull(),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
});

export const recertificationCampaigns = sqliteTable(
  "recertification_campaigns",
  {
    id: text("id").primaryKey(),
    name: text("name").notNull(),
    description: text("description").notNull(),
    owner: text("owner").notNull(),
    scope: text("scope").notNull(),
    dueDate: text("due_date").notNull(),
    total: integer("total").notNull().default(0),
    createdBy: text("created_by").notNull(),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
    updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("recertification_campaigns_due_idx").on(
      table.dueDate,
      table.updatedAt,
    ),
  ],
);

export const ingestionSources = sqliteTable(
  "ingestion_sources",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    name: text("name").notNull(),
    sourceType: text("source_type").notNull(),
    bucketArn: text("bucket_arn").notNull(),
    bucketName: text("bucket_name").notNull(),
    region: text("region").notNull(),
    objectPrefix: text("object_prefix").notNull().default(""),
    roleArn: text("role_arn").notNull(),
    externalId: text("external_id").notNull(),
    kmsKeyArn: text("kms_key_arn").notNull().default(""),
    organizationId: text("organization_id").notNull().default(""),
    ingestionMode: text("ingestion_mode").notNull().default("continuous"),
    backfillStart: text("backfill_start").notNull().default(""),
    includedAccounts: text("included_accounts").notNull().default("[]"),
    excludedAccounts: text("excluded_accounts").notNull().default("[]"),
    includedRegions: text("included_regions").notNull().default("[]"),
    configResourceTypes: text("config_resource_types")
      .notNull()
      .default("[]"),
    retentionDays: integer("retention_days").notNull().default(365),
    status: text("status").notNull().default("draft"),
    testSummary: text("test_summary").notNull().default("{}"),
    lastTestedAt: text("last_tested_at").notNull().default(""),
    lastSuccessfulObjectAt: text("last_successful_object_at")
      .notNull()
      .default(""),
    createdBy: text("created_by").notNull(),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
    updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("ingestion_sources_workspace_status_idx").on(
      table.workspaceId,
      table.status,
    ),
    index("ingestion_sources_bucket_idx").on(
      table.bucketName,
      table.objectPrefix,
    ),
  ],
);

export const ingestionRuns = sqliteTable(
  "ingestion_runs",
  {
    id: text("id").primaryKey(),
    sourceId: text("source_id").notNull(),
    runType: text("run_type").notNull(),
    status: text("status").notNull(),
    discoveredObjects: integer("discovered_objects").notNull().default(0),
    processedObjects: integer("processed_objects").notNull().default(0),
    failedObjects: integer("failed_objects").notNull().default(0),
    parsedRecords: integer("parsed_records").notNull().default(0),
    findingChanges: integer("finding_changes").notNull().default(0),
    cursor: text("cursor").notNull().default(""),
    errorSummary: text("error_summary").notNull().default(""),
    requestedBy: text("requested_by").notNull(),
    startedAt: text("started_at").notNull().default(sql`CURRENT_TIMESTAMP`),
    completedAt: text("completed_at").notNull().default(""),
  },
  (table) => [
    index("ingestion_runs_source_started_idx").on(
      table.sourceId,
      table.startedAt,
    ),
  ],
);

export const ingestedObjects = sqliteTable(
  "ingested_objects",
  {
    id: text("id").primaryKey(),
    sourceId: text("source_id").notNull(),
    bucketName: text("bucket_name").notNull(),
    objectKey: text("object_key").notNull(),
    versionId: text("version_id").notNull().default(""),
    etag: text("etag").notNull().default(""),
    status: text("status").notNull(),
    objectSize: integer("object_size").notNull().default(0),
    recordCount: integer("record_count").notNull().default(0),
    checksum: text("checksum").notNull().default(""),
    failureCode: text("failure_code").notNull().default(""),
    failureDetail: text("failure_detail").notNull().default(""),
    firstSeenAt: text("first_seen_at").notNull().default(sql`CURRENT_TIMESTAMP`),
    processedAt: text("processed_at").notNull().default(""),
  },
  (table) => [
    index("ingested_objects_source_status_idx").on(
      table.sourceId,
      table.status,
    ),
    index("ingested_objects_identity_idx").on(
      table.sourceId,
      table.objectKey,
      table.versionId,
    ),
  ],
);

export const auditEvents = sqliteTable(
  "audit_events",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    actor: text("actor").notNull(),
    action: text("action").notNull(),
    targetType: text("target_type").notNull(),
    targetId: text("target_id").notNull(),
    summary: text("summary").notNull(),
    metadata: text("metadata").notNull().default("{}"),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("audit_events_workspace_created_idx").on(
      table.workspaceId,
      table.createdAt,
    ),
  ],
);

export const userRoles = sqliteTable(
  "user_roles",
  {
    email: text("email").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    role: text("role").notNull().default("viewer"),
    createdBy: text("created_by").notNull(),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
    updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("user_roles_workspace_role_idx").on(table.workspaceId, table.role),
  ],
);

export const systemSettings = sqliteTable("system_settings", {
  key: text("key").primaryKey(),
  workspaceId: text("workspace_id").notNull().default("default"),
  value: text("value").notNull(),
  updatedBy: text("updated_by").notNull(),
  updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
});

export const findingJiraLinks = sqliteTable(
  "finding_jira_links",
  {
    fingerprint: text("fingerprint").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    issueKey: text("issue_key").notNull(),
    issueUrl: text("issue_url").notNull(),
    remoteStatus: text("remote_status").notNull().default(""),
    remoteResolution: text("remote_resolution").notNull().default(""),
    remoteUpdatedAt: text("remote_updated_at").notNull().default(""),
    lastSyncedAt: text("last_synced_at").notNull().default(""),
    createdBy: text("created_by").notNull(),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    uniqueIndex("finding_jira_links_issue_unique").on(
      table.workspaceId,
      table.issueKey,
    ),
  ],
);

export const normalizedCloudTrailEvents = sqliteTable(
  "normalized_cloudtrail_events",
  {
    eventId: text("event_id").primaryKey(),
    sourceId: text("source_id").notNull(),
    accountId: text("account_id").notNull(),
    region: text("region").notNull(),
    securityGroupId: text("security_group_id").notNull().default(""),
    eventName: text("event_name").notNull(),
    eventTime: text("event_time").notNull(),
    actorArn: text("actor_arn").notNull().default(""),
    sourceIp: text("source_ip").notNull().default(""),
    successful: integer("successful").notNull().default(1),
    normalizedPayload: text("normalized_payload").notNull(),
    rawObjectId: text("raw_object_id").notNull(),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("cloudtrail_events_group_time_idx").on(
      table.securityGroupId,
      table.eventTime,
    ),
    index("cloudtrail_events_account_region_idx").on(
      table.accountId,
      table.region,
    ),
  ],
);

export const configItems = sqliteTable(
  "config_items",
  {
    id: text("id").primaryKey(),
    sourceId: text("source_id").notNull(),
    accountId: text("account_id").notNull(),
    region: text("region").notNull(),
    resourceType: text("resource_type").notNull(),
    resourceId: text("resource_id").notNull(),
    resourceArn: text("resource_arn").notNull().default(""),
    configurationStateId: text("configuration_state_id")
      .notNull()
      .default(""),
    captureTime: text("capture_time").notNull(),
    status: text("status").notNull(),
    normalizedConfiguration: text("normalized_configuration").notNull(),
    rawObjectId: text("raw_object_id").notNull(),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("config_items_resource_capture_idx").on(
      table.resourceId,
      table.captureTime,
    ),
    index("config_items_account_region_idx").on(
      table.accountId,
      table.region,
    ),
  ],
);

export const awsEvidenceRecords = sqliteTable(
  "aws_evidence_records",
  {
    fingerprint: text("fingerprint").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    sourceId: text("source_id").notNull(),
    rawObjectId: text("raw_object_id").notNull(),
    sourceType: text("source_type").notNull(),
    evidenceClass: text("evidence_class").notNull(),
    observedAt: text("observed_at").notNull().default(""),
    accountId: text("account_id").notNull().default(""),
    region: text("region").notNull().default(""),
    resourceType: text("resource_type").notNull().default(""),
    resourceId: text("resource_id").notNull().default(""),
    eventName: text("event_name").notNull().default(""),
    disposition: text("disposition").notNull().default(""),
    normalizedPayload: text("normalized_payload").notNull(),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("aws_evidence_source_time_idx").on(
      table.workspaceId,
      table.sourceId,
      table.observedAt,
    ),
    index("aws_evidence_resource_time_idx").on(
      table.workspaceId,
      table.accountId,
      table.region,
      table.resourceId,
      table.observedAt,
    ),
  ],
);

export const productWorkflowRecords = sqliteTable(
  "product_workflow_records",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    kind: text("kind").notNull(),
    subjectId: text("subject_id").notNull(),
    status: text("status").notNull(),
    owner: text("owner").notNull().default("Unassigned"),
    note: text("note").notNull().default(""),
    ticketRef: text("ticket_ref").notNull().default(""),
    expiresAt: text("expires_at").notNull().default(""),
    payload: text("payload").notNull().default("{}"),
    createdBy: text("created_by").notNull(),
    updatedBy: text("updated_by").notNull(),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
    updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("product_workflows_kind_status_idx").on(
      table.workspaceId,
      table.kind,
      table.status,
    ),
    index("product_workflows_subject_idx").on(
      table.workspaceId,
      table.subjectId,
    ),
  ],
);

export const findingObservations = sqliteTable(
  "finding_observations",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    fingerprint: text("fingerprint").notNull(),
    legacyFingerprint: text("legacy_fingerprint").notNull().default(""),
    canonicalResourceKey: text("canonical_resource_key").notNull(),
    firstSeenAt: text("first_seen_at").notNull(),
    lastSeenAt: text("last_seen_at").notNull(),
    lastSnapshotId: text("last_snapshot_id").notNull(),
    state: text("state").notNull().default("active"),
    observationCount: integer("observation_count").notNull().default(1),
    resolvedAt: text("resolved_at").notNull().default(""),
    evidenceSnapshot: text("evidence_snapshot").notNull().default("{}"),
  },
  (table) => [
    uniqueIndex("finding_observations_workspace_fingerprint_unique").on(
      table.workspaceId,
      table.fingerprint,
    ),
    index("finding_observations_resource_state_idx").on(
      table.workspaceId,
      table.canonicalResourceKey,
      table.state,
    ),
    index("finding_observations_temporal_idx").on(
      table.workspaceId,
      table.state,
      table.lastSeenAt,
      table.observationCount,
    ),
  ],
);

export const accessPolicyVersions = sqliteTable(
  "access_policy_versions",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    policyId: text("policy_id").notNull(),
    version: integer("version").notNull(),
    status: text("status").notNull().default("draft"),
    yaml: text("yaml").notNull(),
    evaluation: text("evaluation").notNull().default("{}"),
    createdBy: text("created_by").notNull(),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("access_policy_versions_policy_idx").on(
      table.workspaceId,
      table.policyId,
      table.version,
    ),
  ],
);

export const campaignItems = sqliteTable(
  "campaign_items",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    campaignId: text("campaign_id").notNull(),
    fingerprint: text("fingerprint").notNull(),
    owner: text("owner").notNull(),
    status: text("status").notNull().default("pending"),
    decision: text("decision").notNull().default(""),
    note: text("note").notNull().default(""),
    evidenceSnapshot: text("evidence_snapshot").notNull().default("{}"),
    decidedBy: text("decided_by").notNull().default(""),
    decidedAt: text("decided_at").notNull().default(""),
  },
  (table) => [
    index("campaign_items_campaign_status_idx").on(
      table.workspaceId,
      table.campaignId,
      table.status,
    ),
  ],
);

export const remediationRequests = sqliteTable(
  "remediation_requests",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    fingerprint: text("fingerprint").notNull(),
    canonicalResourceKey: text("canonical_resource_key").notNull(),
    status: text("status").notNull().default("draft"),
    proposedChange: text("proposed_change").notNull(),
    artifactType: text("artifact_type").notNull().default("json"),
    externalRef: text("external_ref").notNull().default(""),
    evidenceBefore: text("evidence_before").notNull().default("{}"),
    evidenceAfter: text("evidence_after").notNull().default("{}"),
    requestedBy: text("requested_by").notNull(),
    approvedBy: text("approved_by").notNull().default(""),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
    updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("remediation_requests_queue_idx").on(
      table.workspaceId,
      table.status,
      table.updatedAt,
    ),
  ],
);

export const integrationDeliveries = sqliteTable(
  "integration_deliveries",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    integration: text("integration").notNull(),
    eventType: text("event_type").notNull(),
    targetId: text("target_id").notNull(),
    status: text("status").notNull().default("pending"),
    attempts: integer("attempts").notNull().default(0),
    payload: text("payload").notNull().default("{}"),
    lastError: text("last_error").notNull().default(""),
    nextAttemptAt: text("next_attempt_at").notNull().default(""),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
    updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("integration_deliveries_queue_idx").on(
      table.workspaceId,
      table.status,
      table.nextAttemptAt,
    ),
  ],
);

export const verificationRuns = sqliteTable(
  "verification_runs",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    remediationId: text("remediation_id").notNull(),
    snapshotId: text("snapshot_id").notNull(),
    status: text("status").notNull(),
    result: text("result").notNull().default("{}"),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("verification_runs_remediation_idx").on(
      table.workspaceId,
      table.remediationId,
      table.createdAt,
    ),
  ],
);

export const programMetricSnapshots = sqliteTable(
  "program_metric_snapshots",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    snapshotId: text("snapshot_id").notNull(),
    periodStart: text("period_start").notNull(),
    metrics: text("metrics").notNull().default("{}"),
    evidenceCoverage: integer("evidence_coverage").notNull().default(0),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("program_metric_snapshots_period_idx").on(
      table.workspaceId,
      table.periodStart,
    ),
  ],
);

export const awsAccountCatalog = sqliteTable(
  "aws_account_catalog",
  {
    accountId: text("account_id").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    accountName: text("account_name").notNull(),
    organizationalUnit: text("organizational_unit").notNull().default("Unassigned"),
    environment: text("environment").notNull().default("Shared"),
    businessUnit: text("business_unit").notNull().default("Unassigned"),
    owner: text("owner").notNull().default("Unassigned"),
    tags: text("tags").notNull().default("{}"),
    status: text("status").notNull().default("active"),
    lastSeenAt: text("last_seen_at").notNull().default(""),
    updatedBy: text("updated_by").notNull(),
    updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("aws_account_catalog_context_idx").on(
      table.workspaceId,
      table.organizationalUnit,
      table.environment,
    ),
  ],
);

export const evidenceCorrelationMappings = sqliteTable(
  "evidence_correlation_mappings",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    sourceIdentifier: text("source_identifier").notNull(),
    securityGroupArn: text("security_group_arn").notNull(),
    confidence: integer("confidence").notNull().default(100),
    reason: text("reason").notNull(),
    status: text("status").notNull().default("active"),
    createdBy: text("created_by").notNull(),
    revokedBy: text("revoked_by").notNull().default(""),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
    updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("evidence_correlation_source_idx").on(table.workspaceId, table.sourceIdentifier, table.status),
    index("evidence_correlation_group_idx").on(table.workspaceId, table.securityGroupArn, table.status),
  ],
);

export const evidenceMonitors = sqliteTable(
  "evidence_monitors",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    name: text("name").notNull(),
    query: text("query").notNull().default(""),
    filters: text("filters").notNull().default("{}"),
    groupBy: text("group_by").notNull().default("account"),
    schedule: text("schedule").notNull().default("daily"),
    triggerMode: text("trigger_mode").notNull().default("enters"),
    destinations: text("destinations").notNull().default("[]"),
    visibility: text("visibility").notNull().default("personal"),
    owner: text("owner").notNull(),
    status: text("status").notNull().default("active"),
    lastRunAt: text("last_run_at").notNull().default(""),
    nextRunAt: text("next_run_at").notNull().default(""),
    lastMatchCount: integer("last_match_count").notNull().default(0),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
    updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [index("evidence_monitors_schedule_idx").on(table.workspaceId, table.status, table.nextRunAt)],
);

export const evidenceMonitorRuns = sqliteTable(
  "evidence_monitor_runs",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    monitorId: text("monitor_id").notNull(),
    status: text("status").notNull(),
    matchCount: integer("match_count").notNull().default(0),
    enteredCount: integer("entered_count").notNull().default(0),
    exitedCount: integer("exited_count").notNull().default(0),
    summary: text("summary").notNull().default("{}"),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [index("evidence_monitor_runs_monitor_idx").on(table.workspaceId, table.monitorId, table.createdAt)],
);

export const evidenceExportJobs = sqliteTable(
  "evidence_export_jobs",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    name: text("name").notNull(),
    format: text("format").notNull(),
    scope: text("scope").notNull().default("{}"),
    schedule: text("schedule").notNull().default("once"),
    status: text("status").notNull().default("queued"),
    rowCount: integer("row_count").notNull().default(0),
    checksum: text("checksum").notNull().default(""),
    requestedBy: text("requested_by").notNull(),
    expiresAt: text("expires_at").notNull().default(""),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
    completedAt: text("completed_at").notNull().default(""),
  },
  (table) => [index("evidence_export_jobs_queue_idx").on(table.workspaceId, table.status, table.createdAt)],
);

export const evidenceRetentionPolicies = sqliteTable("evidence_retention_policies", {
  workspaceId: text("workspace_id").primaryKey().default("default"),
  rawEvidenceDays: integer("raw_evidence_days").notNull().default(400),
  normalizedEvidenceDays: integer("normalized_evidence_days").notNull().default(365),
  auditDays: integer("audit_days").notNull().default(2555),
  exportDays: integer("export_days").notNull().default(30),
  updatedBy: text("updated_by").notNull(),
  updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
});

export const evidenceLegalHolds = sqliteTable(
  "evidence_legal_holds",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    name: text("name").notNull(),
    scopeType: text("scope_type").notNull(),
    scopeValue: text("scope_value").notNull(),
    reason: text("reason").notNull(),
    status: text("status").notNull().default("active"),
    requestedBy: text("requested_by").notNull(),
    releasedBy: text("released_by").notNull().default(""),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
    releasedAt: text("released_at").notNull().default(""),
  },
  (table) => [index("evidence_legal_holds_status_idx").on(table.workspaceId, table.status, table.createdAt)],
);

export const riskScorePolicies = sqliteTable(
  "risk_score_policies",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    name: text("name").notNull(),
    status: text("status").notNull().default("draft"),
    weights: text("weights").notNull().default("{}"),
    thresholds: text("thresholds").notNull().default("{}"),
    createdBy: text("created_by").notNull(),
    updatedBy: text("updated_by").notNull(),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
    updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [index("risk_score_policies_status_idx").on(table.workspaceId, table.status, table.updatedAt)],
);

export const semanticEvidenceEvents = sqliteTable(
  "semantic_evidence_events",
  {
    fingerprint: text("fingerprint").primaryKey(),
    workspaceId: text("workspace_id").notNull().default("default"),
    canonicalEventId: text("canonical_event_id").notNull(),
    providerId: text("provider_id").notNull().default(""),
    sourceType: text("source_type").notNull(),
    securityGroupArn: text("security_group_arn").notNull(),
    observedAt: text("observed_at").notNull(),
    provenance: text("provenance").notNull().default("[]"),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("semantic_evidence_canonical_idx").on(table.workspaceId, table.canonicalEventId),
    index("semantic_evidence_group_time_idx").on(table.workspaceId, table.securityGroupArn, table.observedAt),
  ],
);
