CREATE TABLE `access_policy_versions` (
	`id` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`policy_id` text NOT NULL,
	`version` integer NOT NULL,
	`status` text DEFAULT 'draft' NOT NULL,
	`yaml` text NOT NULL,
	`evaluation` text DEFAULT '{}' NOT NULL,
	`created_by` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `access_policy_versions_policy_idx` ON `access_policy_versions` (`workspace_id`,`policy_id`,`version`);--> statement-breakpoint
CREATE TABLE `campaign_items` (
	`id` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`campaign_id` text NOT NULL,
	`fingerprint` text NOT NULL,
	`owner` text NOT NULL,
	`status` text DEFAULT 'pending' NOT NULL,
	`decision` text DEFAULT '' NOT NULL,
	`note` text DEFAULT '' NOT NULL,
	`evidence_snapshot` text DEFAULT '{}' NOT NULL,
	`decided_by` text DEFAULT '' NOT NULL,
	`decided_at` text DEFAULT '' NOT NULL
);
--> statement-breakpoint
CREATE INDEX `campaign_items_campaign_status_idx` ON `campaign_items` (`workspace_id`,`campaign_id`,`status`);--> statement-breakpoint
CREATE TABLE `finding_jira_links` (
	`fingerprint` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`issue_key` text NOT NULL,
	`issue_url` text NOT NULL,
	`remote_status` text DEFAULT '' NOT NULL,
	`remote_resolution` text DEFAULT '' NOT NULL,
	`remote_updated_at` text DEFAULT '' NOT NULL,
	`last_synced_at` text DEFAULT '' NOT NULL,
	`created_by` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `finding_jira_links_issue_unique` ON `finding_jira_links` (`workspace_id`,`issue_key`);--> statement-breakpoint
CREATE TABLE `finding_observations` (
	`id` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`fingerprint` text NOT NULL,
	`legacy_fingerprint` text DEFAULT '' NOT NULL,
	`canonical_resource_key` text NOT NULL,
	`first_seen_at` text NOT NULL,
	`last_seen_at` text NOT NULL,
	`last_snapshot_id` text NOT NULL,
	`state` text DEFAULT 'active' NOT NULL,
	`observation_count` integer DEFAULT 1 NOT NULL,
	`resolved_at` text DEFAULT '' NOT NULL,
	`evidence_snapshot` text DEFAULT '{}' NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `finding_observations_workspace_fingerprint_unique` ON `finding_observations` (`workspace_id`,`fingerprint`);--> statement-breakpoint
CREATE INDEX `finding_observations_resource_state_idx` ON `finding_observations` (`workspace_id`,`canonical_resource_key`,`state`);--> statement-breakpoint
CREATE TABLE `integration_deliveries` (
	`id` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`integration` text NOT NULL,
	`event_type` text NOT NULL,
	`target_id` text NOT NULL,
	`status` text DEFAULT 'pending' NOT NULL,
	`attempts` integer DEFAULT 0 NOT NULL,
	`payload` text DEFAULT '{}' NOT NULL,
	`last_error` text DEFAULT '' NOT NULL,
	`next_attempt_at` text DEFAULT '' NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `integration_deliveries_queue_idx` ON `integration_deliveries` (`workspace_id`,`status`,`next_attempt_at`);--> statement-breakpoint
CREATE TABLE `program_metric_snapshots` (
	`id` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`snapshot_id` text NOT NULL,
	`period_start` text NOT NULL,
	`metrics` text DEFAULT '{}' NOT NULL,
	`evidence_coverage` integer DEFAULT 0 NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `program_metric_snapshots_period_idx` ON `program_metric_snapshots` (`workspace_id`,`period_start`);--> statement-breakpoint
CREATE TABLE `remediation_requests` (
	`id` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`fingerprint` text NOT NULL,
	`canonical_resource_key` text NOT NULL,
	`status` text DEFAULT 'draft' NOT NULL,
	`proposed_change` text NOT NULL,
	`artifact_type` text DEFAULT 'json' NOT NULL,
	`external_ref` text DEFAULT '' NOT NULL,
	`evidence_before` text DEFAULT '{}' NOT NULL,
	`evidence_after` text DEFAULT '{}' NOT NULL,
	`requested_by` text NOT NULL,
	`approved_by` text DEFAULT '' NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `remediation_requests_queue_idx` ON `remediation_requests` (`workspace_id`,`status`,`updated_at`);--> statement-breakpoint
CREATE TABLE `resource_review_events` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`resource_key` text NOT NULL,
	`security_group_id` text NOT NULL,
	`status` text NOT NULL,
	`assignee` text NOT NULL,
	`reviewer` text NOT NULL,
	`note` text NOT NULL,
	`ticket_ref` text DEFAULT '' NOT NULL,
	`expires_at` text DEFAULT '' NOT NULL,
	`evidence_snapshot` text DEFAULT '{}' NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `resource_review_events_history_idx` ON `resource_review_events` (`workspace_id`,`resource_key`,`created_at`);--> statement-breakpoint
CREATE TABLE `resource_reviews` (
	`resource_key` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`security_group_id` text NOT NULL,
	`account_id` text NOT NULL,
	`region` text NOT NULL,
	`vpc_id` text NOT NULL,
	`status` text DEFAULT 'needs-review' NOT NULL,
	`assignee` text DEFAULT 'Unassigned' NOT NULL,
	`reviewer` text DEFAULT '' NOT NULL,
	`note` text DEFAULT '' NOT NULL,
	`ticket_ref` text DEFAULT '' NOT NULL,
	`expires_at` text DEFAULT '' NOT NULL,
	`evidence_snapshot` text DEFAULT '{}' NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `resource_reviews_workspace_status_idx` ON `resource_reviews` (`workspace_id`,`status`,`updated_at`);--> statement-breakpoint
CREATE TABLE `verification_runs` (
	`id` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`remediation_id` text NOT NULL,
	`snapshot_id` text NOT NULL,
	`status` text NOT NULL,
	`result` text DEFAULT '{}' NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `verification_runs_remediation_idx` ON `verification_runs` (`workspace_id`,`remediation_id`,`created_at`);