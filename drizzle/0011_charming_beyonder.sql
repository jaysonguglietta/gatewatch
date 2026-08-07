CREATE TABLE `aws_account_catalog` (
	`account_id` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`account_name` text NOT NULL,
	`organizational_unit` text DEFAULT 'Unassigned' NOT NULL,
	`environment` text DEFAULT 'Shared' NOT NULL,
	`business_unit` text DEFAULT 'Unassigned' NOT NULL,
	`owner` text DEFAULT 'Unassigned' NOT NULL,
	`tags` text DEFAULT '{}' NOT NULL,
	`status` text DEFAULT 'active' NOT NULL,
	`last_seen_at` text DEFAULT '' NOT NULL,
	`updated_by` text NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `aws_account_catalog_context_idx` ON `aws_account_catalog` (`workspace_id`,`organizational_unit`,`environment`);--> statement-breakpoint
CREATE TABLE `evidence_correlation_mappings` (
	`id` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`source_identifier` text NOT NULL,
	`security_group_arn` text NOT NULL,
	`confidence` integer DEFAULT 100 NOT NULL,
	`reason` text NOT NULL,
	`status` text DEFAULT 'active' NOT NULL,
	`created_by` text NOT NULL,
	`revoked_by` text DEFAULT '' NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `evidence_correlation_source_idx` ON `evidence_correlation_mappings` (`workspace_id`,`source_identifier`,`status`);--> statement-breakpoint
CREATE INDEX `evidence_correlation_group_idx` ON `evidence_correlation_mappings` (`workspace_id`,`security_group_arn`,`status`);--> statement-breakpoint
CREATE TABLE `evidence_export_jobs` (
	`id` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`name` text NOT NULL,
	`format` text NOT NULL,
	`scope` text DEFAULT '{}' NOT NULL,
	`schedule` text DEFAULT 'once' NOT NULL,
	`status` text DEFAULT 'queued' NOT NULL,
	`row_count` integer DEFAULT 0 NOT NULL,
	`checksum` text DEFAULT '' NOT NULL,
	`requested_by` text NOT NULL,
	`expires_at` text DEFAULT '' NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`completed_at` text DEFAULT '' NOT NULL
);
--> statement-breakpoint
CREATE INDEX `evidence_export_jobs_queue_idx` ON `evidence_export_jobs` (`workspace_id`,`status`,`created_at`);--> statement-breakpoint
CREATE TABLE `evidence_legal_holds` (
	`id` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`name` text NOT NULL,
	`scope_type` text NOT NULL,
	`scope_value` text NOT NULL,
	`reason` text NOT NULL,
	`status` text DEFAULT 'active' NOT NULL,
	`requested_by` text NOT NULL,
	`released_by` text DEFAULT '' NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`released_at` text DEFAULT '' NOT NULL
);
--> statement-breakpoint
CREATE INDEX `evidence_legal_holds_status_idx` ON `evidence_legal_holds` (`workspace_id`,`status`,`created_at`);--> statement-breakpoint
CREATE TABLE `evidence_monitor_runs` (
	`id` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`monitor_id` text NOT NULL,
	`status` text NOT NULL,
	`match_count` integer DEFAULT 0 NOT NULL,
	`entered_count` integer DEFAULT 0 NOT NULL,
	`exited_count` integer DEFAULT 0 NOT NULL,
	`summary` text DEFAULT '{}' NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `evidence_monitor_runs_monitor_idx` ON `evidence_monitor_runs` (`workspace_id`,`monitor_id`,`created_at`);--> statement-breakpoint
CREATE TABLE `evidence_monitors` (
	`id` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`name` text NOT NULL,
	`query` text DEFAULT '' NOT NULL,
	`filters` text DEFAULT '{}' NOT NULL,
	`group_by` text DEFAULT 'account' NOT NULL,
	`schedule` text DEFAULT 'daily' NOT NULL,
	`trigger_mode` text DEFAULT 'enters' NOT NULL,
	`destinations` text DEFAULT '[]' NOT NULL,
	`visibility` text DEFAULT 'personal' NOT NULL,
	`owner` text NOT NULL,
	`status` text DEFAULT 'active' NOT NULL,
	`last_run_at` text DEFAULT '' NOT NULL,
	`next_run_at` text DEFAULT '' NOT NULL,
	`last_match_count` integer DEFAULT 0 NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `evidence_monitors_schedule_idx` ON `evidence_monitors` (`workspace_id`,`status`,`next_run_at`);--> statement-breakpoint
CREATE TABLE `evidence_retention_policies` (
	`workspace_id` text PRIMARY KEY DEFAULT 'default' NOT NULL,
	`raw_evidence_days` integer DEFAULT 400 NOT NULL,
	`normalized_evidence_days` integer DEFAULT 365 NOT NULL,
	`audit_days` integer DEFAULT 2555 NOT NULL,
	`export_days` integer DEFAULT 30 NOT NULL,
	`updated_by` text NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE TABLE `risk_score_policies` (
	`id` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`name` text NOT NULL,
	`status` text DEFAULT 'draft' NOT NULL,
	`weights` text DEFAULT '{}' NOT NULL,
	`thresholds` text DEFAULT '{}' NOT NULL,
	`created_by` text NOT NULL,
	`updated_by` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `risk_score_policies_status_idx` ON `risk_score_policies` (`workspace_id`,`status`,`updated_at`);--> statement-breakpoint
CREATE TABLE `semantic_evidence_events` (
	`fingerprint` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`canonical_event_id` text NOT NULL,
	`provider_id` text DEFAULT '' NOT NULL,
	`source_type` text NOT NULL,
	`security_group_arn` text NOT NULL,
	`observed_at` text NOT NULL,
	`provenance` text DEFAULT '[]' NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `semantic_evidence_canonical_idx` ON `semantic_evidence_events` (`workspace_id`,`canonical_event_id`);--> statement-breakpoint
CREATE INDEX `semantic_evidence_group_time_idx` ON `semantic_evidence_events` (`workspace_id`,`security_group_arn`,`observed_at`);