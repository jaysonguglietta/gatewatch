CREATE TABLE `audit_events` (
	`id` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`actor` text NOT NULL,
	`action` text NOT NULL,
	`target_type` text NOT NULL,
	`target_id` text NOT NULL,
	`summary` text NOT NULL,
	`metadata` text DEFAULT '{}' NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `audit_events_workspace_created_idx` ON `audit_events` (`workspace_id`,`created_at`);--> statement-breakpoint
CREATE TABLE `config_items` (
	`id` text PRIMARY KEY NOT NULL,
	`source_id` text NOT NULL,
	`account_id` text NOT NULL,
	`region` text NOT NULL,
	`resource_type` text NOT NULL,
	`resource_id` text NOT NULL,
	`resource_arn` text DEFAULT '' NOT NULL,
	`configuration_state_id` text DEFAULT '' NOT NULL,
	`capture_time` text NOT NULL,
	`status` text NOT NULL,
	`normalized_configuration` text NOT NULL,
	`raw_object_id` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `config_items_resource_capture_idx` ON `config_items` (`resource_id`,`capture_time`);--> statement-breakpoint
CREATE INDEX `config_items_account_region_idx` ON `config_items` (`account_id`,`region`);--> statement-breakpoint
CREATE TABLE `ingested_objects` (
	`id` text PRIMARY KEY NOT NULL,
	`source_id` text NOT NULL,
	`bucket_name` text NOT NULL,
	`object_key` text NOT NULL,
	`version_id` text DEFAULT '' NOT NULL,
	`etag` text DEFAULT '' NOT NULL,
	`status` text NOT NULL,
	`object_size` integer DEFAULT 0 NOT NULL,
	`record_count` integer DEFAULT 0 NOT NULL,
	`checksum` text DEFAULT '' NOT NULL,
	`failure_code` text DEFAULT '' NOT NULL,
	`failure_detail` text DEFAULT '' NOT NULL,
	`first_seen_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`processed_at` text DEFAULT '' NOT NULL
);
--> statement-breakpoint
CREATE INDEX `ingested_objects_source_status_idx` ON `ingested_objects` (`source_id`,`status`);--> statement-breakpoint
CREATE INDEX `ingested_objects_identity_idx` ON `ingested_objects` (`source_id`,`object_key`,`version_id`);--> statement-breakpoint
CREATE TABLE `ingestion_runs` (
	`id` text PRIMARY KEY NOT NULL,
	`source_id` text NOT NULL,
	`run_type` text NOT NULL,
	`status` text NOT NULL,
	`discovered_objects` integer DEFAULT 0 NOT NULL,
	`processed_objects` integer DEFAULT 0 NOT NULL,
	`failed_objects` integer DEFAULT 0 NOT NULL,
	`parsed_records` integer DEFAULT 0 NOT NULL,
	`finding_changes` integer DEFAULT 0 NOT NULL,
	`cursor` text DEFAULT '' NOT NULL,
	`error_summary` text DEFAULT '' NOT NULL,
	`requested_by` text NOT NULL,
	`started_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`completed_at` text DEFAULT '' NOT NULL
);
--> statement-breakpoint
CREATE INDEX `ingestion_runs_source_started_idx` ON `ingestion_runs` (`source_id`,`started_at`);--> statement-breakpoint
CREATE TABLE `ingestion_sources` (
	`id` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`name` text NOT NULL,
	`source_type` text NOT NULL,
	`bucket_arn` text NOT NULL,
	`bucket_name` text NOT NULL,
	`region` text NOT NULL,
	`object_prefix` text DEFAULT '' NOT NULL,
	`role_arn` text NOT NULL,
	`external_id` text NOT NULL,
	`kms_key_arn` text DEFAULT '' NOT NULL,
	`organization_id` text DEFAULT '' NOT NULL,
	`ingestion_mode` text DEFAULT 'continuous' NOT NULL,
	`backfill_start` text DEFAULT '' NOT NULL,
	`included_accounts` text DEFAULT '[]' NOT NULL,
	`excluded_accounts` text DEFAULT '[]' NOT NULL,
	`included_regions` text DEFAULT '[]' NOT NULL,
	`config_resource_types` text DEFAULT '[]' NOT NULL,
	`retention_days` integer DEFAULT 365 NOT NULL,
	`status` text DEFAULT 'draft' NOT NULL,
	`test_summary` text DEFAULT '{}' NOT NULL,
	`last_tested_at` text DEFAULT '' NOT NULL,
	`last_successful_object_at` text DEFAULT '' NOT NULL,
	`created_by` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `ingestion_sources_workspace_status_idx` ON `ingestion_sources` (`workspace_id`,`status`);--> statement-breakpoint
CREATE INDEX `ingestion_sources_bucket_idx` ON `ingestion_sources` (`bucket_name`,`object_prefix`);--> statement-breakpoint
CREATE TABLE `normalized_cloudtrail_events` (
	`event_id` text PRIMARY KEY NOT NULL,
	`source_id` text NOT NULL,
	`account_id` text NOT NULL,
	`region` text NOT NULL,
	`security_group_id` text DEFAULT '' NOT NULL,
	`event_name` text NOT NULL,
	`event_time` text NOT NULL,
	`actor_arn` text DEFAULT '' NOT NULL,
	`source_ip` text DEFAULT '' NOT NULL,
	`successful` integer DEFAULT 1 NOT NULL,
	`normalized_payload` text NOT NULL,
	`raw_object_id` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `cloudtrail_events_group_time_idx` ON `normalized_cloudtrail_events` (`security_group_id`,`event_time`);--> statement-breakpoint
CREATE INDEX `cloudtrail_events_account_region_idx` ON `normalized_cloudtrail_events` (`account_id`,`region`);--> statement-breakpoint
CREATE TABLE `system_settings` (
	`key` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`value` text NOT NULL,
	`updated_by` text NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE TABLE `user_roles` (
	`email` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`role` text DEFAULT 'viewer' NOT NULL,
	`created_by` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `user_roles_workspace_role_idx` ON `user_roles` (`workspace_id`,`role`);