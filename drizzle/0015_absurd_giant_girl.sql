CREATE TABLE `ingestion_source_alerts` (
	`id` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`source_id` text NOT NULL,
	`alert_type` text NOT NULL,
	`status` text DEFAULT 'open' NOT NULL,
	`severity` text DEFAULT 'high' NOT NULL,
	`summary` text NOT NULL,
	`first_observed_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`last_observed_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`resolved_at` text DEFAULT '' NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `ingestion_source_alerts_identity_unique` ON `ingestion_source_alerts` (`workspace_id`,`source_id`,`alert_type`);--> statement-breakpoint
CREATE INDEX `ingestion_source_alerts_status_idx` ON `ingestion_source_alerts` (`workspace_id`,`status`);--> statement-breakpoint
ALTER TABLE `ingestion_sources` ADD `adx_auth_mode` text DEFAULT 'federated' NOT NULL;--> statement-breakpoint
UPDATE `ingestion_sources` SET `adx_auth_mode` = 'client-secret' WHERE `provider` = 'azure-data-explorer';--> statement-breakpoint
ALTER TABLE `ingestion_sources` ADD `adx_schema` text DEFAULT '{}' NOT NULL;--> statement-breakpoint
ALTER TABLE `ingestion_sources` ADD `adx_schema_discovered_at` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `ingestion_sources` ADD `adx_mapping_validated_at` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `ingestion_sources` ADD `adx_lease_owner` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `ingestion_sources` ADD `adx_lease_expires_at` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `ingestion_sources` ADD `freshness_sla_minutes` integer DEFAULT 30 NOT NULL;--> statement-breakpoint
ALTER TABLE `ingestion_sources` ADD `freshness_status` text DEFAULT 'unknown' NOT NULL;--> statement-breakpoint
ALTER TABLE `ingestion_sources` ADD `freshness_checked_at` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `ingestion_sources` ADD `freshness_lag_minutes` integer DEFAULT 0 NOT NULL;
