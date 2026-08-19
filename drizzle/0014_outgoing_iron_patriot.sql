ALTER TABLE `ingestion_sources` ADD `provider` text DEFAULT 'aws-s3' NOT NULL;--> statement-breakpoint
ALTER TABLE `ingestion_sources` ADD `adx_cluster_url` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `ingestion_sources` ADD `adx_database` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `ingestion_sources` ADD `adx_table` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `ingestion_sources` ADD `adx_timestamp_column` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `ingestion_sources` ADD `adx_payload_column` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `ingestion_sources` ADD `adx_query_mode` text DEFAULT 'whole-row' NOT NULL;--> statement-breakpoint
ALTER TABLE `ingestion_sources` ADD `adx_batch_size` integer DEFAULT 500 NOT NULL;--> statement-breakpoint
ALTER TABLE `ingestion_sources` ADD `adx_tenant_id` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `ingestion_sources` ADD `adx_client_id` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `ingestion_sources` ADD `adx_cursor_value` text DEFAULT '' NOT NULL;