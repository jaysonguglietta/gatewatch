CREATE TABLE `aws_evidence_records` (
	`fingerprint` text PRIMARY KEY NOT NULL,
	`source_id` text NOT NULL,
	`raw_object_id` text NOT NULL,
	`source_type` text NOT NULL,
	`evidence_class` text NOT NULL,
	`observed_at` text DEFAULT '' NOT NULL,
	`account_id` text DEFAULT '' NOT NULL,
	`region` text DEFAULT '' NOT NULL,
	`resource_type` text DEFAULT '' NOT NULL,
	`resource_id` text DEFAULT '' NOT NULL,
	`event_name` text DEFAULT '' NOT NULL,
	`disposition` text DEFAULT '' NOT NULL,
	`normalized_payload` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `aws_evidence_source_time_idx` ON `aws_evidence_records` (`source_id`,`observed_at`);--> statement-breakpoint
CREATE INDEX `aws_evidence_resource_time_idx` ON `aws_evidence_records` (`account_id`,`region`,`resource_id`,`observed_at`);