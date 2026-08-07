DROP INDEX `aws_evidence_source_time_idx`;--> statement-breakpoint
DROP INDEX `aws_evidence_resource_time_idx`;--> statement-breakpoint
ALTER TABLE `aws_evidence_records` ADD `workspace_id` text DEFAULT 'default' NOT NULL;--> statement-breakpoint
CREATE INDEX `aws_evidence_source_time_idx` ON `aws_evidence_records` (`workspace_id`,`source_id`,`observed_at`);--> statement-breakpoint
CREATE INDEX `aws_evidence_resource_time_idx` ON `aws_evidence_records` (`workspace_id`,`account_id`,`region`,`resource_id`,`observed_at`);