CREATE TABLE `product_workflow_records` (
	`id` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`kind` text NOT NULL,
	`subject_id` text NOT NULL,
	`status` text NOT NULL,
	`owner` text DEFAULT 'Unassigned' NOT NULL,
	`note` text DEFAULT '' NOT NULL,
	`ticket_ref` text DEFAULT '' NOT NULL,
	`expires_at` text DEFAULT '' NOT NULL,
	`payload` text DEFAULT '{}' NOT NULL,
	`created_by` text NOT NULL,
	`updated_by` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `product_workflows_kind_status_idx` ON `product_workflow_records` (`workspace_id`,`kind`,`status`);--> statement-breakpoint
CREATE INDEX `product_workflows_subject_idx` ON `product_workflow_records` (`workspace_id`,`subject_id`);