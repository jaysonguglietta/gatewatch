CREATE TABLE `security_group_review_events` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`security_group_id` text NOT NULL,
	`status` text NOT NULL,
	`assignee` text NOT NULL,
	`note` text NOT NULL,
	`ticket_ref` text DEFAULT '' NOT NULL,
	`expires_at` text DEFAULT '' NOT NULL,
	`evidence_snapshot` text DEFAULT '' NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
ALTER TABLE `security_group_reviews` ADD `ticket_ref` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `security_group_reviews` ADD `expires_at` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `security_group_reviews` ADD `evidence_snapshot` text DEFAULT '' NOT NULL;