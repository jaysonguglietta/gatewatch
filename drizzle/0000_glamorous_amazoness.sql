CREATE TABLE `security_group_reviews` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`security_group_id` text NOT NULL,
	`status` text DEFAULT 'needs-review' NOT NULL,
	`assignee` text DEFAULT 'Unassigned' NOT NULL,
	`note` text DEFAULT '' NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `security_group_reviews_security_group_id_unique` ON `security_group_reviews` (`security_group_id`);