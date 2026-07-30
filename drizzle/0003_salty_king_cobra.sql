ALTER TABLE `security_group_review_events` ADD `reviewer` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `security_group_reviews` ADD `reviewer` text DEFAULT '' NOT NULL;