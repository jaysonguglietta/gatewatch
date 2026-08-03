CREATE TABLE `finding_decision_details` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`fingerprint` text NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`status` text NOT NULL,
	`reason_code` text DEFAULT '' NOT NULL,
	`next_review_at` text DEFAULT '' NOT NULL,
	`approver` text DEFAULT '' NOT NULL,
	`resolution_evidence` text DEFAULT '' NOT NULL,
	`actor` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `finding_decision_details_history_idx` ON `finding_decision_details` (`workspace_id`,`fingerprint`,`created_at`);--> statement-breakpoint
CREATE TABLE `finding_undo_snapshots` (
	`token` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`actor` text NOT NULL,
	`state` text NOT NULL,
	`expires_at` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `finding_undo_snapshots_expiry_idx` ON `finding_undo_snapshots` (`expires_at`);--> statement-breakpoint
CREATE TABLE `finding_workflow_details` (
	`fingerprint` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`reason_code` text DEFAULT '' NOT NULL,
	`next_review_at` text DEFAULT '' NOT NULL,
	`approver` text DEFAULT '' NOT NULL,
	`resolution_evidence` text DEFAULT '' NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `finding_workflow_details_workspace_idx` ON `finding_workflow_details` (`workspace_id`,`updated_at`);--> statement-breakpoint
CREATE TABLE `saved_finding_view_visibility` (
	`view_id` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`visibility` text DEFAULT 'personal' NOT NULL,
	`created_by` text NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `saved_finding_view_visibility_idx` ON `saved_finding_view_visibility` (`workspace_id`,`visibility`);