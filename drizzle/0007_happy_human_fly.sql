CREATE TABLE `finding_events` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`fingerprint` text NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`event_type` text NOT NULL,
	`from_status` text DEFAULT '' NOT NULL,
	`to_status` text NOT NULL,
	`actor` text NOT NULL,
	`assignee` text DEFAULT 'Unassigned' NOT NULL,
	`note` text DEFAULT '' NOT NULL,
	`ticket_ref` text DEFAULT '' NOT NULL,
	`due_at` text DEFAULT '' NOT NULL,
	`expires_at` text DEFAULT '' NOT NULL,
	`compensating_controls` text DEFAULT '[]' NOT NULL,
	`evidence_snapshot` text DEFAULT '' NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `finding_events_history_idx` ON `finding_events` (`workspace_id`,`fingerprint`,`created_at`);--> statement-breakpoint
CREATE TABLE `finding_workflows` (
	`fingerprint` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`security_group_id` text NOT NULL,
	`finding_key` text NOT NULL,
	`status` text DEFAULT 'new' NOT NULL,
	`assignee` text DEFAULT 'Unassigned' NOT NULL,
	`note` text DEFAULT '' NOT NULL,
	`ticket_ref` text DEFAULT '' NOT NULL,
	`due_at` text DEFAULT '' NOT NULL,
	`expires_at` text DEFAULT '' NOT NULL,
	`compensating_controls` text DEFAULT '[]' NOT NULL,
	`evidence_snapshot` text DEFAULT '' NOT NULL,
	`reviewer` text NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `finding_workflows_queue_idx` ON `finding_workflows` (`workspace_id`,`status`,`updated_at`);--> statement-breakpoint
CREATE INDEX `finding_workflows_group_idx` ON `finding_workflows` (`workspace_id`,`security_group_id`);--> statement-breakpoint
CREATE TABLE `saved_finding_views` (
	`id` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`owner` text NOT NULL,
	`name` text NOT NULL,
	`filters` text DEFAULT '{}' NOT NULL,
	`is_default` integer DEFAULT false NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `saved_finding_views_owner_idx` ON `saved_finding_views` (`workspace_id`,`owner`,`updated_at`);