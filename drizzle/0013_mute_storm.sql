CREATE TABLE `ai_analyses` (
	`id` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`fingerprint` text DEFAULT '' NOT NULL,
	`mode` text NOT NULL,
	`evidence_hash` text NOT NULL,
	`prompt_version` text NOT NULL,
	`schema_version` text NOT NULL,
	`source` text NOT NULL,
	`model_id` text DEFAULT '' NOT NULL,
	`result_json` text NOT NULL,
	`input_tokens` integer DEFAULT 0 NOT NULL,
	`output_tokens` integer DEFAULT 0 NOT NULL,
	`latency_ms` integer DEFAULT 0 NOT NULL,
	`guardrail_action` text DEFAULT '' NOT NULL,
	`guardrail_trace_id` text DEFAULT '' NOT NULL,
	`generated_by` text NOT NULL,
	`generated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`expires_at` text NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `ai_analyses_cache_idx` ON `ai_analyses` (`workspace_id`,`mode`,`evidence_hash`,`prompt_version`);--> statement-breakpoint
CREATE INDEX `ai_analyses_finding_idx` ON `ai_analyses` (`workspace_id`,`fingerprint`,`generated_at`);--> statement-breakpoint
CREATE TABLE `ai_feedback` (
	`id` text PRIMARY KEY NOT NULL,
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`analysis_id` text NOT NULL,
	`rating` text NOT NULL,
	`reason` text DEFAULT '' NOT NULL,
	`actor` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `ai_feedback_actor_idx` ON `ai_feedback` (`workspace_id`,`analysis_id`,`actor`);--> statement-breakpoint
CREATE TABLE `ai_usage_daily` (
	`workspace_id` text DEFAULT 'default' NOT NULL,
	`usage_date` text NOT NULL,
	`actor` text NOT NULL,
	`requests` integer DEFAULT 0 NOT NULL,
	`input_tokens` integer DEFAULT 0 NOT NULL,
	`output_tokens` integer DEFAULT 0 NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `ai_usage_daily_actor_idx` ON `ai_usage_daily` (`workspace_id`,`usage_date`,`actor`);--> statement-breakpoint
CREATE INDEX `finding_observations_temporal_idx` ON `finding_observations` (`workspace_id`,`state`,`last_seen_at`,`observation_count`);