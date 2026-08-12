#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { splitPostgresSql } from "./lib/split-postgres-sql.mjs";

const profile = process.env.AWS_PROFILE || "personal";
const region = process.env.AWS_REGION || "us-east-1";
const stackName = process.env.GATEWATCH_PLATFORM_STACK_NAME || "gatewatch-production-platform";
const workspaceId = process.env.GATEWATCH_WORKSPACE_ID;

if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(workspaceId ?? "")) {
  throw new Error("Set GATEWATCH_WORKSPACE_ID to the immutable lowercase workspace UUID");
}

const aws = (...args) => JSON.parse(execFileSync("aws", [
  ...args,
  "--profile", profile,
  "--region", region,
  "--output", "json",
  "--no-cli-pager",
], { encoding: "utf8", maxBuffer: 20 * 1024 * 1024 }));

const outputs = aws(
  "cloudformation", "describe-stacks", "--stack-name", stackName,
  "--query", "Stacks[0].Outputs",
);
const output = (key) => outputs.find((item) => item.OutputKey === key)?.OutputValue ?? "";
const resourceArn = output("DatabaseClusterArn");
const secretArn = output("DatabaseSecretArn");
if (!resourceArn || !secretArn) throw new Error("Platform stack database outputs are unavailable");

const migrationFiles = [
  "db/postgres/0001_gatewatch_aws.sql",
  "db/postgres/0002_organization_operations.sql",
  "db/postgres/0003_finding_search.sql",
  "db/postgres/0004_bedrock_ai_analyst.sql",
  "db/postgres/0005_security_governance.sql",
];

for (const file of migrationFiles) {
  const statements = splitPostgresSql(readFileSync(resolve(file), "utf8"));
  const { transactionId } = aws(
    "rds-data", "begin-transaction",
    "--resource-arn", resourceArn,
    "--secret-arn", secretArn,
    "--database", "gatewatch",
  );
  try {
    if (file.endsWith("0001_gatewatch_aws.sql")) {
      aws(
        "rds-data", "execute-statement",
        "--resource-arn", resourceArn,
        "--secret-arn", secretArn,
        "--database", "gatewatch",
        "--transaction-id", transactionId,
        "--sql", `SELECT set_config('gatewatch.migration_workspace_id', '${workspaceId}', true)`,
      );
    }
    for (const sql of statements) {
      aws(
        "rds-data", "execute-statement",
        "--resource-arn", resourceArn,
        "--secret-arn", secretArn,
        "--database", "gatewatch",
        "--transaction-id", transactionId,
        "--sql", sql,
      );
    }
    aws(
      "rds-data", "commit-transaction",
      "--resource-arn", resourceArn,
      "--secret-arn", secretArn,
      "--transaction-id", transactionId,
    );
    process.stdout.write(`Applied ${file} (${statements.length} statements)\n`);
  } catch (error) {
    try {
      aws(
        "rds-data", "rollback-transaction",
        "--resource-arn", resourceArn,
        "--secret-arn", secretArn,
        "--transaction-id", transactionId,
      );
    } catch {
      // Preserve the original migration failure.
    }
    throw error;
  }
}

const verification = aws(
  "rds-data", "execute-statement",
  "--resource-arn", resourceArn,
  "--secret-arn", secretArn,
  "--database", "gatewatch",
  "--include-result-metadata",
  "--sql", `SELECT w.id::text AS workspace_id,
    bool_and(c.relrowsecurity AND c.relforcerowsecurity) AS all_workspace_tables_force_rls
    FROM workspaces w
    CROSS JOIN pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE w.slug = 'default' AND n.nspname = 'public' AND c.relkind IN ('r','p')
      AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'workspace_id' AND NOT a.attisdropped)
    GROUP BY w.id`,
);
process.stdout.write(`${JSON.stringify(verification.records)}\n`);
