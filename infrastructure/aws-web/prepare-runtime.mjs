import { readFile, writeFile } from "node:fs/promises";

const source = new URL("../../dist/server/wrangler.json", import.meta.url);
const destination = new URL("../../dist/server/wrangler.aws.json", import.meta.url);
const configuration = JSON.parse(await readFile(source, "utf8"));

configuration.vars = {
  ...configuration.vars,
  GATEWATCH_AWS_RUNTIME: process.env.GATEWATCH_AWS_RUNTIME ?? "true",
  GATEWATCH_AWS_BRIDGE_URL:
    process.env.GATEWATCH_AWS_BRIDGE_URL ?? "http://gatewatch-aws-bridge:3001",
  GATEWATCH_AWS_BRIDGE_TOKEN: process.env.GATEWATCH_AWS_BRIDGE_TOKEN ?? "",
  GATEWATCH_BOOTSTRAP_ADMIN_EMAIL:
    process.env.GATEWATCH_BOOTSTRAP_ADMIN_EMAIL ?? "",
  GATEWATCH_SNAPSHOT_BUCKET: process.env.GATEWATCH_SNAPSHOT_BUCKET ?? "",
  GATEWATCH_SNAPSHOT_KEY:
    process.env.GATEWATCH_SNAPSHOT_KEY ?? "exports/latest.json",
  GATEWATCH_SNAPSHOT_REGION:
    process.env.GATEWATCH_SNAPSHOT_REGION ?? process.env.AWS_REGION ?? "us-east-1",
  GATEWATCH_JIRA_SECRET_ARN:
    process.env.GATEWATCH_JIRA_SECRET_ARN ?? "",
};

await writeFile(destination, `${JSON.stringify(configuration)}\n`, "utf8");
