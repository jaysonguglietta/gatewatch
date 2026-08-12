interface Fetcher {
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}

interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  run(): Promise<unknown>;
  all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
  first<T = Record<string, unknown>>(): Promise<T | null>;
}

interface D1Database {
  prepare(query: string): D1PreparedStatement;
  batch(
    statements: D1PreparedStatement[],
  ): Promise<Array<{ results: Record<string, unknown>[] }>>;
}

declare module "cloudflare:workers" {
  export const env: {
    DB: D1Database;
    GATEWATCH_BOOTSTRAP_ADMIN_EMAIL?: string;
    GATEWATCH_AWS_RUNTIME?: string;
    GATEWATCH_AWS_BRIDGE_URL?: string;
    GATEWATCH_AWS_BRIDGE_TOKEN?: string;
    GATEWATCH_SNAPSHOT_BUCKET?: string;
    GATEWATCH_SNAPSHOT_KEY?: string;
    GATEWATCH_SNAPSHOT_MANIFEST_KEY?: string;
    GATEWATCH_SNAPSHOT_REGION?: string;
    GATEWATCH_ORGANIZATION_EVIDENCE_BUCKET?: string;
    GATEWATCH_ORGANIZATION_MANIFEST_KEY?: string;
    GATEWATCH_JIRA_SECRET_ARN?: string;
    GATEWATCH_IAC_WEBHOOK_TOKEN?: string;
    GATEWATCH_BEDROCK_ENABLED?: string;
    GATEWATCH_BEDROCK_MODEL_ID?: string;
    GATEWATCH_BEDROCK_GUARDRAIL_ID?: string;
    GATEWATCH_BEDROCK_GUARDRAIL_VERSION?: string;
  };
}
