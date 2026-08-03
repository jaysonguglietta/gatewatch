import { env } from "cloudflare:workers";

export type OrganizationCoverageAccount = {
  accountId: string;
  accountName: string;
  status: "succeeded" | "partial" | "failed" | "incomplete";
  regionsExpected: number;
  regionsSucceeded: number;
  regionsFailed: number;
  errorCode: string;
  completedAt: string;
};

export type OrganizationCoverageTarget = {
  accountId: string;
  accountName: string;
  region: string;
  status: "succeeded" | "failed" | "incomplete";
  completedAt: string;
  objectKey: string;
  checksumSha256: string;
  securityGroupCount: number;
  securityGroupRuleCount: number;
  networkInterfaceCount: number;
  errorCode: string;
};

export type OrganizationCoverage = {
  schemaVersion: "2.0";
  evidenceType: "organization-collection-manifest";
  runId: string;
  status: "succeeded" | "partial" | "failed";
  complete: boolean;
  startedAt: string;
  completedAt: string;
  coveragePercent: number;
  summary: {
    accountsExpected: number;
    accountsSucceeded: number;
    accountsPartial: number;
    accountsFailed: number;
    accountsIncomplete: number;
    regionsExpected: number;
    regionsSucceeded: number;
    regionsFailed: number;
    regionsIncomplete: number;
    securityGroupCount: number;
    securityGroupRuleCount: number;
    networkInterfaceCount: number;
  };
  accounts: OrganizationCoverageAccount[];
  targets: OrganizationCoverageTarget[];
};

const MAX_MANIFEST_BYTES = 8 * 1024 * 1024;

function boundedText(value: unknown, maximum = 1024) {
  return typeof value === "string" ? value.slice(0, maximum) : "";
}

function boundedInteger(value: unknown, maximum = 500_000_000) {
  const number = Number(value ?? 0);
  return Number.isSafeInteger(number) && number >= 0
    ? Math.min(number, maximum)
    : 0;
}

function status<T extends string>(value: unknown, allowed: readonly T[], fallback: T) {
  return allowed.includes(value as T) ? (value as T) : fallback;
}

function normalizeCoverage(value: unknown): OrganizationCoverage {
  if (!value || typeof value !== "object") throw new Error("INVALID_COVERAGE_MANIFEST");
  const manifest = value as Record<string, unknown>;
  if (
    manifest.schemaVersion !== "2.0"
    || manifest.evidenceType !== "organization-collection-manifest"
    || !Array.isArray(manifest.accounts)
    || !Array.isArray(manifest.targets)
    || manifest.accounts.length > 10_000
    || manifest.targets.length > 50_000
  ) {
    throw new Error("INVALID_COVERAGE_MANIFEST_SCHEMA");
  }
  const rawSummary = (manifest.summary ?? {}) as Record<string, unknown>;
  const summary = {
    accountsExpected: boundedInteger(rawSummary.accountsExpected, 100_000),
    accountsSucceeded: boundedInteger(rawSummary.accountsSucceeded, 100_000),
    accountsPartial: boundedInteger(rawSummary.accountsPartial, 100_000),
    accountsFailed: boundedInteger(rawSummary.accountsFailed, 100_000),
    accountsIncomplete: boundedInteger(rawSummary.accountsIncomplete, 100_000),
    regionsExpected: boundedInteger(rawSummary.regionsExpected, 1_000_000),
    regionsSucceeded: boundedInteger(rawSummary.regionsSucceeded, 1_000_000),
    regionsFailed: boundedInteger(rawSummary.regionsFailed, 1_000_000),
    regionsIncomplete: boundedInteger(rawSummary.regionsIncomplete, 1_000_000),
    securityGroupCount: boundedInteger(rawSummary.securityGroupCount),
    securityGroupRuleCount: boundedInteger(rawSummary.securityGroupRuleCount),
    networkInterfaceCount: boundedInteger(rawSummary.networkInterfaceCount),
  };
  const accountStates = ["succeeded", "partial", "failed", "incomplete"] as const;
  const targetStates = ["succeeded", "failed", "incomplete"] as const;
  return {
    schemaVersion: "2.0",
    evidenceType: "organization-collection-manifest",
    runId: boundedText(manifest.runId, 64),
    status: status(manifest.status, accountStates, "failed"),
    complete: manifest.complete === true,
    startedAt: boundedText(manifest.startedAt, 64),
    completedAt: boundedText(manifest.completedAt, 64),
    coveragePercent: Math.max(0, Math.min(100, boundedInteger(manifest.coveragePercent, 100))),
    summary,
    accounts: manifest.accounts.map((candidate) => {
      const account = (candidate ?? {}) as Record<string, unknown>;
      return {
        accountId: boundedText(account.accountId, 12),
        accountName: boundedText(account.accountName, 160),
        status: status(account.status, accountStates, "failed"),
        regionsExpected: boundedInteger(account.regionsExpected, 1000),
        regionsSucceeded: boundedInteger(account.regionsSucceeded, 1000),
        regionsFailed: boundedInteger(account.regionsFailed, 1000),
        errorCode: boundedText(account.errorCode, 120),
        completedAt: boundedText(account.completedAt, 64),
      };
    }),
    targets: manifest.targets.map((candidate) => {
      const target = (candidate ?? {}) as Record<string, unknown>;
      return {
        accountId: boundedText(target.accountId, 12),
        accountName: boundedText(target.accountName, 160),
        region: boundedText(target.region, 40),
        status: status(target.status, targetStates, "failed"),
        completedAt: boundedText(target.completedAt, 64),
        objectKey: boundedText(target.objectKey, 1024),
        checksumSha256: boundedText(target.checksumSha256, 64),
        securityGroupCount: boundedInteger(target.securityGroupCount, 100_000),
        securityGroupRuleCount: boundedInteger(target.securityGroupRuleCount, 1_000_000),
        networkInterfaceCount: boundedInteger(target.networkInterfaceCount, 10_000_000),
        errorCode: boundedText(target.errorCode, 120),
      };
    }),
  };
}

export async function loadOrganizationCoverage(): Promise<OrganizationCoverage> {
  const bridgeUrl = boundedText(env.GATEWATCH_AWS_BRIDGE_URL, 500).replace(/\/$/, "");
  const bridgeToken = boundedText(env.GATEWATCH_AWS_BRIDGE_TOKEN, 500);
  if (!bridgeUrl || !bridgeToken) throw new Error("AWS_BRIDGE_NOT_CONFIGURED");
  const response = await fetch(`${bridgeUrl}/coverage`, {
    headers: { authorization: `Bearer ${bridgeToken}` },
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error("ORGANIZATION_COVERAGE_UNAVAILABLE");
  const body = await response.text();
  if (!body || new TextEncoder().encode(body).byteLength > MAX_MANIFEST_BYTES) {
    throw new Error("ORGANIZATION_COVERAGE_INVALID_BODY");
  }
  return normalizeCoverage(JSON.parse(body));
}
