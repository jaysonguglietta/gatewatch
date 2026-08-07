export const dailyFindingQueryFields = [
  "arn",
  "sg",
  "id",
  "name",
  "account",
  "acct",
  "region",
  "vpc",
  "ingress",
  "egress",
  "rule",
  "port",
  "protocol",
  "source",
  "severity",
  "risk",
  "verdict",
  "status",
  "owner",
  "assignee",
  "application",
  "app",
  "environment",
  "env",
  "ou",
  "title",
  "policy",
  "path",
  "resource",
  "tag",
  "actor",
  "evidence",
  "confidence",
  "age",
] as const;

type QueryField = (typeof dailyFindingQueryFields)[number];

export type SearchableDailyFinding = {
  securityGroupArn?: string;
  canonicalResourceKey?: string;
  securityGroupId: string;
  securityGroupName: string;
  accountId: string;
  accountName: string;
  region: string;
  vpcId: string;
  title: string;
  ruleSummary: string;
  severity: string;
  riskScore: number;
  verdict: string;
  status: string;
  owner: string;
  assignee: string;
  application: string;
  environment: string;
  organizationalUnit: string;
  policyName: string;
  policyControl: string;
  pathSummary: string;
  changeActor: string;
  changeSummary: string;
  ageDays: number;
  evidence: {
    state: string;
    confidence: number;
    sources: string[];
    limitations: string[];
  };
  attachments: Array<{
    id: string;
    name: string;
    type: string;
    publicAddress?: string;
    privateAddress?: string;
    networkInterfaceId?: string;
    subnetId?: string;
    vpcId?: string;
    description?: string;
    arn?: string;
    tags?: Record<string, string>;
  }>;
};

export type DailyFindingQueryToken = {
  field: QueryField | "";
  value: string;
};

export type ParsedDailyFindingQuery = {
  tokens: DailyFindingQueryToken[];
  unsupportedFields: string[];
  unclosedQuote: boolean;
};

const supportedFieldSet = new Set<string>(dailyFindingQueryFields);

function normalized(value: unknown) {
  return String(value ?? "").trim().toLowerCase();
}

function includesValue(haystack: unknown, needle: string) {
  return normalized(haystack).includes(normalized(needle));
}

export function securityGroupArnForFinding(
  finding: Pick<SearchableDailyFinding, "securityGroupArn" | "accountId" | "region" | "securityGroupId">,
) {
  if (finding.securityGroupArn?.trim()) return finding.securityGroupArn.trim();
  const partition = finding.region.startsWith("us-gov-")
    ? "aws-us-gov"
    : finding.region.startsWith("cn-")
      ? "aws-cn"
      : "aws";
  return `arn:${partition}:ec2:${finding.region}:${finding.accountId}:security-group/${finding.securityGroupId}`;
}

export function parseDailyFindingQuery(query: string): ParsedDailyFindingQuery {
  const tokens: DailyFindingQueryToken[] = [];
  const unsupportedFields = new Set<string>();
  const tokenPattern = /(?:([a-z][a-z0-9-]*):)?(?:"([^"]*)"|(\S+))/gi;
  let match: RegExpExecArray | null;

  while ((match = tokenPattern.exec(query)) !== null) {
    const requestedField = normalized(match[1]);
    const value = normalized(match[2] ?? match[3]);
    if (!value) continue;
    if (requestedField && !supportedFieldSet.has(requestedField)) {
      unsupportedFields.add(requestedField);
      continue;
    }
    tokens.push({ field: requestedField as QueryField | "", value });
  }

  return {
    tokens,
    unsupportedFields: [...unsupportedFields].sort(),
    unclosedQuote: (query.match(/"/g)?.length ?? 0) % 2 === 1,
  };
}

function numericMatch(actual: number, expression: string) {
  const comparison = expression.match(/^(<=|>=|<|>)?\s*(\d+(?:\.\d+)?)$/);
  if (comparison) {
    const expected = Number(comparison[2]);
    if (comparison[1] === "<") return actual < expected;
    if (comparison[1] === "<=") return actual <= expected;
    if (comparison[1] === ">") return actual > expected;
    if (comparison[1] === ">=") return actual >= expected;
    return actual === expected;
  }
  const range = expression.match(/^(\d+(?:\.\d+)?)\s*-\s*(\d+(?:\.\d+)?)$/);
  if (!range) return false;
  const lower = Math.min(Number(range[1]), Number(range[2]));
  const upper = Math.max(Number(range[1]), Number(range[2]));
  return actual >= lower && actual <= upper;
}

function parsedRule(ruleSummary: string) {
  const match = ruleSummary.match(/^(ingress|egress)\s+([^/]+)\/(.+?)\s+from\s+(.+)$/i);
  return {
    direction: normalized(match?.[1]),
    protocol: normalized(match?.[2]),
    ports: normalized(match?.[3]),
    source: normalized(match?.[4]),
  };
}

function attachmentText(finding: SearchableDailyFinding) {
  return finding.attachments.map((attachment) => [
    attachment.id,
    attachment.name,
    attachment.type,
    attachment.publicAddress,
    attachment.privateAddress,
    attachment.networkInterfaceId,
    attachment.subnetId,
    attachment.vpcId,
    attachment.description,
    attachment.arn,
    ...Object.entries(attachment.tags ?? {}).flatMap(([key, value]) => [key, value, `${key}:${value}`]),
  ].join(" ")).join(" ");
}

function tagText(finding: SearchableDailyFinding) {
  return finding.attachments.flatMap((attachment) =>
    Object.entries(attachment.tags ?? {}).flatMap(([key, value]) => [key, value, `${key}:${value}`]),
  ).join(" ");
}

function allText(finding: SearchableDailyFinding) {
  return [
    securityGroupArnForFinding(finding),
    finding.canonicalResourceKey,
    finding.securityGroupId,
    finding.securityGroupName,
    finding.accountId,
    finding.accountName,
    finding.region,
    finding.vpcId,
    finding.title,
    finding.ruleSummary,
    finding.severity,
    finding.riskScore,
    finding.verdict,
    finding.status,
    finding.owner,
    finding.assignee,
    finding.application,
    finding.environment,
    finding.organizationalUnit,
    finding.policyName,
    finding.policyControl,
    finding.pathSummary,
    finding.changeActor,
    finding.changeSummary,
    finding.evidence.state,
    finding.evidence.confidence,
    ...finding.evidence.sources,
    ...finding.evidence.limitations,
    attachmentText(finding),
  ].join(" ");
}

function tokenMatches(finding: SearchableDailyFinding, token: DailyFindingQueryToken) {
  const { field, value } = token;
  const rule = parsedRule(finding.ruleSummary);
  if (!field) return includesValue(allText(finding), value);
  if (field === "arn") return includesValue(securityGroupArnForFinding(finding), value);
  if (field === "sg" || field === "id") return includesValue(finding.securityGroupId, value);
  if (field === "name") return includesValue(finding.securityGroupName, value);
  if (field === "account" || field === "acct") {
    return includesValue(`${finding.accountId} ${finding.accountName}`, value);
  }
  if (field === "region") return includesValue(finding.region, value);
  if (field === "vpc") return includesValue(finding.vpcId, value);
  if (field === "ingress" || field === "egress") {
    return rule.direction === field && includesValue(finding.ruleSummary, value);
  }
  if (field === "rule") return includesValue(finding.ruleSummary, value);
  if (field === "port") return includesValue(rule.ports, value);
  if (field === "protocol") return includesValue(rule.protocol, value);
  if (field === "source") return includesValue(rule.source, value);
  if (field === "severity") return includesValue(finding.severity, value);
  if (field === "risk") return numericMatch(finding.riskScore, value);
  if (field === "verdict") return includesValue(finding.verdict, value);
  if (field === "status") return includesValue(finding.status, value);
  if (field === "owner") return includesValue(finding.owner, value);
  if (field === "assignee") return includesValue(finding.assignee, value);
  if (field === "application" || field === "app") return includesValue(finding.application, value);
  if (field === "environment" || field === "env") return includesValue(finding.environment, value);
  if (field === "ou") return includesValue(finding.organizationalUnit, value);
  if (field === "title") return includesValue(finding.title, value);
  if (field === "policy") return includesValue(`${finding.policyName} ${finding.policyControl}`, value);
  if (field === "path") return includesValue(finding.pathSummary, value);
  if (field === "resource") return includesValue(attachmentText(finding), value);
  if (field === "tag") return includesValue(tagText(finding), value);
  if (field === "actor") return includesValue(`${finding.changeActor} ${finding.changeSummary}`, value);
  if (field === "evidence") {
    return includesValue(`${finding.evidence.state} ${finding.evidence.sources.join(" ")} ${finding.evidence.limitations.join(" ")}`, value);
  }
  if (field === "confidence") return numericMatch(finding.evidence.confidence, value);
  if (field === "age") return numericMatch(finding.ageDays, value);
  return false;
}

export function dailyFindingMatchesQuery(
  finding: SearchableDailyFinding,
  parsed: ParsedDailyFindingQuery,
) {
  if (parsed.unsupportedFields.length || parsed.unclosedQuote) return false;
  return parsed.tokens.every((token) => tokenMatches(finding, token));
}
