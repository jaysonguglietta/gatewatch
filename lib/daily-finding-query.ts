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
  "internet",
  "changed-after",
  "changed-before",
  "changed-by",
  "recurrence",
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
  changeTime: string;
  ageDays: number;
  lastSeenAt?: string;
  observationCount?: number;
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

type QueryNode =
  | { kind: "term"; token: DailyFindingQueryToken; invalid?: boolean }
  | { kind: "not"; child: QueryNode }
  | { kind: "and" | "or"; left: QueryNode; right: QueryNode };

export type ParsedDailyFindingQuery = {
  tokens: DailyFindingQueryToken[];
  unsupportedFields: string[];
  unclosedQuote: boolean;
  syntaxErrors: string[];
  complexityExceeded: boolean;
  root?: QueryNode;
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
  type Lexeme =
    | { kind: "term"; token: DailyFindingQueryToken; invalid: boolean }
    | { kind: "and" | "or" | "not" | "left" | "right" };

  const tokens: DailyFindingQueryToken[] = [];
  const unsupportedFields = new Set<string>();
  const syntaxErrors: string[] = [];
  const lexemes: Lexeme[] = [];
  const tokenPattern = /\(|\)|\bAND\b|\bOR\b|\bNOT\b|(?:[a-z][a-z0-9-]*:)?(?:"[^"]*"|[^\s()]+)/gi;
  for (const match of query.matchAll(tokenPattern)) {
    const raw = match[0];
    const keyword = raw.toUpperCase();
    if (raw === "(") { lexemes.push({ kind: "left" }); continue; }
    if (raw === ")") { lexemes.push({ kind: "right" }); continue; }
    if (keyword === "AND" || keyword === "OR" || keyword === "NOT") {
      lexemes.push({ kind: keyword.toLowerCase() as "and" | "or" | "not" });
      continue;
    }
    const fieldMatch = raw.match(/^([a-z][a-z0-9-]*):(.*)$/i);
    const requestedField = normalized(fieldMatch?.[1]);
    const rawValue = fieldMatch?.[2] ?? raw;
    const value = normalized(rawValue.replace(/^"|"$/g, ""));
    if (!value) {
      syntaxErrors.push("Search clauses require a value.");
      continue;
    }
    const invalid = Boolean(requestedField && !supportedFieldSet.has(requestedField));
    if (invalid) unsupportedFields.add(requestedField);
    const token = { field: (invalid ? "" : requestedField) as QueryField | "", value };
    if (!invalid) tokens.push(token);
    lexemes.push({ kind: "term", token, invalid });
  }

  let cursor = 0;
  let depth = 0;
  let maxDepth = 0;
  const beginsUnary = (lexeme?: Lexeme) => Boolean(lexeme && ["term", "left", "not"].includes(lexeme.kind));

  function primary(): QueryNode | undefined {
    const lexeme = lexemes[cursor];
    if (!lexeme) return undefined;
    if (lexeme.kind === "term") {
      cursor += 1;
      return { kind: "term", token: lexeme.token, invalid: lexeme.invalid };
    }
    if (lexeme.kind === "left") {
      cursor += 1;
      depth += 1;
      maxDepth = Math.max(maxDepth, depth);
      const node = expression();
      depth -= 1;
      if (lexemes[cursor]?.kind !== "right") syntaxErrors.push("Close every search parenthesis.");
      else cursor += 1;
      return node;
    }
    return undefined;
  }

  function unary(): QueryNode | undefined {
    if (lexemes[cursor]?.kind === "not") {
      cursor += 1;
      const child = unary();
      if (!child) {
        syntaxErrors.push("NOT must be followed by a clause or group.");
        return undefined;
      }
      return { kind: "not", child };
    }
    return primary();
  }

  function conjunction(): QueryNode | undefined {
    let left = unary();
    if (!left) return undefined;
    while (lexemes[cursor]?.kind === "and" || beginsUnary(lexemes[cursor])) {
      if (lexemes[cursor]?.kind === "and") cursor += 1;
      const right = unary();
      if (!right) {
        syntaxErrors.push("AND must be followed by a clause or group.");
        break;
      }
      left = { kind: "and", left, right };
    }
    return left;
  }

  function expression(): QueryNode | undefined {
    let left = conjunction();
    if (!left) return undefined;
    while (lexemes[cursor]?.kind === "or") {
      cursor += 1;
      const right = conjunction();
      if (!right) {
        syntaxErrors.push("OR must be followed by a clause or group.");
        break;
      }
      left = { kind: "or", left, right };
    }
    return left;
  }

  const root = expression();
  if (cursor < lexemes.length) syntaxErrors.push("Check the Boolean operators and parentheses in this query.");
  const unclosedQuote = (query.match(/"/g)?.length ?? 0) % 2 === 1;
  const complexityExceeded = tokens.length > 40 || maxDepth > 5;
  if (complexityExceeded) syntaxErrors.push("Queries are limited to 40 clauses and five nested groups.");
  return { tokens, unsupportedFields: [...unsupportedFields].sort(), unclosedQuote, syntaxErrors: [...new Set(syntaxErrors)], complexityExceeded, root };
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
  if (field === "internet") {
    const verdict = normalized(finding.verdict);
    const state = /internet path|confirmed public/.test(verdict)
      ? "confirmed"
      : /internal|unreachable|blocked|no internet/.test(verdict)
        ? "none"
        : "unknown";
    const requested = value === "internet" ? "confirmed" : value === "no-internet" ? "none" : value;
    return includesValue(state, requested) || includesValue(verdict, value);
  }
  if (field === "changed-after") return Boolean(finding.changeTime && finding.changeTime.slice(0, 10) >= value);
  if (field === "changed-before") return Boolean(finding.changeTime && finding.changeTime.slice(0, 10) <= value);
  if (field === "changed-by") return includesValue(`${finding.changeActor} ${finding.changeSummary}`, value);
  if (field === "recurrence") return numericMatch(finding.observationCount ?? 1, value);
  return false;
}

function evaluate(node: QueryNode | undefined, predicate: (token: DailyFindingQueryToken) => boolean): boolean {
  if (!node) return true;
  if (node.kind === "term") return !node.invalid && predicate(node.token);
  if (node.kind === "not") return !evaluate(node.child, predicate);
  if (node.kind === "and") return evaluate(node.left, predicate) && evaluate(node.right, predicate);
  return evaluate(node.left, predicate) || evaluate(node.right, predicate);
}

export function dailyFindingQueryMatches(
  parsed: ParsedDailyFindingQuery,
  predicate: (token: DailyFindingQueryToken) => boolean,
) {
  if (queryIsInvalid(parsed)) return false;
  return evaluate(parsed.root, predicate);
}

export function dailyFindingQueryMatchedTokens(
  parsed: ParsedDailyFindingQuery,
  predicate: (token: DailyFindingQueryToken) => boolean,
) {
  if (queryIsInvalid(parsed)) return [];
  return positiveMatches(parsed.root, predicate);
}

function positiveMatches(node: QueryNode | undefined, predicate: (token: DailyFindingQueryToken) => boolean): DailyFindingQueryToken[] {
  if (!node) return [];
  if (node.kind === "term") return !node.invalid && predicate(node.token) ? [node.token] : [];
  if (node.kind === "not") return [];
  if (node.kind === "or") {
    return [
      ...(evaluate(node.left, predicate) ? positiveMatches(node.left, predicate) : []),
      ...(evaluate(node.right, predicate) ? positiveMatches(node.right, predicate) : []),
    ];
  }
  return [...positiveMatches(node.left, predicate), ...positiveMatches(node.right, predicate)];
}

function queryIsInvalid(parsed: ParsedDailyFindingQuery) {
  return Boolean(parsed.unsupportedFields.length || parsed.unclosedQuote || parsed.syntaxErrors.length || parsed.complexityExceeded);
}

export function dailyFindingMatchesQuery(
  finding: SearchableDailyFinding,
  parsed: ParsedDailyFindingQuery,
) {
  if (queryIsInvalid(parsed)) return false;
  return evaluate(parsed.root, (token) => tokenMatches(finding, token));
}

const fieldLabels: Partial<Record<QueryField, string>> = {
  arn: "ARN", sg: "Security group", id: "Security group", name: "Group name",
  account: "Account", acct: "Account", region: "Region", vpc: "VPC",
  ingress: "Ingress rule", egress: "Egress rule", rule: "Rule", port: "Port",
  protocol: "Protocol", source: "Rule source", severity: "Severity", risk: "Risk",
  verdict: "Exposure verdict", status: "Workflow", owner: "Owner", assignee: "Assignee",
  application: "Application", app: "Application", environment: "Environment", env: "Environment",
  ou: "Organizational unit", title: "Finding", policy: "Policy", path: "Network path",
  resource: "Attached resource", tag: "Resource tag", actor: "Change actor", "changed-by": "Change actor",
  evidence: "Evidence", confidence: "Evidence confidence", age: "Finding age", internet: "Internet exposure",
  "changed-after": "Changed after", "changed-before": "Changed before", recurrence: "Recurrence",
};

export function dailyFindingMatchReasons(finding: SearchableDailyFinding, parsed: ParsedDailyFindingQuery) {
  if (queryIsInvalid(parsed) || !parsed.root) return [];
  const matched = positiveMatches(parsed.root, (token) => tokenMatches(finding, token));
  return [...new Set(matched.map((token) => token.field
    ? `${fieldLabels[token.field] ?? token.field}: ${token.value}`
    : `Text: ${token.value}`))].slice(0, 6);
}
