import {
  parseAwsEvidenceText,
  type AwsEvidenceImportResult,
  type NormalizedAwsEvidenceRecord,
} from "./aws-evidence-import.ts";
import { sourceTypes, type EvidenceClass, type SourceType } from "./admin-sources.ts";
import type { SecurityGroup, Severity } from "./security-data.ts";

const SECURITY_GROUP_PATTERN = /\bsg-[a-zA-Z0-9-]{3,64}\b/g;
const SECURITY_GROUP_ID_PATTERN = /^sg-[a-zA-Z0-9-]{3,64}$/;
const SECURITY_GROUP_ARN_PATTERN = /\barn:(aws|aws-us-gov|aws-cn):ec2:([a-z0-9-]+):(\d{12}):security-group\/(sg-[a-zA-Z0-9-]{3,64})\b/g;
const AWS_ARN_PARTITION_PATTERN = /\barn:(aws|aws-us-gov|aws-cn):/g;
const SYNTHETIC_ID_PATTERN = /^(?:imported|[a-z-]+)-\d+$/;

export type BatchEvidenceFile = {
  id: string;
  name: string;
  size: number;
  digest: string;
  status: "imported" | "duplicate" | "rejected";
  sourceType?: SourceType;
  sourceLabel?: string;
  recordCount: number;
  warningCount: number;
  error?: string;
  result?: AwsEvidenceImportResult;
};

export type ConsolidatedEvidenceItem = {
  fingerprint: string;
  sourceType: SourceType;
  sourceLabel: string;
  evidenceClass: EvidenceClass;
  fileName: string;
  record: NormalizedAwsEvidenceRecord;
  correlation: "direct" | "resource relationship" | "inventory attachment";
};

export type ConsolidatedSecurityGroupFinding = {
  key: string;
  securityGroupArn: string;
  securityGroupId: string;
  name: string;
  accountId: string;
  region: string;
  severity: Severity;
  riskScore: number;
  sources: string[];
  evidenceClasses: EvidenceClass[];
  evidence: ConsolidatedEvidenceItem[];
  directEvidenceCount: number;
  relatedEvidenceCount: number;
  firstObservedAt: string;
  lastObservedAt: string;
  summary: string;
  matchedInventoryGroup?: SecurityGroup;
};

export type ConsolidatedBatch = {
  findings: ConsolidatedSecurityGroupFinding[];
  uniqueRecords: number;
  duplicateRecords: number;
  unmatchedRecords: ConsolidatedEvidenceItem[];
};

function object(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, child]) => [key, stableValue(child)]),
    );
  }
  return value;
}

function unique(values: string[]) {
  return [...new Set(values.filter(Boolean))];
}

function securityGroupIds(value: unknown) {
  const ids = new Set<string>();
  const visit = (child: unknown, depth = 0) => {
    if (depth > 8 || child === null || child === undefined) return;
    if (typeof child === "string") {
      for (const match of child.matchAll(SECURITY_GROUP_PATTERN)) ids.add(match[0]);
      return;
    }
    if (Array.isArray(child)) {
      for (const item of child.slice(0, 10_000)) visit(item, depth + 1);
      return;
    }
    if (typeof child === "object") {
      for (const item of Object.values(child as Record<string, unknown>)) visit(item, depth + 1);
    }
  };
  visit(value);
  return [...ids];
}

function stringsIn(value: unknown) {
  const values: string[] = [];
  const visit = (child: unknown, depth = 0) => {
    if (depth > 8 || child === null || child === undefined) return;
    if (typeof child === "string") {
      values.push(child);
      return;
    }
    if (Array.isArray(child)) {
      for (const item of child.slice(0, 10_000)) visit(item, depth + 1);
      return;
    }
    if (typeof child === "object") {
      for (const item of Object.values(child as Record<string, unknown>)) visit(item, depth + 1);
    }
  };
  visit(value);
  return values;
}

export function canonicalSecurityGroupArn(
  accountId: string,
  region: string,
  securityGroupId: string,
  evidence: ConsolidatedEvidenceItem[] = [],
) {
  const strings = evidence.flatMap((item) => stringsIn({
    resource: item.record.resource,
    destination: item.record.destination,
    raw: item.record.raw,
  }));
  for (const value of strings) {
    for (const match of value.matchAll(SECURITY_GROUP_ARN_PATTERN)) {
      if (
        match[4] === securityGroupId
        && (!accountId || match[3] === accountId)
        && (!region || match[2] === region)
      ) return match[0];
    }
  }
  if (!/^\d{12}$/.test(accountId) || !/^[a-z]{2}(-gov)?-[a-z]+-\d$/.test(region) || !SECURITY_GROUP_ID_PATTERN.test(securityGroupId)) return "";
  let partition = "aws";
  for (const value of strings) {
    const match = AWS_ARN_PARTITION_PATTERN.exec(value);
    AWS_ARN_PARTITION_PATTERN.lastIndex = 0;
    if (match) {
      partition = match[1];
      break;
    }
  }
  return `arn:${partition}:ec2:${region}:${accountId}:security-group/${securityGroupId}`;
}

function filenameHints(filename: string) {
  const value = filename.toLowerCase();
  const hints: SourceType[] = [];
  const add = (type: SourceType, patterns: string[]) => {
    if (patterns.some((pattern) => value.includes(pattern))) hints.push(type);
  };
  add("cloudtrail", ["cloudtrail"]);
  add("config-history", ["confighistory", "config-history"]);
  add("config-snapshot", ["configsnapshot", "config-snapshot"]);
  add("vpc-flow-logs", ["vpcflowlogs", "vpc-flow"]);
  add("transit-gateway-flow-logs", ["transitgateway", "tgw-flow"]);
  add("reachability-analyzer", ["reachability", "networkinsightsanalysis"]);
  add("network-access-analyzer", ["access-scope", "network-access"]);
  add("elastic-load-balancing", ["elasticloadbalancing", "alb", "nlb"]);
  add("waf", ["waf"]);
  add("cloudfront", ["cloudfront"]);
  add("api-gateway", ["apigateway", "api-gateway"]);
  add("route53-resolver", ["route53", "resolver"]);
  add("network-firewall", ["network-firewall", "networkfirewall"]);
  add("guardduty", ["guardduty"]);
  add("security-hub", ["securityhub", "security-hub"]);
  add("inspector", ["inspector"]);
  return hints;
}

function detectionOrder(text: string, filename: string) {
  const trimmed = text.trimStart();
  const contentHints: SourceType[] = [];
  const add = (type: SourceType, pattern: RegExp) => {
    if (pattern.test(text.slice(0, 500_000))) contentHints.push(type);
  };
  add("cloudtrail", /"eventSource"\s*:|"eventName"\s*:/);
  add("config-snapshot", /"configurationItems"\s*:|"ConfigSnapshot"\s*:/);
  add("config-history", /"configurationItemCaptureTime"\s*:|"configurationStateId"\s*:/);
  add("security-hub", /"SchemaVersion"\s*:\s*"2018-10-08"|"ProductArn"\s*:/);
  add("guardduty", /"service"\s*:\s*\{|"resource"\s*:\s*\{[\s\S]*?"resourceType"/);
  add("inspector", /"findingArn"\s*:|"packageVulnerabilityDetails"\s*:/);
  add("network-firewall", /"firewall_name"\s*:|"event_type"\s*:\s*"(?:alert|flow)"/);
  add("route53-resolver", /"query_name"\s*:|"query_type_id"\s*:/);
  add("waf", /"webaclId"\s*:|"terminatingRuleId"\s*:/);
  add("api-gateway", /"routeKey"\s*:|"resourcePath"\s*:/);
  add("reachability-analyzer", /"NetworkInsightsAnalysisId"\s*:|"NetworkPathFound"\s*:/);
  add("network-access-analyzer", /"NetworkInsightsAccessScope/);
  if (/^#Version:|^#Fields:/m.test(trimmed) && /\bc-ip\b|\bx-edge-location\b/.test(text.slice(0, 20_000))) contentHints.push("cloudfront");
  if (/^(?:http|https|h2|grpcs|tls|tcp|udp)\s/m.test(trimmed)) contentHints.push("elastic-load-balancing");
  if (/^\d+\s+\d{12}\s+(?:eni-|tgw-)/m.test(trimmed)) {
    contentHints.push(trimmed.includes(" tgw-") ? "transit-gateway-flow-logs" : "vpc-flow-logs");
  }
  return unique([...filenameHints(filename), ...contentHints, ...sourceTypes]) as SourceType[];
}

export function detectAwsEvidenceText(text: string, filename = "aws-evidence") {
  const errors: string[] = [];
  for (const sourceType of detectionOrder(text, filename)) {
    try {
      const result = parseAwsEvidenceText(text, sourceType);
      if (sourceType === "cloudtrail" && !/"eventSource"\s*:|"eventName"\s*:/.test(text.slice(0, 500_000))) continue;
      return result;
    } catch (error) {
      errors.push(error instanceof Error ? error.message : `Could not parse ${sourceType}.`);
    }
  }
  throw new Error("Gatewatch could not identify a supported AWS log format. Check that the file is an unmodified AWS export.");
}

export function recordFingerprint(sourceType: SourceType, record: NormalizedAwsEvidenceRecord) {
  const stableId = record.id && !SYNTHETIC_ID_PATTERN.test(record.id) ? record.id : "";
  const sourceFamily = sourceType === "config-history" || sourceType === "config-snapshot"
    ? "aws-config"
    : sourceType;
  return JSON.stringify(stableValue({
    sourceType: sourceFamily,
    stableId,
    observedAt: record.observedAt,
    accountId: record.accountId,
    region: record.region,
    resource: record.resource,
    event: record.event,
    disposition: record.disposition,
    source: record.source,
    destination: record.destination,
    raw: record.raw,
  }));
}

type GroupMatch = {
  group: SecurityGroup | { id: string; name: string; accountId: string; region: string };
  correlation: ConsolidatedEvidenceItem["correlation"];
};

function identifierKeys(accountId: string, region: string, identifier: string) {
  return unique([
    accountId && region ? `${accountId}|${region}|${identifier}` : "",
    accountId ? `${accountId}||${identifier}` : "",
    `||${identifier}`,
  ]);
}

function buildInventoryIndex(groups: SecurityGroup[]) {
  const index = new Map<string, SecurityGroup[]>();
  const add = (group: SecurityGroup, identifier?: string) => {
    if (!identifier) return;
    for (const key of identifierKeys(group.accountId, group.region, identifier)) {
      index.set(key, [...new Set([...(index.get(key) ?? []), group])]);
    }
  };
  for (const group of groups) {
    add(group, group.id);
    add(group, group.name);
    for (const attachment of group.attachments) {
      for (const identifier of [
        attachment.id,
        attachment.name,
        attachment.networkInterfaceId,
        attachment.arn,
        attachment.privateAddress,
        attachment.publicAddress,
      ]) add(group, identifier);
    }
  }
  return index;
}

function buildRelationshipIndex(items: ConsolidatedEvidenceItem[]) {
  const relationships = new Map<string, Set<string>>();
  for (const item of items) {
    if (item.sourceType !== "config-history" && item.sourceType !== "config-snapshot") continue;
    const record = item.record;
    const raw = object(record.raw);
    const resourceId = String(raw.resourceId ?? "");
    const related = Array.isArray(raw.relationships) ? raw.relationships : [];
    const groupIds = securityGroupIds(related);
    if (!resourceId || !groupIds.length) continue;
    for (const key of identifierKeys(record.accountId, record.region, resourceId)) {
      const current = relationships.get(key) ?? new Set<string>();
      groupIds.forEach((id) => current.add(`${record.accountId}|${record.region}|${id}`));
      relationships.set(key, current);
    }
  }
  return relationships;
}

function resolveInventory(index: Map<string, SecurityGroup[]>, accountId: string, region: string, identifier: string) {
  for (const key of identifierKeys(accountId, region, identifier)) {
    const matches = index.get(key);
    if (matches?.length) return matches;
  }
  return [];
}

function directMatches(item: ConsolidatedEvidenceItem, inventory: SecurityGroup[]) {
  const record = item.record;
  const nestedSecurityGroupSources: SourceType[] = [
    "reachability-analyzer",
    "network-access-analyzer",
    "guardduty",
    "security-hub",
    "inspector",
  ];
  const ids = securityGroupIds(
    nestedSecurityGroupSources.includes(item.sourceType)
      ? { resource: record.resource, raw: record.raw }
      : record.resource,
  );
  return ids.map((id) => {
    const existing = inventory.find((group) =>
      group.id === id
      && (!record.accountId || group.accountId === record.accountId)
      && (!record.region || group.region === record.region),
    );
    return {
      group: existing ?? {
        id,
        name: id,
        accountId: record.accountId,
        region: record.region,
      },
      correlation: "direct" as const,
    };
  });
}

function relatedMatches(
  item: ConsolidatedEvidenceItem,
  inventory: SecurityGroup[],
  inventoryIndex: Map<string, SecurityGroup[]>,
  relationshipIndex: Map<string, Set<string>>,
) {
  const record = item.record;
  const identifiers = unique([
    record.resource,
    record.source,
    record.destination,
    String(record.raw["interface-id"] ?? ""),
    String(record.raw.interfaceId ?? ""),
    String(record.raw.resourceId ?? ""),
  ]);
  const matches: GroupMatch[] = [];
  for (const identifier of identifiers) {
    for (const group of resolveInventory(inventoryIndex, record.accountId, record.region, identifier)) {
      matches.push({ group, correlation: "inventory attachment" });
    }
    for (const key of identifierKeys(record.accountId, record.region, identifier)) {
      for (const target of relationshipIndex.get(key) ?? []) {
        const [targetAccountId, targetRegion, securityGroupId] = target.split("|");
        const group = inventory.find((candidate) =>
          candidate.id === securityGroupId
          && (!targetAccountId || candidate.accountId === targetAccountId)
          && (!targetRegion || candidate.region === targetRegion),
        );
        matches.push({
          group: group ?? { id: securityGroupId, name: securityGroupId, accountId: targetAccountId || record.accountId, region: targetRegion || record.region },
          correlation: "resource relationship",
        });
      }
    }
  }
  return [...new Map(matches.map((match) => [`${match.group.accountId}|${match.group.region}|${match.group.id}`, match])).values()];
}

function severityFor(score: number): Severity {
  if (score >= 85) return "critical";
  if (score >= 70) return "high";
  if (score >= 45) return "medium";
  return "low";
}

function findingScore(group: SecurityGroup | undefined, evidence: ConsolidatedEvidenceItem[]) {
  let score = group?.riskScore ?? 20;
  if (evidence.some((item) => item.evidenceClass === "threat-finding")) score += 22;
  if (evidence.some((item) => item.evidenceClass === "reachability" && /reachable|found|active|succeeded/i.test(`${item.record.event} ${item.record.disposition} ${item.record.summary}`))) score += 15;
  if (evidence.some((item) => item.evidenceClass === "observed-traffic" && /accept|allow/i.test(item.record.disposition))) score += 12;
  if (evidence.some((item) => item.sourceType === "cloudtrail" && /broaden|authorize|modify/i.test(`${item.record.event} ${item.record.disposition}`))) score += 12;
  if (evidence.some((item) => /0\.0\.0\.0\/0|::\/0/.test(JSON.stringify(item.record)))) score += 15;
  return Math.min(100, score);
}

function observedRange(evidence: ConsolidatedEvidenceItem[]) {
  const timestamps = evidence
    .map((item) => item.record.observedAt)
    .filter((value) => Number.isFinite(Date.parse(value)))
    .sort();
  return { first: timestamps[0] ?? "", last: timestamps.at(-1) ?? "" };
}

export function consolidateAwsEvidence(files: BatchEvidenceFile[], inventory: SecurityGroup[]): ConsolidatedBatch {
  const uniqueItems: ConsolidatedEvidenceItem[] = [];
  const fingerprints = new Set<string>();
  let duplicateRecords = 0;
  for (const file of files) {
    if (file.status !== "imported" || !file.result) continue;
    for (const record of file.result.records) {
      const fingerprint = recordFingerprint(file.result.sourceType, record);
      if (fingerprints.has(fingerprint)) {
        duplicateRecords += 1;
        continue;
      }
      fingerprints.add(fingerprint);
      uniqueItems.push({
        fingerprint,
        sourceType: file.result.sourceType,
        sourceLabel: file.result.sourceLabel,
        evidenceClass: file.result.evidenceClass,
        fileName: file.name,
        record,
        correlation: "direct",
      });
    }
  }

  const inventoryIndex = buildInventoryIndex(inventory);
  const relationshipIndex = buildRelationshipIndex(uniqueItems);
  const grouped = new Map<string, { match: GroupMatch; evidence: ConsolidatedEvidenceItem[] }>();
  const unmatchedRecords: ConsolidatedEvidenceItem[] = [];

  for (const item of uniqueItems) {
    const matches = directMatches(item, inventory);
    const resolved = matches.length
      ? matches
      : relatedMatches(item, inventory, inventoryIndex, relationshipIndex);
    if (!resolved.length) {
      unmatchedRecords.push(item);
      continue;
    }
    for (const match of resolved) {
      const key = `${match.group.accountId || "unknown"}|${match.group.region || "unknown"}|${match.group.id}`;
      const current = grouped.get(key) ?? { match, evidence: [] };
      current.evidence.push({ ...item, correlation: match.correlation });
      grouped.set(key, current);
    }
  }

  const findings = [...grouped.entries()].map(([key, value]) => {
    const inventoryGroup = "riskScore" in value.match.group ? value.match.group as SecurityGroup : undefined;
    const evidence = value.evidence.sort((left, right) => right.record.observedAt.localeCompare(left.record.observedAt));
    const riskScore = findingScore(inventoryGroup, evidence);
    const sources = unique(evidence.map((item) => item.sourceLabel)).sort();
    const evidenceClasses = unique(evidence.map((item) => item.evidenceClass)) as EvidenceClass[];
    const range = observedRange(evidence);
    const directEvidenceCount = evidence.filter((item) => item.correlation === "direct").length;
    const securityGroupArn = canonicalSecurityGroupArn(
      value.match.group.accountId,
      value.match.group.region,
      value.match.group.id,
      evidence,
    );
    return {
      key: securityGroupArn || key,
      securityGroupArn,
      securityGroupId: value.match.group.id,
      name: value.match.group.name,
      accountId: value.match.group.accountId,
      region: value.match.group.region,
      severity: severityFor(riskScore),
      riskScore,
      sources,
      evidenceClasses,
      evidence,
      directEvidenceCount,
      relatedEvidenceCount: evidence.length - directEvidenceCount,
      firstObservedAt: range.first,
      lastObservedAt: range.last,
      summary: `${evidence.length.toLocaleString()} unique AWS evidence record${evidence.length === 1 ? "" : "s"} consolidated from ${sources.length.toLocaleString()} source type${sources.length === 1 ? "" : "s"}.`,
      matchedInventoryGroup: inventoryGroup,
    } satisfies ConsolidatedSecurityGroupFinding;
  }).sort((left, right) => right.riskScore - left.riskScore || right.evidence.length - left.evidence.length);

  return {
    findings,
    uniqueRecords: uniqueItems.length,
    duplicateRecords,
    unmatchedRecords,
  };
}
