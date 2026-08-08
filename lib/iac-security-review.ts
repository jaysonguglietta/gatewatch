import { parseDocument } from "yaml";

export const IAC_FILE_EXTENSIONS = [".yaml", ".yml", ".template", ".json", ".tf", ".tf.json"] as const;
export const MAX_IAC_FILE_BYTES = 5 * 1024 * 1024;
export const MAX_IAC_FILES = 40;
export const MAX_IAC_RESOURCES_PER_FILE = 2_500;
export const MAX_IAC_RULES_PER_FILE = 2_500;
export const MAX_IAC_BATCH_RULES = 10_000;

export type IacFormat = "cloudformation-yaml" | "cloudformation-json" | "terraform-hcl" | "terraform-json";
export type IacSeverity = "critical" | "high" | "medium" | "low" | "informational";
export type IacVerdict = "block" | "review" | "pass";
export type IacExposure = "potential-internet" | "unknown" | "internal-only";

export type IacRule = {
  id: string;
  direction: "ingress" | "egress";
  protocol: string;
  fromPort: number | null;
  toPort: number | null;
  sources: string[];
  description: string;
  fileName: string;
  resourceAddress: string;
  line: number;
  unresolved: boolean;
};

export type IacIssue = {
  id: string;
  severity: IacSeverity;
  title: string;
  description: string;
  recommendation: string;
  ruleId: string;
  fileName: string;
  resourceAddress: string;
  line: number;
  cwe: string;
};

export type IacSecurityGroupReview = {
  key: string;
  name: string;
  format: IacFormat;
  fileNames: string[];
  resourceAddresses: string[];
  vpc: string;
  description: string;
  rules: IacRule[];
  issues: IacIssue[];
  riskScore: number;
  verdict: IacVerdict;
  exposure: IacExposure;
  exposureReason: string;
  pathSignals: { internetGateway: boolean; publicRoute: boolean; publicAttachment: boolean };
  attachmentSignals: string[];
};

export type IacFileReview = {
  name: string;
  format?: IacFormat;
  status: "parsed" | "rejected";
  resourceCount: number;
  ruleCount: number;
  warnings: string[];
  error?: string;
  groups: IacSecurityGroupReview[];
};

export type IacReviewBatch = {
  files: IacFileReview[];
  groups: IacSecurityGroupReview[];
  totals: {
    files: number;
    parsedFiles: number;
    rejectedFiles: number;
    groups: number;
    rules: number;
    issues: number;
    critical: number;
    high: number;
  };
};

type PendingGroup = Omit<IacSecurityGroupReview, "issues" | "riskScore" | "verdict" | "exposure" | "exposureReason" | "pathSignals"> & {
  context: TemplateContext;
};

type TemplateContext = {
  internetGateway: boolean;
  publicRoute: boolean;
  publicAddress: boolean;
  internetFacingService: boolean;
};

const emptyContext = (): TemplateContext => ({
  internetGateway: false,
  publicRoute: false,
  publicAddress: false,
  internetFacingService: false,
});

const cloudFormationScalarTags = [
  ["!Ref", "Ref"],
  ["!Sub", "Fn::Sub"],
  ["!GetAtt", "Fn::GetAtt"],
  ["!ImportValue", "Fn::ImportValue"],
  ["!GetAZs", "Fn::GetAZs"],
  ["!Base64", "Fn::Base64"],
] as const;

const cloudFormationYamlTags = cloudFormationScalarTags.map(([tag, key]) => ({
  tag,
  identify: () => false,
  resolve: (value: string) => ({ [key]: value }),
}));

function lineAt(text: string, index: number) {
  return text.slice(0, Math.max(0, index)).split("\n").length;
}

function stableId(parts: Array<string | number | null>) {
  let hash = 2166136261;
  const value = parts.join("|");
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return `iac-${(hash >>> 0).toString(16).padStart(8, "0")}`;
}

function clean(value: unknown, fallback = ""): string {
  if (value === null || value === undefined) return fallback;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.map((item) => clean(item)).filter(Boolean).join(", ");
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    if (record.Ref) return `Ref:${clean(record.Ref)}`;
    if (record["Fn::GetAtt"]) return `GetAtt:${clean(record["Fn::GetAtt"])}`;
    if (record["Fn::Sub"]) return clean(record["Fn::Sub"]);
    if (record["Fn::ImportValue"]) return `ImportValue:${clean(record["Fn::ImportValue"])}`;
    try { return JSON.stringify(value); } catch { return fallback; }
  }
  return fallback;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function asArray(value: unknown) {
  return Array.isArray(value) ? value : value === undefined || value === null ? [] : [value];
}

function numberValue(value: unknown): number | null {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function protocolName(value: unknown) {
  const protocol = clean(value, "all").toLowerCase();
  if (protocol === "-1") return "all";
  if (protocol === "6") return "tcp";
  if (protocol === "17") return "udp";
  return protocol;
}

function publicSource(source: string) {
  const normalized = source.toLowerCase().replaceAll(" ", "");
  return normalized === "0.0.0.0/0" || normalized === "::/0";
}

function cidrPrefix(source: string) {
  const match = source.match(/\/([0-9]{1,3})$/);
  return match ? Number(match[1]) : null;
}

function includesPort(rule: IacRule, port: number) {
  if (rule.protocol === "all" || rule.fromPort === null || rule.toPort === null) return true;
  return port >= Math.min(rule.fromPort, rule.toPort) && port <= Math.max(rule.fromPort, rule.toPort);
}

function ruleIssues(rule: IacRule): IacIssue[] {
  const issues: IacIssue[] = [];
  const add = (severity: IacSeverity, title: string, description: string, recommendation: string, cwe = "CWE-284") => {
    issues.push({ id: stableId([rule.id, title]), severity, title, description, recommendation, ruleId: rule.id, fileName: rule.fileName, resourceAddress: rule.resourceAddress, line: rule.line, cwe });
  };
  const publicCidr = rule.sources.some(publicSource);
  const ipv4Public = rule.sources.some((source) => source.replaceAll(" ", "") === "0.0.0.0/0");
  const ipv6Public = rule.sources.some((source) => source.replaceAll(" ", "") === "::/0");
  const allPorts = rule.protocol === "all" || rule.fromPort === null || rule.toPort === null || (rule.fromPort === 0 && rule.toPort >= 65535);
  const width = rule.fromPort !== null && rule.toPort !== null ? Math.abs(rule.toPort - rule.fromPort) + 1 : 65536;

  if (rule.unresolved) add("medium", "Rule contains unresolved expressions", "One or more source, port, or protocol expressions could not be reduced without deployment-time values.", "Resolve variables, module outputs, conditions, and computed values in CI before allowing deployment.", "CWE-20");
  if (!rule.description) add("low", "Security-group rule has no description", "The rule does not document its intended source, service, or expiry.", "Add an owner-oriented description and reference the approval or exception ticket.");
  if (rule.direction === "ingress" && publicCidr && allPorts) add("critical", "All traffic is open to the internet", `The rule permits every protocol or port from ${rule.sources.filter(publicSource).join(" and ")}.`, "Remove the rule or replace it with the exact approved protocol, port, and trusted source.");
  if (rule.direction === "ingress" && publicCidr && (includesPort(rule, 22) || includesPort(rule, 3389))) add("critical", "Administrative access is open to the internet", "SSH or RDP is reachable from an unrestricted IPv4 or IPv6 source if an internet path exists.", "Use SSM Session Manager, a managed VPN, or an approved prefix list; do not expose administration ports publicly.");
  if (rule.direction === "ingress" && publicCidr && [1433, 1521, 27017, 3306, 5432, 6379, 9200, 9300].some((port) => includesPort(rule, port))) add("critical", "Database or data service is open to the internet", "The permitted range includes a common database, cache, or search service port.", "Reference the application security group or an approved private network source instead of an internet CIDR.");
  if (rule.direction === "ingress" && publicCidr && [3000, 4200, 5000, 5601, 8000, 8080, 8888].some((port) => includesPort(rule, port))) add("high", "Development or management service may be public", "The permitted range includes a common development server, dashboard, or alternate management port.", "Restrict the source and confirm the service is intended to be internet-facing.");
  if (rule.direction === "ingress" && publicCidr && width > 100 && !allPorts) add("high", "Wide port range is open to the internet", `The rule exposes ${width.toLocaleString()} ports to an unrestricted source.`, "Split the rule into the smallest approved service ports and trusted sources.");
  if (rule.direction === "ingress" && publicCidr && !issues.some((issue) => issue.severity === "critical" || issue.severity === "high")) add("medium", "Ingress is open to an unrestricted source", `The rule allows ${ipv4Public ? "all IPv4 addresses" : ""}${ipv4Public && ipv6Public ? " and " : ""}${ipv6Public ? "all IPv6 addresses" : ""}.`, "Confirm an intentional public service and require complete route, public-address, and edge-control evidence.");
  if (rule.direction === "egress" && publicCidr && allPorts) add("medium", "Unrestricted internet egress", "The rule permits workloads to initiate any protocol to any IPv4 or IPv6 destination.", "Constrain egress to approved endpoints, prefix lists, VPC endpoints, and required service ports.", "CWE-923");
  for (const source of rule.sources) {
    const prefix = cidrPrefix(source);
    if (!publicSource(source) && ((source.includes(":") && prefix !== null && prefix <= 32) || (!source.includes(":") && prefix !== null && prefix <= 8))) {
      add("medium", "Very broad private or IPv6 CIDR", `${source} covers a large address space and may enable unintended lateral access.`, "Use security-group references or narrower workload and subnet CIDRs.");
    }
  }
  return issues;
}

function finalizeGroup(group: PendingGroup): IacSecurityGroupReview {
  const uniqueRules = [...new Map(group.rules.map((rule) => [`${rule.direction}|${rule.protocol}|${rule.fromPort}|${rule.toPort}|${[...rule.sources].sort().join(",")}`, rule])).values()];
  const issues = uniqueRules.flatMap(ruleIssues);
  const weights: Record<IacSeverity, number> = { critical: 35, high: 22, medium: 10, low: 3, informational: 0 };
  const riskScore = Math.min(100, issues.reduce((sum, issue) => sum + weights[issue.severity], 0));
  const hasPublicRule = uniqueRules.some((rule) => rule.direction === "ingress" && rule.sources.some(publicSource));
  const publicPathSignals = Number(group.context.internetGateway) + Number(group.context.publicRoute) + Number(group.context.publicAddress || group.context.internetFacingService);
  const exposure: IacExposure = hasPublicRule ? publicPathSignals >= 3 ? "potential-internet" : "unknown" : "internal-only";
  const exposureReason = exposure === "potential-internet"
    ? "The template contains an unrestricted ingress rule plus internet-gateway, public-route, and public attachment signals. Runtime reachability still requires deployed-state verification."
    : exposure === "unknown"
      ? `An unrestricted ingress rule exists, but only ${publicPathSignals} of 3 public-path signal groups are present in the uploaded files.`
      : "No unrestricted IPv4 or IPv6 ingress rule was found in the uploaded definition.";
  const verdict: IacVerdict = issues.some((issue) => issue.severity === "critical") ? "block" : issues.some((issue) => ["high", "medium"].includes(issue.severity)) ? "review" : "pass";
  const { context: _context, ...result } = group;
  void _context;
  return {
    ...result,
    rules: uniqueRules,
    issues,
    riskScore,
    verdict,
    exposure,
    exposureReason,
    pathSignals: {
      internetGateway: group.context.internetGateway,
      publicRoute: group.context.publicRoute,
      publicAttachment: group.context.publicAddress || group.context.internetFacingService,
    },
  };
}

function cloudFormationContext(resources: Record<string, unknown>): TemplateContext {
  const context = emptyContext();
  for (const value of Object.values(resources)) {
    const resource = asRecord(value);
    const type = clean(resource.Type);
    const properties = asRecord(resource.Properties);
    if (type === "AWS::EC2::InternetGateway" || type === "AWS::EC2::VPCGatewayAttachment") context.internetGateway = true;
    if (type === "AWS::EC2::Route" && [clean(properties.DestinationCidrBlock), clean(properties.DestinationIpv6CidrBlock)].some(publicSource) && clean(properties.GatewayId)) context.publicRoute = true;
    if (["AWS::EC2::EIP", "AWS::EC2::EIPAssociation"].includes(type) || properties.AssociatePublicIpAddress === true || properties.MapPublicIpOnLaunch === true) context.publicAddress = true;
    if ((type === "AWS::ElasticLoadBalancingV2::LoadBalancer" && clean(properties.Scheme, "internet-facing") !== "internal") || properties.PubliclyAccessible === true) context.internetFacingService = true;
  }
  return context;
}

function resourceLine(text: string, logicalId: string) {
  const patterns = [new RegExp(`^[ \\t]*${logicalId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[ \\t]*:`, "m"), new RegExp(`"${logicalId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"\\s*:`)];
  const index = patterns.map((pattern) => text.search(pattern)).find((value) => value >= 0) ?? 0;
  return lineAt(text, index);
}

function cloudFormationRule(input: unknown, direction: "ingress" | "egress", fileName: string, address: string, line: number): IacRule {
  const properties = asRecord(input);
  const rawCidrSources = [properties.CidrIp, properties.CidrIpv6].flatMap(asArray);
  const cidrSources = rawCidrSources.map((value) => clean(value)).filter(Boolean);
  const referenceSources = [properties.SourceSecurityGroupId, properties.SourcePrefixListId, properties.DestinationSecurityGroupId, properties.DestinationPrefixListId].flatMap(asArray).map((value) => clean(value)).filter(Boolean);
  const sources = [...cidrSources, ...referenceSources];
  const unresolved = rawCidrSources.some((source) => typeof source !== "string" && typeof source !== "number")
    || cidrSources.some((source) => /Ref:|GetAtt:|ImportValue:|\$\{|\{\s*"Fn::/.test(source))
    || [properties.FromPort, properties.ToPort].some((value) => value !== undefined && numberValue(value) === null);
  return {
    id: stableId([fileName, address, direction, protocolName(properties.IpProtocol), clean(properties.FromPort), clean(properties.ToPort), sources.join(",")]),
    direction,
    protocol: protocolName(properties.IpProtocol),
    fromPort: numberValue(properties.FromPort),
    toPort: numberValue(properties.ToPort),
    sources: sources.length ? sources : ["Unresolved source"],
    description: clean(properties.Description),
    fileName,
    resourceAddress: address,
    line,
    unresolved: unresolved || !sources.length,
  };
}

function parseCloudFormation(name: string, text: string, json: boolean): IacFileReview {
  let document: Record<string, unknown>;
  const warnings: string[] = [];
  if (json) {
    document = asRecord(JSON.parse(text));
  } else {
    const parsed = parseDocument(text, { prettyErrors: false, customTags: cloudFormationYamlTags });
    if (parsed.errors.length) throw new Error(`CloudFormation YAML is invalid: ${parsed.errors[0].message}`);
    const unknownWarnings = parsed.warnings.filter((warning) => !/Unresolved tag: !(Ref|Sub|GetAtt|Join|If|ImportValue|Select|Split|FindInMap|GetAZs|Base64|Cidr|Transform)/.test(warning.message));
    warnings.push(...unknownWarnings.slice(0, 8).map((warning) => warning.message.split("\n")[0]));
    document = asRecord(parsed.toJS({ maxAliasCount: 50 }));
  }
  const resources = asRecord(document.Resources);
  if (!Object.keys(resources).length) throw new Error("No CloudFormation Resources section was found.");
  if (Object.keys(resources).length > MAX_IAC_RESOURCES_PER_FILE) throw new Error(`CloudFormation templates are limited to ${MAX_IAC_RESOURCES_PER_FILE.toLocaleString()} resources per file.`);
  const context = cloudFormationContext(resources);
  const pending = new Map<string, PendingGroup>();
  const ensure = (key: string, logicalId: string, properties: Record<string, unknown>) => {
    const existing = pending.get(key);
    if (existing) return existing;
    const group: PendingGroup = {
      key,
      name: clean(properties.GroupName, logicalId),
      format: json ? "cloudformation-json" : "cloudformation-yaml",
      fileNames: [name],
      resourceAddresses: [logicalId],
      vpc: clean(properties.VpcId, "Unresolved VPC"),
      description: clean(properties.GroupDescription),
      rules: [],
      attachmentSignals: [],
      context,
    };
    pending.set(key, group);
    return group;
  };

  for (const [logicalId, rawResource] of Object.entries(resources)) {
    const resource = asRecord(rawResource);
    const type = clean(resource.Type);
    const properties = asRecord(resource.Properties);
    const line = resourceLine(text, logicalId);
    if (type === "AWS::EC2::SecurityGroup") {
      const group = ensure(`cloudformation:${logicalId}`, logicalId, properties);
      for (const [direction, value] of [["ingress", properties.SecurityGroupIngress], ["egress", properties.SecurityGroupEgress]] as const) {
        asArray(value).forEach((rule, index) => group.rules.push(cloudFormationRule(rule, direction, name, `${logicalId}.${direction}[${index}]`, line)));
      }
      continue;
    }
    if (type === "AWS::EC2::SecurityGroupIngress" || type === "AWS::EC2::SecurityGroupEgress") {
      const direction = type.endsWith("Ingress") ? "ingress" : "egress";
      const target = clean(properties.GroupId || properties.GroupName, `${logicalId}:unresolved-group`);
      const logicalTarget = target.replace(/^(Ref|GetAtt):/, "").split(/[.,]/)[0];
      const key = `cloudformation:${logicalTarget}`;
      const group = ensure(key, logicalTarget, {});
      if (!group.resourceAddresses.includes(logicalId)) group.resourceAddresses.push(logicalId);
      group.rules.push(cloudFormationRule(properties, direction, name, logicalId, line));
    }
  }

  for (const [logicalId, rawResource] of Object.entries(resources)) {
    const resource = asRecord(rawResource);
    const properties = asRecord(resource.Properties);
    const referenceText = clean([properties.SecurityGroupIds, properties.SecurityGroups, properties.GroupSet, properties.VpcSecurityGroupIds]);
    for (const group of pending.values()) {
      const logicalIdValue = group.key.replace("cloudformation:", "");
      if (referenceText.includes(logicalIdValue)) group.attachmentSignals.push(`${logicalId} · ${clean(resource.Type)}`);
    }
  }
  const groups = [...pending.values()].map(finalizeGroup).sort((left, right) => right.riskScore - left.riskScore || left.name.localeCompare(right.name));
  if (groups.reduce((sum, group) => sum + group.rules.length, 0) > MAX_IAC_RULES_PER_FILE) throw new Error(`Infrastructure files are limited to ${MAX_IAC_RULES_PER_FILE.toLocaleString()} security-group rules.`);
  return { name, format: json ? "cloudformation-json" : "cloudformation-yaml", status: "parsed", resourceCount: Object.keys(resources).length, ruleCount: groups.reduce((sum, group) => sum + group.rules.length, 0), warnings, groups };
}

function matchingBrace(text: string, openIndex: number) {
  let depth = 0;
  let quote = "";
  let escape = false;
  let lineComment = false;
  let blockComment = false;
  for (let index = openIndex; index < text.length; index += 1) {
    const char = text[index];
    const next = text[index + 1] ?? "";
    if (lineComment) { if (char === "\n") lineComment = false; continue; }
    if (blockComment) { if (char === "*" && next === "/") { blockComment = false; index += 1; } continue; }
    if (quote) {
      if (escape) { escape = false; continue; }
      if (char === "\\") { escape = true; continue; }
      if (char === quote) quote = "";
      continue;
    }
    if (char === "#" || (char === "/" && next === "/")) { lineComment = true; if (char === "/") index += 1; continue; }
    if (char === "/" && next === "*") { blockComment = true; index += 1; continue; }
    if (char === '"' || char === "'") { quote = char; continue; }
    if (char === "{") depth += 1;
    if (char === "}" && --depth === 0) return index;
  }
  return -1;
}

type HclBlock = { type: string; labels: string[]; body: string; start: number; bodyStart: number };

function hclBlocks(text: string, blockType?: string): HclBlock[] {
  const pattern = /\b([a-zA-Z_][\w-]*)\s*((?:"(?:[^"\\]|\\.)*"\s*){0,2})\{/g;
  const blocks: HclBlock[] = [];
  for (const match of text.matchAll(pattern)) {
    const type = match[1];
    if (blockType && type !== blockType) continue;
    const start = match.index ?? 0;
    const lineStart = text.lastIndexOf("\n", start) + 1;
    const before = text.slice(lineStart, start).trim();
    if (before && !before.startsWith("dynamic")) continue;
    const open = start + match[0].lastIndexOf("{");
    const close = matchingBrace(text, open);
    if (close < 0) continue;
    const labels = [...match[2].matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((label) => label[1]);
    blocks.push({ type, labels, body: text.slice(open + 1, close), start, bodyStart: open + 1 });
  }
  return blocks;
}

function hclAttribute(body: string, name: string) {
  const match = new RegExp(`(?:^|\\n)[ \\t]*${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[ \\t]*=[ \\t]*`, "m").exec(body);
  if (!match) return undefined;
  const start = match.index + match[0].length;
  let square = 0;
  let curly = 0;
  let paren = 0;
  let quote = "";
  let escape = false;
  for (let index = start; index < body.length; index += 1) {
    const char = body[index];
    if (quote) {
      if (escape) escape = false;
      else if (char === "\\") escape = true;
      else if (char === quote) quote = "";
      continue;
    }
    if (char === '"' || char === "'") { quote = char; continue; }
    if (char === "[") square += 1; else if (char === "]") square -= 1;
    if (char === "{") curly += 1; else if (char === "}") curly -= 1;
    if (char === "(") paren += 1; else if (char === ")") paren -= 1;
    if ((char === "\n" || char === "\r") && square <= 0 && curly <= 0 && paren <= 0) return body.slice(start, index).trim().replace(/,$/, "");
  }
  return body.slice(start).trim().replace(/,$/, "");
}

function hclLiteral(expression: string | undefined, variables: Map<string, string>): unknown {
  if (expression === undefined) return undefined;
  const value = expression.trim();
  if (variables.has(value)) return hclLiteral(variables.get(value), variables);
  if (/^"(?:[^"\\]|\\.)*"$/.test(value)) {
    try { return JSON.parse(value); } catch { return value.slice(1, -1); }
  }
  if (/^-?\d+(?:\.\d+)?$/.test(value)) return Number(value);
  if (value === "true") return true;
  if (value === "false") return false;
  if (value.startsWith("[") && value.endsWith("]")) {
    const inner = value.slice(1, -1).trim();
    if (!inner) return [];
    return inner.split(",").map((item) => hclLiteral(item.trim(), variables)).filter((item) => item !== undefined);
  }
  return value;
}

function terraformContext(text: string, variables: Map<string, string>): TemplateContext {
  const context = emptyContext();
  for (const block of hclBlocks(text, "resource")) {
    const type = block.labels[0] ?? "";
    if (["aws_internet_gateway", "aws_egress_only_internet_gateway"].includes(type)) context.internetGateway = true;
    if (type === "aws_route" && [clean(hclLiteral(hclAttribute(block.body, "destination_cidr_block"), variables)), clean(hclLiteral(hclAttribute(block.body, "destination_ipv6_cidr_block"), variables))].some(publicSource) && hclAttribute(block.body, "gateway_id")) context.publicRoute = true;
    if (hclLiteral(hclAttribute(block.body, "associate_public_ip_address"), variables) === true || type === "aws_eip") context.publicAddress = true;
    if ((type === "aws_lb" && hclLiteral(hclAttribute(block.body, "internal"), variables) !== true) || hclLiteral(hclAttribute(block.body, "publicly_accessible"), variables) === true) context.internetFacingService = true;
  }
  return context;
}

function terraformRule(block: HclBlock, direction: "ingress" | "egress", fileName: string, address: string, absoluteBodyStart: number, variables: Map<string, string>, fullText: string): IacRule {
  const attr = (name: string) => hclLiteral(hclAttribute(block.body, name), variables);
  const sourceValues = [attr("cidr_blocks"), attr("ipv6_cidr_blocks"), attr("cidr_ipv4"), attr("cidr_ipv6"), attr("source_security_group_id"), attr("referenced_security_group_id"), attr("prefix_list_ids")]
    .flatMap(asArray).map((value) => clean(value)).filter(Boolean);
  const protocolExpression = hclAttribute(block.body, "protocol") ?? hclAttribute(block.body, "ip_protocol");
  const fromExpression = hclAttribute(block.body, "from_port");
  const toExpression = hclAttribute(block.body, "to_port");
  const protocol = protocolName(hclLiteral(protocolExpression, variables));
  const fromPort = numberValue(hclLiteral(fromExpression, variables));
  const toPort = numberValue(hclLiteral(toExpression, variables));
  const unresolvedValues = [protocolExpression, fromExpression, toExpression, ...sourceValues].filter(Boolean).map((value) => clean(value));
  const unresolved = !sourceValues.length || unresolvedValues.some((value) => {
    if (/^(?:\$\{)?aws_security_group\.[\w-]+\.id\}?$/.test(value) || /^(?:\$\{)?aws_vpc_security_group\.[\w-]+\.id\}?$/.test(value)) return false;
    return /\b(var|local|module|data)\.|\$\{|each\.|count\./.test(value);
  });
  return {
    id: stableId([fileName, address, direction, protocol, fromPort, toPort, sourceValues.join(",")]),
    direction,
    protocol,
    fromPort,
    toPort,
    sources: sourceValues.length ? sourceValues : ["Unresolved source"],
    description: clean(attr("description")),
    fileName,
    resourceAddress: address,
    line: lineAt(fullText, absoluteBodyStart + block.start),
    unresolved,
  };
}

function parseTerraformHcl(name: string, text: string): IacFileReview {
  const resources = hclBlocks(text, "resource");
  if (!resources.length) throw new Error("No Terraform resource blocks were found.");
  if (resources.length > MAX_IAC_RESOURCES_PER_FILE) throw new Error(`Terraform files are limited to ${MAX_IAC_RESOURCES_PER_FILE.toLocaleString()} resources per file.`);
  const variables = new Map<string, string>();
  for (const block of hclBlocks(text, "variable")) {
    if (block.labels[0]) {
      const value = hclAttribute(block.body, "default");
      if (value !== undefined) variables.set(`var.${block.labels[0]}`, value);
    }
  }
  const context = terraformContext(text, variables);
  const pending = new Map<string, PendingGroup>();
  const ensure = (key: string, nameValue: string, block?: HclBlock) => {
    const existing = pending.get(key);
    if (existing) return existing;
    const group: PendingGroup = {
      key,
      name: nameValue,
      format: "terraform-hcl",
      fileNames: [name],
      resourceAddresses: [key.replace("terraform:", "")],
      vpc: block ? clean(hclLiteral(hclAttribute(block.body, "vpc_id"), variables), "Unresolved VPC") : "Unresolved VPC",
      description: block ? clean(hclLiteral(hclAttribute(block.body, "description"), variables)) : "",
      rules: [],
      attachmentSignals: [],
      context,
    };
    pending.set(key, group);
    return group;
  };

  for (const resource of resources) {
    const [type, resourceName = "unnamed"] = resource.labels;
    const address = `${type}.${resourceName}`;
    if (type === "aws_security_group") {
      const group = ensure(`terraform:${address}`, clean(hclLiteral(hclAttribute(resource.body, "name"), variables), resourceName), resource);
      for (const direction of ["ingress", "egress"] as const) {
        for (const nested of hclBlocks(resource.body, direction)) group.rules.push(terraformRule(nested, direction, name, `${address}.${direction}`, resource.bodyStart, variables, text));
      }
      continue;
    }
    if (["aws_security_group_rule", "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule"].includes(type)) {
      const targetExpression = clean(hclLiteral(hclAttribute(resource.body, "security_group_id"), variables), `${address}.unresolved`);
      const normalizedTarget = targetExpression.replace(/^\$\{?|\}?$/g, "").replace(/\.id$/, "");
      const key = `terraform:${normalizedTarget}`;
      const direction = type.includes("ingress") ? "ingress" : type.includes("egress") ? "egress" : clean(hclLiteral(hclAttribute(resource.body, "type"), variables), "ingress") === "egress" ? "egress" : "ingress";
      const group = ensure(key, normalizedTarget.split(".").at(-1) ?? resourceName);
      if (!group.resourceAddresses.includes(address)) group.resourceAddresses.push(address);
      group.rules.push(terraformRule({ ...resource, start: 0 }, direction, name, address, resource.start, variables, text));
    }
  }

  for (const resource of resources) {
    const [type, resourceName = "unnamed"] = resource.labels;
    if (["aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule"].includes(type)) continue;
    const referenceText = ["security_groups", "vpc_security_group_ids", "security_group_id"].map((attribute) => hclAttribute(resource.body, attribute) ?? "").join(" ");
    for (const group of pending.values()) {
      const target = group.key.replace("terraform:", "");
      if (referenceText.includes(target)) group.attachmentSignals.push(`${type}.${resourceName}`);
    }
  }
  const groups = [...pending.values()].map(finalizeGroup).sort((left, right) => right.riskScore - left.riskScore || left.name.localeCompare(right.name));
  if (groups.reduce((sum, group) => sum + group.rules.length, 0) > MAX_IAC_RULES_PER_FILE) throw new Error(`Infrastructure files are limited to ${MAX_IAC_RULES_PER_FILE.toLocaleString()} security-group rules.`);
  const warnings = text.includes("dynamic \"ingress\"") || text.includes("dynamic \"egress\"") ? ["Dynamic security-group rule blocks require resolved plan JSON for complete evaluation."] : [];
  return { name, format: "terraform-hcl", status: "parsed", resourceCount: resources.length, ruleCount: groups.reduce((sum, group) => sum + group.rules.length, 0), warnings, groups };
}

function terraformJsonBlocks(root: Record<string, unknown>) {
  const blocks: Array<{ type: string; name: string; body: Record<string, unknown> }> = [];
  const resources = asRecord(root.resource);
  for (const [type, names] of Object.entries(resources)) for (const [name, body] of Object.entries(asRecord(names))) blocks.push({ type, name, body: asRecord(body) });
  return blocks;
}

function terraformJsonRule(body: Record<string, unknown>, direction: "ingress" | "egress", fileName: string, address: string): IacRule {
  const sources = [body.cidr_blocks, body.ipv6_cidr_blocks, body.cidr_ipv4, body.cidr_ipv6, body.source_security_group_id, body.referenced_security_group_id, body.prefix_list_ids].flatMap(asArray).map((value) => clean(value)).filter(Boolean);
  const rawValues = [body.protocol, body.ip_protocol, body.from_port, body.to_port, ...sources].map((value) => clean(value));
  const unresolved = !sources.length || rawValues.some((value) => {
    if (/^(?:\$\{)?aws_security_group\.[\w-]+\.id\}?$/.test(value) || /^(?:\$\{)?aws_vpc_security_group\.[\w-]+\.id\}?$/.test(value)) return false;
    return /\$\{|\b(var|local|module|data)\./.test(value);
  });
  return { id: stableId([fileName, address, direction, rawValues.join("|")]), direction, protocol: protocolName(body.protocol ?? body.ip_protocol), fromPort: numberValue(body.from_port), toPort: numberValue(body.to_port), sources: sources.length ? sources : ["Unresolved source"], description: clean(body.description), fileName, resourceAddress: address, line: 1, unresolved };
}

function parseTerraformJson(name: string, text: string): IacFileReview {
  const document = asRecord(JSON.parse(text));
  const resources = terraformJsonBlocks(document);
  if (!resources.length) throw new Error("No Terraform JSON resource definitions were found.");
  if (resources.length > MAX_IAC_RESOURCES_PER_FILE) throw new Error(`Terraform files are limited to ${MAX_IAC_RESOURCES_PER_FILE.toLocaleString()} resources per file.`);
  const context = emptyContext();
  context.internetGateway = resources.some((resource) => ["aws_internet_gateway", "aws_egress_only_internet_gateway"].includes(resource.type));
  context.publicRoute = resources.some((resource) => resource.type === "aws_route" && [clean(resource.body.destination_cidr_block), clean(resource.body.destination_ipv6_cidr_block)].some(publicSource) && clean(resource.body.gateway_id));
  context.publicAddress = resources.some((resource) => resource.type === "aws_eip" || resource.body.associate_public_ip_address === true);
  context.internetFacingService = resources.some((resource) => (resource.type === "aws_lb" && resource.body.internal !== true) || resource.body.publicly_accessible === true);
  const pending = new Map<string, PendingGroup>();
  const ensure = (key: string, nameValue: string, body: Record<string, unknown> = {}) => {
    const existing = pending.get(key); if (existing) return existing;
    const group: PendingGroup = { key, name: nameValue, format: "terraform-json", fileNames: [name], resourceAddresses: [key.replace("terraform:", "")], vpc: clean(body.vpc_id, "Unresolved VPC"), description: clean(body.description), rules: [], attachmentSignals: [], context };
    pending.set(key, group); return group;
  };
  for (const resource of resources) {
    const address = `${resource.type}.${resource.name}`;
    if (resource.type === "aws_security_group") {
      const group = ensure(`terraform:${address}`, clean(resource.body.name, resource.name), resource.body);
      for (const direction of ["ingress", "egress"] as const) asArray(resource.body[direction]).forEach((rule, index) => group.rules.push(terraformJsonRule(asRecord(rule), direction, name, `${address}.${direction}[${index}]`)));
    } else if (["aws_security_group_rule", "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule"].includes(resource.type)) {
      const target = clean(resource.body.security_group_id, `${address}.unresolved`).replace(/\.id$/, "");
      const direction = resource.type.includes("ingress") ? "ingress" : resource.type.includes("egress") ? "egress" : clean(resource.body.type, "ingress") === "egress" ? "egress" : "ingress";
      const group = ensure(`terraform:${target}`, target.split(".").at(-1) ?? resource.name);
      group.rules.push(terraformJsonRule(resource.body, direction, name, address));
    }
  }
  const groups = [...pending.values()].map(finalizeGroup).sort((left, right) => right.riskScore - left.riskScore);
  if (groups.reduce((sum, group) => sum + group.rules.length, 0) > MAX_IAC_RULES_PER_FILE) throw new Error(`Infrastructure files are limited to ${MAX_IAC_RULES_PER_FILE.toLocaleString()} security-group rules.`);
  return { name, format: "terraform-json", status: "parsed", resourceCount: resources.length, ruleCount: groups.reduce((sum, group) => sum + group.rules.length, 0), warnings: [], groups };
}

function isSupportedName(name: string) {
  const normalized = name.toLowerCase();
  return IAC_FILE_EXTENSIONS.some((extension) => normalized.endsWith(extension));
}

export function reviewInfrastructureFile(name: string, text: string): IacFileReview {
  const safeName = name.slice(0, 240);
  try {
    if (!isSupportedName(safeName)) throw new Error("Choose a CloudFormation YAML/JSON or Terraform .tf/.tf.json file.");
    if (!text.trim()) throw new Error("The infrastructure file is empty.");
    if (new TextEncoder().encode(text).byteLength > MAX_IAC_FILE_BYTES) throw new Error("The infrastructure file is larger than 5 MB.");
    const lower = safeName.toLowerCase();
    if (lower.endsWith(".tf")) return parseTerraformHcl(safeName, text);
    if (lower.endsWith(".tf.json")) return parseTerraformJson(safeName, text);
    if (lower.endsWith(".yaml") || lower.endsWith(".yml") || lower.endsWith(".template")) return parseCloudFormation(safeName, text, false);
    const parsed = asRecord(JSON.parse(text));
    if (parsed.Resources) return parseCloudFormation(safeName, text, true);
    if (parsed.resource || parsed.module || parsed.variable || parsed.terraform) return parseTerraformJson(safeName, text);
    throw new Error("The JSON file is neither a CloudFormation template nor Terraform JSON configuration.");
  } catch (error) {
    return { name: safeName, status: "rejected", resourceCount: 0, ruleCount: 0, warnings: [], error: error instanceof Error ? error.message.slice(0, 500) : "The infrastructure file could not be parsed.", groups: [] };
  }
}

export function consolidateInfrastructureReviews(files: IacFileReview[]): IacReviewBatch {
  const grouped = new Map<string, IacSecurityGroupReview>();
  for (const file of files) for (const group of file.groups) {
    const existing = grouped.get(group.key);
    if (!existing) { grouped.set(group.key, group); continue; }
    const context: TemplateContext = {
      internetGateway: existing.pathSignals.internetGateway || group.pathSignals.internetGateway,
      publicRoute: existing.pathSignals.publicRoute || group.pathSignals.publicRoute,
      publicAddress: existing.pathSignals.publicAttachment || group.pathSignals.publicAttachment,
      internetFacingService: false,
    };
    const merged: PendingGroup = {
      key: group.key,
      name: existing.name || group.name,
      format: existing.format,
      fileNames: [...new Set([...existing.fileNames, ...group.fileNames])],
      resourceAddresses: [...new Set([...existing.resourceAddresses, ...group.resourceAddresses])],
      vpc: existing.vpc !== "Unresolved VPC" ? existing.vpc : group.vpc,
      description: existing.description || group.description,
      rules: [...existing.rules, ...group.rules],
      attachmentSignals: [...new Set([...existing.attachmentSignals, ...group.attachmentSignals])],
      context,
    };
    const finalized = finalizeGroup(merged);
    grouped.set(group.key, finalized);
  }
  const groups = [...grouped.values()].sort((left, right) => right.riskScore - left.riskScore || left.name.localeCompare(right.name));
  const issues = groups.flatMap((group) => group.issues);
  return {
    files,
    groups,
    totals: {
      files: files.length,
      parsedFiles: files.filter((file) => file.status === "parsed").length,
      rejectedFiles: files.filter((file) => file.status === "rejected").length,
      groups: groups.length,
      rules: groups.reduce((sum, group) => sum + group.rules.length, 0),
      issues: issues.length,
      critical: issues.filter((issue) => issue.severity === "critical").length,
      high: issues.filter((issue) => issue.severity === "high").length,
    },
  };
}
