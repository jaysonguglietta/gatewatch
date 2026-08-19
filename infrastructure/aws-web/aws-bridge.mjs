import { createServer } from "node:http";
import { createHash, timingSafeEqual } from "node:crypto";
import { BedrockRuntimeClient, ConverseCommand } from "@aws-sdk/client-bedrock-runtime";
import { GetObjectCommand, ListObjectsV2Command, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { AssumeRoleCommand, STSClient } from "@aws-sdk/client-sts";
import { fromTemporaryCredentials } from "@aws-sdk/credential-providers";
import {
  GetSecretValueCommand,
  PutSecretValueCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";

const port = 3001;
const host = process.env.GATEWATCH_AWS_BRIDGE_HOST ?? "127.0.0.1";
const token = process.env.GATEWATCH_AWS_BRIDGE_TOKEN ?? "";
const snapshotBucket = process.env.GATEWATCH_SNAPSHOT_BUCKET ?? "";
const snapshotKey = process.env.GATEWATCH_SNAPSHOT_KEY ?? "exports/latest.json";
const snapshotManifestKey = process.env.GATEWATCH_SNAPSHOT_MANIFEST_KEY ?? "manifests/latest.json";
const snapshotRegion = process.env.GATEWATCH_SNAPSHOT_REGION ?? process.env.AWS_REGION ?? "us-east-1";
const organizationEvidenceBucket = process.env.GATEWATCH_ORGANIZATION_EVIDENCE_BUCKET ?? "";
const organizationManifestKey = process.env.GATEWATCH_ORGANIZATION_MANIFEST_KEY ?? "manifests/latest.json";
const auditArchiveBucket = process.env.GATEWATCH_AUDIT_ARCHIVE_BUCKET ?? "";
const workspaceId = process.env.GATEWATCH_WORKSPACE_ID ?? "";
const maxRequestBytes = 96_000;
const maxSnapshotBytes = 25 * 1024 * 1024;
const maxManifestBytes = 8 * 1024 * 1024;
const jiraSecretArn = process.env.GATEWATCH_JIRA_SECRET_ARN ?? "";
const adxSecretArn = process.env.GATEWATCH_ADX_SECRET_ARN ?? "";
const region = process.env.AWS_REGION ?? "us-east-1";
const bridgeRoleArn = process.env.GATEWATCH_AWS_BRIDGE_ROLE_ARN ?? "";
if (!/^arn:[a-z0-9-]+:iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_\/-]{1,512}$/.test(bridgeRoleArn)) {
  throw new Error("The AWS bridge requires its dedicated runtime role ARN.");
}
const credentials = fromTemporaryCredentials({
  params: {
    RoleArn: bridgeRoleArn,
    RoleSessionName: "gatewatch-aws-bridge",
    DurationSeconds: 3600,
  },
  clientConfig: { region },
});
const secrets = new SecretsManagerClient({ region, credentials });
const bedrockEnabled = process.env.GATEWATCH_BEDROCK_ENABLED === "true";
const bedrockModelId = process.env.GATEWATCH_BEDROCK_MODEL_ID ?? "us.amazon.nova-2-lite-v1:0";
const bedrockGuardrailId = process.env.GATEWATCH_BEDROCK_GUARDRAIL_ID ?? "";
const bedrockGuardrailVersion = process.env.GATEWATCH_BEDROCK_GUARDRAIL_VERSION ?? "";
const bedrock = new BedrockRuntimeClient({ region, credentials });

if (!token || !snapshotBucket || !auditArchiveBucket || !/^[a-f0-9-]{36}$/.test(workspaceId)) {
  throw new Error("The AWS bridge requires its private token, snapshot bucket, audit archive, and workspace identity.");
}

function json(response, status, value) {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  response.end(JSON.stringify(value));
}

function authorized(request) {
  const value = request.headers.authorization ?? "";
  return value.length === token.length + 7 && value === `Bearer ${token}`;
}

async function requestBody(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maxRequestBytes) throw new Error("REQUEST_TOO_LARGE");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function text(value, max = 500) {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}

function bedrockStatus() {
  return {
    enabled: bedrockEnabled,
    modelId: bedrockEnabled ? bedrockModelId : "",
    region: process.env.AWS_REGION ?? "us-east-1",
    guardrailConfigured: Boolean(bedrockGuardrailId && bedrockGuardrailVersion),
    guardrailVersion: bedrockGuardrailVersion,
  };
}

async function archiveAuditEvent(input) {
  const event = {
    schemaVersion: input?.schemaVersion === "1.0" ? "1.0" : "",
    id: text(input?.id, 36),
    workspaceId: text(input?.workspaceId, 64),
    actorSubject: text(input?.actorSubject, 255),
    action: text(input?.action, 120),
    targetType: text(input?.targetType, 120),
    targetId: text(input?.targetId, 500),
    summary: text(input?.summary, 800),
    metadata: input?.metadata && typeof input.metadata === "object" && !Array.isArray(input.metadata)
      ? input.metadata
      : {},
    createdAt: text(input?.createdAt, 40),
  };
  const created = new Date(event.createdAt);
  if (
    event.schemaVersion !== "1.0"
    || !/^[a-f0-9-]{36}$/.test(event.id)
    || event.workspaceId !== "default"
    || !/^[A-Za-z0-9:_-]{8,255}$/.test(event.actorSubject)
    || !/^[a-z0-9._-]{2,120}$/.test(event.action)
    || !event.targetType
    || !event.targetId
    || !event.summary
    || !Number.isFinite(created.getTime())
  ) {
    throw new Error("AUDIT_EVENT_INVALID");
  }
  const body = Buffer.from(`${JSON.stringify({ ...event, workspaceId })}\n`, "utf8");
  if (body.length > 16_384) throw new Error("AUDIT_EVENT_TOO_LARGE");
  const digest = createHash("sha256").update(body).digest("hex");
  const key = `audit/application/workspace=${workspaceId}/date=${created.toISOString().slice(0, 10)}/${event.id}.json`;
  const result = await new S3Client({ region, credentials }).send(
    new PutObjectCommand({
      Bucket: auditArchiveBucket,
      Key: key,
      Body: body,
      ContentType: "application/x-ndjson",
      ChecksumSHA256: createHash("sha256").update(body).digest("base64"),
      Metadata: { "content-sha256": digest, "event-id": event.id },
    }),
  );
  if (!result.VersionId) throw new Error("AUDIT_ARCHIVE_VERSION_REQUIRED");
  return { archived: true, versionId: result.VersionId, digest };
}

async function analyzeWithBedrock(input) {
  if (!bedrockEnabled) throw new Error("BEDROCK_NOT_CONFIGURED");
  const mode = text(input.mode, 20);
  const system = text(input.system, 4_000);
  const prompt = text(input.prompt, 60_000);
  const schema = input.schema && typeof input.schema === "object" && !Array.isArray(input.schema) ? input.schema : null;
  const schemaText = schema ? JSON.stringify(schema) : "";
  if (!new Set(["finding", "hunt", "digest", "cluster", "remediation"]).has(mode) || !system || !prompt || !schema || schemaText.length > 16_000 || schema.additionalProperties !== false) {
    throw new Error("BEDROCK_REQUEST_INVALID");
  }
  const started = Date.now();
  const traceId = createHash("sha256").update(`${mode}|${prompt}`, "utf8").digest("hex").slice(0, 24);
  const result = await bedrock.send(new ConverseCommand({
    modelId: bedrockModelId,
    system: [{ text: system }],
    messages: [{
      role: "user",
      content: [{ guardContent: { text: { text: prompt, qualifiers: ["guard_content"] } } }],
    }],
    inferenceConfig: { maxTokens: 4_000, temperature: 0, topP: 0.2 },
    ...(bedrockGuardrailId && bedrockGuardrailVersion ? {
      guardrailConfig: {
        guardrailIdentifier: bedrockGuardrailId,
        guardrailVersion: bedrockGuardrailVersion,
        trace: "enabled",
      },
    } : {}),
    toolConfig: {
      tools: [{
        toolSpec: {
          name: "submit_gatewatch_analysis",
          description: "Return the evidence-cited Gatewatch security analysis. This tool records advisory output and never executes a change.",
          inputSchema: { json: schema },
        },
      }],
      toolChoice: { tool: { name: "submit_gatewatch_analysis" } },
    },
    requestMetadata: { application: "gatewatch", mode, traceId },
  }));
  const toolUse = result.output?.message?.content?.find((item) => item.toolUse?.name === "submit_gatewatch_analysis")?.toolUse;
  if (!toolUse?.input || Buffer.byteLength(JSON.stringify(toolUse.input), "utf8") > 64_000) throw new Error("BEDROCK_OUTPUT_INVALID");
  const analysis = toolUse.input;
  return {
    analysis,
    modelId: bedrockModelId,
    usage: {
      inputTokens: Number(result.usage?.inputTokens ?? 0),
      outputTokens: Number(result.usage?.outputTokens ?? 0),
      latencyMs: Number(result.metrics?.latencyMs ?? Date.now() - started),
    },
    guardrail: {
      configured: Boolean(bedrockGuardrailId && bedrockGuardrailVersion),
      action: text(result.stopReason, 80) || "completed",
      traceId,
    },
  };
}

async function jiraSecret() {
  if (!jiraSecretArn) throw new Error("JIRA_NOT_AVAILABLE");
  const result = await secrets.send(
    new GetSecretValueCommand({ SecretId: jiraSecretArn }),
  );
  try {
    return JSON.parse(result.SecretString || '{"configured":false}');
  } catch {
    throw new Error("JIRA_SECRET_INVALID");
  }
}

function jiraConfiguration(input, existing = {}) {
  const rawUrl = text(input.baseUrl ?? existing.baseUrl, 400).replace(/\/$/, "");
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error("JIRA_URL_INVALID");
  }
  if (
    parsed.protocol !== "https:" ||
    !parsed.hostname.endsWith(".atlassian.net") ||
    parsed.username ||
    parsed.password ||
    (parsed.pathname !== "/" && parsed.pathname !== "") ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error("JIRA_URL_INVALID");
  }
  const email = text(input.email ?? existing.email, 254).toLowerCase();
  const apiToken = text(input.apiToken, 1000) || text(existing.apiToken, 1000);
  const projectKey = text(input.projectKey ?? existing.projectKey, 20).toUpperCase();
  const issueType = text(input.issueType ?? existing.issueType, 80) || "Task";
  if (
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    apiToken.length < 8 ||
    !/^[A-Z][A-Z0-9_]{1,19}$/.test(projectKey)
  ) {
    throw new Error("JIRA_CONFIGURATION_INVALID");
  }
  return { baseUrl: parsed.origin, email, apiToken, projectKey, issueType };
}

async function jiraRequest(configuration, path, init = {}) {
  const response = await fetch(`${configuration.baseUrl}${path}`, {
    ...init,
    redirect: "error",
    headers: {
      accept: "application/json",
      authorization: `Basic ${Buffer.from(`${configuration.email}:${configuration.apiToken}`).toString("base64")}`,
      ...(init.body ? { "content-type": "application/json" } : {}),
      ...(init.headers ?? {}),
    },
    signal: AbortSignal.timeout(15_000),
  });
  const body = await response.text();
  if (Buffer.byteLength(body) > 512_000) throw new Error("JIRA_RESPONSE_TOO_LARGE");
  let payload = {};
  if (body) {
    try { payload = JSON.parse(body); } catch { payload = {}; }
  }
  if (!response.ok) {
    const detail = text(
      payload.errorMessages?.[0] ?? Object.values(payload.errors ?? {})[0],
      240,
    );
    const error = new Error(detail || `JIRA_HTTP_${response.status}`);
    error.statusCode = response.status;
    throw error;
  }
  return payload;
}

async function testJira(input) {
  const existing = await jiraSecret();
  const configuration = jiraConfiguration(input, existing);
  const [user, project, issueTypes] = await Promise.all([
    jiraRequest(configuration, "/rest/api/3/myself"),
    jiraRequest(configuration, `/rest/api/3/project/${encodeURIComponent(configuration.projectKey)}`),
    jiraRequest(configuration, `/rest/api/3/issue/createmeta/${encodeURIComponent(configuration.projectKey)}/issuetypes`),
  ]);
  const types = Array.isArray(issueTypes.values) ? issueTypes.values : [];
  if (!types.some((item) => item.name === configuration.issueType)) {
    throw new Error("JIRA_ISSUE_TYPE_NOT_AVAILABLE");
  }
  return {
    passed: true,
    testedAt: new Date().toISOString(),
    displayName: text(user.displayName, 160),
    projectName: text(project.name, 160),
    issueTypes: types.map((item) => text(item.name, 80)).filter(Boolean).slice(0, 50),
    configuration,
  };
}

async function saveJira(input) {
  const tested = await testJira(input);
  const stored = {
    ...tested.configuration,
    configured: true,
    displayName: tested.displayName,
    projectName: tested.projectName,
    issueTypes: tested.issueTypes,
    lastTestedAt: tested.testedAt,
  };
  await secrets.send(
    new PutSecretValueCommand({
      SecretId: jiraSecretArn,
      SecretString: JSON.stringify(stored),
    }),
  );
  return jiraStatus(stored);
}

function jiraStatus(configuration) {
  return {
    configured: Boolean(configuration.configured),
    baseUrl: text(configuration.baseUrl, 400),
    email: text(configuration.email, 254),
    projectKey: text(configuration.projectKey, 20),
    issueType: text(configuration.issueType, 80) || "Task",
    displayName: text(configuration.displayName, 160),
    projectName: text(configuration.projectName, 160),
    issueTypes: Array.isArray(configuration.issueTypes)
      ? configuration.issueTypes.map((item) => text(item, 80)).filter(Boolean).slice(0, 50)
      : [],
    lastTestedAt: text(configuration.lastTestedAt, 80),
    tokenStored: Boolean(configuration.apiToken),
  };
}

function publicJiraError(error) {
  const code = error instanceof Error ? error.message : "";
  const status = Number(error?.statusCode ?? 0);
  if (code === "JIRA_NOT_CONFIGURED") return "Configure Jira Cloud in Admin → Integrations before creating tickets.";
  if (code === "JIRA_URL_INVALID") return "Enter the root URL for an HTTPS *.atlassian.net Jira Cloud site.";
  if (code === "JIRA_CONFIGURATION_INVALID") return "Check the Jira email, API token, and project key.";
  if (code === "JIRA_ISSUE_TYPE_NOT_AVAILABLE") return "The selected issue type is not available in this Jira project.";
  if (code === "JIRA_FINDINGS_LIMIT") return "Create Jira tickets in batches of 20 findings or fewer.";
  if (code === "JIRA_FINDINGS_REQUIRED") return "Select at least one finding.";
  if (status === 401) return "Jira rejected the email or API token.";
  if (status === 403) return "The Jira identity needs Browse Projects and Create Issues permissions.";
  if (status === 404) return "The Jira project or issue type could not be found.";
  if (status === 429) return "Jira rate-limited the request. Wait a moment and retry.";
  return "Jira Cloud could not complete the request.";
}

function adfText(value) {
  return { type: "text", text: text(value, 1500) || "Not available" };
}

function jiraDescription(finding) {
  const lines = [
    ["Security group", `${text(finding.securityGroupName, 240)} (${text(finding.securityGroupId, 120)})`],
    ["Account", `${text(finding.accountName, 240)} (${text(finding.accountId, 20)})`],
    ["Region", text(finding.region, 40)],
    ["Severity / risk", `${text(finding.severity, 20)} / ${Number(finding.riskScore) || 0}`],
    ["Effective rule", text(finding.ruleSummary, 1000)],
    ["Exposure", text(finding.pathSummary, 1000)],
    ["Owner", text(finding.owner, 240)],
    ["Recommended action", text(finding.recommendation, 1500)],
  ];
  return {
    type: "doc",
    version: 1,
    content: [
      { type: "paragraph", content: [adfText("Gatewatch created this issue from an evidence-backed security-group finding.")] },
      {
        type: "bulletList",
        content: lines.map(([label, value]) => ({
          type: "listItem",
          content: [{ type: "paragraph", content: [{ type: "text", text: `${label}: `, marks: [{ type: "strong" }] }, adfText(value)] }],
        })),
      },
      { type: "paragraph", content: [adfText(`Finding fingerprint: ${text(finding.fingerprint, 200)}`)] },
    ],
  };
}

async function createJiraIssues(input) {
  const configuration = await jiraSecret();
  if (!configuration.configured) throw new Error("JIRA_NOT_CONFIGURED");
  const validated = jiraConfiguration({}, configuration);
  const findings = Array.isArray(input.findings) ? input.findings : [];
  if (!findings.length) throw new Error("JIRA_FINDINGS_REQUIRED");
  if (findings.length > 20) throw new Error("JIRA_FINDINGS_LIMIT");
  const created = [];
  const failed = [];
  for (const finding of findings) {
    try {
      const payload = await jiraRequest(validated, "/rest/api/3/issue", {
        method: "POST",
        body: JSON.stringify({
          fields: {
            project: { key: validated.projectKey },
            issuetype: { name: validated.issueType },
            summary: `[Gatewatch] ${text(finding.title, 220)}`,
            description: jiraDescription(finding),
            labels: ["gatewatch", "security-group", `severity-${text(finding.severity, 20).toLowerCase()}`],
          },
        }),
      });
      const key = text(payload.key, 80);
      if (!key) throw new Error("JIRA_ISSUE_KEY_MISSING");
      created.push({
        fingerprint: text(finding.fingerprint, 200),
        key,
        url: `${validated.baseUrl}/browse/${encodeURIComponent(key)}`,
      });
    } catch (error) {
      failed.push({
        fingerprint: text(finding.fingerprint, 200),
        error: publicJiraError(error),
      });
    }
  }
  return { created, failed, projectKey: validated.projectKey };
}

async function syncJiraIssues(input) {
  const configuration = await jiraSecret();
  if (!configuration.configured) throw new Error("JIRA_NOT_CONFIGURED");
  const validated = jiraConfiguration({}, configuration);
  const issueKeys = Array.isArray(input.issueKeys)
    ? input.issueKeys.map((value) => text(value, 80)).filter(Boolean).slice(0, 50)
    : [];
  const issues = [];
  for (const issueKey of issueKeys) {
    try {
      const payload = await jiraRequest(
        validated,
        `/rest/api/3/issue/${encodeURIComponent(issueKey)}?fields=status,resolution,updated`,
      );
      issues.push({
        key: issueKey,
        status: text(payload.fields?.status?.name, 120),
        statusCategory: text(payload.fields?.status?.statusCategory?.key, 80),
        resolution: text(payload.fields?.resolution?.name, 120),
        updatedAt: text(payload.fields?.updated, 80),
      });
    } catch (error) {
      issues.push({ key: issueKey, error: publicJiraError(error) });
    }
  }
  return { issues, syncedAt: new Date().toISOString() };
}

function sourceFormat(source, key = "") {
  if (source.sourceType === "cloudtrail" || key.includes("CloudTrail")) {
    return "AWS CloudTrail JSON.GZ";
  }
  if (source.sourceType === "config-history" || key.includes("ConfigHistory")) {
    return "AWS Config history";
  }
  return "AWS Config snapshot";
}

function check(key, label, status, detail) {
  return { key, label, status, detail };
}

async function inventory() {
  const s3 = new S3Client({ region: snapshotRegion, credentials });
  const manifestResult = await s3.send(
    new GetObjectCommand({ Bucket: snapshotBucket, Key: snapshotManifestKey }),
  );
  const manifestValue = await manifestResult.Body?.transformToString("utf8");
  if (!manifestValue || Buffer.byteLength(manifestValue) > 1_000_000) {
    throw new Error("SNAPSHOT_MANIFEST_INVALID");
  }
  const manifest = JSON.parse(manifestValue);
  if (
    manifest?.schemaVersion !== "1.0"
    || manifest?.complete !== true
    || !/^[a-f0-9]{64}$/.test(String(manifest?.sha256 ?? ""))
    || typeof manifest?.snapshotId !== "string"
  ) {
    throw new Error("SNAPSHOT_MANIFEST_SCHEMA_INVALID");
  }
  const result = await s3.send(
    new GetObjectCommand({ Bucket: snapshotBucket, Key: snapshotKey }),
  );
  if (
    typeof result.ContentLength === "number" &&
    result.ContentLength > maxSnapshotBytes
  ) {
    throw new Error("SNAPSHOT_TOO_LARGE");
  }
  const value = await result.Body?.transformToString("utf8");
  if (!value || Buffer.byteLength(value) > maxSnapshotBytes) {
    throw new Error("SNAPSHOT_INVALID");
  }
  const expected = Buffer.from(manifest.sha256, "hex");
  const actual = createHash("sha256").update(value, "utf8").digest();
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
    throw new Error("SNAPSHOT_CHECKSUM_MISMATCH");
  }
  const snapshot = JSON.parse(value);
  if (snapshot.snapshotId !== manifest.snapshotId || snapshot.complete !== true) {
    throw new Error("SNAPSHOT_MANIFEST_MISMATCH");
  }
  return snapshot;
}

async function organizationCoverage() {
  if (!organizationEvidenceBucket) throw new Error("ORGANIZATION_EVIDENCE_NOT_CONFIGURED");
  const result = await new S3Client({ region: snapshotRegion, credentials }).send(
    new GetObjectCommand({
      Bucket: organizationEvidenceBucket,
      Key: organizationManifestKey,
    }),
  );
  if (typeof result.ContentLength === "number" && result.ContentLength > maxManifestBytes) {
    throw new Error("ORGANIZATION_MANIFEST_TOO_LARGE");
  }
  const value = await result.Body?.transformToString("utf8");
  if (!value || Buffer.byteLength(value) > maxManifestBytes) {
    throw new Error("ORGANIZATION_MANIFEST_INVALID");
  }
  const parsed = JSON.parse(value);
  if (
    parsed?.schemaVersion !== "2.0"
    || parsed?.evidenceType !== "organization-collection-manifest"
    || !Array.isArray(parsed.accounts)
    || !Array.isArray(parsed.targets)
  ) {
    throw new Error("ORGANIZATION_MANIFEST_SCHEMA_INVALID");
  }
  return parsed;
}

async function testSource(source) {
  const region = text(source.region, 40);
  const roleArn = text(source.roleArn, 600);
  const bucketName = text(source.bucketName, 255);
  const objectPrefix = text(source.objectPrefix, 1024);
  const externalId = text(source.externalId, 160);
  if (
    !/^[a-z0-9-]+-[0-9]$/.test(region) ||
    !/^arn:[a-z0-9-]+:iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_\/-]+$/.test(roleArn) ||
    !/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(bucketName)
  ) {
    throw new Error("INVALID_SOURCE_CONFIGURATION");
  }
  const testedAt = new Date().toISOString();
  const assumed = await new STSClient({ region, credentials }).send(
    new AssumeRoleCommand({
      RoleArn: roleArn,
      RoleSessionName: `gatewatch-source-test-${Date.now()}`,
      ExternalId: externalId || undefined,
      DurationSeconds: 900,
    }),
  );
  if (
    !assumed.Credentials?.AccessKeyId ||
    !assumed.Credentials.SecretAccessKey ||
    !assumed.Credentials.SessionToken
  ) {
    throw new Error("INCOMPLETE_STS_CREDENTIALS");
  }
  const s3 = new S3Client({
    region,
    credentials: {
      accessKeyId: assumed.Credentials.AccessKeyId,
      secretAccessKey: assumed.Credentials.SecretAccessKey,
      sessionToken: assumed.Credentials.SessionToken,
      expiration: assumed.Credentials.Expiration,
    },
  });
  const listing = await s3.send(
    new ListObjectsV2Command({
      Bucket: bucketName,
      Prefix: objectPrefix || undefined,
      MaxKeys: 5,
    }),
  );
  const newest = [...(listing.Contents ?? [])]
    .filter((item) => item.Key)
    .sort(
      (a, b) =>
        (b.LastModified?.getTime() ?? 0) -
        (a.LastModified?.getTime() ?? 0),
    )[0];
  if (!newest?.Key) {
    return {
      mode: "live",
      testedAt,
      passed: false,
      detectedFormat: sourceFormat(source),
      checks: [
        check("role", "Assume role", "passed", "STS issued temporary credentials."),
        check("list", "List configured prefix", "passed", "The prefix is readable but contains no objects."),
        check("sample", "Read sample object", "failed", "Add a CloudTrail or AWS Config delivery file, then test again."),
      ],
    };
  }
  await s3.send(
    new GetObjectCommand({
      Bucket: bucketName,
      Key: newest.Key,
      Range: "bytes=0-65535",
    }),
  );
  return {
    mode: "live",
    testedAt,
    passed: true,
    detectedFormat: sourceFormat(source, newest.Key),
    newestObject: {
      key: newest.Key,
      size: newest.Size ?? 0,
      lastModified: newest.LastModified?.toISOString() ?? "",
    },
    checks: [
      check("role", "Assume role", "passed", "STS issued temporary credentials."),
      check("list", "List configured prefix", "passed", `${listing.KeyCount ?? 0} sample object(s) discovered.`),
      check("sample", "Read sample object", "passed", "A bounded range read succeeded; KMS access is available if required."),
      check("format", "Detected delivery format", "passed", sourceFormat(source, newest.Key)),
    ],
  };
}

const ADX_CLUSTER_SUFFIXES = [
  ".kusto.windows.net",
  ".kusto.usgovcloudapi.net",
  ".kusto.chinacloudapi.cn",
];

function adxSource(input) {
  const sourceId = text(input.sourceId, 80);
  const clusterUrl = text(input.clusterUrl, 400).replace(/\/$/, "");
  const database = text(input.database, 127);
  const table = text(input.table, 127);
  const timestampColumn = text(input.timestampColumn, 127);
  const payloadColumn = text(input.payloadColumn, 127);
  const queryMode = text(input.queryMode, 30);
  const batchSize = Math.trunc(Number(input.batchSize) || 500);
  const tenantId = text(input.tenantId, 36).toLowerCase();
  const clientId = text(input.clientId, 36).toLowerCase();
  const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
  let parsed;
  try { parsed = new URL(clusterUrl); } catch { throw new Error("ADX_CLUSTER_INVALID"); }
  const hostname = parsed.hostname.toLowerCase();
  if (
    !/^src-[a-f0-9-]{36}$/.test(sourceId) ||
    parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.port ||
    (parsed.pathname !== "/" && parsed.pathname !== "") || parsed.search || parsed.hash ||
    !ADX_CLUSTER_SUFFIXES.some((suffix) => hostname.endsWith(suffix)) ||
    hostname.split(".").some((label) => !/^[a-z0-9-]{1,63}$/.test(label)) ||
    ![database, table, timestampColumn].every((value) => /^[A-Za-z_][A-Za-z0-9_]{0,126}$/.test(value)) ||
    (payloadColumn && !/^[A-Za-z_][A-Za-z0-9_]{0,126}$/.test(payloadColumn)) ||
    !["whole-row", "payload-column"].includes(queryMode) ||
    (queryMode === "payload-column" && !payloadColumn) ||
    batchSize < 10 || batchSize > 1000 || !uuid.test(tenantId) || !uuid.test(clientId)
  ) {
    throw new Error("ADX_SOURCE_INVALID");
  }
  return {
    sourceId,
    clusterUrl: `https://${hostname}`,
    database,
    table,
    timestampColumn,
    payloadColumn,
    queryMode,
    batchSize,
    tenantId,
    clientId,
  };
}

async function adxVault() {
  if (!adxSecretArn) throw new Error("ADX_NOT_AVAILABLE");
  const result = await secrets.send(new GetSecretValueCommand({ SecretId: adxSecretArn }));
  try {
    const parsed = JSON.parse(result.SecretString || "{}");
    return {
      connections: parsed.connections && typeof parsed.connections === "object" && !Array.isArray(parsed.connections)
        ? parsed.connections
        : {},
    };
  } catch {
    throw new Error("ADX_SECRET_INVALID");
  }
}

function adxCredential(input) {
  const tenantId = text(input.tenantId, 36).toLowerCase();
  const clientId = text(input.clientId, 36).toLowerCase();
  const clientSecret = typeof input.clientSecret === "string" ? input.clientSecret.slice(0, 2_000) : "";
  const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
  if (!uuid.test(tenantId) || !uuid.test(clientId) || clientSecret.length < 16 || /[\u0000\r\n]/.test(clientSecret)) {
    throw new Error("ADX_CREDENTIAL_INVALID");
  }
  return { tenantId, clientId, clientSecret };
}

async function saveAdxCredential(input) {
  const source = adxSource(input);
  const credential = adxCredential(input);
  const vault = await adxVault();
  vault.connections[source.sourceId] = credential;
  await secrets.send(new PutSecretValueCommand({
    SecretId: adxSecretArn,
    SecretString: JSON.stringify(vault),
  }));
  return { configured: true };
}

async function removeAdxCredential(input) {
  const sourceId = text(input.sourceId, 80);
  if (!/^src-[a-f0-9-]{36}$/.test(sourceId)) throw new Error("ADX_SOURCE_INVALID");
  const vault = await adxVault();
  const removed = Boolean(vault.connections[sourceId]);
  delete vault.connections[sourceId];
  await secrets.send(new PutSecretValueCommand({
    SecretId: adxSecretArn,
    SecretString: JSON.stringify(vault),
  }));
  return { removed };
}

async function boundedFetchJson(response, maximumBytes) {
  const declared = Number(response.headers.get("content-length") || 0);
  if (declared > maximumBytes) throw new Error("ADX_RESPONSE_TOO_LARGE");
  const chunks = [];
  let received = 0;
  const reader = response.body?.getReader();
  if (reader) {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > maximumBytes) {
        await reader.cancel();
        throw new Error("ADX_RESPONSE_TOO_LARGE");
      }
      chunks.push(Buffer.from(value));
    }
  }
  const body = Buffer.concat(chunks).toString("utf8");
  try { return body ? JSON.parse(body) : {}; } catch { throw new Error("ADX_RESPONSE_INVALID"); }
}

function adxAuthority(clusterUrl, tenantId) {
  const hostname = new URL(clusterUrl).hostname;
  if (hostname.endsWith(".kusto.usgovcloudapi.net")) return `https://login.microsoftonline.us/${tenantId}/oauth2/v2.0/token`;
  if (hostname.endsWith(".kusto.chinacloudapi.cn")) return `https://login.chinacloudapi.cn/${tenantId}/oauth2/v2.0/token`;
  return `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;
}

async function adxAccessToken(source, credential) {
  const body = new URLSearchParams({
    client_id: credential.clientId,
    client_secret: credential.clientSecret,
    grant_type: "client_credentials",
    scope: `${source.clusterUrl}/.default`,
  });
  const response = await fetch(adxAuthority(source.clusterUrl, credential.tenantId), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
    redirect: "error",
    signal: AbortSignal.timeout(12_000),
  });
  const payload = await boundedFetchJson(response, 256 * 1024);
  if (!response.ok || typeof payload.access_token !== "string" || payload.access_token.length < 100) {
    const error = new Error("ADX_AUTHENTICATION_FAILED");
    error.statusCode = response.status;
    throw error;
  }
  return payload.access_token;
}

function primaryAdxTable(payload) {
  if (Array.isArray(payload)) {
    return payload.find((frame) => frame?.FrameType === "DataTable" && frame?.TableKind === "PrimaryResult")
      ?? payload.find((frame) => Array.isArray(frame?.Columns) && Array.isArray(frame?.Rows));
  }
  if (Array.isArray(payload?.Tables)) return payload.Tables[0];
  return null;
}

function adxRecords(payload, source) {
  const table = primaryAdxTable(payload);
  if (!table || !Array.isArray(table.Columns) || !Array.isArray(table.Rows)) {
    throw new Error("ADX_RESULT_SCHEMA_INVALID");
  }
  const columns = table.Columns.map((column, index) => text(column?.ColumnName ?? column?.name, 127) || `column_${index + 1}`);
  const records = [];
  let skippedRows = 0;
  let queriedRows = 0;
  let nextCheckpoint = "";
  let nextCursor = "";
  for (const values of table.Rows.slice(0, source.batchSize)) {
    queriedRows += 1;
    if (!Array.isArray(values)) {
      skippedRows += 1;
      continue;
    }
    const row = Object.fromEntries(columns.map((column, index) => [column, values[index] ?? null]));
    const cursorValue = text(row.GatewatchCursor ?? row.__gatewatch_cursor, 64).toLowerCase();
    const timestampValue = source.queryMode === "payload-column"
      ? row.GatewatchTimestamp
      : row[source.timestampColumn];
    const timestamp = typeof timestampValue === "string" && Number.isFinite(Date.parse(timestampValue))
      ? new Date(timestampValue).toISOString()
      : "";
    if (timestamp && (timestamp > nextCheckpoint || (timestamp === nextCheckpoint && cursorValue > nextCursor))) {
      nextCheckpoint = timestamp;
      nextCursor = cursorValue;
    }
    if (source.queryMode === "payload-column") {
      const raw = row.GatewatchPayload;
      let parsed = raw;
      if (typeof raw === "string") {
        try { parsed = JSON.parse(raw); } catch { skippedRows += 1; continue; }
      }
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        skippedRows += 1;
        continue;
      }
      records.push(timestamp && !parsed[source.timestampColumn]
        ? { ...parsed, [source.timestampColumn]: timestamp }
        : parsed);
    } else {
      delete row.__gatewatch_cursor;
      records.push(timestamp && !row.timestamp && !row.eventTime && !row.time
        ? { ...row, timestamp }
        : row);
    }
  }
  return {
    columns: columns.filter((column) => column !== "__gatewatch_cursor" && column !== "GatewatchCursor"),
    records,
    skippedRows,
    queriedRows,
    nextCheckpoint,
    nextCursor,
  };
}

async function queryAdx(input) {
  const source = adxSource(input);
  const mode = text(input.mode, 20) === "sync" ? "sync" : "preview";
  const checkpointDate = new Date(text(input.checkpoint, 80));
  const checkpointCursor = text(input.cursor, 64).toLowerCase();
  if (mode === "sync" && !Number.isFinite(checkpointDate.getTime())) {
    throw new Error("ADX_CHECKPOINT_INVALID");
  }
  if (mode === "sync" && !/^[a-f0-9]{0,64}$/.test(checkpointCursor)) {
    throw new Error("ADX_CHECKPOINT_INVALID");
  }
  const vault = await adxVault();
  const credential = vault.connections[source.sourceId];
  if (!credential) throw new Error("ADX_CREDENTIAL_NOT_CONFIGURED");
  if (credential.tenantId !== source.tenantId || credential.clientId !== source.clientId) {
    throw new Error("ADX_CREDENTIAL_IDENTITY_MISMATCH");
  }
  const token = await adxAccessToken(source, credential);
  const projection = source.queryMode === "payload-column"
    ? `| project GatewatchTimestamp=${source.timestampColumn}, GatewatchCursor=__gatewatch_cursor, GatewatchPayload=${source.payloadColumn}`
    : "";
  const limit = mode === "preview" ? 5 : source.batchSize;
  const query = mode === "sync"
    ? `declare query_parameters(gatewatch_checkpoint:datetime, gatewatch_cursor:string, gatewatch_limit:long);\ntable("${source.table}")\n| extend __gatewatch_cursor=hash_sha256(tostring(pack_all()))\n| where ${source.timestampColumn} > gatewatch_checkpoint or (${source.timestampColumn} == gatewatch_checkpoint and __gatewatch_cursor > gatewatch_cursor)\n| order by ${source.timestampColumn} asc, __gatewatch_cursor asc\n| take gatewatch_limit\n${projection}`
    : `table("${source.table}")\n| extend __gatewatch_cursor=hash_sha256(tostring(pack_all()))\n| order by ${source.timestampColumn} desc, __gatewatch_cursor desc\n| take ${limit}\n${projection}`;
  const properties = {
    Options: {
      servertimeout: "00:00:20",
      truncationmaxrecords: limit,
      truncationmaxsize: 5 * 1024 * 1024,
    },
    Parameters: mode === "sync"
      ? {
          gatewatch_checkpoint: `datetime(${checkpointDate.toISOString()})`,
          gatewatch_cursor: checkpointCursor,
          gatewatch_limit: `long(${limit})`,
        }
      : {},
  };
  const response = await fetch(`${source.clusterUrl}/v2/rest/query`, {
    method: "POST",
    headers: {
      accept: "application/json",
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      "x-ms-app": "Gatewatch",
      "x-ms-client-version": "gatewatch-adx/1.0",
    },
    body: JSON.stringify({ db: source.database, csl: query, properties: JSON.stringify(properties) }),
    redirect: "error",
    signal: AbortSignal.timeout(25_000),
  });
  const payload = await boundedFetchJson(response, 5 * 1024 * 1024);
  if (!response.ok) {
    const error = new Error("ADX_QUERY_FAILED");
    error.statusCode = response.status;
    throw error;
  }
  const result = adxRecords(payload, source);
  return {
    columns: result.columns,
    records: result.records,
    rowCount: result.queriedRows,
    skippedRows: result.skippedRows,
    truncated: result.queriedRows >= limit,
    nextCheckpoint: result.nextCheckpoint,
    nextCursor: result.nextCursor,
  };
}

function publicAdxError(error) {
  const code = error instanceof Error ? error.message : "";
  const status = Number(error?.statusCode ?? 0);
  if (code === "ADX_NOT_AVAILABLE") return "Azure Data Explorer credentials are not enabled in this deployment.";
  if (code === "ADX_CREDENTIAL_NOT_CONFIGURED") return "Save a Microsoft Entra application credential for this source.";
  if (code === "ADX_CREDENTIAL_IDENTITY_MISMATCH") return "The stored Microsoft Entra credential does not match this source. Edit the source and replace the client secret.";
  if (code === "ADX_CREDENTIAL_INVALID") return "Check the Microsoft Entra tenant, client ID, and client secret.";
  if (code === "ADX_SOURCE_INVALID" || code === "ADX_CLUSTER_INVALID") return "The Azure Data Explorer source configuration is invalid.";
  if (code === "ADX_RESPONSE_TOO_LARGE") return "Azure Data Explorer exceeded the five-megabyte response limit. Reduce the batch size.";
  if (status === 401 || code === "ADX_AUTHENTICATION_FAILED") return "Microsoft Entra rejected the application credential.";
  if (status === 403) return "The Microsoft Entra application needs viewer access to the configured ADX database.";
  if (status === 404) return "The Azure Data Explorer cluster, database, or table was not found.";
  if (status === 429) return "Azure Data Explorer rate-limited the request. Wait and retry.";
  return "Azure Data Explorer could not complete the bounded read-only query.";
}

createServer(async (request, response) => {
  try {
    if (request.url === "/health") {
      return json(response, 200, { status: "ok" });
    }
    if (!authorized(request)) return json(response, 401, { error: "Unauthorized" });
    if (request.method === "GET" && request.url === "/inventory") {
      return json(response, 200, await inventory());
    }
    if (request.method === "GET" && request.url === "/coverage") {
      return json(response, 200, await organizationCoverage());
    }
    if (request.method === "GET" && request.url === "/bedrock/status") {
      return json(response, 200, bedrockStatus());
    }
    if (request.method === "POST" && request.url === "/bedrock/analyze") {
      return json(response, 200, await analyzeWithBedrock(await requestBody(request)));
    }
    if (request.method === "POST" && request.url === "/audit/events") {
      return json(response, 200, await archiveAuditEvent(await requestBody(request)));
    }
    if (request.method === "POST" && request.url === "/test-source") {
      return json(response, 200, await testSource(await requestBody(request)));
    }
    if (request.method === "POST" && request.url === "/adx/config") {
      return json(response, 200, await saveAdxCredential(await requestBody(request)));
    }
    if (request.method === "POST" && request.url === "/adx/remove") {
      return json(response, 200, await removeAdxCredential(await requestBody(request)));
    }
    if (request.method === "POST" && request.url === "/adx/test") {
      return json(response, 200, await queryAdx({ ...await requestBody(request), mode: "preview" }));
    }
    if (request.method === "POST" && request.url === "/adx/query") {
      return json(response, 200, await queryAdx(await requestBody(request)));
    }
    if (request.method === "GET" && request.url === "/jira/status") {
      return json(response, 200, jiraStatus(await jiraSecret()));
    }
    if (request.method === "POST" && request.url === "/jira/test") {
      const tested = await testJira(await requestBody(request));
      const stored = await jiraSecret();
      return json(response, 200, {
        ...jiraStatus({ ...stored, ...tested.configuration, ...tested, lastTestedAt: tested.testedAt }),
        configured: Boolean(stored.configured),
        tokenStored: Boolean(stored.apiToken),
        passed: true,
      });
    }
    if (request.method === "POST" && request.url === "/jira/config") {
      return json(response, 200, await saveJira(await requestBody(request)));
    }
    if (request.method === "POST" && request.url === "/jira/issues") {
      return json(response, 200, await createJiraIssues(await requestBody(request)));
    }
    if (request.method === "POST" && request.url === "/jira/sync") {
      return json(response, 200, await syncJiraIssues(await requestBody(request)));
    }
    return json(response, 404, { error: "Not found" });
  } catch (error) {
    console.error(
      "AWS bridge request failed",
      error instanceof Error ? error.name : "UnknownError",
    );
    const isJiraRequest = request.url?.startsWith("/jira/");
    const isBedrockRequest = request.url?.startsWith("/bedrock/");
    const isAuditRequest = request.url?.startsWith("/audit/");
    const isAdxRequest = request.url?.startsWith("/adx/");
    return json(response, 502, {
      error: isJiraRequest
        ? publicJiraError(error)
        : isAdxRequest
          ? publicAdxError(error)
        : isBedrockRequest
          ? "Bedrock analysis failed"
          : isAuditRequest
            ? "Audit archival failed; the event remains queued for retry"
            : "AWS operation failed",
    });
  }
}).listen(port, host, () => {
  console.log(`Gatewatch AWS bridge listening on ${host}:${port}.`);
});
