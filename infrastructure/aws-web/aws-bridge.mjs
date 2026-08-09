import { createServer } from "node:http";
import { createHash, timingSafeEqual } from "node:crypto";
import { BedrockRuntimeClient, ConverseCommand } from "@aws-sdk/client-bedrock-runtime";
import { GetObjectCommand, ListObjectsV2Command, S3Client } from "@aws-sdk/client-s3";
import { AssumeRoleCommand, STSClient } from "@aws-sdk/client-sts";
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
const maxRequestBytes = 96_000;
const maxSnapshotBytes = 25 * 1024 * 1024;
const maxManifestBytes = 8 * 1024 * 1024;
const jiraSecretArn = process.env.GATEWATCH_JIRA_SECRET_ARN ?? "";
const secrets = new SecretsManagerClient({ region: process.env.AWS_REGION ?? "us-east-1" });
const bedrockEnabled = process.env.GATEWATCH_BEDROCK_ENABLED === "true";
const bedrockModelId = process.env.GATEWATCH_BEDROCK_MODEL_ID ?? "us.amazon.nova-2-lite-v1:0";
const bedrockGuardrailId = process.env.GATEWATCH_BEDROCK_GUARDRAIL_ID ?? "";
const bedrockGuardrailVersion = process.env.GATEWATCH_BEDROCK_GUARDRAIL_VERSION ?? "";
const bedrock = new BedrockRuntimeClient({ region: process.env.AWS_REGION ?? "us-east-1" });

if (!token || !snapshotBucket) {
  throw new Error("The AWS bridge requires its private token and snapshot bucket.");
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
  const s3 = new S3Client({ region: snapshotRegion });
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
  const result = await new S3Client({ region: snapshotRegion }).send(
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
  const assumed = await new STSClient({ region }).send(
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
    if (request.method === "POST" && request.url === "/test-source") {
      return json(response, 200, await testSource(await requestBody(request)));
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
    return json(response, 502, {
      error: isJiraRequest ? publicJiraError(error) : isBedrockRequest ? "Bedrock analysis failed" : "AWS operation failed",
    });
  }
}).listen(port, host, () => {
  console.log(`Gatewatch AWS bridge listening on ${host}:${port}.`);
});
