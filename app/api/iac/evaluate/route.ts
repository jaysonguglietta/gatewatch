import { env } from "cloudflare:workers";
import { cleanText } from "../../../../lib/admin-sources";
import { HttpInputError, readBoundedJson } from "../../../../lib/http-security";
import {
  consolidateInfrastructureReviews,
  reviewInfrastructureFile,
} from "../../../../lib/iac-security-review";
import { canonicalJson, sha256Hex } from "../../../../lib/security-integrity";
import {
  apiJson,
  audit,
  ensureAdminSchema,
  requestUser,
  sameOrigin,
} from "../../../../lib/server-admin";

async function tokenMatches(request: Request) {
  const configured = env.GATEWATCH_IAC_WEBHOOK_TOKEN ?? "";
  const supplied = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "") ?? "";
  if (configured.length < 32 || supplied.length !== configured.length) return false;
  const [expected, actual] = await Promise.all(
    [configured, supplied].map((value) =>
      crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
    ),
  );
  const left = new Uint8Array(expected);
  const right = new Uint8Array(actual);
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

export async function POST(request: Request) {
  const browserUser = requestUser(request);
  const webhookAuthenticated = await tokenMatches(request);
  if (!browserUser && !webhookAuthenticated) {
    return apiJson({ error: "A hosting identity or valid CI bearer token is required." }, 401);
  }
  if (browserUser && !webhookAuthenticated && !sameOrigin(request)) {
    return apiJson({ error: "Origin is not allowed." }, 403);
  }
  const user = browserUser || "iac-webhook";
  try {
    const input = await readBoundedJson(request, 2_500_000);
    const repository = cleanText(input.repository, 240);
    const pullRequest = cleanText(input.pullRequest, 80);
    const commitAuthor = cleanText(input.author, 160);
    const environment = cleanText(input.environment, 80);
    const proposedChange = cleanText(input.proposedChange, 2_000);
    const declaredArtifactDigest = cleanText(input.artifactDigest, 64).toLowerCase();
    const files = Array.isArray(input.files) ? input.files.slice(0, 21) : [];
    if (!repository || !pullRequest || files.length < 1 || files.length > 20) {
      return apiJson({ error: "Repository, pull request, and between 1 and 20 infrastructure files are required." }, 400);
    }
    const normalizedFiles = files.map((value) => {
      const record = value && typeof value === "object" && !Array.isArray(value)
        ? value as Record<string, unknown>
        : {};
      return {
        name: cleanText(record.name, 240),
        content: typeof record.content === "string" ? record.content : "",
      };
    });
    if (normalizedFiles.some((file) => !file.name || !file.content)) {
      return apiJson({ error: "Every infrastructure file requires a name and UTF-8 text content." }, 400);
    }
    const artifactBytes = normalizedFiles.reduce(
      (total, file) => total + new TextEncoder().encode(file.content).byteLength,
      0,
    );
    if (artifactBytes > 2_000_000) {
      return apiJson({ error: "The combined infrastructure artifact is larger than 2 MB." }, 413);
    }
    const artifactDigest = await sha256Hex(canonicalJson(normalizedFiles));
    if (declaredArtifactDigest && (!/^[a-f0-9]{64}$/.test(declaredArtifactDigest) || declaredArtifactDigest !== artifactDigest)) {
      return apiJson({ error: "The supplied artifact digest does not match the evaluated files." }, 409);
    }
    const batch = consolidateInfrastructureReviews(
      normalizedFiles.map((file) => reviewInfrastructureFile(file.name, file.content)),
    );
    if (!batch.totals.parsedFiles || batch.totals.rejectedFiles) {
      return apiJson({
        error: "Every submitted infrastructure file must parse successfully before Gatewatch can issue a verdict.",
        rejectedFiles: batch.files.filter((file) => file.status === "rejected").map((file) => ({ name: file.name, error: file.error })),
      }, 422);
    }
    const issues = batch.groups.flatMap((group) => group.issues);
    const projectedRisk = batch.groups.reduce((maximum, group) => Math.max(maximum, group.riskScore), 0);
    const verdict = batch.totals.critical > 0
      ? "Block"
      : batch.totals.high > 0 || issues.some((issue) => issue.severity === "medium")
        ? "Review"
        : "Pass";
    const policy = "Gatewatch deterministic IaC security-group baseline";
    const id = `iac:${crypto.randomUUID()}`;
    const evaluation = {
      id,
      repository,
      pullRequest,
      commitAuthor,
      submittedBy: user,
      environment,
      proposedChange: proposedChange || `Evaluate ${normalizedFiles.length} infrastructure file(s).`,
      artifactDigest,
      artifactBytes,
      projectedRisk,
      verdict,
      policy,
      totals: batch.totals,
      files: batch.files.map((file) => ({
        name: file.name,
        format: file.format,
        status: file.status,
        resources: file.resourceCount,
        rules: file.ruleCount,
        warnings: file.warnings,
      })),
      findings: issues.slice(0, 500).map((issue) => ({
        id: issue.id,
        severity: issue.severity,
        title: issue.title,
        fileName: issue.fileName,
        resourceAddress: issue.resourceAddress,
        line: issue.line,
        cwe: issue.cwe,
      })),
      evidence: [
        `Artifact SHA-256: ${artifactDigest}`,
        `Parsed files: ${batch.totals.parsedFiles}`,
        `Security groups: ${batch.totals.groups}`,
        `Issues: ${batch.totals.issues}`,
        `Policy: ${policy}`,
        `Evaluated by ${user}`,
      ],
    };
    await ensureAdminSchema();
    await env.DB.prepare(
      `INSERT INTO integration_deliveries
        (id, workspace_id, integration, event_type, target_id, status,
         attempts, payload, next_attempt_at)
       VALUES (?, 'default', 'iac', 'iac.evaluation', ?, 'evaluated', 1, ?, '')`,
    ).bind(id, `${repository}:${pullRequest}`, JSON.stringify(evaluation)).run();
    await audit(user, "iac.evaluated", "pull-request", `${repository}:${pullRequest}`, `IaC evaluation returned ${verdict}.`, { artifactDigest, artifactBytes, projectedRisk, verdict, policy, totals: batch.totals });
    return apiJson({ evaluation }, 201);
  } catch (error) {
    if (error instanceof HttpInputError) return apiJson({ error: error.message }, error.status);
    return apiJson({ error: "The IaC evaluation could not be completed." }, 503);
  }
}
