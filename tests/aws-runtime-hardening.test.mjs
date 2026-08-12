import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const source = (path) => readFile(new URL(path, root), "utf8");

test("requires named Cognito users, MFA, short-lived tokens, and authorization code flow", async () => {
  const [template, installer] = await Promise.all([
    source("infrastructure/cloudformation/gatewatch-aws-web.yaml"),
    source("infrastructure/aws-web/install.sh"),
  ]);

  assert.match(template, /GatewatchUserPool:[\s\S]*MfaConfiguration: "ON"/);
  assert.match(template, /EnabledMfas:[\s\S]*- SOFTWARE_TOKEN_MFA/);
  assert.match(template, /AdminCreateUserConfig:[\s\S]*AllowAdminCreateUserOnly: true/);
  assert.match(template, /GatewatchUserPoolClient:[\s\S]*GenerateSecret: false/);
  assert.match(template, /AllowedOAuthFlows:[\s\S]*- code/);
  assert.match(template, /AccessTokenValidity: 15/);
  assert.match(template, /PreventUserExistenceErrors: ENABLED/);
  assert.doesNotMatch(template, /WebAuthenticationSecret/);
  assert.doesNotMatch(installer, /auth_basic|htpasswd/);
  assert.match(installer, /OAUTH2_PROXY_CODE_CHALLENGE_METHOD=S256/);
  assert.match(installer, /OAUTH2_PROXY_COOKIE_NAME=__Host-gatewatch/);
  assert.match(installer, /OAUTH2_PROXY_COOKIE_SECURE=true/);
  assert.match(installer, /OAUTH2_PROXY_SET_XAUTHREQUEST=true/);
});

test("terminates TLS at both edge and origin and prevents direct origin access", async () => {
  const [template, installer] = await Promise.all([
    source("infrastructure/cloudformation/gatewatch-aws-web.yaml"),
    source("infrastructure/aws-web/install.sh"),
  ]);

  assert.match(template, /OriginHttpsListener:[\s\S]*Protocol: HTTPS/);
  assert.match(template, /ViewerProtocolPolicy: redirect-to-https/);
  assert.match(template, /OriginProtocolPolicy: https-only/);
  assert.match(template, /CloudFrontOriginPrefixListId/);
  assert.match(template, /SourcePrefixListId: !Ref CloudFrontOriginPrefixListId/);
  assert.match(template, /OriginCustomHeaders:[\s\S]*X-Gatewatch-Origin/);
  assert.match(installer, /server_tokens off/);
  assert.match(installer, /X-Gatewatch-Origin/);
  assert.match(installer, /Content-Security-Policy/);
  assert.match(installer, /Permissions-Policy/);
});

test("adds edge abuse controls and privacy-conscious security logging", async () => {
  const template = await source("infrastructure/cloudformation/gatewatch-aws-web.yaml");

  assert.match(template, /GatewatchWebAcl:[\s\S]*Scope: CLOUDFRONT/);
  assert.match(template, /AWSManagedRulesCommonRuleSet/);
  assert.match(template, /AWSManagedRulesKnownBadInputsRuleSet/);
  assert.match(template, /AWSManagedRulesAmazonIpReputationList/);
  assert.match(template, /RateBasedStatement:[\s\S]*Limit: 1000/);
  assert.match(template, /Name: AiAnalysisRateLimit[\s\S]*Limit: 60/);
  assert.match(template, /SearchString: \/api\/ai\/analysis/);
  assert.match(template, /Name: IacEvaluationRateLimit[\s\S]*Limit: 100/);
  assert.match(template, /SearchString: \/api\/iac\/evaluate/);
  assert.match(template, /GatewatchWafLogging/);
  assert.match(template, /SingleHeader:[\s\S]*Name: authorization/);
  assert.match(template, /SingleHeader:[\s\S]*Name: cookie/);
  assert.match(template, /WebACLId: !GetAtt GatewatchWebAcl\.Arn/);
  assert.match(template, /Logging:[\s\S]*IncludeCookies: false/);
});

test("uses separate generated secrets and resource-scoped KMS permissions", async () => {
  const [template, installer] = await Promise.all([
    source("infrastructure/cloudformation/gatewatch-aws-web.yaml"),
    source("infrastructure/aws-web/install.sh"),
  ]);

  assert.match(template, /CloudFrontOriginSecret:/);
  assert.match(template, /AwsBridgeSecret:/);
  assert.match(template, /OidcCookieSecret:/);
  assert.match(template, /SnapshotKmsKeyArn/);
  assert.doesNotMatch(template, /Action:\s*\n\s*- kms:Decrypt\s*\n\s*Resource: "\*"/);
  assert.match(installer, /BRIDGE_SECRET_ARN="\$3"/);
  assert.match(installer, /--secret-id "\$BRIDGE_SECRET_ARN"/);
  assert.doesNotMatch(installer, /BRIDGE_TOKEN="\$ORIGIN_SECRET"/);
  assert.match(template, /AwsBridgeRuntimeRole:/);
  assert.match(template, /WebAssumeBridgeRuntimePolicy:/);
  assert.match(installer, /GATEWATCH_AWS_BRIDGE_ROLE_ARN="\$BRIDGE_ROLE_ARN"/);
  assert.match(installer, /AWS_EC2_METADATA_DISABLED=true/);
  assert.match(installer, /172\.30\.0\.10\/32 -d 169\.254\.169\.254\/32 -j ACCEPT/);
  assert.match(installer, /172\.30\.0\.0\/24 -d 169\.254\.169\.254\/32 -j REJECT/);
  assert.match(template, /SourceOrganizationId/);
  assert.match(template, /aws:ResourceOrgID: !Ref SourceOrganizationId/);
  assert.match(template, /WebEgressToFileSystem/);
  assert.match(template, /WebPrivateSubnet:/);
  assert.match(template, /WebPrivateSubnetB:/);
  assert.match(template, /WebNatGateway:/);
  assert.match(template, /NatGatewayId: !Ref WebNatGateway/);
  assert.match(template, /WebInstance:[\s\S]*AssociatePublicIpAddress: false[\s\S]*SubnetId: !Ref WebPrivateSubnet/);
  assert.match(template, /OriginLoadBalancer:[\s\S]*Scheme: internal[\s\S]*!Ref WebPrivateSubnetB/);
  assert.match(template, /PrivateWebVpcOrigin:[\s\S]*Type: AWS::CloudFront::VpcOrigin/);
  assert.match(template, /VpcOriginConfig:[\s\S]*VpcOriginId: !GetAtt PrivateWebVpcOrigin.Id/);
  assert.match(template, /PublicCertificate:[\s\S]*ValidationMethod: DNS/);
  assert.match(template, /OriginCertificate:[\s\S]*ValidationMethod: DNS/);
  assert.doesNotMatch(template, /OriginLoadBalancer:[\s\S]*Scheme: internet-facing/);
  assert.doesNotMatch(template, /MapPublicIpOnLaunch: true/);
  assert.doesNotMatch(template, /Description: AWS APIs, package repositories, and container registry[\s\S]*IpProtocol: "-1"/);
});

test("builds a minimal digest-pinned standalone production image without a development server", async () => {
  const [dockerfile, deploy, nextConfig, packageJson] = await Promise.all([
    source("infrastructure/aws-web/Dockerfile"),
    source("scripts/deploy-aws-web.sh"),
    source("next.config.ts"),
    source("package.json"),
  ]);

  assert.match(dockerfile, /ARG NODE_RUNTIME_IMAGE/);
  assert.equal((dockerfile.match(/FROM \$\{NODE_RUNTIME_IMAGE\}/g) ?? []).length, 2);
  assert.match(dockerfile, /npm ci --omit=dev/);
  assert.doesNotMatch(dockerfile, /--inspector/);
  assert.doesNotMatch(dockerfile, /wrangler dev|vinext start/);
  assert.match(dockerfile, /CMD \["node", "server\.js"\]/);
  assert.match(nextConfig, /output: process\.env\.GATEWATCH_TARGET === "aws" \? "standalone"/);
  assert.match(packageJson, /"build:aws": "GATEWATCH_TARGET=aws GATEWATCH_SQLITE_PATH=:memory: next build --webpack"/);
  assert.match(deploy, /GATEWATCH_OAUTH2_PROXY_IMAGE/);
  assert.match(deploy, /GATEWATCH_RELEASE_IMAGE_ARCHIVE/);
  assert.match(deploy, /gh attestation verify/);
  assert.match(deploy, /--source-ref refs\/heads\/main/);
  assert.match(deploy, /--source-digest "\$RELEASE_COMMIT"/);
  assert.match(deploy, /git archive --format=zip/);
  assert.doesNotMatch(deploy, /zip -qr/);
  assert.match(deploy, /GATEWATCH_RELEASE_IMAGE_REF/);
  assert.match(deploy, /GATEWATCH_RELEASE_PRINCIPAL_ARN/);
  assert.match(deploy, /DenyUnapprovedArtifactPublishers/);
  assert.match(deploy, /DenyArtifactDeletion/);
  assert.doesNotMatch(deploy, /GATEWATCH_NODE_RUNTIME_IMAGE/);
  assert.match(deploy, /must be deployed in us-east-1/);
});

test("loads only a verified prebuilt image and applies restrictive container defaults", async () => {
  const [template, installer] = await Promise.all([
    source("infrastructure/cloudformation/gatewatch-aws-web.yaml"),
    source("infrastructure/aws-web/install.sh"),
  ]);

  assert.match(template, /ImageArtifactVersionId/);
  assert.match(template, /ImageArtifactSha256/);
  assert.match(template, /ApplicationImageRef/);
  assert.doesNotMatch(template, /NodeRuntimeImage/);
  assert.match(installer, /sha256sum -c -/);
  assert.match(installer, /gzip -cd "\$APPLICATION_IMAGE_ARCHIVE" \| docker load/);
  assert.doesNotMatch(installer, /docker build/);
  assert.equal((installer.match(/--read-only/g) ?? []).length, 3);
  assert.equal((installer.match(/--cap-drop ALL/g) ?? []).length, 3);
  assert.equal((installer.match(/no-new-privileges:true/g) ?? []).length, 3);
  assert.equal((installer.match(/--pids-limit/g) ?? []).length, 3);
});

test("AWS standalone storage preserves D1 batch ordering and rollback semantics", async () => {
  process.env.GATEWATCH_SQLITE_PATH = ":memory:";
  const { env } = await import(`../lib/aws-cloudflare-workers.ts?test=${Date.now()}`);

  await env.DB.batch([
    env.DB.prepare("CREATE TABLE runtime_smoke (id TEXT PRIMARY KEY, value TEXT NOT NULL)"),
    env.DB.prepare("CREATE INDEX runtime_smoke_value_idx ON runtime_smoke (value)"),
    env.DB.prepare("INSERT INTO runtime_smoke (id, value) VALUES (?, ?)").bind("one", "safe"),
  ]);
  assert.deepEqual(
    await env.DB.prepare("SELECT id, value FROM runtime_smoke").first(),
    { id: "one", value: "safe" },
  );

  await assert.rejects(() => env.DB.batch([
    env.DB.prepare("INSERT INTO runtime_smoke (id, value) VALUES (?, ?)").bind("two", "rollback"),
    env.DB.prepare("INSERT INTO runtime_smoke (id, value) VALUES (?, ?)").bind("one", "duplicate"),
  ]));
  assert.equal(
    await env.DB.prepare("SELECT id FROM runtime_smoke WHERE id = ?").bind("two").first(),
    null,
  );
});

test("release CI scans the final image and emits SBOM and signed provenance", async () => {
  const workflow = await source(".github/workflows/release-security.yml");

  assert.match(workflow, /NODE_RUNTIME_IMAGE: node:22-bookworm-slim@sha256:[a-f0-9]{64}/);
  assert.match(workflow, /docker buildx build[\s\S]*--platform linux\/arm64[\s\S]*infrastructure\/aws-web\/Dockerfile/);
  assert.match(workflow, /docker\/setup-qemu-action@[a-f0-9]{40}/);
  assert.match(workflow, /docker\/setup-buildx-action@[a-f0-9]{40}/);
  assert.match(workflow, /image-ref: \$\{\{ env\.RELEASE_IMAGE \}\}/);
  assert.match(workflow, /severity: CRITICAL,HIGH/);
  assert.match(workflow, /format: cyclonedx/);
  assert.match(workflow, /actions\/attest-build-provenance@[a-f0-9]{40}/);
  assert.doesNotMatch(workflow, /uses: [^\n]+@(v\d+|master)\s*$/m);
});
