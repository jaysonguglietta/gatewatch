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
});

test("builds a minimal digest-pinned production image without an inspector", async () => {
  const [dockerfile, deploy] = await Promise.all([
    source("infrastructure/aws-web/Dockerfile"),
    source("scripts/deploy-aws-web.sh"),
  ]);

  assert.match(dockerfile, /ARG NODE_RUNTIME_IMAGE/);
  assert.equal((dockerfile.match(/FROM \$\{NODE_RUNTIME_IMAGE\}/g) ?? []).length, 2);
  assert.match(dockerfile, /npm ci --omit=dev/);
  assert.doesNotMatch(dockerfile, /--inspector/);
  assert.match(deploy, /GATEWATCH_OAUTH2_PROXY_IMAGE/);
  assert.match(deploy, /GATEWATCH_NODE_RUNTIME_IMAGE/);
  assert.match(deploy, /must be deployed in us-east-1/);
});
