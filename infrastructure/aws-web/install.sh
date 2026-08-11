#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 24 ]]; then
  echo "Usage: install.sh REGION ORIGIN_SECRET_ARN BRIDGE_SECRET_ARN COOKIE_SECRET_ARN JIRA_SECRET_ARN USER_POOL_ID USER_POOL_CLIENT_ID COGNITO_DOMAIN_PREFIX PUBLIC_URL BOOTSTRAP_ADMIN_EMAIL SNAPSHOT_BUCKET SNAPSHOT_KEY SNAPSHOT_MANIFEST_KEY SNAPSHOT_REGION ORGANIZATION_EVIDENCE_BUCKET ORGANIZATION_MANIFEST_KEY LOG_GROUP RELEASE_ID BEDROCK_ENABLED BEDROCK_MODEL_ID BEDROCK_GUARDRAIL_ID BEDROCK_GUARDRAIL_VERSION OAUTH2_PROXY_IMAGE NODE_RUNTIME_IMAGE" >&2
  exit 2
fi

REGION="$1"
ORIGIN_SECRET_ARN="$2"
BRIDGE_SECRET_ARN="$3"
COOKIE_SECRET_ARN="$4"
JIRA_SECRET_ARN="$5"
USER_POOL_ID="$6"
USER_POOL_CLIENT_ID="$7"
COGNITO_DOMAIN_PREFIX="$8"
PUBLIC_URL="$9"
BOOTSTRAP_ADMIN_EMAIL="${10}"
SNAPSHOT_BUCKET="${11}"
SNAPSHOT_KEY="${12}"
SNAPSHOT_MANIFEST_KEY="${13}"
SNAPSHOT_REGION="${14}"
ORGANIZATION_EVIDENCE_BUCKET="${15}"
ORGANIZATION_MANIFEST_KEY="${16}"
LOG_GROUP="${17}"
RELEASE_ID="${18}"
BEDROCK_ENABLED="${19}"
BEDROCK_MODEL_ID="${20}"
BEDROCK_GUARDRAIL_ID="${21}"
BEDROCK_GUARDRAIL_VERSION="${22}"
OAUTH2_PROXY_IMAGE="${23}"
NODE_RUNTIME_IMAGE="${24}"
PUBLIC_HOST="${PUBLIC_URL#https://}"

if [[ "$PUBLIC_URL" != "https://$PUBLIC_HOST" || "$PUBLIC_HOST" == */* ]]; then
  echo "PUBLIC_URL must be an HTTPS origin without a path." >&2
  exit 2
fi

ORIGIN_TOKEN="$(aws secretsmanager get-secret-value \
  --region "$REGION" \
  --secret-id "$ORIGIN_SECRET_ARN" \
  --query SecretString \
  --output text)"
BRIDGE_TOKEN="$(aws secretsmanager get-secret-value \
  --region "$REGION" \
  --secret-id "$BRIDGE_SECRET_ARN" \
  --query SecretString \
  --output text)"
COOKIE_SECRET="$(aws secretsmanager get-secret-value \
  --region "$REGION" \
  --secret-id "$COOKIE_SECRET_ARN" \
  --query SecretString \
  --output text)"

install -d -m 0750 -o 1000 -g 1000 /srv/gatewatch/data

cat >/etc/nginx/conf.d/gatewatch.conf <<'NGINX'
server_tokens off;

map $request_uri $gatewatch_health_request {
  default 0;
  /healthz 1;
}

map $http_x_gatewatch_origin $gatewatch_origin_header {
  default 0;
  "__ORIGIN_TOKEN__" 1;
}

map "$gatewatch_health_request:$gatewatch_origin_header" $gatewatch_origin_allowed {
  default 0;
  "1:0" 1;
  "1:1" 1;
  "0:1" 1;
}

server {
  listen 80 default_server;
  server_name _;
  client_max_body_size 30m;

  if ($gatewatch_origin_allowed = 0) {
    return 403;
  }

  add_header X-Content-Type-Options nosniff always;
  add_header Referrer-Policy same-origin always;
  add_header X-Frame-Options DENY always;
  add_header Permissions-Policy "camera=(), geolocation=(), microphone=(), payment=(), usb=()" always;
  add_header Content-Security-Policy "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; form-action 'self'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; upgrade-insecure-requests" always;

  location = /healthz {
    access_log off;
    default_type text/plain;
    return 200 "ok\n";
  }

  location /oauth2/ {
    proxy_pass http://127.0.0.1:4180;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Auth-Request-Redirect $request_uri;
  }

  location = /oauth2/auth {
    proxy_pass http://127.0.0.1:4180;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-Proto https;
  }

  location = /signout-with-chatgpt {
    return 302 /oauth2/sign_out;
  }

  location / {
    auth_request /oauth2/auth;
    error_page 401 =403 /oauth2/sign_in;
    auth_request_set $gatewatch_email $upstream_http_x_auth_request_email;
    auth_request_set $gatewatch_subject $upstream_http_x_auth_request_user;
    auth_request_set $gatewatch_cookie $upstream_http_set_cookie;
    add_header Set-Cookie $gatewatch_cookie always;

    proxy_pass http://127.0.0.1:3000;
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-Host $http_host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header oai-authenticated-user-email $gatewatch_email;
    proxy_set_header oai-authenticated-user-id $gatewatch_subject;
    proxy_set_header oai-authenticated-user-full-name $gatewatch_email;
    proxy_set_header oai-authenticated-user-full-name-encoding "percent-encoded-utf-8";
    proxy_set_header Authorization "";
    proxy_read_timeout 120s;
  }
}
NGINX
sed -i "s|__ORIGIN_TOKEN__|$ORIGIN_TOKEN|g" /etc/nginx/conf.d/gatewatch.conf
rm -f /etc/nginx/conf.d/default.conf
nginx -t
systemctl enable nginx
systemctl restart nginx

docker build --pull \
  --build-arg "NODE_RUNTIME_IMAGE=$NODE_RUNTIME_IMAGE" \
  --tag "gatewatch-web:$RELEASE_ID" \
  --file infrastructure/aws-web/Dockerfile \
  .

docker network inspect gatewatch-internal >/dev/null 2>&1 || \
  docker network create gatewatch-internal >/dev/null
docker rm -f gatewatch-oauth2-proxy >/dev/null 2>&1 || true
docker run -d \
  --name gatewatch-oauth2-proxy \
  --restart unless-stopped \
  --network gatewatch-internal \
  --publish 127.0.0.1:4180:4180 \
  --env OAUTH2_PROXY_PROVIDER=oidc \
  --env "OAUTH2_PROXY_OIDC_ISSUER_URL=https://cognito-idp.$REGION.amazonaws.com/$USER_POOL_ID" \
  --env "OAUTH2_PROXY_CLIENT_ID=$USER_POOL_CLIENT_ID" \
  --env OAUTH2_PROXY_CLIENT_SECRET= \
  --env OAUTH2_PROXY_CODE_CHALLENGE_METHOD=S256 \
  --env "OAUTH2_PROXY_REDIRECT_URL=$PUBLIC_URL/oauth2/callback" \
  --env "OAUTH2_PROXY_BACKEND_LOGOUT_URL=https://$COGNITO_DOMAIN_PREFIX.auth.$REGION.amazoncognito.com/logout?client_id=$USER_POOL_CLIENT_ID&logout_uri=$PUBLIC_URL/" \
  --env OAUTH2_PROXY_SCOPE="openid email profile" \
  --env OAUTH2_PROXY_EMAIL_DOMAINS=* \
  --env "OAUTH2_PROXY_WHITELIST_DOMAINS=$PUBLIC_HOST" \
  --env OAUTH2_PROXY_HTTP_ADDRESS=0.0.0.0:4180 \
  --env OAUTH2_PROXY_UPSTREAMS=static://202 \
  --env OAUTH2_PROXY_REVERSE_PROXY=true \
  --env OAUTH2_PROXY_SET_XAUTHREQUEST=true \
  --env OAUTH2_PROXY_SKIP_PROVIDER_BUTTON=true \
  --env "OAUTH2_PROXY_COOKIE_SECRET=$COOKIE_SECRET" \
  --env OAUTH2_PROXY_COOKIE_NAME=__Host-gatewatch \
  --env OAUTH2_PROXY_COOKIE_SECURE=true \
  --env OAUTH2_PROXY_COOKIE_HTTPONLY=true \
  --env OAUTH2_PROXY_COOKIE_SAMESITE=lax \
  --env OAUTH2_PROXY_COOKIE_REFRESH=5m \
  --env OAUTH2_PROXY_COOKIE_EXPIRE=8h \
  --env OAUTH2_PROXY_SESSION_COOKIE_MINIMAL=true \
  --env OAUTH2_PROXY_PASS_ACCESS_TOKEN=false \
  --log-driver awslogs \
  --log-opt "awslogs-region=$REGION" \
  --log-opt "awslogs-group=$LOG_GROUP" \
  --log-opt "awslogs-stream=oauth2-proxy" \
  "$OAUTH2_PROXY_IMAGE"

docker rm -f gatewatch-aws-bridge >/dev/null 2>&1 || true
docker run -d \
  --name gatewatch-aws-bridge \
  --restart unless-stopped \
  --network gatewatch-internal \
  --env AWS_REGION="$REGION" \
  --env AWS_DEFAULT_REGION="$REGION" \
  --env GATEWATCH_AWS_BRIDGE_HOST=0.0.0.0 \
  --env GATEWATCH_AWS_BRIDGE_TOKEN="$BRIDGE_TOKEN" \
  --env GATEWATCH_JIRA_SECRET_ARN="$JIRA_SECRET_ARN" \
  --env GATEWATCH_SNAPSHOT_BUCKET="$SNAPSHOT_BUCKET" \
  --env GATEWATCH_SNAPSHOT_KEY="$SNAPSHOT_KEY" \
  --env GATEWATCH_SNAPSHOT_MANIFEST_KEY="$SNAPSHOT_MANIFEST_KEY" \
  --env GATEWATCH_SNAPSHOT_REGION="$SNAPSHOT_REGION" \
  --env GATEWATCH_ORGANIZATION_EVIDENCE_BUCKET="$ORGANIZATION_EVIDENCE_BUCKET" \
  --env GATEWATCH_ORGANIZATION_MANIFEST_KEY="$ORGANIZATION_MANIFEST_KEY" \
  --env GATEWATCH_BEDROCK_ENABLED="$BEDROCK_ENABLED" \
  --env GATEWATCH_BEDROCK_MODEL_ID="$BEDROCK_MODEL_ID" \
  --env GATEWATCH_BEDROCK_GUARDRAIL_ID="$BEDROCK_GUARDRAIL_ID" \
  --env GATEWATCH_BEDROCK_GUARDRAIL_VERSION="$BEDROCK_GUARDRAIL_VERSION" \
  --log-driver awslogs \
  --log-opt "awslogs-region=$REGION" \
  --log-opt "awslogs-group=$LOG_GROUP" \
  --log-opt "awslogs-stream=aws-bridge" \
  "gatewatch-web:$RELEASE_ID" \
  node infrastructure/aws-web/aws-bridge.mjs

docker rm -f gatewatch-web >/dev/null 2>&1 || true
docker run -d \
  --name gatewatch-web \
  --restart unless-stopped \
  --network gatewatch-internal \
  --publish 127.0.0.1:3000:3000 \
  --volume /srv/gatewatch/data:/data \
  --env AWS_REGION="$REGION" \
  --env AWS_DEFAULT_REGION="$REGION" \
  --env GATEWATCH_AWS_RUNTIME=true \
  --env GATEWATCH_AWS_BRIDGE_URL=http://gatewatch-aws-bridge:3001 \
  --env GATEWATCH_AWS_BRIDGE_TOKEN="$BRIDGE_TOKEN" \
  --env GATEWATCH_JIRA_SECRET_ARN="$JIRA_SECRET_ARN" \
  --env GATEWATCH_BOOTSTRAP_ADMIN_EMAIL="$BOOTSTRAP_ADMIN_EMAIL" \
  --env GATEWATCH_SNAPSHOT_BUCKET="$SNAPSHOT_BUCKET" \
  --env GATEWATCH_SNAPSHOT_KEY="$SNAPSHOT_KEY" \
  --env GATEWATCH_SNAPSHOT_MANIFEST_KEY="$SNAPSHOT_MANIFEST_KEY" \
  --env GATEWATCH_SNAPSHOT_REGION="$SNAPSHOT_REGION" \
  --env GATEWATCH_ORGANIZATION_EVIDENCE_BUCKET="$ORGANIZATION_EVIDENCE_BUCKET" \
  --env GATEWATCH_ORGANIZATION_MANIFEST_KEY="$ORGANIZATION_MANIFEST_KEY" \
  --env GATEWATCH_BEDROCK_ENABLED="$BEDROCK_ENABLED" \
  --env GATEWATCH_BEDROCK_MODEL_ID="$BEDROCK_MODEL_ID" \
  --env GATEWATCH_BEDROCK_GUARDRAIL_ID="$BEDROCK_GUARDRAIL_ID" \
  --env GATEWATCH_BEDROCK_GUARDRAIL_VERSION="$BEDROCK_GUARDRAIL_VERSION" \
  --log-driver awslogs \
  --log-opt "awslogs-region=$REGION" \
  --log-opt "awslogs-group=$LOG_GROUP" \
  --log-opt "awslogs-stream=application" \
  "gatewatch-web:$RELEASE_ID"

for _ in {1..60}; do
  if curl --fail --silent --show-error \
    --header "X-Gatewatch-Origin: $ORIGIN_TOKEN" \
    http://127.0.0.1/healthz >/dev/null; then
    docker image prune -f >/dev/null 2>&1 || true
    echo "Gatewatch web runtime is healthy."
    exit 0
  fi
  sleep 5
done

docker logs --tail 100 gatewatch-web >&2 || true
echo "Gatewatch did not become healthy within five minutes." >&2
exit 1
