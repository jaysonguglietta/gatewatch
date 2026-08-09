#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 16 ]]; then
  echo "Usage: install.sh REGION AUTH_SECRET_ARN ORIGIN_SECRET_ARN JIRA_SECRET_ARN SNAPSHOT_BUCKET SNAPSHOT_KEY SNAPSHOT_MANIFEST_KEY SNAPSHOT_REGION ORGANIZATION_EVIDENCE_BUCKET ORGANIZATION_MANIFEST_KEY LOG_GROUP RELEASE_ID BEDROCK_ENABLED BEDROCK_MODEL_ID BEDROCK_GUARDRAIL_ID BEDROCK_GUARDRAIL_VERSION" >&2
  exit 2
fi

REGION="$1"
AUTH_SECRET_ARN="$2"
ORIGIN_SECRET_ARN="$3"
JIRA_SECRET_ARN="$4"
SNAPSHOT_BUCKET="$5"
SNAPSHOT_KEY="$6"
SNAPSHOT_MANIFEST_KEY="$7"
SNAPSHOT_REGION="$8"
ORGANIZATION_EVIDENCE_BUCKET="$9"
ORGANIZATION_MANIFEST_KEY="${10}"
LOG_GROUP="${11}"
RELEASE_ID="${12}"
BEDROCK_ENABLED="${13}"
BEDROCK_MODEL_ID="${14}"
BEDROCK_GUARDRAIL_ID="${15}"
BEDROCK_GUARDRAIL_VERSION="${16}"

AUTH_JSON="$(aws secretsmanager get-secret-value \
  --region "$REGION" \
  --secret-id "$AUTH_SECRET_ARN" \
  --query SecretString \
  --output text)"
AUTH_USERNAME="$(jq -er '.username' <<<"$AUTH_JSON")"
AUTH_PASSWORD="$(jq -er '.password' <<<"$AUTH_JSON")"
ORIGIN_TOKEN="$(aws secretsmanager get-secret-value \
  --region "$REGION" \
  --secret-id "$ORIGIN_SECRET_ARN" \
  --query SecretString \
  --output text)"

install -d -m 0750 -o 1000 -g 1000 /srv/gatewatch/data
htpasswd -bcB /etc/nginx/.gatewatch-users "$AUTH_USERNAME" "$AUTH_PASSWORD" >/dev/null
chown root:nginx /etc/nginx/.gatewatch-users
chmod 0640 /etc/nginx/.gatewatch-users

cat >/etc/nginx/conf.d/gatewatch.conf <<'NGINX'
server {
  listen 80 default_server;
  server_name _;
  client_max_body_size 30m;

  if ($http_x_gatewatch_origin != "__ORIGIN_TOKEN__") {
    return 403;
  }

  auth_basic "Gatewatch";
  auth_basic_user_file /etc/nginx/.gatewatch-users;

  add_header X-Content-Type-Options nosniff always;
  add_header Referrer-Policy same-origin always;
  add_header X-Frame-Options DENY always;

  location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-Host $http_host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header oai-authenticated-user-email "$remote_user@gatewatch.local";
    proxy_set_header oai-authenticated-user-full-name "$remote_user";
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
  --tag "gatewatch-web:$RELEASE_ID" \
  --file infrastructure/aws-web/Dockerfile \
  .

docker network inspect gatewatch-internal >/dev/null 2>&1 || \
  docker network create gatewatch-internal >/dev/null
docker rm -f gatewatch-aws-bridge >/dev/null 2>&1 || true
docker run -d \
  --name gatewatch-aws-bridge \
  --restart unless-stopped \
  --network gatewatch-internal \
  --env AWS_REGION="$REGION" \
  --env AWS_DEFAULT_REGION="$REGION" \
  --env GATEWATCH_AWS_BRIDGE_HOST=0.0.0.0 \
  --env GATEWATCH_AWS_BRIDGE_TOKEN="$ORIGIN_TOKEN" \
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
  --env GATEWATCH_AWS_BRIDGE_TOKEN="$ORIGIN_TOKEN" \
  --env GATEWATCH_JIRA_SECRET_ARN="$JIRA_SECRET_ARN" \
  --env GATEWATCH_BOOTSTRAP_ADMIN_EMAIL="$AUTH_USERNAME@gatewatch.local" \
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
    --user "$AUTH_USERNAME:$AUTH_PASSWORD" \
    --header "X-Gatewatch-Origin: $ORIGIN_TOKEN" \
    http://127.0.0.1/ >/dev/null; then
    docker image prune -f >/dev/null 2>&1 || true
    echo "Gatewatch web runtime is healthy."
    exit 0
  fi
  sleep 5
done

docker logs --tail 100 gatewatch-web >&2 || true
echo "Gatewatch did not become healthy within five minutes." >&2
exit 1
