#!/usr/bin/env bash

set -euo pipefail

PROFILE="${AWS_PROFILE:-personal}"
REGION="${AWS_REGION:-$(aws configure get region --profile "$PROFILE")}"
REGION="${REGION:-us-east-1}"
STACK_NAME="${GATEWATCH_WEB_STACK_NAME:-gatewatch-personal-web}"
COLLECTOR_STACK_NAME="${GATEWATCH_STACK_NAME:-gatewatch-personal-sg-collector}"
ORGANIZATION_COLLECTOR_STACK_NAME="${GATEWATCH_ORGANIZATION_STACK_NAME:-gatewatch-organization-collector}"
TEMPLATE="infrastructure/cloudformation/gatewatch-aws-web.yaml"
PUBLIC_DOMAIN_NAME="${GATEWATCH_PUBLIC_DOMAIN_NAME:?Set GATEWATCH_PUBLIC_DOMAIN_NAME to the managed HTTPS hostname.}"
ORIGIN_DOMAIN_NAME="${GATEWATCH_ORIGIN_DOMAIN_NAME:?Set GATEWATCH_ORIGIN_DOMAIN_NAME to the dedicated ALB origin hostname.}"
HOSTED_ZONE_ID="${GATEWATCH_HOSTED_ZONE_ID:?Set GATEWATCH_HOSTED_ZONE_ID to the Route 53 hosted zone ID.}"
PUBLIC_CERTIFICATE_ARN="${GATEWATCH_PUBLIC_CERTIFICATE_ARN:?Set GATEWATCH_PUBLIC_CERTIFICATE_ARN to the us-east-1 ACM certificate ARN.}"
ORIGIN_CERTIFICATE_ARN="${GATEWATCH_ORIGIN_CERTIFICATE_ARN:?Set GATEWATCH_ORIGIN_CERTIFICATE_ARN to the regional ACM certificate ARN.}"
BOOTSTRAP_ADMIN_EMAIL="${GATEWATCH_BOOTSTRAP_ADMIN_EMAIL:?Set GATEWATCH_BOOTSTRAP_ADMIN_EMAIL to the first named administrator.}"
COGNITO_DOMAIN_PREFIX="${GATEWATCH_COGNITO_DOMAIN_PREFIX:?Set GATEWATCH_COGNITO_DOMAIN_PREFIX to a globally unique prefix.}"
OAUTH2_PROXY_IMAGE="${GATEWATCH_OAUTH2_PROXY_IMAGE:?Set GATEWATCH_OAUTH2_PROXY_IMAGE to a digest-pinned image.}"
NODE_RUNTIME_IMAGE="${GATEWATCH_NODE_RUNTIME_IMAGE:?Set GATEWATCH_NODE_RUNTIME_IMAGE to a digest-pinned Node image.}"

if [[ "$REGION" != "us-east-1" ]]; then
  echo "The Gatewatch web stack must be deployed in us-east-1 because it creates a CloudFront-scoped WAF." >&2
  exit 1
fi

if [[ ! -f "$TEMPLATE" || ! -f package-lock.json ]]; then
  echo "Run this script from the Gatewatch repository root." >&2
  exit 1
fi

ACCOUNT_ID="$(aws sts get-caller-identity \
  --profile "$PROFILE" \
  --query Account \
  --output text \
  --no-cli-pager)"
ARTIFACT_BUCKET="${GATEWATCH_ARTIFACT_BUCKET:-gatewatch-artifacts-$ACCOUNT_ID-$REGION}"
SNAPSHOT_BUCKET="$(aws cloudformation describe-stacks \
  --profile "$PROFILE" \
  --region "$REGION" \
  --stack-name "$COLLECTOR_STACK_NAME" \
  --query 'Stacks[0].Outputs[?OutputKey==`SnapshotBucketName`].OutputValue' \
  --output text \
  --no-cli-pager)"
SNAPSHOT_KMS_KEY_ARN="$(aws cloudformation describe-stacks \
  --profile "$PROFILE" \
  --region "$REGION" \
  --stack-name "$COLLECTOR_STACK_NAME" \
  --query 'Stacks[0].Outputs[?OutputKey==`SnapshotKeyArn`].OutputValue' \
  --output text \
  --no-cli-pager)"

if [[ -z "$SNAPSHOT_BUCKET" || "$SNAPSHOT_BUCKET" == "None" || -z "$SNAPSHOT_KMS_KEY_ARN" || "$SNAPSHOT_KMS_KEY_ARN" == "None" ]]; then
  echo "Deploy the current Gatewatch collector before deploying the web dashboard." >&2
  exit 1
fi

ORGANIZATION_EVIDENCE_BUCKET="$(aws cloudformation describe-stacks \
  --profile "$PROFILE" \
  --region "$REGION" \
  --stack-name "$ORGANIZATION_COLLECTOR_STACK_NAME" \
  --query 'Stacks[0].Outputs[?OutputKey==`EvidenceBucketName`].OutputValue' \
  --output text \
  --no-cli-pager 2>/dev/null || true)"
if [[ "$ORGANIZATION_EVIDENCE_BUCKET" == "None" ]]; then
  ORGANIZATION_EVIDENCE_BUCKET=""
fi
ORGANIZATION_EVIDENCE_KMS_KEY_ARN=""
if [[ -n "$ORGANIZATION_EVIDENCE_BUCKET" ]]; then
  ORGANIZATION_EVIDENCE_KMS_KEY_ARN="$(aws cloudformation describe-stacks \
    --profile "$PROFILE" \
    --region "$REGION" \
    --stack-name "$ORGANIZATION_COLLECTOR_STACK_NAME" \
    --query 'Stacks[0].Outputs[?OutputKey==`EvidenceKeyArn`].OutputValue' \
    --output text \
    --no-cli-pager)"
fi

if ! aws s3api head-bucket \
  --profile "$PROFILE" \
  --region "$REGION" \
  --bucket "$ARTIFACT_BUCKET" 2>/dev/null; then
  if [[ "$REGION" == "us-east-1" ]]; then
    aws s3api create-bucket \
      --profile "$PROFILE" \
      --region "$REGION" \
      --bucket "$ARTIFACT_BUCKET" \
      --no-cli-pager >/dev/null
  else
    aws s3api create-bucket \
      --profile "$PROFILE" \
      --region "$REGION" \
      --bucket "$ARTIFACT_BUCKET" \
      --create-bucket-configuration "LocationConstraint=$REGION" \
      --no-cli-pager >/dev/null
  fi
fi

aws s3api put-public-access-block \
  --profile "$PROFILE" \
  --region "$REGION" \
  --bucket "$ARTIFACT_BUCKET" \
  --public-access-block-configuration \
    'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
aws s3api put-bucket-encryption \
  --profile "$PROFILE" \
  --region "$REGION" \
  --bucket "$ARTIFACT_BUCKET" \
  --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BucketKeyEnabled":false}]}'
aws s3api put-bucket-versioning \
  --profile "$PROFILE" \
  --region "$REGION" \
  --bucket "$ARTIFACT_BUCKET" \
  --versioning-configuration Status=Enabled
aws s3api put-bucket-lifecycle-configuration \
  --profile "$PROFILE" \
  --region "$REGION" \
  --bucket "$ARTIFACT_BUCKET" \
  --lifecycle-configuration \
    '{"Rules":[{"ID":"ExpireOldGatewatchReleases","Status":"Enabled","Filter":{"Prefix":"releases/"},"Expiration":{"Days":90},"NoncurrentVersionExpiration":{"NoncurrentDays":30,"NewerNoncurrentVersions":3}}]}'

PACKAGE_DIR="$(mktemp -d -t gatewatch-web-package.XXXXXX)"
PACKAGE_PATH="$PACKAGE_DIR/gatewatch-web.zip"
trap 'rm -rf "$PACKAGE_DIR"' EXIT

zip -qr "$PACKAGE_PATH" . \
  -x '.git/*' \
     'node_modules/*' \
     'dist/*' \
     '.next/*' \
     '.wrangler/*' \
     '.env' \
     '.env.*' \
     '*.pem' \
     '*.key' \
     '*.log' \
     '*.zip' \
     'samples/*.gz' \
     '.DS_Store'

PACKAGE_SHA256="$(shasum -a 256 "$PACKAGE_PATH" | awk '{print $1}')"
ARTIFACT_KEY="releases/$PACKAGE_SHA256/gatewatch-web.zip"

aws s3 cp "$PACKAGE_PATH" "s3://$ARTIFACT_BUCKET/$ARTIFACT_KEY" \
  --profile "$PROFILE" \
  --region "$REGION" \
  --sse AES256 \
  --metadata "sha256=$PACKAGE_SHA256" \
  --no-progress

ARTIFACT_VERSION_ID="$(aws s3api head-object \
  --profile "$PROFILE" \
  --region "$REGION" \
  --bucket "$ARTIFACT_BUCKET" \
  --key "$ARTIFACT_KEY" \
  --query VersionId \
  --output text \
  --no-cli-pager)"
if [[ -z "$ARTIFACT_VERSION_ID" || "$ARTIFACT_VERSION_ID" == "None" ]]; then
  echo "The release artifact must have an immutable S3 version ID." >&2
  exit 1
fi

CLOUDFRONT_PREFIX_LIST="$(aws ec2 describe-managed-prefix-lists \
  --profile "$PROFILE" \
  --region "$REGION" \
  --filters Name=prefix-list-name,Values=com.amazonaws.global.cloudfront.origin-facing \
  --query 'PrefixLists[0].PrefixListId' \
  --output text \
  --no-cli-pager)"

if [[ -z "$CLOUDFRONT_PREFIX_LIST" || "$CLOUDFRONT_PREFIX_LIST" == "None" ]]; then
  echo "The AWS-managed CloudFront origin prefix list was not found." >&2
  exit 1
fi

aws cloudformation validate-template \
  --profile "$PROFILE" \
  --region "$REGION" \
  --template-body "file://$TEMPLATE" \
  --no-cli-pager >/dev/null

EXISTING_STACK_STATUS="$(aws cloudformation describe-stacks \
  --profile "$PROFILE" \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --query 'Stacks[0].StackStatus' \
  --output text \
  --no-cli-pager 2>/dev/null || true)"
if [[ "$EXISTING_STACK_STATUS" == "ROLLBACK_COMPLETE" ]]; then
  echo "Removing the empty rolled-back stack before retrying deployment."
  aws cloudformation delete-stack \
    --profile "$PROFILE" \
    --region "$REGION" \
    --stack-name "$STACK_NAME" \
    --no-cli-pager
  aws cloudformation wait stack-delete-complete \
    --profile "$PROFILE" \
    --region "$REGION" \
    --stack-name "$STACK_NAME"
fi

echo "Deploying the complete Gatewatch web dashboard to account $ACCOUNT_ID in $REGION."
aws cloudformation deploy \
  --profile "$PROFILE" \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --template-file "$TEMPLATE" \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    EnvironmentName=personal \
    ArtifactBucket="$ARTIFACT_BUCKET" \
    ArtifactKey="$ARTIFACT_KEY" \
    ArtifactVersionId="$ARTIFACT_VERSION_ID" \
    ArtifactSha256="$PACKAGE_SHA256" \
    SnapshotBucket="$SNAPSHOT_BUCKET" \
    SnapshotKey=exports/latest.json \
    SnapshotManifestKey=manifests/latest.json \
    SnapshotRegion="$REGION" \
    OrganizationEvidenceBucket="$ORGANIZATION_EVIDENCE_BUCKET" \
    OrganizationManifestKey=manifests/latest.json \
    CloudFrontOriginPrefixListId="$CLOUDFRONT_PREFIX_LIST" \
    PublicDomainName="$PUBLIC_DOMAIN_NAME" \
    OriginDomainName="$ORIGIN_DOMAIN_NAME" \
    HostedZoneId="$HOSTED_ZONE_ID" \
    PublicCertificateArn="$PUBLIC_CERTIFICATE_ARN" \
    OriginCertificateArn="$ORIGIN_CERTIFICATE_ARN" \
    BootstrapAdminEmail="$BOOTSTRAP_ADMIN_EMAIL" \
    CognitoDomainPrefix="$COGNITO_DOMAIN_PREFIX" \
    OAuth2ProxyImage="$OAUTH2_PROXY_IMAGE" \
    NodeRuntimeImage="$NODE_RUNTIME_IMAGE" \
    SnapshotKmsKeyArn="$SNAPSHOT_KMS_KEY_ARN" \
    OrganizationEvidenceKmsKeyArn="$ORGANIZATION_EVIDENCE_KMS_KEY_ARN" \
    InstanceType=t4g.small

DASHBOARD_URL="$(aws cloudformation describe-stacks \
  --profile "$PROFILE" \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --query 'Stacks[0].Outputs[?OutputKey==`DashboardUrl`].OutputValue' \
  --output text \
  --no-cli-pager)"
for ATTEMPT in $(seq 1 40); do
  STATUS_CODE="$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --max-time 20 \
    "$DASHBOARD_URL/healthz" || true)"
  if [[ "$STATUS_CODE" == "200" ]]; then
    break
  fi
  sleep 15
done

if [[ "$STATUS_CODE" != "200" ]]; then
  echo "The stack completed, but the protected edge health endpoint returned HTTP $STATUS_CODE." >&2
  exit 1
fi

echo "Gatewatch is available at $DASHBOARD_URL"
echo "Cognito sent a temporary password to $BOOTSTRAP_ADMIN_EMAIL. MFA enrollment is required at first sign-in."
