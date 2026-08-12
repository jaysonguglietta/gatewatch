#!/usr/bin/env bash

set -euo pipefail

PROFILE="${AWS_PROFILE:-personal}"
REGION="${AWS_REGION:-$(aws configure get region --profile "$PROFILE")}"
REGION="${REGION:-us-east-1}"
STACK_NAME="${GATEWATCH_ORGANIZATION_STACK_NAME:-gatewatch-organization-collector}"
TEMPLATE="infrastructure/cloudformation/gatewatch-organization-collector.yaml"
SOURCE="infrastructure/lambda/organization-collector/index.py"
TARGET_IDS="${GATEWATCH_ORGANIZATION_TARGET_IDS:-}"
STACKSET_CALL_AS="${GATEWATCH_STACKSET_CALL_AS:-DELEGATED_ADMIN}"
REGION_ALLOW_LIST="${GATEWATCH_REGION_ALLOW_LIST:-}"
EXCLUDED_ACCOUNTS="${GATEWATCH_EXCLUDED_ACCOUNT_IDS:-}"

if [[ ! -f "$TEMPLATE" || ! -f "$SOURCE" ]]; then
  echo "Run this script from the Gatewatch repository root." >&2
  exit 1
fi
if [[ -z "$TARGET_IDS" ]]; then
  echo "Set GATEWATCH_ORGANIZATION_TARGET_IDS to one or more comma-separated root/OU IDs." >&2
  exit 2
fi

ACCOUNT_ID="$(aws sts get-caller-identity \
  --profile "$PROFILE" \
  --query Account \
  --output text \
  --no-cli-pager)"
ARTIFACT_BUCKET="${GATEWATCH_ARTIFACT_BUCKET:-gatewatch-artifacts-$ACCOUNT_ID-$REGION}"

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
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
aws s3api put-bucket-versioning \
  --profile "$PROFILE" \
  --region "$REGION" \
  --bucket "$ARTIFACT_BUCKET" \
  --versioning-configuration Status=Enabled

PACKAGE_DIR="$(mktemp -d -t gatewatch-organization-collector.XXXXXX)"
trap 'rm -rf "$PACKAGE_DIR"' EXIT
cp -p "$SOURCE" "$PACKAGE_DIR/index.py"
(cd "$PACKAGE_DIR" && zip -q collector.zip index.py)
PACKAGE_SHA256="$(shasum -a 256 "$PACKAGE_DIR/collector.zip" | awk '{print $1}')"
ARTIFACT_KEY="lambda/organization-collector/$PACKAGE_SHA256/collector.zip"

aws s3 cp "$PACKAGE_DIR/collector.zip" "s3://$ARTIFACT_BUCKET/$ARTIFACT_KEY" \
  --profile "$PROFILE" \
  --region "$REGION" \
  --sse AES256 \
  --metadata "sha256=$PACKAGE_SHA256" \
  --no-progress

aws cloudformation validate-template \
  --profile "$PROFILE" \
  --region "$REGION" \
  --template-body "file://$TEMPLATE" \
  --no-cli-pager >/dev/null

echo "Deploying Gatewatch organization collection to $ACCOUNT_ID in $REGION."
aws cloudformation deploy \
  --profile "$PROFILE" \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --template-file "$TEMPLATE" \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    OrganizationTargetIds="$TARGET_IDS" \
    ExcludedAccountIds="$EXCLUDED_ACCOUNTS" \
    StackSetCallAs="$STACKSET_CALL_AS" \
    RegionAllowList="$REGION_ALLOW_LIST" \
    LambdaArtifactBucket="$ARTIFACT_BUCKET" \
    LambdaArtifactKey="$ARTIFACT_KEY" \
    MaximumAccountConcurrency="${GATEWATCH_ACCOUNT_CONCURRENCY:-100}" \
    MaximumRegionConcurrency="${GATEWATCH_REGION_CONCURRENCY:-4}" \
    'ScheduleExpression=rate(6 hours)'

STATE_MACHINE_ARN="$(aws cloudformation describe-stacks \
  --profile "$PROFILE" \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --query 'Stacks[0].Outputs[?OutputKey==`CollectionStateMachineArn`].OutputValue' \
  --output text \
  --no-cli-pager)"

EXECUTION_ARN="$(aws stepfunctions start-execution \
  --profile "$PROFILE" \
  --region "$REGION" \
  --state-machine-arn "$STATE_MACHINE_ARN" \
  --input '{"trigger":"initial-deployment"}' \
  --query executionArn \
  --output text \
  --no-cli-pager)"

echo "Organization collector deployed. Initial collection started: $EXECUTION_ARN"
aws cloudformation describe-stacks \
  --profile "$PROFILE" \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --query 'Stacks[0].Outputs[].[OutputKey,OutputValue]' \
  --output table \
  --no-cli-pager
