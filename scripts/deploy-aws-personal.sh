#!/usr/bin/env bash

set -euo pipefail

PROFILE="${AWS_PROFILE:-personal}"
REGION="${AWS_REGION:-$(aws configure get region --profile "$PROFILE")}"
REGION="${REGION:-us-east-1}"
STACK_NAME="${GATEWATCH_STACK_NAME:-gatewatch-personal-sg-collector}"
TEMPLATE="infrastructure/cloudformation/gatewatch-security-group-collector.yaml"

if [[ ! -f "$TEMPLATE" ]]; then
  echo "Run this script from the Gatewatch repository root." >&2
  exit 1
fi

ACCOUNT_ID="$(aws sts get-caller-identity \
  --profile "$PROFILE" \
  --query Account \
  --output text \
  --no-cli-pager)"
ARTIFACT_BUCKET="${GATEWATCH_ARTIFACT_BUCKET:-gatewatch-artifacts-$ACCOUNT_ID-$REGION}"

echo "Deploying Gatewatch collector to AWS account $ACCOUNT_ID in $REGION using profile $PROFILE."

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
fi

aws cloudformation deploy \
  --profile "$PROFILE" \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --template-file "$TEMPLATE" \
  --s3-bucket "$ARTIFACT_BUCKET" \
  --s3-prefix cloudformation/collector \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    CollectionScope=single-account \
    'ScheduleExpression=cron(0 12 * * ? *)' \
    SnapshotRetentionDays=365 \
    LogRetentionDays=90 \
    IncludeNetworkInterfaceUsage=true \
    StrictMode=true \
    MaximumParallelScans=4 \
    CollectorFunctionName=gatewatch-personal-security-group-collector

FUNCTION_NAME="$(aws cloudformation describe-stacks \
  --profile "$PROFILE" \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --query 'Stacks[0].Outputs[?OutputKey==`CollectorFunctionArn`].OutputValue' \
  --output text \
  --no-cli-pager)"

RESULT_FILE="$(mktemp -t gatewatch-collection-result.XXXXXX.json)"
trap 'rm -f "$RESULT_FILE"' EXIT

aws lambda invoke \
  --profile "$PROFILE" \
  --region "$REGION" \
  --function-name "$FUNCTION_NAME" \
  --cli-binary-format raw-in-base64-out \
  --payload '{"trigger":"initial-deployment"}' \
  --no-cli-pager \
  "$RESULT_FILE" >/dev/null

if ! node -e '
  const fs = require("node:fs");
  const result = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  if (result.errorMessage) {
    console.error(`Initial collection failed: ${result.errorMessage}`);
    process.exit(1);
  }
  const summary = result.summary ?? {};
  console.log(`Initial collection completed: ${summary.securityGroupCount ?? 0} security groups, ${summary.securityGroupRuleCount ?? 0} rules across ${summary.regionsScanned ?? 0} Regions.`);
' "$RESULT_FILE"; then
  echo "Inspect /aws/lambda/gatewatch-personal-security-group-collector in CloudWatch Logs." >&2
  exit 1
fi

aws cloudformation describe-stacks \
  --profile "$PROFILE" \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --query 'Stacks[0].Outputs[].[OutputKey,OutputValue]' \
  --output table \
  --no-cli-pager
