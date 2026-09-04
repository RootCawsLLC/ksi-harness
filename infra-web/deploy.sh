#!/usr/bin/env bash
# End-to-end deploy: base infra -> build image in CodeBuild -> App Runner service.
# Requires: terraform, aws CLI (authenticated to the target account), git.
# Run from the infra-web/ directory. The repo HEAD must contain web/ and the Dockerfile
# (git archive packages tracked files only).
set -euo pipefail
cd "$(dirname "$0")"
REPO_ROOT="$(cd .. && pwd)"

echo "==> 1/4 Provisioning base infrastructure (deploy_service=false)"
terraform apply -auto-approve -var deploy_service=false

SRC_BUCKET=$(terraform output -raw source_bucket)
CB=$(terraform output -raw codebuild_project)

echo "==> 2/4 Packaging source and uploading to s3://$SRC_BUCKET/source.zip"
git -C "$REPO_ROOT" archive --format=zip -o "$REPO_ROOT/source.zip" HEAD
aws s3 cp "$REPO_ROOT/source.zip" "s3://$SRC_BUCKET/source.zip"
rm -f "$REPO_ROOT/source.zip"

echo "==> 3/4 Building image in CodeBuild"
BUILD_ID=$(aws codebuild start-build --project-name "$CB" --query 'build.id' --output text)
echo "    build: $BUILD_ID"
while true; do
  STATUS=$(aws codebuild batch-get-builds --ids "$BUILD_ID" --query 'builds[0].buildStatus' --output text)
  [ "$STATUS" = "IN_PROGRESS" ] || break
  sleep 10
done
echo "    build status: $STATUS"
[ "$STATUS" = "SUCCEEDED" ] || { echo "Build failed; see CodeBuild logs for $CB."; exit 1; }

echo "==> 4/4 Deploying App Runner service (deploy_service=true)"
terraform apply -auto-approve -var deploy_service=true

URL=$(terraform output -raw service_url)
echo
echo "Done. Service URL: $URL"
echo
