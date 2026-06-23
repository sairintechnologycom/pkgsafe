#!/usr/bin/env bash
set -e

# Make sure pkgsafe is in the path
export PATH="$PATH:$(dirname "$0")/.."

ARGS=()

if [ -n "$INPUT_LOCKFILE" ]; then
  ARGS+=("--lockfile" "$INPUT_LOCKFILE")
fi

if [ -n "$INPUT_DEPENDENCY_FILE" ]; then
  ARGS+=("--dependency-file" "$INPUT_DEPENDENCY_FILE")
fi

if [ -n "$INPUT_ECOSYSTEM" ]; then
  ARGS+=("--ecosystem" "$INPUT_ECOSYSTEM")
fi

# Only add policy if the file exists
if [ -n "$INPUT_POLICY" ] && [ -f "$INPUT_POLICY" ]; then
  ARGS+=("--policy" "$INPUT_POLICY")
fi

if [ -n "$INPUT_MODE" ]; then
  ARGS+=("--mode" "$INPUT_MODE")
fi

if [ -n "$INPUT_FAIL_ON" ]; then
  ARGS+=("--fail-on" "$INPUT_FAIL_ON")
fi

if [ "$INPUT_CHANGED_ONLY" = "true" ]; then
  ARGS+=("--changed-only")
fi

if [ -n "$INPUT_BASELINE" ]; then
  ARGS+=("--baseline" "$INPUT_BASELINE")
fi

if [ "$INPUT_SANDBOX" = "true" ]; then
  ARGS+=("--sandbox")
fi

if [ "$INPUT_OFFLINE" = "true" ]; then
  ARGS+=("--offline")
fi

if [ -n "$INPUT_POLICY_PACK" ]; then
  ARGS+=("--policy-pack" "$INPUT_POLICY_PACK")
fi

if [ -n "$INPUT_REGISTRY_CONFIG" ]; then
  ARGS+=("--registry-config" "$INPUT_REGISTRY_CONFIG")
fi

if [ "$INPUT_ENTERPRISE_MODE" = "true" ]; then
  ARGS+=("--enterprise-mode")
else
  ARGS+=("--enterprise-mode=false")
fi

JSON_REPORT="${RUNNER_TEMP:-/tmp}/pkgsafe-results.json"
SARIF_REPORT="${RUNNER_TEMP:-/tmp}/pkgsafe-results.sarif"
MD_SUMMARY="${RUNNER_TEMP:-/tmp}/pkgsafe-summary.md"

ARGS+=("--json-output" "$JSON_REPORT")
ARGS+=("--sarif-output" "$SARIF_REPORT")
ARGS+=("--summary-output" "$MD_SUMMARY")

echo "Running PkgSafe CI scan with args: ${ARGS[@]}"

# Run the command and capture exit code
set +e
pkgsafe ci scan "${ARGS[@]}"
EXIT_CODE=$?
set -e

# Process results if the report was generated
if [ -f "$JSON_REPORT" ]; then
  DECISION=$(jq -r '.decision' "$JSON_REPORT")
  MAX_RISK_SCORE=$(jq -r '[.findings[].risk_score] | max // 0' "$JSON_REPORT" 2>/dev/null || echo 0)
  PACKAGES_SCANNED=$(jq -r '.summary.packages_scanned' "$JSON_REPORT")
  WARN_COUNT=$(jq -r '.summary.warn' "$JSON_REPORT")
  BLOCK_COUNT=$(jq -r '.summary.block' "$JSON_REPORT")

  echo "decision=$DECISION" >> "$GITHUB_OUTPUT"
  echo "risk-score=$MAX_RISK_SCORE" >> "$GITHUB_OUTPUT"
  echo "packages-scanned=$PACKAGES_SCANNED" >> "$GITHUB_OUTPUT"
  echo "warn-count=$WARN_COUNT" >> "$GITHUB_OUTPUT"
  echo "block-count=$BLOCK_COUNT" >> "$GITHUB_OUTPUT"
  echo "json-report=$JSON_REPORT" >> "$GITHUB_OUTPUT"
  echo "sarif-report=$SARIF_REPORT" >> "$GITHUB_OUTPUT"
  echo "markdown-summary=$MD_SUMMARY" >> "$GITHUB_OUTPUT"
fi

# Prepend the PR comment marker to markdown summary if comment-pr is enabled
if [ "$INPUT_COMMENT_PR" = "true" ] && [ "$GITHUB_EVENT_NAME" = "pull_request" ] && [ -f "$MD_SUMMARY" ]; then
  echo "Posting or updating pull request comment..."
  
  # Ensure the file starts with the hidden marker
  TMP_FILE=$(mktemp)
  echo "<!-- pkgsafe-pr-comment -->" > "$TMP_FILE"
  cat "$MD_SUMMARY" >> "$TMP_FILE"
  mv "$TMP_FILE" "$MD_SUMMARY"

  PR_NUMBER=$(jq -r '.pull_request.number' "$GITHUB_EVENT_PATH")
  
  # Find existing comment
  set +e
  COMMENT_ID=$(gh api "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" --paginate | jq -r ".[] | select(.body | contains(\"<!-- pkgsafe-pr-comment -->\")) | .id" | head -n 1)
  set -e

  if [ -n "$COMMENT_ID" ] && [ "$COMMENT_ID" != "null" ]; then
    echo "Updating existing comment $COMMENT_ID..."
    gh api -X PATCH "repos/${GITHUB_REPOSITORY}/issues/comments/${COMMENT_ID}" -F body=@"$MD_SUMMARY" > /dev/null
  else
    echo "Creating new comment..."
    gh api -X POST "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" -F body=@"$MD_SUMMARY" > /dev/null
  fi
fi

# Return the exit code of the scanner
exit $EXIT_CODE
