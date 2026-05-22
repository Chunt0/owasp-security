#!/usr/bin/env bash
# secrets-scan.sh
# Scans for hardcoded secrets, API keys, tokens, and credentials.
# Deterministic output — no LLM inference. Results are verifiable grep matches.
#
# Usage:
#   ./secrets-scan.sh [target_dir] [--output findings.json]
#
# Excludes: node_modules, .git, vendor, dist, *.lock, test fixtures

set -euo pipefail

TARGET="${1:-.}"
OUTPUT_FILE=""
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) OUTPUT_FILE="$2"; shift 2 ;;
    *) shift ;;
  esac
done

FINDINGS=()

EXCLUDE_DIRS="node_modules|\.git|vendor|dist|build|\.next|__pycache__|\.venv|venv"
EXCLUDE_FILES="\.lock$|\.min\.js$|package-lock\.json$|yarn\.lock$"

scan_secret() {
  local rule="$1"
  local pattern="$2"
  local description="$3"

  while IFS=: read -r file line match; do
    [[ -z "$file" ]] && continue
    # Skip excluded dirs and files
    echo "$file" | grep -qP "$EXCLUDE_DIRS" && continue
    echo "$file" | grep -qP "$EXCLUDE_FILES" && continue
    # Skip obvious test/example files
    echo "$file" | grep -qiP '(test|spec|fixture|example|mock|sample|fake)' && continue

    match="${match//\"/\\\"}"
    # Redact the actual secret value in output — show only that it matched
    redacted=$(echo "$match" | sed -E 's/([=:]\s*["\x27]?)[A-Za-z0-9+/=_\-]{8,}/\1[REDACTED]/g')
    redacted="${redacted//\"/\\\"}"

    FINDINGS+=("{\"severity\":\"CRITICAL\",\"category\":\"SecretsExposure\",\"rule\":\"${rule}\",\"file\":\"${file}\",\"line\":${line},\"match\":\"${redacted}\",\"description\":\"${description}\"}")
  done < <(grep -rn -P "$pattern" "$TARGET" 2>/dev/null || true)
}

# ─── Generic high-entropy secrets ──────────────────────────────────────────────
scan_secret "generic-api-key" \
  '(?i)(api_?key|apikey|access_?key|secret_?key|client_?secret)\s*[=:]\s*["\x27]?[A-Za-z0-9+/=_\-]{20,}' \
  "Possible API key or secret. Move to environment variable or secrets vault."

scan_secret "generic-token" \
  '(?i)(auth_?token|bearer_?token|access_?token|refresh_?token)\s*[=:]\s*["\x27][A-Za-z0-9._\-]{20,}' \
  "Possible auth token hardcoded. Rotate immediately and move to secrets management."

scan_secret "generic-password" \
  '(?i)(password|passwd|pwd)\s*[=:]\s*["\x27][^\s"\x27]{6,}["\x27]' \
  "Possible hardcoded password. Use environment variables or a vault."

# ─── Provider-specific patterns ────────────────────────────────────────────────
scan_secret "aws-access-key" \
  'AKIA[0-9A-Z]{16}' \
  "AWS access key ID detected. Rotate immediately via IAM console."

scan_secret "aws-secret-key" \
  '(?i)aws.{0,20}secret.{0,20}["\x27][A-Za-z0-9/+=]{40}' \
  "AWS secret access key detected. Rotate immediately."

scan_secret "github-token" \
  'gh[pousr]_[A-Za-z0-9]{36,}' \
  "GitHub personal access token detected. Revoke at github.com/settings/tokens."

scan_secret "openai-key" \
  'sk-[A-Za-z0-9]{20,}' \
  "OpenAI API key pattern detected. Rotate at platform.openai.com/api-keys."

scan_secret "anthropic-key" \
  'sk-ant-[A-Za-z0-9\-]{20,}' \
  "Anthropic API key detected. Rotate at console.anthropic.com."

scan_secret "slack-token" \
  'xox[baprs]-[A-Za-z0-9\-]{10,}' \
  "Slack token detected. Rotate at api.slack.com/apps."

scan_secret "stripe-key" \
  '(sk|pk)_(live|test)_[A-Za-z0-9]{24,}' \
  "Stripe API key detected. Rotate at dashboard.stripe.com/apikeys."

scan_secret "private-key-block" \
  '-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----' \
  "Private key material found in source file. Remove immediately and rotate the key pair."

scan_secret "jwt-hardcoded" \
  'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}' \
  "Hardcoded JWT found. Tokens should never be committed — rotate and use env/vault."

scan_secret "database-connection-string" \
  '(?i)(postgres|mysql|mongodb|redis|mssql):\/\/[^@\s]+:[^@\s]+@' \
  "Database connection string with credentials. Move to environment variables."

# ─── .env file checks ──────────────────────────────────────────────────────────
# Check if .env files are tracked in git
if git -C "$TARGET" rev-parse --git-dir > /dev/null 2>&1; then
  while IFS= read -r tracked_env; do
    [[ -z "$tracked_env" ]] && continue
    FINDINGS+=("{\"severity\":\"CRITICAL\",\"category\":\"SecretsExposure\",\"rule\":\"env-file-tracked\",\"file\":\"${tracked_env}\",\"line\":0,\"match\":\"${tracked_env} is tracked by git\",\"description\":\".env file committed to git. Remove with git filter-branch or BFG Repo Cleaner, add to .gitignore.\"}")
  done < <(git -C "$TARGET" ls-files | grep -P '\.env($|\.)' 2>/dev/null || true)
fi

# ─── Build output ──────────────────────────────────────────────────────────────
FINDINGS_JSON=$(IFS=,; echo "${FINDINGS[*]:-}")
OUTPUT=$(cat <<EOF
{
  "schema_version": "1.0",
  "tool": "secrets-scan.sh",
  "timestamp": "${TIMESTAMP}",
  "target": "${TARGET}",
  "note": "Secret values are REDACTED in this report. Matches show location only.",
  "summary": {
    "total": ${#FINDINGS[@]}
  },
  "findings": [${FINDINGS_JSON}]
}
EOF
)

if [[ -n "$OUTPUT_FILE" ]]; then
  mkdir -p "$(dirname "$OUTPUT_FILE")"
  echo "$OUTPUT" > "$OUTPUT_FILE"
  echo "🔑 Secrets scan complete: ${#FINDINGS[@]} potential secrets found"
  echo "📄 Report written to: ${OUTPUT_FILE}"
  if [[ ${#FINDINGS[@]} -gt 0 ]]; then
    echo "⚠️  Review findings and rotate any confirmed secrets immediately."
  fi
else
  echo "$OUTPUT"
fi
