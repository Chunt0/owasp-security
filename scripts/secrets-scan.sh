#!/usr/bin/env bash
# secrets-scan.sh
# TruffleHog-first secrets scanner with grep fallback.
# TruffleHog uses entropy analysis + 700+ detector patterns vs simple regex.
#
# Usage:
#   ./secrets-scan.sh [target_dir] [--output findings.json]

set -euo pipefail

TARGET="${1:-.}"
OUTPUT_FILE=""
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
ENGINE="unknown"

shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) OUTPUT_FILE="$2"; shift 2 ;;
    *) shift ;;
  esac
done

FINDINGS=()
EXCLUDE_DIRS="node_modules|\.git|vendor|dist|build|\.next|__pycache__|\.venv|venv|bun\.lockb|package-lock\.json|yarn\.lock"

# ─── TruffleHog (preferred) ────────────────────────────────────────────────────
run_trufflehog() {
  ENGINE="trufflehog"
  echo "  → TruffleHog found. Running entropy + 700+ detector patterns..."

  local TMP_TH
  TMP_TH=$(mktemp /tmp/trufflehog-out.XXXXXX.json)

  # --no-verification: faster, offline — remove flag to verify secrets are live
  # --json: machine-readable output
  # --only-verified: alternatively use this to only show confirmed live secrets
  trufflehog filesystem "$TARGET" \
    --no-verification \
    --json \
    2>/dev/null > "$TMP_TH" || true

  # TruffleHog outputs one JSON object per line (NDJSON)
  if [[ -s "$TMP_TH" ]] && command -v python3 &>/dev/null; then
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      local parsed
      parsed=$(python3 - "$line" <<'PYEOF' 2>/dev/null || true)
import json, sys
try:
    r = json.loads(sys.argv[1])
    det  = r.get("DetectorName", "unknown")
    src  = r.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
    file = src.get("file", "")
    line = src.get("line", 0)
    raw  = r.get("Raw", "")
    # Redact — show only first 4 and last 4 chars of secret
    redacted = raw[:4] + "..." + raw[-4:] if len(raw) > 8 else "[REDACTED]"
    print(json.dumps({
        "severity":    "CRITICAL",
        "category":    "SecretsExposure",
        "rule":        f"trufflehog-{det.lower()}",
        "file":        file,
        "line":        line,
        "match":       f"{det} secret detected: {redacted}",
        "remediation": f"Rotate this {det} credential immediately. Move to environment variables or a secrets vault."
    }))
except Exception:
    pass
PYEOF
      [[ -n "$parsed" ]] && FINDINGS+=("$parsed")
    done < "$TMP_TH"
  fi

  rm -f "$TMP_TH"
}

# ─── Grep fallback ─────────────────────────────────────────────────────────────
run_grep_fallback() {
  ENGINE="grep-fallback"
  echo "  → TruffleHog not found. Using grep fallback (install trufflehog for better results)."
  echo "    Install: brew install trufflesecurity/trufflehog/trufflehog"
  echo "             OR: curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh"

  add_finding() {
    local severity="$1" category="$2" rule="$3" file="$4" line="$5" match="$6" desc="$7"
    match="${match//\"/\\\"}"
    # Redact actual secret value
    local redacted
    redacted=$(echo "$match" | sed -E 's/([=:]["'"'"']?)[A-Za-z0-9+\/=_\-]{8,}/\1[REDACTED]/g')
    redacted="${redacted//\"/\\\"}"
    FINDINGS+=("{\"severity\":\"${severity}\",\"category\":\"${category}\",\"rule\":\"${rule}\",\"file\":\"${file}\",\"line\":${line},\"match\":\"${redacted}\",\"remediation\":\"${desc}\"}")
  }

  scan_secret() {
    local rule="$1" pattern="$2" description="$3"
    while IFS=: read -r file line match; do
      [[ -z "$file" ]] && continue
      echo "$file" | grep -qP "$EXCLUDE_DIRS" && continue
      echo "$file" | grep -qiP '(test|spec|fixture|example|mock|sample|fake)' && continue
      add_finding "CRITICAL" "SecretsExposure" "$rule" "$file" "$line" "$match" "$description"
    done < <(grep -rn -P "$pattern" "$TARGET" 2>/dev/null || true)
  }

  scan_secret "generic-api-key" \
    '(?i)(api_?key|apikey|access_?key|secret_?key|client_?secret)\s*[=:]\s*["\x27]?[A-Za-z0-9+\/=_\-]{20,}' \
    "Possible API key. Move to environment variable or secrets vault."

  scan_secret "generic-token" \
    '(?i)(auth_?token|bearer_?token|access_?token|refresh_?token)\s*[=:]\s*["\x27][A-Za-z0-9._\-]{20,}' \
    "Possible auth token. Rotate immediately and move to secrets management."

  scan_secret "generic-password" \
    '(?i)(password|passwd|pwd)\s*[=:]\s*["\x27][^\s"\x27]{8,}["\x27]' \
    "Possible hardcoded password. Use environment variables or a vault."

  scan_secret "aws-access-key-id" \
    'AKIA[0-9A-Z]{16}' \
    "AWS access key ID. Rotate immediately via IAM console."

  scan_secret "aws-secret-key" \
    '(?i)aws.{0,20}secret.{0,20}["\x27][A-Za-z0-9\/+=]{40}' \
    "AWS secret access key. Rotate immediately."

  scan_secret "github-token" \
    'gh[pousr]_[A-Za-z0-9]{36,}' \
    "GitHub token. Revoke at github.com/settings/tokens."

  scan_secret "openai-key" \
    'sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}|sk-proj-[A-Za-z0-9_\-]{50,}' \
    "OpenAI API key. Rotate at platform.openai.com/api-keys."

  scan_secret "anthropic-key" \
    'sk-ant-[A-Za-z0-9\-]{20,}' \
    "Anthropic API key. Rotate at console.anthropic.com."

  scan_secret "stripe-key" \
    '(sk|pk)_(live|test)_[A-Za-z0-9]{24,}' \
    "Stripe API key. Rotate at dashboard.stripe.com/apikeys."

  scan_secret "slack-token" \
    'xox[baprs]-[A-Za-z0-9\-]{10,}' \
    "Slack token. Rotate at api.slack.com/apps."

  scan_secret "private-key-block" \
    '-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----' \
    "Private key in source file. Remove and rotate the key pair immediately."

  scan_secret "jwt-hardcoded" \
    'eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}' \
    "Hardcoded JWT. Tokens should never be committed — rotate and use env/vault."

  scan_secret "database-url" \
    '(?i)(postgres|mysql|mongodb|redis|mssql):\/\/[^@\s]+:[^@\s]+@' \
    "Database connection string with credentials. Move to environment variables."

  scan_secret "sendgrid-key" \
    'SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}' \
    "SendGrid API key. Rotate at app.sendgrid.com/settings/api_keys."

  scan_secret "twilio-key" \
    'SK[0-9a-fA-F]{32}' \
    "Twilio API key. Rotate at console.twilio.com."
}

# ─── Check .env files tracked in git ──────────────────────────────────────────
check_tracked_env_files() {
  if git -C "$TARGET" rev-parse --git-dir > /dev/null 2>&1; then
    while IFS= read -r tracked_env; do
      [[ -z "$tracked_env" ]] && continue
      FINDINGS+=("{\"severity\":\"CRITICAL\",\"category\":\"SecretsExposure\",\"rule\":\"env-file-committed\",\"file\":\"${tracked_env}\",\"line\":0,\"match\":\"${tracked_env} is tracked by git\",\"remediation\":\".env file committed to git. Remove with BFG Repo Cleaner or git filter-repo, then add to .gitignore.\"}")
    done < <(git -C "$TARGET" ls-files | grep -P '\.env($|\.)' 2>/dev/null || true)
  fi
}

# ─── Choose engine ─────────────────────────────────────────────────────────────
if command -v trufflehog &>/dev/null; then
  run_trufflehog
else
  run_grep_fallback
fi

check_tracked_env_files

# ─── Build output ──────────────────────────────────────────────────────────────
FINDINGS_JSON=$(IFS=,; echo "${FINDINGS[*]:-}")
OUTPUT=$(cat <<EOF
{
  "schema_version": "1.0",
  "tool": "secrets-scan.sh",
  "engine": "${ENGINE}",
  "timestamp": "${TIMESTAMP}",
  "target": "${TARGET}",
  "note": "Secret values are REDACTED in this report. Matches show location only.",
  "summary": { "total": ${#FINDINGS[@]} },
  "findings": [${FINDINGS_JSON}]
}
EOF
)

if [[ -n "$OUTPUT_FILE" ]]; then
  mkdir -p "$(dirname "$OUTPUT_FILE")"
  echo "$OUTPUT" > "$OUTPUT_FILE"
  echo "🔑 Secrets scan complete [engine: ${ENGINE}]: ${#FINDINGS[@]} potential secrets found"
  [[ ${#FINDINGS[@]} -gt 0 ]] && echo "⚠️  Review and rotate any confirmed secrets immediately."
  echo "📄 Report: ${OUTPUT_FILE}"
else
  echo "$OUTPUT"
fi
