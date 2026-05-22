#!/usr/bin/env bash
# run-full-audit.sh
# Orchestrates all security scripts and merges output into a single findings report.
# Each run produces a timestamped file so audit history is preserved.
# A `latest` symlink always points to the most recent run.
#
# Usage:
#   ./run-full-audit.sh [target_dir] [--url https://yourapp.com] [--dir .claude/findings]
#
# Output:
#   .claude/findings/audit-YYYYMMDD-HHMMSS.json   ← timestamped report
#   .claude/findings/latest.json                   ← symlink to most recent

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-.}"
URL=""
FINDINGS_DIR=".claude/findings"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
DATESTAMP=$(date -u +"%Y%m%d-%H%M%S")

shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) URL="$2";          shift 2 ;;
    --dir) FINDINGS_DIR="$2"; shift 2 ;;
    *) shift ;;
  esac
done

# Timestamped output file — never overwritten
OUTPUT_FILE="${FINDINGS_DIR}/audit-${DATESTAMP}.json"
LATEST_LINK="${FINDINGS_DIR}/latest.json"

mkdir -p "$FINDINGS_DIR"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo ""
echo "╔══════════════════════════════════════╗"
echo "║     OWASP Security Audit Suite       ║"
echo "╚══════════════════════════════════════╝"
echo ""

# ─── Run each scanner ─────────────────────────────────────────────────────────

echo "▶ [1/4] Static analysis (OWASP patterns)..."
bash "$SCRIPT_DIR/security-audit.sh" "$TARGET" --output "$TMP_DIR/static.json" || true

echo "▶ [2/4] Secrets scan..."
bash "$SCRIPT_DIR/secrets-scan.sh" "$TARGET" --output "$TMP_DIR/secrets.json" || true

echo "▶ [3/4] Dependency vulnerabilities..."
bash "$SCRIPT_DIR/deps-audit.sh" "$TARGET" --output "$TMP_DIR/deps.json" || true

if [[ -n "$URL" ]]; then
  echo "▶ [4/4] HTTP security headers ($URL)..."
  bash "$SCRIPT_DIR/headers-check.sh" "$URL" --output "$TMP_DIR/headers.json" || true
else
  echo "▶ [4/4] HTTP headers check skipped (no --url provided)"
  echo '{"tool":"headers-check.sh","skipped":true,"reason":"No --url provided"}' > "$TMP_DIR/headers.json"
fi

# ─── Merge all reports ────────────────────────────────────────────────────────

read_json() { cat "$TMP_DIR/$1.json" 2>/dev/null || echo '{}'; }

STATIC_JSON=$(read_json "static")
SECRETS_JSON=$(read_json "secrets")
DEPS_JSON=$(read_json "deps")
HEADERS_JSON=$(read_json "headers")

# Count total findings across all tools
total_findings() {
  local json="$1"
  echo "$json" | grep -o '"severity"' | wc -l | tr -d ' '
}

STATIC_COUNT=$(total_findings "$STATIC_JSON")
SECRETS_COUNT=$(total_findings "$SECRETS_JSON")
HEADERS_COUNT=$(total_findings "$HEADERS_JSON")
TOTAL=$((STATIC_COUNT + SECRETS_COUNT + HEADERS_COUNT))

cat > "$OUTPUT_FILE" <<EOF
{
  "schema_version": "1.0",
  "report_type": "full-audit",
  "timestamp": "${TIMESTAMP}",
  "run_id": "audit-${DATESTAMP}",
  "target": "${TARGET}",
  "url": "${URL:-null}",
  "summary": {
    "total_findings": ${TOTAL},
    "static_analysis_findings": ${STATIC_COUNT},
    "secrets_findings": ${SECRETS_COUNT},
    "header_findings": ${HEADERS_COUNT}
  },
  "instructions_for_claude": "This report contains deterministic, verifiable findings from static analysis tools. When interpreting these results: (1) Do NOT re-scan or regenerate findings already present here. (2) Prioritize, explain, and suggest fixes for listed findings. (3) Reference findings by their 'rule' and 'file' fields. (4) Flag CRITICAL findings first. (5) To compare with a previous run, diff the 'findings' arrays by 'rule'+'file'+'line'. (6) Re-run run-full-audit.sh for a fresh scan rather than inferring new findings.",
  "static_analysis": ${STATIC_JSON},
  "secrets_scan": ${SECRETS_JSON},
  "dependency_audit": ${DEPS_JSON},
  "headers_audit": ${HEADERS_JSON}
}
EOF

# ─── Update latest symlink ────────────────────────────────────────────────────
# Use absolute path for symlink so it works from any working directory
ABS_OUTPUT_FILE="$(cd "$(dirname "$OUTPUT_FILE")" && pwd)/$(basename "$OUTPUT_FILE")"
ABS_LATEST_LINK="$(cd "$(dirname "$LATEST_LINK")" && pwd)/$(basename "$LATEST_LINK")"

ln -sf "$ABS_OUTPUT_FILE" "$ABS_LATEST_LINK"

# ─── Show audit history ───────────────────────────────────────────────────────
HISTORY_COUNT=$(ls "${FINDINGS_DIR}"/audit-*.json 2>/dev/null | wc -l | tr -d ' ')

echo ""
echo "══════════════════════════════════════════"
echo " Audit Complete"
echo "══════════════════════════════════════════"
echo " Static findings : $STATIC_COUNT"
echo " Secrets found   : $SECRETS_COUNT"
echo " Header issues   : $HEADERS_COUNT"
echo "──────────────────────────────────────────"
echo " TOTAL           : $TOTAL"
echo "══════════════════════════════════════════"
echo ""
echo "📄 This run : $OUTPUT_FILE"
echo "🔗 Latest   : $LATEST_LINK → $(basename "$OUTPUT_FILE")"
echo "📚 History  : ${HISTORY_COUNT} audit(s) in ${FINDINGS_DIR}/"
echo ""
echo "💡 Analyze:  claude 'Read ${LATEST_LINK} and give me a prioritized remediation plan'"
echo "💡 Compare:  claude 'Compare the two most recent audits in ${FINDINGS_DIR}/ and show what changed'"
echo ""
