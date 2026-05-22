#!/usr/bin/env bash
# run-full-audit.sh
# Orchestrates all security scripts and merges output into a single findings report.
# Claude reads this report instead of regenerating findings from scratch.
#
# Usage:
#   ./run-full-audit.sh [target_dir] [--url https://yourapp.com] [--output report.json]
#
# Example:
#   ./run-full-audit.sh ./src --url https://myapp.com --output .claude/findings/full-audit.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-.}"
URL=""
OUTPUT_FILE=".claude/findings/full-audit.json"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)    URL="$2";         shift 2 ;;
    --output) OUTPUT_FILE="$2"; shift 2 ;;
    *) shift ;;
  esac
done

mkdir -p "$(dirname "$OUTPUT_FILE")"
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
  "target": "${TARGET}",
  "url": "${URL:-null}",
  "summary": {
    "total_findings": ${TOTAL},
    "static_analysis_findings": ${STATIC_COUNT},
    "secrets_findings": ${SECRETS_COUNT},
    "header_findings": ${HEADERS_COUNT}
  },
  "instructions_for_claude": "This report contains deterministic, verifiable findings from static analysis tools. When interpreting these results: (1) Do NOT re-scan or regenerate findings that are already present here. (2) Focus your analysis on prioritizing, explaining, and suggesting fixes for the findings listed. (3) Reference findings by their 'rule' and 'file' fields. (4) Flag any CRITICAL findings first. (5) If a follow-up audit is needed, re-run run-full-audit.sh rather than inferring new findings.",
  "static_analysis": ${STATIC_JSON},
  "secrets_scan": ${SECRETS_JSON},
  "dependency_audit": ${DEPS_JSON},
  "headers_audit": ${HEADERS_JSON}
}
EOF

# ─── Summary output ───────────────────────────────────────────────────────────
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
echo "📄 Full report: $OUTPUT_FILE"
echo ""
echo "💡 To have Claude analyze these results, run:"
echo "   claude 'Read $OUTPUT_FILE and give me a prioritized remediation plan'"
echo ""
