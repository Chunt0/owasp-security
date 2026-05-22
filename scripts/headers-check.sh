#!/usr/bin/env bash
# headers-check.sh
# Verifies HTTP security headers against OWASP best practices.
# Deterministic — actual server responses, not model guesses.
#
# Usage:
#   ./headers-check.sh https://yourapp.com [--output findings.json]
#   ./headers-check.sh http://localhost:3000 --output .claude/findings/headers.json

set -euo pipefail

URL="${1:-}"
OUTPUT_FILE=""
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

if [[ -z "$URL" ]]; then
  echo "Usage: $0 <url> [--output findings.json]"
  exit 1
fi

shift
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) OUTPUT_FILE="$2"; shift 2 ;;
    *) shift ;;
  esac
done

FINDINGS=()
PASSES=()

# Fetch headers
HEADERS=$(curl -sI --max-time 10 --location "$URL" 2>/dev/null || true)
if [[ -z "$HEADERS" ]]; then
  echo "❌ Could not connect to $URL"
  exit 1
fi

add_finding() {
  local severity="$1"
  local header="$2"
  local issue="$3"
  local remediation="$4"
  FINDINGS+=("{\"severity\":\"${severity}\",\"header\":\"${header}\",\"issue\":\"${issue}\",\"remediation\":\"${remediation}\"}")
}

add_pass() {
  local header="$1"
  local value="$2"
  value="${value//\"/\\\"}"
  PASSES+=("{\"header\":\"${header}\",\"value\":\"${value}\"}")
}

check_header() {
  local header_name="$1"
  echo "$HEADERS" | grep -i "^${header_name}:" | head -1 | sed 's/^[^:]*: //' | tr -d '\r'
}

# ─── Strict-Transport-Security ─────────────────────────────────────────────────
HSTS=$(check_header "strict-transport-security")
if [[ -z "$HSTS" ]]; then
  add_finding "HIGH" "Strict-Transport-Security" \
    "Header missing. Browsers will not enforce HTTPS." \
    "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
elif echo "$HSTS" | grep -qiP 'max-age=(\d+)' ; then
  MAX_AGE=$(echo "$HSTS" | grep -oP 'max-age=\K\d+')
  if [[ "$MAX_AGE" -lt 31536000 ]]; then
    add_finding "MEDIUM" "Strict-Transport-Security" \
      "max-age=${MAX_AGE} is below recommended 31536000 (1 year)." \
      "Set max-age to at least 31536000."
  else
    add_pass "Strict-Transport-Security" "$HSTS"
  fi
fi

# ─── Content-Security-Policy ───────────────────────────────────────────────────
CSP=$(check_header "content-security-policy")
if [[ -z "$CSP" ]]; then
  add_finding "HIGH" "Content-Security-Policy" \
    "Header missing. No XSS or injection protection from browser." \
    "Add a CSP that restricts script-src, object-src, and base-uri at minimum."
elif echo "$CSP" | grep -qP "script-src\s+['\"]unsafe-inline['\"]|script-src\s+\*"; then
  add_finding "HIGH" "Content-Security-Policy" \
    "CSP contains 'unsafe-inline' or wildcard in script-src — negates XSS protection." \
    "Remove 'unsafe-inline' from script-src. Use nonces or hashes instead."
else
  add_pass "Content-Security-Policy" "${CSP:0:80}..."
fi

# ─── X-Content-Type-Options ────────────────────────────────────────────────────
XCTO=$(check_header "x-content-type-options")
if [[ -z "$XCTO" ]]; then
  add_finding "MEDIUM" "X-Content-Type-Options" \
    "Header missing. Browser may MIME-sniff responses." \
    "Add: X-Content-Type-Options: nosniff"
else
  add_pass "X-Content-Type-Options" "$XCTO"
fi

# ─── X-Frame-Options ───────────────────────────────────────────────────────────
XFO=$(check_header "x-frame-options")
CSP_FRAME=$(echo "$CSP" | grep -oi 'frame-ancestors[^;]*' || true)
if [[ -z "$XFO" && -z "$CSP_FRAME" ]]; then
  add_finding "MEDIUM" "X-Frame-Options" \
    "Neither X-Frame-Options nor CSP frame-ancestors set. Clickjacking possible." \
    "Add: X-Frame-Options: DENY (or use CSP frame-ancestors 'none')"
else
  add_pass "X-Frame-Options" "${XFO:-set via CSP frame-ancestors}"
fi

# ─── Referrer-Policy ───────────────────────────────────────────────────────────
RP=$(check_header "referrer-policy")
if [[ -z "$RP" ]]; then
  add_finding "LOW" "Referrer-Policy" \
    "Header missing. URLs (including paths/query strings) may leak to third parties." \
    "Add: Referrer-Policy: strict-origin-when-cross-origin"
else
  add_pass "Referrer-Policy" "$RP"
fi

# ─── Permissions-Policy ────────────────────────────────────────────────────────
PP=$(check_header "permissions-policy")
if [[ -z "$PP" ]]; then
  add_finding "LOW" "Permissions-Policy" \
    "Header missing. Browser features (camera, mic, geolocation) not restricted." \
    "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"
else
  add_pass "Permissions-Policy" "$PP"
fi

# ─── Server header leakage ─────────────────────────────────────────────────────
SERVER=$(check_header "server")
if echo "$SERVER" | grep -qiP '(apache|nginx|iis|express|gunicorn)/[\d.]+'; then
  add_finding "LOW" "Server" \
    "Server header leaks software version: ${SERVER}" \
    "Strip or genericize the Server header to not reveal stack details."
fi

XPOWERED=$(check_header "x-powered-by")
if [[ -n "$XPOWERED" ]]; then
  add_finding "LOW" "X-Powered-By" \
    "X-Powered-By header exposes stack: ${XPOWERED}" \
    "Remove X-Powered-By header (e.g., app.disable('x-powered-by') in Express)."
fi

# ─── CORS wildcard ─────────────────────────────────────────────────────────────
CORS=$(check_header "access-control-allow-origin")
if [[ "$CORS" == "*" ]]; then
  ACAO_CREDS=$(check_header "access-control-allow-credentials")
  if [[ "$ACAO_CREDS" == "true" ]]; then
    add_finding "CRITICAL" "Access-Control-Allow-Origin" \
      "Wildcard CORS (*) combined with Allow-Credentials: true. Browsers block this but it signals a misconfiguration." \
      "Replace wildcard with explicit allowed origins. Never combine * with credentials."
  else
    add_finding "MEDIUM" "Access-Control-Allow-Origin" \
      "Wildcard CORS (*) allows any origin to read responses." \
      "Replace with explicit allowed origins list unless this is a truly public API."
  fi
fi

# ─── Build output ──────────────────────────────────────────────────────────────
FINDINGS_JSON=$(IFS=,; echo "${FINDINGS[*]:-}")
PASSES_JSON=$(IFS=,; echo "${PASSES[*]:-}")

CRITICAL_COUNT=0; HIGH_COUNT=0; MEDIUM_COUNT=0; LOW_COUNT=0
for f in "${FINDINGS[@]}"; do
  [[ "$f" == *'"CRITICAL"'* ]] && ((CRITICAL_COUNT++)) || true
  [[ "$f" == *'"HIGH"'*     ]] && ((HIGH_COUNT++))     || true
  [[ "$f" == *'"MEDIUM"'*   ]] && ((MEDIUM_COUNT++))   || true
  [[ "$f" == *'"LOW"'*      ]] && ((LOW_COUNT++))      || true
done

OUTPUT=$(cat <<EOF
{
  "schema_version": "1.0",
  "tool": "headers-check.sh",
  "timestamp": "${TIMESTAMP}",
  "target": "${URL}",
  "summary": {
    "total_issues": ${#FINDINGS[@]},
    "critical": ${CRITICAL_COUNT},
    "high": ${HIGH_COUNT},
    "medium": ${MEDIUM_COUNT},
    "low": ${LOW_COUNT},
    "passing": ${#PASSES[@]}
  },
  "issues": [${FINDINGS_JSON}],
  "passing": [${PASSES_JSON}]
}
EOF
)

if [[ -n "$OUTPUT_FILE" ]]; then
  mkdir -p "$(dirname "$OUTPUT_FILE")"
  echo "$OUTPUT" > "$OUTPUT_FILE"
  echo "🛡️  Headers check complete: ${#FINDINGS[@]} issues (${#PASSES[@]} passing)"
  echo "📄 Report written to: ${OUTPUT_FILE}"
else
  echo "$OUTPUT"
fi
