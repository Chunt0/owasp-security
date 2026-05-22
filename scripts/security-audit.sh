#!/usr/bin/env bash
# security-audit.sh
# Semgrep-first OWASP static analysis with grep fallback.
# Semgrep uses AST + data flow — not grep — so false positive rate is dramatically lower.
#
# Usage:
#   ./security-audit.sh [target_dir] [--output findings.json]

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

# ─── Semgrep (preferred) ───────────────────────────────────────────────────────
run_semgrep() {
  ENGINE="semgrep"
  echo "  → Semgrep found. Running OWASP + secrets rule packs..."

  local TMP_SEMGREP
  TMP_SEMGREP=$(mktemp /tmp/semgrep-out.XXXXXX.json)

  # Run with OWASP top 10 + injection + secrets packs
  # --no-git-ignore: scan everything, --quiet: suppress progress noise
  semgrep \
    --config "p/owasp-top-ten" \
    --config "p/javascript" \
    --config "p/typescript" \
    --config "p/python" \
    --config "p/php" \
    --config "p/ruby" \
    --config "p/java" \
    --config "p/golang" \
    --json \
    --quiet \
    --no-git-ignore \
    "$TARGET" > "$TMP_SEMGREP" 2>/dev/null || true

  # Parse semgrep JSON into our findings schema
  if command -v python3 &>/dev/null && [[ -s "$TMP_SEMGREP" ]]; then
    local parsed
    parsed=$(python3 - "$TMP_SEMGREP" <<'PYEOF'
import json, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

results = data.get("results", [])
out = []
for r in results:
    sev_map = {"ERROR": "CRITICAL", "WARNING": "HIGH", "INFO": "MEDIUM"}
    sev = sev_map.get(r.get("extra", {}).get("severity", "INFO"), "MEDIUM")

    meta  = r.get("extra", {}).get("metadata", {})
    owasp = meta.get("owasp", [""])[0] if isinstance(meta.get("owasp"), list) else meta.get("owasp", "")
    cwe   = meta.get("cwe", [""])[0]   if isinstance(meta.get("cwe"),   list) else meta.get("cwe",   "")

    match_lines = r.get("extra", {}).get("lines", "").strip().replace('"', '\\"').replace("\n", "\\n")

    out.append(json.dumps({
        "severity":    sev,
        "category":    owasp or cwe or "semgrep",
        "rule":        r.get("check_id", ""),
        "file":        r.get("path", ""),
        "line":        r.get("start", {}).get("line", 0),
        "match":       match_lines[:200],
        "remediation": r.get("extra", {}).get("message", "See semgrep rule for details.")
    }))

print(",".join(out))
PYEOF
)
    # Add each finding
    if [[ -n "$parsed" ]]; then
      # Split on },{ boundaries into array
      while IFS= read -r finding; do
        [[ -n "$finding" ]] && FINDINGS+=("$finding")
      done < <(echo "[$parsed]" | python3 -c "
import json,sys
data=json.load(sys.stdin)
for item in data:
    print(json.dumps(item))
" 2>/dev/null || true)
    fi
  fi

  rm -f "$TMP_SEMGREP"
}

# ─── Grep fallback ─────────────────────────────────────────────────────────────
run_grep_fallback() {
  ENGINE="grep-fallback"
  echo "  → Semgrep not found. Using grep fallback (install semgrep for better results)."
  echo "    Install: pip install semgrep  OR  brew install semgrep"

  EXTENSIONS="py,js,ts,jsx,tsx,php,rb,java,go,cs,sh"

  add_finding() {
    local severity="$1" category="$2" rule="$3" file="$4" line="$5" match="$6" remediation="$7"
    match="${match//\"/\\\"}"
    FINDINGS+=("{\"severity\":\"${severity}\",\"category\":\"${category}\",\"rule\":\"${rule}\",\"file\":\"${file}\",\"line\":${line},\"match\":\"${match}\",\"remediation\":\"${remediation}\"}")
  }

  scan_pattern() {
    local severity="$1" category="$2" rule="$3" pattern="$4" remediation="$5"
    local extensions="${6:-$EXTENSIONS}"
    IFS=',' read -ra EXTS <<< "$extensions"
    for ext in "${EXTS[@]}"; do
      while IFS=: read -r file line match; do
        [[ -z "$file" ]] && continue
        add_finding "$severity" "$category" "$rule" "$file" "$line" "$match" "$remediation"
      done < <(grep -rn --include="*.${ext}" -P "$pattern" "$TARGET" 2>/dev/null || true)
    done
  }

  # ── Injection: SQL — only match clear string concat into execute/query calls
  # Avoids .format() in non-SQL context, avoids % modulo operator
  scan_pattern "CRITICAL" "A05:Injection" "sql-string-concat" \
    '(cursor|db|conn|connection)\.(execute|query|raw)\s*\(\s*[f]?["\x27].*(\+|%s|%d)' \
    "Use parameterized queries. Never concatenate user input into SQL strings." \
    "py,js,ts,tsx,jsx,php,rb,java"

  # ── Injection: Shell — subprocess with shell=True or os.system
  scan_pattern "CRITICAL" "A05:Injection" "shell-injection" \
    'os\.system\s*\(|subprocess\.[a-z]+\(.+shell\s*=\s*True' \
    "Use subprocess.run() with shell=False and a list of arguments." \
    "py"

  # ── Injection: eval with user-controlled input (skip test files)
  scan_pattern "CRITICAL" "A05:Injection" "eval-injection" \
    '\beval\s*\(\s*(req\.|request\.|params\.|body\.|query\.|user)' \
    "Never pass user-controlled input to eval()." \
    "py,js,ts,tsx,jsx,php,rb"

  # ── Unsafe deserialization
  scan_pattern "HIGH" "A05:Injection" "deserialize-unsafe" \
    'pickle\.loads\s*\(|yaml\.load\s*\([^,)]+\)|Marshal\.load\s*\(' \
    "Use json.loads or yaml.safe_load instead." \
    "py,rb"

  # ── Auth: weak hashing
  scan_pattern "CRITICAL" "A07:AuthFailures" "weak-hash" \
    'hashlib\.(md5|sha1)\s*\(.*password|md5\s*\(\s*\$password' \
    "Use Argon2 or bcrypt for password hashing. MD5/SHA1 are not suitable." \
    "py,php"

  # ── Auth: JWT none algorithm
  scan_pattern "HIGH" "A07:AuthFailures" "jwt-none-alg" \
    'algorithms\s*=\s*\[.*["\x27]none["\x27]|verify\s*=\s*False' \
    "Never allow 'none' algorithm. Pin explicitly to RS256 or HS256." \
    "py,js,ts,tsx"

  # ── Access control: missing auth decorator on route handlers
  scan_pattern "HIGH" "A01:BrokenAccessControl" "unprotected-route" \
    '^@app\.route\s*\(|^router\.(get|post|put|delete|patch)\s*\(' \
    "Verify this route has authentication/authorization middleware." \
    "py,js,ts,tsx"

  # ── Config: debug mode enabled
  scan_pattern "HIGH" "A02:Misconfiguration" "debug-enabled" \
    'DEBUG\s*=\s*True|app\.run\(.*debug\s*=\s*True' \
    "Disable debug mode in production. Use environment-based config." \
    "py"

  # ── Config: SSL verification disabled
  scan_pattern "HIGH" "A02:Misconfiguration" "ssl-verify-disabled" \
    'verify\s*=\s*False|rejectUnauthorized\s*:\s*false' \
    "Never disable SSL verification in production." \
    "py,js,ts,tsx"

  # ── HTTP URLs — only flag external, not localhost/internal config values
  scan_pattern "MEDIUM" "A04:CryptoFailures" "plaintext-http-url" \
    'https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1|host\b)[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}' \
    "Verify this URL uses HTTPS. HTTP transmits data in plaintext." \
    "py,js,ts,tsx,jsx"

  # ── Weak PRNG
  scan_pattern "HIGH" "A04:CryptoFailures" "weak-random" \
    'Math\.random\s*\(\s*\)|random\.random\s*\(\s*\)' \
    "Use cryptographically secure random: crypto.randomBytes() or secrets.token_hex()." \
    "js,ts,tsx,jsx,py"

  # ── SSRF: user-controlled URL in fetch/requests
  scan_pattern "CRITICAL" "API7:SSRF" "unvalidated-url-fetch" \
    '(fetch|axios\.(get|post)|requests\.(get|post))\s*\(\s*(req\.|request\.|params\.|body\.|query\.)' \
    "Validate user-supplied URLs against an allowlist. Block internal IP ranges." \
    "py,js,ts,tsx,jsx"

  # ── LLM: prompt injection via concatenation
  scan_pattern "CRITICAL" "LLM01:PromptInjection" "unsanitized-prompt-concat" \
    '(system_prompt|messages|prompt)\s*[+]=\s*|`[^`]*\$\{.*(user|input|query|body|message)' \
    "Never concatenate user input into prompts. Use structured roles and delimiters." \
    "py,js,ts,tsx,jsx"
}

# ─── Choose engine ─────────────────────────────────────────────────────────────
if command -v semgrep &>/dev/null; then
  run_semgrep
else
  run_grep_fallback
fi

# ─── Build output ──────────────────────────────────────────────────────────────
CRITICAL_COUNT=0; HIGH_COUNT=0; MEDIUM_COUNT=0

for f in "${FINDINGS[@]}"; do
  [[ "$f" == *'"severity":"CRITICAL"'* ]] && ((CRITICAL_COUNT++)) || true
  [[ "$f" == *'"severity":"HIGH"'*     ]] && ((HIGH_COUNT++))     || true
  [[ "$f" == *'"severity":"MEDIUM"'*   ]] && ((MEDIUM_COUNT++))   || true
done

FINDINGS_JSON=$(IFS=,; echo "${FINDINGS[*]:-}")
OUTPUT=$(cat <<EOF
{
  "schema_version": "1.0",
  "tool": "security-audit.sh",
  "engine": "${ENGINE}",
  "timestamp": "${TIMESTAMP}",
  "target": "${TARGET}",
  "summary": {
    "total": ${#FINDINGS[@]},
    "critical": ${CRITICAL_COUNT},
    "high": ${HIGH_COUNT},
    "medium": ${MEDIUM_COUNT}
  },
  "findings": [${FINDINGS_JSON}]
}
EOF
)

if [[ -n "$OUTPUT_FILE" ]]; then
  mkdir -p "$(dirname "$OUTPUT_FILE")"
  echo "$OUTPUT" > "$OUTPUT_FILE"
  echo "✅ Static analysis complete [engine: ${ENGINE}]: ${#FINDINGS[@]} findings (${CRITICAL_COUNT} critical, ${HIGH_COUNT} high, ${MEDIUM_COUNT} medium)"
  echo "📄 Report: ${OUTPUT_FILE}"
else
  echo "$OUTPUT"
fi
