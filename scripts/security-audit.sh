#!/usr/bin/env bash
# security-audit.sh
# Deterministic static analysis scanner for OWASP Top 10 patterns.
# Produces structured JSON findings — no LLM inference required.
#
# Usage:
#   ./security-audit.sh [target_dir] [--output findings.json]
#   ./security-audit.sh ./src --output .claude/findings/audit.json
#
# Output: JSON array of findings written to --output path (default: stdout)

set -euo pipefail

TARGET="${1:-.}"
OUTPUT_FILE=""
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Parse flags
shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) OUTPUT_FILE="$2"; shift 2 ;;
    *) shift ;;
  esac
done

FINDINGS=()

# ─── Helper ────────────────────────────────────────────────────────────────────
add_finding() {
  local severity="$1"
  local category="$2"
  local rule="$3"
  local file="$4"
  local line="$5"
  local match="$6"
  local remediation="$7"

  # Escape double quotes in match string
  match="${match//\"/\\\"}"

  FINDINGS+=("{\"severity\":\"${severity}\",\"category\":\"${category}\",\"rule\":\"${rule}\",\"file\":\"${file}\",\"line\":${line},\"match\":\"${match}\",\"remediation\":\"${remediation}\"}")
}

scan_pattern() {
  local severity="$1"
  local category="$2"
  local rule="$3"
  local pattern="$4"
  local remediation="$5"
  local extensions="${6:-py,js,ts,php,rb,java,go,cs,sh}"

  IFS=',' read -ra EXTS <<< "$extensions"
  for ext in "${EXTS[@]}"; do
    while IFS=: read -r file line match; do
      [[ -z "$file" ]] && continue
      add_finding "$severity" "$category" "$rule" "$file" "$line" "$match" "$remediation"
    done < <(grep -rn --include="*.${ext}" -P "$pattern" "$TARGET" 2>/dev/null || true)
  done
}

# ─── A05: Injection ────────────────────────────────────────────────────────────
scan_pattern "CRITICAL" "A05:Injection" "sql-string-concat" \
  '(execute|query|raw)\s*\(\s*[f"\x27].*\+|%\s*\w+|\.format\(' \
  "Use parameterized queries. Never concatenate user input into SQL strings." \
  "py,js,ts,php,rb,java"

scan_pattern "CRITICAL" "A05:Injection" "shell-injection" \
  'os\.system\s*\(|subprocess\.[a-z]+\(.+shell\s*=\s*True|exec\s*\(' \
  "Use subprocess.run() with shell=False and a list of arguments." \
  "py"

scan_pattern "CRITICAL" "A05:Injection" "eval-injection" \
  '\beval\s*\(' \
  "Never pass user-controlled input to eval(). Use safe parsers instead." \
  "py,js,ts,php,rb"

scan_pattern "HIGH" "A05:Injection" "deserialize-unsafe" \
  'pickle\.loads|yaml\.load\s*\([^,)]+\)|Marshal\.load|ObjectInputStream|unserialize\(' \
  "Use safe deserialization: json.loads, yaml.safe_load, or allowlisted types." \
  "py,rb,java,php"

# ─── A07: Auth Failures ────────────────────────────────────────────────────────
scan_pattern "CRITICAL" "A07:AuthFailures" "weak-hash" \
  'md5\s*\(|sha1\s*\(|hashlib\.(md5|sha1)\s*\(' \
  "Use Argon2 or bcrypt for password hashing. MD5/SHA1 are not suitable." \
  "py,js,ts,php,rb,java"

scan_pattern "HIGH" "A07:AuthFailures" "hardcoded-secret" \
  '(password|secret|api_?key|auth_?token|private_?key)\s*=\s*["\x27][A-Za-z0-9+/=_\-]{8,}["\x27]' \
  "Move secrets to environment variables or a secrets vault." \
  "py,js,ts,php,rb,java,go,cs,env"

scan_pattern "HIGH" "A07:AuthFailures" "jwt-none-alg" \
  'algorithms\s*=\s*\[.*none.*\]|verify\s*=\s*False' \
  "Never allow 'none' algorithm. Pin to RS256 or HS256 explicitly." \
  "py,js,ts"

# ─── A01: Broken Access Control ────────────────────────────────────────────────
scan_pattern "HIGH" "A01:BrokenAccessControl" "mass-assignment" \
  '\*\*request\.(json|form|data|POST)|User\.new\(params\[|\.permit!' \
  "Allowlist accepted fields explicitly. Never unpack raw request data into models." \
  "py,rb"

scan_pattern "HIGH" "A01:BrokenAccessControl" "path-traversal" \
  'open\s*\(\s*.*\+|readFile\s*\(\s*.*\+|include\s*\(\s*\$_(GET|POST|REQUEST)' \
  "Validate and sanitize file paths. Use realpath() and check against an allowed base directory." \
  "py,js,ts,php"

# ─── A02: Security Misconfiguration ───────────────────────────────────────────
scan_pattern "HIGH" "A02:Misconfiguration" "debug-enabled" \
  'DEBUG\s*=\s*True|debug\s*=\s*true|app\.run\(.*debug\s*=\s*True' \
  "Disable debug mode in production. Use environment-based config." \
  "py,js,ts,rb"

scan_pattern "HIGH" "A02:Misconfiguration" "cors-wildcard" \
  'Access-Control-Allow-Origin.*\*|allow_origins\s*=\s*\[.*\*.*\]|cors\(\s*\*\s*\)' \
  "Replace wildcard CORS with an explicit allowlist of trusted origins." \
  "py,js,ts,rb,java"

scan_pattern "MEDIUM" "A02:Misconfiguration" "ssl-verify-disabled" \
  'verify\s*=\s*False|ssl_verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureRequestWarning' \
  "Never disable SSL verification in production. Fix the certificate instead." \
  "py,js,ts,rb"

# ─── A04: Cryptographic Failures ──────────────────────────────────────────────
scan_pattern "HIGH" "A04:CryptoFailures" "weak-random" \
  'random\.random\(\)|Math\.random\(\)|rand\(\)|mt_rand\(' \
  "Use cryptographically secure random: secrets.token_hex(), crypto.randomBytes(), or equivalent." \
  "py,js,ts,php,rb"

scan_pattern "HIGH" "A04:CryptoFailures" "http-url" \
  'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)' \
  "Use HTTPS for all external URLs. HTTP transmits data in plaintext." \
  "py,js,ts,php,rb,java,go,cs"

# ─── A09: Logging Failures ─────────────────────────────────────────────────────
scan_pattern "MEDIUM" "A09:LoggingFailures" "sensitive-in-log" \
  'log(ger)?\.(info|debug|warn|error)\s*\(.*password|log\s*\(.*token|print\s*\(.*secret' \
  "Never log passwords, tokens, or secrets. Redact sensitive fields before logging." \
  "py,js,ts,php,rb,java,go"

# ─── A10: Exception Handling ───────────────────────────────────────────────────
scan_pattern "HIGH" "A10:ExceptionHandling" "bare-except-passthrough" \
  'except\s*Exception\s*as\s+\w+:\s*\n\s*(pass|return\s+True)' \
  "Never silently swallow exceptions that control access or auth. Log and fail closed." \
  "py"

# ─── SSRF ──────────────────────────────────────────────────────────────────────
scan_pattern "CRITICAL" "API7:SSRF" "unvalidated-url-fetch" \
  'requests\.(get|post|put|patch)\s*\(\s*\w*(url|URL|uri|URI|endpoint|path)\b|fetch\s*\(\s*\w*(url|URL)' \
  "Validate user-supplied URLs against an allowlist. Block private/internal IP ranges." \
  "py,js,ts"

# ─── LLM Security ──────────────────────────────────────────────────────────────
scan_pattern "CRITICAL" "LLM01:PromptInjection" "unsanitized-prompt-concat" \
  '(system_prompt|prompt|messages)\s*[+=]\s*.*user_?input|f[\"\x27].*{user' \
  "Never concatenate user input directly into prompts. Use structured roles and delimiters." \
  "py,js,ts"

scan_pattern "HIGH" "LLM06:ExcessiveAgency" "unrestricted-tool-surface" \
  'tools\s*=\s*ALL_TOOLS|tools\s*=\s*\*|agent.*admin.*token|credentials\s*=\s*admin' \
  "Use minimum required tools. Scope credentials with short TTL and least privilege." \
  "py,js,ts"

# ─── Build output ──────────────────────────────────────────────────────────────
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0

for f in "${FINDINGS[@]}"; do
  [[ "$f" == *'"severity":"CRITICAL"'* ]] && ((CRITICAL_COUNT++)) || true
  [[ "$f" == *'"severity":"HIGH"'* ]]     && ((HIGH_COUNT++))     || true
  [[ "$f" == *'"severity":"MEDIUM"'* ]]   && ((MEDIUM_COUNT++))   || true
done

FINDINGS_JSON=$(IFS=,; echo "${FINDINGS[*]:-}")
OUTPUT=$(cat <<EOF
{
  "schema_version": "1.0",
  "tool": "security-audit.sh",
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
  echo "✅ Audit complete: ${#FINDINGS[@]} findings (${CRITICAL_COUNT} critical, ${HIGH_COUNT} high, ${MEDIUM_COUNT} medium)"
  echo "📄 Report written to: ${OUTPUT_FILE}"
else
  echo "$OUTPUT"
fi
