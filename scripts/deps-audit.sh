#!/usr/bin/env bash
# deps-audit.sh
# Runs native dependency vulnerability scanners for each detected ecosystem.
# Deterministic — shells out to real tools, not LLM guesses.
#
# Supported ecosystems:
#   Node.js  → npm audit (requires npm)
#   Python   → pip-audit (pip install pip-audit) or safety
#   Ruby     → bundle audit (gem install bundler-audit)
#   Go       → govulncheck (go install golang.org/x/vuln/cmd/govulncheck@latest)
#   Rust     → cargo audit (cargo install cargo-audit)
#   Java     → OWASP dependency-check (if installed)
#
# Usage:
#   ./deps-audit.sh [target_dir] [--output findings.json]

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

RESULTS=()
MISSING_TOOLS=()

run_audit() {
  local ecosystem="$1"
  local tool="$2"
  local cmd="$3"
  local dir="${4:-$TARGET}"

  if ! command -v "$tool" &>/dev/null; then
    MISSING_TOOLS+=("$ecosystem: '$tool' not found")
    return
  fi

  echo "🔍 Running ${ecosystem} audit..."
  local output exit_code
  output=$(cd "$dir" && eval "$cmd" 2>&1) || exit_code=$?
  output="${output//\"/\\\"}"
  output="${output//$'\n'/\\n}"

  RESULTS+=("{\"ecosystem\":\"${ecosystem}\",\"tool\":\"${tool}\",\"status\":\"completed\",\"output\":\"${output}\"}")
}

# ─── Detect and run per ecosystem ─────────────────────────────────────────────

# Node.js
if [[ -f "$TARGET/package.json" ]]; then
  run_audit "Node.js" "npm" "npm audit --json 2>/dev/null || npm audit 2>&1" "$TARGET"
fi

# Python
if [[ -f "$TARGET/requirements.txt" ]] || [[ -f "$TARGET/pyproject.toml" ]] || [[ -f "$TARGET/Pipfile" ]]; then
  if command -v pip-audit &>/dev/null; then
    run_audit "Python" "pip-audit" "pip-audit --format json 2>/dev/null || pip-audit 2>&1" "$TARGET"
  elif command -v safety &>/dev/null; then
    run_audit "Python" "safety" "safety check --output json 2>/dev/null || safety check 2>&1" "$TARGET"
  else
    MISSING_TOOLS+=("Python: neither 'pip-audit' nor 'safety' found. Install: pip install pip-audit")
  fi
fi

# Ruby
if [[ -f "$TARGET/Gemfile.lock" ]]; then
  if command -v bundle &>/dev/null && bundle exec bundler-audit --version &>/dev/null 2>&1; then
    run_audit "Ruby" "bundle" "bundle exec bundler-audit check --update 2>&1" "$TARGET"
  elif command -v bundler-audit &>/dev/null; then
    run_audit "Ruby" "bundler-audit" "bundler-audit check --update 2>&1" "$TARGET"
  else
    MISSING_TOOLS+=("Ruby: 'bundler-audit' not found. Install: gem install bundler-audit")
  fi
fi

# Go
if [[ -f "$TARGET/go.mod" ]]; then
  run_audit "Go" "govulncheck" "govulncheck ./... 2>&1" "$TARGET"
fi

# Rust
if [[ -f "$TARGET/Cargo.toml" ]]; then
  run_audit "Rust" "cargo-audit" "cargo audit --json 2>/dev/null || cargo audit 2>&1" "$TARGET"
fi

# Java (OWASP Dependency-Check)
if [[ -f "$TARGET/pom.xml" ]] || [[ -f "$TARGET/build.gradle" ]]; then
  if command -v dependency-check &>/dev/null; then
    run_audit "Java" "dependency-check" "dependency-check --scan . --format JSON --out /tmp/depcheck-out 2>&1 && cat /tmp/depcheck-out/dependency-check-report.json 2>/dev/null || echo 'See dependency-check output'" "$TARGET"
  else
    MISSING_TOOLS+=("Java: 'dependency-check' not found. Install OWASP Dependency-Check: https://owasp.org/www-project-dependency-check/")
  fi
fi

# ─── Build output ──────────────────────────────────────────────────────────────
RESULTS_JSON=$(IFS=,; echo "${RESULTS[*]:-}")
MISSING_JSON=""
if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
  MISSING_STRS=()
  for m in "${MISSING_TOOLS[@]}"; do
    m="${m//\"/\\\"}"
    MISSING_STRS+=("\"$m\"")
  done
  MISSING_JSON=$(IFS=,; echo "${MISSING_STRS[*]}")
fi

OUTPUT=$(cat <<EOF
{
  "schema_version": "1.0",
  "tool": "deps-audit.sh",
  "timestamp": "${TIMESTAMP}",
  "target": "${TARGET}",
  "summary": {
    "ecosystems_scanned": ${#RESULTS[@]},
    "missing_tools": ${#MISSING_TOOLS[@]}
  },
  "results": [${RESULTS_JSON}],
  "missing_tools": [${MISSING_JSON}]
}
EOF
)

if [[ -n "$OUTPUT_FILE" ]]; then
  mkdir -p "$(dirname "$OUTPUT_FILE")"
  echo "$OUTPUT" > "$OUTPUT_FILE"
  echo "📦 Dependency audit complete: ${#RESULTS[@]} ecosystems scanned"
  if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
    echo "⚠️  Missing tools:"
    for m in "${MISSING_TOOLS[@]}"; do echo "    - $m"; done
  fi
  echo "📄 Report written to: ${OUTPUT_FILE}"
else
  echo "$OUTPUT"
fi
