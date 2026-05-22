# owasp-security

A Claude Code skill for comprehensive security auditing based on OWASP Top 10:2025,
API Security Top 10, LLM Top 10, and Agentic AI security standards.

## What's included

- `SKILL.md` — skill entry point with checklists and secure code patterns
- `scripts/run-full-audit.sh` — orchestrates all scanners into one JSON report
- `scripts/security-audit.sh` — static grep-based OWASP pattern scanner
- `scripts/secrets-scan.sh` — hardcoded credentials and key detection
- `scripts/headers-check.sh` — HTTP security headers checker (requires live URL)
- `scripts/deps-audit.sh` — dependency vulnerability scanner (npm, pip, gem, go, cargo)
- `references/findings-schema.json` — structured output schema for findings

## Install

```bash
git clone https://github.com/Chunt0/owasp-security ~/.claude/skills/owasp-security
chmod +x ~/.claude/skills/owasp-security/scripts/*.sh
```

## Usage

```bash
# Full audit (no live URL yet)
~/.claude/skills/owasp-security/scripts/run-full-audit.sh ./your-project

# With live URL
~/.claude/skills/owasp-security/scripts/run-full-audit.sh ./your-project --url https://yourapp.com
```
