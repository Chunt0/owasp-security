---
name: owasp-security
description: Use when reviewing code for security vulnerabilities, implementing authentication/authorization, handling user input, or discussing web application security. Covers OWASP Top 10:2025, API Security Top 10, ASVS 5.0, LLM Top 10 (2025), and Agentic AI security (2026).
---

# OWASP Security Best Practices Skill

Apply these security standards when writing or reviewing code.

---

## Agent Instructions (Read First)

Before generating any security analysis, check for existing scan results:

1. **Check for existing findings first:**
   - Look for `.claude/findings/full-audit.json` or any `*.json` in `.claude/findings/`
   - If a report exists and is less than 24 hours old, **read it and interpret it — do not re-scan**
   - Reference findings by their `rule` and `file` fields from the report

2. **Run scripts for deterministic checks — do not guess:**
   - Static code patterns → `scripts/security-audit.sh`
   - Hardcoded secrets → `scripts/secrets-scan.sh`
   - HTTP headers → `scripts/headers-check.sh <url>`
   - Dependencies → `scripts/deps-audit.sh`
   - All at once → `scripts/run-full-audit.sh`

3. **When writing new findings**, use `references/findings-schema.json` as the output schema so reports are consistent and diffable across runs.

4. **Never regenerate** patterns, checklists, or boilerplate that are already in this skill or in an existing findings report. Reference them by name.

---

## Quick Reference: OWASP Top 10:2025

| # | Vulnerability | Severity | Key Prevention |
|---|---------------|----------|----------------|
| A01 | Broken Access Control | 🔴 CRITICAL | Deny by default, enforce server-side, verify ownership |
| A02 | Security Misconfiguration | 🟠 HIGH | Harden configs, disable defaults, minimize features |
| A03 | Supply Chain Failures | 🟠 HIGH | Lock versions, verify integrity, audit dependencies |
| A04 | Cryptographic Failures | 🔴 CRITICAL | TLS 1.2+, AES-256-GCM, Argon2/bcrypt for passwords |
| A05 | Injection | 🔴 CRITICAL | Parameterized queries, input validation, safe APIs |
| A06 | Insecure Design | 🟠 HIGH | Threat model, rate limit, design security controls |
| A07 | Auth Failures | 🔴 CRITICAL | MFA, check breached passwords, secure sessions |
| A08 | Integrity Failures | 🟠 HIGH | Sign packages, SRI for CDN, safe serialization |
| A09 | Logging Failures | 🟡 MEDIUM | Log security events, structured format, alerting |
| A10 | Exception Handling | 🟠 HIGH | Fail-closed, hide internals, log with context |

---

## Quick Reference: OWASP API Security Top 10 (2023)

| # | Risk | Severity | Key Mitigation |
|---|------|----------|----------------|
| API1 | Broken Object Level Auth | 🔴 CRITICAL | Validate ownership on every object request |
| API2 | Broken Auth | 🔴 CRITICAL | Short-lived tokens, rotate secrets, no creds in URLs |
| API3 | Broken Object Property Auth | 🟠 HIGH | Never return full objects; use allowlist field projection |
| API4 | Unrestricted Resource Consumption | 🟠 HIGH | Rate limit, cap page size, timeout all requests |
| API5 | Broken Function Level Auth | 🔴 CRITICAL | Separate admin endpoints, deny-by-default |
| API6 | Unrestricted Access to Sensitive Flows | 🟠 HIGH | Step-up auth for sensitive operations |
| API7 | SSRF | 🔴 CRITICAL | Allowlist outbound destinations, block internal IPs |
| API8 | Security Misconfiguration | 🟠 HIGH | Disable debug, strip version headers, no CORS wildcard |
| API9 | Improper Inventory | 🟡 MEDIUM | Maintain API catalog, deprecate old versions |
| API10 | Unsafe Consumption of APIs | 🟠 HIGH | Treat 3rd-party API responses as untrusted input |

---

## Security Code Review Checklist

### Input Handling
- [ ] 🔴 CRITICAL: All user input validated server-side
- [ ] 🔴 CRITICAL: Using parameterized queries (not string concatenation)
- [ ] 🟡 MEDIUM: Input length limits enforced
- [ ] 🟡 MEDIUM: Allowlist validation preferred over denylist

### Authentication & Sessions
- [ ] 🔴 CRITICAL: Passwords hashed with Argon2/bcrypt (not MD5/SHA1)
- [ ] 🔴 CRITICAL: Session tokens have sufficient entropy (128+ bits)
- [ ] 🟠 HIGH: Sessions invalidated on logout
- [ ] 🟠 HIGH: MFA available for sensitive operations
- [ ] 🟠 HIGH: Breached password list checked on registration/reset
- [ ] 🟠 HIGH: JWT algorithm pinned (never `["HS256", "RS256"]` together)
- [ ] 🟠 HIGH: JWT `exp`, `iss`, `aud` claims validated
- [ ] 🟡 MEDIUM: Short-lived access tokens (15 min), longer refresh tokens
- [ ] 🟡 MEDIUM: Refresh token rotation enforced (invalidate old on use)
- [ ] 🟡 MEDIUM: Passkeys/WebAuthn considered for modern MFA

### Access Control
- [ ] 🔴 CRITICAL: Authorization checked on every request
- [ ] 🔴 CRITICAL: Deny by default policy
- [ ] 🟠 HIGH: Check for framework-level auth middleware before flagging missing per-route auth
- [ ] 🟠 HIGH: Using object references user cannot manipulate
- [ ] 🟠 HIGH: Privilege escalation paths reviewed
- [ ] 🟠 HIGH: Mass assignment prevented (allowlist accepted fields)
- [ ] 🟡 MEDIUM: Admin endpoints separated from user endpoints

### Data Protection
- [ ] 🔴 CRITICAL: Sensitive data encrypted at rest
- [ ] 🔴 CRITICAL: TLS for all data in transit
- [ ] 🟠 HIGH: No sensitive data in URLs or logs
- [ ] 🟠 HIGH: Secrets in environment/vault (not code)
- [ ] 🟡 MEDIUM: PII redacted before sending to third-party services or LLMs

### Error Handling
- [ ] 🟠 HIGH: No stack traces exposed to users
- [ ] 🟠 HIGH: Fail-closed on errors (deny, not allow)
- [ ] 🟠 HIGH: All exceptions logged with context
- [ ] 🟡 MEDIUM: Consistent error responses (no enumeration)

### Security Headers
- [ ] 🟠 HIGH: `Content-Security-Policy`
- [ ] 🟠 HIGH: `Strict-Transport-Security` (`max-age=31536000; includeSubDomains`)
- [ ] 🟠 HIGH: `X-Content-Type-Options: nosniff`
- [ ] 🟠 HIGH: `X-Frame-Options: DENY` or CSP `frame-ancestors`
- [ ] 🟡 MEDIUM: `Referrer-Policy: strict-origin-when-cross-origin`
- [ ] 🟡 MEDIUM: `Permissions-Policy` — disables unused browser features
- [ ] 🟡 MEDIUM: No `X-Powered-By` or `Server` version headers

### CORS
- [ ] 🔴 CRITICAL: No wildcard `Access-Control-Allow-Origin: *` with credentials
- [ ] 🟠 HIGH: CORS origin validated against explicit allowlist
- [ ] 🟡 MEDIUM: Allowed methods and headers explicitly specified

### File Uploads
- [ ] 🔴 CRITICAL: File extension validated against allowlist
- [ ] 🔴 CRITICAL: Magic bytes verified — don't trust extension alone
- [ ] 🟠 HIGH: Maximum file size enforced
- [ ] 🟠 HIGH: Files stored outside webroot with randomized names
- [ ] 🟠 HIGH: Uploaded files never executed by the server

### SSRF Prevention
- [ ] 🔴 CRITICAL: User-supplied URLs validated against an allowlist of hostnames
- [ ] 🔴 CRITICAL: Internal/private IP ranges blocked (10.x, 172.16.x, 192.168.x, 169.254.x)
- [ ] 🟠 HIGH: DNS rebinding mitigated (resolve once, validate IP before request)
- [ ] 🟠 HIGH: Redirects not followed automatically on user-controlled URLs
- [ ] 🟡 MEDIUM: Cloud metadata endpoint (169.254.169.254) explicitly blocked

### Container & Cloud
- [ ] 🟠 HIGH: Docker images run as non-root user (`USER 1001`)
- [ ] 🟠 HIGH: No secrets in Dockerfiles or image layers — use secrets mounts
- [ ] 🟠 HIGH: Cloud metadata endpoints blocked from app network
- [ ] 🟠 HIGH: IAM roles scoped to minimum permissions (no wildcard `*` actions)
- [ ] 🟠 HIGH: S3/storage buckets not publicly accessible unless intentional
- [ ] 🟡 MEDIUM: Read-only filesystem where possible
- [ ] 🟡 MEDIUM: Kubernetes: no `privileged: true`, drop capabilities, use NetworkPolicy

---

## Secure Code Patterns

### SQL Injection Prevention
```python
# UNSAFE
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
# SAFE
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

### Command Injection Prevention
```python
# UNSAFE
os.system(f"convert {filename} output.png")
# SAFE
subprocess.run(["convert", filename, "output.png"], shell=False)
```

### Password Storage
```python
# UNSAFE
hashlib.md5(password.encode()).hexdigest()
# SAFE
from argon2 import PasswordHasher
PasswordHasher().hash(password)
```

### Access Control
```python
# UNSAFE — No authorization check
@app.route('/api/user/<user_id>')
def get_user(user_id):
    return db.get_user(user_id)

# SAFE — Authorization enforced
@app.route('/api/user/<user_id>')
@login_required
def get_user(user_id):
    if current_user.id != user_id and not current_user.is_admin:
        abort(403)
    return db.get_user(user_id)
```

### Fail-Closed Pattern
```python
# UNSAFE — Fail-open
def check_permission(user, resource):
    try:
        return auth_service.check(user, resource)
    except Exception:
        return True  # DANGEROUS!

# SAFE — Fail-closed
def check_permission(user, resource):
    try:
        return auth_service.check(user, resource)
    except Exception as e:
        logger.error(f"Auth check failed: {e}")
        return False
```

### JWT Security
```python
# UNSAFE — algorithm confusion attack
jwt.decode(token, key, algorithms=["HS256", "RS256", "none"])
# SAFE — pin the algorithm explicitly
jwt.decode(
    token, key,
    algorithms=["RS256"],
    options={"require": ["exp", "iat", "iss"]},
    issuer="https://auth.example.com",
    audience="api.example.com",
)
```

### SSRF Prevention
```python
ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}

def safe_fetch(url: str):
    parsed = urlparse(url)
    if parsed.scheme not in ("https",):
        raise ValueError("Only HTTPS allowed")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Blocked host")
    ip = socket.gethostbyname(parsed.hostname)
    if ipaddress.ip_address(ip).is_private:
        raise ValueError("Private IP blocked")
    return requests.get(url, timeout=5, allow_redirects=False)
```

### Mass Assignment Prevention
```python
# UNSAFE
user = User(**request.json)
# SAFE
ALLOWED_FIELDS = {"name", "email", "bio"}
data = {k: v for k, v in request.json.items() if k in ALLOWED_FIELDS}
user = User(**data)
```

### CORS
```python
ALLOWED_ORIGINS = {"https://app.example.com", "https://admin.example.com"}
origin = request.headers.get("Origin", "")
if origin in ALLOWED_ORIGINS:
    response.headers["Access-Control-Allow-Origin"] = origin
```

---

## Agentic AI Security (OWASP 2026)

| Risk | Description | Mitigation |
|------|-------------|------------|
| ASI01: Goal Hijack | Prompt injection alters agent objectives | Input sanitization, goal boundaries, behavioral monitoring |
| ASI02: Tool Misuse | Tools used in unintended ways | Least privilege, fine-grained permissions, validate I/O |
| ASI03: Identity & Privilege Abuse | Delegated trust, inherited credentials | Short-lived scoped tokens, identity verification |
| ASI04: Supply Chain | Compromised plugins/MCP servers | Verify signatures, sandbox, allowlist plugins |
| ASI05: Code Execution | Unsafe code generation/execution | Sandbox execution, static analysis, human approval |
| ASI06: Memory Poisoning | Corrupted RAG/context data | Validate stored content, segment by trust level |
| ASI07: Insecure Inter-Agent Comms | Spoofing/intercepting agent-to-agent messages | Authenticate, encrypt, verify message integrity |
| ASI08: Cascading Failures | Errors propagate across systems | Circuit breakers, graceful degradation, isolation |
| ASI09: Human-Agent Trust Exploitation | Over-trust in agents | Label AI content, user education, verification steps |
| ASI10: Rogue Agents | Compromised agents acting maliciously | Behavior monitoring, kill switches, anomaly detection |

### Agent Security Checklist
- [ ] 🔴 CRITICAL: All agent inputs sanitized and validated
- [ ] 🔴 CRITICAL: Tools operate with minimum required permissions
- [ ] 🔴 CRITICAL: Credentials are short-lived and scoped
- [ ] 🟠 HIGH: Third-party plugins verified and sandboxed
- [ ] 🟠 HIGH: Code execution happens in isolated environments
- [ ] 🟠 HIGH: Human approval required for destructive or external-effect actions
- [ ] 🟡 MEDIUM: Circuit breakers between agent components
- [ ] 🟡 MEDIUM: Kill switch available for agent systems

---

## OWASP Top 10 for LLM Applications (2025)

| # | Risk | Severity | Key Mitigation |
|---|------|----------|----------------|
| LLM01 | Prompt Injection | 🔴 CRITICAL | Separate trusted instructions from untrusted data |
| LLM02 | Sensitive Information Disclosure | 🔴 CRITICAL | Sanitize RAG data, strip PII, restrict retrieval per user |
| LLM03 | Supply Chain | 🟠 HIGH | Verify model provenance, lock versions |
| LLM04 | Data and Model Poisoning | 🟠 HIGH | Validate training sources, anomaly-detect on ingestion |
| LLM05 | Improper Output Handling | 🔴 CRITICAL | Treat LLM output as untrusted before any sink |
| LLM06 | Excessive Agency | 🔴 CRITICAL | Minimize tools, require human approval for destructive actions |
| LLM07 | System Prompt Leakage | 🟠 HIGH | Never put secrets or auth logic in system prompt |
| LLM08 | Vector and Embedding Weaknesses | 🟠 HIGH | Tenant-isolate vector stores, sign/hash chunks |
| LLM09 | Misinformation | 🟡 MEDIUM | Cite sources, require grounding for high-stakes answers |
| LLM10 | Unbounded Consumption | 🟠 HIGH | Rate-limit, cap tokens per request, hard timeouts |

### LLM Security Checklist
- [ ] 🔴 CRITICAL: User input never blindly concatenated into system prompt
- [ ] 🔴 CRITICAL: LLM output treated as untrusted before reaching tool/DOM/shell/SQL
- [ ] 🔴 CRITICAL: Tool/function-calling surface is minimal and least-privilege
- [ ] 🟠 HIGH: Destructive tools require explicit human approval
- [ ] 🟠 HIGH: System prompt contains no secrets or auth rules
- [ ] 🟠 HIGH: PII redacted before sending to model or logging
- [ ] 🟠 HIGH: Model and adapter versions pinned and verifiable
- [ ] 🟡 MEDIUM: Per-user token and cost budgets enforced
- [ ] 🟡 MEDIUM: Hard timeouts on completions and tool calls

---

## ASVS 5.0 Key Requirements

### Level 1 — All Applications (Baseline)
- Passwords minimum 12 characters
- Check against breached password lists (HaveIBeenPwned API)
- Rate limiting on authentication endpoints
- Session tokens 128+ bits entropy
- HTTPS everywhere; HSTS enabled
- Full spec: https://asvs.owasp.org (L2 is the recommended baseline for most production apps)

### Level 2 — Sensitive Data
All L1 requirements, plus: MFA, cryptographic key management, comprehensive security logging.

### Level 3 — Critical Systems
All L1/L2 requirements, plus: HSM for keys, threat modeling docs, penetration testing validation.

---

## Language-Specific Security Quirks

> Think like a senior security researcher: consider memory model, type system, std library CVEs, ecosystem attack vectors, and runtime behavior.

| Language | Top Risks | Key Watch-fors |
|----------|-----------|----------------|
| JavaScript/TypeScript | Prototype pollution, XSS, eval injection | `eval()`, `innerHTML`, `__proto__` |
| Python | Pickle RCE, shell injection, format string | `pickle`, `eval()`, `os.system()`, `shell=True` |
| Java | Deserialization RCE, XXE, JNDI | `ObjectInputStream`, XML parsers, JNDI lookups |
| C# | BinaryFormatter, SQL injection | `BinaryFormatter`, `TypeNameHandling.All` |
| PHP | Type juggling, file inclusion, unserialize | `==` vs `===`, `include($_GET[...])`, `unserialize()` |
| Go | Race conditions, template injection | `template.HTML()`, `unsafe` package, goroutine races |
| Ruby | Mass assignment, YAML RCE, regex DoS | `YAML.load`, `Marshal.load`, `.permit!` |
| Rust | Unsafe blocks, integer overflow (release) | `unsafe {}`, `.unwrap()` on untrusted input |
| C/C++ | Buffer overflow, use-after-free, format string | `strcpy`, `gets`, `printf(userInput)` |
| Shell | Command injection, word splitting | Unquoted vars, `eval`, missing `set -euo pipefail` |
| SQL | Injection, dynamic queries | String concat in queries, `EXECUTE IMMEDIATE` |

---

## Threat Modeling Quick Reference (STRIDE)

| Threat | Question | Example |
|--------|----------|---------|
| **S**poofing | Can an attacker impersonate a user or service? | Forged JWT, session fixation |
| **T**ampering | Can data be modified in transit or at rest? | Missing HMAC, no integrity check |
| **R**epudiation | Can a user deny performing an action? | Missing audit logs |
| **I**nformation Disclosure | Can sensitive data leak? | Stack traces, verbose errors |
| **D**enial of Service | Can availability be disrupted? | No rate limiting, unbounded queries |
| **E**levation of Privilege | Can a user gain more access? | Missing authz check, mass assignment |

**Quick prompt:** *"What's the worst thing an attacker could do to this component, and what stops them?"*

---

## When to Apply This Skill

- Writing auth, authorization, or session management code
- Handling user input or external data of any kind
- Implementing cryptography or password storage
- Reviewing code for security vulnerabilities
- Designing API endpoints (REST, GraphQL, gRPC)
- Building AI agent systems or LLM integrations
- Making outbound HTTP requests with user-controlled parameters
- Working with JWTs, OAuth, or SSO flows
- Setting up logging, monitoring, or error handling
- Any language — apply the deep analysis mindset throughout
