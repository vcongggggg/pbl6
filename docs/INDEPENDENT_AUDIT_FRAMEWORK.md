# PBL6 — INDEPENDENT 8-LAYER SOURCE CODE AUDIT FRAMEWORK

> **Web API Security Platform — Independent Security & Architecture Verification**

---

# 0. CORE REVIEW PRINCIPLES

## 0.1 Source of Truth
Always prioritize evidence in this order:
1. Actual runtime behavior
2. Executed tests / reproducible commands
3. Actual source code
4. Configuration files
5. Database schema / migrations
6. Docker configuration
7. CI/CD configuration
8. Documentation
9. Developer claims / previous agent reports

Never treat documentation as proof that a feature exists.

## 0.2 Evidence Classification
Every important conclusion MUST be classified as exactly one of:

### [VERIFIED]
The reviewer directly executed the relevant code, test, request, benchmark, or security scenario and observed the result.

### [CODE-VERIFIED]
The behavior can be established through deterministic source-code inspection but was not executed.

### [UNVERIFIED]
The reviewer could not establish the claim because required infrastructure, dependency, model, service, credentials, or environment was unavailable.

### [CONTRADICTED]
The implementation contradicts documentation, specification, previous report, test expectation, or claimed behavior.

Never present [UNVERIFIED] findings as verified.
Never invent test results, benchmark numbers, coverage percentages, CVE status, or security guarantees.

## 0.3 No False Positives
Do not report a vulnerability merely because a theoretically dangerous pattern exists.
For every security finding, determine:
1. Is the vulnerable code reachable?
2. Can an attacker control the relevant input?
3. Is there an existing mitigation?
4. Can the attack actually be reproduced?
5. What is the real impact?

Distinguish: theoretical concern vs exploitable vulnerability vs hardening recommendation.

## 0.4 No False Negatives
Do not stop after finding one issue. Continue auditing the complete relevant attack surface.

## 0.5 Never Trust "Looks Secure"
Statements such as "validated", "sanitized", "safe", "protected", "rate limited", "hashed", "encrypted", "isolated", "OWASP compliant" are NOT evidence. Verify the implementation.

## 0.6 Preserve Existing Architecture
Do not rewrite the project merely to make the audit easier. Only recommend architectural changes when justified by security, correctness, reliability, scalability, academic requirements, or maintainability.

## 0.7 Review Scope
Inspect the entire repository where relevant:
```text
gateway/        (FastAPI WAF Gateway, middleware, pipeline, rate limiter, rule engine, DB)
dashboard/      (Next.js / React UI frontend)
ml-engine/      (Feature extraction, Isolation Forest, XGBoost, anomaly detection)
bookie/         (Target API / Upstream bookstore service)
tests/          (Unit, integration, performance, and security test suites)
scripts/        (Profiling, benchmarking, seed, migrations, automation)
docs/           (Architecture specs, academic reports, benchmark records)
docker/         (Compose, Dockerfiles, network policies)
```

---

# 1. SECURITY & THREAT MODEL AUDIT (OWASP API SECURITY TOP 10)

## 1.1 API1 — Broken Object Level Authorization (BOLA/IDOR)
* Predictable resource identifiers (sequential IDs, UUIDs without auth check).
* Missing ownership checks when accessing user logs, alerts, rules, or gateway metrics.
* Test scenarios: User A -> Object B, Unauthenticated -> Object.

## 1.2 API2 — Broken Authentication
* Token validation, expiration, and rotation mechanisms (JWT, API keys).
* Algorithm confusion (`none` algorithm, HMAC vs RSA key confusion).
* Weak secrets, hardcoded secrets, or malformed authentication header crashes.

## 1.3 API3 — Broken Object Property Level Authorization (Mass Assignment)
* Unfiltered schema inputs allowing modification of protected attributes (`role`, `is_admin`, `threat_score_override`).
* Excessive data exposure in response payloads.

## 1.4 API4 — Unrestricted Resource Consumption
* Request body size limits (unbounded JSON parsing, large file uploads).
* Regex complexity, catastrophic backtracking (ReDoS).
* Memory-intensive operations (unbounded caches, deques without maxlen, runaway rate limiter state).

## 1.5 API5 — Broken Function Level Authorization
* Administrative endpoints (`/admin`, `/api/v1/rules`, `/api/v1/models/reload`).
* Verify strict role enforcement and function-level access boundaries.

## 1.6 API6 — Unrestricted Access to Sensitive Business Flows
* Attack execution, rule tampering, model switching, security log wipeout.

## 1.7 API7 — Server-Side Request Forgery (SSRF)
* Verify that the gateway only proxies to explicitly configured, whitelisted upstream targets (`127.0.0.1:5000` / `bookie`).
* Block requests attempting to route to internal metadata (`169.254.169.254`), loopback probing, or unauthorized internal subnets.

## 1.8 API8 — Security Misconfiguration
* Debug mode enabled in production (`DEBUG=True`, verbose stack traces).
* Permissive CORS (`Access-Control-Allow-Origin: *` with credentials).
* Insecure Docker defaults, exposed database ports, default credentials.

## 1.9 API9 — Improper Inventory Management
* Documented vs actual live endpoints (API drift).
* Unversioned, deprecated, or hidden debug endpoints remaining accessible.

## 1.10 API10 — Unsafe Consumption of APIs
* Upstream validation, timeouts, retries, and redirect handling when communicating:
  `Client -> Gateway (:8000) -> Upstream Bookie (:5000) -> Database / Model`.
* Handle malformed or malicious upstream responses without gateway crash.

---

# 2. INPUT VALIDATION & ATTACK PAYLOAD AUDIT

Audit all user-controlled inputs:
* Path, Query parameters, Headers, Body (JSON, form-data, multipart), Cookies, IP headers, Content-Type, HTTP methods.
* Attacks tested: SQL Injection, Cross-Site Scripting (XSS), Command Injection, Path Traversal, SSRF, CRLF Injection, HTTP Request Smuggling, Template Injection.
* Edge-case payloads: `None`, `null`, empty string, negative numbers, NaN, Infinity, malformed UTF-8, zero-width characters, mixed normalization, double URL encoding, Base64/hex obfuscation.

---

# 3. WAF / DETECTION ENGINE AUDIT

## 3.1 Normalization
* Verify `InputNormalizer` prevents bypasses via mixed case, comments (`/**/`), double encoding, Unicode homoglyphs, or chunked transfer encoding.

## 3.2 Rule Correctness
* Inspect rules for false-positive risk on legitimate traffic and false-negative risk on obfuscated payloads.

## 3.3 Threat Score Standardization
* Threat Score MUST strictly satisfy:
  $$0 \le 	ext{Threat Score} \le 100$$
* Prohibit dividing by 10.0 or converting to an inconsistent $0 - 10$ scale.
* Check integer/float conversion, weight accumulation, and boundary clamping.

## 3.4 Detection Determinism
* Given identical input, configuration, and model seed, the detection decision must be deterministic.

---

# 4. SECRETS & CREDENTIAL AUDIT
* Search entire repository and Git history for API keys, JWT secrets, database passwords, tokens, private keys (`.pem`, `.key`).
* Verify secrets are strictly loaded from `.env` and excluded via `.gitignore`.

---

# 5. DEPENDENCY & SUPPLY CHAIN AUDIT
* Check `requirements.txt`, `pyproject.toml`, and lock files for unpinned packages, known CVEs, and outdated vulnerable libraries.
* Verify base Docker images use pinned versions.

---

# 6. ML / MODEL SECURITY AUDIT
* Inspect model loading mechanisms (`pickle`, `joblib`, `cloudpickle`).
* Treat pickle/joblib deserialization as a high-risk boundary.
* Verify SHA-256 model checksum verification and secure fallback when a model file is missing or corrupted.

---

# 7. IP SPOOFING & PROXY HEADER AUDIT
* Audit client IP extraction: `X-Forwarded-For`, `X-Real-IP`, `Forwarded`.
* Ensure that untrusted client-supplied headers cannot spoof identity, bypass rate limiting, or poison security audit logs unless behind an explicitly configured trusted proxy.

---

# 8. PERFORMANCE, MEMORY & CONCURRENCY AUDIT

## 8.1 Big-O & Computational Complexity
* Audit regex for catastrophic backtracking (ReDoS).
* Inspect feature extraction, rule scanning, and tokenization algorithms to ensure $\mathcal{O}(n)$ or $\mathcal{O}(n \log n)$ bounds.

## 8.2 In-Memory Leak & Unbounded Growth
* Inspect all in-memory structures: Sliding window deques, IP counters, cache dictionaries, risk engine states.
* Verify strict maximum size bounds (`maxlen`), TTL expiration, and active periodic cleanup routines.

## 8.3 Database & SQLite Concurrency
* Inspect SQLite session management, WAL mode, transaction isolation, and connection pooling.
* Verify `NullPool` or thread-safe pooling to prevent `database is locked` errors under concurrent write traffic.

---

# 9. ARCHITECTURE ANTI-DRIFT & NETWORK TOPOLOGY

Expected Core Services & Ports:
```text
Gateway (FastAPI WAF):     Port 8000
Upstream API (Bookie):     Port 5000
Dashboard UI (Next.js):    Port 3000
```

Expected Flow:
```text
Client -> Gateway (:8000) -> Detection & Decision Pipeline -> Upstream Target (:5000)
```
Verify that upstream ports are isolated within internal Docker bridge networks and cannot be directly accessed by untrusted external clients.

---

# 10. ACADEMIC & SCIENTIFIC SKEPTICISM

## 10.1 Academic Alignment
* Map implementation principles to:
  * **ISO/IEC 25010** (Software product Quality Requirements and Evaluation).
  * **ISO/IEC 27004:2016** (Information security management — Monitoring, measurement, analysis and evaluation).
  * **RFC 6585** (Additional HTTP Status Codes — 429 Too Many Requests).
  * **RFC 7807** (Problem Details for HTTP APIs).
  * Benchmark baseline papers (Torrano-Gimenez Wiley 2015, CSIC 2010, MDPI Electronics 2025).

## 10.2 Scientific Skepticism ("Too Good To Be True")
* Investigate unusually perfect results:
  * Accuracy / F1 = 100%, 0 False Positives, Sub-millisecond latency under 10,000 req/s.
* Root-cause investigation: Check for data leakage, mock bypass, skipped database I/O, or synthetic benchmark contamination.

---

# 11. FINDING CLASSIFICATION & FORMAT

Every reported finding MUST use this standard schema:

```text
[FINDING]
ID:                    SEC-PBL6-<XXX> / PERF-PBL6-<XXX> / LOGIC-PBL6-<XXX>
SEVERITY:              CRITICAL | HIGH | MEDIUM | LOW | INFO
STATUS:                OPEN | FIXED | VERIFIED | UNVERIFIED
EVIDENCE LEVEL:        [VERIFIED] | [CODE-VERIFIED] | [UNVERIFIED] | [CONTRADICTED]

TITLE:                 Concise summary of the finding
AFFECTED COMPONENT:    e.g., Gateway WAF / Rate Limiter / ML Engine / DB Session
AFFECTED FILE(S):      file:///path/to/file.py (with line range)

DESCRIPTION:           Detailed technical explanation of the issue
ATTACK / FAILURE:      Concrete step-by-step exploit or failure scenario
EVIDENCE:              Exact command output, trace, or deterministic code quote
REPRODUCTION:          Deterministic steps to reproduce

EXPECTED BEHAVIOR:     Correct compliant behavior
ACTUAL BEHAVIOR:       Observed behavior in repository
IMPACT:                Security, stability, or academic consequence
ROOT CAUSE:            Underlying design, architectural, or logic flaw
RECOMMENDATION:        Actionable code diff or architectural fix
REGRESSION TEST:       Proposed test case to prevent recurrence
CONFIDENCE:            HIGH | MEDIUM | LOW
```

---

# 12. MANDATORY PROTOCOLS & FEEDBACK LOOP

1. **Read-Only Audit Principle:** Reviewer never directly overwrites or modifies product code.
2. **Coder Feedback Loop Bridge:** Actionable tasks MUST be written into `docs/REVIEW_FEEDBACK.md` with `- [ ]` checklist and proposed code diffs.
3. **Telegram Communication:** Every plan, finding, and completion report MUST be dispatched to Telegram via:
   ```bash
   python "C:\Study\HocKy6\notify_telegram.py" "<Report Content>"
   ```
