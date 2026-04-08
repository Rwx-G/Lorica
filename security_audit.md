# Security Audit Report - Lorica v1.0.0

**Date:** 2026-04-08
**Author:** Romain G.
**Scope:** Full codebase security review (Rust backend, Svelte frontend, dependencies, configuration)
**Method:** Automated static analysis + manual code review (5 parallel analysis agents)

---

## Executive Summary

5 parallel analysis agents audited: project structure, Rust dependencies, WAF/auth/TLS, frontend, and dangerous code patterns. **No critical remotely-exploitable vulnerability found.** Overall security posture is **solid** for a v1.0.0 release.

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High     | 3 |
| Medium   | 5 |
| Low      | 7 |

---

## High Severity

### H1. WAF does not scan request bodies

**File:** `lorica-waf/src/engine.rs:245-272`

The `evaluate()` method only inspects the URI path, query string, and selected headers. Request bodies (POST data, JSON payloads, file uploads) are never scanned. This is a significant gap because:

- SQL injection payloads commonly appear in POST parameters
- XSS payloads are frequently in form bodies
- XXE attacks are entirely body-based (XML documents)
- SSTI/command injection often targets body parameters

**Impact:** Complete WAF bypass via POST requests.
**Mitigating factor:** The WAF protects proxied traffic, not the admin API (which is localhost-only and auth-protected).
**Recommendation:** Document as a known limitation for v1.0.0 and plan body scanning for a future release.

**Resolution:** Added `evaluate_body()` to WafEngine and integrated it via `request_body_filter` in the proxy. Text bodies up to 1 MB are buffered and scanned; binary payloads are skipped. Known limitation documented in `docs/security.md`.

### H2. Single-pass URL decoding allows double-encoding bypass

**File:** `lorica-waf/src/engine.rs:383-405`

The `url_decode()` function only performs a single pass of URL decoding. An attacker can double-encode payloads to bypass detection:
- `%253Cscript%253E` decodes to `%3Cscript%3E` (pass 1) but needs a second pass to become `<script>`.

Additionally, the URI path is scanned **without** URL decoding (line 259), while the query string and headers are decoded. This inconsistency means URL-encoded attacks in the path may be missed.

The path traversal rule does include `%252e%252e` as a pattern, but this is a piecemeal fix.

**Recommendation:** Implement recursive decoding (decode until stable, max 3 iterations) and decode the path as well.

### H3. `cargo audit` failures silently ignored in CI - FIXED

**File:** `.github/workflows/ci.yml:40`

```yaml
cargo audit 2>&1 || true  # CVE findings never block the build
```

Known vulnerabilities in dependencies will never fail the CI pipeline, defeating the purpose of the audit step.

**Recommendation:** Remove `|| true` before release.

**Resolution:** Removed `|| true` so `cargo audit` failures now block the build.

---

## Medium Severity

### M1. Argon2 parameter mismatch between hashing and verification - FIXED

**File:** `lorica-api/src/auth.rs:172`

The `hash_password()` function (used for creating/changing passwords) uses `Argon2::default()`, while `argon2_hasher()` (used for verification) configures explicit OWASP-compliant parameters (Argon2id, 19 MiB, 2 iterations).

**Fix:** Replaced `Argon2::default()` with `argon2_hasher()` in `hash_password()`.

**Resolution:** `hash_password()` now uses `argon2_hasher()` with OWASP-compliant parameters.

### M2. No session invalidation on password change - FIXED

**File:** `lorica-api/src/auth.rs:151-158`

After a password change, existing sessions remain valid. If an attacker has stolen a session token, changing the password does not revoke their access.

**Recommendation:** Invalidate all sessions for the user (except the current one) after a password change.

**Resolution:** Added `remove_all_for_user_except()` to SessionStore and called it after password change.

### M3. No Content-Security-Policy or security headers on dashboard - FIXED

**File:** `lorica-dashboard/src/lib.rs:58-82`

`serve_embedded_file()` only sets `Content-Type` and `Cache-Control`. Missing headers:
- `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`

**Mitigating factor:** The dashboard is served on the management port (localhost only).

**Resolution:** Added CSP, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy headers to all dashboard responses.

### M4. Request body size limit relies solely on Content-Length header

**File:** `lorica/src/proxy_wiring.rs:916-927`

The body size check uses the `Content-Length` header. `Transfer-Encoding: chunked` requests bypass this entirely because they have no `Content-Length`. A streaming body could grow indefinitely without being rejected.

**Recommendation:** Also enforce byte counting during transfer for chunked requests.

**Resolution:** Added byte counting in `request_body_filter` that accumulates received chunk sizes and returns 413 when the route's `max_request_body_bytes` is exceeded.

### M5. Login rate limiter uses a global key instead of per-IP - FIXED

**File:** `lorica-api/src/auth.rs:54`

The rate limiter uses the fixed key `"login"` instead of the client IP. All users share the same bucket (5 attempts / 60s). An attacker can block all legitimate logins by exhausting the global rate limit.

**Mitigating factor:** The API listens on `127.0.0.1` only (localhost), so an external attacker cannot reach the login endpoint directly.

**Resolution:** Rate limiter key changed to `login:{ip}` using `ConnectInfo<SocketAddr>`. Server updated to use `into_make_service_with_connect_info`.

---

## Low Severity

### L1. No maximum password length - FIXED

**File:** `lorica-api/src/auth.rs:129`

Minimum is 8 characters, but there is no maximum. An attacker could send a multi-MB password to cause a DoS via Argon2 (memory/CPU consumption).

**Recommendation:** Add an upper limit (e.g., 128 characters).

**Resolution:** Added 128-character maximum password length validation.

### L2. Legacy rustls 0.21 via AWS SDK

**File:** `Cargo.lock`

The dependency chain includes rustls 0.21.12 (end-of-life) pulled transitively by `aws-smithy-http-client` for Route53 DNS API calls. This is not in the serving path but enlarges the attack surface.

**Recommendation:** Track AWS SDK update to eliminate the legacy chain.

### L3. No `cargo-deny` configuration

No `deny.toml` file exists. `cargo-deny` provides license auditing, ban lists, duplicate detection, and advisory checks beyond `cargo audit`.

**Recommendation:** Add `deny.toml` and run `cargo deny check` in CI.

### L4. No `#![deny(unsafe_code)]` on pure-logic crates

66 occurrences of `unsafe` across 20 source files (mostly in forked Pingora core/proxy crates). Pure-logic crates like `lorica-waf`, `lorica-config`, `lorica-notify`, `lorica-bench`, and `lorica-api` should never need unsafe.

**Recommendation:** Add `#![deny(unsafe_code)]` to pure-logic crates.

### L5. Duplicate `openssl-probe` versions

Two versions present: 0.1.6 (used by `lorica-core`) and 0.2.1. The old 0.1.6 pinning is unnecessary.

**Recommendation:** Bump to 0.2 in `lorica-core/Cargo.toml`.

### L6. `/metrics` endpoint is unauthenticated

**File:** `lorica-api/src/server.rs:95-96`

Prometheus metrics are exposed without authentication. Metrics can reveal route IDs, backend addresses, request rates, and internal architecture details.

**Mitigating factor:** The API binds to localhost only (`127.0.0.1`).

### L7. `dig` command invoked with user-supplied DNS server parameter - FIXED

**File:** `lorica-api/src/acme.rs:1956-1976`

The DNS server address from user input is passed to the `dig` command. While `.args()` is safer than shell expansion (no shell injection), the parameter is not validated for format.

**Recommendation:** Validate DNS server parameter format (IP or hostname) before passing to `dig`.

**Resolution:** Added `is_valid_dns_server()` validation that rejects empty values, values over 253 chars, and any characters outside alphanumeric/dots/hyphens/colons/brackets.

---

## Positive Findings

### Authentication and Sessions
- **Argon2id** with OWASP parameters for verification
- **Session cookies**: `HttpOnly; Secure; SameSite=Strict; Path=/api`
- **Session IDs**: UUID v4, cryptographically random
- **Sliding window** 30-minute timeout with automatic GC of expired sessions
- **Initial password** randomly generated (24 chars), forced change on first login
- **Login rate limiting**: 5 attempts per 60-second window

### API Security
- **Localhost-only binding** (`127.0.0.1`) - admin API never directly exposed
- **Clear separation** of public routes (login, ACME, metrics) vs protected routes (auth middleware)
- **Config import** limited to 1 MB
- **Regex validation** with size limit (1024 chars) for `path_rewrite_pattern`
- **Parameterized SQL queries** throughout (rusqlite `params![]`) - no SQL injection

### Anti-SSRF in Load Test
- `validate_target_url()` only allows configured route hostnames + localhost
- Rejects private IPs (10.x, 192.168.x), 0.0.0.0, dangerous schemes (ftp, file, gopher, etc.)
- Detects octal/hex/decimal IP encoding evasion

### WAF - 39 CRS-Inspired Rules
- **11 categories**: SQL injection, XSS, path traversal, command injection, protocol violations, SSRF, Log4Shell/JNDI, XXE, SSTI, prototype pollution, IP blocklist
- Evasion detection: octal/hex IP encoding, `$IFS`, JNDI lookups, Spring4Shell
- Custom rule support with regex validation
- Detection and blocking modes per route
- IP blocklist with external feed support

### TLS and ACME
- **rustls throughout** - no OpenSSL in the serving path
- **TLS 1.2 and 1.3 only** - no legacy SSL/TLS 1.0/1.1
- CRL (Certificate Revocation List) support
- Let's Encrypt with HTTP-01 and DNS-01 challenges
- ACME challenges persisted to SQLite (resilient to restarts)
- Challenge cleanup after use

### Encryption at Rest
- **AES-256-GCM** for certificate private keys, DNS provider credentials, webhook auth headers
- Key file with `0o600` permissions
- Key rotation support via `lorica rotate-key` command
- Sensitive fields masked in API responses (`mask_sensitive_config()`)

### Systemd Hardening (Excellent)
- `PrivateTmp=yes`
- `NoNewPrivileges=yes`
- `ProtectSystem=strict`
- `ProtectHome=yes`
- `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` (minimum required)
- `MemoryDenyWriteExecute=yes`
- `SystemCallFilter=@system-service`
- `SystemCallArchitectures=native`
- `RestrictNamespaces=yes`
- `RestrictSUIDSGID=yes`
- `LockPersonality=yes`
- `UMask=0077`

### Frontend Security
- **Zero XSS risk**: all `{@html}` usage renders hardcoded SVG icon constants, never user data
- **No secrets in localStorage** - only UI preferences
- **No runtime dependencies** - Svelte compiles to static assets embedded in the binary
- **Credential fields are write-only** - never populated from API responses
- **WebSocket connections** properly authenticated via session cookie

### Rust Code Quality
- **No hardcoded secrets**, no `.env` files
- `unsafe` code confined to forked Pingora crates for low-level socket/fd operations (expected for a proxy)
- **No `transmute`** usage
- All external dependencies from crates.io with checksums
- All cryptographic operations use well-regarded crates (ring, argon2, rcgen, instant-acme)
- `rusqlite` uses `bundled` feature (known-good SQLite version)

---

## Recommended Action Plan (all before release)

### Quick fixes

| # | Action | Effort | Status |
|---|--------|--------|--------|
| 1 | Fix `hash_password()` to use `argon2_hasher()` | 5 min | DONE |
| 2 | Remove `\|\| true` from `cargo audit` in CI | 1 min | DONE |
| 3 | Add max password length (~128 chars) | 5 min | DONE |

### Security hardening

| # | Action | Effort | Status |
|---|--------|--------|--------|
| 4 | Invalidate sessions on password change | 30 min | DONE |
| 5 | Add CSP + security headers on dashboard | 30 min | DONE |
| 6 | Document WAF limitation (no body scanning) in security docs | 15 min | DONE |
| 7 | Add `deny.toml` for `cargo-deny` | 30 min | DONE |

### WAF and proxy improvements

| # | Action | Effort | Status |
|---|--------|--------|--------|
| 8 | WAF body scanning | 1-2 days | DONE |
| 9 | Recursive URL decoding in WAF | 2 hours | DONE |
| 10 | Per-IP login rate limiting | 1 hour | DONE |
| 11 | Chunked transfer body size enforcement | 2 hours | DONE |
| 12 | Add `#![deny(unsafe_code)]` to pure-logic crates | 1 hour | DONE |

### Additional fixes applied

| # | Action | Status |
|---|--------|--------|
| 13 | Validate DNS server parameter before passing to dig (L7) | DONE |
| 14 | Add 10 MB global request body size limit on API | DONE |

---

## Conclusion

Lorica v1.0.0 demonstrates a strong security foundation. The core architecture follows defense-in-depth principles: localhost-only admin API, Argon2id authentication, AES-256-GCM encryption at rest, comprehensive systemd hardening, and a 39-rule WAF engine. All 14 action items have been resolved. The WAF now scans request bodies (text up to 1 MB), uses recursive URL decoding, and enforces body size limits on chunked transfers.
