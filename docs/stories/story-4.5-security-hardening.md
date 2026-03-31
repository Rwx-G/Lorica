# Story 4.5: Security Hardening

**Epic:** [Epic 4 - Production](../prd/epic-4-production.md)
**Status:** Done
**Priority:** P2
**Depends on:** Epic 1 complete

---

As an infrastructure engineer,
I want Lorica to be hardened for production deployment,
so that the proxy itself is not a security liability.

## Acceptance Criteria

1. `cargo audit` clean - no known vulnerabilities in dependencies
2. Fuzz testing for TLS handshake, HTTP parsing, and API input handling
3. Rate limiting on management API (brute-force protection for login)
4. Session timeout and secure cookie flags for dashboard auth
5. No secrets in logs (password, cert private keys masked)
6. systemd hardening: PrivateTmp, NoNewPrivileges, ProtectSystem
7. Security documentation: threat model, hardening guide

## Integration Verification

- IV1: `cargo audit` returns no vulnerabilities
- IV2: Fuzz testing runs for minimum 1 hour without crashes
- IV3: Brute-force login attempt is rate-limited after 5 failures
- IV4: Private key material never appears in log output

## Tasks

- [x] Add cargo-audit to CI pipeline
- [x] Set up fuzz testing targets (cargo-fuzz)
- [ ] Fuzz TLS handshake path
- [x] Fuzz HTTP request parsing
- [x] Fuzz API JSON input handling
- [x] Verify rate limiting on login endpoint
- [x] Verify session timeout and cookie flags (HttpOnly, Secure, SameSite)
- [x] Audit all log statements for secret leakage
- [x] Update systemd unit file with hardening directives
- [x] Write threat model document
- [x] Write hardening guide

## Dev Notes

- Fuzz targets: TLS ClientHello parsing, HTTP request header parsing, API JSON deserialization
- Rate limiting: 5 failed login attempts per minute, then 429 for 60 seconds
- Cookie flags: HttpOnly (no JS access), Secure (HTTPS only), SameSite=Strict
- systemd hardening: PrivateTmp=yes, NoNewPrivileges=yes, ProtectSystem=strict, ProtectHome=yes
- Secret masking: implement a tracing layer that redacts known secret field names
