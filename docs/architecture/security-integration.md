# Security Integration

## Existing Security Measures (Pingora)

**Authentication:** None (framework, no user-facing auth)
**Authorization:** None
**Data Protection:** TLS termination via rustls. Connection pooling prevents upstream credential leakage.
**Security Tools:** None built-in. Relies on consumer implementation.

## Enhancement Security Requirements

**New Security Measures:**
- Admin authentication with argon2 password hashing
- Session-based auth with HTTP-only secure cookies
- Rate limiting on login endpoint (brute-force protection)
- Management port bound to localhost only (non-configurable)
- Private key material encrypted at rest in SQLite
- WAF engine for request inspection (Phase 2+)
- Structured security event logging for SIEM integration

**Integration Points:**
- Auth middleware in axum tower stack
- WAF evaluation in `ProxyHttp::request_filter()` phase
- Notification system for security events

**Compliance Requirements:**
- No secrets in logs (private keys, passwords masked)
- No secrets in TOML export (private keys exported separately or encrypted)
- Dependency auditing via `cargo audit` in CI

## Security Testing

**Existing Security Tests:** None in Pingora (framework responsibility delegated to consumer)
**New Security Test Requirements:**
- Auth bypass attempts (invalid sessions, expired cookies, missing tokens)
- SQL injection on API endpoints (parameterized queries should prevent)
- Path traversal on dashboard asset serving
- TLS configuration validation (no weak ciphers, no TLS < 1.2)
- Rate limiting verification under concurrent login attempts
**Penetration Testing:** Manual security review before first production deployment. Fuzz testing for TLS handshake and HTTP parsing paths.
