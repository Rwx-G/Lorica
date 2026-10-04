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

## Planes and controls added after the v1.0 blueprint

The management port stays loopback-only. The surfaces below are the ones a later release added beside it; `docs/security/threat-model.md` carries their actors and threats, `docs/security/hardening-guide.md` their operator guidance.

- **Automation plane (v1.8.0, opt-in).** A second HTTPS listener, `--automation-listen`, with a mandatory source-CIDR allowlist enforced at TCP accept, bearer-token authentication only (a minted token stored as an HMAC, or a GitLab OIDC ID token), a fail-closed per-path scope gate and an audit row for every request. Tokens are minted on the management plane only, so no token can mint a successor. Reference: `docs/automation.md`.
- **Automation read, write and admin surfaces (v1.9.0).** Read paths behind seven read scopes, route, backend and certificate writes behind three write scopes, and `PUT /automation/v1/settings` behind `settings:write`. Each runs the management handler with the token as the actor; the plane adds authorization only: the token's hostname and CIDR grants checked on what a write claims and on the row it targets, route fields no token may set, route and backend protections a token may only strengthen, and a nine-key settings allowlist with a bound and a safe direction per key. The rules are data in `lorica-automation-policy`.
- **Management MCP server (v1.9.0).** `lorica-mcp` is a client of the automation plane, never of the management API. A server is one tier (read, config or admin), resolved from its token's scopes; a token spanning two tiers starts no server over stdio and is refused with 403 on the Streamable HTTP path, `POST /automation/v1/mcp`, which sits behind everything the automation listener enforces. Attacker-written text reaches the model inside a fence marked as data, the audit row separates what the node established from what the caller asserted, and credentials and a short list of withheld values never cross. Reference: `docs/mcp.md`.
- **WAF body hold (v1.9.0).** In Blocking mode, `request_filter` reads and scans an inspectable request body in full, bounded by the route's scan window and the node-wide scan budget, before the upstream is dialled; a refused body reaches no backend and no mirror. Detection mode and bodies the WAF does not inspect still stream, and a body the scan budget refuses mid-read is forwarded unscanned past that point (fail-open by design).
- **Management CLI pin (v1.9.0).** Every CLI command that logs in pins the exact certificate the management listener records as served (`<data-dir>/management/served-cert.pem`) before the password is sent, so a local process holding the unprivileged loopback port during a restart cannot receive it. A failed management bind is fatal in both run modes.

## Security Testing

**Existing Security Tests:** None in Pingora (framework responsibility delegated to consumer)
**New Security Test Requirements:**
- Auth bypass attempts (invalid sessions, expired cookies, missing tokens)
- SQL injection on API endpoints (parameterized queries should prevent)
- Path traversal on dashboard asset serving
- TLS configuration validation (no weak ciphers, no TLS < 1.2)
- Rate limiting verification under concurrent login attempts
**Penetration Testing:** Manual security review before first production deployment. Fuzz testing for TLS handshake and HTTP parsing paths.
