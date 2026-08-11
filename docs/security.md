# Lorica Security Documentation

## Threat Model

### Assets
- **TLS private keys** - stored AES-256-GCM encrypted in SQLite database
- **Admin credentials** - argon2-hashed in database, never logged in plaintext
- **Session tokens** - HttpOnly, Secure, SameSite=Strict cookies
- **Configuration data** - routes, backends, settings in embedded SQLite

### Trust Boundaries
1. **Internet -> Lorica proxy** (ports 80/443): untrusted HTTP/HTTPS traffic
2. **Lorica proxy -> Backends**: internal network, TLS optional per backend
3. **Localhost -> Management API** (port 9443): trusted admin access only
4. **Admin browser -> Dashboard**: authenticated session over HTTPS

### Threat Categories

| Threat | Mitigation | Status |
|--------|-----------|--------|
| SQL injection via API | Parameterized queries (rusqlite params!) | Implemented |
| XSS via dashboard | Svelte auto-escapes output, no innerHTML | Implemented |
| CSRF | SameSite=Strict cookies, no CORS | Implemented |
| Brute-force login | Rate limiting: 5 attempts/min, then 429 | Implemented |
| Session hijacking | HttpOnly + Secure + SameSite cookies | Implemented |
| WAF bypass | 49 OWASP-inspired rules (46 general + 3 header-scoped), per-rule toggle | Implemented |
| Secret leakage in logs | Private keys never logged, passwords hashed | Verified |
| Dependency vulnerabilities | `cargo audit` (serde_yml warning - Pingora upstream) | Monitored |
| Privilege escalation | systemd: NoNewPrivileges, ProtectSystem=strict | Implemented |
| Memory corruption | Rust memory safety, no unsafe in product code | By design |

### Known Limitations

- **WAF body scan is bounded.** The WAF engine inspects the URI path, query string, selected headers AND the first 1 MiB of the request body (path-traversal and protocol-violation rules are excluded from body scanning to limit false positives - see v1.1.0 changelog). Bodies exceeding the 1 MiB scan window are handled per the route's `waf_mode` (v1.5.2 audit H-2) : Blocking mode returns `413 Payload Too Large` ; Detection mode emits a `BodyTruncated` WAF event, increments `lorica_waf_events_total{category="protocol_violation",action="detected"}`, and lets the request through with a partial scan on the first 1 MiB. The 1 MiB cap is currently hard-coded ; an operator-tunable knob is on the v1.6.0 backlog. Backend applications remain responsible for input validation on bodies > 1 MiB.
- **serde_yml** (RUSTSEC-2025-0068): inherited from Pingora fork. Low risk - only used for Pingora internal server config parsing, not user input. Migration to serde_yaml_ng planned.
- **HTTP-01 ACME challenge** requires port 80 reachable from Internet. Not suitable for NAT/internal deployments without DNS-01 (planned).
- **HTTPS listener** requires the operator to bind port 443 at boot ; the listener itself is up before any cert is loaded. Certificate add / update / delete + ACME issuance (HTTP-01 / DNS-01 / DNS-01 manual) + ACME auto-renewal hot-reload into the running process across both single-process and multi-worker modes (v1.5.2 fix). A new cert becomes serveable as soon as at least one route's `certificate_id` references it - the resolver filters by route-reference to avoid loading orphan certs. Same window exists for cert removal. Port-level changes (`http_port` / `https_port`) still require a restart - those re-bind the TCP listener.

## Hardening Guide

### systemd (production deployment)

The provided `dist/lorica.service` includes:
- `NoNewPrivileges=yes` - prevents privilege escalation
- `ProtectSystem=strict` - read-only filesystem except data directory
- `ProtectHome=yes` - no access to home directories
- `PrivateTmp=yes` - isolated /tmp
- `MemoryDenyWriteExecute=yes` - W^X enforcement
- `SystemCallFilter=@system-service` - syscall allowlist
- `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` - only port binding capability
- `RestrictNamespaces=yes` - no namespace creation
- `UMask=0077` - restrictive file permissions

The unit also carries `Type=notify` + `NotifyAccess=all` + `KillMode=mixed`
+ `TimeoutStopSec=90` for the zero-downtime hot binary upgrade. Upgrade
uploads are gated on an operator-managed Ed25519 signature; see
[hot-upgrade.md](hot-upgrade.md) and
[installation.md](installation.md#hot-binary-upgrade).

### Network
- Management API binds to **localhost only** (127.0.0.1)
- Use socat or SSH tunnel for remote administration
- Proxy ports (80/443) are the only externally exposed services

### Access control (RBAC, v1.6.0)

Multi-user role-based access control on the management API and
dashboard (Story 8.3):

- Three roles: `super_admin` (everything, including user management,
  settings writes, config import, and binary upgrades), `operator`
  (full CRUD on the traffic plane: routes, backends, certificates,
  WAF, SLA, probes, load tests, cache, bans; read-only settings),
  `viewer` (read-only; certificate downloads and config export are
  blocked, and stored secrets are masked in every response).
- Authorization is a single fail-closed policy middleware
  (`lorica-api/src/middleware/authorize.rs`): any state-mutating
  method requires Operator minimum by default, so a future endpoint
  cannot accidentally ship Viewer-mutable.
- Sessions carry the role at login; any role change, disable, or
  admin password reset invalidates every session of the target user
  immediately (no stale-privilege window).
- Login rejects disabled accounts with the same generic message and
  post-verification timing as a wrong password (no account
  enumeration oracle).
- Password policy on set/change: minimum 14 characters plus
  upper/lower/digit/symbol classes (tunable via
  `password_min_length` / `password_require_complexity`); Argon2id
  (19 MiB, t=2) for storage.
- Migration details: [migrations/v1.6.0-rbac.md](migrations/v1.6.0-rbac.md).

### Database
- SQLite with WAL mode for crash safety
- `PRAGMA busy_timeout=5000` for concurrent worker access
- Private keys encrypted with AES-256-GCM at rest
- Database file permissions: 0600 (owner read/write only)

### Monitoring
- `/metrics` endpoint available for Prometheus (no auth, localhost only)
- Structured JSON logging via tracing for SIEM integration
- WAF events logged with alert_type and matched rule details

## Fuzz Testing

Fuzz targets are set up for:
1. **HTTP request parsing** - malformed headers, oversized requests
2. **API JSON input** - invalid JSON, extreme values, nested objects
3. **WAF rule evaluation** - crafted attack payloads

Run fuzz tests (requires nightly Rust):
```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run HTTP parser fuzz target
cargo +nightly fuzz run fuzz_http_parse -- -max_total_time=3600

# Run API input fuzz target
cargo +nightly fuzz run fuzz_api_input -- -max_total_time=3600
```

Fuzz targets are in `fuzz/` directory (not included in release builds).
