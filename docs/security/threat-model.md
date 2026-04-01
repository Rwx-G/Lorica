# Lorica Threat Model

**Author:** Romain G.
**Version:** 1.0
**Date:** 2026-03-31

## Overview

Lorica is a reverse proxy that sits between the Internet and backend services. It terminates TLS, routes HTTP traffic, provides WAF protection, and exposes a management dashboard on localhost. This document identifies threat categories and mitigations.

## Trust Boundaries

```
Internet  -->  [ Lorica Proxy (8080/8443) ]  -->  Backend Services
                       |
               [ Management API (9443, localhost only) ]
                       |
               [ Admin User (browser) ]
```

1. **Internet to Proxy** - Untrusted. All inbound traffic is potentially malicious.
2. **Proxy to Backends** - Semi-trusted. Backends are internal but may be compromised.
3. **Admin to Management API** - Trusted after authentication. Localhost-only binding.
4. **Database** - Trusted. SQLite on local filesystem with WAL mode.

## Threat Categories

### T1: Network-Level Attacks

| Threat | Mitigation | Status |
|--------|-----------|--------|
| DDoS on proxy ports | Rate limiting at OS level, connection limits | Partial - OS-level |
| TLS downgrade | rustls with TLS 1.2+ minimum, no OpenSSL | Implemented |
| Certificate impersonation | SNI-based cert resolver, certs stored encrypted at rest | Implemented |
| Man-in-the-middle | TLS termination with strong cipher suites via rustls | Implemented |

### T2: Application-Level Attacks

| Threat | Mitigation | Status |
|--------|-----------|--------|
| SQL injection via proxy | WAF engine with 18 OWASP-inspired rules | Implemented |
| XSS via proxy | WAF detection/blocking with configurable rules | Implemented |
| Path traversal | WAF rules + URL decoding before inspection | Implemented |
| Command injection | WAF rules covering common injection patterns | Implemented |
| Request smuggling | HTTP parsing via httparse (strict mode) | Implemented |
| IP-based attacks | IPv4 blocklist with 800k+ known malicious IPs | Implemented |

### T3: Management API Attacks

| Threat | Mitigation | Status |
|--------|-----------|--------|
| Unauthorized access | Session-based auth with HTTP-only cookies | Implemented |
| Brute force login | Rate limiter on /auth/login endpoint | Implemented |
| Session hijacking | Localhost-only binding (127.0.0.1), no remote access | Implemented |
| CSRF | Same-origin cookie policy, JSON-only API | Implemented |
| Weak passwords | 12-character minimum, forced change on first login | Implemented |
| API abuse | All mutations require authenticated session | Implemented |

### T4: Data at Rest

| Threat | Mitigation | Status |
|--------|-----------|--------|
| Certificate key theft | AES-256-GCM encryption for private keys in SQLite | Implemented |
| Database tampering | WAL mode, file permissions (0600 on key files) | Implemented |
| Config exfiltration | Export requires auth, TOML export sanitizes keys | Implemented |
| Log data leakage | In-memory ring buffer (10k entries), no disk persistence | Implemented |

### T5: Supply Chain

| Threat | Mitigation | Status |
|--------|-----------|--------|
| Dependency vulnerabilities | `cargo-audit` in CI pipeline | Implemented |
| Malicious crate injection | Cargo.lock pinned, reproducible builds | Implemented |
| Binary tampering | GPG package signing | Implemented |

### T6: Operational

| Threat | Mitigation | Status |
|--------|-----------|--------|
| Proxy overload from load testing | CPU circuit breaker (90% threshold), safe limits | Implemented |
| Probe storm | max_active_probes system limit (default 50) | Implemented |
| Worker process crash | Supervisor auto-restart with exponential backoff | Implemented |
| Config corruption | TOML import with preview/diff before apply | Implemented |
| Certificate expiry | Configurable warning/critical thresholds, ACME auto-renewal | Implemented |

## Residual Risks

1. **Management API on localhost** - If an attacker gains local shell access, they can access the API. Mitigation: this is inherent to the deployment model (single-binary, self-hosted).
2. **WAF bypass** - Custom regex rules may have gaps. Mitigation: defense-in-depth, WAF is one layer.
3. **ACME HTTP-01 requires port 80** - NAT/firewall may block validation. Mitigation: DNS-01 challenge alternative available.

## Review Schedule

This threat model should be reviewed when:
- New external-facing features are added
- New dependency categories are introduced
- A security incident occurs
