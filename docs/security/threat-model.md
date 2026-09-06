# Lorica Threat Model

**Author:** Romain G.
**Version:** 1.0
**Date:** 2026-03-31

## Overview

Lorica is a reverse proxy that sits between the Internet and backend services. It terminates TLS, routes HTTP traffic, provides WAF protection, and exposes a management dashboard on localhost. Since v1.7.0 a node can additionally participate in a multi-node cluster over a dedicated, mutually authenticated cluster plane. This document identifies threat categories and mitigations.

## Trust Boundaries

```
Internet  -->  [ Lorica Proxy (8080/8443) ]  -->  Backend Services
                       |
               [ Management API (9443, localhost only) ]
                       |
               [ Admin User (browser) ]

Follower nodes  -->  [ Cluster plane (--cluster-listen, opt-in) ]
   (outbound only)         operational listener: mTLS mandatory
                           enrollment listener: token-gated window
```

1. **Internet to Proxy** - Untrusted. All inbound traffic is potentially malicious.
2. **Proxy to Backends** - Semi-trusted. Backends are internal but may be compromised.
3. **Admin to Management API** - Trusted after authentication. Localhost-only binding; the management API itself never accepts remote connections. Fleet coordination does NOT ride on this plane.
4. **Database** - Trusted. SQLite on local filesystem with WAL mode.
5. **Follower to Control Plane (cluster plane)** - Authenticated by mutual TLS against the fleet's own cluster CA; no public or system CA is trusted on this plane. Disabled by default; only exists when the operator passes `--cluster-listen` on the control plane. Followers dial OUT to the control plane and expose no inbound port of their own.
6. **Enrollment listener** - The only unauthenticated network surface in the product. It is a separate listener from the operational one, is closed unless at least one join token is live, auto-closes when the last unexpired token is burned or expires, and enforces pre-authentication budgets (handshake timeout, concurrent-handshake cap, in-flight enrollment cap, per-connection byte and time budgets) before any token verification runs.

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
| SQL injection via proxy | WAF engine with 49 OWASP-inspired rules | Implemented |
| XSS via proxy | WAF detection/blocking with configurable rules | Implemented |
| Path traversal | WAF rules + URL decoding before inspection | Implemented |
| Command injection | WAF rules covering common injection patterns | Implemented |
| Request smuggling | HTTP parsing via httparse (strict mode) | Implemented |
| IP-based attacks | IPv4 blocklist with ~80k known malicious IPs (Data-Shield) | Implemented |

### T3: Management API Attacks

| Threat | Mitigation | Status |
|--------|-----------|--------|
| Unauthorized access | Session-based auth with HTTP-only cookies | Implemented |
| Brute force login | Rate limiter on /auth/login endpoint | Implemented |
| Session hijacking | Localhost-only binding (127.0.0.1); the management API accepts no remote access (fleet traffic uses the separate cluster plane) | Implemented |
| CSRF | Same-origin cookie policy, JSON-only API | Implemented |
| Weak passwords | 14-character minimum + complexity classes, forced change on first login | Implemented |
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

#### Known transitive advisories (awaiting upstream)

These RUSTSEC advisories are visible to `cargo audit` but hit only through forked Pingora crates (`lorica-tls`, `lorica-core`, etc.) that we deliberately do not modify to keep upstream resync cheap. They are tracked here so an incremental review is unambiguous:

| ID | Crate | Surface in Lorica-native code | Path |
|----|-------|-------------------------------|------|
| RUSTSEC-2025-0134 | `rustls-pemfile 2.2.0` (unmaintained) | None : direct usage swapped to `rustls-pki-types::pem_slice_iter` in the `lorica` runtime crate (v1.5.0) and the forked `lorica-tls` crate (v1.5.2 audit L-16) | Transitive via `lorica-tls` → `rustls-native-certs 0.7.x` only. Closes when `lorica-tls` bumps `rustls-native-certs` to `0.8` (which itself dropped the dep) - tracked in `docs/backlog.md` deps batch (audit L-15) |
| RUSTSEC-2026-0097 | `rand 0.8.6` (was `0.8.5`; unsound with custom logger) | **Cleared in v1.5.8**: the transitive `0.8` line was bumped `0.8.5 -> 0.8.6` via `cargo update`, so `cargo audit` no longer flags it. Native call sites had already moved to `rand 0.9` in v1.5.0 | Was transitive via `captcha`, forked `lorica-runtime`/`lorica-limits` |

`RUSTSEC-2026-0097` is resolved as of v1.5.8 (bumped to the fixed `rand 0.8.6`). `RUSTSEC-2025-0134` (`rustls-pemfile`) remains the one live transitive advisory: the forked crates inherit the upstream fix when Pingora migrates, and until then the mitigation is scope limitation (Lorica-native code does not call the affected API directly) plus the fact that it requires a condition we do not create (an unmaintained-but-functional parser on a known PEM format).

### T6: Cluster Plane (v1.7.0+)

The cluster plane is opt-in: none of these surfaces exist unless the operator starts the control plane with `--cluster-listen`. See `docs/cluster.md` for the full trust model.

| Threat | Mitigation | Status |
|--------|-----------|--------|
| Rogue node joins the fleet | Operational listener requires client certificates (rustls `WebPkiClientVerifier` without `allow_unauthenticated`); only leaves issued by the fleet's cluster CA verify | Implemented |
| Impersonation of the control plane | Follower dialer trusts the cluster CA only (no system roots); control-plane leaves are `serverAuth`-only, node leaves `clientAuth`-only, so neither can stand in for the other | Implemented |
| Abuse of the enrollment listener | Separate listener, closed unless a join token is live, auto-closes on last token burn/expiry; pre-auth budgets (handshake timeout, concurrency caps, byte/time budgets) enforced before any token work; refusals are opaque on the wire with the diagnostic logged locally | Implemented |
| Confused deputy via cluster messages | Cluster protocol is a disjoint proto package from the worker command channel; the bridge into `lorica-command` is an explicit whitelist translation with no pass-through of a peer-supplied command type; a cluster frame that decodes as a worker command drops the connection | Implemented |
| Version/build fingerprinting pre-auth | Version and schema negotiation happen after client-certificate verification on the operational path; the enrollment path returns an opaque code | Implemented |
| Reconnect stampede after control-plane restart | Convergence admission control: concurrent-session limit with a queue and `RETRY_LATER`; follower backoff with jitter whose cap scales with fleet size | Implemented |
| Cluster CA key theft | CA private key encrypted (AES-256-GCM) at rest under the node master key; covered by `lorica rotate-key`; the master-key file is the fleet's identity root (see Residual Risks) | Implemented |
| Enrollment as a resource-exhaustion primitive | Token is `<public_id>.<payload>`: one indexed lookup and one constant-time HMAC-SHA256 verification per attempt (a dummy digest when the id is unknown), no memory-hard KDF; verification runs under the listener's in-flight enrollment cap | Implemented |
| Rogue control plane harvesting a token | The token pins the SHA-256 of the control-plane LEAF public key, not the CA; the joiner also checks the SAN against the `--control-plane` host, the validity window and the `serverAuth` EKU before sending anything | Implemented |
| Privilege escalation through a CSR | No CSR: the node sends a bare public key and the control plane assigns subject, EKU (`clientAuth` only), `CA:FALSE`, serial and validity; key type allowlist (Ed25519, P-256, RSA-2048+) | Implemented |
| Token replay / concurrent redemption | The burn is one conditional `UPDATE ... WHERE state='unused' AND expires_at > now` that must affect exactly one row BEFORE any signing; a bad key or binding mismatch refuses without burning | Implemented |
| A one-hour token becoming a permanent identity | Enrollment lands `Pending`: no configuration or certificates until a SuperAdmin activates (or `--cluster-auto-activate`, logged at WARN); tokens can be bound to a node name and a source CIDR | Implemented |
| Token leakage through argv | `lorica cluster join` accepts the token only from `--token-file`, `--token-stdin` or `LORICA_JOIN_TOKEN`; the CLI and the dashboard show it apart from the command that consumes it | Implemented |
| A revoked node keeping access | Revocation puts the node's serials on a CA-signed CRL, rebuilds the operational verifier `with_crls` and arc-swaps it; the live session is ended synchronously through the session registry | Implemented |
| Node impersonation via a payload `node_id` | Identity is the certificate fingerprint recorded at enrollment; payloads carry no trusted identity; a valid certificate with no roster entry, or a revoked one, is dropped before any byte is read and audited | Implemented |
| A local shell dropping a node while keeping fleet keys | `lorica cluster leave` requires a SuperAdmin credential on the local API (the instance notifies the control plane) or proof of control-plane-side deregistration; it wipes the identity and audits on both sides | Implemented |

### T7: Operational

| Threat | Mitigation | Status |
|--------|-----------|--------|
| Proxy overload from load testing | CPU circuit breaker (90% threshold), safe limits | Implemented |
| Probe storm | max_active_probes system limit (default 50) | Implemented |
| Worker process crash | Supervisor auto-restart with exponential backoff | Implemented |
| Config corruption | TOML import with preview/diff before apply | Implemented |
| Certificate expiry | Configurable warning/critical thresholds, ACME auto-renewal | Implemented |

## Residual Risks

1. **Management API on localhost** - If an attacker gains local shell access, they can access the API. Mitigation: this is inherent to the deployment model (single-binary, self-hosted). Note that "localhost only" describes the management API specifically; a clustered control plane additionally exposes the cluster plane, whose own boundary is described in T6.
2. **WAF bypass** - Custom regex rules may have gaps. Mitigation: defense-in-depth, WAF is one layer.
3. **ACME HTTP-01 requires port 80** - NAT/firewall may block validation. Mitigation: DNS-01 challenge alternative available.
4. **Master key file as fleet identity root** - On a clustered control plane, `<data_dir>/encryption.key` (32 raw bytes, mode 0600, no KDF, no passphrase, no machine binding) encrypts the cluster CA private key. An attacker who reads that file plus the database can mint fleet identities. Mitigation: filesystem permissions, the systemd sandbox, and the firewall guidance in the hardening guide; `docs/cluster.md` states this promotion of the key file's blast radius explicitly.

## Review Schedule

This threat model should be reviewed when:
- New external-facing features are added
- New dependency categories are introduced
- A security incident occurs
