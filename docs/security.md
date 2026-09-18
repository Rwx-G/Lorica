# Lorica Security Documentation

## Threat Model

The threat model lives in [docs/security/threat-model.md](security/threat-model.md):
assets, trust boundaries, and the threat categories T1 to T8 with one
mitigation table each (network, application, management API, data at rest,
supply chain, cluster plane, operational, automation plane and request
capture), followed by the residual risks. It is one document rather than a
summary here and a copy there, because the copy that used to sit in this
section stopped being true two releases before anyone noticed.

### Known Limitations

- **WAF body scan is bounded.** The WAF engine inspects the URI path, query string, selected headers AND the first 1 MiB of the request body (path-traversal and protocol-violation rules are excluded from body scanning to limit false positives - see v1.1.0 changelog). Bodies exceeding the 1 MiB scan window are handled per the route's `waf_mode` (v1.5.2 audit H-2) : Blocking mode returns `413 Payload Too Large` ; Detection mode emits a `BodyTruncated` WAF event, increments `lorica_waf_events_total{category="protocol_violation",action="detected"}`, and lets the request through with a partial scan on the first 1 MiB. The 1 MiB cap is currently hard-coded ; an operator-tunable knob remains on the backlog. Backend applications remain responsible for input validation on bodies > 1 MiB.
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

### Tamper-evident admin audit log (v1.6.0)

Every state-mutating management-API call is recorded in a dedicated
`audit_log` table (Story 8.9):

- Each row carries `{operator_username, operator_role, action,
  target_type, target_id, before/after payload SHA-256 hashes, ip,
  user_agent}` plus a hash chain. The payloads themselves are never
  stored - only their hashes - so no secret material lands in the
  audit trail by construction.
- **Hash chain**: `chain_hash = SHA-256(prev_chain_hash ||
  length-prefixed row fields)`, genesis row anchors on 32 zero bytes.
  `GET /api/v1/audit/verify` (SuperAdmin only) walks the chain from
  genesis and returns the earliest row where recomputation diverges,
  localising any tampering (a modified field, or a deleted middle row
  breaking its successor's `prev_chain_hash`).
- `GET /api/v1/audit` (Operator+) lists entries with operator /
  action-prefix / date-range filters; the dashboard Security tab
  renders them with a chain-status column and a verify button.
- Emission is fail-open: an audit-write failure logs an error but
  never fails the underlying mutation (availability over
  auditability; the chain covers integrity, not liveness). Events are
  also emitted on the `lorica::audit` tracing target and attach to the
  request span, so OTel users can pivot from a trace to its audit
  footprint.
- **Retention** is day-based (`audit_log_retention_days`, default 90;
  `0` = keep forever) and chain-safe: before truncating, the earliest
  surviving row's `prev_chain_hash` is stored as a "retention seal" in
  `audit_log_meta`, which `verify` treats as the new genesis so the
  surviving suffix still verifies.

### Resource-exhaustion caps (v1.6.0)

Story 8.9 hardening knobs, all live-reloadable via settings:

- **Per-source-IP TCP connection cap** (`connection_limits_per_ip`,
  default off): connections beyond the cap for one source IP are
  refused at `accept()`, before the TLS handshake, so a single IP
  cannot exhaust `max_global_connections`. The cap is enforced per
  worker process (effective ceiling `value x workers` in multi-worker
  mode); refusals surface on `lorica_per_ip_connection_refused_total`.
- **Bot-challenge stash caps** (`bot_stash_max_entries` default 10000,
  `bot_stash_per_prefix_max` default 100 per /24 IPv4 or /48 IPv6):
  over-cap challenge issuance is REFUSED with `503 Retry-After: 30`
  instead of evicting legitimate pending challenges, so captcha
  flooding cannot OOM the process or displace honest users.
- **Per-route mirror concurrency** (`mirror_max_concurrent_per_route`
  default 32, `mirror_max_concurrent_global` default 4096): shadow /
  mirror sub-requests use a per-route semaphore plus a coarse global
  net, so one slow shadow target cannot starve every other route's
  mirrors.

### Request authority validation

Lorica routes, matches WAF rules, and applies per-route IP lists and
Basic-auth on one value: the request's authority. A request that
carries two of them is refused rather than resolved, because any
resolution rule the proxy picks can differ from the one the upstream
picks, and the gap between the two is a policy bypass.

Refused on HTTP/1 and HTTP/2 alike:

- more than one `Host` header field (RFC 9112 section 3.2);
- userinfo in `Host` or in the URI authority, for example
  `Host: evil.example@target.example`. `http::Uri::host` strips
  userinfo, so a check comparing raw bytes and a router parsing the
  authority disagree about which host this is;
- a `Host` that differs from the URI authority (`:authority` on
  HTTP/2). This is stricter than RFC 9112 section 3.2.2, which says to
  replace the conflicting `Host`.

HTTP/2 additionally answers 400 to a stream that carries neither
`:authority` nor `Host`, and keeps its per-connection budget for
malformed streams: a client that sends enough of them has the
connection torn down rather than the rejections running unbounded.

An absolute-form request target (`GET http://host/path HTTP/1.1`) is
refused earlier still, when the request header is parsed, so it never
reaches routing. Legitimate clients do not send one to a reverse proxy.

### WAF body inspection (v1.7.2, v1.8.0)

The WAF buffers a request body only when it can parse it, and the
decision is taken on the declared `Content-Type` before the first
chunk is buffered.

**What is inspected.** `application/json`,
`application/x-www-form-urlencoded`, `application/xml`, `text/xml`,
every `text/` subtype, and the RFC 6839 structured suffixes `+json`
and `+xml` (so `application/activity+json` and
`application/atom+xml`). The media type is read up to the first `;`,
so `charset` parameters do not matter, and the comparison is
case-insensitive. Everything else, **an absent or malformed
`Content-Type` included**, is not inspected.

**Why the list is that list.** The engine scans text. A body that
does not decode as UTF-8 returns a Pass on the first byte, so every
byte buffered for a binary upload was wasted work, and on a
WAF-Blocking route the `413` that followed was a rejection with no
rule behind it. That is the choice this removes: a route serving
Nextcloud, ownCloud, Seafile, WebDAV or any S3-style upload endpoint
no longer has to pick between "WAF on the route" and "uploads work".

**`multipart/form-data` is not inspected.** Lorica has no multipart
parser, so scanning it would mean running SQL and XSS signatures over
the raw envelope, base64 and binary part payloads included: high
false-positive, low value. A parser with a separate limit for the
non-file parts (the ModSecurity `SecRequestBodyNoFilesLimit` model)
is tracked in `docs/backlog.md`.

**How much of an inspected body is read (v1.8.0).** Two caps, and they
answer different questions.

| Setting | Scope | Default | Range | Answers |
|---|---|---|---|---|
| `max_request_body_bytes` | per route | unset | | what the proxy accepts at all |
| `waf_body_scan_max_bytes` | per route | 1 MiB | 4 KiB to 64 MiB | how much of an accepted, inspectable body the WAF reads |
| `waf_body_scan_max_inflight_bytes` | global | 256 MiB | 1 MiB to 16 GiB | how much the node holds in scan buffers at once |

A body the `Content-Type` rules above exclude is never buffered, so
none of the three applies to it: the only ceiling a binary upload meets
is the route's `max_request_body_bytes`. Raising
`waf_body_scan_max_bytes` widens the window for the bodies that are
actually inspected, which is what a JSON API legitimately posting 5 MB
documents needs, and it costs that value times the concurrent inspected
requests on that route. The oversize behaviour past the window does not
change: Blocking answers `413`, Detection emits one truncation event and
scans what it has. The padding bypass closed by the v1.5.1 audit stays
closed, because a megabyte of inert text in front of a payload still
reaches the window.

**The global budget fails OPEN, deliberately.** When a request would
push the node past `waf_body_scan_max_inflight_bytes`, its body is not
buffered, not scanned, and the request is **allowed through** in both
Blocking and Detection mode, with one WAF event
(`protocol_violation` / `skipped`) and
`lorica_waf_body_scans_total{outcome="skipped_budget"}`.

Failing closed was the other option and it is worse. The budget is
shared by every route on the node, so any client able to fill it would
be able to turn it into a `413` for everyone else: a denial of service
handed out by the control that exists to prevent one. A scan gap that
increments a counter is a gap you can alarm on; a fleet-wide `413`
storm is an outage. Alarm on that series, and on
`lorica_waf_body_scan_inflight_bytes` sitting near the ceiling.

Under `--workers N` the budget is per worker, like every other
process-wide byte ceiling in Lorica, so the node's real worst case is
`N` times the setting. Size the host accordingly.

**A worked example, the case this exists for.** A Nextcloud route:
uploads flow untouched while the WAF stays armed on everything the
engine can actually read.

```jsonc
{
  "waf_enabled": true,
  "waf_mode": "blocking",
  // Multi-gigabyte uploads are accepted...
  "max_request_body_bytes": 2147483648,
  // ...and never buffered: application/octet-stream is not inspectable,
  // so this window applies only to the JSON and form traffic on the
  // same route, where 1 MiB is plenty.
  "waf_body_scan_max_bytes": 1048576
}
```

A `PUT` of a 100 MB file with `Content-Type: application/octet-stream`
reaches the upstream byte for byte,
`lorica_waf_body_scan_inflight_bytes` never leaves zero, and
`lorica_waf_body_scans_total{outcome="skipped_content_type"}`
increments. A `POST` of a JSON body carrying a SQL injection payload on
the same route is still answered `403`.

**The residual risk, stated plainly.** A client that declares
`application/octet-stream` skips inspection, whatever the bytes
actually are. The mitigating argument is that the upstream will also
treat the body as an opaque blob, so a SQL payload declared as a
binary blob reaches an application that was never going to parse it
as SQL. **The argument does not hold for an application that ignores
the declared type and sniffs the body instead.** If that describes
your upstream, the WAF is not the control to rely on for its request
bodies: the application's own input handling is.

A second gap of the same family: a `Content-Encoding: gzip` body is
not valid UTF-8, so it was already passing uninspected before this
change. Decompressing before inspection needs a decompression-bomb
budget of its own and is backlog, not shipped.

**The caps and how they interact.** Two ceilings apply to a request
body, and only one of them moved:

| Cap | Scope | Applies to | Over the cap |
|-----|-------|-----------|--------------|
| `max_request_body_bytes` | per route, operator-set | every body | `413`, always |
| WAF scan window (1 MiB, compiled in) | per route, fixed | inspectable bodies only | `413` in Blocking, `BodyTruncated` event plus a partial scan in Detection |

So an inspectable body is bounded by both, and a non-inspectable body
by `max_request_body_bytes` alone. Set it: with the WAF no longer
bounding large uploads, it is the only thing standing between a route
and an unbounded `PUT`.

The v1.5.1 audit H-2 padding bypass stays closed. An attacker who
prefixes a megabyte of inert text to a JSON payload is sending a body
that IS inspectable, so the scan window still applies and a Blocking
route still answers `413`.

**A Nextcloud route.**

```
max_request_body_bytes = 17179869184   # 16 GiB, your largest upload
waf_enabled            = true
waf_mode               = blocking
```

`PUT /remote.php/dav/files/user01/big.iso` with
`Content-Type: application/octet-stream` now streams through
untouched. The JSON and form endpoints on the same host keep full
WAF coverage, because those bodies are inspectable and under the scan
window.

### Database
- SQLite with WAL mode for crash safety
- `PRAGMA busy_timeout=5000` for concurrent worker access
- Private keys encrypted with AES-256-GCM at rest
- Database file permissions: 0600 (owner read/write only)

### Monitoring
- `/metrics` endpoint available for Prometheus (localhost only; optional auth, see "Management plane authentication")
- Structured JSON logging via tracing for SIEM integration
- WAF events logged with alert_type and matched rule details

### Management plane authentication (v1.6.0)

The management API (default port 9443) binds to loopback only and is
served over TLS. Three controls harden it.

**TLS listener.** The management API terminates TLS. A self-signed
certificate is generated on first boot (SANs `localhost`, the machine
hostname, `127.0.0.1`, `::1`; ~1 year validity), persisted under
`<data-dir>/management/` (directory `0700`, private key `0600`), and
regenerated automatically once it is within 30 days of expiry. Serving
the management plane over TLS lets the `Secure`-flagged session cookie
round-trip through a fronting reverse proxy instead of being silently
dropped. Operators who terminate TLS at Lorica with their own
certificate set `management_cert_pem_path` + `management_key_pem_path`;
when both point at readable files the self-signed material is ignored.
Clients reach the API over `https://`; the bundled `lorica` CLI uses
`https://127.0.0.1` and accepts the self-signed certificate, since the
target is always loopback (no MITM surface to defend).

**`/metrics` authentication (on by default since v1.7.0).** The
endpoint exposes the full backend topology and certificate inventory,
which on a shared or multi-tenant host any local user could otherwise
read. Since v1.7.0 the global setting `metrics_require_auth` defaults
to `true` and every scrape must present ONE of:

- a valid dashboard session cookie sent explicitly by an API client
  (`curl -H "Cookie: lorica_session=..."`); the cookie is scoped to
  `Path=/api`, so a browser does not send it to `/metrics`. An operator
  who wants the document in a browser reads the same text at
  `GET /api/v1/metrics`, behind the ordinary session gate, or
- a static bearer token supplied as `Authorization: Bearer <token>`.

The token is configured via the `prometheus_scrape_token` setting or,
preferably, injected out of band through the environment variable
`LORICA_PROMETHEUS_SCRAPE_TOKEN` (the env value overrides the stored
one). The token is compared in constant time so a failed attempt does
not leak how many leading bytes matched. A rejected scrape returns
`401` with `WWW-Authenticate: Bearer realm="lorica-metrics"`. The
token is masked (`**REDACTED**`) in `GET /api/v1/settings` responses
and is never written to the reload diff.

> Migration note (v1.6.0 to v1.7.0): v1.6.0 shipped this setting off
> for back-compat. An install that never changed it has no stored
> value, so it takes the new default on upgrade and its unauthenticated
> scrapes answer `401` from the first boot on v1.7.0. Before upgrading,
> either configure `prometheus_scrape_token` (or set
> `LORICA_PROMETHEUS_SCRAPE_TOKEN` in the unit's environment) and add
> the `Authorization: Bearer` header to the scrape job, or set
> `metrics_require_auth = false` explicitly to keep the v1.6.0
> behaviour. An install that had already set the value either way is
> unaffected: a stored value always wins over the default.

**Dashboard CSP.** The dashboard document carries a strict CSP3 policy
(built in `lorica-dashboard/src/csp.rs`): `default-src 'self'`,
`script-src 'self'`, `frame-ancestors 'none'`, `form-action 'self'`,
`base-uri 'none'`, `object-src 'none'`, and a `connect-src` scoped to
the loopback WebSocket origins. `style-src` drops `'unsafe-inline'` in
favour of a per-request 128-bit nonce, regenerated on every document
load and injected into both the `Content-Security-Policy` header and the
served HTML, so an injected inline `<style>` block is blocked. A
companion `style-src-attr 'unsafe-inline'` keeps Svelte's runtime inline
`style=` attributes working, which a `style-src` nonce cannot authorize.

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
