# Fork Information

Lorica is a fork of [Cloudflare Pingora](https://github.com/cloudflare/pingora), modified to serve as a dashboard-first reverse proxy product.

## Origin

| Field | Value |
|-------|-------|
| Upstream repository | <https://github.com/cloudflare/pingora> |
| Upstream license | Apache-2.0 |
| Fork date | 2026-03-29 |
| Upstream version at fork | `0.8.0` baseline (upstream `main` as of the fork date: after the `0.8.0` release of 2026-03-02, before `0.8.1`) |
| Git remote | `upstream` - `https://github.com/cloudflare/pingora.git` |

## Renaming Rules

All crate names and Rust module paths were renamed:

| Upstream name | Lorica name | Notes |
|---------------|-------------|-------|
| `pingora-core` | `lorica-core` | Core server framework |
| `pingora-proxy` | `lorica-proxy` | HTTP proxy engine |
| `pingora-http` | `lorica-http` | HTTP utilities |
| `pingora-error` | `lorica-error` | Error types |
| `pingora-pool` | `lorica-pool` | Connection pool |
| `pingora-timeout` | `lorica-timeout` | Timeout utilities |
| `pingora-header-serde` | `lorica-header-serde` | Header serialization |
| `pingora-runtime` | `lorica-runtime` | Tokio runtime wrapper |
| `pingora-ketama` | `lorica-ketama` | Consistent hashing |
| `pingora-limits` | `lorica-limits` | Rate estimator |
| `pingora-load-balancing` | `lorica-lb` | Load balancing strategies |
| `pingora-cache` | `lorica-cache` | HTTP response cache |
| `pingora-memory-cache` | `lorica-memory-cache` | In-memory cache backend |
| `pingora-lru` | `lorica-lru` | LRU eviction |
| `tinyufo` | `tinyufo` | TinyUFO cache algorithm (unchanged) |

**Rust imports**: all `use pingora_*` became `use lorica_*`.

## Removed Components

The following upstream crates and features were **deleted** during the fork:

| Removed | Reason |
|---------|--------|
| `pingora-openssl` | Lorica uses rustls exclusively |
| `pingora-boringssl` | Lorica uses rustls exclusively |
| `pingora-s2n` | Lorica uses rustls exclusively |
| Conditional TLS compilation (`#[cfg]` blocks) | Only rustls remains |
| Sentry integration | Cloudflare-specific observability |
| `cf-rustracing` | Cloudflare-specific tracing |
| Example binaries | Replaced by Lorica's own binary |
| Windows support (787 lines) | Linux-only project |

## Added Crates (Lorica-specific)

These crates do not exist in upstream Pingora:

| Crate | Purpose |
|-------|---------|
| `lorica` | CLI binary, supervisor, worker orchestration |
| `lorica-api` | axum REST API, auth, session management, RBAC |
| `lorica-config` | SQLite store, versioned migrations, TOML export/import |
| `lorica-dashboard` | Svelte 5 frontend embedded via rust-embed |
| `lorica-waf` | WAF engine, OWASP rules, IP blocklist |
| `lorica-notify` | Alert dispatch (stdout, SMTP, webhook, Slack) |
| `lorica-bench` | SLA monitoring, load testing engine |
| `lorica-worker` | fork+exec worker isolation, socket passing |
| `lorica-command` | Protobuf supervisor-worker command channel |
| `lorica-acme` | Pure ACME core: HTTP-01 / DNS-01 issuance driver, DNS challengers (Cloudflare / Route53 / OVH) |
| `lorica-metrics` | Shared Prometheus registry + cross-worker counter aggregation |
| `lorica-challenge` | Bot-protection challenge engine (PoW / captcha / cookie) |
| `lorica-geoip` | GeoIP / ASN country and network lookups |
| `lorica-shmem` | Anonymous `memfd` shared region for per-IP WAF flood / auto-ban counters |
| `lorica-cluster` | Multi-node fleet: enrollment, the mutually authenticated cluster plane, configuration and certificate replication, telemetry fan-in |
| `lorica-mcp` | Management MCP server: a scope-gated tool surface over the automation plane, spoken over stdio or over a path on the automation listener |
| `lorica-automation-policy` | The automation plane's policy as data: scope vocabulary, MCP tier table, admin settings allowlist, one-way protections |
| `lorica-tls` | SNI resolver, hot-swap, encrypted key storage (extends upstream TLS) |

## Comparing with Upstream

To compare Lorica's forked crates against upstream Pingora:

```bash
# Fetch upstream changes
git fetch upstream

# Compare a specific forked crate (account for renaming)
# Example: compare lorica-core against pingora-core
diff <(git show upstream/main:pingora-core/src/server.rs) lorica-core/src/server.rs

# List files changed in a forked crate
diff -rq <(git archive upstream/main pingora-proxy/src | tar -tf -) \
     <(ls lorica-proxy/src/)
```

### Name mapping for diffs

When comparing files across repositories, apply these substitutions:

- Directory: `pingora-{name}` - `lorica-{name}` (except `pingora-load-balancing` - `lorica-lb`)
- Cargo.toml package names: `pingora-{name}` - `lorica-{name}`
- Rust imports: `pingora_{name}` - `lorica_{name}`
- Feature flags: `pingora_` prefix - `lorica_` prefix (where applicable)

### What to check on upstream updates

1. **Security patches** in `pingora-core`, `pingora-proxy`, `pingora-http` - apply to corresponding `lorica-*` crates
2. **Performance improvements** in connection pool, load balancing, cache
3. **New TLS features** in `pingora-rustls` (Lorica's TLS is based on this)
4. **Breaking API changes** that affect `lorica-proxy` integration points

## Lorica divergences in forked crates

Behaviour changes Lorica made inside a forked crate, beyond the renaming.
Each is marked `Lorica:` in a comment at its site. Re-apply every one
after any upstream sync that touches the function it lives in.

- **`lorica-proxy`, the initial body send of the upstream leg (v1.9.0).**
  Sites: `proxy_h1.rs` `proxy_handle_downstream`, `proxy_h2.rs`
  `bidirection_down_to_up`, `proxy_custom.rs`
  `custom_bidirection_down_to_up`. Upstream runs the initial body send
  only for a retry buffer (and, on HTTP/1, an empty body). Lorica also
  runs it when the downstream body was already read in full before the
  upstream leg (`downstream_state.is_done()`), except an empty body on
  HTTP/2 and the custom protocol, whose stream was already ended with
  the request header. Without it, a body a request filter consumed never
  gets an end-of-body `request_body_filter` call and the upstream
  request hangs. The WAF's Blocking-mode body hold (`WafBodyHold` in
  `lorica/src/proxy_wiring.rs`) hands the held body over through that
  call.
- **`lorica-core` and `lorica-proxy`, the downstream idle timeout
  (v1.9.0, backlog #82).** Sites: `lorica-core/src/apps/mod.rs`
  (`HttpServerApp::downstream_idle_timeout`, a new defaulted method,
  read in `ServerApp::process_new` for the HTTP/2 accept loop, the
  wait before the first HTTP/1.x request and every HTTP/1.x keepalive
  reuse), `lorica-proxy/src/proxy_trait.rs`
  (`ProxyHttp::downstream_idle_timeout`, defaulted to `None`) and
  `lorica-proxy/src/lib.rs` (`HttpProxy` forwards it). Upstream waits
  without bound between HTTP/1.1 requests (`read_request` resets
  keepalive to `Some(0)` on every request) unless the application sets
  a bound per request, waits a fixed 60 s for the first one, and reads
  the HTTP/2 idle timeout from the static `HttpServerOptions`. The new
  method is asked per connection and per reuse, so Lorica's
  `downstream_idle_timeout_s` setting applies on reload; with `None`
  every site behaves as upstream does. Two more sites carry the same
  bound on HTTP/2. `ServerApp::process_new` applies it to
  `server::handshake`, which completes only once the client has sent its
  connection preface: upstream waits for it without bound, so a client
  that went silent after TLS held the connection before the accept
  loop's idle timeout could start. And
  `lorica-core/src/protocols/http/v2/server.rs`
  (`accept_downstream_sessions`, `wait_for_idle_timeout`) keeps one idle
  deadline per idle period, cleared only by an accepted session: upstream
  restarts the idle sleep on every loop iteration, so each stream
  rejected during acceptance (ambiguous `Content-Length`, conflicting
  authority) started the period over, up to the malformed-stream budget.
- **`lorica-core`, the HTTP/2 request body read timeout (v1.9.0).**
  Sites: `lorica-core/src/protocols/http/v2/server.rs`
  (`HttpSession::read_body_bytes`, where upstream leaves
  `// TODO: timeout`, and the new `set_read_timeout` /
  `get_read_timeout`) and `lorica-core/src/protocols/http/server.rs`
  (`ServerSession::set_read_timeout` and `get_read_timeout`, which
  upstream makes a no-op for HTTP/2). Upstream bounds an HTTP/1.x body
  read by the session's read timeout (60 s by default) and an HTTP/2 one
  by nothing. Lorica's HTTP/2 session takes the same per-read timeout,
  reset on every read, failing with `ReadTimedout` past it. The default
  stays `None`, as upstream, so only a caller that sets it is affected;
  Lorica sets none globally, since a gRPC client stream may pause
  between messages for as long as it likes, and its WAF body hold bounds
  its own reads (`hold_body_until_verdict` in
  `lorica/src/proxy_wiring.rs`).
- **`lorica-core` and `lorica-proxy`, the request-header timeout
  (v1.9.0, slowloris).** Sites: `lorica-core/src/protocols/http/v1/server.rs`
  (`HttpSession::read_request` bounds the whole header from its first
  byte when `set_header_timeout` was given a value, and records
  `header_read_duration`), `lorica-core/src/protocols/http/server.rs`
  (the `ServerSession` forwarders, HTTP/1.x only),
  `lorica-core/src/apps/mod.rs` (`HttpServerApp::downstream_header_timeout`,
  a new defaulted method, applied to the first HTTP/1.x session and to
  every keepalive reuse in `ServerApp::process_new`),
  `lorica-proxy/src/proxy_trait.rs` (`ProxyHttp::downstream_header_timeout`,
  defaulted to `None`) and `lorica-proxy/src/lib.rs` (`HttpProxy` forwards
  it, and `handle_new_request` answers a `ReadTimedout` header read with
  `408` where upstream closes without a response). Upstream bounds each
  read of the header separately (keepalive or read timeout), so a client
  sending one byte per gap holds the read indefinitely, and offers no
  measure of how long the header took. Lorica's `header_timeout_s` is
  read per request from the live snapshot; with `None` the read loop
  behaves as upstream does. The `408` also covers upstream's own read
  timeout on a header (`KeepaliveStatus::Off`), which RFC 9110 15.5.9
  describes as well as the new bound.

## Upstream sync record

Each release cycle that pulls upstream commits into the forked crates is
recorded here, most recent first. Commit ids are upstream `main` ids
(`git fetch upstream`). `docs/backlog.md` #81 carries the reasoning per
commit; the `[1.7.0]` CHANGELOG entries describe the user-visible effect.

| Cycle | Upstream range | Ported | Not ported (deliberate) |
|-------|----------------|--------|-------------------------|
| 1.7.0 (2026-09-09) | fork baseline to `09696b51` (2026-08-25) | `aece9932`, `6e2158d5` (re-implemented on the `RwLock` pool), `d5ade3a2`, `e21646be`, `f486cd84`, `b8aacad8`, `28c18e6b` + `ca23f166` (source, not the integration tests), `ff6693b7`, `d248583f` (source), `0c081493`, `7166d81e`, `6dcc236a`, `5bec4059`, `915590a9`, `3e657e2f` + `3dd51643` | proxy task API family `d7728cac`, `5a822047`, `8683056e`, `7142ad46`, `9c16af9c`, `17325ff4`, `b90d4203` and the six April feature commits it sits on (backlog #83); feature commits `21140569`, `4a9a34c5`, `600c5c0d`, `402acae5` |
| 1.5.8 (2026-06-05) | `0.8.1` | bounded HTTP/2 server limits (`default_h2_options`) | - |

How a commit is ported: `git format-patch -1 <sha>`, rename the paths and
identifiers per the mapping above, then `git -c rerere.enabled=false apply
--3way`. A hunk that does not apply is ported by hand; the fork's
`Box<HttpSession>` in `H2Accept::Session` and its `RwLock<HashMap>`
connection pool are the two places upstream has since diverged. Never
stage a file that still carries conflict markers: rerere would record the
broken state as a resolution.

## Attribution

See [NOTICE](NOTICE) for full attribution. Lorica is licensed under Apache-2.0, same as upstream Pingora.
