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
| `pingora-rustls` | `lorica-tls` | rustls integration, plus Lorica-owned modules (below) |
| `tinyufo` | `tinyufo` | TinyUFO cache algorithm (unchanged) |

**Rust imports**: all `use pingora_*` became `use lorica_*`.

**`lorica-tls` is half upstream.** A source file whose header carries
Cloudflare's copyright tracks `pingora-rustls` and is diffed against it
on a sync; one that carries Lorica's has no upstream counterpart and is
not (the SNI certificate resolver and its hot swap, OCSP stapling, the
inlined `no_debug`, and `http_client`, the TLS policy of every outbound
`reqwest` client). `grep -l Cloudflare lorica-tls/src/*.rs` lists the
first kind.

## Removed Components

The following upstream crates and features were **deleted** during the fork:

| Removed | Reason |
|---------|--------|
| `pingora-openssl` | Lorica uses rustls exclusively |
| `pingora-boringssl` | Lorica uses rustls exclusively |
| `pingora-s2n` | Lorica uses rustls exclusively |
| The OpenSSL/BoringSSL and s2n backends of `lorica-core` (the `boringssl_openssl` and `s2n` modules under `connectors/tls`, `listeners/tls`, `protocols/tls` and `utils/tls`) | Lorica uses rustls exclusively. Until v1.10.2 their sources stayed on disk, declared by no `mod` and never compiled; they are deleted now |
| The `openssl`, `boringssl`, `s2n` and `openssl_derived` features and the `#[cfg]` branches on them | Only rustls remains. The `rustls` feature (which implies `any_tls`) still chooses between rustls and the no-TLS stub in `protocols/tls/noop_tls` |
| Sentry integration | Cloudflare-specific observability |
| `cf-rustracing` | Cloudflare-specific tracing |
| Example binaries, except the `lorica-core` ones that build on rustls | Replaced by Lorica's own binary. The OpenSSL-only `client_cert` example of `lorica-core` and its keys went with the backends in v1.10.2 |
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
| `lorica-adcs` | AD CS enrollment client: CSR to issued certificate through CES, WS-Trust over HTTPS with Kerberos SPNEGO bound to the TLS channel |

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

- Directory: `pingora-{name}` - `lorica-{name}` (except `pingora-load-balancing` - `lorica-lb` and `pingora-rustls` - `lorica-tls`)
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
Each is marked `Lorica:` in a comment at its site, except an upstream
test the fork skips, whose `#[ignore = "..."]` reason is the marker.
Re-apply every one after any upstream sync that touches the function it
lives in.

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
- **`lorica-core`, two HTTP/2 server tests rewritten for h2 0.4.20
  (v1.10.0, tests only).** Sites:
  `lorica-core/src/protocols/http/v2/server.rs`,
  `test_req_conflicting_content_length_rejected` (same name upstream) and
  `test_req_malformed_stream_budget_exhausted`. h2 0.4.20 resets a request
  carrying conflicting `Content-Length` values in its own codec, before
  `accept` yields it, so `validate_content_length_without_transfer_encoding`
  never sees it and the stream never counts against
  `MAX_MALFORMED_STREAMS_PER_CONN`. Upstream's version expects
  `H2Accept::Rejected` from the acceptance check; Lorica's accepts either
  layer and asserts the property instead: the request never surfaces as a
  session, the client sees `PROTOCOL_ERROR`, and a client repeating it gets
  the connection torn down after a bounded number of streams (h2's own
  limit on locally reset streams, `max_local_error_reset_streams`, left at
  h2's default by `default_h2_options`). The malformed-stream
  budget stays exercised by `test_authority_mismatch_exhausts_malformed_stream_budget`.
  Take upstream's version of these two tests only once upstream runs on
  h2 0.4.20 or later.
- **`lorica-core`, one HTTP/2 server test skipped since h2 0.4.16 (tests
  only).** Site: `lorica-core/src/protocols/http/v2/server.rs`,
  `test_req_header_no_eos_empty_data_with_eos`, under
  `#[ignore = "h2 >= 0.4.16 (RUSTSEC-2026-0258 fix): ..."]`. Its client
  drops the stream right after the trailing empty DATA frame, and since
  the RUSTSEC-2026-0258 fix the resulting `RST_STREAM(CANCEL)` overtakes
  that frame, so the server sees a reset rather than the end of the body:
  the test racing itself, not a server defect. Kept as upstream wrote it
  so the file stays rebaseable; drop the `ignore` once upstream reworks
  the test.
- **`lorica-tls`, the platform trust store load on `rustls-native-certs`
  0.8 (v1.10.2, RUSTSEC-2025-0134).** Site: `lorica-tls/src/lib.rs`
  (`load_platform_certs_incl_env_into_store` and the crate-private
  `add_native_certs_into_store` it calls, which the Lorica module
  `http_client::public_roots` calls too, so outbound HTTP reads the
  platform store on the same rule as backend TLS). Upstream pins
  `rustls-native-certs` 0.7, the last thing in the tree pulling the
  unmaintained `rustls-pemfile`. 0.8 no longer returns `Result<Vec<_>>`
  but every certificate it could load beside every error it met.
  Upstream failed the whole load on the first read error or the first
  certificate the root store rejected; Lorica keeps what loaded, logs the
  rest at WARN, and fails only when nothing loaded and something went
  wrong, with the first read error, else the first rejection. An empty
  store with no error is still `Ok`, as upstream. The re-exported
  `load_native_certs` now has the 0.8 signature; nothing in the
  workspace calls it. `load_ca_file_into_store` in the same file reads its
  PEM through `http_client::add_pem_roots`, with the refusals it already
  had (a block that does not decode, a certificate the store refuses, a
  file with none), and now leaves the store untouched when it refuses.
- **`lorica-core` and `lorica-lb`, no `derivative` (v1.10.2,
  RUSTSEC-2024-0388).** Sites: `lorica-core/src/upstreams/peer.rs`
  (`impl Debug for PeerOptions`) and `lorica-lb/src/lib.rs` (`Backend`:
  `PartialEq`, `Eq`, `PartialOrd`, `Ord`, `Hash`). Upstream derives these
  with the unmaintained `derivative` crate. Lorica writes them by hand
  with the same semantics: `PeerOptions`' `Debug` prints every field in
  declaration order except the two hook closures, and `Backend` compares
  and hashes `addr` then `weight` and never `ext`. `Backend`'s `Clone`
  and `Debug` are plain std derives. Each hand-written impl starts from a
  destructuring that names every field (`PeerOptions`' `Debug`, and
  `Backend::identity`, which `Backend`'s comparisons and hash read), so a field
  an upstream sync adds to either struct fails to compile there until it
  is printed or compared, or explicitly left out.
- **`lorica-core`, no YAML server configuration (v1.10.2,
  RUSTSEC-2024-0449).** Sites: `lorica-core/src/server/configuration/mod.rs`
  (`ServerConf`, `Opt`) and `lorica-core/src/server/mod.rs`
  (`Server::new`, `Server::new_with_opt_and_conf`). Upstream reads
  `ServerConf` from the YAML file the `-c` / `--conf` flag names
  (`load_from_yaml`, `load_yaml_with_opt_override`, `from_yaml`,
  `to_yaml`) and builds even its defaults by parsing the document
  `version: 1`, through `serde_yaml_ng` and the unmaintained
  `unsafe-libyaml`. Lorica only ever calls `Server::new(None)`, so all of
  it is gone, with the `Opt::conf` field and the serde derives on
  `ServerConf` that nothing else used. `ServerConf::new` constructs
  `ServerConf::default()` with `version: 1`, the value the YAML parse
  produced (a test pins every field), and returns `Self` instead of
  `Option<Self>`; `new_with_opt_override` likewise. `ServerConf::validate`
  is gone with the loader that was its only caller: it refused a
  `max_blocking_threads` of zero, which `ServerConf::new` never sets; a
  configuration built by hand with it still stops the server at startup,
  on the assertion in tokio's runtime builder rather than with an error.
  `Server::new` keeps its `Result` signature, which nothing can fail any
  more. The integration-test server of `lorica-core` builds
  the configuration its `tests/pingora_conf.yaml` used to hold in code,
  and the file is deleted (as is `lorica-proxy`'s, with the suites below
  that read it). On an upstream
  sync, take new `ServerConf` fields with their `Default` value and leave
  the YAML path out.
- **Forked crates on newer dependency majors (v1.10.2, API adaptations
  only).** Upstream's forked crates pin dependency majors the rest of the
  workspace has left, which kept a second copy of each in the binary.
  Lorica moves them to the workspace's version, in each fork's
  `Cargo.toml` (the authority on which crate is at which version), and
  adapts the call sites without changing what the code does. The moves
  that needed code: `rand` 0.10 everywhere (`thread_rng` is `rng`,
  `gen` / `gen_range` are `random` / `random_range` on `RngExt`,
  `SliceRandom::choose` is `IndexedRandom::choose`, `distributions` is
  `distr`, `Uniform::new` returns a `Result`); `nix` 0.31 in
  `lorica-core` (`transfer_fd` passes `AT_FDCWD` to `fchmodat` where it
  passed `None`); `sfv` 0.16 in `lorica-core` (the Accept-Encoding parser
  calls `Parser::new(..).parse::<List>()` and reads tokens through
  `as_str`). `openssl-probe` left `lorica-core` altogether: its one call
  site was the never-compiled OpenSSL connector, deleted with the other
  backends (see Removed Components). The `x509-parser`, `strum`, `blake2`,
  `brotli`, `daggy`, `float-cmp`, `hashbrown`, `i_key_sort`, `rstest` and
  `quick_cache` moves needed none; `lorica-lru` takes `hashbrown` with
  only the `default-hasher` and `inline-more` features. On an upstream
  sync, keep Lorica's version and port the new code to its API rather
  than taking upstream's manifest line.
- **`lorica-proxy`, no integration suites (v1.10.2, tests only).** Gone:
  `tests/test_basic.rs`, `tests/test_upstream.rs` and everything under
  `tests/` only they used (the `utils/` harness with its mock origin,
  WebSocket echo servers and certificate loaders, the openresty
  configuration and key material under `utils/conf/`, `tests/keys/`,
  `tests/headers.dict`), the two `[[test]]` targets, the
  `integration-tests` feature and the dev-dependencies nothing else in the
  crate uses (`hyper` 0.14, `hyperlocal` 0.8, `reqwest`, `httparse`,
  `env_logger`, `tokio-tungstenite`, `futures-util`, and the `lorica-lb`,
  `lorica-limits`, `prometheus`, `serde` and `serde_json` entries left
  over from upstream's example binaries). The suites drive the proxy
  against an openresty origin the fork never provisioned, sat behind a
  feature no job enabled, and had stopped compiling (hyper 0.14 types
  against the `http` 1 API, the `tungstenite` `Utf8Bytes` change). The
  crate's unit tests in `src/` are unaffected. Upstream fixes and new
  tests in these files no longer port: a fix whose only test lives there
  is ported with a unit test written against the fork, or recorded as not
  ported in the sync record below.
- **`lorica-core` and `lorica-lb`, the TLS-gated tests run, minus the
  ones that dial the Internet (v1.10.2, tests only).** Upstream gates its
  connector, listener and TLS tests on `any_tls`; the forked-crate test
  job now has a rustls step that compiles and runs them. The ones that
  connect to `1.1.1.1` / `one.one.one.one` carry
  `#[ignore = "needs network access to ..."]` (`cargo test -- --ignored`
  still runs them): sites in `lorica-core/src/connectors/mod.rs`,
  `connectors/http/mod.rs`, `connectors/http/v1.rs`,
  `connectors/http/v2.rs` and `lorica-lb/src/health_check.rs`. Plain-TCP
  tests in the default-feature build that dial the same hosts are left as
  upstream wrote them. On an upstream sync, keep the `ignore` on those
  tests, and give one to any new test of these modules that leaves the
  machine.
- **`lorica-tls` and `lorica-core`, reqwest 0.13 on a preconfigured TLS
  configuration (v1.10.2).** Sites: the reqwest entry of the workspace
  `Cargo.toml`, which the forks' manifests take with `workspace = true`;
  `lorica-tls/src/http_client.rs` (a Lorica module, no upstream
  counterpart) and the `PemObject` re-export in `lorica-tls/src/lib.rs`;
  the reqwest clients of `lorica-core/tests/test_basic.rs` and of
  `lorica-core/src/listeners/mod.rs`'s tests. Upstream's forks use reqwest
  0.12 with `rustls-tls-webpki-roots`, which falls back to the `ring`
  provider and seeds the root store from the webpki bundle. reqwest 0.13
  has no such feature: left to itself it verifies through
  `rustls-platform-verifier` on the process-wide provider and panics in
  `Client::build` when none is installed, and its default provider is
  `aws-lc-rs`. Lorica builds every client, the forks' test clients
  included, on a `ClientConfig` from `lorica_tls::http_client`, handed
  over by `http_client::client_builder`: `ring`, rustls' default protocol
  versions, ALPN `http/1.1`, and the webpki bundle plus the platform store
  (`public()`), or no verification at all where upstream called
  `danger_accept_invalid_certs(true)` (`unverified()`). reqwest leaves the
  ALPN of a preconfigured configuration alone, so a client that must be
  able to negotiate HTTP/2 is built on `offering_http2(..)`, as the h2
  assertions of `test_basic.rs` are; `.http1_only()` clients keep the
  `http/1.1`-only offer. `reqwest::get` there becomes a client built the
  same way. On an upstream sync, a new test client goes through the same
  helpers: the workspace `clippy.toml` refuses `reqwest::Client::builder`
  and its siblings everywhere else, the forks included.
- **`lorica-core`, the client certificate chain in the TLS digest
  (v1.10.3).** Sites: `lorica-core/src/protocols/tls/digest.rs` (the
  `SslDigest::peer_cert_chain` and `peer_chain_verdicts` fields and the
  `PeerCertChain` and `PeerChainVerdicts` types, which upstream does not
  have) and
  `lorica-core/src/protocols/tls/rustls/stream.rs`
  (`SslDigest::from_stream` fills the chain, on an accepted connection
  only). Upstream's digest keeps the organization, serial number and a
  hash of the peer's end-entity certificate and drops the rest, which is
  enough when one listener trusts one set of roots. Lorica installs on its
  HTTPS listener the union of every mTLS route's CA bundle, so a
  certificate the handshake accepted may come from another route's CA:
  the proxy verifies the chain again against the route's own bundle
  (`lorica::mtls::RouteClientVerifier`), and needs the chain to do it.
  `PeerCertChain` bounds the copy, since rustls keeps its own for the
  life of the connection: past its certificate count or byte bound the
  chain is kept truncated, still counts as presented, and is withheld
  from verification, so it is refused rather than judged on a prefix; its
  `Debug` prints the shape, never the certificates.
  `PeerChainVerdicts` keeps those verdicts per connection, so a keep-alive
  or HTTP/2 connection verifies once per route rather than once per
  request. `SslDigest::new` keeps upstream's signature and starts both
  empty. On an upstream sync, keep the two fields and the fill in
  `from_stream`; a new field upstream adds goes beside them.
- **`lorica-core`, each subject organization kept apart (v1.10.3).**
  Sites: `lorica-core/src/utils/tls/rustls.rs`
  (`get_organizations_x509` and `get_organizations_serial_bytes`, which
  upstream does not have), the `SslDigest::peer_organizations` field in
  `digest.rs`, and `SslDigest::from_stream` in
  `protocols/tls/rustls/stream.rs`. Upstream's `organization` joins every
  `O=` value of the peer's subject with no separator, so `O=Ac, O=me`
  reads as `Acme`, which is harmless for display and wrong for an
  allowlist. `from_stream` now parses the end-entity once, through the
  new function, and derives `organization` from the list by the same
  join, so that field is unchanged; Lorica's mTLS allowlist reads the
  list. On an upstream sync, keep `from_stream` on the list function.
- **`lorica-core`, the client's server name in the TLS digest
  (v1.10.3).** Sites: the `SslDigest::server_name` field in
  `lorica-core/src/protocols/tls/digest.rs` and its fill in
  `SslDigest::from_stream` (`protocols/tls/rustls/stream.rs`), on an
  accepted connection only. Upstream keeps no SNI in the digest. A
  client chooses its certificate for the server name of its handshake,
  and a request on the connection may name another host (HTTP/2
  coalescing, a reused connection); Lorica's mTLS check answers 421
  rather than 495 or 496 in that case, so the client retries on a new
  connection for the right host. `SslDigest::new` starts it `None`.
- **`lorica-core`, a certificate for a client that sends no SNI
  (v1.10.5, issue #53).** Site: `lorica-core/src/listeners/tls/rustls/mod.rs`
  (`TlsSettings::with_resolver`, `TlsSettings::build`, the
  `local_ip_configs` field of `Acceptor`, and `Acceptor::tls_handshake`
  with its helper `local_ip_acceptor`). rustls chooses the certificate
  from the ClientHello alone, and a client dialing an IP sends no SNI
  (RFC 6066), so Lorica's resolver cannot answer it. `with_resolver`,
  Lorica's constructor for its hot-swapped resolver, now takes a
  `lorica_tls::cert_resolver::ResolvesServerCertByLocalIp` (a Lorica
  trait, beside `CertResolver` in `lorica-tls`), and `build` hands the
  listener's `ServerConfig` and that resolver to a
  `lorica_tls::cert_resolver::LocalIpConfigs`. Before the handshake,
  `tls_handshake` asks it for a config, giving it a closure that reads
  the local address from the stream's socket digest; when it answers,
  the handshake runs on that config, otherwise on the listener's own,
  as upstream. Which config, when the local address is read (the
  digest's `local_addr` is a lazy `getsockname`, read only while some
  loaded certificate carries an address), the caching and what the
  copy keeps all live in `lorica-tls`, so a stream TLS terminator
  outside Pingora's listeners can use the same type. No
  `LazyConfigAcceptor`. On an upstream sync, keep the extra `Acceptor`
  field and its fill in `build`, and keep `tls_handshake` choosing the
  acceptor before it calls `handshake` or `handshake_with_callback`.
- **`lorica-core`, a certificate x509-parser refuses is an error
  (v1.10.3).** Site: `parse_der_reporting_errors` in
  `lorica-core/src/utils/tls/rustls.rs`, behind
  `get_organization_serial_bytes` and `get_organizations_serial_bytes`.
  Upstream's `get_organization_serial_bytes` returns a `Result` and
  still `expect`s the parse, so a peer certificate the handshake
  accepted and x509-parser refused would panic the connection task; its
  caller in `from_stream` already treats an error as "no organization".
- **`lorica-core`, `HttpPeer::new` refuses an address that yields no
  socket address (v1.4.0, folded into `new` in v1.10.5).** Site:
  `HttpPeer::new` in `lorica-core/src/upstreams/peer.rs`. Upstream made
  `new` return a `Result` in `b44baef4` but still panics when the address
  converts and yields no socket address; Lorica returns a `SocketError`
  there too, because the address comes from an operator's backend
  configuration and a panic would take down the proxy task serving it.
  Until 1.10.5 this lived in a Lorica-only `HttpPeer::try_new` beside a
  panicking `new`. On an upstream sync, keep the second `or_err` in `new`
  and leave out upstream's `# Panics` section.
- **`lorica-core`, the HTTP/1 body reader carries half of `bd054bad`
  (v1.10.5).** Sites: `lorica-core/src/protocols/http/v1/body.rs`
  (`BodyReader::prepare_buf` through `release_completed_buf`,
  `convert_to_close_delimited`, the excess warning in `do_read_body`,
  the partial chunk head and last-chunk split in `do_read_chunked_body`,
  the split-tail parse in `do_read_chunked_body_final`),
  `lorica-core/src/protocols/l4/stream.rs` (`BUF_READ_SIZE` and
  `Stream::set_buffer_capacity`) and the tests built on them
  (`http/v1/body_fuzz.rs`, which reads through `set_buffer_capacity`).
  Upstream's `f8ecae90` (release empty read buffers, 1.10.5 row below)
  is written on the buffer handling of `bd054bad`, which belongs to
  HTTP/1 request pipelining, a feature the fork does not take (`4a9a34c5`,
  1.7.0 row). The port brings the half `f8ecae90` needs, as upstream
  wrote it: the body buffer holds only the bytes read and is filled by
  `read_buf`, the partial chunk head is compacted in place with its
  offsets committed before the await so a cancelled read resumes, and
  the bytes after the last chunk are split off rather than copied and
  parsed in place for the trailers. The other half is absent:
  `prepare_owned_buf` and `init_chunked_owned`,
  `init_content_length_owned`, `init_close_delimited_owned` (adopting
  the header parser's allocation instead of copying the preread),
  `take_body_overread` and `push_body_overread` (handing the excess to
  the next pipelined session), and the downgrade of downstream excess
  from a warning to debug. So every init copies its preread,
  `convert_to_close_delimited` copies the overread, and downstream excess
  still warns. On the transport side the fork has no `L4BufferSettings`
  (`c0845a86`, per-listener buffer sizes, never taken): `set_buffer`
  keeps fixed sizes and `set_buffer_capacity` stands in for upstream's
  `set_buffer(L4BufferSettings)` for the tests that vary the read-ahead
  capacity. Each site carries a `Lorica:` comment. On an upstream sync,
  a change to these functions is ported onto this shape, checked by
  `body_reader_fuzz_fixed_seeds` (and the ignored soak for a longer run).
  A port of `bd054bad` proper, with pipelining, replaces the copies by
  the owned variants and the overread hand-off, restores upstream's
  debug log, and drops this entry; taking `L4BufferSettings` replaces
  `set_buffer_capacity` and `BUF_READ_SIZE` with upstream's settings and
  `DEFAULT_L4_READ_BUFFER_SIZE`. The 32 KiB sizes are upstream's, whose
  reason (jemalloc's tcache) does not hold for a binary on glibc malloc;
  both comments say so, pending a benchmark.

## Upstream sync record

Each release cycle that pulls upstream commits into the forked crates is
recorded here, most recent first. Commit ids are upstream `main` ids
(`git fetch upstream`). `docs/backlog.md` #81 carries the reasoning per
commit; the `[1.7.0]` CHANGELOG entries describe the user-visible effect.

| Cycle | Upstream range | Ported | Not ported (deliberate) |
|-------|----------------|--------|-------------------------|
| 1.10.5 (2026-11-12) | `1adcb381`..`3f87e92c` | `0358ae7f` (rand 0.10 calls; its test keeps a file of its own, as upstream's), `790916e1` (moves `thread_local` from a dependency of `lorica-runtime` to a dev-dependency, as upstream does), `47613cc8`, `b44baef4` + `c261234c` (by hand: the fork already had the fallible constructor as the Lorica-only `HttpPeer::try_new`, with `new` panicking on it; `try_new` is folded into `new`, which keeps its stricter refusal of an address that yields no socket address, where upstream still panics, so the `# Panics` section of `c261234c` is not carried; the docs/ and example hunks touch files the fork does not carry), `f8ecae90` (by hand: its `body.rs` hunks sit on the buffer handling of `bd054bad`, HTTP/1 pipelining without copies, which no pass took since it serves the pipelining feature `4a9a34c5` ruled out in the 1.7.0 row; the port brings the part of `bd054bad` the commit needs, a `BytesMut` holding only the bytes read and filled by `read_buf`, the partial chunk head compacted with its offsets committed before the await, the tail after the last chunk split off rather than copied, and leaves out its owned-preread init variants and overread hand-off, so upstream's tests run their borrowed-preread half; `stream.rs` has no `L4BufferSettings`, so `set_buffer` keeps its fixed sizes through a new `set_buffer_capacity`; recorded as a divergence above), `f2fca311` (by hand: borrowed prereads only, the L4 transport through `set_buffer_capacity`, rand 0.10, so its seeds do not replay upstream's cases), `8b91e00c` (it rewrites `FixedBuffer` whole and so also brings `b1572eee`, the release of a truncated retry buffer, an earlier upstream commit no pass recorded) | Deferred to Epic 12: `5104a3e0` (opt-in accept limits per listening endpoint: handshake timeout, open-connection and pending-handshake caps, closing peers that already left) and `4a9d66d8` (a listener `Tracer` reporting downstream connection lifetime from accept). Both act on Pingora's listeners, which here serve HTTP only, and have no consumer today; Epic 12's stream accept loop runs outside them (`docs/prd/epic-12-v1.11.0.md`, Architecture), but its connection budgets and fd reserve for HTTP are where caps on the HTTP listeners get decided, beside the fork's own per-IP accept permit (Story 8.9). `5104a3e0` also lands on `listeners/tls/rustls/mod.rs` and `l4/stream.rs`. `33a9e210` (abandon unfinished custom upstream responses): it extends the custom-session abandonment of the cache-fill opt-in `989ed973`, ruled out in the 1.10.0 row, so `proxy_custom.rs` here has nothing to extend, and Lorica does not wire the custom-protocol path; the same reason as `7de472d2` there. `2578e3a2` + `9c7b63ce` (`WrappedX509::parse` and its refusal of trailing bytes): additive API, and nothing in the workspace builds a `WrappedX509` outside `utils/tls`. `4f203931` (despite its title, wires `upgrade_sock_connect_accept_max_retries` into Pingora's own graceful upgrade): Lorica never sets the field (`ServerConf::new` leaves it `None`), with `None` the wired path behaves as it does now, and Lorica's hot upgrade calls `Fds::send_to_sock` and `get_from_sock` directly. CI only: `3f87e92c` (cargo nextest), `b5592940` (a soak step for the body reader fuzz in upstream's CI; the soak is ported as the ignored `body_reader_fuzz_soak`) |
| 1.10.2 (2026-11-04) | `84f21ee9`..`1adcb381` | `80b68c34` + `56965c34` (by hand: neither connector hunk applied, the fork's `reused_stream` calls `matches_fd` without the `cfg(unix)` and its imports differ; the `idle_poll` signature change in `lorica-pool` came over as upstream wrote it, the `RwLock` pool itself is untouched; the hand-off race test sits in its own `reuse_race_tests` module rather than upstream's `any_tls`-gated `tests`, so that it also runs in the forked-crate test job's default-feature build; the gated module itself runs in that job's rustls step since the same cycle), `b5dea5a6` (with its strict round-trip tests), `1adcb381`, `a7106806` | early request body buffering before peer selection `da2af11e`, `23d43604`, `9836342e`, `7b709f12` (a new opt-in feature, its phase docs, and a fix to its `body_routing` example, an example binary the fork does not carry); it lands on exactly the sites of the initial body send divergence in `proxy_h1.rs`, `proxy_h2.rs` and `proxy_custom.rs`, which the WAF body hold depends on. `cb16c871` (TLS verify callback for upstream connections) and `b0c6e442` (vectored TLS write coalescing), both OpenSSL/BoringSSL-only; the fork is rustls-only. `95857fe8` (illumos and Solaris builds; Linux-only project). `e479d66c` (docs.rs metadata). `6502a633` (audit ignore for `crypto-bigint` 0.5.5, absent from Lorica's lockfile). `8d1adda2` (zstd 0.14.3, which Lorica's lockfile already resolves) |
| 1.10.0 (2026-10-27) | `4487f7b2`..`84f21ee9` | `b62452fc` (by hand: the completion sync lands in the inlined upstream task branch, no `PipeState` assertions in its tests), `81463f8a` (by hand: `read_body_or_idle` stays an `async_trait` method on the dyn custom session, `custom_session_tests.rs` adapted), `10a83456` (the `do_write_chunked_body` hunk and its unit test; the body-task hunk patches the proxy task API path the fork lacks, and the `test_basic.rs` test needs the upstream `HttpOrigin` utilities), `c1c4a0da`, `a554e713` (with `read_response_header_non_utf8`, not the HEAD-response tests that rode along in the conflicting hunk), `5b30d71d` (by hand: no `L4BufferSettings` here, so a stream-level zero-capacity test replaces the listener one) | `7de472d2` (custom upload failure handling): its fix is written against `PipeState` and the producer/delivery split of `ResponseStateMachine` from `7142ad46`, part of the proxy task API family deferred in the 1.7.0 row (backlog #83), and its tests sit on the `989ed973` cache-fill abandonment harness and `tokio` `test-util`; Lorica does not wire the custom-protocol path it fixes. Features: `5641e50c` (configurable HTTP/1 response parser; this fork already normalises obsolete line folding since 1.7.0 and keeps its lenient defaults), `5dc98c41` (runtime groups shared across services; Lorica runs one proxy service per worker), `62b3227e` (Dial9 profiling runtime options, no Dial9 here), `42df06a3` (downstream fd in the TLS certificate callback, an OpenSSL/BoringSSL-only change; the fork is rustls-only). Cache opt-ins `989ed973`, `0741cf08`, `565ec1ef`, `ac7cf04e` (downstream abandonment of a cache fill, early cancellation, client watch during a stalled hit or a subrequest pipe: new opt-in APIs, defaults unchanged). LRU and storage `9c589336`, `11b9eb3c`, `327cc69c` (new conditional and paired LRU mutations, eviction-accounting hooks for out-of-band storage, a data-peek helper), `27e90f93`, `1f59e578` (an `unwrap` on a write into a `Vec` turned into an error, and its message). CI and test-only: `84f21ee9`, `1b0a4b97`, `d316bab1`, `9b88c0ff`, `623e163d`, `3e204141`, `952b5caa`, `a884c5b3`, `962a6b63`, `7010f0d5`, `3658dafb` |
| 1.9.2 (2026-10-14) | commits deferred by the `4487f7b2` pass | `b01edce5` (sharded shutdown `Notify`, which also closes a lost wakeup: a request that started waiting for its header after `http_cleanup()` had fired waited out the grace period; both tests in `lorica-proxy/src/lib.rs`, not the `benches/shutdown_signal.rs` benchmark, which mirrors private types) | the request-target chain, upstream order `ffab8302` -> `1e551289` -> `baf4fe5c` -> `ee78ceb6`. Only the authority checks of `ffab8302` were ported (1.7.2); its absolute-form and CONNECT classifier, its H2 egress rewrite and the three commits after it were not. Together they make absolute-form, authority-form CONNECT and non-UTF-8 targets parse, then fix how they are stored, fragment-stripped and forwarded. None of those shapes reach a header here, whatever the method (`non_origin_form_targets_do_not_reach_the_header` in `lorica-core/src/protocols/http/v1/server.rs`, which sends authority-form as both `GET` and `CONNECT`, and `absolute_form_targets_do_not_survive_header_parsing` in `authority.rs`), so for this fork the chain is a feature: RFC 9112 absolute-form acceptance |
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
