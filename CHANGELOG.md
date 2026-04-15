# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

Author: Rwx-G

## [Unreleased]

### Fixed

- Bot-protection `/lorica/bot/solve` endpoint mis-rejected solutions with 403 when the client was reached via a trusted proxy (v1.4.0 Epic 3 follow-up surfaced by the `bot` E2E profile). The challenge-render path unwrapped X-Forwarded-For and stashed the pending entry's IP prefix under the resolved client's /24 or /64, but the cross-cutting `/lorica/bot/solve` interception read the raw TCP client address. The stashed prefix and the solve-time prefix did not match, so the "client network changed" guard fired on every legitimate solve. The interception now runs the same XFF-trust check as `request_filter` proper (direct TCP client ∈ `trusted_proxies` → honour the leftmost XFF entry).
- `lorica_geoip_block_total` Prometheus counter label `route_id` was always `_unknown` in worker mode and often `_unknown` in single-process (v1.4.0 Epic 2 follow-up surfaced by the new `geoip` E2E profile). The counter callsite in `proxy_wiring::request_filter` read `ctx.route_id` which is only populated further down the filter (after response-headers, forward-auth, etc.), so a GeoIP rejection always fired with the unset fallback. Switched to `entry.route.id` which is already bound in scope at the point the rule evaluates
- GeoIP DB sanity check was too strict for test fixtures (v1.4.0 Epic 2 follow-up). `load_from_path` rejected any `.mmdb` where `8.8.8.8` did not resolve, which blocked the MaxMind open-licensed test fixture we ship in `tests-e2e-docker/fixtures/`. The check now tries a list of probes (8.8.8.8, 1.1.1.1, and a known-hit from the MaxMind test fixture) and accepts the DB if ANY of them resolves — strict enough to reject an empty / wrong-type DB, permissive enough to accept test databases that index a partial IPv4 space
- OTLP HTTP exporter endpoint composition (v1.4.0 Epic 1 follow-up to story 1.4a). opentelemetry-otlp 0.31 does not auto-suffix the signal path onto `with_endpoint(base_url)` for HTTP transports — the POST lands on `/` and Jaeger / Tempo / the OTel collector all reply 404. `lorica::otel::init` now appends `/v1/traces` when the configured `otlp_endpoint` does not already include it, so operators can paste the base URL from their collector and still get spans through. gRPC transport is unchanged (the path is implicit in the proto definition).
- OTLP exporter panic on BatchSpanProcessor worker thread (v1.4.0 Epic 1 follow-up). The SDK spawns a dedicated OS thread (not a Tokio task) for the batch processor; the `reqwest-client` (async) feature on opentelemetry-otlp 0.31 panicked with "there is no reactor running, must be called from the context of a Tokio 1.x runtime" whenever that thread tried to flush. Switched to `reqwest-blocking-client` so the batch processor uses the synchronous reqwest API, which does not need a Tokio context.
- OTel settings hot-reload (v1.4.0 Epic 1 follow-up). A dashboard edit to `otlp_endpoint` / `otlp_protocol` / `otlp_service_name` / `otlp_sampling_ratio` previously required a process restart to take effect because `otel::init` only ran at startup from `main.rs`. New `apply_otel_settings_from_store` helper in `lorica::reload` snapshots the four fields, hashes them, and calls `otel::init` / `otel::shutdown` only when the snapshot diverges from the last applied value (so unrelated config edits do not churn the BatchSpanProcessor). Wired into every `reload_proxy_config*` entry point — live for single-process, supervisor, and worker runtimes.

### Added

- OpenTelemetry tracing scaffolding (feature-gated, off by default). New Cargo feature `otel` on the `lorica` crate pulls in `opentelemetry` 0.31, `opentelemetry_sdk` 0.31, `opentelemetry-otlp` 0.31, `opentelemetry-semantic-conventions` 0.31 and `tracing-opentelemetry` 0.32. Policy matches `route53` since the v1.3.0 supply-chain audit (SC-M-3): non-OTel users do not pay the dep-graph cost and the `.deb` / `.rpm` / Dockerfile / CI build scripts stay on default features unchanged. Four new fields on `GlobalSettings`: `otlp_endpoint` (Option<String>, None = disabled at runtime even with the feature built in), `otlp_protocol` ("grpc" / "http-proto" / "http-json", default "http-proto"), `otlp_service_name` (default "lorica") and `otlp_sampling_ratio` (f64 in 0.0..=1.0, default 0.1 matching Tempo / Grafana overhead guidance). API validation in `PUT /api/v1/settings` enforces URL scheme, protocol enum, service-name length (1..=256), and finite sampling ratio. `global_settings` is a key-value table so no SQL migration is required; four new keys are read / written alongside the existing ones. Actual exporter init, span creation, W3C context propagation and log correlation land in the following stories
- W3C trace context propagation (always on, does not require the `otel` feature). `request_filter` parses the incoming `traceparent` header and either preserves the trace_id while rolling a new parent-span id for Lorica (when the client sent a well-formed header) or synthesises a fresh deterministic trace from the request_id (when there was no client header or it was malformed). `upstream_request_filter` then always injects the outgoing `traceparent` on the wire so the backend sees a continuous trace tree across the Lorica hop. `tracestate` passes through unchanged when present (vendor-opaque per RFC). The generated parent-span id uses FNV-1a 64 seeded by `(trace_id, request_id)` so two Lorica workers seeing the same request synthesise the same span id (required for well-formed trees under multi-worker fan-out). Parsing is ~50 ns and rejects malformed or reserved-zero values to avoid propagating client-injected garbage. Overhead when OTel is disabled: one header lookup + one parse attempt per request
- OTLP exporter lifecycle (feature-gated behind `otel`, no-op when the feature is off). `lorica::otel::init()` installs a global `SdkTracerProvider` when `GlobalSettings.otlp_endpoint` is set: builds an OTLP `SpanExporter` matching the configured protocol (http-proto via reqwest, http-json via reqwest, grpc via tonic), attaches a `Resource` carrying `service.name` / `service.version`, wraps a `ParentBased(TraceIdRatioBased)` sampler so a sampled parent always carries through the proxy hop, and installs the provider as the OTel global. Repeatable: a second `init()` tears down the previous provider atomically so a config reload that changes endpoint / protocol / service name / sampling ratio takes effect without a restart. `lorica::otel::shutdown()` flushes the batch exporter and releases the provider. Wired into all three runtime paths for init (single-process, supervisor, each forked worker) so every runtime installs its own independent exporter inside its own Tokio runtime and a stuck worker cannot block another worker's flush queue. Shutdown-time flush is wired for single-process and supervisor after their drain deadlines; workers inherit the `BatchSpanProcessor`'s periodic export (default ~5 s interval) which drains spans during steady-state operation (tracked as a follow-up to expose a pre-exit flush hook from `lorica-core::Server`, since `run_forever()` returns `!`). A `try_init_otel_from_settings(store, role)` helper deduplicates the three init call sites; the `role` label ("single-process" / "supervisor" / "worker") is included in the startup log line so multi-process installs can tell which component finished tracing init. Init failures are `warn!` and do not block startup (observability is not a critical path)
- Tracing -> OpenTelemetry bridge (story 1.4c). `init_logging` now installs a `tracing_opentelemetry::OpenTelemetryLayer` (feature-gated behind `otel`) wrapped in a `tracing_subscriber::reload::Layer` so the embedded `BoxedTracer` can be swapped from a startup-noop placeholder to the real provider once `otel::init` runs. The reload callback is type-erased behind a `Box<dyn Fn(BoxedTracer) + Send + Sync>` stored in `lorica::otel::OTEL_RELOAD_HOOK`, keeping the subscriber-chain type parameters out of `otel.rs`. With the bridge installed, every `#[tracing::instrument]` span on the proxy hot path (`http_request` on `request_filter`, `upstream_request_filter`, `response_filter`, `logging`, `fail_to_proxy`) is mirrored into an OTel span and exported via the global provider — no manual `BoxedSpan` plumbing left in `proxy_wiring`. The `http_request` root tracing span (now named after the OTel HTTP semconv convention rather than `request_filter`) is captured into `RequestCtx.root_tracing_span` at the top of the hook so the four child hooks can `parent = &ctx.root_tracing_span` their own `#[instrument]` spans under it, producing a properly nested trace tree in Jaeger / Tempo. The W3C parent context (when the client sent a valid `traceparent`) is set on the root span via `tracing_opentelemetry::OpenTelemetrySpanExt::set_parent`. Final-state HTTP semconv attributes (`http.response.status_code`, `lorica.latency_ms`, `server.address`, `network.peer.address`, `lorica.route_id`, `lorica.trace.origin`, `client.geo.country_iso_code`, `error.message`, plus the well-known `otel.status_code` mapped from 5xx -> ERROR / else -> OK) are recorded via `Span::record` on the root span at the end of `logging()` so the bridge emits them on span close. Removes the now-redundant `lorica::otel::ActiveSpan` wrapper + `start_root_span` helper + `ctx.otel_span` field — the bridge handles span creation end-to-end. Microbench file `otel_overhead` slimmed down to the always-on W3C wire-format primitives (the bridge cost is collector-bound and is measured via the `tests-e2e-docker/` Jaeger profile rather than via criterion in-process).
- Per-request OpenTelemetry root span (feature-gated behind `otel`). Each proxied request gets a `Server`-kind span named `HTTP {method}`, created in `request_filter` right after W3C traceparent parsing so the span links to the client's parent context when a valid header was present (trace_id preserved + remote parent span context attached, so Jaeger / Tempo renders the client above Lorica in the tree) or starts a fresh root otherwise. Span ends in the final `logging()` hook with OTel HTTP semconv attributes: `http.request.method`, `url.path`, `http.response.status_code`, `server.address` (Host header), `network.peer.address` (backend socket), `lorica.route_id` for consistency with the Prometheus label set, `lorica.latency_ms`, `lorica.trace.origin` ("client" vs "lorica"), and `error.message` on blocked / errored paths. Span status follows OTel convention (5xx -> Error, everything else -> Ok). The `ActiveSpan` wrapper in `lorica::otel` is a ZST when the feature is off, so call sites do not need `#[cfg]` guards and the compile-time overhead of the instrumentation is zero on default builds
- Log / trace correlation via `#[tracing::instrument]` on every proxy hook (`request_filter`, `upstream_request_filter`, `response_filter`, `logging`, `fail_to_proxy`). Each hook opens a tracing span whose fields carry `trace_id`, `span_id`, and `request_id`, read from the `outgoing_traceparent` populated in `request_filter` (W3C propagation is always on, so correlation fields are populated regardless of the `otel` feature). Every `tracing::info!` / `warn!` / `error!` emitted inside those hooks automatically inherits the span fields in both the JSON and text log outputs, so an operator can grep Loki / ELK for a Jaeger trace id and land directly on every Lorica log line for that request, or paste a `trace_id` from a log line into Jaeger / Tempo to jump to the trace. In `request_filter` the fields start as `field::Empty` and are filled via `Span::current().record(...)` immediately after traceparent parsing, so even the ACME challenge handler and the global flood / connection-limit rejections that happen at the top of the hook carry the correlation fields. No refactoring of the subscriber was required: the existing `tracing_subscriber::fmt().json()` configuration already emits span fields on every event record by default
- GeoIP country-code filter per route (v1.4.0 Epic 2 stories 2.1 / 2.2 / 2.3 / 2.4 / 2.5 / 2.6 / 2.7). Dashboard integration: new "GeoIP country filter" section in the Protection tab with a mode dropdown (Allowlist / Denylist) and a comma-separated country list input. Front-end validation mirrors the API side — empty denylist is legal and means "filter off for this route", allowlist with empty list is rejected server-side. TESTING-GUIDE section 19 walks through the first-run DB install (manual curl + gunzip to `/var/lib/lorica/geoip.mmdb`), dashboard config, faked-source-IP test via `X-Forwarded-For`, and the CC-BY 4.0 attribution requirement. Attribution for the DB-IP Lite Country source added to the top-level `NOTICE` file as required by the CC-BY 4.0 licence. Data source is `DB-IP Lite Country` (CC-BY 4.0, no account required, monthly refresh). New `lorica-geoip` crate wraps `maxminddb 0.27` behind a lock-free `ArcSwapOption<maxminddb::Reader>` so hot-swaps are atomic; per-lookup cost is a single `decode_path` call on `country.iso_code`. Typed `CountryCode` newtype (two uppercase ASCII letters) and typed `GeoIpError` (Io / Parse / SanityCheck) surface from the loader. `GeoIpResolver::load_from_path` sanity-checks by looking up `8.8.8.8` before publishing — a file that parses as `.mmdb` but indexes nothing useful is rejected, keeping the previous DB live. The auto-update task in `lorica_geoip::updater` downloads the current-month `.mmdb.gz` once a week via reqwest + flate2, decompresses with a 128 MiB uncompressed cap (zip-bomb guard), validates via the resolver's own sanity check in a temp file, then atomic-renames onto the operator-configured path and calls `resolver.load_from_path` so the in-memory reader is replaced without dropping in-flight lookups. Fail-soft: any cycle error (network blip, response too small, gzip decode error, DB validation failure) keeps the previously-loaded DB live and retries on the next tick. Wired into all three runtimes: single-process opens the DB and spawns the updater inside its own tokio runtime; the supervisor runs a standalone updater that keeps the on-disk copy fresh (workers pick up the refresh on restart); each forked worker opens its own read-only copy at fork time. Per-route `Route.geoip = Option<GeoIpConfig>` carries `mode: Allowlist | Denylist` + `countries: Vec<String>`; evaluation placement is after per-route IP allow / deny and before WAF so a cheap geographic rejection runs before expensive regex matching. Unknown country (reserved / private IP, DB miss) falls through without blocking so a legitimate client behind a corporate NAT is never accidentally denied — operators that want fail-close semantics layer `ip_allowlist` on top. API validation in `POST/PUT /api/v1/routes` rejects non-ISO-alpha-2 country codes, dedups + uppercases the list, caps at 300 entries, and refuses an empty `countries` list in allowlist mode (would block everything). Schema migration V34 adds the idempotent `routes.geoip` column; existing rows continue to serialise as NULL. Two new `GlobalSettings` fields: `geoip_db_path` (absolute path, Option<String>, None = feature off) and `geoip_auto_update_enabled` (bool, default false — operators opt in after reading the CC-BY 4.0 attribution requirement). Observability: new Prometheus counter `lorica_geoip_block_total{route_id, country, mode}` fires on every rejection (bounded cardinality: routes * ~240 countries * 2 modes), and the resolved country is stamped on the per-request OTel root span as `client.geo.country_iso_code` on every request — even the ones that are not blocked — so Jaeger / Tempo traces carry geography for analytics and anomaly detection regardless of whether a route's rule actually fired
- OpenTelemetry E2E smoke test in `tests-e2e-docker/` under a new docker-compose `otel` profile. Brings up Jaeger all-in-one (1.60, OTLP gRPC + HTTP enabled) alongside a Lorica built with `--build-arg LORICA_FEATURES=otel`, then runs `run-otel-smoke.sh` in the test-runner container which logs into the management API, configures `otlp_endpoint=http://jaeger:4318` + `sampling_ratio=1.0`, creates a test route, sends a traced request carrying a deterministic W3C traceparent (`00-4bf92f35...4736-00f067aa0ba902b7-01`), polls the Jaeger HTTP query API (`/api/traces/{id}`) for up to 30 s, and asserts the resulting span carries the expected HTTP semconv tags (`http.request.method=GET`, `http.response.status_code=200`, `url.path=/`, `lorica.route_id` matching the created route id). New `LORICA_FEATURES` build arg on `tests-e2e-docker/Dockerfile` selects Cargo features at build time so the same Dockerfile covers both the default and OTel-enabled images. The smoke test exits non-zero on any missing span / missing tag, making it suitable for wiring into CI later without noise
- Hot-reload of `GlobalSettings.geoip_db_path` (v1.4.0 Epic 2 follow-up). A dashboard edit to the DB path previously required a Lorica restart to take effect because `load_from_path` on the process-wide resolver only ran in the boot path. New `apply_geoip_settings_from_store` hook in `lorica::reload` wires into every `reload_proxy_config*` entry point and calls `load_from_path` (or `unload()` when the path is cleared) on the resolver handle registered at startup via a new `lorica::geoip::set_handle` / `handle()` pair (OnceLock<Arc<GeoIpResolver>> — same "type-erased hook out of the chain" pattern as `otel::OTEL_RELOAD_HOOK`). Dedup via a `parking_lot::Mutex<Option<String>>` snapshot so unrelated settings edits do not re-open the `.mmdb` on every reload. On failure the old DB stays live, the snapshot is NOT advanced, and a `warn!` fires so the operator sees the problem on the next save attempt. Worker mode keeps its startup-load semantics for now: the supervisor's reload covers supervisor-side lookups; worker-side in-memory readers pick up updater-written files on the next 24-hour tick or a worker restart (broadcasting an RPC reload command to workers is tracked as a v1.4.x follow-up)
- Auto-update cadence for the DB-IP Lite Country feed changed from 7 days to 24 hours (`lorica_geoip::updater::UPDATE_INTERVAL`). Keeps Lorica within one day of a mid-month upstream regeneration (happens when the maintainer ships a fix or re-scores the dataset) and matches the refresh rhythm operators expect from other IP-reputation feeds. Bandwidth cost is trivial (~3 MiB gzip per day) and the atomic ArcSwap publish means in-flight requests are never blocked
- GeoIP Docker E2E smoke test under a new docker-compose `geoip` profile (v1.4.0 Epic 2 story 2.7 coverage). Brings up a Lorica container with MaxMind's open `GeoIP2-Country-Test.mmdb` fixture (Apache-2.0, checked in under `tests-e2e-docker/fixtures/`) volume-mounted at `/var/lib/lorica/geoip-test.mmdb`. `run-geoip-smoke.sh` sets `geoip_db_path` + `trusted_proxies` over the management API (exercising the new hot-reload hook end-to-end — not a startup pre-seed), creates a route, drives three requests with known fixture IPs (US = 214.78.120.5, KR = 2001:220::1, unknown = 192.0.2.1) via `X-Forwarded-For`, flips the route between `denylist=[US]` and `allowlist=[US]`, and asserts status codes plus `lorica_geoip_block_total{route_id, country, mode}` counter deltas. Covers the three decision branches (allowlist pass / deny, denylist pass / deny) and the unknown-country fallthrough design choice end-to-end. 16/16 assertions pass on the real Docker run
- Worker-mode OpenTelemetry E2E smoke test under a new docker-compose `otel-workers` profile (v1.4.0 Epic 1 story 1.6 coverage). Same `run-otel-smoke.sh` script runs against a Lorica built with `--features otel` AND `--workers 2`, so the OTel init path (`try_init_otel_from_settings("worker")`) gets exercised inside a forked worker process rather than just single-process mode. Separate Jaeger instance (`jaeger-workers`) and shared volume (`shared-otel-workers`) keep the two OTel profiles independent; the single-process `otel` profile was otherwise unchanged
- Log / trace correlation assertion in `run-otel-smoke.sh` (v1.4.0 Epic 1 story 1.5 coverage). New `entrypoint-otel.sh` tees Lorica's JSON log to `/shared/lorica.log`; after the traced request fires, the smoke greps for the client's W3C `trace_id` in the log, proving the `span.record("trace_id", ...)` on the `http_request` root span flattens into the fmt layer's JSON output. Without this assertion, earlier smokes would have regressed silently if the fmt layer was ever refactored to drop span fields
- OTel log/trace correlation check in the smoke is non-destructive when the log file is missing (soft fail with diagnostic tail) so an operator debugging a compose file typo sees useful context instead of a cryptic grep miss
- Unit tests for `GeoIpConfig::blocks()` (7 cases) extracted into `lorica-config` so the allowlist / denylist decision rule is directly verifiable without a proxy session; `request_filter` now calls the extracted method instead of inlining the match. Unit tests for the API validator `validate_geoip` (8 cases covering case normalisation, trimming, dedup, alpha-2 enforcement, oversize-list cap, and the allowlist-must-be-non-empty rule). Unit test for `inc_geoip_block` that exercises the Prometheus counter through the public API and scrapes the text format to prove the `(route_id, country, mode)` triple shows up with the expected count. HTTP mock integration tests for `lorica_geoip::updater::run_once` covering the 404, `TooSmall`, `TooLarge`, and `Validation` error branches (uses a minimal `std::net::TcpListener` server in a worker thread — no new dev-deps beyond extending `tokio` with `net` + `rt-multi-thread`)
- **Bot-protection design doc** (v1.4.0 Epic 3, story 3.1) at
  `docs/architecture/bot-protection.md`. Specifies the three graded
  challenge modes (Cookie, JavaScript PoW, image captcha), the
  HMAC-signed verdict cookie wire format (route_id + /24 v4 or /64
  v6 IP prefix + expires_at + mode, 41 or 46 bytes before base64url),
  the PoW algorithm (SHA-256 over `hex_nonce || counter_decimal`
  with 14–22 configurable leading zero bits), the captcha alphabet
  defaults, the five-category bypass matrix (IP CIDRs, ASNs,
  countries, User-Agent regex, rDNS with forward confirmation),
  the `only_country` inverse gate, the HMAC secret lifecycle
  (rotated on each cert renewal so cookie validity is capped at
  the cert TTL), and the exact request-filter placement (after
  GeoIP, before forward_auth). Includes an in-scope / out-of-scope
  threat model and an implementation-checklist that maps 1:1 to the
  remaining stories
- **`lorica-challenge` crate** (v1.4.0 Epic 3, story 3.2). New
  workspace member with three modules: `cookie` (HMAC-SHA256 sign /
  verify with `subtle::ConstantTimeEq` on the tag, ± 30 s clock-skew
  grace at verify time, deterministic wire size 41 / 46 bytes before
  base64url — size pinned by tests), `pow` (`Challenge::new` with
  mandatory difficulty bound 14..=22, hex-encoded 16-byte nonce,
  `verify_solution` with O(1) SHA-256 check + bit-mask comparison,
  plus test-only `mine` for reproducible round-trip tests),
  `captcha` (image generation via the pure-Rust `captcha = "1.0"`
  crate with a curated alphabet that excludes both visual confusables
  `0/O/1/l/I` and the glyphs the default font cannot render `L/o`;
  verify is case-insensitive with constant-time compare), and
  `secret` (process-wide HMAC-SHA256 key in `ArcSwap<Option<Arc<[u8;
  32]>>>`, hot-swappable via `rotate`, generated from `OsRng` via
  `generate`). 52 unit tests covering every public boundary: HMAC
  forgery attempts (flipped payload byte, flipped tag byte, wrong
  secret), length and discriminator validation, NAT-tolerance
  semantics (same /24 or /64 still validates), expiry grace, PoW
  off-by-one, bit-mask behaviour across byte boundaries, captcha
  alphabet rules, mismatch detection, and RNG non-determinism. No
  `unwrap` on any user-reachable path. Dep footprint: RustCrypto
  (hmac 0.12 + sha2 0.10 + subtle 2), base64 0.22, rand 0.8,
  arc-swap 1, once_cell 1, captcha 1.0 (which pulls image + lodepng
  for PNG encoding); all version-pinned to match the existing
  `Cargo.lock` transitive resolution so the workspace does not pull
  two copies of anything
- **Bot-protection config model + migration V35** (v1.4.0 Epic 3,
  story 3.3). New `Route.bot_protection: Option<BotProtectionConfig>`
  field in `lorica-config::models::route` carrying `mode` (Cookie /
  Javascript / Captcha), `cookie_ttl_s` (u32, default 86400, capped
  at 604800 = 7 days), `pow_difficulty` (u8 in 14..=22, default 18),
  `captcha_alphabet` (String, default excludes `0/O/1/l/I` and the
  font-unsupported `L/o`), a `bypass: BotBypassRules` sub-struct
  (ip_cidrs, asns, countries, user_agents, rdns), and
  `only_country: Option<Vec<String>>` inverse gate. New
  `GlobalSettings.bot_hmac_secret_hex` field for the process-wide
  HMAC secret (hex-encoded so the key-value `global_settings` table
  does not need a BLOB column). Idempotent `ALTER TABLE routes ADD
  COLUMN bot_protection TEXT` migration — existing rows serialise
  as NULL. `validate_bot_protection` in `lorica-api::routes::crud`
  enforces difficulty bounds, alphabet shape (10..=128 ASCII-
  printable chars, no duplicates), CIDR syntax, ISO alpha-2 country
  codes (case-normalised to upper), UA regex compilation, rDNS
  shape rules (no bare TLD, no leading dot, printable ASCII), and
  a 500-entry cap per bypass category. 19 unit tests cover every
  rejection branch. RouteResponse + CreateRouteRequest +
  UpdateRouteRequest all expose the new field over the API, and
  the existing `route_to_response` / create / update handlers are
  wired end-to-end
- **Bot-protection challenge rendering** (v1.4.0 Epic 3, story 3.4).
  New `lorica_challenge::render` module produces self-contained
  HTML pages for the three modes — no external CSS, no CDN, no
  remote script. `render_cookie_refresh_page` emits a
  `meta http-equiv="refresh"` bounce for the passive mode;
  `render_pow_page` embeds an inline SHA-256 PoW worker using
  `crypto.subtle.digest` with chunked async execution and
  `requestAnimationFrame`-based progress updates so the UI stays
  responsive at high difficulty; `render_captcha_page` places the
  one-shot signed image URL + a single-field form. Every page
  carries a `<noscript>` fallback block that never loads anything
  remotely, embeds a `prefers-color-scheme: dark` media query for
  mobile dark-mode users, and uses system fonts (no web-font
  fetch). `render_plaintext_fallback` produces a short 403 body
  for clients that did not advertise `text/html` in Accept so
  curl / wget see a meaningful message. HTML escaping covers the
  five dangerous characters (`& < > " '`) on every substituted
  value — regression-tested so a route hostname containing
  `</script>` cannot break out of the JS block, and a submit URL
  containing `"` cannot escape the attribute context. 11 unit
  tests cover escaping, field propagation, optional contact-line
  rendering, difficulty-dependent hint text, and UTF-8 declaration
- **Bot-protection E2E Docker smoke + TESTING-GUIDE section 20**
  (v1.4.0 Epic 3, stories 3.9 + 3.10). New docker-compose `bot`
  profile with a `lorica-bot` container (default features, GeoIP
  fixture mounted so the country-bypass resolves for known test
  IPs) and a `bot-smoke` test-runner. 30 assertions on a real
  Docker run, green end-to-end: Cookie mode (challenge page +
  Set-Cookie + passthrough-on-replay), JavaScript PoW (mine at
  difficulty 14 via a `python3` helper embedded in the shell
  script, POST nonce+counter to `/lorica/bot/solve`, 302 +
  Set-Cookie, passthrough on replay, wrong-counter replay is
  rejected with 403), Captcha (page renders with an
  `/lorica/bot/captcha/{nonce}` image URL, `Content-Type:
  image/png`, unknown nonce returns 404), all three functional
  bypass categories (IP CIDR, country, UA regex), the
  `only_country` inverse gate, and the Prometheus counter
  increments across the `{shown, passed, bypassed}` outcomes.
  TESTING-GUIDE section 20 walks through each mode with copy-
  pasteable curl + python recipes, lists the metrics to watch,
  and documents the four v1.4.0 limitations (ASN / rDNS deferred,
  cross-worker stash per-worker, HMAC rotation on cert renewal
  not yet auto-wired, rDNS-without-forward-confirm explicitly
  marked as a must-not regression)
- **Dashboard Bot Protection tab section** (v1.4.0 Epic 3, story
  3.8). Under Routes &rarr; Protection, below the GeoIP filter:
  a toggle switch to enable / disable per route, a mode dropdown
  (Cookie / JavaScript / Captcha), cookie-TTL input (1..=604800),
  and mode-specific controls. JavaScript mode surfaces the PoW
  difficulty slider (14..=22) with live "expected median solve
  time" hint text that matches the scale table in the design doc
  — the slider value flips the hint between "~50 ms", "~800 ms
  (~2 s on mobile)", "~12 s (UX degraded on mobile)" so the
  operator sees the friction-vs-bot-cost trade without reading
  the spec. Captcha mode surfaces the alphabet editor with the
  curated default pre-filled. Bypass editor has three sub-sections:
  IP CIDRs (comma-separated), countries (ISO alpha-2), User-Agent
  regexes (newline-separated because commas legitimately appear
  in regex syntax); `only_country` inverse gate below. ASN and
  rDNS bypass deferred-to-follow-up status surfaced inline. Form
  state + API mapping wired in `lib/route-form.ts` + `lib/api.ts`
  (new `BotProtectionConfig` / `BotProtectionMode` / `BotBypassRules`
  types). 178 frontend tests PASS, `svelte-check` clean
- **Bot-protection verdict cache** (v1.4.0 Epic 3, story 3.6).
  Per-process DashMap cache of (route_id, IP prefix, cookie hash)
  → expires_at. `evaluate()` checks the cache BEFORE re-running
  HMAC-SHA256 verify; a hit short-circuits at ~50 ns vs ~1 µs for
  the full verify. Cached entries carry the cookie's own
  `expires_at` so a stale cache entry cannot extend a cookie past
  its TTL. FIFO-bounded at 16 384 entries matching the existing
  `forward_auth` cache shape. Four unit tests cover
  hit-skips-verify, expired-entry-is-miss, key-differs-per-scope,
  and FIFO eviction at capacity. Cross-worker sharing via
  `VerdictCacheEngine::Rpc` evaluated and deferred to a follow-up
  (the HMAC verify is fast enough that an RPC hop would be a net
  loss)
- **Bot-protection metrics + OTel span attributes** (v1.4.0 Epic
  3, story 3.7). New Prometheus counter
  `lorica_bot_challenge_total{route_id, mode, outcome}` with
  outcome ∈ { shown / passed / failed / bypassed }. Fires from
  every terminal decision point: the evaluator (passed on valid
  cookie, bypassed on bypass-category or only_country-miss),
  `serve_challenge` (shown on the HTML / plain-text render,
  passed on Cookie-mode's immediate verdict issuance),
  `handle_solve` (passed on successful verify, failed on
  wrong answer / expired nonce). Routes without bot_protection
  never touch the counter. Three new fields on the per-request
  `http_request` OTel span — outcome, mode, reason — finer
  granularity than the Prometheus labels so Jaeger / Tempo can
  break down the `bypassed` bucket per reason without inflating
  Prometheus cardinality
- **Bot-protection HMAC secret lifecycle** (v1.4.0 Epic 3, story
  3.5a). New `apply_bot_secret_from_store` hook in `lorica::reload`
  that runs inside every `reload_proxy_config*` entry point.
  First-boot path: reads the persisted hex secret from
  `GlobalSettings.bot_hmac_secret_hex`; generates + persists a fresh
  32-byte secret via `lorica_challenge::secret::generate` if the
  column is empty or malformed (log at info! / warn!). Subsequent
  reloads read the same hex, dedup via an in-memory snapshot, and
  install via `secret::rotate` when it changes (enables the
  cert-renewal rotation path that lands in story 3.8 without any
  further plumbing). Hex parse + encode helpers are private to
  the reload module because the wire format is a library-internal
  contract. `lorica` now depends on `lorica-challenge` + `sha2 0.10`
  for the request-filter integration that lands in 3.5c
- **Bot-protection evaluator + in-process challenge stash** (v1.4.0
  Epic 3, story 3.5c — foundations). New `lorica::bot` module with
  two concerns: (a) `BotEngine`, a `parking_lot::Mutex<HashMap>`
  stash for pending PoW and captcha challenges with
  `fresh_nonce` (16-byte hex via `OsRng`), `insert` (overwrite-on-
  collision — 2^-128 collision probability makes the branch
  unobservable in practice), `take` (atomic remove + return, so a
  single challenge can be verified at most once — replay defence),
  `captcha_image` (read-only PNG lookup that does NOT consume the
  entry, so a user can reload the image without losing the
  challenge), and `prune_expired`; (b) `evaluate`, a pure-logic
  decision function with signature `EvalInputs -> Decision` that
  walks the bypass matrix in strict order per the design doc §
  6.3 — verdict cookie check (with route+IP-prefix scope
  validation), IP CIDR, country, User-Agent regex, then the
  `only_country` inverse gate. Returns `Decision::Pass {
  reason: PassReason }` or `Decision::Challenge`. The `PassReason`
  variants are wired up for the Prometheus counter that lands in
  story 3.7. URL-path routing helpers `is_bot_solve_path` /
  `parse_bot_captcha_path` recognise the two Lorica-handled bot
  endpoints with query-string tolerance and path-traversal
  rejection. 16 unit tests cover the cookie-scope guards (wrong
  route id, wrong IP prefix, both reject), the bypass-matrix
  ordering, the `only_country` gate in the three states (match,
  miss, country unknown), engine stash semantics (round-trip,
  take-consumes, prune-expired, captcha-image-never-consumes),
  URL-path parsing, and cookie extraction across whitespace
  variants. Actual wiring into `proxy_wiring::request_filter` is
  the next logical commit
- **v1.4.0 scope: ASN + rDNS bypass deferred** (v1.4.0 Epic 3,
  story 3.5b). `bot_protection.bypass.asns` and
  `bot_protection.bypass.rdns` both require significant
  infrastructure that did not land in v1.4.0 (ASN database +
  resolver for the former; a forward-confirmation DNS pipeline for
  the latter — an rDNS match without forward-confirm is a
  documented backdoor). The API validator now rejects non-empty
  lists for both categories with a clear error message pointing
  at the "tracked as a follow-up" status. Fields remain in
  `BotBypassRules` so the follow-up stories ship without a schema
  migration. Three out of five bypass categories are fully
  functional for v1.4.0: `ip_cidrs`, `countries`, `user_agents`
- **Bot-protection `request_filter` session wiring** (v1.4.0 Epic
  3, story 3.5d). New `lorica::proxy_wiring::bot_handlers` submodule
  carries the three session-interactive handlers + form / cookie /
  response helpers. `request_filter` now intercepts the two
  Lorica-handled cross-cutting URLs early (right after the ACME
  challenge): `POST /lorica/bot/solve` goes to `handle_solve`
  (body read bounded at 2 KiB, form parse, take stashed entry,
  dispatch by mode, verify, mint verdict cookie bound to stashed
  route_id + IP prefix, 302 to the stashed return URL), and
  `GET /lorica/bot/captcha/{nonce}` goes to
  `handle_captcha_image` (PNG lookup + one-shot `Cache-Control:
  no-store, private` so no proxy caches the short-lived image).
  After the GeoIP stage, every route with `bot_protection` is
  evaluated via `crate::bot::evaluate`: Pass → request forwards;
  Challenge → `serve_challenge` renders the mode-specific page,
  stashes the pending entry (PoW difficulty / captcha expected
  text + PNG bytes), and writes the HTML (or plain-text 403 when
  the Accept header does not advertise `text/html`, so curl / wget
  see a line instead of a blob of HTML). Cookie-mode is special:
  no server-side stash + no solve round trip, the page IS the
  verdict issuance (meta-refresh bounces + Set-Cookie header).
  Form parsing is a 50-line local implementation of
  application/x-www-form-urlencoded (percent decode + `+` as
  space + skip-malformed) — no new dependency. `Set-Cookie`
  header includes `HttpOnly`, `SameSite=Lax`, `Max-Age`, `Path=/`;
  `Secure` is deliberately omitted for dev-HTTP deployments and
  can become per-route in a follow-up. 9 new unit tests cover the
  form parser (percent, plus-as-space, malformed, truncated
  escapes), Accept-HTML detection, cookie header shape, and
  hex ↔ 16-byte round-trips
- **Bot-protection HMAC secret lifecycle** (v1.4.0 Epic 3, story: three groups (`otel_traceparent`, `otel_active_span`, `otel_per_request`) cover the six atomic operations that every request touches (parse valid / malformed traceparent, synthesise from request_id, derive child traceparent, serialise wire format, span creation / is_recording / end / set_str / set_i64 / set_status) plus two end-to-end scenarios that aggregate the full OTel touch-points a single request incurs. Runs under both default and `--features otel` so operators can quantify the cost of compiling the feature in without installing a real provider. Reference numbers (Docker `rust:1-bookworm`, bench profile, 30-sample criterion run): `parse_valid` 77 ns / 76 ns (-0.8 % under `otel`), `parse_malformed` 31 ns / 29 ns (-5.6 %), `synthesise_from_request_id` 140 ns / 150 ns (+7.0 %), `child_from_parent` 123 ns / 132 ns (+7.8 %), `to_header_value` 99 ns / 91 ns (-9.0 %), `empty_construction` 23 ps / near-ZST. Aggregate per-request OTel touch-point budget stays under 500 ns with the feature off (W3C parse + child + serialise + ZST span ops) and under 600 ns with the feature on but no provider installed — well within the ROADMAP-stated "< 2 % proxy overhead at sampling 0.1" target. Exercised by CI as part of the standard bench harness (criterion 0.5) alongside the existing `circuit_breaker` and `canary_bucket` benches

## [1.3.0] - 2026-04-14

### Added

- Native daily rotation + 14-file retention on the structured tracing log file (`--log-file` path). Switched `tracing_appender::rolling::never()` to `RollingFileAppender::builder().rotation(DAILY).max_log_files(14)` so an unattended install can no longer fill the disk via the JSON log stream. Today's log keeps the operator-configured filename; rotated files are date-suffixed (`lorica.log.2026-04-13`). Falls back to non-rotating append (with a stderr warning) if the builder rejects the path so a misconfigured log destination never blocks startup. External logrotate is no longer required
- Default static error pages (Cloudflare-style three-tier diagnostic layout) for every status Lorica surfaces directly: 408 (slowloris), 429 (rate limit), 403 (WAF / IP ban / blocklist / allowlist / denylist / WebSocket disabled), 495/496 (mTLS), 500/502/503/504/522 (proxy + origin). Renders a header band (title + Wikipedia link + UTC timestamp), a diagnostic strip with You / Network / Host icons and a per-status badge marking the failing tier (down-arrow notch under the broken hop), a two-column "What happened? / What can I do?" explanation, and a footer with the Request ID for log correlation. Anti-fingerprint: no proxy product name, no version, no hostname leak; the Host tier label is the request's `Host` header (already known to the requester) and is HTML-escaped. Per-route `error_page_html` override (with `{{status}}` / `{{message}}` substitution) takes precedence when configured. Wired into `fail_to_proxy`, the maintenance 503, the per-route + global max-connections 503s, the token-bucket and legacy 429 rate limiters, the mTLS 495/496 gate, the slowloris 408 reject, the WAF block 403 (request and body), the WebSocket-disabled 403, the per-route IP allowlist/denylist 403s, the pre-route IP ban + IP blocklist 403s, and the forward-auth fail-closed 503. Pre-route stages (global conn limit, IP ban, IP blocklist) always render the default page since no route override is consultable at that stage. Retry-After / X-RateLimit-Reset headers are preserved on 429 responses
- `/metrics` pull-on-scrape over pipelined RPC (WPAR worker-parity audit, Phase 6 / WPAR-7): Prometheus scrapes now trigger a fresh fan-out to every worker via the pipelined RPC channel before the handler reads the aggregated state. Each worker responds with a `MetricsReport` payload carrying per-request counters (cache_hits / cache_misses / active_connections / ban_entries / EWMA scores / backend connections / per-route request counts / WAF counts); the supervisor aggregates into `AggregatedMetrics` and the scrape encodes it. Dedup via an `Instant`-based lock collapses concurrent scrapes within a 250 ms window into a single fan-out - scraping /metrics from five concurrent Prometheus servers only hits the workers once. Per-worker 500 ms timeout bounds the fan-out; non-responders fall back silently to the cached state (populated by the existing periodic-pull task), so a stuck worker cannot stall a scrape. A 1 s wall-clock watchdog wraps the refresher call in the handler as a last resort. See design § 7
- Forward-auth verdict cache over pipelined RPC (WPAR worker-parity audit, Phase 4 / WPAR-2): `VerdictCacheEngine::Rpc` routes lookup/push through the supervisor in worker mode, so an Allow verdict cached by one worker is served from every worker's hot path on subsequent requests and a session revocation invalidates the cache uniformly across the pool. Single-process mode keeps the per-process `FORWARD_AUTH_VERDICT_CACHE` static unchanged. RPC wire is extended with `ForwardAuthHeader` so cached Allow outcomes can serve the injected upstream headers (Remote-User, Remote-Groups, ...) without a second round trip to the auth backend. Transport failure degrades gracefully: a failed lookup RPC falls through to the upstream auth call (fail-open semantics match the single-process lazy-eviction path); a failed push is fire-and-forget so the downstream request still completes. Supervisor-side cache preserves the existing `FORWARD_AUTH_VERDICT_CACHE` semantics (16 384-entry FIFO, per-route partitioning via NUL-separated key, only Allow verdicts cached, Cache-Control: no-store honored). See `docs/architecture/worker-shared-state.md` § 7
- Circuit-breaker over pipelined RPC (WPAR worker-parity audit, Phase 5 / WPAR-3): `BreakerEngine::Rpc` replaces the per-worker `CircuitBreaker::is_available` / `record_failure` / `record_success` with async `admit()` / `record()` calls that delegate to a supervisor-owned state machine. The supervisor tracks `Closed` / `Open` / `HalfOpen(in-flight probe)` per `(route_id, backend)` so a HalfOpen probe slot is allocated atomically across workers (no two workers can each believe they hold the probe at the same time), and a failure on one worker trips the breaker for every worker. `BreakerDecision` is tri-state: `Allow` (Closed), `AllowProbe` (HalfOpen slot granted), `Deny` (Open). Workers remember a probe-admitted backend on the per-request `ProxyCtx.breaker_probe_backend` so the subsequent outcome report is flagged `was_probe=true`, letting the supervisor close the breaker on probe success or bounce back to Open on probe failure. Transport error fails open so a flaky supervisor channel never DoS's the data plane. Single-process mode keeps the in-process `CircuitBreaker` unchanged under `BreakerEngine::Local`. See design § 7
- Two-phase config reload over pipelined RPC (WPAR worker-parity audit, Phase 7 / WPAR-8): `ConfigReloadPrepare` + `ConfigReloadCommit` replaces the legacy one-shot `CommandType::ConfigReload` on the legacy UDS channel. The Prepare half (2 s timeout, slow path: SQLite read + `ProxyConfig::from_store` + wrr_state preservation + mTLS fingerprint drift detection) runs concurrently on every worker; the Commit half (500 ms timeout, fast path: single ArcSwap) publishes atomically on all workers at once. The divergence window across workers collapses from ~10-50 ms (synchronous reload per worker on legacy channel) to the UDS RTT (microseconds). Per-worker `GenerationGate` enforces monotonicity: a reordered stale Prepare is rejected (`observe`), a commit for a non-matching generation is rejected while the prepared slot is preserved (`observe_commit`). Supervisor coordinator fans out both phases via `coordinate_config_reload`; on Prepare failure the legacy broadcast fallback fires so a partial RPC regression never stalls a config rollout. A worker with no RPC channel yet registered (early supervisor startup) also falls through to the legacy broadcast. See design § 7
- Per-route rate limiting (WPAR worker-parity audit, Phase 3): new `rate_limit: { capacity, refill_per_sec, scope }` config field on `Route` exposes a per-route token-bucket limiter applied after ban-list / IP-blocklist / redirect checks but before mTLS / forward-auth / WAF (cheap rejection of abusive clients before expensive evaluation). `scope: per_ip` (default) creates one bucket per (route, client IP) - isolates abusive clients without penalising the rest; `scope: per_route` creates a single shared bucket for the route - caps aggregate traffic to a fragile origin. Rejected requests return `429 Too Many Requests` with a `Retry-After` header computed from the refill rate. Dashboard: three new inputs under the Protection tab (capacity, refill/s, scope dropdown). API validates `capacity` and `refill_per_sec <= 1_000_000` to prevent `u32::MAX` overflow. Schema migration V33. Built on the `lorica_limits::token_bucket` primitives (Mutex-guarded authoritative bucket with fixed-point 1e6-scale tokens, lazy time-based refill, clock-rewind-is-noop). In multi-worker mode (`--workers N >= 1`) the supervisor holds the authoritative bucket registry and workers keep CAS-based `LocalBucket` caches that sync every 100 ms over a dedicated pipelined RPC socketpair (separate from the legacy command channel). Aggregate admission is bounded at `capacity + 100 ms × N_workers × refill_per_sec` worth of tokens - the design's documented initial-tick over-admission (§ 6) - after which workers converge on the authoritative state
- WAF auto-ban counter migrated to shared memory (WPAR worker-parity audit, Phase 3): per-IP violation counting moved from the supervisor-local DashMap (fed by UDS WAF-event forwarding) to the `lorica-shmem` `waf_auto_ban` atomic hashtable. Workers increment the cross-worker counter directly on each WAF block; the supervisor reads the counter, compares against the configured threshold, and on first crossing broadcasts `BanIp` to all workers then CAS-resets the slot so the next round starts at zero. Eliminates the dashmap/shmem/UDS triple-source skew and gives identical accounting across the pool. Single-process mode keeps the existing per-process fallback path unchanged. See `docs/architecture/worker-shared-state.md` § 5-6
- `lorica-shmem` crate (WPAR worker-parity audit, Phase 2): anonymous memfd-backed shared-memory region for cross-worker atomic counters. `SharedRegion` holds two 128 Ki-slot open-addressing hashtables (`waf_flood`, `waf_auto_ban`) used by WPAR-1 for per-IP flood and auto-ban counts. Each slot is a 64-byte cache line carrying three independent `AtomicU64` fields (key, value, last_update_ns); no seqlock - readers consume `value` with a single atomic load and writers race on commutative `fetch_add`, so there are no torn reads regardless of writer concurrency. Linear probing up to `MAX_PROBE = 16` with a `SATURATED = u64::MAX` sentinel for chain exhaustion (fail-safe: WAF treats saturation as "limit reached"). SipHash-1-3 with a 128-bit supervisor-randomized key (via `getrandom`) prevents an attacker from crafting IPs that collide into the same probe chain. `memfd_create(MFD_CLOEXEC)` + `mmap(MAP_SHARED)`; the supervisor passes the fd to each worker at fork via the existing SCM_RIGHTS machinery. Magic number (ASCII "LORICASHM") and `layout_version` verified on worker open. Synchronous `evict_once(region, now_ns, stale_after)` primitive called by the supervisor's eviction loop; CAS-based slot release leaves `value` / `last_update_ns` for the next claim to reset. 24 unit tests plus 5 fork-based multi-process integration tests (disjoint-key no-crosstalk, same-key commutative-sum, siphash-key shared across children, SIGKILL survivor sanity, probe-chain saturation). See `docs/architecture/worker-shared-state.md` § 5
- `lorica-command` pipelined RPC framework (WPAR worker-parity audit, Phase 1): new `RpcEndpoint` demultiplexes concurrent in-flight requests on a single Unix socket via a background reader task and a per-sequence in-flight map, with a bounded outbound queue (capacity 256) that backpressures through a per-request timeout rather than growing unbounded. In-flight entries are removed on every exit path (Ok, Closed, Timeout) so dead senders cannot linger. Adds an `Envelope` wire frame that carries either a `Command` or a `Response` (required because the two shared leading prost tags), new `CommandType` variants for the upcoming WPAR RPCs (`RateLimitQuery/Delta`, `VerdictLookup/Push`, `BreakerQuery/Report`, `ConfigReloadPrepare/Commit`), typed payload oneofs on `Command` and `Response`, tri-state `BreakerDecision` (`Allow`/`Deny`/`AllowProbe`) per the supervisor-owned HalfOpen-probe model, a `Coalescer<K,V>` dedup primitive with TTL-bounded caching for the upcoming `/metrics` fan-out, and a `GenerationGate` atomic watermark enforcing strictly increasing reload generations. 37 unit tests including concurrency, adjacent-request isolation, peer-drop cleanup, and high-volume pipelining. See `docs/architecture/worker-shared-state.md` § 4
- Connection pre-filter: IP allow/deny CIDR policy enforced at TCP accept, before TLS handshake. Configurable via new `connection_allow_cidrs` and `connection_deny_cidrs` `GlobalSettings` fields; editable in the dashboard Settings tab. Deny always wins; a non-empty allow list switches the filter to default-deny. Hot-reloaded via arc-swap - listener-state stays consistent without rebuilding endpoints, in both single-process and worker modes
- Cache predictor: shared 16-shard LRU (32K keys total) remembers cache keys whose origin responded uncacheable (OriginNotCache, ResponseTooLarge, or user-defined custom reason) and short-circuits the cache state machine on the next request. Reduces cache-lock contention and variance-key computation on known-bypass traffic. Transient errors (InternalError, UpstreamError, storage failures, lock timeouts) are not remembered
- Cache Vary support: per-route `cache_vary_headers` partition the cache by request header values (e.g. Accept-Encoding, Accept-Language) so different clients get separate cache entries under the same URL. Merged with the origin's `Vary` response header so both operator config and RFC 7234 semantics take effect. `Vary: *` anchors the variance on the request URI to keep cache cardinality bounded. Editable in the dashboard Caching tab. Schema migration V25 adds the column with a default of `[]`
- Header-based routing: per-route `header_rules` select a specific backend group based on a request header's value. Supports Exact, Prefix and Regex match types with regex compiled once per route at load time (a malformed regex disables only that rule, never the whole route; the dashboard flags disabled rules with a red badge so operators can republish). Evaluated before path rules so a path rule with its own `backend_ids` can still override. Enables A/B testing (`X-Version: beta`), multi-tenant routing (`X-Tenant: acme`), and similar content-negotiation patterns without touching upstream URLs. New dashboard Header Rules tab. Schema migration V26 adds the column with a default of `[]`
- Canary traffic split: per-route `traffic_splits` send a configurable percentage of requests to alternate backend groups. Assignment is sticky per client IP via a deterministic hash of `(route_id, client_ip)`, so a given user stays on the same version across requests on the same route. Splits are evaluated AFTER header rules (explicit opt-in wins) and BEFORE path rules (URL-specific overrides still win). Dangling backend IDs are logged at load time but consume their weight band (falling back to route defaults) rather than silently rebalancing traffic to the next split. API rejects weight > 100 or cumulative > 100, and non-zero weight with empty backends. New dashboard Canary tab with total-weight summary. Schema migration V27
- Forward authentication: per-route `forward_auth` gates every request through an external authentication service (Authelia, Authentik, Keycloak, oauth2-proxy) before reaching the upstream. The standard `X-Forwarded-*` header set (Method, Proto, Host, Uri, For) plus Cookie, Authorization and User-Agent are sent verbatim to the auth service; 2xx returns allow the request (optional `response_headers` are harvested and injected into the upstream, e.g. `Remote-User`); 401/403/3xx responses are forwarded to the client verbatim (critical for Authelia's login-redirect flow); timeout or connection failure fails closed with 503. Evaluated after route match and WAF but before any backend selection so denied requests never touch the upstream. API validates URL scheme (http/https), host presence, timeout range (1..60000 ms), and non-empty response-header names; a warn log fires when the scheme is `http://` and the host isn't loopback so operators know credentials will traverse cleartext. Optional per-route verdict cache via `verdict_cache_ttl_ms` (default 0 = off, API-capped at 60 s): `Allow` verdicts are cached keyed on the NUL-separated `{route_id}\0{cookie}` literal (no truncated-hash collision surface), honors the auth service's `Cache-Control: no-store` / `no-cache` directives, 16 384-entry bounded FIFO so a cookie-flood attack can't exhaust memory. `Deny` / `FailClosed` are never cached. Dashboard exposure in the Security tab. Schema migration V28
- Request mirroring (shadow testing): per-route `mirror` duplicates requests to one or more secondary backends for A/B validation and shadow testing. Fire-and-forget via a shared reqwest client with redirects disabled and a 256-slot global concurrency semaphore - a saturated or dead shadow never impacts the primary request. Sampling is deterministic per `X-Request-Id` so retries of the same request land on the same mirror decision. Mirror requests carry `X-Lorica-Mirror: 1` so shadow backends can filter the traffic from their own metrics. Request bodies on POST/PUT/PATCH are forwarded in full up to a configurable `max_body_bytes` cap (default 1 MiB, max 128 MiB, 0 = headers-only); requests whose body exceeds the cap are sent to the primary normally but skipped for mirroring (a truncated body would mislead the shadow). Trust model: shadow backends receive Cookie / Authorization / session headers verbatim (matching Nginx `mirror`, Traefik `Mirroring`, Envoy `request_mirror_policies`), so shadows must be deployed in the same trust boundary as the primary - the `X-Lorica-Mirror: 1` marker is for log/metric filtering, not a security boundary. API validates non-empty/deduplicated backend list, sample_percent 0..=100, timeout 1..60000 ms, and max_body_bytes ceiling. Dashboard exposure in the Security tab. Schema migration V29
- Stale-while-revalidate background refresh: when a cached entry is past its TTL but within the route's `stale_while_revalidate_s` window, the proxy now serves the stale body to the client immediately and spawns a background sub-request that fetches fresh content from the upstream, updates the cache, and releases the write lock. The next request sees the refreshed entry without a round-trip. Built on Pingora's `SubrequestSpawner` + the existing cache-lock infrastructure; `response_cache_filter` already emits the SWR/SIE durations on the `CacheMeta`. Past the SWR window, stale hits fall back to synchronous revalidation as before
- Response body rewriting (Nginx `sub_filter` equivalent): per-route `response_rewrite` applies an ordered list of search-and-replace rules to upstream response bodies before they reach the client. Supports literal patterns (default) and regex with capture-group substitution (`$1`, `$2`). Rules compose (each rule runs on the output of the previous one). Only text-ish content is rewritten - configurable `content_type_prefixes` (default `text/`); compressed responses (`Content-Encoding: gzip/br`) pass through unchanged to avoid corrupting the stream. Bodies exceeding `max_body_bytes` (default 1 MiB, cap 128 MiB) stream through verbatim rather than emit a partial rewrite. Cross-chunk patterns are caught because the engine buffers the full body before running rules. `Content-Length` is automatically dropped on rewritten responses (new length differs from origin). API validates regex compilability at write time, non-empty patterns, and bounded limits. Schema migration V30 adds `routes.response_rewrite TEXT` as nullable JSON. Dashboard: dedicated "Rewrite" tab with per-rule reorder/expand UX. HEAD responses, 1xx/204/304 statuses, and cache-enabled routes are skipped (the last is mutually exclusive with rewriting in v1 and is surfaced via a warn log)
- mTLS client verification: per-route `mtls` requires connecting clients to present an X.509 certificate signed by the configured CA bundle and, optionally, constrains which certificate subject organizations are allowed. The TLS handshake verifier is built at listener startup from the union of all per-route CAs (via rustls `WebPkiClientVerifier` with `allow_unauthenticated`), so different routes on the same listener can have different policies. Per-request enforcement runs before forward_auth: `required = true` with no client cert returns 496 ("SSL certificate required"), a presented cert whose O= isn't in `allowed_organizations` returns 495 ("SSL certificate error"). Rustls `ServerConfig` is immutable after build, so changes to `ca_cert_pem` require a restart; toggling `required` and editing `allowed_organizations` hot-reload. API validates PEM decodability, presence of at least one CERTIFICATE block, X.509 DER integrity, a 1 MiB bundle cap, and dedup/non-empty entries in the organization allowlist. Schema migration V31 adds `routes.mtls TEXT` as nullable JSON. Dashboard exposure in the Security tab
- Prometheus counters for every v1.3.0 feature with non-trivial activity, exposed on the existing `GET /metrics` endpoint: `lorica_cache_predictor_bypass_total{route_id}`, `lorica_header_rule_match_total{route_id, rule_index}` (with `rule_index = "default"` for fallthrough), `lorica_canary_split_selected_total{route_id, split_name}` (with `"default"` / `"unnamed"` labels), `lorica_mirror_outcome_total{route_id, outcome}` (outcomes: `spawned`, `dropped_saturated`, `dropped_oversize_body`, `errored`), `lorica_forward_auth_cache_total{route_id, outcome}` (outcomes: `hit`, `miss`). Cardinality is bounded by route count - no user-input-derived labels
- Supervisor -> worker pipelined-RPC Prometheus counter (`lorica_supervisor_rpc_outcome_total{kind, outcome}`): one counter spanning `metrics_pull` / `config_reload_{prepare,commit,abort}` with `ok` / `timeout` / `error` outcomes. Lets ops tell apart "all workers slow on Prepare" (DB contention) from "one worker stuck on metrics pull" (downstream issue)
- Config-validation endpoints to shorten the save-fail-retry loop when configuring auth and mTLS: `POST /api/v1/validate/mtls-pem` parses a candidate CA PEM and returns the per-cert subjects so operators can confirm their bundle before committing; `POST /api/v1/validate/forward-auth` issues one GET to a candidate auth URL and reports status, elapsed time, and a whitelisted subset of response headers (Location, Remote-User, Remote-Groups, Remote-Email, Content-Type). Surfaced in the dashboard Security tab as inline "Validate PEM" / "Test connection" buttons

### Changed

- `sla_purge_enabled` global setting now defaults to `true` (was `false`). Bounds disk usage out of the box: the existing `sla_purge_retention_days` (90 days) and `sla_purge_schedule` ("first_of_month") apply automatically on fresh installs. Operators who need full SLA history can opt out via the dashboard Settings tab. Existing installations keep their stored value; only fresh installs and configs that omit the field pick up the new default
- Circuit breaker now scopes state by `(route_id, backend)` instead of by backend alone. Two routes that share the same upstream IP:port (common when a single Teleport / nginx front-door multiplexes several virtual hosts on one port) no longer punish each other: failures on one route open the breaker only for that route, leaving sibling routes routable to the same physical backend
- Response body rewriting: compiled rules are now resolved once in `response_filter` and stored on the per-request context, replacing a linear scan of all routes that previously ran on every body chunk. Per-chunk overhead is a pointer clone regardless of route count
- Basic auth credential cache keys are now the raw NUL-joined `"{credential}\0{hash}"` string instead of a 64-bit `DefaultHasher` digest. Two distinct credentials can no longer collide on a truncated hash and share a cache slot (same design as the forward auth verdict cache)
- Forward auth `X-Forwarded-Proto` is now derived from the TLS socket state (`ssl_digest`) instead of HTTP version. h2c (HTTP/2 over plaintext) would previously be reported as `https` to the auth service
- `canary_bucket` now uses FNV-1a with fixed constants instead of `DefaultHasher` (which seeds a random `RandomState` per process). Canary assignments are now stable across restarts and rolling upgrades: the same client IP lands on the same bucket on the new process as on the old one, so a rollout does not silently reshuffle which users see the canary
- `RouteEntry` is now stored as `Arc<RouteEntry>` in `ProxyConfig` and the matched entry is cached in the per-request context during `request_filter`. `upstream_peer` no longer re-runs `find_route` on the same request; the entry is reused as a pointer clone
- Canary / header-rule / path-rule overrides remain strictly fail-closed when all of their backends are breaker-open or unhealthy (502 rather than fallback to route defaults). Documented explicitly in `upstream_peer` so operators know a bad canary surfaces as a visible error on the fraction of traffic routed to it, not as silent absorption by the primary
- Email notification channel update: the masked-password restore path now rejects the request with a clear error when the stored config is missing, unparseable, or carries no `smtp_password`. Prior code silently fell through and persisted the literal `"********"` mask back to the database, erasing the real SMTP password
- Custom WAF rule compilation now caps both the raw pattern length (4 KiB) and the compiled NFA/DFA size (512 KiB) via `RegexBuilder::size_limit`. An authenticated admin submitting a pathological alternation can no longer stall the management API thread or balloon memory during hot-reload. Runtime matching was already linear via the `regex` crate; this closes the compile-time surface
- Pinned `rustls-pemfile = "=2.1.2"` in `lorica` and `lorica-tls` to keep the workspace off the 2.2.0 line flagged unmaintained by RustSec (RUSTSEC-2025-0134). The unmaintained API is not used; pinning is precautionary while rustls upstream lands the in-tree replacement
- E2E Docker harness (`tests-e2e-docker/`) now runs as the non-root `lorica` user end-to-end. The entrypoints no longer need `su` to drop privileges because the exposed ports (9443/8080/8443) are above 1024 and `CAP_NET_BIND_SERVICE` is not required
- Bumped `dashmap 5.5.3 -> 6.1.0` across `lorica`, `lorica-api`, `lorica-limits`; 5.x had iterator-invariant unsoundness fixed in 6.x (supply-chain audit SC-M-1, SC-M-4)
- Bumped `tokio-tungstenite 0.20.1 -> 0.29.0` in `lorica-proxy` to drop a duplicated websocket frame parser and pull in fuzzer-driven fixes (supply-chain audit SC-M-2)
- Bumped `brotli 3 -> 8` in `lorica-core` (supply-chain audit SC-L-1); API source-compatible for Lorica's `CompressorWriter` / `DecompressorWriter` usage
- `lorica-api` feature `route53` flipped to off by default (supply-chain audit SC-M-3). Non-Route53 deployments no longer ship the `aws-smithy-http-client` dep graph that drags `rustls 0.21` + `hyper 0.14`. Users of ACME DNS-01 via Route53 build with `cargo build --release --features route53`. BREAKING for downstream packagers who relied on the default feature
- Inlined `no_debug` (was `no_debug = "3.1.0"` unmaintained single-file crate, supply-chain audit SC-L-3) as `lorica-tls::no_debug` module. Dropped the dep; public API preserved via `pub use crate::no_debug::{...}`
- Dropped `daemonize = "0.5"` dep (RUSTSEC-2025-0069, unmaintained). Production Lorica runs under `systemd Type=simple`; legacy `--daemon` flag now emits a warning and falls through to foreground execution. BREAKING only for operators who relied on `--daemon` outside systemd (a non-use-case in practice)
- CI: new `Semgrep (security)` job running 7 `p/*` rulesets + `trailofbits/semgrep-rules` (generic / javascript / rs / yaml), non-blocking with SARIF upload as PR artifact. Closes the original `p/bash` / `p/yaml` / `p/sql` coverage gap (audit round 1 identified them as 404 on the registry)
- CI: new `Frontend lint` step running `svelte-check` + `eslint-plugin-svelte` (flat config with `svelte/no-at-html-tags` + `svelte/no-target-blank` + `no-eval` family). Regression guard for the Svelte XSS manual audit pass (audit coverage gap)
- Split `lorica/src/proxy_wiring.rs` from 8 561 LOC down to 4 170 LOC (-51 %) as audit M-8 follow-up. Tests block (~3 k LOC) moved to `proxy_wiring/tests.rs`; RPC dispatch enums (BreakerAdmission / BreakerEngine / VerdictCacheEngine / RateLimitEngine) moved to `proxy_wiring/engines.rs`; forward-auth + verdict-cache to `proxy_wiring/forward_auth.rs`; mirror + response-rewrite to `proxy_wiring/mirror_rewrite.rs`; pure helpers (sanitize_html, mTLS, canary, cache vary, header rules) to `proxy_wiring/helpers.rs`. All re-exported via `pub use` so the existing `lorica::proxy_wiring::*` import path is preserved. No functional change

### Fixed

- Worker auto-respawn race during supervisor shutdown: the worker monitor task (which detects crashed workers and respawns them) blocks on a `std::sync::Mutex` shared with the supervisor's shutdown path. `monitor_handle.abort()` cannot fire while the monitor is parked on that mutex (abort only takes effect at the next `.await`), and `manager.shutdown_all()` holds the mutex synchronously for the full ~30 s drain. When `shutdown_all` releases the mutex after SIGKILL'ing stragglers, the monitor unblocks, sees those workers as crashed, and respawns them BEFORE reaching the loop's next `sleep().await` cancellation point. The freshly forked workers get SIGTERM ms later, can't drain in time, and systemd ends up SIGKILL'ing the whole service group past `TimeoutStopSec`. Fix: introduce a `shutting_down` `AtomicBool`. The supervisor sets it before `shutdown_all` (and still calls `monitor_handle.abort()` as a backstop). The monitor checks the flag both before and after acquiring the mutex; on the post-acquire check it returns early without restarting any worker, regardless of how long it waited for the mutex
- Worker RPC listener hang on supervisor shutdown: `RpcEndpoint::Inner::drop` did not actually abort the reader + writer tokio tasks (dropping a `JoinHandle` is detach, not abort), so a dropped endpoint kept its socket halves alive and the peer never saw EOF. Worker shutdown then hung past the 10 s `TaskTracker` drain. Fix: `Inner::drop` now calls `handle.abort()` on both tasks. Regression test `reload_listener_drains_on_supervisor_eof` asserts completion within 5 s
- `SupervisorBreakerRegistry` stale-probe deadlock (audit H-1): if the probe-admitted worker crashed between admit and report, the breaker entry was pinned in `HalfOpen { probe_in_flight: true }` forever and every subsequent query for that `(route, backend)` returned Deny until supervisor restart. `HalfOpen` now carries `probe_started_at: Option<Instant>`; on the next query observing `elapsed >= cooldown` the supervisor synthesises a failed probe, bumps the failure counter, transitions back to Open with a fresh cooldown, and emits a warn log. Regression test `breaker_registry_stale_probe_recovers_after_cooldown`
- `lorica-worker::fd_passing::recv_worker_fds` kernel-FD leak on error paths (audit H-2): the function collected raw `RawFd`s into a `Vec` and returned `Err(...)` on UTF-8 validation / fds-tokens mismatch / bad `FdKind` token without closing them. Received FDs are now wrapped in `OwnedFd` immediately after `recvmsg` so every error path `close(2)`s via the RAII drop. Added `MSG_TRUNC` / `MSG_CTRUNC` detection so silent kernel truncation returns `InvalidPayload` instead of adopting a half-received FD set. Added a compile-time size assertion on `PAYLOAD_BUF_SIZE`
- Two-phase config reload non-atomic `connection_filter` publish (audit H-3): `PendingProxyConfig` now carries the full `reload::PreparedReload` rather than only `Arc<ProxyConfig>`, so the Commit handler calls `commit_prepared_reload(proxy_config, filter, prepared)` which publishes the ArcSwap and the filter CIDR reload together. Prior code re-read the filter separately, opening a short window where ProxyConfig v2 ran against filter v1 on reloads that flipped `connection_allow_cidrs` / `connection_deny_cidrs`. The worker-side RPC listener is now wired with `Some(connection_filter)` at the call site (was `None`)
- `EwmaTracker::record` hot-path allocation (audit M-1): the common case (backend already known) no longer pays for an `addr.to_string()` per request. `get_mut` path + first-sample seeding without the 30 % alpha bias
- TOCTOU in `SupervisorVerdictCache::lookup` + `FORWARD_AUTH_VERDICT_CACHE` expiry eviction (audit M-2 + M-3): a concurrent fresh insert racing with an expiry observation could be evicted by the stale lookup. Replaced with `dashmap::DashMap::remove_if` that evicts only when the entry's `expires_at` still matches the observation
- `handle_rate_limit_delta` mutex contention on first-seen keys (audit M-4): N concurrent `RateLimitDelta` RPCs on a first-seen `{route|scope}` previously serialised on the `store` `tokio::Mutex` for N SQLite reads. Added a supervisor-side `rl_policy_cache` DashMap that caches per-route policy, invalidated on every reload (both the fully-succeeded two-phase commit and the legacy-broadcast fallback)
- Predictable `generate_request_id` IDs (audit M-5): previous implementation used `DefaultHasher(SystemTime::nanos XOR thread_id)`, which is deterministic given inputs and collides on same-nanosecond concurrent same-thread requests. Replaced with `OsRng.fill_bytes(16)` for 128 bits of unpredictable ID
- `ConfigReloadAbort` RPC (audit M-7): new wire-additive `CommandType::ConfigReloadAbort` (tag 14) fanned out to workers that succeeded Prepare when a peer fails; worker drops the pending slot on generation match instead of pinning one orphan `Arc<ProxyConfig>` per worker until the next reload
- `lorica-shmem::now_ns` silent fallback (audit L-1): `clock_gettime` failure now emits a warn log instead of silently returning 0, which would stall eviction without any signal to ops
- `lorica-command::IncomingCommand::reply` debug-assert on caller-supplied sequence mismatch (audit L-3): release builds still overwrite with the originating command's sequence, but wiring bugs that pass a different non-zero sequence now surface in tests
- `generate_random_password` deterministic RNG (audit L-5): replaced `thread_rng()` with `ChaCha20Rng::from_rng(OsRng)` so the first-run admin password pedigree matches `hash_password`'s OS-entropy salt
- `lorica-limits::token_bucket::refill_locked` overflow-defence tightening (audit L-6): added a `debug_assert!` that `refill_per_sec <= 1_000_000` (the API cap) so future regressions surface in tests instead of silently saturating


## [1.2.0] - 2026-04-11

### Added

- Cache lock for thundering herd protection: only one request fetches from upstream on cache miss, others wait for the cached response (10 s timeout)
- Stale-while-error: serve cached responses when upstream fails (60 s) and during background revalidation (10 s), via `should_serve_stale()` hook
- Cache PURGE method: HTTP PURGE requests invalidate cached entries matching the request URI
- gRPC-Web bridge module: transparently converts HTTP/1.1 gRPC-web requests to HTTP/2 gRPC for upstream backends
- Least Connections load balancing algorithm: routes traffic to the backend with the fewest active connections
- HTTP Basic Auth per route: username/password (Argon2id-hashed) with 401 + WWW-Authenticate challenge. Configurable in Security tab
- Maintenance mode per route: returns 503 with Retry-After header and optional custom HTML error page
- Custom error pages: configurable HTML template for upstream errors (502/504) with `{{status}}` and `{{message}}` placeholders, served via `fail_to_proxy()` hook
- Enriched retry policy: `retry_on_methods` field filters which HTTP methods are eligible for retry (e.g. GET, HEAD only), preventing duplicate side-effects on POST/PUT
- Structured log output: `--log-format` CLI option (json/text) and `--log-file` for file output alongside stdout. Propagated to worker processes
- OCSP stapling: automatic OCSP response fetch from CA responder (AIA extension), attached to TLS handshakes via rustls CertifiedKey. Best-effort with warning on failure
- Production Dockerfile: multi-stage build (Node 22 + Rust + Debian slim), non-root user, volume mount at /var/lib/lorica
- Per-route stale cache configuration: `stale_while_revalidate_s` (default 10) and `stale_if_error_s` (default 60) configurable via API and dashboard Caching tab

### Security

- PURGE method restricted to loopback and trusted proxy CIDRs to prevent external cache invalidation
- HTML escape for `{{message}}` placeholder in custom error pages to prevent XSS via crafted upstream error messages
- Basic auth credential verification cache (60 s TTL) avoids Argon2 hot-path overhead on repeated requests

### Changed

- Route struct wrapped in Arc in ProxyConfig to avoid deep-cloning on every request (~300-500ns saved)
- Path rewrite regex wrapped in Arc to avoid compiled NFA/DFA duplication per request
- WAF rule matching uses single `find()` instead of `is_match()` + `find()` (halves regex cost on matches)
- WAF `url_decode` fast path skips decode loop when input has no percent-encoding
- HTML sanitize regexes compiled once at startup via `Lazy<Regex>` instead of per-call

### Fixed

- Per-route IP allowlist/denylist CIDR matching was using string prefix comparison (`starts_with`), which incorrectly matched `10.1.2.3` against `10.1.2.30/24`. Now uses proper network containment via ipnet
- WAF event category filter: filter now applied at SQL level so LIMIT returns correct results when filtering by category (e.g. XSS events were invisible when IP Blocklist dominated the top N rows)
- list_routes() SELECT was missing stale_while_revalidate_s, stale_if_error_s, and retry_on_methods columns, causing maintenance_mode and other v1.2.0 fields to read incorrect values from shifted column indices
- Frontend TypeScript types synchronized with Rust API: WafEvent (route_hostname, action), ProxyInfo (http_port, https_port), GlobalSettings (waf_whitelist_ips), route-form test fixture (v1.2.0 fields)
- Supervisor mutex poison recovery: worker monitor and shutdown no longer panic on poisoned mutex, recover gracefully with warning log
- Encryption key load failure now logs an explicit error instead of silently falling back to unencrypted storage
- Dashboard accessibility: all dialog overlays have Escape key handler, aria-modal, tabindex; all sortable table headers have keyboard Enter handler and role="button"; backdrop has role="presentation"
- Prometheus metric creation uses `expect()` instead of `unwrap()` for better startup diagnostics
- `log_store.rs` `copy_to_sql` handles conversion errors gracefully instead of panicking
- SLA CSV export response builder uses `expect()` instead of `unwrap()`

## [1.1.0] - 2026-04-10

### Added

- Global WAF whitelist IPs in Settings: IPs or CIDRs that bypass WAF evaluation, rate limiting, IP blocklist, and auto-ban entirely. Prevents operators from being auto-banned by false positives (e.g. CMS body content triggering path traversal rules)
- CLI `lorica unban <IP> --password <PASSWORD>` command for emergency IP removal when locked out of the dashboard
- Access logs: configurable entry limit (100/500/1K/5K/10K) and "X of Y entries" total count display
- 12 new WAF rules (49 total): SQLi auth bypass, info schema recon, encoding evasion, NoSQL injection (MongoDB), XSS eval/base64, backup file access, PowerShell/Windows commands, HTTP request smuggling, scanner detection, PHP/Java deserialization, HTTP method abuse
- X-Request-Id header: unique request identifier generated per request, propagated to backends and logged in access logs for end-to-end tracing
- Circuit breaker: per-backend failure tracking that removes backends from rotation after 5 consecutive errors (5xx or connection failures), with 10s cooldown and half-open probe before recovery
- Sticky sessions: cookie-based session affinity per route. When enabled, a `LORICA_SRV` cookie containing the backend ID is set on first request. Subsequent requests are routed to the same backend. Falls back to normal load balancing if the backend is down

### Fixed

- Duplicate access log entries in worker mode: workers now persist logs directly, supervisor only pushes to in-memory buffer for WebSocket streaming
- WAF body scanning false positives: path traversal (930xxx) and protocol violation (920xxx) rules are no longer applied to request bodies, preventing false positives on CMS content containing `..\ ` or similar text
- SLA metrics polluted by proxy-level rejections and connection errors: WAF blocks, bans, rate limits, return_status responses, and upstream/downstream errors (resets, timeouts) are excluded from SLA latency percentiles
- SLA breach notifications not firing in worker mode: supervisor now checks thresholds on every flush cycle regardless of local data, reading SLA metrics flushed by workers
- Access logs: disabling auto-refresh/live toggle did not disconnect WebSocket, choice not persisted across page reloads
- IP blocklist WAF events showing `-` as route when request has no Host header: now falls back to URI authority (IP:port)
- Security page: missing category labels (SSRF, XXE, SSTI, Log4Shell, IP Blocklist, Prototype Pollution) and event filter options
- Client H2 disconnects ("not a result of an error") no longer shown as errors in access logs - status 0 is sufficient
- TCP keepalive on upstream connections (idle 15s, interval 5s, 3 probes) to detect stale/half-closed pooled connections before reuse
- Upstream idle connection timeout (60s) evicts stale connections from the pool
- Upstream keepalive pool auto-sizing at startup: 128 for <= 15 backends, scales to 8 per backend up to 1024 max

## [1.0.0] - 2026-04-09

### Added

**Proxy Engine**

- HTTP/HTTPS reverse proxy built on Cloudflare Pingora with host-based and path-prefix routing, TLS termination via rustls, structured JSON access logging, and configuration hot-reload via arc-swap
- Path rules: ordered sub-path overrides within a route for backends, cache, headers, rate limits, or direct HTTP status responses. First match wins with prefix and exact match types
- Route `redirect_to` field for 301 redirects (www-to-non-www, domain migrations) with automatic path and query string preservation
- Route `return_status` field for direct HTTP status responses (e.g. 403, 404) without proxying
- Catch-all hostname `_` as last-resort fallback when no exact or wildcard match is found
- Path rewriting with strip/add prefix and regex capture groups (linear time, ReDoS-safe)
- Per-backend `h2_upstream` toggle for HTTP/2 upstream (h2c plaintext, ALPN h2 for TLS) enabling gRPC proxying
- Round-robin, Peak EWMA, Consistent Hash, and Random load balancing strategies per route
- Configurable proxy headers, response headers, per-route timeouts, WebSocket passthrough, hostname aliases, force HTTPS redirect, per-route gzip compression and retry attempts
- X-Forwarded-Proto detection via TLS session digest
- SO_REUSEPORT on all proxy listeners for kernel-level connection distribution
- Connection pooling with health-aware backend filtering
- Cookie merge support for upstream responses

**Security**

- WAF engine with 39 OWASP CRS-inspired rules: SQLi, XSS, path traversal, command injection, SSRF (cloud metadata, localhost, internal networks, dangerous URI schemes), Log4Shell/JNDI, XXE, CRLF injection. Detection or blocking mode. Sub-0.5ms evaluation latency
- Custom WAF rules persisted in SQLite, configurable per-rule enable/disable at runtime
- IP blocklist auto-fetched from Data-Shield IPv4 Blocklist (~80,000 entries, O(1) lookup, refreshed every 6h)
- Per-route rate limiting with configurable RPS, burst tolerance, and proper `X-RateLimit-*` response headers
- Auto-ban for IPs exceeding rate limits (configurable threshold and duration), with global supervisor-aggregated counters in multi-worker mode
- Trusted proxies CIDR list for X-Forwarded-For validation, preventing IP spoofing via header injection
- Per-route max connections (503 rejection), global connection limit, adaptive flood defense (auto-halves rate limits under flood)
- Slowloris detection with configurable threshold (408 rejection)
- Security header presets (strict/moderate/none) with custom preset support, IP allowlist/denylist, CORS per route
- Encrypted notification configs and certificate private keys at rest (AES-256-GCM)
- Database file permissions restricted to 0600, encryption key file created atomically with 0600 permissions
- Redacted password hashes in config export; import rejects redacted hashes
- Explicit Argon2id parameters (OWASP-compliant) for password hashing and verification
- Maximum password length (128 chars) to prevent DoS via large Argon2 inputs
- Session invalidation on password change (all sessions except current)
- Per-IP login rate limiting (was global bucket)
- CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy headers on dashboard
- Recursive URL decoding in WAF (max 3 passes) to prevent double-encoding bypass
- WAF request body scanning for SQL injection, XSS, and command injection in POST data (text bodies up to 1 MB, binary payloads skipped)
- DNS server parameter validation before shell command execution
- 10 MB global API request body size limit
- `#![deny(unsafe_code)]` on pure-logic crates (waf, config, notify, bench, api)
- `cargo-deny` configuration for supply chain auditing
- Empty SNI validates full certificate chain (CA, expiration, revocation)
- Load test target URL restricted to localhost to prevent external attacks
- HTTP request smuggling protections tested (CL.TE desync, TE obfuscation, duplicate CL)
- CRL (Certificate Revocation List) support for upstream TLS via `--upstream-crl-file` with automatic hot-reload every 60s

**TLS & Certificates**

- ACME HTTP-01 automatic provisioning via instant-acme with challenges served on proxy port 80
- ACME DNS-01 automatic provisioning with Cloudflare, Route53 (AWS SDK), and OVH providers
- ACME DNS-01 manual mode (two-step flow for any DNS provider)
- Multi-domain SAN and wildcard certificate support for DNS-01 flows
- Global DNS providers: credentials configured once in Settings, referenced by ID during provisioning
- Smart auto-renewal: certificates remember their provisioning method and DNS credentials, renewing automatically every 12h (30 days before expiry). Manual DNS-01 certificates skipped
- Background certificate expiry check every 12h with CertExpiring notifications at configurable warning/critical thresholds
- SNI-based certificate hot-swap via arc-swap with wildcard support (`*.example.com`)
- Certificate upload parses X.509 metadata (issuer, validity, SAN domains, fingerprint)
- Encryption key rotation via `lorica rotate-key --new-key-file` CLI command
- TLS termination in worker mode with per-worker CertResolver loaded from DB
- HTTPS listener starts unconditionally; TLS works as soon as the first cert is uploaded

**Dashboard**

- Embedded Svelte 5 + TypeScript frontend (~59 KB gzipped) compiled into the binary via rust-embed
- Overview cockpit with system health cards, setup checklist, section helpers with animated expand/collapse
- Routes CRUD with 25+ settings across 7 tabs, path rules tab with reorder and collapsible overrides
- Backends CRUD with address, weight, health check (TCP/HTTP), TLS upstream, HTTP/2 toggle, active connections
- Certificates management with ACME (HTTP-01, DNS-01) and manual upload, manual renewal button
- Security page with WAF event table, category filtering, 39 rule toggles, IP ban list with unban
- SLA page with passive/active side-by-side comparison, latency percentile tables, config editor, CSV/JSON export
- Load test page with config management, clone, one-click execution, real-time SSE progress, historical results with comparison
- Active probes CRUD with route selection and enable/disable toggle
- Access logs with real-time WebSocket streaming (green pulsing indicator), CSV/JSON export with date range picker
- System page with worker table (PID, health, heartbeat latency), CPU/memory/disk gauges
- Settings page with notification channels (structured forms per type), DNS providers, security header presets, config export/import with diff preview, getting started guide toggle
- Nginx config import wizard with path rules and certificate import support
- Notification form with structured fields per channel (SMTP, Webhook, Slack), alert type checkboxes, real test delivery via Test button
- Graceful error handling when backend is unreachable, auto-redirect to login on 401 session expiry
- Light/dark theme toggle, consistent full-width layout, CSS design-token variables

**Notifications**

- Notification system with 5 alert types: cert_expiring, backend_down, waf_alert, config_changed, ip_banned
- Four delivery channels: stdout (structured JSON), SMTP email (STARTTLS), HTTP webhook, Slack
- Per-channel rate limiting (sliding window), channel subscription filtering, event history (100 events)
- Notification history endpoint and dashboard table
- Hot-reload from database configs, broadcast-based AlertSender for proxy hot path

**Monitoring**

- Passive SLA monitoring from real traffic with lock-free atomic counters, time-bucketed aggregation, rolling windows (1h/24h/7d/30d), configurable success criteria
- Active SLA monitoring with synthetic HTTP probes (configurable method, path, status, interval, timeout)
- SLA threshold alerts with automatic notifications when passive SLA drops below target
- Built-in load testing with configurable concurrency, RPS, duration, safe limits, CPU circuit breaker (90%), cron scheduling, SSE streaming, config cloning
- Prometheus metrics at `/metrics`: request count, latency histograms, active connections, backend health, cert expiry, WAF events, system CPU/memory
- Worker metrics aggregation: cache hits/misses, active connections, ban list, EWMA scores from workers to supervisor

**Caching**

- HTTP response cache via Pingora MemCache with LRU eviction (128 MiB cap, TinyUFO algorithm)
- Per-route toggle with configurable TTL and max size, Cache-Control header respect, Authorization/Cookie bypass
- Path rule cache overrides for sub-path-specific caching
- X-Cache-Status response header (HIT/MISS/STALE/REVALIDATED/BYPASS)
- Cache purge and stats APIs

**Worker Mode**

- Process-based worker isolation: supervisor forks N workers, passes listening sockets via SCM_RIGHTS
- Protobuf command channel over Unix socketpair for ConfigReload, heartbeat monitoring (5s interval)
- Graceful shutdown with 30s drain timeout then SIGKILL
- Real-time access log forwarding via Unix domain socket (log.sock) with sub-millisecond latency
- WAF engine in supervisor with global auto-ban counter aggregation across workers
- TLS termination, SLA collection, load testing, notification dispatch all functional in worker mode
- Worker PIDs, health status, and heartbeat latency visible in System dashboard
- Exponential restart backoff (1s-30s), supervisor closes listening sockets after spawning

**Configuration**

- Embedded SQLite database with WAL mode, CRUD for all entities, 13+ schema migrations
- AES-256-GCM encryption for certificate private keys and notification configs at rest
- TOML config export/import with preview and diff, DNS provider CRUD with encrypted credentials
- REST API on localhost:9443 via axum with session-based auth, sliding window session renewal, rate-limited login
- CLI with `--version`, `--data-dir`, `--log-level`, `--management-port`, `--http-port`, `--https-port`, `--workers`, `--upstream-crl-file`
- OpenAPI 3.0.3 specification covering all 85+ endpoints
- IP blocklist and WAF disabled rules persisted in GlobalSettings and restored on restart

**Packaging**

- `.deb` package with systemd service, user creation, permissions, service enable/auto-restart on upgrade
- `.rpm` spec with equivalent packaging
- Security-hardened systemd unit (ProtectSystem, PrivateTmp, NoNewPrivileges, MemoryDenyWriteExecute, SystemCallFilter, LimitNOFILE=65536)
- GitHub Actions CI pipeline (lint, test, build, package) with GPG-signed release artifacts
- NOTICE file crediting Cloudflare Pingora, FORK.md documenting fork lineage

**Testing**

- 892 Rust unit tests across 25 crates (463 product + 429 forked Pingora), 119 frontend Vitest tests, 350+ E2E Docker assertions across standalone and worker modes
- Docker Compose E2E test suite with 350+ assertions across 65+ sections (standalone + worker modes)
- Fuzz testing targets for WAF evaluation and API input
- Reproducible benchmark suite using oha in Docker (single-process, multi-worker, WAF, cache scenarios)
- Performance tuning guide with kernel sysctl, fd limits, worker sizing, cache and rate limit tuning

### Removed

- Windows support removed from forked Pingora crates (Linux-only)

[1.3.0]: https://github.com/Rwx-G/Lorica/releases/tag/v1.3.0
[1.2.0]: https://github.com/Rwx-G/Lorica/releases/tag/v1.2.0
[1.1.0]: https://github.com/Rwx-G/Lorica/releases/tag/v1.1.0
[1.0.0]: https://github.com/Rwx-G/Lorica/releases/tag/v1.0.0
