# Epic 8: Multi-User RBAC, AI Bot Defense & Zero-Downtime Upgrades (v1.6.0)

**Author:** Romain G.
**Target version:** 1.6.0
**Status:** Draft

**Epic Goal:** Land the v1.6.0 release cycle: three headline features (AI-crawler deny-list as a first-class protection layer, hot binary upgrade for zero-downtime restarts, team settings with multi-user RBAC), the long-standing module split of `proxy_wiring.rs` + `main.rs`, and the open audit-closure backlog (cert-resolver reliability, health-check parallelism, SQLite reactor-stall pass, management plane TLS, defense-in-depth, settings cleanup, observability gap, supply-chain vendoring of `captcha`).

**Integration Requirements:** All work lands on a single `feat/v1.6.0` branch with one final PR to `main` (per project workflow). Foundation refactors (Story 8.1) ship first so the headline features and hardening passes land on the deduplicated layout. The new `lorica-metrics` crate (Story 8.11) is a prerequisite for any new Prometheus counter introduced in this cycle to avoid retrofitting the `lorica-api` -> `lorica-bench` / `lorica-notify` dependency cycle. Worker-mode parity is mandatory: every new feature exercising shared state must round-trip through the supervisor RPC channel (`lorica-command`) and ship a worker-mode e2e test in `tests-e2e-docker/`. No behaviour change in single-process mode unless explicitly stated. `cargo test --workspace`, `cargo clippy --tests -- -D warnings`, `cargo audit`, `pnpm lint`, and `pnpm exec svelte-check` must stay green at every commit.

---

## Story 8.1: Foundation Module Split (`proxy_wiring.rs` + `main.rs`)

**Status:** Done (closed in `feat/v1.6.0` branch, head `3e97183`)

As a Lorica maintainer,
I want `lorica/src/proxy_wiring.rs` (5195 LOC) and `lorica/src/main.rs` (4329 LOC) split into focused sub-modules with the supervisor / worker / single-process spawn duplication factored into a shared `BackgroundTasks::start(role)`,
so that future feature work lands on a code shape that does not require synchronising three near-identical wiring branches (the v1.5.2 worker-mode cert-hot-reload bug originated in this duplication).

### Acceptance Criteria

1. **[Done]** `lorica/src/main.rs` shrunk from 4600 to 3576 LOC (-1024 LOC). Layout shipped : `cli/{rotate_key, unban}.rs` + `startup/{logging, signals, otel, notify, control_plane, data_plane, waf_uds, log_uds, shmem_eviction, api_server, worker_monitor}.rs`. The exact `cli/{serve, reset_admin}.rs` + `startup/{encryption_key, workers, runtime, background_tasks}.rs` layout from the AC text was rebalanced once the actual call sites were factored - the shared per-role wiring landed as `spawn_control_plane_tasks` + `init_data_plane_handles` + `spawn_data_plane_pruners` instead of one monolithic `BackgroundTasks::start(role)`, because the supervisor / worker / single-process roles share *different* subsets (control plane is supervisor + single ; data plane is worker + single ; api server is supervisor + single ; worker monitor is supervisor only). One monolithic helper would have re-introduced the asymmetry the AC was trying to prevent ; the per-concern helpers force every new spawn to declare which roles need it explicitly.
2. **[Done]** Per-role spawn helpers landed at the granularity above (see AC #1 rebalance note). `spawn_control_plane_tasks` returns a `ControlPlaneHandles` struct ; `init_data_plane_handles` + `spawn_data_plane_pruners` cover the worker / single-process data plane ; `spawn_api_server` + `spawn_worker_monitor` cover the heavy tokio::spawn closures.
3. **[Done]** `run_supervisor` and `run_single_process` now read as flat sequences of helper calls. `run_worker` continues to host its own data-plane bootstrap inline (the extracted helpers cover the parts shared with single-process). Three follow-up `fix(...)` commits closed v1.5.2-style asymmetries surfaced by the extraction : workers-mode load-test scheduler missing, single-process notify dispatcher reload missing, write_decision Retry-After consistency.
4. **[Done]** `lorica/src/proxy_wiring.rs` shrunk from 5440 to ~4350 LOC, redistributed across `proxy_wiring/{lb, helpers, context, routing, error_pages, forward_auth, ..., filters/{connection, ip, rate_limit, auth, waf, geoip, route_directive}}.rs`. The original AC envisioned `filters/{cache, waf, rate_limit, forward_auth, bot}.rs` ; the practical split shipped with concrete concerns from the actual implementation (no cache helpers run as inline filter checks, no bot-challenge gate runs in the same dispatch shape ; the seven concerns above cover the same intent against the real code). Each filter file attaches helpers via its own inherent `impl LoricaProxy` block so the type stays a single inherent type at the type-system level while each file holds a narrow `use` set.
5. **[Done]** `request_filter` decomposed into 16 `fn check_<name>` helpers (15 in `request_filter` + 1 in `request_body_filter`), each returning `Option<Decision>` (sync) or `Result<Option<Decision>>` (async). Top-level reads as the prescribed `if let Some(d) = self.check_X(...)? { return write_decision(session, &ctx.request_id, d).await; }` sequence. Helpers : check_global_connection_limit, check_ip_banned, check_ip_blocked, check_websocket_disabled, check_token_bucket_rate_limit, check_mtls, check_forward_auth, check_maintenance_mode, check_return_status, check_ip_allow_deny, check_geoip, check_slowloris, check_route_conn_limit, check_legacy_rate_limit, check_waf_request_filter, check_waf_body_filter. The four sites that initially resisted extraction (return_status with redirect_to passthrough, legacy rate_limit_rps with auto-ban, WAF block with shmem auto-ban, async forward_auth Allow / Deny / FailClosed) closed cleanly once `Decision` grew `redirect(status, location)` + `passthrough(status, headers, body)` constructors and `DecisionBody::Custom(Vec<u8>)` variant.
6. **[Done]** `write_decision(session, request_id, decision)` is the sole sink for every error-response site. The `extra_headers` parameter shipped as `Vec<(Cow<'static, str>, String)>` on the `Decision` struct itself (not the function signature) so the builder API can layer headers fluently : `Decision::reject(status, reason).with_html(...).with_header("Retry-After", "1".to_string())`. The Retry-After + X-RateLimit-Reset drift sites are now first-class - every rate-limit reject and the maintenance-mode 503 carry Retry-After uniformly.
7. **[Done]** Shipped in 23 commits on `feat/v1.6.0` (`feat/v1.6.0` cumulative range bd4219b..3e97183). Granularity is finer than the prescribed "5 + 4 commits" target because each helper extraction was its own commit + immediate clippy + tests validation, which surfaced 3 audit findings closed inline (workers-mode load-test scheduler, single-process notify reload, Retry-After consistency).
8. **[Done]** AC #8 mechanical parity verification ran source-level on `bd4219b..HEAD` instead of byte-equal `cargo expand` output (the latter is unrealistic given the file split moves declarations between modules - expansions are equivalent up to module path aliasing, which would require a normalising step that's brittle). Side-effect call-site count parity verified across nine production sites (`persist_waf_event` 7=7, `record_waf_event` 6=6, `inc_geoip_block` 1=1, `AlertType::IpBanned` 3=3, `AlertType::WafAlert` 2=2, `rate_limiter.observe` 1=1, `forward_auth_inject set` 1=1, `ip_blocklist().is_blocked_str` 1=1, `record_blocklist_event` 1=1). Filter-chain dispatch ORDER preserved verbatim. The four counts that DO drift (`Decision::reject/redirect/passthrough` 0->23, `insert_header(` 63->51, `ResponseHeader::build` 30->21, `ban_list.insert` 3->9) drift in the expected direction (new builder API replaces inline pattern ; consolidated write_decision drops per-site Content-Type + Content-Length pair ; 6 NEW test-side ban_list inserts are the audit M-22 cert-reload regression suite).

### Integration Verification

- **[Done]** IV1: 268 lorica unit tests pass at HEAD ; the same suite passed on bd4219b before any extraction work.
- **[Done]** IV2: `tests-e2e-docker/run.sh` audit pass surfaced two latent bugs (waf_events_clear bucket name collision, run.sh teardown profile gap) - both fixed during Story 8.1 with their own changelog entries. The harness now passes cleanly across single-process + workers + cert-export profiles.
- **[Done]** IV3: The v1.5.2 worker-cert-hot-reload regression test (`proxy_wiring::cert_reload_commit_tests`) still passes ; the worker-mode Docker suite exercises the deduplicated supervisor + worker spawn paths.

---

## Story 8.2: AI-Crawler (LLM) Deny-List

As an infrastructure engineer,
I want a first-class deny-list for AI / LLM crawlers (GPTBot, ClaudeBot, CCBot, PerplexityBot, Bytespider, ...) with User-Agent matching and rDNS forward-confirmation,
so that I can opt my routes out of LLM training scrapes without hand-rolling WAF custom rules and without false-positive blocking of legitimate Googlebot / Bingbot.

### Acceptance Criteria

1. New module `lorica/src/ai_bot.rs` (or extension of the existing bot module) carrying a curated `AiCrawler` registry (User-Agent regex + canonical rDNS suffix per crawler) ; ships with at minimum: GPTBot, ChatGPT-User, ClaudeBot, anthropic-ai, CCBot, PerplexityBot, Bytespider, Google-Extended, Applebot-Extended, Amazonbot, FacebookBot, Diffbot.
2. Per-route `ai_bot_policy: Option<AiBotPolicy>` field with three modes: `Off` (default, no behaviour change), `Deny` (return 403 + Retry-After: 86400 + plain-text body explaining the policy), `Log` (allow + structured-log + Prometheus counter).
3. rDNS forward-confirmation reuses the existing `lorica-rdns` infrastructure ; cache-hit path stays sub-millisecond. A User-Agent claiming to be `GPTBot` whose rDNS does not resolve back to `*.openai.com` is treated as spoofed and falls through to the regular WAF / rate-limit pipeline (configurable: `treat_spoofed_as = "deny" | "log" | "allow"`).
4. Three Prometheus counters: `lorica_ai_bot_total{crawler, route_id, action="deny|log|spoofed"}`. Cardinality bounded by `crawler_count * route_count * 3`.
5. Dashboard route drawer "Protection" tab gains an "AI crawler policy" section: dropdown (Off / Deny / Log) + spoofed-fallback dropdown + a "Detected crawlers" widget pulling the last 24h from the counter (top-5 by hit count).
6. Settings page gains a global "AI crawler registry" panel showing the 12+ built-in definitions (read-only) AND a "Custom crawlers" sub-section: full CRUD on operator-defined entries with `name`, `user_agent_pattern` (regex, validated server-side), `rdns_suffix` (optional ; if empty, rDNS check is skipped), `enabled` toggle. Custom entries are merged with the built-in registry at request-evaluation time ; on conflict (same `name`), custom wins.
7. New endpoints `GET / POST / PUT / DELETE /api/v1/ai-crawlers/custom` (Operator + SuperAdmin) backed by a new `ai_crawlers_custom` SQLite table. Pattern compilation errors return HTTP 400 with the regex error message.
8. Per-route policy AND custom-crawler edits hot-reload through the existing two-phase commit path (no restart).
9. Documentation: new `docs/ai-crawlers.md` page covering the built-in registry, the custom-crawler operator workflow, the rDNS forward-confirmation logic, the false-positive policy (Googlebot is intentionally excluded - it is a search-index bot, not an LLM training bot), and the operator-tunables.

### Integration Verification

- IV1: A `curl -H "User-Agent: GPTBot/1.0" https://route` returns 403 with the explanation body when policy = Deny ; 200 when policy = Off ; 200 + structured log entry when policy = Log.
- IV2: A `curl -H "User-Agent: GPTBot/1.0"` originating from an IP whose rDNS does not resolve to `*.openai.com` is treated according to `treat_spoofed_as` (default `deny`).
- IV3: New `tests-e2e-docker/` profile `ai-bot-smoke` exercises the 3 modes + spoof-detection (~12 assertions) ; runs in both single-process and workers mode.

---

## Story 8.3: Team Settings - Multi-User RBAC

As an operator running Lorica on a shared infrastructure team,
I want multiple admin / operator / viewer accounts with role-based access control,
so that I can grant junior engineers read-only access without sharing the single admin password and so that audit logs (Story 8.9) carry meaningful operator identity.

### Acceptance Criteria

1. New `users` table (`id`, `username`, `password_hash` argon2id, `role` enum, `created_at`, `last_login_at`, `disabled_at`, `created_by`) ; the existing single-admin row is migrated as `username = "admin", role = SuperAdmin` (one-shot DB migration, idempotent).
2. Three built-in roles: `SuperAdmin` (full access + user management + license / settings / encryption-key rotation), `Operator` (full CRUD on routes / backends / certs / WAF / SLA / load-tests / probes / cache / bans, read on settings, NO user management, NO encryption-key rotation), `Viewer` (read-only on everything except secrets - cert private keys, SMTP password, webhook URLs, DNS provider tokens are scrubbed in JSON responses).
3. Login flow: username + password (`POST /api/v1/auth/login` body changes from `{password}` to `{username, password}` ; backwards-compat shim accepts the old shape and routes to `username = "admin"`).
4. Session cookie carries the user_id ; `Session` extension carries `username + role` so handlers can authorise.
5. New CRUD endpoints under `/api/v1/users` (SuperAdmin only): `GET /users`, `POST /users`, `GET /users/:id`, `PUT /users/:id` (password / role / disabled flag), `DELETE /users/:id` (cannot delete the last SuperAdmin ; cannot delete self).
6. Per-handler authorisation: a `require_role!(Operator)` macro on every mutating endpoint ; `require_role!(SuperAdmin)` on settings / DNS providers / notification configs / cert-export ACL editing / user CRUD.
7. Dashboard Settings gains a "Users & access" tab: user table (username / role / last login / status / actions) + create-user dialog + change-password dialog + role-change dropdown + disable toggle. Viewer accounts see the dashboard with mutating buttons hidden.
8. Password policy: minimum 14 chars + at least one of each [upper, lower, digit, symbol] (configurable via settings) ; same hash + verification stack as the existing single-admin (argon2id).
9. Migration path documented in `docs/migrations/v1.6.0-rbac.md` with a one-paragraph operator note explaining the auto-migration of the existing admin password.

### Integration Verification

- IV1: A Viewer-role session calling `POST /api/v1/routes` receives 403 ; calling `GET /api/v1/routes` succeeds and the JSON has secrets scrubbed.
- IV2: An Operator-role session can create a route but `PUT /api/v1/settings` returns 403.
- IV3: New `tests-e2e-docker/` profile `rbac-smoke` exercises the 3 roles end-to-end (~25 assertions) including the secret-scrub verification ; runs in both single-process and workers mode.

---

## Story 8.4: Hot Binary Upgrade

As an operator,
I want to replace the running `lorica` binary with a newer version without dropping a single in-flight request and without restarting the systemd unit,
so that I can ship security patches and minor releases without scheduling a maintenance window.

### Acceptance Criteria

1. New CLI subcommand `lorica upgrade --binary <path>` (SuperAdmin only when invoked via API) initiates the hot-upgrade handoff.
2. Handoff protocol: the running supervisor (old) executes the new binary via `execve` with a documented env var `LORICA_HOT_UPGRADE_FDS=...` listing the inherited listening sockets (HTTP, HTTPS, management) by FD number ; the new supervisor parses the env var, rebinds the listeners from the inherited FDs (no re-bind on the OS - same kernel sockets), spawns its own workers, then signals the old supervisor to drain.
3. The old supervisor's workers enter drain (existing `Closing` state machine from Story 2.4): no new connections accepted, in-flight requests complete on the configured `worker_drain_timeout_s` (default 30s, configurable per Story #4 / pre-existing).
4. New `POST /api/v1/system/upgrade` endpoint (SuperAdmin only) accepting a multipart upload of the new binary ; the API verifies the GPG signature against the bundled signing key (or a configurable allowed-signers file), stages the binary at `/var/lib/lorica/upgrade/lorica.new`, and triggers the handoff.
5. `lorica_hot_upgrade_total{outcome="ok|signature_failed|exec_failed|drain_timeout"}` counter ; `lorica_hot_upgrade_drain_seconds` histogram.
6. Failure rollback: if the new binary fails to bind / panics within 10s, the old supervisor cancels the drain and resumes accepting connections ; the staged binary is moved to `/var/lib/lorica/upgrade/lorica.failed.<timestamp>` for diagnosis.
7. Dashboard Settings gains a "Binary upgrade" panel (SuperAdmin only): file picker, signature verification result, current version vs uploaded version, "Start upgrade" button with `ConfirmDialog` warning that traffic will drain over up to 30s.
8. systemd unit drop-in note in `docs/installation.md`: the unit's `ExecStart` does not need any change ; `KillMode=mixed` and `TimeoutStopSec=` already accommodate the drain window.
9. Docker image gains the same capability: the in-container supervisor honours the same `LORICA_HOT_UPGRADE_FDS` env var (operator can `docker exec` a binary swap, though the typical Docker workflow stays "rebuild the image and `docker compose up -d`").

### Integration Verification

- IV1: A 5-minute `wrk -c 50 -d 5m` against a live route survives a hot upgrade triggered at the 2-minute mark with zero connection errors and zero 5xx responses (measured via `wrk` output).
- IV2: A binary signed with a non-allowed key is rejected at `POST /api/v1/system/upgrade` with HTTP 400 ; the running binary is unaffected.
- IV3: New `tests-e2e-docker/` profile `hot-upgrade-smoke` performs an upgrade end-to-end with sustained traffic ; asserts zero dropped connections + the new PID is visible at `GET /api/v1/system` post-upgrade (~15 assertions).

---

## Story 8.5: Cert-Resolver Reliability Pass

As an infrastructure engineer,
I want OCSP staple refresh to run as a background task instead of on the cert-resolver-reload critical path, the cert-resolver reload to be partial-tolerant (one bad cert does not poison the whole batch), and Prometheus counters that surface reload outcomes,
so that long-running supervisors keep stapling fresh OCSP responses, cert-installs do not block TLS handshakes for 10s, and a single malformed cert does not silently break TLS for every other domain.

### Acceptance Criteria

1. `static OCSP_CLIENT: Lazy<reqwest::Client>` hoisted in `lorica-tls/src/ocsp.rs`, mirroring the `HEALTH_HTTP_CLIENT` precedent ; per-fetch client construction removed from `fetch_ocsp_response`.
2. New background task `ocsp_refresh_loop` (spawned via `task_tracker.spawn` from `BackgroundTasks::start`) walks the cert resolver's entries every `min(nextUpdate - now, 6h)`, re-fetches each staple via `try_fetch_ocsp`, and `arc-swap`s a fresh `Inner` via `CertResolver::refresh_staples(...)`.
3. `reload_cert_resolver` becomes synchronous in OCSP terms: it loads cert bodies only ; OCSP fetches are deferred to the next `ocsp_refresh_loop` tick (typically <5s after the swap).
4. `CertResolver::reload` becomes partial-tolerant: builds cert-by-cert, logs + skips malformed entries, swaps with the rest. The previous "one bad cert short-circuits the whole batch" behaviour is gone.
5. Four new Prometheus counters: `lorica_cert_resolver_reload_total{worker_id, result="ok|fail"}`, `lorica_cert_resolver_active_domains{worker_id}` (gauge), `lorica_ocsp_refresh_total{result="ok|fail"}`, `lorica_cert_resolver_pending_ocsp_seconds{domain}` (gauge).
6. Hot-swap of OCSP staple bytes does not affect in-flight TLS handshakes (validated against the existing cert-hot-swap regression suite).
7. Documentation in `docs/architecture/cert-resolver.md` updated with the new lifecycle diagram (reload = cert bodies only ; OCSP refresh = background task).

### Integration Verification

- IV1: Installing a cert via `POST /api/v1/certificates` is observable on the TLS listener within 200 ms (was 1-10s when an OCSP responder was slow). Measure via `openssl s_client -servername <newhost> -connect localhost:8443 < /dev/null` race against the install POST.
- IV2: Inserting a malformed cert in the DB (e.g. truncated PEM) does not block reload of the other certs ; `lorica_cert_resolver_reload_total{result="fail"}` increments and a warning log mentions the bad cert ID ; the other domains stay reachable.
- IV3: A 30-day soak (simulated via a mocked OCSP responder advancing `nextUpdate` every 10 minutes) shows `lorica_ocsp_refresh_total{result="ok"}` incrementing on every cycle ; the resolver never serves an OCSP staple older than 12h.

---

## Story 8.6: Health-Check Parallelism Pass

As an infrastructure engineer,
I want backend health probes to run concurrently with a sane parallelism cap, the EWMA tracker to use sharded locking instead of a global RwLock, and cold backends to be picked LAST instead of being thundering-herded,
so that one slow backend does not stall the entire health-probe round and so that adding a new backend does not knock it over with simultaneous "I have no EWMA score, score = 0.0, pick me" routing decisions.

### Acceptance Criteria

1. `health_check_loop` (`lorica/src/health.rs:104-225`) replaces the sequential `for backend in &backends { ... }` with `futures::stream::iter(backends).for_each_concurrent(MAX_PARALLEL_PROBES, ...)`.
2. New global setting `health_max_concurrent_probes: u32` (default 32, range 1..=512) drives `MAX_PARALLEL_PROBES`.
3. Per-backend health-status diffs are collected in-memory across the round and applied in a single `spawn_blocking` SQLite transaction at end-of-round (folds into Story 8.7's `db_blocking` helper).
4. `EwmaTracker` global `RwLock<HashMap<String, f64>>` replaced with `DashMap<String, parking_lot::Mutex<f64>>` (sharded write contention, single-key lock for the read-modify-write).
5. `EwmaTracker::select_best` cold-backend behaviour fixed: `unwrap_or(f64::INFINITY)` so cold backends are picked LAST (matches the actual scoring direction where lower = faster) ; the previous `unwrap_or(0.0)` thundering-herd is gone.
6. Optional explore-bias (5% of `select_best` calls return a uniformly-random unscored backend if any exist, to prime EWMA scores) gated behind a new `peak_ewma_explore_ratio: f32` global setting (default 0.05, range 0.0..=0.5).
7. New Prometheus histogram `lorica_health_check_round_seconds` and counter `lorica_health_check_probes_total{result="ok|fail|timeout"}`.

### Integration Verification

- IV1: A configuration with 100 backends where one always times out (5s `TCP_CONNECT_TIMEOUT`) completes a full probe round in <1s with `health_max_concurrent_probes=32` (was ~5s before).
- IV2: Adding a brand-new backend to a 10-backend Peak-EWMA route with sustained load does NOT route the next 100 requests all to the new backend ; the new backend receives ~`100 / 11` requests over the first probe cycle.
- IV3: Existing `cargo test -p lorica --test proxy_routing_test` and the Docker `peak_ewma` smoke (if present) pass unchanged.

---

## Story 8.7: SQLite Reactor-Stall Pass

As a Lorica maintainer,
I want every async handler that touches `ConfigStore` to go through a `db_blocking` helper, the bot-stash to live on its own dedicated connection, and access-log + WAF event persistence to flow through a bounded mpsc channel with batched INSERT,
so that a contended SQLite WAL stops stalling the tokio reactor and so that high-traffic WAF events do not bottleneck on a single mutex per insert.

### Acceptance Criteria

1. New helper in `lorica-api/src/lib.rs` (or `state.rs`): `pub async fn db_blocking<T, F>(state: &AppState, f: F) -> Result<T, ApiError> where F: FnOnce(&LogStore) -> rusqlite::Result<T> + Send + 'static, T: Send + 'static`.
2. The 7 v1.5.2-introduced sites (`logs.rs::get_logs / export_logs / clear_logs`, `waf.rs::get_waf_events / get_waf_stats`, `settings.rs::notification_history`) are migrated through `db_blocking`.
3. The remaining ~80 `ConfigStore` call sites in `lorica-api/src/{routes/crud, backends, certificates, settings, sla, dns_providers, probes, loadtest, status, config, auth, acme/*, cert_export, waf, cache}.rs` are migrated through `db_blocking`. N+1 patterns (e.g. `routes/crud.rs:3195` list_routes + per-route list_backends_for_route) are folded into single `LEFT JOIN ... GROUP BY` SQL where it materially reduces round-trips.
4. Bot-stash gets its own `Arc<parking_lot::Mutex<rusqlite::Connection>>` (separate from `ConfigStore`) tuned for ephemeral state: `synchronous=OFF`, `journal_mode=MEMORY`, no encryption-key state. The 5 `BotEngine` sites (`bot.rs::insert / take / captcha_image / prune_expired / len`) consume the new connection ; their cross-worker `tokio::sync::Mutex` is dropped.
5. Access-log persistence (`proxy_wiring.rs:5144-5147`) and WAF event persistence (5 sites at `:2375 / :3615 / :3736 / :3904 / :3948`) are decoupled through a bounded `tokio::sync::mpsc::channel<LogEvent>`. Hot path does `tx.try_send(event)` (drops on overflow with `lorica_log_events_dropped_total{kind="access|waf"}` counter). A single background task owned by `BackgroundTasks::start` drains and batches `INSERT` (100 rows per transaction or 100 ms wall, whichever first) via `spawn_blocking`.
6. Channel capacity defaults: 10000 access-log events, 1000 WAF events ; both operator-tunable via new `log_buffer_capacity` / `waf_buffer_capacity` global settings.
7. Same channel feeds the WebSocket log-stream subscribers (no change in behaviour, single source).

### Integration Verification

- IV1: An operator polling Overview (9 parallel calls every 30s) + auto-refresh on Routes / Logs / Security / SLA shows zero `tokio` reactor stall warnings (`tokio-console` clean) under sustained 1k req/s.
- IV2: A WAF-blocking burst (e.g. 1000 SQLi attempts/s) does not increase the per-request latency of legitimate traffic by more than 10% ; the access-log lag (measured via `lorica_log_events_dropped_total`) stays at zero under defaults.
- IV3: New `tests-e2e-docker/` assertion in the existing single-process suite measures access-log INSERT throughput at >50k events/s (was <5k/s pre-fix).

---

## Story 8.8: Management Plane Hardening (TLS + Metrics Auth + CSP3 Nonces)

As an operator,
I want the management API on port 9443 to be served over TLS with an auto-managed self-signed cert, an opt-in auth knob on `/metrics`, the `lorica unban` CLI to use the correct URL scheme, AND the dashboard CSP to drop `'unsafe-inline'` from `style-src` via CSP3 per-request nonces,
so that `Secure`-flagged session cookies actually round-trip through corporate reverse proxies, any local user on a multi-tenant box cannot scrape the full backend topology + cert inventory from `/metrics` unauthenticated, and the dashboard XSS posture stops requiring an inline-styles bypass.

### Acceptance Criteria

1. Management listener migrates from `axum` over plaintext HTTP to `axum-server` with rustls config. A self-signed cert (`localhost` + the resolvable hostname + `127.0.0.1` + `::1` SANs) is auto-generated at first boot, persisted at `/var/lib/lorica/management/cert.pem` + `key.pem`, and auto-rotated 30 days before expiry (~1 year validity).
2. Operator can override the self-signed cert with their own (TLS termination at Lorica, e.g. for direct-access deployments) via existing `Settings -> Management TLS` config: `management_cert_pem_path` + `management_key_pem_path`. When set, the auto-generated cert is ignored.
3. `lorica unban` CLI subcommand uses `https://127.0.0.1:{port}` with `danger_accept_invalid_certs(true)` (matches the existing CLI behaviour with the now-correct scheme). Connect-error message improves to `"Cannot connect to management API on port {port}: {e}. Hint: is lorica running and is --management-port correct?"`.
4. New global setting `metrics_require_auth: bool` (default `false` for back-compat in v1.6.0 ; will flip to `true` in v1.7.0 with a release-note migration paragraph). When `true`, `/metrics` requires either a session cookie OR a static bearer token configured via `prometheus_scrape_token: Option<String>` (env-var override `LORICA_PROMETHEUS_SCRAPE_TOKEN`).
5. Bearer-token auth uses constant-time comparison ; failed auth returns `401 WWW-Authenticate: Bearer realm="lorica-metrics"`.
6. **CSP3 nonces for `style-src` (drops `'unsafe-inline'`)** : a Vite plugin in `lorica-dashboard/frontend/` rewrites the embedded `index.html` template at build time to mark every `<style>` block and the placeholder for the per-request nonce (token replaced server-side). The dashboard backend (`lorica-dashboard/src/lib.rs`) generates a 128-bit cryptographically-random nonce per request, injects it into both the served HTML (`<style nonce="...">`) and the `Content-Security-Policy` header (`style-src 'self' 'nonce-...'`), and removes `'unsafe-inline'` from the directive. Svelte's runtime-injected scoped styles continue to work because the runtime is patched (or the `svelte/internal` style emitter is wrapped) to apply the nonce to dynamically-created `<style>` elements.
7. CSP header generation moves into a dedicated `csp.rs` helper covering script-src, style-src, frame-ancestors, form-action, base-uri, object-src (the v1.5.2 CSP3 directives stay unchanged) ; the `style-src` directive is the only one that gains a per-request nonce.
8. Documentation: `docs/security.md` gains a "Management plane authentication" section explaining the trust model + the `metrics_require_auth` toggle + the new CSP3 nonce posture ; `docs/installation.md` notes the self-signed cert behaviour and the operator-cert override.

### Integration Verification

- IV1: `curl https://localhost:9443/api/v1/status` works (with `-k` for the self-signed cert) ; `curl http://localhost:9443/api/v1/status` returns a connection-reset / TLS-handshake error.
- IV2: With `metrics_require_auth=true` + `prometheus_scrape_token=secret`, `curl https://localhost:9443/metrics` returns 401 ; `curl -H "Authorization: Bearer secret" https://localhost:9443/metrics` returns 200.
- IV3: `lorica unban 1.2.3.4 --password X` works against a running supervisor (no scheme-mismatch connect error).
- IV4: The served dashboard HTML contains `<style nonce="<random>">` tags AND the response carries `Content-Security-Policy: ... style-src 'self' 'nonce-<random>'; ...` (no `'unsafe-inline'`) ; the dashboard renders without browser-console CSP-violation warnings ; the nonce is different on every request (verified by issuing two consecutive `curl -I` requests and comparing).

---

## Story 8.9: Defense-in-Depth Pass

As a security-conscious operator,
I want a structured admin audit log on every state-mutating endpoint, a per-source-IP TCP connection cap, bounded captcha-PNG stash, and a per-route mirror semaphore,
so that I can answer "who deleted route X at 03:14?", a single source IP cannot exhaust `max_global_connections`, captcha flooding cannot OOM the process, and one slow shadow target cannot starve every other route's mirror.

### Acceptance Criteria

1. New `audit_log!(state, action = "route.delete", target_id = id, before = ..., session = &session)` macro feeding a dedicated `lorica::audit` structured-log target. Applied uniformly to every state-mutating handler (~30 sites across `lorica-api/src/{routes/crud, backends, certificates, settings, dns_providers, probes, loadtest, config, auth, acme/*, cert_export, waf, cache, users}.rs`). RBAC username (Story 8.3) is the operator identity in the log.
2. Per-row audit-log entry shape: `{id, timestamp, operator_username, operator_role, action, target_type, target_id, before_payload_hash, after_payload_hash, ip, user_agent, prev_chain_hash, chain_hash}`. `before` / `after` payloads are SHA-256-hashed individually. `chain_hash = SHA-256(prev_chain_hash || timestamp || operator_username || action || target_type || target_id || before_payload_hash || after_payload_hash)` ; the genesis row uses `prev_chain_hash = 0x00 * 32`.
3. New `GET /api/v1/audit/verify` endpoint (SuperAdmin only) walks the audit table from genesis, recomputes each `chain_hash`, and returns `{verified: bool, total_rows, first_break_id?, first_break_reason?}`. A break (chain mismatch or missing prev row) localises tampering to the earliest affected row.
4. Audit-log emission is also bridged to OTel via the existing tracing subscriber: the `audit_log!` macro emits a `tracing::info!(target: "lorica::audit", ...)` event AND attaches it to the current request span (when one exists), so operators using OTel correlation can pivot from a request trace to its audit footprint.
5. New global setting `connection_limits_per_ip: Option<u32>` (default `None` = no cap). Enforced at TCP accept (in the existing connect-time CIDR filter neighbourhood at `lorica/src/proxy_wiring.rs:3410-3430`) via `DashMap<IpAddr, AtomicU32>` ; over-cap connections are refused at `accept()` (no TLS handshake, no log entry except a counter `lorica_per_ip_connection_refused_total`).
6. Captcha PNG stash (Story 8.7's bot-stash refactor) gains: a global LRU cap (default 10000 entries, configurable `bot_stash_max_entries`) + a per-IP-prefix counter (default `/24` for IPv4, `/48` for IPv6, configurable `bot_stash_per_prefix_max`, default 100). Over-cap challenge issuance returns `503 Retry-After: 30`.
7. `MIRROR_SEMAPHORE` global cap of 256 replaced with per-route semaphores: `DashMap<RouteId, Arc<Semaphore>>` sized from a new `mirror_max_concurrent_per_route` global setting (default 32). A coarse global safety net stays at `mirror_max_concurrent_global` (default 4096).
8. Dashboard Security tab gains an "Audit log" sub-page: paginated table (timestamp / operator / action / target / chain status) with filtering by operator, action prefix, and date range, plus a "Verify chain integrity" button calling `/api/v1/audit/verify` and rendering the result. Backed by a new `GET /api/v1/audit` endpoint (Operator + SuperAdmin only ; SuperAdmin sees the verify button).
9. Audit log retention: stored in a dedicated `audit_log` SQLite table with auto-eviction via existing `LogStore` retention machinery (default 90 days, configurable `audit_log_retention_days`). Retention truncation preserves chain integrity by storing the earliest-surviving row's `prev_chain_hash` as a "retention seal" in the `audit_log_meta` table ; `verify` accepts the seal as the new genesis when older rows are absent.

### Integration Verification

- IV1: `DELETE /api/v1/routes/5` issued by user `alice` produces an audit-log entry with `operator_username="alice", action="route.delete", target_id=5` ; visible via `GET /api/v1/audit?action=route.delete` ; the entry's `chain_hash` matches the recomputed value.
- IV2: 1000 simultaneous TCP connect attempts from a single IP with `connection_limits_per_ip=10` result in 10 successful connects + 990 refused connects ; `lorica_per_ip_connection_refused_total` shows 990.
- IV3: A mirror endpoint configured to hang indefinitely on route A does not impact route B's mirror throughput (measured via parallel `wrk` against both routes).
- IV4: After 100 audit-log mutations, `GET /api/v1/audit/verify` returns `{verified: true, total_rows: 100}` ; manually tampering with row 47's `target_id` in SQLite makes verify return `{verified: false, first_break_id: 47, first_break_reason: "chain_hash_mismatch"}`. Retention-truncating the first 50 rows + re-running verify still returns `{verified: true}` thanks to the retention seal.

---

## Story 8.10: Settings & Rate-Limit Cleanup

As a Lorica maintainer,
I want `header_timeout_s` + `flood_strict_rps` actually wired (Story 7.3 leftovers), the dual rate-limit code paths unified, and the 335-LOC `update_settings` repetition replaced with a `SettingsPatch` builder,
so that the settings audit history stops surfacing `[x]`-checked-but-not-actually-implemented gaps and so that adding a new setting becomes one builder call instead of seven hand-rolled lines.

### Acceptance Criteria

1. `header_timeout_s: u32` field added to `lorica-config/src/models/settings.rs::GlobalSettings` (default 10) ; plumbed to per-worker config + the proxy hot path (slowloris read-timeout on the header phase).
2. `flood_strict_rps: u32` field added to `GlobalSettings` (default = `flood_threshold_rps / 2`) ; plumbed to the existing flood-strict half-factor logic.
3. The dual rate-limit engines (`Route.rate_limit_rps` legacy + `Route.rate_limit: Option<RateLimit>` new) converge: the legacy fields become a thin compatibility shim that synthesises `RateLimit { capacity: burst.unwrap_or(rps), refill_per_sec: rps, scope: PerIp }` and routes through the new `LocalBucket` path only. The legacy `self.rate_limiter.observe` block at `proxy_wiring.rs:3653-3749` is deleted.
4. Auto-ban escalation lifts to the unified path (today only the legacy path triggers auto-ban ; an operator using the new struct silently loses escalation).
5. Path-rule overrides know about the unified path (today only legacy fields propagate to per-path overrides).
6. `update_settings` (`lorica-api/src/settings.rs:120-454`, 335 LOC of repeated `if let Some(x) = ... { check; settings.x = x }`) is rewritten as a `SettingsPatch::new(&body).numeric_range(...).string_choice(...).apply(&mut settings)?` builder. Range / choice metadata becomes machine-readable, extending the v1.5.2 const-lift work to settings field bounds.
7. Settings field bounds are exported via a new `GET /api/v1/settings/schema` endpoint (used by the dashboard form to render input constraints client-side ; replaces the hardcoded constraints in the Svelte components).
8. DB migration: a one-shot "upgrade legacy rate-limit fields" notice in the operator log on first boot of v1.6.0 listing affected routes (no DB write ; operators are encouraged but not forced to migrate).

### Integration Verification

- IV1: A route with both `rate_limit_rps=10` and no `rate_limit` struct enforces the same 10rps cap as before, and now also escalates to auto-ban after the configured threshold.
- IV2: A route with `rate_limit: { capacity: 10, refill_per_sec: 10, scope: PerIp }` and a path rule overriding to `rate_limit_rps=100` correctly applies the 100rps cap on the matched path (was silently ignored before).
- IV3: `cargo test -p lorica-api` covers the `SettingsPatch` builder via property-based tests on the bound-checking shape (existing settings tests stay green).

---

## Story 8.11: Observability Gap (lorica-metrics + SLA / probe / notification counters + BanReason)

As an operator,
I want to alert on SLA threshold breaches, active-probe outcomes, and notification-dispatch outcomes from Prometheus, and I want the `/api/v1/bans` JSON to tell me WHY each IP was banned,
so that my on-call workflow does not depend on parsing notification e-mails out-of-band and so that the dashboard Security view can show 4 fields per row (IP / reason / expiry / unban) instead of 3.

### Acceptance Criteria

1. New `lorica-metrics` crate extracted from `lorica-api/src/metrics.rs`: owns the custom Prometheus `REGISTRY` + the metric registration helpers + the type-safe counter wrappers. `lorica-api`, `lorica-bench`, `lorica-notify` all depend on `lorica-metrics` ; the `lorica-api` -> `lorica-bench` / `lorica-notify` cycle is unblocked.
2. Three new Prometheus counters / histograms registered in their respective crates:
   - `lorica_sla_breach_total{route_id, threshold_kind="latency_p95|latency_p99|error_rate|uptime"}` from `lorica-bench/src/passive_sla/persistence.rs`.
   - `lorica_active_probe_outcome_total{probe_id, outcome="ok|fail|timeout"}` from `lorica-bench/src/active_probes.rs`.
   - `lorica_notification_dispatch_total{channel="email|webhook|slack|stdout", outcome="ok|http_4xx|http_5xx|timeout|connect_failed"}` from `lorica-notify/src/channels/{email,slack,webhook,stdout}.rs`.
3. `BanReason` enum (`RateLimit`, `WafFlood`, `WafCriticalRule`, `Manual`) added to `lorica/src/cache.rs` ; the ban-list value type changes from `(banned_at, duration_s)` to `(banned_at, duration_s, reason)`.
4. `BanReason` is surfaced in the `/api/v1/bans` JSON as a `reason` field on each row.
5. Dashboard Security -> Bans table gains a "Reason" column with a coloured pill per reason (`RateLimit` = orange, `WafFlood` = red, `WafCriticalRule` = dark red, `Manual` = grey).
6. Existing ban-issuance call sites are audited and pass the correct `BanReason` (no defaulting to `RateLimit` ; the supervisor-side `BanIp` RPC payload from Story 2.x gains a `reason` field).
7. `lorica-metrics` re-exports `prometheus` so consumers do not have to depend on `prometheus` directly ; this avoids version-skew between the four crates.

### Integration Verification

- IV1: Triggering an SLA breach (latency p95 > threshold) via a load-test against a slow backend increments `lorica_sla_breach_total{threshold_kind="latency_p95"}` ; visible in `/metrics`.
- IV2: A failing notification webhook (configured to a 500-returning endpoint) increments `lorica_notification_dispatch_total{channel="webhook",outcome="http_5xx"}`.
- IV3: An IP banned via the WAF flood path appears in `GET /api/v1/bans` with `reason: "waf_flood"` ; the dashboard renders the orange/red pill correctly.

---

## Story 8.12: Vendor `captcha 1.0` into `lorica-challenge`

As a security-conscious maintainer,
I want the `captcha 1.0` external dependency (single-maintainer, ~13 months inactive, on a security-sensitive bot-challenge path) inlined into `lorica-challenge`,
so that the supply-chain takeover surface collapses onto code we review at vendor-time and so that the v1.6.0 audit row M-16 (supply chain) closes.

### Acceptance Criteria

1. `lorica-challenge/src/captcha/` module created with the inlined captcha generation logic (~600 LOC of pure Rust: PNG generation via `lodepng` or `png` crate, embedded font, filter / distortion code).
2. The `captcha = "1.0"` workspace dependency is removed from `lorica-challenge/Cargo.toml`. `cargo audit` confirms the supply-chain row clears.
3. The vendoring follows the v1.3.0 `no_debug` precedent: original license header preserved in a `LICENSE` file under `lorica-challenge/src/captcha/` ; original author credited in the module-level doc comment ; deltas vs upstream documented in `lorica-challenge/src/captcha/VENDORING.md`.
4. The existing `lorica-challenge::captcha::Captcha::new(...)` API surface is preserved byte-for-byte (drop-in replacement) ; consumers in `lorica/src/bot.rs` see no change.
5. New unit tests in `lorica-challenge/src/captcha/tests.rs` cover: PNG output is a valid PNG (header + IDAT), output dimensions match the configured size, generated text matches what `as_tuple()` returns, two consecutive calls produce different images (RNG bias check).
6. `cargo audit` is clean ; the v1.6.0 release notes mention the vendoring with a one-paragraph rationale.

### Integration Verification

- IV1: Bot-challenge image-captcha fallback (PoW disabled, captcha mode enabled) returns a valid PNG image with the expected text (verified via existing `tests-e2e-docker/` bot-smoke profile).
- IV2: `cargo audit` passes with zero `RUSTSEC-*` advisories on `captcha`.
- IV3: `cargo deny check` (if used) shows zero new license-compatibility warnings ; the `LICENSE` file is detected.

---

## Out of Scope (deferred)

- **`rustls-pemfile` removal in `lorica-tls` fork** (backlog #14) and **`rand 0.8` removal in forked crates** (backlog #15): blocked on upstream Pingora migration ; tracking-only. Native Lorica code already migrated in v1.5.0 ; transitive deps clear once Pingora upstream lands its own migration.
- **Audit-log Merkle-tree mode** (extension of Story 8.9): the v1.6.0 ships a linear SHA-256 chain (each row carries `prev_chain_hash` + `chain_hash` ; verification walks rows in order). A Merkle-tree variant for sub-linear partial-range verification is a v1.7.0+ candidate if operator demand surfaces.
- **Operator-defined AI crawler retroactive evaluation** (extension of Story 8.2): custom crawlers added via `POST /api/v1/ai-crawlers/custom` apply to NEW requests only ; back-evaluating against the access-log to retroactively flag past requests is out of scope.
