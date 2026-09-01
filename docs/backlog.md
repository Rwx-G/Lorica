# Technical Backlog

Bug fixes, improvements, and maintenance tasks. For new features, see the Roadmap section in [README.md](/README.md).

## Resolved in v1.6.0 (Epic 8)

These items shipped in the v1.6.0 cycle and have been pruned from the Open
table. See `docs/qa/epic-8-report.md`, the `[1.6.0]` section of
`CHANGELOG.md`, and the commit log:
**#17** (header_timeout_s + flood_strict_rps, Story 8.10), **#18** +
**#33** (OCSP background refresh + OCSP_CLIENT + partial-tolerant
cert-resolver metrics, Story 8.5), **#19** (admin audit log, Story 8.9),
**#20** (management-plane TLS listener + `/metrics` auth + `unban` scheme,
Story 8.8), **#21** (per-source-IP connection cap, Story 8.9), **#22**
(BanReason, Story 8.11), **#26** (CSP3 style-src nonce, Story 8.8),
**#27** (vendor `captcha`, Story 8.12), **#29** (dual rate-limit path
unification, Story 8.10), **#37** (SLA / probe / notification counters +
`lorica-metrics`, Story 8.11), **#38** (bot-stash caps, Story 8.9),
**#39** (per-route mirror semaphores, Story 8.9), **#43** + **#45**
(clippy-1.95 workspace cleanup), **#44** (WAF retention + 24h count),
**#46** (`settings/schema` endpoint, Story 8.10 AC #7), **#47** (Story 8.8
completion - the management TLS listener and CSP3 nonce shipped, so the
partial-status pointer is retired).

**#42** (v1.5.9 architect-reviewer structural refactors) - all five slices
landed in the v1.6.0 audit-fix follow-up: **(d)** `lorica-waf` /
`lorica-notify` versioned onto the product line; **(e)** `run_migrations`
converted to a tracked `(version, fn)` table with an idempotent
`add_column_if_absent` guard (old-field-DB upgrade path tested); **(b)**
`AppState`'s mode-specific `Option<Arc<...>>` fields collapsed into a `Mode`
enum so invalid single-process/supervisor combinations are unconstructable;
**(a)** the pure ACME core (DNS challengers + instant-acme driver) extracted
into a new first-party `lorica-acme` crate; **(c)** an `openapi.yaml` <->
axum-route-table drift-gate test (which caught and reconciled three
undocumented endpoints). Sub-items (f) source-tree and the split of
`proxy_wiring.rs` / `main.rs` were already resolved in v1.5.10.

**#48** (settings cross-field validation) - `GlobalSettings::validate_cross_fields`
added in `lorica-config`, called from `lorica-api::settings::update_settings`
on the merged result before persist. Enforces `cert_warning_days >
cert_critical_days` and `flood_strict_rps < flood_threshold_rps` (when both
set; `0` strict = auto). Per-field bounds stay at the API boundary; the
uid/gid and zero-duration-ban NOTE drifts are documented intentional choices,
not invariants. Five unit tests in `lorica-config`.

## Open

| # | Item | Type | Notes |
|---|------|------|-------|
| 14 | Upstream-sync `rustls-pemfile` removal in `lorica-tls` | Track | RUSTSEC-2025-0134 (unmaintained) is visible transitively through our Pingora fork `lorica-tls`. Native Lorica code migrated to `rustls-pki-types` in v1.5.0 ; the transitive dep will clear once Pingora upstream migrates. Upstream tracking issue [cloudflare/pingora#772](https://github.com/cloudflare/pingora/issues/772) is still open (re-checked during the v1.6.0 dependency pass). Monitor their tracker ; pull the change into the fork when it lands. |
| 15 | Upstream-sync `rand 0.8` removal in forked crates | Track | RUSTSEC-2026-0097 (unsound with custom logger) was visible transitively via Pingora forks (`lorica-runtime`, `lorica-limits`), the `tungstenite` / `axum` chain, and the `captcha` crate. Native Lorica code is on `rand 0.9` (v1.5.0) and the advisory itself was cleared in v1.5.8 (bumped `0.8.5 -> 0.8.6`). Removing the `0.8` line entirely still depends on the upstream forks bumping to `rand 0.9`. NOTE (v1.6.0 dep pass): the product-crate `rand 0.9 -> 0.10` bump was deliberately NOT taken - it is pervasive across product AND the pinned-at-0.8 forked crates, so bumping would fragment the workspace into three `rand` majors without removing the old line from the tree. `reqwest 0.12 -> 0.13` deferred for the same reason (forked `lorica-tls` keeps 0.12). Both revisit when the fork moves. |
| 49 | Arc-wrap `SinkEvent` for multi-lane publish | Perf | Story 9.8 QA (performance-auditor, Medium, measure-first): with syslog + OTLP both enabled, each exported event pays one deep clone per lane plus the initial clone (~3 string-heavy clones per access row at request volume). Wrapping the payload in `Arc` collapses that to refcount bumps. Structural change to the `SinkEvent`/`SinkPayload` surface touching both consumers ; confirm allocator pressure under a load test with both sinks on before doing it. |
| 50 | OTLP logs per-kind toggles | Feature | Story 9.8 QA: syslog has access/waf/audit toggles, the OTLP lane is all-on (`SinkLane` already models the filter ; it is a settings gap, not a design one). Add `otlp_logs_{access,waf,audit}_enabled` when an operator asks for e.g. audit-only OTLP. |
| 51 | Invert sink lane creation: `install() -> Receiver` handoff to consumer-side registration | Refactor | Story 9.8 QA (architect-reviewer): the OTLP lane's receiver must be wired by the caller, an obligation stated only in prose ; a dropped receiver or failed `init_logs` leaves a lane whose events all drop (mitigated in 9.8 by lane self-removal for syslog and cfg gating for OTLP, but not compiler-enforced). Revisit when Story 9.2 adds the next consumer of this seam - a `register_lane(name, filter) -> Receiver` API called by the consumer owner makes "installed lane, dead consumer" unrepresentable. |
| 52 | Shared-runtime-services crate boundary (`lorica-obs`) | Arch | Decision recorded during Story 9.8: the sink hub + syslog transport live in `lorica-api` beside `log_writer.rs` (whose bounded/try_send/drop contract they reuse) even though their consumers and lifecycle owners live in `lorica`. Acceptable while there is ONE shared runtime service ; when the cluster stories (9.2-9.6) add another, extract `lorica-obs` (metrics + log_writer + log_sinks) in one move instead of per-story accretion. |
| 53 | Log-sink observability follow-ups | Observability | Story 9.8 QA leftovers, none blocking: (a) `lorica_log_sink_up{sink}` gauge from the consumer loop's connection state (needs per-worker gauge aggregation, which only exists for counters today) ; (b) unit tests around `apply_log_sinks_from_store` transitions (dedup no-op, enable/disable) - global-state heavy, needs a test seam ; (c) a `--workers` variant of the `log-sinks` e2e phase to exercise the per-worker counter aggregation end to end (the counters ARE in `PER_WORKER_COUNTERS` and covered by its sync test, but no e2e asserts the aggregate). |
| 54 | Viewer role can read sink topology | Policy | Story 9.8 QA (security-auditor, Info): `GET /settings` is Viewer-accessible and now discloses `syslog_endpoint`, the CA / client-cert public halves and `syslog_extra_sd` to the least-trusted authenticated role. Pre-existing pattern (same as `otlp_endpoint`, GeoIP paths). Decide deliberately whether sink topology should be SuperAdmin-read-only ; today it follows the house convention. |
| 55 | Small dedup follow-ups from Story 9.8 reviews | Refactor | (a) `SettingsWatcher<T>` helper to collapse the repeated `OnceLock<Mutex<Option<Snapshot>>>` scaffolds in `lorica/src/reload.rs` (now 3+ instances) ; (b) `normalizeSettingsForm()` extraction in `Settings.svelte` (load and save-response mapping duplicated, pre-existing hot spot) ; (c) shared `ensure_otlp_signal_path()` for the 4 copies of the `/v1/<signal>` suffix-append closure across `lorica/src/otel.rs` and `lorica-api/src/settings.rs` (2 collapsed into `probe_otlp_endpoint` already ; the two exporter-side copies remain). |
