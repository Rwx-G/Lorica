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
