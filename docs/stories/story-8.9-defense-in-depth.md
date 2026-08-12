# Story 8.9: Defense-in-Depth Pass

**Epic:** [Epic 8 - Multi-User RBAC, AI Bot Defense & Zero-Downtime Upgrades (v1.6.0)](../prd/epic-8-v1.6.0.md)
**Status:** Done
**Priority:** P1
**Author:** Romain G.
**Depends on:** Story 8.3 (RBAC `Session.username`/`role` as operator identity, shipped on this branch); Story 8.7 bot-stash refactor (shipped v1.5.10); Story 8.11 lorica-metrics (shipped on this branch).

---

As a security-conscious operator, I want a structured admin audit log on every state-mutating endpoint, a per-source-IP TCP connection cap, a bounded captcha-PNG stash, and a per-route mirror semaphore, so that I can answer "who deleted route X at 03:14?", a single source IP cannot exhaust `max_global_connections`, captcha flooding cannot OOM the process, and one slow shadow target cannot starve every other route's mirror.

## Acceptance Criteria (from the Epic 8 PRD)

1. New `audit_log!(state, action = "route.delete", target_id = id, before = ..., session = &session)` macro feeding a dedicated `lorica::audit` structured-log target. Applied uniformly to every state-mutating handler (~30 sites across `lorica-api/src/{routes/crud, backends, certificates, settings, dns_providers, probes, loadtest, config, auth, acme/*, cert_export, waf, cache, users}.rs`). RBAC username (Story 8.3) is the operator identity in the log.
2. Per-row audit-log entry shape: `{id, timestamp, operator_username, operator_role, action, target_type, target_id, before_payload_hash, after_payload_hash, ip, user_agent, prev_chain_hash, chain_hash}`. `before` / `after` payloads are SHA-256-hashed individually. `chain_hash = SHA-256(prev_chain_hash || timestamp || operator_username || operator_role || action || target_type || target_id || before_payload_hash || after_payload_hash || ip || user_agent)`; every field is length-prefixed with its u64-LE byte length before hashing so a boundary shift (`ab|c` vs `a|bc`) cannot collide. The genesis row uses `prev_chain_hash = 0x00 * 32`. (Amended 2026-08-12: the chain binds all eleven content fields, including `operator_role`, `ip`, and `user_agent`, rather than the original seven, so those columns cannot be altered without breaking the chain. This is a tamper-EVIDENT guarantee - an on-host writer holding the co-located DB has no separate key to forge against; a keyed-HMAC variant with an off-box head anchor is the stronger follow-up if forensic non-repudiation against a root-level attacker is required.)
3. New `GET /api/v1/audit/verify` endpoint (SuperAdmin only) walks the audit table from genesis, recomputes each `chain_hash`, and returns `{verified: bool, total_rows, first_break_id?, first_break_reason?}`. A break (chain mismatch or missing prev row) localises tampering to the earliest affected row.
4. Audit-log emission is also bridged to OTel via the existing tracing subscriber: the `audit_log!` macro emits a `tracing::info!(target: "lorica::audit", ...)` event AND attaches it to the current request span (when one exists), so operators using OTel correlation can pivot from a request trace to its audit footprint.
5. New global setting `connection_limits_per_ip: Option<u32>` (default `None` = no cap). Enforced at TCP accept (in the existing connect-time CIDR filter neighbourhood at `lorica/src/proxy_wiring.rs:3410-3430`) via `DashMap<IpAddr, AtomicU32>`; over-cap connections are refused at `accept()` (no TLS handshake, no log entry except a counter `lorica_per_ip_connection_refused_total`).
6. Captcha PNG stash (Story 8.7's bot-stash refactor) gains: a global LRU cap (default 10000 entries, configurable `bot_stash_max_entries`) + a per-IP-prefix counter (default `/24` for IPv4, `/48` for IPv6, configurable `bot_stash_per_prefix_max`, default 100). Over-cap challenge issuance returns `503 Retry-After: 30`.
7. `MIRROR_SEMAPHORE` global cap of 256 replaced with per-route semaphores: `DashMap<RouteId, Arc<Semaphore>>` sized from a new `mirror_max_concurrent_per_route` global setting (default 32). A coarse global safety net stays at `mirror_max_concurrent_global` (default 4096).
8. Dashboard Security tab gains an "Audit log" sub-page: paginated table (timestamp / operator / action / target / chain status) with filtering by operator, action prefix, and date range, plus a "Verify chain integrity" button calling `/api/v1/audit/verify` and rendering the result. Backed by a new `GET /api/v1/audit` endpoint (Operator + SuperAdmin only; SuperAdmin sees the verify button).
9. Audit log retention: stored in a dedicated `audit_log` SQLite table with auto-eviction via existing `LogStore` retention machinery (default 90 days, configurable `audit_log_retention_days`). Retention truncation preserves chain integrity by storing the earliest-surviving row's `prev_chain_hash` as a "retention seal" in the `audit_log_meta` table; `verify` accepts the seal as the new genesis when older rows are absent.

## Integration Verification

- IV1: `DELETE /api/v1/routes/5` issued by user `alice` produces an audit-log entry with `operator_username="alice", action="route.delete", target_id=5`; visible via `GET /api/v1/audit?action=route.delete`; the entry's `chain_hash` matches the recomputed value.
- IV2: 1000 simultaneous TCP connect attempts from a single IP with `connection_limits_per_ip=10` result in 10 successful connects + 990 refused connects; `lorica_per_ip_connection_refused_total` shows 990.
- IV3: A mirror endpoint configured to hang indefinitely on route A does not impact route B's mirror throughput (measured via parallel `wrk` against both routes).
- IV4: After 100 audit-log mutations, `GET /api/v1/audit/verify` returns `{verified: true, total_rows: 100}`; manually tampering with row 47's `target_id` in SQLite makes verify return `{verified: false, first_break_id: 47, first_break_reason: "chain_hash_mismatch"}`. Retention-truncating the first 50 rows + re-running verify still returns `{verified: true}` thanks to the retention seal.

## Tasks

- [x] AC #2/#9 (audit storage): `audit_log` + `audit_log_meta` tables in `LogStore::open`; `insert_audit` computes the chain INSIDE the single `Mutex<Connection>` critical section (read last `chain_hash` + write row atomically, no writer-queue path); `query_audit` (operator / action-prefix / date-range filters + limit + before_id cursor, LIKE wildcards escaped); `verify_audit_chain` (genesis or retention-seal start); `enforce_audit_retention` (cutoff-based DELETE + seal write, empty-table case seals the tail); retention hooked into `spawn_retention_loop` with new `audit_log_retention_days` setting (default 90, 0 = keep forever).
- [ ] AC #1/#4 (emission): `lorica-api/src/audit.rs` with `AuditEntry` builder + `record_audit(...)` helper (macro-or-fn per Dev Notes) that SHA-256-hashes before/after payloads, inserts via `spawn_blocking` (skip when `log_store` is `None`), and emits `tracing::info!(target: "lorica::audit", ...)`; light `api_request` span middleware so the event lands inside a request span; applied to every state-mutating handler (~45 real sites incl. sla / logs-clear / upgrade / ai-crawlers, see Dev Notes inventory).
- [ ] AC #3/#8 API: `GET /api/v1/audit` (Operator+, authorize floor via existing GET+users-style carve-out) + `GET /api/v1/audit/verify` (SuperAdmin only); OpenAPI.
- [ ] AC #5: per-IP connection cap. Fork change in `lorica-core` listeners: `ConnectionFilter` gains an RAII accept-permit so the count decrements on stream drop (see Dev Notes design); `GlobalConnectionFilter` gains `DashMap<IpAddr, AtomicU32>` + `ArcSwapOption<u32>` limit; `connection_limits_per_ip` setting plumbed via `PreparedReload`/`commit_prepared_reload`; `lorica_per_ip_connection_refused_total` counter registered via lorica-metrics + `PER_WORKER_COUNTERS` aggregation (refusals happen in worker processes).
- [ ] AC #6: bot-stash caps. `bot_stash_insert` gains refuse-over-cap semantics (global `bot_stash_max_entries`, per-prefix `bot_stash_per_prefix_max` via `COUNT` on `(ip_prefix_disc, ip_prefix_bytes)` + new index); `BotEngine::insert` returns capacity outcome; `serve_challenge` returns `503` + `Retry-After: 30` on refusal (Cookie mode exempt, no stash); settings keys + plumbing.
- [ ] AC #7: mirror semaphores. `MIRROR_SEMAPHORE` (256 global) replaced by `DashMap<String, Arc<Semaphore>>` per route + global net; sized from `mirror_max_concurrent_per_route` (default 32) / `mirror_max_concurrent_global` (default 4096) passed through `ProxyConfig`; stale-route entries pruned on reload.
- [x] AC #8 UI: "Audit" tab in `Security.svelte` (6th in-file tab): filterable paginated table + chain-status column + SuperAdmin-only "Verify chain integrity" button; api.ts types + methods.
- [x] Settings surface: `audit_log_retention_days`, `connection_limits_per_ip`, `bot_stash_max_entries`, `bot_stash_per_prefix_max`, `mirror_max_concurrent_per_route`, `mirror_max_concurrent_global` (model + store + UpdateSettingsRequest + frontend types; UI exposure in GlobalConfig/Network tab where fitting).
- [x] IV coverage: unit tests (chain compute/verify/tamper/seal, stash caps, username inventory); e2e `audit-smoke` profile (IV1 + IV4 tamper via sqlite3 + retention seal; per-IP cap asserted with parallel connects if practical, else unit/integration-level); IV3 asserted at unit level (two routes, one saturated semaphore, other proceeds).
- [x] Gates: product-crate tests, CI clippy set, cargo audit, frontend svelte-check/tsc/lint/vitest, e2e profiles green.

## Dev Notes

### Audit storage (verified 2026-08-11)

- `LogStore` (`lorica-api/src/log_store.rs`) is `Mutex<Connection>` on `<data_dir>/access-log.db`, tables created inline in `open()` (no migration-version table; additive `let _ = ALTER` precedent). Add `audit_log` + `audit_log_meta` there. Retention today is count-based (`enforce_retention`); `audit_log_retention_days` needs a `DELETE WHERE timestamp < cutoff` form + seal upsert.
- **Chain serialization**: two concurrent inserts must not fork the chain. `insert_audit` reads `chain_hash` of the max-id row and writes the new row inside ONE lock hold. Do NOT route audit rows through the `log_writer` mpsc (supervisor mode has `log_writer = None` anyway; API handlers insert directly via `spawn_blocking`).
- `AppState.log_store` is `None` in worker mode and unit tests: emission is `if let Some(store)` - the management API only runs in supervisor/single, so no audit rows are lost. `spawn_retention_loop` (startup/mod.rs:262, hourly) runs in exactly those processes.
- Timestamps: RFC 3339 UTC strings (matches access_logs). `target_id` stored TEXT.

### Emission shape (AC #1 deviation, macro -> helper fn)

The PRD sketches `audit_log!(state, action = ..., before = ..., session = &session)`. A declarative macro adds nothing over a plain async helper here (no varargs, no compile-time target table) and hides the `.await`. Ship `audit::record(&state, &session, req_meta, action, target_type, target_id, before, after)` where `req_meta` carries ip + user-agent captured by the handler (`ConnectInfo` + `HeaderMap` are pure additive extractor params; `require_auth` already injects `Session` on every protected route). `before`/`after` are `Option<&serde_json::Value>` hashed SHA-256 before storage (payloads themselves are never persisted - no secret material lands in the audit table by construction).
Failure policy: audit insert failure logs `tracing::error!` and does NOT fail the mutation (availability over auditability; the tamper-evident chain covers integrity, not liveness). Emission happens AFTER the mutation succeeds, with the outcome reflected in `after` (deletes: `after = None`).

### Handler inventory (~45 emission sites)

routes/crud 3 (route.create/update/delete), backends 3, certificates 4 (+self-signed), settings 7 (settings.update, notification.create/test/update/delete, preference.update/delete), dns_providers 4 (incl. test - it fires outbound calls with stored credentials), probes 3, loadtest 7 (config CRUD + start/confirm/abort/clone), config 2 (import + export - export dumps the config, audit-worthy read), auth 3 (login success, logout, password.change - login is pre-session: operator fields come from the just-verified user), routes/cert_export 4 (acl.create/delete, reapply, orphan.delete), waf 6, cache 2 (cache.purge, ban.delete), users 3, ai_crawlers 3, acme 6 (4 provision flows + manual check/confirm + cert.renew), sla 2, logs 1 (logs.clear), upgrade 1 (system.upgrade). `cert_export.rs` internal exporters (ACME-triggered) are system actions, not operator actions: out of audit scope this story.
Signature template: `certificates.rs::download_certificate` already carries `Option<ConnectInfo<SocketAddr>> + Extension<AppState> + Extension<Session>`.

### AC #4 reality (OTel)

The OTel bridge layer has no per-target filter and lorica-api has no request span today. Plan: emit the `lorica::audit` event (flows to fmt + OTel automatically), and add a minimal `api_request` span middleware (method, path, username once authed) so `Span::current()` is meaningful; "attaches to the current request span (when one exists)" is then true for every API mutation. No per-layer target filtering added this story.

### AC #5 design (the hard one)

There is no disconnect hook in the forked listener: `ConnectionFilter::should_accept(Option<&SocketAddr>) -> bool` and the accepted `Stream` escapes the filter (lorica-core/src/listeners/l4.rs:375). A live per-IP count therefore needs a fork change: `should_accept` is superseded by an acquire-style API returning an RAII permit that `ListenerEndpoint::accept` attaches to the accepted stream (dropped with the connection -> decrement). Fallback if the stream cannot carry a guard cheaply: decrement via a `Drop` guard boxed into the stream's socket digest extension. Semantics documented honestly: the cap is per worker process (each worker owns a `GlobalConnectionFilter`), so the effective cap is `N x workers`; the setting doc and dashboard hint say so (shmem-backed global count is out of scope, backlog candidate).
Refusal is silent by design except `lorica_per_ip_connection_refused_total` - registered through lorica-metrics AND added to `PER_WORKER_COUNTERS` + `resolve_per_worker_counter` (refusals happen in workers; without aggregation the supervisor-served /metrics would read 0).

### AC #6 semantics change

Current `bot_stash_insert` EVICTS oldest rows over 10k (flooder always wins a slot, evicting legitimate pending challenges). This story flips to REFUSAL: over global cap or per-prefix cap, the insert is rejected and `serve_challenge` answers `503 Retry-After: 30` (extend `write_plain` with an optional Retry-After). Cookie mode allocates no stash entry: exempt. New index on `(ip_prefix_disc, ip_prefix_bytes)` for the per-prefix COUNT. The `/24 / /48` prefix derivation already exists at stash time (`ip_prefix_disc`/`ip_prefix_bytes` columns, Story 8.7).

### AC #7 wiring

`spawn_mirrors` is a free fn (`mirror_rewrite.rs:355`) with `route_id: String` already threaded; caller sits in `filters.rs` with `&ProxyConfig` loaded. Add `mirror_max_concurrent_per_route` / `mirror_max_concurrent_global` to `ProxyConfigGlobals` -> `ProxyConfig` (reload.rs:662 pattern), pass both into `spawn_mirrors`, replace the `Lazy<Semaphore>` with `Lazy<DashMap<String, Arc<Semaphore>>>` + a global `Lazy<Semaphore>`-style net sized once (net stays coarse: resize-on-reload not required for a safety net; per-route semaphores are created lazily sized from the current setting and rebuilt when the sizing value changes - store the size alongside the semaphore and replace on mismatch). `try_acquire` on both, `dropped_saturated` metric outcome preserved.

### Settings plumbing map

API-only: `audit_log_retention_days`. Data-plane (need ProxyConfig or filter plumbing + reload): `connection_limits_per_ip` (via `PreparedReload`/`commit_prepared_reload` next to the CIDR policy), `mirror_max_concurrent_per_route`/`_global` (via ProxyConfigGlobals), `bot_stash_max_entries`/`bot_stash_per_prefix_max` (read where? `serve_challenge` has no GlobalSettings: thread through `BotProtectionConfig`-adjacent runtime config or a process-global `ArcSwap` refreshed in `apply_per_process_reload_state` - decide at implementation, the ArcSwap matches the bot-secret precedent).

### Authorization

`GET /api/v1/audit` must be Operator+ (AC #8) - GETs default to Viewer in `authorize.rs`, so add an explicit carve-out (like the cert-download rule). `/api/v1/audit/verify` -> SuperAdmin carve-out.

## Dev Agent Record

### Debug Log

- Phase 1: `ring` (already a lorica-api dep) provides SHA-256; no new dependency. Chain fields are hashed length-prefixed (u64 LE + bytes), not raw-concatenated - boundary-shift collisions (`ab|c` vs `a|bc`) are unit-tested. clippy `too_many_arguments` forced `compute_chain_hash(prev, &ChainInput)` with `From<&NewAuditEntry>` / `From<&AuditRecord>` conversions.
- Retention seal semantics: seal = the earliest SURVIVING row's `prev_chain_hash`; when truncation empties the table, seal = newest deleted row's `chain_hash` so the NEXT insert still chains (tested). `insert_audit` prefers last-row hash > seal > genesis.

### Completion Notes

All 9 AC + 4 IV covered across 7 commits (story, storage, emission, per-IP cap, stash+mirror, e2e+docs, e2e-root-fix, ui). Disclosed deviations, all in Dev Notes: (1) `audit::record` helper fn instead of an `audit_log!` macro; (2) the per-IP cap is per-worker-process, so the effective ceiling is `value x workers` (documented in the setting + security.md; a shmem-backed global count is a backlog item); (3) bot-stash flips from eviction to refusal (`503 Retry-After: 30`), a deliberate behaviour change so a flooder cannot displace legitimate pending challenges; (4) a minimal `api_request` span middleware added for AC #4 (lorica-api had no request span). IV1 + IV4 are covered end-to-end by the `audit` e2e profile (17/17, including a real sqlite tamper of row id=3 that verify localises with `chain_hash_mismatch`, plus the Operator/SuperAdmin/Viewer floors on `/audit` and `/audit/verify`); IV3 (mirror isolation) and the retention seal are unit-tested. Fork note: AC #5 required a `lorica-core` listener change - `ConnectionFilter` gained an RAII accept-permit (`AcceptVerdict`/`AcceptPermit`) that `ListenerEndpoint::accept` attaches to the stream, so the per-IP count decrements exactly at connection close; the default trait impl preserves every existing filter. Env note: the SynologyDrive mount silently corrupts `include_bytes!` fixtures (ai_bot vendor_ips) while git reports them clean; restore with `git checkout -- lorica/src/ai_bot/vendor_ips/` before running `cargo test -p lorica --lib` locally.

## File List

Backend (storage + emission):
- lorica-api/src/audit.rs (new: chain primitives + AuditContext + record + list/verify handlers)
- lorica-api/src/log_store.rs (audit_log + audit_log_meta tables, insert/query/verify/enforce_audit_retention)
- lorica-api/src/middleware/{request_span.rs (new), mod.rs, authorize.rs} (api_request span; /audit + /audit/verify role floors)
- lorica-api/src/{server.rs, lib.rs} (routes + span layer + module)
- lorica-api/src/{routes/crud.rs, backends.rs, certificates.rs, settings.rs, dns_providers.rs, probes.rs, loadtest.rs, config.rs, auth.rs, routes/cert_export.rs, waf.rs, cache.rs, users.rs, ai_crawlers.rs, sla.rs, logs.rs, upgrade.rs, acme/{http01,dns01,dns01_manual,renewal}.rs} (~45 audit emission sites)
- lorica/src/startup/mod.rs (audit retention hook in spawn_retention_loop)

Per-IP cap (fork + filter):
- lorica-core/src/listeners/{connection_filter.rs (AcceptVerdict/AcceptPermit/try_accept), l4.rs (permit ride-along), mod.rs} + protocols/l4/stream.rs (accept_permit field)
- lorica/src/connection_filter.rs (per-IP DashMap + RAII PerIpPermit), lorica/src/reload.rs (PreparedReload.connection_limits_per_ip), lorica-api/src/metrics.rs (counter + PER_WORKER_COUNTERS)

Stash + mirror:
- lorica-config/src/store/bot_stash.rs (BotStashInsertOutcome refusal + per-prefix cap), store/mod.rs (V43 prefix index), lib.rs
- lorica/src/bot.rs (BotEngine::insert caps), proxy_wiring/{bot_handlers.rs (503 Retry-After), filters.rs, config.rs (ProxyConfigGlobals fields), mirror_rewrite.rs (per-route semaphores), proxy_wiring.rs}

Config + settings:
- lorica-config/src/models/settings.rs, store/settings.rs (6 new keys)

Frontend:
- lorica-dashboard/frontend/src/lib/api.ts (Audit types + methods, settings fields)
- lorica-dashboard/frontend/src/routes/Security.svelte (Audit tab), routes/Settings.svelte, components/settings-tabs/NetworkTab.svelte (defense-in-depth settings)

E2E + docs:
- tests-e2e-docker/{docker-compose.yml, run.sh, test-runner/Dockerfile, test-runner/run-audit-smoke.sh (new)} (audit profile, sqlite tamper)
- docs/security.md (audit-log + resource-cap sections), CHANGELOG.md

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-08-12 | 1.2 | AC #2 amended (approved): the `chain_hash` formula now binds all eleven content fields (adds `operator_role`, `ip`, `user_agent`) instead of the original seven, matching the hardened chain landed in the v1.6.0 audit-fix sweep. Fields stay length-prefixed. Keeps the stronger tamper-evidence; keyed-HMAC-with-off-box-anchor noted as the follow-up for root-attacker non-repudiation. | Romain G. |
| 2026-08-12 | 1.1 | Epic 8 lance-dev closure: full e2e verified this cycle (audit-smoke 17/17: chain verify, sqlite tamper localisation, per-IP cap, RBAC floors), CI gates green. No Critical/High open. Status -> Done. | Romain G. |
| 2026-08-11 | 1.0 | Phases 2-5: audit emission on ~45 handlers + `/audit` + `/audit/verify` + api_request span (AC #1 #3 #4); per-source-IP TCP connection cap via a lorica-core RAII accept-permit fork + per-IP DashMap + counter (AC #5); bot-stash refusal caps with `503 Retry-After` + per-prefix index + per-route mirror semaphores (AC #6 #7); dashboard Audit tab + defense-in-depth settings (AC #8); 6 settings keys; audit e2e profile 17/17 (sqlite tamper localisation + RBAC floors, IV1 #4); security.md + CHANGELOG. Deviations recorded in Completion Notes. Status -> Review. Gates: lorica-api 560 + lorica-config 200 + lorica 314 lib tests green, CI clippy clean, cargo audit clean, frontend svelte-check/tsc/lint/vitest 363 green, audit e2e 17/17. | Romain G. |
| 2026-08-11 | 0.2 | Phase 1 (AC #2 #9 storage): audit.rs chain primitives (GENESIS, hash_payload, ChainInput, compute/recompute) + audit_log/audit_log_meta tables + insert/query/verify/retention in LogStore + audit_log_retention_days setting + hourly retention hook. 11 unit tests (chain round-trip, tamper localisation, middle-row deletion, seal survival incl. empty-table, filter escaping). lorica-api 559 tests green, clippy clean. | Romain G. |
| 2026-08-11 | 0.1 | Story drafted from Epic 8 PRD + deep code exploration (LogStore retention, 57-handler mutation inventory, missing disconnect hook in forked listener, stash eviction-vs-refusal, mirror semaphore wiring, settings plumbing map). Deviations flagged in Dev Notes: helper fn instead of macro (AC #1), per-worker cap semantics (AC #5), stash refusal replaces eviction (AC #6), minimal API request span added for AC #4. | Romain G. |
