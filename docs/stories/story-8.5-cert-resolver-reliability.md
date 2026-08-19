# Story 8.5: Cert-Resolver Reliability Pass

**Epic:** 8 (v1.6.0)
**Status:** Review
**Author:** Romain G.

## Story

As an infrastructure engineer,
I want OCSP staple refresh to run as a background task instead of on the
cert-resolver-reload critical path, the cert-resolver reload to be
partial-tolerant (one bad cert does not poison the whole batch), and
Prometheus counters that surface reload outcomes,
so that long-running supervisors keep stapling fresh OCSP responses,
cert-installs do not block TLS handshakes for 10s, and a single
malformed cert does not silently break TLS for every other domain.

## Acceptance Criteria

1. `static OCSP_CLIENT: Lazy<reqwest::Client>` hoisted in
   `lorica-tls/src/ocsp.rs`, mirroring the `HEALTH_HTTP_CLIENT`
   precedent; per-fetch client construction removed from
   `fetch_ocsp_response`.
2. New background task `ocsp_refresh_loop` walks the cert resolver's
   entries every `min(nextUpdate - now, 6h)`, re-fetches each staple via
   `try_fetch_ocsp`, and `arc-swap`s a fresh `Inner` via
   `CertResolver::refresh_staples(...)`.
3. `reload_cert_resolver` becomes synchronous in OCSP terms: it loads
   cert bodies only; OCSP fetches are deferred to the next
   `ocsp_refresh_loop` tick (typically <5s after the swap).
4. `CertResolver::reload` is partial-tolerant: builds cert-by-cert, logs
   + skips malformed entries, swaps with the rest.
5. Four new Prometheus counters:
   `lorica_cert_resolver_reload_total{result="ok|fail"}`,
   `lorica_cert_resolver_active_domains` (gauge),
   `lorica_ocsp_refresh_total{result="ok|fail"}`,
   `lorica_cert_resolver_pending_ocsp_seconds{domain}` (gauge).
6. Hot-swap of OCSP staple bytes does not affect in-flight TLS
   handshakes.
7. Documentation in `docs/architecture/cert-resolver.md` updated with
   the new lifecycle (reload = cert bodies only; OCSP refresh =
   background task).

## Tasks / Subtasks

- [x] AC #1: `OCSP_CLIENT` static in `ocsp.rs` (`std::sync::LazyLock`,
      no new dep on the 1.95 toolchain), timeout + redirect policy baked
      in; `fetch_ocsp_response` uses it.
- [x] AC #4: confirmed already implemented (v1.5.3 partial-tolerant
      `reload` + `ReloadStats::skipped_domains` + two regression tests).
- [x] AC #2/#6: `CertResolver::refresh_staples(&HashMap<domain, ocsp>)`
      rebuilds affected `CertifiedKey`s (clone cert chain + `Arc` key,
      set `.ocsp`), single `arc-swap`; `RefreshStats`; 2 unit tests.
- [x] AC #2: `spawn_ocsp_refresh_loop` in `startup/mod.rs` (6h interval
      + post-reload notify), wired in `single.rs` and `worker.rs`.
- [x] AC #3: `reload_cert_resolver` builds `CertData` with
      `ocsp_response: None`, fires `OCSP_REFRESH_NOTIFY` after the swap.
- [x] AC #5: 4 metrics in `lorica-api/src/metrics.rs` (2 counters
      per-worker aggregated, active-domains gauge refreshed
      supervisor-side, pending-ocsp gauge set in-process).
- [x] AC #7: `docs/architecture/cert-resolver.md` written.

## Dev Notes

Design decisions and deviations:

- **AC #1 `Lazy` -> `std::sync::LazyLock`**: `lorica-tls` does not depend
  on `once_cell`; the 1.95 toolchain has `LazyLock` stable, so no new
  dependency was added. Same semantics as the `HEALTH_HTTP_CLIENT`
  `once_cell::Lazy` precedent.
- **`refresh_staples` rebuilds without PEM**: the resolver does not
  retain PEM after reload. Rather than retain it, the background loop
  re-reads cert bodies from the store (as `reload_cert_resolver`
  already does) to fetch OCSP, then hands the resolver a
  `domain -> ocsp` map. `refresh_staples` rebuilds each `CertifiedKey`
  by cloning the parsed cert chain (`CertifiedKey.cert`) and the
  `Arc`-shared signing key (`CertifiedKey.key`) and setting `.ocsp` -
  no PEM re-parse, no key re-derivation. rustls 0.23 exposes those
  fields publicly (verified by compile).
- **Cadence**: `min(nextUpdate - now, 6h)` collapses to a flat 6h for
  every real-world CA (public OCSP `nextUpdate` is days out). The loop
  uses a 6h interval plus an immediate `Notify` nudge fired by
  `reload_cert_resolver` after each swap, so a freshly installed cert is
  stapled within seconds (AC #3 "typically <5s"). Per-response
  `nextUpdate` parsing to shorten the interval for exotic sub-6h
  responders is not implemented (no real CA ships one; the 6h floor
  keeps staples well under the IV3 12h age bound).
- **AC #5 `worker_id` label deviation**: the two counters are
  per-worker aggregated through the established `PER_WORKER_COUNTERS`
  machinery (supervisor sums worker deltas) rather than carrying a
  literal `worker_id` label - consistent with every other per-worker
  counter in the codebase (Story 8.11 pattern). `active_domains` is
  refreshed supervisor-side from the store in `get_metrics` (the
  supervisor has no resolver), so it is meaningful in both modes.
  `pending_ocsp_seconds{domain}` is a runtime gauge set in-process by
  the loop; like every Lorica runtime gauge it is not shipped from
  workers to the supervisor, so it is authoritative in single-process
  mode - the cross-worker OCSP signal there is `ocsp_refresh_total`.
- **Worker mode**: each worker owns its own resolver and runs its own
  loop; OCSP fetches are idempotent, so N workers fetching independently
  is correct (minor redundancy).

## Dev Agent Record

### Completion Notes

- lorica-tls: `OCSP_CLIENT` + `refresh_staples`/`RefreshStats` +
  `domains()`; `cargo test -p lorica-tls --lib` 35/35 green (incl. 2 new
  refresh_staples tests), no warnings.
- lorica/lorica-api wiring: metrics (4), reload defer + notify + reload
  counter, `spawn_ocsp_refresh_loop`, both startup modes. Verified in
  Docker: clippy `-D warnings` on lorica-tls + lorica-api + lorica
  (all-targets), lorica-api lib tests green. Frontend build skipped via
  `SKIP_FRONTEND_BUILD=1` (no frontend change in this story).

## File List

- `lorica-tls/src/ocsp.rs` (OCSP_CLIENT static, shared client)
- `lorica-tls/src/cert_resolver.rs` (refresh_staples, RefreshStats,
  domains, staple_for test helper, 2 tests)
- `lorica-api/src/metrics.rs` (4 metrics + helpers, PER_WORKER wiring,
  active_domains refresh in get_metrics)
- `lorica/src/reload.rs` (defer OCSP, OCSP_REFRESH_NOTIFY, reload
  counter)
- `lorica/src/startup/mod.rs` (spawn_ocsp_refresh_loop)
- `lorica/src/startup/single.rs` (loop wired)
- `lorica/src/startup/worker.rs` (loop wired)
- `docs/architecture/cert-resolver.md` (new)

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-08-12 | 1.0 | Story drafted from Epic 8 PRD + implemented: OCSP shared client, background refresh loop + notify, reload OCSP-deferral, refresh_staples arc-swap, 4 metrics, architecture doc. AC #4 was already satisfied (v1.5.3). Gates: lorica-tls 35/35, clippy clean on lorica-tls/lorica-api/lorica, lorica-api lib tests green. Status -> Review. | Romain G. |
