# Story 8.10: Settings & Rate-Limit Cleanup

**Epic:** 8 (v1.6.0)
**Status:** Review
**Author:** Romain G.

## Story

As a Lorica maintainer,
I want `header_timeout_s` + `flood_strict_rps` actually wired (Story 7.3
leftovers) and the dual rate-limit code paths unified,
so that the settings audit history stops surfacing checked-but-not-wired
gaps and adding rate-limit behaviour lives on one admission path.

## Scope note

Story 8.10 is partially shipped: the `update_settings` dedup (AC #6)
landed in v1.5.10 via helper functions (not a `SettingsPatch` builder).
This pass covers the remaining backlog items: wire `header_timeout_s` +
`flood_strict_rps` (backlog #17) and unify the dual rate-limit paths
(backlog #29). AC #7 (`GET /api/v1/settings/schema`) is deferred.

## Acceptance Criteria

1. `header_timeout_s: u32` (default 10) on `GlobalSettings`, plumbed to
   the proxy header phase as a slowloris read-timeout floor.
2. `flood_strict_rps: u32` (default = `flood_threshold_rps / 2`) plumbed
   to the flood-strict factor.
3. Dual rate-limit engines converge: legacy `rate_limit_rps` becomes a
   thin shim synthesising `RateLimit { capacity: burst.unwrap_or(rps),
   refill_per_sec: rps, scope: PerIp }` and routes through the unified
   `LocalBucket` path only; the legacy `rate_limiter.observe` block is
   deleted.
4. Auto-ban escalation lifts to the unified path.
5. Path-rule overrides know about the unified path.
6. `update_settings` dedup - shipped v1.5.10 (helper functions).
7. `GET /api/v1/settings/schema` - **deferred** (see scope note).
8. First-boot operator notice listing routes on the legacy rate-limit
   fields (no DB write).

## Tasks / Subtasks

- [x] AC #1: `header_timeout_s` field + store + diff + plumb to
      `check_slowloris` as the smallest-positive-of(route_ms, global_ms)
      header floor.
- [x] AC #2: `flood_strict_rps` field + store + diff + plumb as the
      flood token-cost multiplier (`flood_threshold_rps / flood_strict_rps`;
      default 0 = auto = `flood_threshold_rps / 2` = the historical 0.5x).
- [x] AC #3: `RateLimit::from_legacy` + `Route::effective_rate_limit`;
      `check_structured_rate_limit` is the single admission point; legacy
      `check_legacy_rate_limit` deleted; `rate_limiter` field removed.
- [x] AC #4: auto-ban escalation (violations tracker + `ban_list` insert
      with `BanReason::RateLimit` + alert) now on the unified path.
- [x] AC #5: `with_path_rule_overrides` re-synthesises `rate_limit` when
      a rule overrides `rate_limit_rps`.
- [x] AC #8: `Once`-guarded first-boot notice in `reload.rs`.
- [x] AC #6: verified already shipped (v1.5.10).
- [ ] AC #7: deferred.

## Dev Notes

Implemented by a delegated agent, then reviewed + re-verified by the
orchestrator. Deviations (all intentional, flagged):

- **Flood model**: the token-bucket path has no sliding-window "limit"
  to halve, so `flood_strict_rps` becomes a per-request token-cost
  multiplier `flood_threshold_rps / flood_strict_rps` on PerIp buckets.
  The default (`flood_strict_rps = 0` -> auto `flood_threshold_rps / 2`)
  reproduces the historical 0.5x factor exactly; the
  `test_flood_threshold_halves_effective_limit` regression pins it.
- **Legacy `rate_limit_rps = 0`** now means "no limit" (yields `None`
  from `effective_rate_limit`) rather than the latent legacy behaviour
  of 429-ing every request - `0` as "disabled" matches token-bucket
  convention and the dashboard's disabled state. No test relied on
  rps=0-as-block.
- **`from_legacy` capacity** uses `burst.filter(|b| b>0).unwrap_or(rps)
  .max(1)` - a degenerate zero-burst guard; identical to the literal
  `burst.unwrap_or(rps)` for every real (None / positive) input.
- **Ordering**: legacy routes are now rate-limited at the unified
  `check_structured_rate_limit` position (before `check_slowloris`)
  instead of the old late legacy slot - both were already pre-WAF, so an
  over-limit slow request now gets 429 before 408. Benign; no protection
  removed. The full `lorica` dispatch-order-lock + 314 lib tests stay
  green.

## Dev Agent Record

### Completion Notes

Gates (Docker, CI-matching): clippy `-p lorica-config -p lorica-api
--all-targets -D warnings` clean; `lorica` crate produces no new clippy
warnings from this story (pre-existing Story 8.2 `check_robots_txt`
doc-list warnings + forked `lorica-proxy` lints are toolchain-1.95 drift,
to be cleaned at epic finalization); `cargo test -p lorica-config` 207 +
7 new equivalence/override/auto-ban tests + doctest; `cargo test -p
lorica-api` 560 + 207; `cargo test -p lorica --lib` 314 passed / 0 failed
(flood 0.5x, slowloris, rate-limit, dispatch order).

## File List

- `lorica-config/src/models/settings.rs` (header_timeout_s,
  flood_strict_rps + defaults)
- `lorica-config/src/models/route.rs` (from_legacy, effective_rate_limit,
  path-rule override re-synth)
- `lorica-config/src/models/tests.rs` (7 tests)
- `lorica-config/src/store/settings.rs` (persist/read new keys)
- `lorica-config/src/diff.rs` (surface new settings in reload diff)
- `lorica-api/src/settings.rs` (request fields + ranged apply)
- `lorica/src/proxy_wiring/config.rs` (ProxyConfig(Globals) fields)
- `lorica/src/proxy_wiring/engines.rs` (remaining_tokens)
- `lorica/src/proxy_wiring/filters.rs` (unified check_structured_rate_limit,
  legacy stage deleted, slowloris global floor)
- `lorica/src/proxy_wiring.rs` (call-site wiring, rate_limiter field removed)
- `lorica/src/reload.rs` (plumb settings + first-boot legacy notice)

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-08-12 | 1.0 | Remaining 8.10 scope (delegated + orchestrator-verified): header_timeout_s + flood_strict_rps wired; dual rate-limit paths unified onto the token-bucket admission path (legacy shim via RateLimit::from_legacy), auto-ban + flood 0.5x + rate-limit headers preserved; first-boot legacy notice. AC #7 deferred, AC #6 already shipped v1.5.10. Gates green incl. lorica lib 314/0. Status -> Review. | Romain G. |
