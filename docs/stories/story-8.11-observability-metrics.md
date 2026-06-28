# Story 8.11: Observability Gap (lorica-metrics + SLA / probe / notification counters + BanReason)

**Epic:** [Epic 8 - Multi-User RBAC, AI Bot Defense & Zero-Downtime Upgrades (v1.6.0)](../prd/epic-8-v1.6.0.md)
**Status:** Review
**Priority:** P1
**Author:** Romain G.

---

As an operator, I want to alert on SLA threshold breaches, active-probe outcomes, and notification-dispatch outcomes from Prometheus, and I want the `/api/v1/bans` JSON to tell me WHY each IP was banned.

## Acceptance Criteria (from the Epic 8 PRD)

1. New `lorica-metrics` crate extracted from `lorica-api/src/metrics.rs`: owns the custom Prometheus `REGISTRY` + registration helpers + type-safe counter wrappers. `lorica-api`, `lorica-bench`, `lorica-notify` all depend on it; the `lorica-api -> lorica-bench / lorica-notify` cycle is unblocked.
2. Three new counters: `lorica_sla_breach_total{route_id, threshold_kind}` (lorica-bench passive SLA), `lorica_active_probe_outcome_total{probe_id, outcome}` (lorica-bench active probes), `lorica_notification_dispatch_total{channel, outcome}` (lorica-notify channels).
3. `BanReason` enum (`RateLimit`, `WafFlood`, `WafCriticalRule`, `Manual`); the ban-list value type carries the reason.
4. `BanReason` surfaced in `/api/v1/bans` JSON as a `reason` field.
5. Dashboard Security -> Bans table gains a Reason column with a coloured pill per reason.
6. Ban-issuance call sites audited and pass the correct `BanReason`; the supervisor-side `BanIp` RPC payload gains a reason field.
7. `lorica-metrics` re-exports `prometheus` so consumers do not depend on it directly (version-skew guard).

## Tasks

- [x] AC #1/#7: extract `lorica-metrics` (REGISTRY + register helpers + generic per-worker snapshot/apply + `pub use prometheus`); lorica-api/bench/notify depend on it; workspace members, both Dockerfiles, BUMP-CHECKLIST, source-tree updated. Cycle confirmed broken via `cargo tree`.
- [x] AC #2: SLA-breach + active-probe counters (lorica-bench), notification-dispatch counter (lorica-notify), registered via lorica-metrics; unit tests per counter.
- [x] AC #3/#4/#6: `BanReason` enum (lorica-api/src/ban.rs), ban value `(Instant,u64)` -> `(Instant,u64,BanReason)`, issuance sites pass the real reason, BanIp RPC + worker ban-report carry the reason, `/api/v1/bans` returns `reason`.
- [x] AC #5: dashboard Reason column + coloured pills.
- [ ] e2e for IV1/IV2/IV3 (deferred - see Dev Notes; counters + ban-reason are unit-tested, a metrics-scrape e2e is a follow-up).

## Integration Verification

- IV1: an SLA breach increments `lorica_sla_breach_total`. (Unit: `record_sla_breach_increments_counter`; the breach transition site records it.)
- IV2: a failing notification webhook increments `lorica_notification_dispatch_total{channel="webhook",outcome="http_5xx"}`. (Unit: `classify_response_status_buckets` + per-channel record.)
- IV3: an IP banned via WAF appears in `GET /api/v1/bans` with a `reason`; the dashboard renders the pill. (Unit: `list_bans_includes_reason`, `merged_ban_list_carries_reason`.)

## Dev Notes

### Extraction shape (AC #1)
Minimal, low-risk extraction from the 1716-line `lorica-api/src/metrics.rs`: `lorica-metrics` owns `REGISTRY`, the `register_int_counter[_vec]` / `register_int_gauge[_vec]` / `register_histogram_vec` helpers, `gather()`, the generic cross-worker snapshot/apply machinery (`GenericCounterTuple`, `CounterTarget`, `snapshot_per_worker_counters(names)`, `apply_worker_generic_counters`), and `pub use prometheus`. lorica-api KEEPS all its counters, the `record_*`/`inc_*` helpers, the `/metrics` handler, the `AI_BOT_STATS_BUFFER`, and the domain `PER_WORKER_COUNTERS` list (passed into the generic snapshot fn); it just registers against the shared REGISTRY. Metric names + `/metrics` output are unchanged. The 8.2 AI-bot counters thus already sit on the shared registry - no separate migration needed.

### SLA threshold_kind deviation (AC #2)
The PRD suggested `threshold_kind = latency_p95|latency_p99|error_rate|uptime`, but the passive-SLA evaluator (`check_thresholds`) reduces every route to ONE composite boolean (`success_pct >= target_pct`); the per-bucket `max_latency_ms` / `success_status` thresholds are already folded into `success_count` BEFORE the breach transition, so the distinct cause is not available at the emit point. The counter therefore ships a single honest `threshold_kind = "target_pct"`. Exposing distinct kinds would require threading the failing dimension through the SLA aggregation pipeline - a separate enhancement, out of scope for a counter story.

### BanReason reality vs the PRD (AC #3/#6)
- The PRD names `lorica/src/cache.rs` as the enum home; that file does not exist. The real data-plane ban map is `LoricaProxy.ban_list: DashMap<String, (Instant, u64)>` in `lorica/src/proxy_wiring.rs`, read by the management API in `lorica-api/src/cache.rs::list_bans`. The enum lives in `lorica-api/src/ban.rs` (reachable from the binary, which depends on lorica-api).
- The value type became a 3-tuple `(Instant, u64, BanReason)` (aliased `BanMap` to satisfy clippy `type_complexity`).
- `WafFlood` and `Manual` are defined per AC #3 but have NO issuance site in the current codebase: there is a single WAF auto-ban path (repeated WAF blocks crossing `waf_ban_threshold`) mapped to `WafCriticalRule`, and the codebase "flood" defense is the rate-limiter's adaptive halving which feeds the `RateLimit` ban; there is no manual-ban POST endpoint (only `DELETE /api/v1/bans/{ip}`). No default-to-`RateLimit` anywhere - each issuance site passes its real reason; RPC-decode boundaries default to `WafCriticalRule` (the only reason the supervisor broadcasts) for forward-compat.
- RPC: `lorica-command` messages are hand-written prost (the `.proto` is documentation-only). `Command.ban_reason` = field 6, `BanReportEntry.reason` = field 4 (both new int32, no reuse).

### lorica-notify dispatch outcome mapping
webhook/slack: 2xx->ok, 4xx->http_4xx, 5xx->http_5xx, `reqwest is_timeout`->timeout, other transport->connect_failed. SMTP (no HTTP status): ok / timeout-ish text -> timeout / else connect_failed. stdout always ok. Recorded inside each channel `send` (where the live error/status exists), exactly once per dispatch attempt.

## File List

- lorica-metrics/ (new crate: Cargo.toml, src/lib.rs)
- lorica-api/src/metrics.rs (re-point to shared REGISTRY), Cargo.toml
- lorica-bench/{Cargo.toml, src/lib.rs, src/metrics.rs (new), src/passive_sla/persistence.rs, src/active_probes.rs}
- lorica-notify/{Cargo.toml, src/lib.rs, src/metrics.rs (new), src/channels/{mod,email,webhook,slack}.rs}
- lorica-api/{src/ban.rs (new), lib.rs, server.rs, cache.rs, workers.rs, tests.rs, openapi.yaml}
- lorica-command/{proto/command.proto, src/messages.rs}
- lorica/src/{proxy_wiring.rs, proxy_wiring/filters.rs, proxy_wiring/worker_rpc.rs, startup/worker.rs, startup/supervisor.rs}, lorica/tests/metrics_pull_rpc_e2e_test.rs
- lorica-dashboard/frontend/src/{lib/api.ts, routes/Security.svelte}
- Cargo.toml, Cargo.lock, Dockerfile, Dockerfile.dev, docs/BUMP-CHECKLIST.md, docs/architecture/source-tree.md

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-06-28 | 1.0 | Story implemented. lorica-metrics extracted (cycle broken, metric names unchanged); SLA-breach + active-probe + notification-dispatch counters; BanReason end-to-end (enum + value type + issuance + BanIp RPC + /api/v1/bans + dashboard pills). Deviations: SLA threshold_kind is a single composite `target_pct` (evaluator reduces to one boolean); WafFlood + Manual variants defined but unused (no issuance site in the current codebase). e2e for the 3 IVs deferred (counters + ban-reason unit-tested). Gates: clippy product set clean, lorica-api 506 / lorica-command 44 / lorica-bench 66 / lorica-notify 60 / lorica-metrics tests pass, lorica binary compiles, frontend tsc/svelte-check/lint clean. | Romain G. |
| 2026-06-28 | 1.1 | BMad completion audit (AC-completion, security/cardinality, architecture+quality) + remediation. Verdict: 7/7 AC met; security sound (counter cardinality bounded, BanReason i32 decode total/panic-free, ban enforcement gates only on duration with reason cosmetic); both disclosed deviations confirmed accurate (SLA single target_pct, WafFlood/Manual unused) - their consequence is that the PRD's literal IV1 `threshold_kind="latency_p95"` and IV3 `reason="waf_flood"` cannot occur (the SLA model is target-pct-only; the WAF ban path is waf_critical_rule). Fixes (commits 6aa68391, 8b2be535): a guard test pins each PER_WORKER_COUNTERS name to its registered label arity (silent-misroute class); the triplicated BanReportEntry->reason wire decode is a single `decode_ban_report_entry` helper with a round-trip + fallback unit test (worker-mode reason path was only asserted on ip/len); the bare `(Instant,u64,BanReason)` ban tuple becomes a named `BanRecord` struct (transposition-magnet removed). Low findings accepted with rationale: SMTP/probe timeout string-matching (clean fix needs typed-error plumbing), `reset_*_for_test` pub (needed cross-crate), idiom divergence + lorica-api helper retrofit (taste / explicit follow-up). cargo audit re-run for the new crate (no new advisory surface). | Romain G. |
