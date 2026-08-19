# Epic 8 QA Report - v1.6.0

**Epic:** Multi-User RBAC, AI Bot Defense & Zero-Downtime Upgrades
**Target version:** 1.6.0
**Date:** 2026-08-12
**Author:** Romain G.

## 1. Executive summary

Epic 8 lands the v1.6.0 cycle: three headline features (AI-crawler
deny-list, hot binary upgrade, multi-user RBAC) plus the audit-closure
backlog (cert-resolver reliability, defense-in-depth, observability,
settings/rate-limit cleanup, supply-chain vendoring, management-plane
hardening).

Overall gate: **PASS.** Every Epic 8 story is Done. Story 8.8
(management-plane hardening) initially landed as a partial - its
metrics-auth hardening shipped first while the TLS-listener migration and
CSP3 style-src nonce were held back for verifiability - and was then
completed in the same cycle once e2e / frontend-build verification was
available: the management API is served over TLS (verified by the Docker
e2e suite over https, rbac 37/37 + audit 17/17) and the dashboard CSP
drops `'unsafe-inline'` from style-src via a per-request nonce. The one
residual is the browser-only CSP-violation check (IV4), left as an
operator spot-check. Story 8.10 also gained its `settings/schema`
endpoint (AC #7), and two v1.6.0-candidate backlog items closed
in-cycle: the WAF retention + 24h count (#44) and the clippy-1.95
workspace cleanup (#43/#45).

Story status:

| Story | Title | Status |
|-------|-------|--------|
| 8.1 | Foundation module split | Closed (shipped v1.5.10/11) |
| 8.2 | AI-crawler deny-list | Done |
| 8.3 | Multi-user RBAC | Done |
| 8.4 | Hot binary upgrade | Done |
| 8.5 | Cert-resolver reliability | Done |
| 8.6 | Health-check parallelism | Closed (shipped v1.5.8/10) |
| 8.7 | SQLite reactor-stall pass | Closed (shipped v1.5.10) |
| 8.8 | Management-plane hardening | Done |
| 8.9 | Defense-in-depth | Done |
| 8.10 | Settings & rate-limit cleanup | Done |
| 8.11 | Observability gap | Done |
| 8.12 | Vendor captcha | Done |

Top findings across the epic (ranked by impact x feasibility):

1. **Management TLS + CSP3 nonce completed after a staged deferral
   (Story 8.8).** The two highest-effort, hardest-to-verify hardening
   items shipped one gate later than the rest of 8.8: the metrics-auth
   half landed first (clearest exposure: unauth `/metrics` leaks backend
   topology + cert inventory), then the TLS listener (backlog #20) and
   CSP3 nonce (backlog #26) landed once e2e / frontend-build verification
   was available (rbac + audit e2e over https; frontend gates). Staging
   avoided merging an unverifiable rewrite of the primary management
   interface.
2. **Toolchain-1.95 clippy drift, now cleared.** `cargo clippy
   --workspace --all-targets -- -D warnings` was red on the forked
   `lorica-proxy` (`collapsible_match`) and the `lorica` binary doc-list
   warnings (Story 8.2 `check_robots_txt` doc); both are resolved
   (backlog #43/#45) - a scoped allow on the vendored crate, a reword on
   the doc - so the full workspace is now clippy-clean. CI already
   clippied only the product crates, all of which were clean, so there
   was
   no CI/release impact; a cosmetic cleanup is worth doing at the next
   Pingora sync.
3. **rps=0 semantics change (Story 8.10).** A legacy `rate_limit_rps` of
   0 now means "no limit" (token-bucket convention) instead of the
   latent "reject everything". Intentional correctness fix; no config or
   test relied on the old behaviour.
4. **Gauges are per-process in worker mode (Story 8.5).** The two new
   OCSP gauges are authoritative in single-process mode only; the
   cross-worker signal is the `ocsp_refresh_total` counter, which does
   aggregate. Documented in the metric help + architecture doc.
5. **Vendored captcha keeps upstream style behind a scoped clippy
   allow (Story 8.12).** `#![allow(clippy::all)]` is scoped to the
   `vendored/` subtree only, so re-syncing with upstream stays a diff.

## 2. Per-story results

### 8.5 Cert-resolver reliability - Done
OCSP stapling moved off the reload critical path into a background
refresh loop (6h + post-reload notify); reload swaps cert bodies only,
so a fresh cert is served in ~200 ms instead of waiting up to 10 s on a
slow responder. Shared `OCSP_CLIENT`; `CertResolver::refresh_staples`
arc-swap; 4 metrics. Partial-tolerant reload was already in place
(v1.5.3). Gates: lorica-tls 35/35 (+2), lorica-api 560, lorica lib clean,
clippy clean. AC #4 pre-satisfied. No Critical/High.

### 8.8 Management-plane hardening - Done
Opt-in `/metrics` auth (`metrics_require_auth`, default off) with
constant-time bearer (`subtle`), `401 WWW-Authenticate: Bearer
realm="lorica-metrics"`, session-OR-bearer, fail-closed, ACME challenge
kept public; scrape-token secret scrubbing; dedicated `csp.rs` helper.
Management API served over TLS via a manual `tokio-rustls` + `hyper-util`
accept loop (no `axum-server`): rcgen self-signed cert gen / persist
(dir 0700, key 0600) / 30-day rotate, operator override,
`unban`/`login`/`upgrade` on https. CSP3 style-src per-request nonce
(drops `'unsafe-inline'`, `style-src-attr` fallback for Svelte `style=`).
`docs/security.md` + `installation.md` updated. Security review:
constant-time compare, 401 challenge, ACME-public router split, token
masking, cert 0600 / dir 0700, TLS accept loop with `ConnectInfo`
preserved - all confirmed. Gates: full-workspace clippy clean, lorica-api
570 (+6 management_tls) + lorica-dashboard 10 (+2 csp) tests, frontend
svelte-check 0 / tsc / lint / vitest 363, e2e over https rbac 37/37 +
audit 17/17. Residual: browser IV4 CSP-violation check (operator
spot-check). No Critical/High.

### 8.10 Settings & rate-limit cleanup - Done
`header_timeout_s` + `flood_strict_rps` wired; the dual per-route
rate-limit engines converge onto one token-bucket admission path
(`RateLimit::from_legacy` shim), with auto-ban + flood 0.5x +
`X-RateLimit-*` headers preserved and per-path overrides now reaching
the unified path; legacy stage deleted; first-boot legacy-route notice.
AC #6 pre-shipped (v1.5.10); AC #7 (schema endpoint) deferred. Gates:
clippy clean (config+api), lorica lib 314/0 (flood/slowloris/dispatch
order all green). No Critical/High.

### 8.12 Vendor captcha - Done
`captcha 1.0.0` (MIT) inlined under `lorica-challenge/src/captcha/
vendored/`, external dep removed (audit row M-16 closed). API preserved
(bot.rs untouched); LICENSE + VENDORING.md; 4 behavioural tests. Net
dependency tree shrinks (`hound`, duplicate `base64 0.13` leave). Gates:
lorica-challenge tests green, clippy clean, `cargo audit` clear of
captcha. No Critical/High.

### 8.2 / 8.3 / 8.4 / 8.9 / 8.11 - Done
Implemented and audited in prior sessions (design + implementation +
BMad completion audits recorded in each story's change log). 8.3 and 8.9
were additionally e2e-verified this cycle (rbac-smoke 37/37 in both
modes; audit-smoke 17/17 incl. sqlite tamper localisation + RBAC floors).
Rolled to Done at epic closure. No open Critical/High.

## 3. Cross-cutting findings

- **Delegated implementation, independently gated.** Stories 8.10, 8.12,
  and 8.8 were implemented by subagents and then re-verified by the
  orchestrator against the full Docker gate. This caught a real gap the
  subagent missed on 8.12 (clippy `-D warnings` failing on the vendored
  subtree), which was fixed before commit - a reminder that `cargo test`
  passing is not `cargo clippy -D warnings` passing.
- **Worker-mode parity.** New per-worker counters (8.5 reload/OCSP, 8.9
  per-IP refusals, 8.2 AI-bot) all route through the `lorica-metrics`
  cross-worker aggregation (8.11); new gauges are documented as
  per-process.
- **Secret handling convention** (RBAC 8.3) reused consistently: the
  8.8 scrape token is scrubbed in GET and sentinel-preserved on PUT like
  every other stored secret.

## 4. NFR validation

- **Security:** metrics-auth is constant-time + fail-closed; captcha
  supply-chain surface removed; audit-log hash chain + per-IP/stash/
  mirror caps (8.9) shipped. Deferred: management TLS (session cookie
  `Secure` flag still relies on the localhost trustworthy-origin
  exemption until #20 lands) and CSP3 nonce.
- **Performance:** OCSP off the handshake critical path (8.5);
  rate-limit unified on one bucket lookup (8.10). No new hot-path
  allocations introduced.
- **Reliability:** partial-tolerant cert reload (8.5); rate-limit
  behavioural equivalence pinned by tests (8.10).
- **Maintainability:** one rate-limit path instead of two (8.10); CSP in
  one helper (8.8); metrics registry centralised (8.11).

## 5. Strengths confirmed

- Every committed story passed clippy `-D warnings` on its product
  crates and its full relevant test suite in the CI-matching Docker
  image before commit.
- Deferrals are honest and mapped: each carries a concrete reason and a
  backlog entry with the follow-up blast radius, not a silent gap.

## 6. Recommendations

- **Immediate:** none blocking release. The full workspace passes
  `cargo clippy --all-targets -- -D warnings`, every product-crate test
  suite is green, and the Docker e2e suite passes over https.
- **Operator spot-check:** confirm the dashboard renders with zero
  browser-console CSP violations (Story 8.8 IV4) - the one check that
  cannot run headless.
- **Backlog / future:** migrate the remaining settings tabs
  (CertExport / Network / Observability) onto the new `settings/schema`
  endpoint (the endpoint already exposes their bounds); optionally add
  `waf_event_retention` to the import/reload diff if operators want
  retention changes surfaced there (left out for parity with
  `access_log_retention`, which is also not in the diff).
