# Story 8.8: Management Plane Hardening (TLS + Metrics Auth + CSP3 Nonces)

**Epic:** 8 (v1.6.0)
**Status:** Review (partial - AC #1, #6, and the AC #3 scheme flip deferred to backlog)
**Author:** Romain G.

## Story

As an operator,
I want the management API on port 9443 over TLS with an auto-managed
self-signed cert, an opt-in auth knob on `/metrics`, the `lorica unban`
CLI to use the correct URL scheme, AND the dashboard CSP to drop
`'unsafe-inline'` from `style-src` via CSP3 per-request nonces.

## Acceptance Criteria status

| AC | Status |
|----|--------|
| #1 TLS listener (rcgen self-signed, persist, 30d rotate) | Deferred (backlog) |
| #2 Operator cert-override settings | Settings landed (inert until #1) |
| #3 `unban` CLI | Error message improved; https scheme flip deferred (coupled to #1) |
| #4 `metrics_require_auth` + `prometheus_scrape_token` | Done + verified |
| #5 Constant-time bearer + 401 challenge | Done + verified |
| #6 CSP3 per-request style-src nonce | Deferred (backlog) |
| #7 Dedicated `csp.rs` helper | Done + verified |
| #8 Docs | `docs/security.md` mgmt-auth section done; TLS/self-signed docs deferred with #1 |

## Deferred work (why, and the mapped follow-up)

- **AC #1 management TLS listener.** Achievable with the in-lockfile
  crates (`tokio-rustls`, `hyper-util`, `rustls`, `rcgen`) - no new
  dependency - but it rewrites how every API / dashboard / CLI client
  reaches the server, and the live TLS handshake (IV1/IV2/IV3) can only
  be proven by the `tests-e2e-docker` suite, not the unit/clippy gate
  run in this pass. Shipping an unverifiable rewrite of the primary
  management interface is the "half-migration that breaks the API"
  hazard, so it is deferred rather than merged unverified. Blast radius
  mapped for the follow-up: `tests-e2e-docker/docker-compose.yml` (~15
  `LORICA_API=http://...:9443` lines to flip to `https://`), `-k` in
  `test-runner/helpers.sh` + each `run-*.sh`, and 9 `run.sh` readiness
  probes. socat is a transparent TCP passthrough, so no compose
  healthchecks change.
- **AC #3 scheme flip.** Flipping `unban` to `https://` +
  `danger_accept_invalid_certs` against a still-plaintext server would
  break the command, so it is coupled to #1. The connect-error message
  improvement landed independently.
- **AC #6 CSP3 nonce.** The production Vite build extracts component CSS
  to linked stylesheets, so the served `index.html` has no inline
  `<style>` block to nonce; and a `style-src` nonce does not authorize
  the inline `style=` attributes Svelte 5 emits at runtime, so dropping
  `'unsafe-inline'` needs `style-src-attr` / `'unsafe-hashes'` handling
  plus a real-browser check of IV4 (zero console CSP violations,
  per-request-changing nonce) that the headless gate cannot run. The
  `csp.rs` helper is nonce-ready (`build_csp(Some(nonce))` already emits
  the nonce directive and drops `'unsafe-inline'`); only the
  front-to-back wiring + browser verification remain.

## Dev Notes

Delivered + verified this pass:

- **Metrics auth** (`lorica-api/src/middleware/metrics_auth.rs`, new):
  `metrics_require_auth` (default `false`) gates `/metrics`; a scrape
  presents a session cookie OR the `prometheus_scrape_token` bearer
  (env override `LORICA_PROMETHEUS_SCRAPE_TOKEN` wins). Bearer compare
  is constant-time (`subtle::ConstantTimeEq`); failed auth is `401` with
  `WWW-Authenticate: Bearer realm="lorica-metrics"`. Fail-closed on
  missing state or store-read error. `/metrics` is split into its own
  sub-router carrying the layer; the ACME challenge route is a separate
  un-gated router so the CA still reaches it unauthenticated. The
  middleware extracts the cookie value + clones `SessionStore` before
  any `.await` (holding `&Request` across an await makes the future
  `!Send`).
- **Settings** (`lorica-config`): `metrics_require_auth`,
  `prometheus_scrape_token`, `management_cert_pem_path`,
  `management_key_pem_path` (all default-safe). The scrape token is a
  secret: `GET /settings` masks it as `**REDACTED**`, `PUT` treats that
  sentinel as "leave unchanged" (existing secret convention). Only the
  non-secret `metrics_require_auth` is surfaced in the reload diff.
- **CSP helper** (`lorica-dashboard/src/csp.rs`, new): `build_csp` owns
  every directive; `lib.rs` serves `build_csp(None)` so the emitted
  policy is byte-identical to before (existing CSP tests stay green).

Deviation: `subtle = "2"` added as a direct dep of `lorica-api`
(promotion; already resolved at 2.6.1 in `Cargo.lock` via the
dalek/rustls stack - no new crate, no new advisory).

## Dev Agent Record

### Completion Notes

Implemented by a delegated agent (safe/verifiable ACs first), then
orchestrator-reviewed (constant-time compare, 401 challenge, ACME-stays-
public router split, token scrubbing) and re-verified in Docker: clippy
`-p lorica-api -p lorica-config -p lorica-dashboard --all-targets -D
warnings` RC=0; `cargo test` lorica-api 564 (incl 4 metrics_auth tests),
lorica-config 207, lorica-dashboard 9 (incl 2 csp tests) + csp doctest,
all green.

## File List

- `lorica-api/src/middleware/metrics_auth.rs` (new)
- `lorica-api/src/middleware/mod.rs` (module wiring)
- `lorica-api/src/server.rs` (/metrics sub-router + layer, ACME split)
- `lorica-api/src/settings.rs` (secret masking + cert-path fields)
- `lorica-api/Cargo.toml` (subtle promoted)
- `lorica-config/src/models/settings.rs` (4 settings + defaults)
- `lorica-config/src/store/settings.rs`, `lorica-config/src/diff.rs`
- `lorica-dashboard/src/csp.rs` (new), `lorica-dashboard/src/lib.rs`
- `lorica/src/cli.rs` (unban connect-error message)
- `docs/security.md` (management-plane authentication section)

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-08-12 | 0.5 | Partial delivery (delegated + orchestrator-verified): opt-in `/metrics` auth with constant-time bearer + 401 challenge (AC #4/#5), dedicated `csp.rs` helper (AC #7), cert-override + auth settings scaffolding (AC #2), `unban` error-message improvement, `docs/security.md` section. AC #1 (mgmt TLS listener), AC #6 (CSP3 nonce) and the AC #3 scheme flip deferred to backlog with mapped follow-ups (verifiability constraints). Gates green. Status -> Review (partial). | Romain G. |
