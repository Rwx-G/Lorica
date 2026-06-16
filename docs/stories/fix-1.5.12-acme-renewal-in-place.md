# Fix 1.5.12 - ACME renewal in-place (stop orphaning routes and burning LE quota)

Author: Romain G.

Status: Review

## Context

Production incident (2026-06-16). For `mail.kaliaops.com` the ACME auto-renewal
kept issuing a new certificate every day until Let's Encrypt rate-limited the
account:

```
ACME renewal failed - existing cert still active
domain: mail.kaliaops.com
error: too many certificates (5) already issued for this exact set of identifiers
       in the last 168h0m0s, retry after ... (urn:...:rateLimited)
```

Root cause confirmed from the journal and the code:

1. The renewal path is `INSERT new cert (new UUID)` -> `reassign route old->new`
   -> `delete old` (`lorica-api/src/acme/renewal.rs:151-196`,
   `lorica-api/src/acme/http01.rs:227-269`, `dns01.rs:317-360`). The renewal
   loop logs `routes reassigned to renewed certificate` only when the reassign
   matched a route (`renewal.rs:163`). Every healthy domain shows that line
   (`routes:1`); `mail.kaliaops.com` never does, i.e. its reassign matched
   zero routes. The route stayed on the old cert.
2. The renewal eligibility filter (`should_auto_renew`, `renewal.rs:41-54`, and
   the loop guard `renewal.rs:95-101`) only checks `is_acme`, `acme_auto_renew`,
   `dns01-manual`, and the expiry window. It never checks whether the cert is
   bound to a route. Unbound duplicate certs for the same identifier set were
   therefore renewed on every cycle; renewing an unbound cert produces another
   unbound cert (reassign matches 0), so the served cert (bound, in-window) was
   never replaced and stayed in the renewal window, re-firing daily.
3. On a `rateLimited` error the loop does the correct fail-safe ("existing cert
   still active") but ignores the `retry after` timestamp and re-attempts every
   `check_interval`, hammering LE (attempts on Jun 11, 12, 12, 13, 14, 15, 16,
   16).

There is no `UNIQUE` constraint on `certificates` (no dedup), and the
cert-export feature does no database writes (`lorica-api/src/cert_export.rs`),
so "exported" is a correlation (those are the manually-managed certs that had
accumulated duplicates), not a cause.

The design itself is the fond problem: minting a fresh random id per issuance
and then re-pointing references is what allows orphans. Caddy, Traefik and
certbot all key a cert by its identifier set under a stable key and renew
**in place**; they cannot orphan a route by construction.

## Acceptance Criteria

AC1 - In-place renewal. Renewing an existing ACME certificate updates that
certificate row (same `id`, new pem/key/not_before/not_after/san_domains) via
`ConfigStore::update_certificate`, instead of inserting a new row and
reassigning routes. After a renewal:
- the certificate keeps its `id`;
- every route that referenced it still references it (no `reassign`, no
  `delete`, no orphan row created);
- the TLS resolver serves the new leaf after the normal config reload.
Fresh issuance (no pre-existing cert) keeps inserting a new row as today.

AC2 - Only renew bound certificates. The auto-renewal loop skips any
certificate not referenced by at least one route (`routes.certificate_id`),
using the same active-cert-id derivation as `reload_cert_resolver`
(`lorica/src/reload.rs:828-846`). An unbound ACME cert is never auto-renewed.
The manual renew endpoint (`POST /certificates/:id/renew`) is unchanged in
intent but must also renew in place (AC1).

AC3 - Respect Let's Encrypt rate limiting. On a `rateLimited` ACME error the
loop records a cooldown for that certificate and does not re-attempt its
renewal before the cooldown expires. The cooldown is taken from the error's
`retry after <RFC stamp>` when parseable, otherwise a safe default (24h).
Cooldown state is per-process (in-memory) for this patch; persistence across
restarts is out of scope and noted as a follow-up. The cooldown must be logged
at INFO when it suppresses an attempt.

AC4 - Purge superseded orphan ACME certs at startup. At startup, after the
store is open, delete ACME certificates (`is_acme = true`) that are BOTH
unreferenced by any route AND superseded (another certificate exists for the
same identifier set - same primary `domain` and same `san_domains` set - with a
later `not_after`). A unique unbound cert with no newer sibling is kept (an
operator may bind it). Each purge is logged at INFO with the count and ids. The
purge runs in both single-process and supervisor startup paths, mirroring the
`reexport_all` startup hook.

AC5 - No regression. All existing tests pass; clippy/audit/fmt clean per the
project gates. New behavior is covered by tests (see Testing).

## Tasks / Subtasks

- [x] AC1: thread an `existing_cert_id: Option<&str>` through
  `renew_with_method` -> `provision_with_acme` / `provision_with_acme_dns`.
  When `Some`, persist via `update_certificate` (same id); when `None`, keep
  `create_certificate`. Return the (unchanged) cert id.
- [x] AC1: in `renewal.rs`, the auto-renewal loop and `renew_certificate`
  (manual) call the renewal with `Some(cert.id)`, and DROP the `reassign` +
  `delete` block. Keep the success log and `notify_config_changed`.
- [x] AC1: confirm `update_certificate` re-encrypts `key_pem` and updates
  `san_domains`, `not_before`, `not_after`, `fingerprint`, `issuer`,
  `acme_method` (it does, `certs.rs:77-107`). `created_at` stays the original.
- [x] AC2: in the loop, build the bound-cert-id set from `list_routes()` and
  skip certs not in it (before the expiry check). Add the same guard to
  `should_auto_renew` is NOT possible (it lacks route context) - do it in the
  loop and add a small pure helper `is_bound(cert_id, &route_ids)` that is
  unit-testable.
- [x] AC3: add an in-memory `HashMap<String /*cert id*/, DateTime<Utc>>`
  cooldown map owned by the renewal task. Skip a cert whose cooldown is in the
  future. On `Err`, classify `rateLimited` (string match on
  `urn:ietf:params:acme:error:rateLimited` / "rateLimited" / "too many
  certificates") and parse `retry after <stamp>`; set the cooldown.
- [x] AC4: add `ConfigStore` helpers to list certs + routes (exist) and a pure
  function `superseded_orphans(certs, route_ids) -> Vec<String>` returning ids
  to purge; call `delete_certificate` for each at startup. Unit-test the pure
  function.
- [x] Version bump 1.5.11 -> 1.5.12 across `docs/BUMP-CHECKLIST.md` files.
- [x] CHANGELOG: add `## [1.5.12]` Fixed + Security entries.
- [x] Tests (see Testing).

## Dev Notes

- `provision_with_acme` / `provision_with_acme_dns` currently end with
  `create_certificate` inside a `db_blocking`, then an awaited
  `export_after_release`. For renewal-in-place, swap the `create_certificate`
  for `update_certificate` when `existing_cert_id` is `Some`. The awaited export
  stays (it is fine; it does no DB writes) but is no longer between a create and
  a separate reassign, so it cannot interleave with a route switch.
- Dropping `reassign`/`delete` from the renewal loop removes the only callers of
  `reassign_certificate`. Keep `reassign_certificate` in the store (still used
  by tests / future) but it is no longer on the renewal hot path.
- The resolver keys by domain and serves only route-bound certs
  (`reload.rs:842-846`), so in-place update is picked up by the existing
  `notify_config_changed` -> reload, no extra wiring.
- Rate-limit string: the live error is
  `... too many certificates (5) already issued for this exact set of
  identifiers in the last 168h0m0s, retry after 2026-06-11 06:19:40 UTC: see ...
  (urn:ietf:params:acme:error:rateLimited)`. Parse the substring after
  `retry after ` up to ` UTC` / `:` as `%Y-%m-%d %H:%M:%S` UTC.
- Identifier-set equality for purge: compare primary `domain` plus the SORTED,
  de-duplicated `san_domains` so ordering differences do not defeat the match.
- AC4 anchor (correction): there is NO `reexport_all` startup hook;
  `reexport_all` is an API endpoint (`lorica-api/src/routes/cert_export.rs:180`).
  Run the purge in the shared both-modes startup tail
  `lorica/src/startup/mod.rs::run_api_server` (around line 171, just before
  `spawn_renewal_task`), where `state.store` exists, so single-process and
  supervisor modes share one call site and cannot drift.
- AC3 cooldown lives inside `spawn_renewal_task`'s async loop (owned by the
  task, not global): declare the `HashMap` before the `loop {}` so it persists
  across `check_interval` ticks for the lifetime of the process.

## Testing

- `should_auto_renew` unchanged tests still pass; add a loop-level test (or a
  pure `is_bound` test) proving an unbound cert is skipped.
- In-place renewal: with an in-memory store, seed a cert + a route referencing
  it; run the renewal-store mutation with `existing_cert_id = Some(id)`; assert
  the cert id is unchanged, the route still points to it, and
  `list_certificates().len()` did not grow.
- Rate-limit: a pure helper `cooldown_from_error(&str) -> Option<DateTime<Utc>>`
  parses the retry-after; assert it parses the real message and falls back to
  `None` (caller applies default) on garbage.
- Purge: `superseded_orphans` returns the older unbound dup id, keeps the bound
  one and a unique unbound one.

## File List

Modified:

- `lorica-api/src/acme/http01.rs` - `provision_with_acme` takes
  `existing_cert_id`, in-place update vs insert.
- `lorica-api/src/acme/dns01.rs` - `provision_with_acme_dns` takes
  `existing_cert_id`, in-place update vs insert.
- `lorica-api/src/acme/renewal.rs` - `existing_cert_id` threaded through
  `renew_with_method`; reassign + delete dropped; AC2 bound-only skip; AC3
  cooldown map + `cooldown_from_error`; pure `is_bound` + `superseded_orphans`.
- `lorica-api/src/acme/mod.rs` - re-export `superseded_orphans`.
- `lorica-api/src/acme/tests.rs` - unit tests for `is_bound`,
  `cooldown_from_error`, `superseded_orphans`.
- `lorica/src/startup/mod.rs` - `purge_superseded_acme_orphans` helper + call in
  the shared `run_api_server` tail (AC4).
- `lorica-config/src/tests.rs` - in-place renewal store test (AC1).
- `CHANGELOG.md` - `## [1.5.12]` Fixed + Security entries.
- Version bump 1.5.11 -> 1.5.12: `lorica/Cargo.toml`, `lorica-api/Cargo.toml`,
  `lorica-bench/Cargo.toml`, `lorica-challenge/Cargo.toml`,
  `lorica-command/Cargo.toml`, `lorica-config/Cargo.toml`,
  `lorica-dashboard/Cargo.toml`, `lorica-geoip/Cargo.toml`,
  `lorica-shmem/Cargo.toml`, `lorica-worker/Cargo.toml`,
  `lorica-api/openapi.yaml`, `lorica-dashboard/frontend/package.json`,
  `lorica-dashboard/frontend/package-lock.json`, `dist/rpm/lorica.spec`,
  `README.md`.

## Dev Agent Record

### Completion Notes

- AC1: `provision_with_acme` (http01) and `provision_with_acme_dns` (dns01) now
  take `existing_cert_id: Option<&str>`. `Some` -> `update_certificate` (same
  id, route bindings untouched); `None` -> `create_certificate` with a fresh
  UUID. `renew_with_method`, the auto-renewal loop, and the manual
  `renew_certificate` endpoint all pass `Some(&cert.id)`. The reassign + delete
  block is gone from both renewal paths. `created_at` is preserved because
  `update_certificate` never writes that column.
- AC2: the loop derives a `HashSet<String>` of route-bound cert ids from
  `list_routes()` (same shape as `reload_cert_resolver`) and skips any cert that
  is not bound, before the expiry checks. Pure helper `is_bound` is unit-tested.
- AC3: a `HashMap<String, DateTime<Utc>>` cooldown map is declared before the
  `loop {}` so it persists across ticks. A cert in cooldown is skipped with an
  INFO log. On an `Err`, `cooldown_from_error` classifies rate-limit messages
  (`rateLimited` / "too many certificates"), parses `retry after <stamp>`
  (`%Y-%m-%d %H:%M:%S` UTC), and falls back to `now + 24h`. A successful renewal
  clears the cooldown entry.
- AC4: pure `superseded_orphans(certs, bound_ids) -> Vec<String>` lives in
  `lorica-api/src/acme/renewal.rs` (re-exported from `acme`). Identity is the
  primary `domain` plus the sorted, de-duplicated `san_domains`. The startup
  helper `purge_superseded_acme_orphans` in `lorica/src/startup/mod.rs` runs
  once in the shared `run_api_server` tail (single-process + supervisor), lists
  certs + routes, deletes each orphan, and logs an INFO with count + ids.

### Decisions / gotchas

- `reassign_certificate` is kept in the store as a `pub fn`; it is now unused on
  the renewal hot path but, being public API of `lorica-config`, it does not
  trip `dead_code` under `-D warnings`. No test references it (the story note to
  the contrary is stale); none was added.
- The in-place store mutation behavior (id kept, route binding kept, no row
  growth, `created_at` preserved) is covered by a `lorica-config` store test
  that reuses the existing `make_route` / `make_certificate` fixtures, rather
  than reconstructing a full `Route` literal inside `lorica-api`.
- The manual `POST /certificates/:id/renew` response keeps its
  `old_cert_id` + `new_cert_id` fields (now both equal to the unchanged id)
  rather than collapsing to a single field, so the dashboard's existing
  `renewCertificate` response type (`lorica-dashboard/frontend/src/lib/api.ts`)
  is not broken.
- Version bump and CHANGELOG are intentionally NOT touched in the dev pass
  (orchestrator owns versioning).

### QA review round (3 BMAD reviewers + 6 auditors)

Findings actioned by the orchestrator after the multi-agent review:

- `superseded_orphans` identity is now the UNION of `domain` and `san_domains`
  (sorted, de-duplicated), not the `(domain, sans)` pair. A penetration/security
  finding showed uploaded certs store SANs without repeating the primary, so the
  pair-keyed version under-matched real duplicates. Also rewritten single-pass
  (latest-`not_after`-per-identity map) to drop the O(n^2) scan and the repeated
  clones the perf/quality auditors flagged.
- The cooldown parsed from a Let's Encrypt `retry after` is clamped to
  `now + 7 days` (security finding): a hostile/garbled far-future stamp can no
  longer suspend auto-renewal until the live cert expires.
- Extracted a pure `in_cooldown` predicate (used by the loop's skip) so AC3's
  skip behavior is unit-testable, per the test-adequacy finding. Added a
  per-tick `retain` sweep of expired cooldown entries so the map stays bounded.
- Added tests: `in_cooldown` (future/expired/absent), cooldown clamp, garbage
  stamp -> 24h fallback, `superseded_orphans` `not_after` tie (both kept), and
  primary-absent-from-SAN identity match.

Findings consciously NOT actioned (out of scope / non-issues): inline
`should_auto_renew` duplication and the `all_domains` dedup are pre-existing;
purged orphans do not leave stale exported files (they share the surviving
cert's hostname export dir); moving `superseded_orphans` into `lorica-config`
is an optional future cleanup; the manual renew endpoint intentionally has no
cooldown (AC3 is auto-loop only).

## Change Log

- 2026-06-16: Draft created (Romain G.) from the 2026-06-16 mail.kaliaops.com
  rate-limit incident analysis.
- 2026-06-16: Implemented AC1-AC4 + tests (Romain G.). In-place ACME renewal,
  bound-only auto-renewal, per-process rate-limit cooldown, startup orphan
  purge. Status -> Review.
- 2026-06-16: QA round (Romain G.). Actioned multi-agent review: union-set
  orphan identity + single-pass selector, 7 day cooldown clamp, `in_cooldown`
  extraction + per-tick sweep, extra tests. Version bump 1.5.11 -> 1.5.12 and
  CHANGELOG. Clippy (exact CI command) clean, tests green.
