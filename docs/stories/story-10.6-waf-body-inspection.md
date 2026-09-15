# Story 10.6: Content-Type-Aware WAF Body Inspection

**Epic:** [Epic 10 - Conditional Request Capture & CI Automation API (v1.8.0)](../prd/epic-10-v1.8.0.md)
**Status:** InProgress - AC #1 to #4 shipped in v1.7.2, the rest is v1.8.0 (see Delivery split)
**Priority:** P1
**Author:** Romain G.
**Depends on:** nothing on the v1.8.0 branch. Touches the v1.5.1 audit H-2 remediation (`WAF_BODY_SCAN_MAX`, `lorica/src/proxy_wiring.rs:73`) and must not regress it.

---

As an operator running a large-file application behind Lorica (Nextcloud, ownCloud, Seafile, any WebDAV or S3-style upload endpoint),
I want the WAF to stay enabled on the route while multi-gigabyte uploads flow through untouched,
so that I do not have to choose between "WAF on the route" and "uploads work", which is the choice `WAF_BODY_SCAN_MAX = 1 MiB` forces today.

## Problem

`WafEngine::evaluate_body` (`lorica-waf/src/engine/eval.rs:250`) returns `Pass` immediately on any body that does not decode as UTF-8. Binary uploads are never scanned. But the decision to buffer and the decision to reject happen much earlier, in `check_body_limits` (`lorica/src/proxy_wiring/filters.rs:2074`) and `request_body_filter` (`lorica/src/proxy_wiring.rs:1024`), on byte count alone.

The result on a WAF-Blocking route: a 500 MB `PUT /remote.php/dav/files/user01/big.iso` with `Content-Type: application/octet-stream` is buffered up to 1 MiB and answered `413 Payload Too Large`, for a scan that would have returned `Pass` on the first byte. The route pays the full cost of inspection and receives none of its benefit, and the operator's only remedies today are to disable the WAF on the route or to move the upload endpoint to a separate route with the WAF off.

Raising `WAF_BODY_SCAN_MAX` alone does not fix this: it multiplies the per-request memory cost of every route to accommodate bodies that are never inspected.

## Acceptance Criteria

1. **Content-Type gating lives in `lorica-waf` and is the primary mechanism.** New public `pub fn body_is_inspectable(content_type: Option<&str>) -> bool` backed by a documented const. The media type is taken up to the first `;` (parameters such as `charset=utf-8` ignored), trimmed, compared ASCII-case-insensitively. Inspectable: `application/json`, `application/x-www-form-urlencoded`, `application/xml`, `text/xml`, any `text/` prefix, and the RFC 6839 structured suffixes `+json` and `+xml` (so `application/activity+json` and `application/atom+xml` are covered). Everything else, **including an absent or unparseable `Content-Type` header**, is not inspectable. The function is pure, has unit tests covering each arm, and is re-exported from the crate root.
2. **`multipart/form-data` is deliberately not inspectable in 1.8.0.** Lorica has no multipart parser; scanning the raw envelope means scanning base64 and binary part payloads for SQL keywords, which is high false-positive and low value. The const carries an inline comment saying so, `docs/security.md` says so in prose, and a multipart parser with a separate non-file-parts limit (the ModSecurity `SecRequestBodyNoFilesLimit` model) is recorded in `docs/backlog.md` as the follow-up.
3. **The inspection decision is computed once per request and cached.** `RequestCtx` (`lorica/src/proxy_wiring/context.rs:25`) gains `waf_body_inspect: bool` and `waf_body_scan_max: usize`, both set in `check_body_limits` where the request header is already in hand. `request_body_filter` reads the cached values and never re-parses a header or re-reads the route snapshot per chunk. The Content-Length path and the chunked path consult the same two fields, which removes the current duplication where both sites independently re-derive `(waf_enabled, waf_mode)` from the snapshot.
4. **A non-inspectable body is never buffered and never counted against the WAF cap.** When `waf_body_inspect == false`: `ctx.waf_body_buffer` stays `None`, the WAF oversize branch is skipped in both enforcement sites, and the only size ceiling that applies is the route's `max_request_body_bytes`. `evaluate_body` is not called at end of stream. Behaviour is identical in `Blocking` and `Detection` mode, because the engine's verdict on such a body is `Pass` in both.
5. **New per-route `waf_body_scan_max_bytes: Option<u64>`.** `None` means the crate default (`WAF_BODY_SCAN_DEFAULT = 1_048_576`, the current constant renamed). Validated in `lorica-api/src/routes/crud.rs` alongside `max_request_body_bytes`: accepted range `4_096 ..= 67_108_864` (4 KiB to 64 MiB), `0` normalised to `None` like `max_request_body_bytes` (`crud.rs:3535`), anything else 422 with a field-level error. The field only widens the window for bodies that are actually inspected, so it is orthogonal to AC #1 and useful on its own for a JSON API that legitimately posts 5 MB documents.
6. **Oversize semantics are unchanged, they just apply to a smaller set of requests.** An inspectable body past the effective cap still returns 413 in `Blocking` and still emits exactly one `BodyTruncated` `WafEvent` plus a partial scan in `Detection` (v1.5.1 audit H-2 stance preserved). The padding bypass the audit closed stays closed: an attacker who prefixes 1 MiB of inert text to a JSON payload still hits the cap and is still rejected on a Blocking route.
7. **A global in-flight buffer budget, and it fails open.** New global setting `waf_body_scan_max_inflight_bytes` (default 268_435_456, 256 MiB) tracked as a process-wide `AtomicU64` incremented and decremented as capture buffers grow and are released. A request that would push the total past the budget is not buffered, is not scanned, is **allowed through** in both WAF modes, emits one `ScanSkippedBudget` `WafEvent`, and increments the drop counter. Failing closed here would let any client turn a shared global budget into a fleet-wide 413 storm, which is a worse outcome than a scan gap that is alarmed on; `docs/security.md` states the trade-off in those terms. The budget is per process, so worker mode multiplies it by the worker count and the setting's documentation says so, matching the Story 8.9 per-IP-cap precedent.
8. **Observability.** New counter `lorica_waf_body_scans_total{outcome}` with `outcome` in `scanned | skipped_content_type | skipped_budget | truncated | rejected`, registered through `lorica-metrics` and added to `PER_WORKER_COUNTERS` with a `resolve_per_worker_counter` arm, because every one of these outcomes is produced inside worker processes. New gauge `lorica_waf_body_scan_inflight_bytes`. `WafEventKind` gains `ScanSkippedBudget` next to the existing `BodyTruncated`.
9. **API, dashboard and contract.** `waf_body_scan_max_bytes` on the route read, create and update payloads in `crud.rs`, in `lorica-api/openapi.yaml` (kept green against `lorica-api/tests/openapi_contract.rs`), in `api.ts`, and in `route-form.ts` as a MB-denominated field mirroring `max_body_mb`. The dashboard exposes it in the Protection tab's WAF subsection (not in "Body size limit", which is a different concept and must not be confused with it) with a hint naming the memory cost: "Only bodies the WAF can parse are buffered. Cost is this value times concurrent requests on this route." `waf_body_scan_max_inflight_bytes` joins the global settings surface.
10. **Documentation.** `docs/security.md` gains a "WAF body inspection" section: the inspectable set and why each entry is in it, the spoofed-`Content-Type` residual risk stated plainly (a client that declares `application/octet-stream` skips inspection; the mitigating argument is that the upstream will also treat the body as an opaque blob, and the argument does not hold for an application that ignores the declared type), the two caps and their interaction with `max_request_body_bytes`, the fail-open budget rationale, and a worked Nextcloud route configuration. `CHANGELOG.md` `[Unreleased]` under Changed and Security.

## Integration Verification

- IV1 (the Nextcloud shape): one route, `waf_enabled = true`, `waf_mode = blocking`, `max_request_body_bytes = 2 GiB`. A 100 MB `PUT` with `Content-Type: application/octet-stream` returns the upstream's 2xx, the upstream receives all 100 MB byte-identical, `lorica_waf_body_scan_inflight_bytes` never leaves 0, and `lorica_waf_body_scans_total{outcome="skipped_content_type"}` increments by one. On the same route in the same run, a `POST` with `Content-Type: application/json` carrying a SQLi payload is answered 403 and produces a `WafEvent`.
- IV2 (the widened window actually widens): route with `waf_body_scan_max_bytes = 8388608`. A 6 MB JSON body whose payload sits at offset 5 MB is blocked, which is impossible under today's 1 MiB cap. A 10 MB JSON body on the same route returns 413. The same 6 MB body on a sibling route left at the default returns 413, proving the setting is per route and not global.
- IV3 (chunked parity): both IV1 and IV2 repeated with `Transfer-Encoding: chunked` and no `Content-Length`, with identical outcomes, exercising the `request_body_filter` path rather than the `check_body_limits` fast path.
- IV4 (the audit stays closed): a JSON body of 1 MiB of inert padding followed by a SQLi payload returns 413 on a Blocking route and emits exactly one `BodyTruncated` event plus a partial scan on a Detection route. Verbatim re-run of the v1.5.1 H-2 regression case.
- IV5 (budget): with `waf_body_scan_max_inflight_bytes` lowered to a value two concurrent large JSON bodies exceed, the second request is allowed through with a `ScanSkippedBudget` event and `outcome="skipped_budget"`, returns no 413, and the gauge returns to 0 once both requests complete.

## Tasks

- [x] AC #1/#2 (v1.7.2): `body_is_inspectable` + `INSPECTABLE_BODY_CONTENT_TYPES` in `lorica-waf` (new `body_types.rs` or alongside `eval.rs`), re-export, unit tests per arm including suffix matching, absent header, parameter stripping, case folding, and the multipart exclusion.
- [ ] AC #5: `waf_body_scan_max_bytes` on `Route` (`lorica-config/src/models/route.rs`), migration 56 `migrate_route_waf_body_scan_cap` appending the column, the three SELECT/INSERT column lists in `store/routes.rs:125,247,294` plus the UPDATE at `:393`, the positional index in `store/row_helpers.rs`, and `canonical.rs:634` so the config hash and the cluster replication digest stay stable.
- [x] AC #3/#4/#6 (v1.7.2, `waf_body_inspect` only, the cap stays the constant until AC #5): `RequestCtx` fields, decision computed in `check_body_limits` (`filters.rs:2074`), both enforcement sites collapsed onto the cached values (`filters.rs:2083` and `proxy_wiring.rs:1024-1084`), `evaluate_body` call site skipped when not inspecting.
- [ ] AC #7: `waf_body_scan_max_inflight_bytes` global setting (model + store + `UpdateSettingsRequest` + frontend types), process-global `AtomicU64` with an RAII guard so the decrement cannot be skipped on an early return or a dropped connection, fail-open path + `ScanSkippedBudget`.
- [ ] AC #8: `WafEventKind::ScanSkippedBudget`, `lorica_waf_body_scans_total` + `lorica_waf_body_scan_inflight_bytes` through `lorica-metrics`, `PER_WORKER_COUNTERS` + `resolve_per_worker_counter` arms.
- [ ] AC #9: `crud.rs` validation and the three route payload structs, `openapi.yaml` + contract test, `api.ts`, `route-form.ts` (to/from form, modified-field tracking, validation), ProtectionTab WAF subsection field.
- [ ] AC #10: `docs/security.md` section, `docs/backlog.md` multipart follow-up entry, `CHANGELOG.md`. v1.7.2 landed all three for what shipped: the inspectable set, the spoofed-`Content-Type` and gzip gaps, the two caps and their interaction, the Nextcloud route, backlog #86. The fail-open budget rationale follows AC #7.
- [ ] IV coverage: `lorica/tests/waf_body_inspection_e2e_test.rs` exists and covers IV1, IV3 and IV4; IV2 needs AC #5 and IV5 needs AC #7. Remaining: IV2 and IV5 against the existing in-process test harness used by `lorica/tests/rate_limit_e2e_test.rs`; unit tests for the budget guard and the cap resolution (`None` -> default, `0` -> `None`, out-of-range -> 422).
- [ ] Gates: `cargo test -p lorica-config -p lorica-waf -p lorica-api -p lorica`, `cargo clippy --all-targets --all-features -- -D warnings` with `RUSTFLAGS=-D warnings`, `cargo audit`, `npm run check` + `npm run lint` + `npx vitest run` in `lorica-dashboard/frontend`.

## Dev Notes

### Delivery split

AC #1 to #4 shipped in the v1.7.2 patch, ahead of the rest of Epic
10. They are the part that removes the operator's dilemma, and they
are patch-shaped: a pure function, one cached boolean on
`RequestCtx`, and two call sites reading it. No migration, no new
setting, no API field, no dashboard surface, so nothing in the
replicated configuration model moves and a mixed-version fleet is
unaffected.

What stayed for v1.8.0, and why none of it is patch-shaped: AC #5
(per-route `waf_body_scan_max_bytes`) needs migration 56, the three
SELECT lists, `canonical.rs` and the API contract; AC #7 (global
in-flight budget) is a new global setting plus a process-wide
accounting guard; AC #8 (the counters) needs `PER_WORKER_COUNTERS`
plumbing; AC #9 is the API and dashboard surface for both settings.

The order matters for AC #7. Its budget exists to bound
`waf_body_scan_max_bytes x concurrent requests`, and while the cap is
the compiled-in 1 MiB the worst case is the one the proxy has always
had. Shipping the gate first strictly lowers that number, since
binary uploads stopped allocating a buffer at all.

### Why gating and not a bigger constant

`evaluate_body` already short-circuits on `std::str::from_utf8` failure (`eval.rs:250`). Every byte buffered for a body that fails that check is pure waste, and on a Blocking route the 413 is worse than waste: it is a false positive with no rule behind it. Gating on `Content-Type` moves the existing engine-level decision earlier, to the point where it can avoid the buffer instead of discovering it was pointless afterwards. This is the ModSecurity model (`SecRequestBodyAccess` drives buffering off the parsed content type) and the AWS WAF model (oversize handling is per content type). The per-route cap in AC #5 is the secondary knob for the genuinely-text case; it is not the fix for Nextcloud.

Note that gating on the declared type is strictly more conservative than the current behaviour in one direction and strictly less in another: a `text/plain` 900 KB body is inspected exactly as today, and an `application/octet-stream` body that happens to be valid UTF-8 SQL is no longer inspected. AC #10 requires that second case to be documented rather than glossed over.

### Enforcement sites, verified 2026-09-13

- `check_body_limits` (`lorica/src/proxy_wiring/filters.rs:2074`) holds `session.req_header()` and `entry.route`. This is where both new `RequestCtx` fields are set. The route-level check at `:2083` runs first and is independent of the WAF; leave it exactly where it is.
- `request_body_filter` (`lorica/src/proxy_wiring.rs:974`) does three things in sequence: the chunked `max_request_body_bytes` check (`:990`), the WAF oversize branch (`:1024`), and the buffer growth (`:1075`). Only the second and third become conditional on `ctx.waf_body_inspect`. The `cap_meta` tuple clone at `:1024` disappears with the cached fields.
- The buffer-growth guard at `:1078` currently hardcodes `WAF_BODY_SCAN_MAX`; it becomes `ctx.waf_body_scan_max`. Keep the guard even though the Blocking branch returns before reaching it, for the reason already documented in the comment at `:1071`.

### Storage and cluster

`routes` columns are read positionally in `row_helpers.rs` (`max_request_body_bytes` is index 25). Append the new column at the end of the table and at the end of every SELECT list so no existing index shifts. Routes already replicate through the Story 9.4 allowlist, so a follower picks the field up with no transport change, but `canonical.rs` must carry it or the control plane and the follower will disagree on the config hash and loop on replication.

### Worker mode

The route snapshot reaches workers through the existing `ProxyConfig` `ArcSwap`, so AC #5 needs no plumbing there. The budget in AC #7 and every counter in AC #8 are per worker process; both need the `PER_WORKER_COUNTERS` aggregation or the supervisor-served `/metrics` reads zero, the same trap Story 8.9 hit with `lorica_per_ip_connection_refused_total`.

### Memory arithmetic to put in the docs

Worst case per route is `waf_body_scan_max_bytes x concurrent inspectable requests on that route`. At the 64 MiB ceiling and 500 concurrent requests that is 32 GB, which is why AC #7 exists and why the API bound is 64 MiB rather than "whatever the operator types". The global budget is the real ceiling; the per-route value is a shape, not a guarantee.

### Out of scope, with reasons

- **A multipart parser.** See AC #2. Backlog.
- **Decompressing `Content-Encoding: gzip` bodies before inspection.** A gzipped JSON body is not valid UTF-8, so it already passes uninspected today; this story does not change that, and fixing it means a decompression bomb budget of its own. Backlog, and named as a known gap in `docs/security.md`.
- **Making the inspectable content-type set operator-configurable.** It describes what the engine can parse, not a policy preference. An operator who wants less inspection already has `waf_enabled` per route. Promote it to a setting only if a real request arrives.
- **An explicit per-route oversize action (`reject` / `partial` / `skip`, the ModSecurity `SecRequestBodyLimitAction` shape).** Deriving it from `waf_mode` is sufficient once AC #1 lands, because what remains under the cap is text that a Blocking route should reject.
- **Response body inspection.** Lorica does not scan response bodies today and this story does not start.

## Dev Agent Record

### Debug Log

(empty)

### Completion Notes

**v1.7.2 (AC #1 to #4).** The gate reads
`ctx.waf_body_inspect`, set once in `check_body_limits` where the
request header is in hand, and both enforcement sites consult it
rather than re-deriving `(waf_enabled, waf_mode)` from the route
snapshot. That removed the per-chunk `cap_meta` tuple clone in
`request_body_filter` as a side effect: the route fields are now
cloned only on the oversize path.

`evaluate_body` needed no call-site guard. It already runs only when
`ctx.waf_body_buffer` is `Some` and non-empty, and a non-inspectable
body never creates the buffer, so AC #4's "not called at end of
stream" falls out of the buffering change rather than being enforced
twice.

Two arms of `body_is_inspectable` are there because of what they
would otherwise do: a bare `+json` (no `/`) must not reach the
suffix rule, and a multibyte media type would panic a naive
`media[..5]` prefix compare. Both have a test.

The e2e file asserts what the upstream received, not only the status
code, because "the request was not rejected" and "the upstream got
all of the bytes" are different claims and only the second one is the
Nextcloud case. The origin de-chunks so the count compares like for
like whichever framing the proxy picks for the upstream leg.

## File List

Shipped in v1.7.2 (AC #1 to #4):

- `lorica-waf/src/body_types.rs` (new), `lorica-waf/src/lib.rs` (module + re-export)
- `lorica/src/proxy_wiring/context.rs` (`waf_body_inspect`), `lorica/src/proxy_wiring.rs` (the constant's contract, `request_body_filter`), `lorica/src/proxy_wiring/filters.rs` (`check_body_limits`)
- `lorica/tests/waf_body_inspection_e2e_test.rs` (new)
- `docs/security.md`, `docs/backlog.md` (#86), `CHANGELOG.md`

Anticipated for the v1.8.0 remainder (AC #5, #7, #8, #9):

- `lorica-waf/src/` (`WafEventKind::ScanSkippedBudget`)
- `lorica-config/src/models/route.rs`, `models/settings.rs`, `store/routes.rs`, `store/row_helpers.rs`, `store/mod.rs` (migration 56), `store/settings.rs`, `canonical.rs`
- `lorica-api/src/routes/crud.rs`, `lorica-api/src/metrics.rs`, `lorica-api/openapi.yaml`
- `lorica-dashboard/frontend/src/lib/api.ts`, `lib/route-form.ts`, `components/route-tabs/ProtectionTab.svelte`, global settings tab

## Change Log

- 2026-09-15: AC #1 to #4 implemented and shipped in the v1.7.2 patch: `body_is_inspectable` in `lorica-waf`, the cached `waf_body_inspect` decision on `RequestCtx`, both enforcement sites reading it, nine end-to-end assertions over a real proxy, and the `docs/security.md` section. AC #5, #7, #8 and #9 stay on the v1.8.0 branch; see Delivery split for why the order is this one. Status InProgress.
- 2026-09-13: Story drafted from the Nextcloud upload case. Root cause identified as the byte-count-only buffering decision in front of an engine that already skips non-UTF-8 bodies, not the value of `WAF_BODY_SCAN_MAX` itself.
