# Story 10.1: Capture Rules, Two-Phase Matching and Budgets

**Epic:** [Epic 10 - Conditional Request Capture & CI Automation API (v1.8.0)](../prd/epic-10-v1.8.0.md)
**Status:** InProgress
**Priority:** P0, the epic's headline
**Author:** Romain G.
**Depends on:** Story 10.0 (a capture rule replicates through the same path, and the payload it travels in is now cut per recipient).
**Blocks:** Story 10.2, which gives the record a format, a redaction pass and somewhere to go.

---

As an operator debugging an intermittent backend failure,
I want to declare a rule that keeps the full request and response for a subset of traffic on one route,
so that the next 502 from the internal network shows me exactly what was sent, without a packet sniffer and without dumping the whole route.

## Problem

When a backend returns 502 for one client in twenty, the access log gives a
status, a latency and a request id. What was actually sent is gone. The
options today are a packet capture on a box terminating TLS, which is a
worse idea than the bug, or turning up logging on the backend, which is
often someone else's system.

The proxy is the one place that already holds both halves of the exchange
in memory at the moment the verdict is known. The WAF already buffers
request bodies under a cap; the mirror already models what to do when a
body exceeds one. What is missing is a rule that says which exchanges are
worth keeping and a guarantee that keeping them cannot hurt the traffic
that is working.

## What this changes that is not obvious

**The buffering decision is made before the answer exists.** Whether a
capture is worth taking depends on the response status, which arrives long
after the point where the request body has to be buffered or discarded.
So matching is two-phase: request-side predicates decide whether to pay
the buffering cost, response-side predicates decide whether the buffer
becomes a record. Everything expensive is gated on phase one, which is why
`route_id` is mandatory and why `source_cidrs` exists at all.

**A capture rule is an operator-authored memory allocation on a node that
also terminates production TLS.** Every cap in this story exists for that
reason, and the global ceiling exists because per-rule caps multiply.

**The blob version moves.** `capture_rules` joins `CanonicalConfig`, whose
decode is strict (`deny_unknown_fields`) and gated on
`CANONICAL_FORMAT_VERSION`. Bumping it to 2 means a 1.7.x follower refuses
a 1.8.0 blob with a clear message instead of a confusing field error. That
is the right failure, and the documented upgrade order already sequences
it: the same change carries a schema migration, so a 1.7.x follower is
refused at the handshake by the schema gate before the blob is ever
offered. See AC #10.

## Acceptance Criteria

1. **Model and storage.** New `CaptureRule` in `lorica-config` with its own migration and CRUD in the store: `id`, `name`, `route_id` (mandatory, foreign key), `enabled`, `match` (request-side predicates), `emit` (response-side predicates), `capture` (what to keep and how much), `limits`, `output`, `created_by`, `created_at`, `expires_at`, counters `captures_emitted`, `captures_dropped`. Rules replicate to followers through the Story 9.4 allowlist; `expires_at` is absolute UTC so every node agrees.

2. **Request-side predicates (phase 1, evaluated once at `request_filter`)** decide whether this request is a capture candidate and therefore whether its body is buffered: `source_cidrs` (parsed by the same helper as `ConnectionFilterPolicy::from_cidrs`, evaluated against the same client IP the access log uses, XFF-aware), `methods`, `path_prefix`, `path_regex`, `headers` (name plus `HeaderMatchType::{Exact,Prefix,Regex}` reused from `Route`). An empty predicate set matches every request on the route.

3. **Response-side predicates (phase 2, evaluated at `logging`)** decide whether a buffered candidate is emitted or discarded: `status` (exact codes or the classes `4xx` / `5xx`, plus `499` for client-aborted), `min_latency_ms`, `upstream_error`. Predicates inside `emit` are ORed; `match` and `emit` are ANDed. An empty `emit` is accepted only with an explicit `"emit": {"always": true}`, so a forgotten condition is not a silent full dump.

4. **Body buffering reuses the existing seams, with the mirror's overflow stance.** The request body accumulates in `request_body_filter` into a buffer distinct from `ctx.waf_body_buffer`, because the WAF buffer is released before the response exists. The response body accumulates in `response_body_filter`. Both stop at `request_body_max_bytes` / `response_body_max_bytes` (default 64 KiB, hard cap 4 MiB) and flip to an overflowed state the way `mirror_rewrite.rs` does: the bytes kept are retained, `truncated: true` is set, and the stream continues untouched. Content types in `STREAM_CONTENT_TYPE_PREFIXES` are never buffered on the response side and the record says `body_skipped: "streaming"`. Buffering copies once and never holds the body past `logging`.

5. **Budgets are mandatory and enforced per rule.** `max_captures` (default 100, hard cap 10 000), `rate_per_minute` (default 10, sliding window), `ttl` (default 1 h, hard cap 7 days) which the API materialises into `expires_at` at creation. Reaching `max_captures` or `expires_at` flips `enabled = false` and audits it; the rule is never deleted automatically, so the operator sees what happened. Counters and the rate window are per process; in worker mode the semantics are per worker and `docs/capture.md` says so, with the absolute `expires_at` as the fleet-consistent bound.

6. **Memory ceiling per node.** A global `capture_max_inflight_bytes` (default 64 MiB) across all rules and all in-flight candidates. Over it, new candidates are not buffered, the record is emitted with `body_skipped: "budget"` if the response-side predicate matches, and `lorica_captures_total{outcome="dropped_budget"}` increments.

7. **Hot reload.** Rules live in the `ProxyConfig` snapshot behind the existing `ArcSwap`, compiled (regexes, CIDR sets) at snapshot build time, never per request. Regex size and compile budgets reuse the WAF custom-rule caps.

8. **API.** `GET /api/v1/capture/rules` (Operator+), `POST /api/v1/capture/rules` (SuperAdmin), `GET|PUT|DELETE /api/v1/capture/rules/{id}` (SuperAdmin), `POST /api/v1/capture/rules/{id}/disable` (Operator+, so an on-call operator can stop a capture without being able to start one). `POST` returns 422 with a field-level error on an unbounded rule.

9. **Prometheus:** `lorica_capture_rules_active`, `lorica_captures_total{rule_id, outcome=emitted|dropped_rate|dropped_budget|dropped_sink}`, `lorica_capture_inflight_bytes`.

10. **The blob version moves to 2, deliberately.** `CANONICAL_FORMAT_VERSION` becomes 2 in the same change that adds `capture_rules` to `CanonicalConfig`. A node on version 1 receiving a version 2 blob refuses it by version rather than by unknown field, which is what the stamp exists for. `docs/cluster.md` records that the upgrade order already covers this, because the accompanying schema migration makes the handshake refuse an older follower first, and the frozen wire corpus is unaffected since the blob stays opaque bytes on the wire.

## Integration Verification

- **IV1:** A rule with `source_cidrs = ["172.30.0.0/16"]` and `status = ["5xx"]` on route R, against a backend answering 200 on `/ok` and 502 on `/fail`: requests from `172.30.1.10` to `/fail` produce exactly one record each with the full request body; requests to `/ok` produce none and hold no buffer past `logging`; requests from `10.0.0.5` to `/fail` produce none and are never buffered.
- **IV2:** A 10 MiB request body against a 64 KiB cap emits a record with `truncated: true` and 65 536 body bytes, while the upstream receives all 10 MiB unchanged; p99 on the unmatched sibling route is unchanged with the rule active.
- **IV3:** A rule with `max_captures = 3` disables itself after the third emission and audits; a rule with `ttl = "2m"` disables itself after two minutes on a control plane and on a follower within one heartbeat of each other.
- **IV4:** A 1.7.x follower offered a version 2 blob refuses it with the version message, and the round aborts rather than half-applying.

## Tasks

- [x] AC #1: the model, the migration (56), the store CRUD, the replication allowlist entry, and the `CanonicalConfig` field. A capture rule is cut with its route, and its two counters stay out of the blob.
- [x] AC #10: `CANONICAL_FORMAT_VERSION` to 2 with the refusal test. The `docs/cluster.md` paragraph rides the documentation slice.
- [x] AC #2/#3: the predicate types and their evaluation, unit-tested away from the proxy.
- [x] AC #7: compilation into a `CompiledCaptureRules` set keyed by route. Wiring it into the `ProxyConfig` snapshot rides the proxy slice.
- [ ] AC #4: the two buffering seams and the overflow stance.
- [ ] AC #5/#6: the budgets, the sliding window, the global ceiling, the self-disable and its audit.
- [ ] AC #8: the API surface with the 422 cases.
- [ ] AC #9: the metrics.
- [ ] Gates: the three CI clippy commands with `RUSTFLAGS=-D warnings`, every Rust suite, `cargo audit`, and the frontend three once Story 10.2 adds the page.

## Dev Notes

### Order matters here

The model and the blob-version bump land first and alone, because every
later slice depends on the shape and because AC #10 is the one change in
this story that a mixed-version fleet can notice. Predicate evaluation is
next and is pure: it takes a request head and a response verdict and
answers a boolean, so it is unit-testable without a proxy. The hot-path
buffering lands only once both are settled, because that is where a
mistake costs latency on traffic that has nothing to do with capture.

### The thing most likely to go wrong

Holding a body past `logging`. The buffer is attached to the request
context and the context outlives the callback in exactly one direction;
every early-return path in `response_body_filter` has to release it. The
WAF buffer already solved this once and the answer should look the same.

### What is deliberately not here

Body redaction. The body is what the operator asked to see; headers and
query parameters are where credentials hide, and Story 10.2 redacts those.

## Dev Agent Record

### Debug Log

**Two budgets could not be reused, and both are named rather than
hidden.** `lorica-config` depends on neither `regex` nor `ipnet`. The
pattern-length cap is therefore a constant restated from the WAF's
`MAX_CUSTOM_PATTERN_LEN` with a comment saying so, and the compiled-size
budget (`RegexBuilder::size_limit`) has to be applied in whichever crate
actually builds the matcher, which is the proxy slice. CIDR validation is
hand-rolled on `std::net` with an explicit prefix bound; it converges onto
the connection filter's parser when Story 10.3 moves that policy into this
crate. Note the two differ deliberately in what they DO with a bad entry:
the filter warns and skips, a write-time validator refuses.

**`prepare_replica` does not validate capture rules**, and that is
deliberate. A follower stricter than its control plane aborts the round
for the whole fleet, which is the failure mode Story 9.4 AC #5 exists to
avoid. The defence is on the apply instead: a rule naming a route this
node does not serve is dropped and counted.

**A bad `source_cidrs` entry fails the whole rule**, which is the
opposite of what `connection_filter::parse_cidrs` does with the same
input. That one skips the entry and warns. Here skipping can empty the
list, and an empty list means every client, so a typo would widen a
capture rather than narrow it. The connection filter has the same shape
and the same risk on a path where an empty list is the documented
default; that is backlog #88, found while writing this.

**`StatusMatch::ClientError` excludes 499.** 499 is the client-abort
marker, not a status a backend returned; folding it into the 4xx class
would make every "show me client errors" rule silently collect aborted
requests too. `ClientAborted` is the only way to ask for it.

### Completion Notes

(empty)

## File List

Anticipated, to be corrected during implementation.

- `lorica-config/src/models/capture.rs` (new), `models/mod.rs`, `store/capture.rs` (new), `store/mod.rs` (migration), `canonical.rs`, `store/replica.rs`
- `lorica/src/proxy_wiring.rs`, `proxy_wiring/context.rs`, `lorica/src/startup/` (snapshot build)
- `lorica-api/src/routes/capture.rs` (new), `lorica-api/src/metrics.rs`, `openapi`
- `docs/capture.md` (new), `docs/cluster.md`, `CHANGELOG.md`

## Change Log

- 2026-09-16: Story drafted from the Epic 10 PRD. Added AC #10: the PRD did not state that adding a replicated table moves `CANONICAL_FORMAT_VERSION`, and the strict decode makes that a mixed-version event worth naming rather than discovering.
