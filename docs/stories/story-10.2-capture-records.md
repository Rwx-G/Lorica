# Story 10.2: Capture Records, Redaction, Sinks and Dashboard

**Epic:** [Epic 10 - Conditional Request Capture & CI Automation API (v1.8.0)](../prd/epic-10-v1.8.0.md)
**Status:** Draft
**Priority:** P0
**Author:** Romain G.
**Depends on:** Story 10.1, which decides what is captured. This story decides what the capture looks like and where it goes.
**Blocks:** nothing. It closes the capture half of the epic.

---

As a security-conscious operator,
I want captured traffic to leave the proxy in a stable, redacted, structured format,
so that I can ship it to the SIEM that already receives the access log without leaking credentials into it.

## Problem

A capture is the most sensitive thing this proxy will ever emit. It is a
verbatim copy of a request and its response, taken at the point where TLS
has already been terminated, and it is written to a sink an operator
pointed somewhere. Everything about its format is a safety question
before it is an ergonomics one.

Two failure modes matter more than the rest. The first is a credential
surviving into the SIEM: an `Authorization` header or a session cookie
copied verbatim into a log that a wider audience reads than the one that
could read the traffic. The second is a sink that stops accepting
records, a full disk or a wedged collector, turning into a source of 5xx
on production traffic.

## What this changes that is not obvious

**The record has to join the access log.** A capture is only useful next
to the row that already describes the request, so `request_id` is the
same value in both, and that constraint decides where in the request
lifecycle the record is built.

**Headers are a list, not a map.** A map loses duplicates, and duplicated
headers are exactly the thing worth seeing when debugging why a proxy and
a backend disagree about a request. This also keeps the record honest
about order.

**Redaction is not configurable downward.** A rule may add names to the
redaction list and may never remove one. An operator who can create a
capture rule can already see the traffic; the point is that the RECORD,
which travels further than they do, carries less.

**The captured response body is the UPSTREAM's, before any rewrite this
proxy applied.** Story 10.1's buffering runs ahead of the response-rewrite
path on purpose: the story's own motivation is a backend returning
something wrong, and for that the raw upstream bytes are the evidence. The
consequence is that a capture can disagree with what the client received
on a route that rewrites bodies, and an operator comparing the two would
be right to be confused. `docs/capture.md` has to say this plainly, and
the record's own documentation with it. This is a semantic choice, not an
implementation detail.

**Bodies are deliberately not redacted**, and that has to be said out
loud rather than left as an omission. The body is the thing the operator
asked to see. A body-level redaction pass that an operator can trust is a
different feature; pretending to have one would be worse than not having
it.

## Acceptance Criteria

1. **Record format.** One JSON document per capture, `kind = "capture"`, carrying `rule_id`, `rule_name`, `route_id`, `request_id` (the same value as the access-log row, so the two join), `timestamp`, `client_ip`, `is_xff`, `backend`, `latency_ms`, `error`, then `request { method, uri, version, headers[], body, body_encoding, body_bytes_total, truncated, body_skipped }` and `response { status, headers[], body, body_encoding, body_bytes_total, truncated, body_skipped }`. `body_encoding` is `utf8` when the content type is textual and the bytes are valid UTF-8, `base64` otherwise. Headers are an ordered list of pairs, never a map, so duplicates survive.

2. **Redaction by default.** `Authorization`, `Proxy-Authorization`, `Cookie` and `Set-Cookie`, plus any header named in the rule's `redact.headers`, are replaced by `<redacted:N bytes>` where N is the length of what was removed. Query-string parameters named in `redact.query` are masked the same way. Redaction cannot be disabled through the API: a rule may only extend the list. Body redaction is out of scope and `docs/capture.md` says so explicitly.

3. **Sinks.** `SinkKind` in `lorica-api/src/log_sinks/mod.rs` gains `Capture`, with the same per-kind toggles as `access` / `waf` / `audit` on syslog and OTLP logs. This closes backlog #50 for the new kind at the same time. The default output is the structured stdout or rolling-file log through the existing `tracing` layer at target `lorica::capture`. An optional `output.dir` writes one file per capture (`<timestamp>-<request_id>.json`, mode `0640`, owner `lorica`) under a directory that must already exist and be writable, with the rule's `max_dir_bytes` and oldest-first pruning. Captures never enter the SQLite access-log database: a 64 KiB body per row would break the bounded writer's memory model.

4. **Sink failure never touches the request.** A full directory, a slow syslog collector or a closed OTLP exporter increments `lorica_captures_total{outcome="dropped_sink"}` and drops the record. Same stance as Story 9.8.

5. **Dashboard.** A "Capture" page under Observability: the rule list with live counters, remaining budget and time to expiry; a create form that refuses to submit without a route and without a status or latency condition (or the explicit "always" acknowledgement), showing the resulting `expires_at`; and a "Recent captures" panel fed by a bounded in-memory ring (last 50 records, bodies elided past 4 KiB) with a download button for the full record while it is still in the ring. Role gating mirrors the API.

6. **Audit.** Rule creation, update, manual disable, auto-disable (budget or expiry) and deletion are audited with the operator identity, the route and the effective predicates.

7. **Documentation.** `docs/capture.md`: the two-phase model, the caps, the worker-mode semantics, a SIEM example, and a "why did my rule expire" troubleshooting section.

## Integration Verification

- **IV1:** A captured request carrying `Authorization: Bearer x` and `Cookie: s=y` produces a record where both values are `<redacted:...>` on stdout, in the syslog collector and in the OTLP collector, and the collector-side record joins the access-log row on `request_id`.
- **IV2:** With `output.dir` on a read-only mount, requests keep flowing with zero 5xx and the drop counter increments.
- **IV3:** A binary `application/octet-stream` body round-trips through `base64` and decodes byte-for-byte to the original.
- **IV4:** The redaction list from a rule is additive: a rule naming `X-Api-Key` redacts it AND still redacts `Authorization`, which no rule can turn off.

## Tasks

- [ ] AC #1: the record type and its serialisation, with the `body_encoding` decision unit-tested on both branches.
- [ ] AC #2: the redaction pass, with the always-redacted set as a constant no configuration path can reach.
- [ ] AC #3: `SinkKind::Capture`, the lane registration, the `tracing` target, and the directory writer with its pruning.
- [ ] AC #4: the drop path and its counter.
- [ ] AC #5: the dashboard page, the ring, and the three frontend gates.
- [ ] AC #6: the audit rows.
- [ ] AC #7: `docs/capture.md`, including two things an operator will otherwise discover the hard way: the response body is the upstream's and predates any rewrite, and a capture rule cannot be disabled on a follower without break-glass because it arrives by replication and a local change would be overwritten on the next round.
- [ ] Gates: the three CI clippy commands with `RUSTFLAGS=-D warnings`, every Rust suite, `cargo audit`, and the frontend three (`npm run check`, `npm run lint`, `npx vitest run`).

## Dev Notes

### The lane registration is already the right shape

Backlog #51 was closed in the v1.8.0 hygiene pass: a consumer that lives
outside `install` calls `register_lane` once it is running, and the
returned `Receiver` is the proof that a live consumer exists. A lane whose
consumer dies is torn out on the next event. So the capture lane costs one
`register_lane` call and inherits the "installed lane, dead consumer"
guarantee rather than re-deriving it. Backlog #49 (the `Arc<SinkPayload>`
hand-off) was closed in the same pass and for this story specifically: a
capture record carries bodies up to 64 KiB, and a deep clone per lane at
request volume was the thing that made the measure-first gate worth
lifting early.

### The thing most likely to go wrong

The always-redacted set becoming reachable from configuration. It must be
a constant, the merge must be a union and never a replacement, and the
test for it must assert the negative: a rule that names nothing still
redacts `Authorization`, and a rule that tries to name it does not
un-redact it.

### Where the record is built

At `logging`, after the response verdict exists and before the buffers are
released. That is the only point where both halves and the access-log
`request_id` are in hand at once.

## Dev Agent Record

### Debug Log

(empty)

### Completion Notes

(empty)

## File List

Anticipated, to be corrected during implementation.

- `lorica/src/capture/` (new: record building, redaction, the ring)
- `lorica-api/src/log_sinks/mod.rs`, `lorica-api/src/metrics.rs`
- `lorica-dashboard/frontend/src/routes/Capture.svelte` (new) and its test
- `docs/capture.md` (new), `CHANGELOG.md`

## Change Log

- 2026-09-16: Story drafted from the Epic 10 PRD. Added IV4: the PRD states that redaction cannot be disabled but does not ask anyone to prove it, and "a configuration path that can reach the always-redacted set" is the one defect in this story that would be silent.
