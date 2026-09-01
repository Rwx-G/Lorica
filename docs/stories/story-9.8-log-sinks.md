# Story 9.8: Syslog Sink and OTLP Logs Signal

**Epic:** 9 (v1.7.0)
**Status:** Done
**Author:** Romain G.

**Depends on:** nothing in this epic. Independent of the cluster and
should land first in the cycle to de-risk the release.

## Story

As an operator with an existing SIEM,
I want Lorica to ship its logs where the rest of my estate already sends
them,
so that I do not have to scrape a dashboard or tail a file to get access
logs and WAF events into my pipeline.

## Acceptance Criteria

1. Syslog: RFC 5424 framing implemented in-tree over UDP, TCP and TCP
   with TLS, using the already-present `tokio` and `tokio-rustls`
   stack. **No new dependency.** Configurable facility, per-event-kind
   severity mapping and structured-data fields. Access logs, WAF events
   and audit entries independently toggleable.
2. OTLP logs: enable the `logs` feature on the already-pinned
   `opentelemetry` / `opentelemetry_sdk` / `opentelemetry-otlp` 0.32
   crates. No new crate and no version bump. `trace_id` and `span_id`
   are attached from the active span context.
3. Both sinks carry `node_id` and `node_name` from Story 9.6 and work
   identically on a standalone install.
4. Both sinks are non-blocking and bounded, reusing the `log_writer.rs`
   contract. Overflow increments
   `lorica_log_sink_dropped_total{sink, kind}`.
5. The execution model is an acceptance criterion: the story states
   whether the sinks run on the existing non-tokio OS thread with
   blocking sockets or on a parallel tokio task fed by a second queue.
6. Settings gains a "Log export" tab with a per-sink test action
   reporting success, failure reason and round-trip time.
7. Both sinks hot-reload through the existing two-phase path with no
   restart.
8. Sink secrets (TLS client keys, OTLP authorization headers) are
   scrubbed from JSON responses and TOML export.
9. Documentation in the README observability section and
   `docs/cluster.md`, with a worked SIEM example and a worked OTLP
   collector example.

## Tasks / Subtasks

- [x] AC #1: RFC 5424 encoder + three transports + per-kind toggles.
- [x] AC #2: `logs` feature flip, exporter wiring, span-context
      correlation.
- [x] AC #3: node identity fields on both sinks.
- [x] AC #4: bounded queue + drop counters.
- [x] AC #5: decide the execution model, document it, implement.
- [x] AC #6: Settings tab + test endpoints.
- [x] AC #7: hot reload through the two-phase path.
- [x] AC #8: scrubbing on JSON and TOML paths.
- [x] AC #9: docs (README done; `docs/cluster.md` section deferred to
      Story 9.6, which creates that file - see Completion Notes).

## Dev Notes

**AC #1: hand-roll it.** Grep for `syslog` and `rfc5424` across
`Cargo.lock` returns nothing, and `lorica-notify/src/channels/` has only
`email.rs`, `slack.rs`, `stdout.rs`, `webhook.rs`. The obvious crate
(`syslog`) is unmaintained since 2022 and Unix-socket-oriented. RFC 5424
is a header line plus structured data, roughly 150 lines over
`tokio::net::UdpSocket` / `TcpStream` / `tokio-rustls`, all already
present. For a security appliance, that beats adding supply-chain
surface, and this project's policy requires sign-off for new
dependencies anyway.

**AC #2: no new crate, but the correlation is not free.**
`lorica/Cargo.toml:102-106` pins `opentelemetry`, `opentelemetry_sdk`
and `opentelemetry-otlp` at 0.32 (plus `tracing-opentelemetry` 0.33),
all optional behind the `otel` feature, and `Cargo.lock:3913-3999`
confirms 0.32.0/0.32.1 resolved with `opentelemetry-proto` 0.32 already
in the tree. The current feature lists are `trace`-only, so enabling the
logs signal is adding `"logs"` to three existing feature lists.

The catch: the canonical way to attach `trace_id` / `span_id` to
`tracing` events is `opentelemetry-appender-tracing`, which is **not**
in `Cargo.lock`. The alternative is constructing `LogRecord`s against
the SDK logger API and reading the active span context, which
`lorica/src/otel.rs:24-70` already parses for W3C traceparent. Doable
without a new dependency, but it is real work that the first draft
budgeted nothing for. If the hand-rolled path turns out worse than
expected, adding `opentelemetry-appender-tracing` needs explicit
sign-off.

**AC #4: the contract already exists, copy it.**
`lorica-api/src/log_writer.rs:1-25` implements exactly the bounded /
`try_send` / drop / `lorica_log_write_dropped_total{kind}` behaviour this
story needs. Do not invent a second one.

**AC #5 is the decision that drives the whole story.**
`log_writer.rs:20-23` states the consumer is deliberately "a plain OS
thread, not a tokio task, so the writer behaves identically in
supervisor, worker, and single-process modes regardless of which runtime
(if any) is current at spawn time". A syslog-over-TLS sink and an OTLP
exporter both want async I/O. Either the sinks run on that OS thread
with blocking sockets, or a second queue feeds a tokio task and the
mode-independence argument has to be re-made for that path. Pick one
before writing code; getting this wrong is the kind of
supervisor/worker asymmetry that has bitten this project before.

**AC #8** follows the existing treatment of webhook URLs, Slack URLs and
`auth_header`, which are scrubbed on JSON GET after the v1.5.1 TOML
scrub asymmetry was fixed.

**Why this story goes first.** It is the only story in Epic 9 with no
dependency on the cluster, it delivers the half of issue #26's log
requirement that does not need a fleet, and landing it early gives the
release something shippable while the cluster stories are still moving.

## Dev Agent Record

### Debug Log

- 2026-09-01: first Docker `cargo check` failed twice on environment,
  not code: (1) `lorica-dashboard/build.rs` needs
  `SKIP_FRONTEND_BUILD=1` in a Node-less container; (2)
  `rust:1-bookworm` lacks `cmake` + `protobuf-compiler`
  (`libz-ng-sys`) - both already documented in
  `.claude/rules/lorica-docker.md`.
- 2026-09-01: `Result<Option<TlsConnector>, _>::expect_err` does not
  compile (`TlsConnector: !Debug`); the unit test matches instead.

### Completion Notes

- **AC #5 decision (execution model)**: each sink consumer is a plain
  OS thread. The syslog consumer owns a **current-thread tokio
  runtime** (async sockets for TCP+TLS); the OTLP consumer uses
  `blocking_recv` and needs no runtime at all (the SDK batch
  processor does its own I/O on a dedicated thread). This keeps
  `log_writer.rs`'s mode-independence argument (identical behaviour
  in supervisor, worker and single-process modes regardless of the
  ambient runtime) while still using async I/O where a sink needs it.
- **Placement deviation from the anticipated File List**: the syslog
  sink lives in `lorica-api/src/log_sinks/` (beside `log_writer.rs`,
  whose bounded/`try_send`/drop contract it reuses), NOT in
  `lorica-notify`. lorica-notify is alert-only (10 events / 60 s
  rate limit) and has neither `tokio/net` nor `tokio-rustls`;
  putting a per-request-volume sink there would have added deps and
  fought the dispatcher's rate limiter.
- **Trace correlation (AC #2/#3)** is captured at publish time on the
  hot path (`ctx.outgoing_traceparent`) and carried on the event
  envelope - the consumer thread has no ambient span. WAF events
  publish without trace context (several emit sites are pre-route
  with no ctx in scope); the access-log record for the same request
  carries the correlation.
- **Process topology**: access logs + WAF events publish from the
  proxy process (worker / single), audit entries from the management
  process (supervisor / single) via `emit_audit_event`, the single
  funnel all audit paths hit. Each process installs its own hub via
  `apply_per_process_reload_state` (6th line) + boot-time calls in
  the three startups; snapshot-dedup mirrors the OTel exporter so a
  route edit never tears down sink connections.
- **gRPC + auth header**: `otlp_logs_auth_header` is not applied on
  the `grpc` transport (would pull tonic metadata types in);
  a warn log points operators at http-proto / http-json. Documented
  in the code and the API doc comment.
- **node_id / node_name (AC #3)**: fields exist on the sink config
  and the wire formats (syslog SD params, OTLP attributes) but stay
  empty until Story 9.6 wires cluster identity; standalone installs
  emit without them, as required.
- **AC #9 partial deferral**: README observability section done
  (worked rsyslog + OTLP collector examples); `docs/cluster.md` does
  not exist yet - it is created by Story 9.6, which must add the
  log-sink section there.
- Rate limiting: all three settings test probes (otel, syslog,
  otlp-logs) are rate-limited (`destructive_cud` bucket); the
  historical otel probe gained the limiter during QA for consistency.

### QA iteration 1 (2026-09-01, five parallel auditors)

Findings fixed in-loop (Critical=0, High=5, all resolved):

- **PUT /settings returned every secret unmasked** (security, High,
  pre-existing structural asymmetry with GET): masking extracted into
  `mask_settings_secrets` applied by both handlers; regression test
  asserts no raw secret bytes in the PUT body.
- **Worker-side sink counters invisible on /metrics** (architecture,
  High): `lorica_log_sink_{dropped,sent,truncated}_total` added to
  `PER_WORKER_COUNTERS` + resolve arms.
- **No sink drain on shutdown / hot upgrade** (architecture, High):
  `log_sinks::shutdown_and_drain(3s)` called from `otel::shutdown`
  (both feature variants) before the OTLP consumer join + provider
  flush; every exit path already calls `otel::shutdown`.
- **Dead consumer left a live lane; PEM unvalidated at PUT**
  (architecture, High): lanes carry ids and self-remove on terminal
  consumer failure; install spawns the consumer before installing the
  lane; `PUT /settings` builds the exact TLS connector and 400s on
  bad material.
- **validators.test.ts "broken assertion"** (quality, High):
  FALSE POSITIVE - the fixture contained a raw 0x01 byte invisible in
  terminal rendering (Vitest was green all along). The raw byte was
  the real defect: replaced with an explicit `String.fromCharCode(1)`.

Medium/Low fixed: per-transport message ceilings (1536 B UDP / 7168 B
stream bodies) with UTF-8-safe truncation + `truncated="1"` SD param +
counter (closes the UDP EMSGSIZE self-eviction and collector-desync
vectors); sink secrets encrypted at rest via `encrypt_config` +
covered by `rotate_encryption_key` (rotation test); cleartext
transport warn (API log + UI hint); audit records on both sink test
endpoints; control chars stripped from SD values and rejected in
`syslog_extra_sd` values (+512-char cap); PEM parse errors mapped to
fixed strings (no key material in error bodies); sink export decoupled
from the local `access_log_enabled` toggle; `lorica_log_sink_sent_total`;
versioned self-describing JSON body (`v`, `kind`) shared by both
consumers; probe helper dedup (otel + otlp-logs handlers); frontend
test-runner dedup; encode-after-backoff reorder; single-lock publish;
audit sink record reuses the persisted row's timestamp and is gated on
`wants()`; `with_node_identity` seam for Story 9.6; manual `Debug`
redacting the client key; per-process fan-out documented in README.

Findings rejected with rationale: store numeric `unwrap_or` fallbacks
(consistent with the recent sibling fields, e.g.
`cert_export_file_mode`); ArcSwap migration for the hub (new dep edge
for a nanosecond-scale win; the double-lock was fixed instead);
`tcp-tls` as default transport (UDP is the standard syslog operator
expectation; loud warnings instead). Deferred items recorded as
backlog #49-#55.

Verification after fixes: 573 Rust tests green, CI-equivalent clippy
clean, cargo audit clean (pre-existing warnings only), all four
frontend gates green (383 Vitest tests), log-sinks e2e smoke re-built
and re-run after the fixes: 23/23.

### Handoff notes for later stories

- **Story 9.1** (`rotate_encryption_key` table-driven rework): the
  rotation loop now also covers the `global_settings` keys
  `syslog_tls_client_key_pem` and `otlp_logs_auth_header` - fold them
  into the table-driven enumeration and its coverage test.
- **Story 9.2**: reuse the sink-lane seam deliberately - see backlog
  #51 (registration inversion) and #52 (lorica-obs boundary).
- **Story 9.6**: wire node identity via
  `LogSinksConfig::with_node_identity` in
  `lorica/src/reload.rs::apply_log_sinks_from_store`, and add the
  log-sink section to the new `docs/cluster.md` (AC #9 deferral).

## File List

- `lorica-config/src/models/settings.rs` (15 new GlobalSettings fields + defaults)
- `lorica-config/src/store/settings.rs` (KV read arms + write stanzas)
- `lorica-config/src/export.rs` (scrub syslog client key + OTLP auth header)
- `lorica-config/src/import.rs` (reject redacted sink secrets)
- `lorica-config/src/tests.rs` (round-trip + scrub/reject tests)
- `lorica-api/src/log_sinks/mod.rs` (new: sink hub, config, publish API)
- `lorica-api/src/log_sinks/syslog.rs` (new: RFC 5424 encoder + UDP/TCP/TLS transports + test message)
- `lorica-api/src/lib.rs` (module registration)
- `lorica-api/Cargo.toml` (tokio `net` feature)
- `lorica-api/src/metrics.rs` (`lorica_log_sink_dropped_total{sink,kind}`)
- `lorica-api/src/audit.rs` (publish audit entries to sinks)
- `lorica-api/src/settings.rs` (validation, scrubbing, schema, 2 test endpoints)
- `lorica-api/src/server.rs` (routes for the test endpoints)
- `lorica-api/openapi.yaml` (2 new paths)
- `lorica/Cargo.toml` (`logs` feature on the three otel crates)
- `lorica/src/otel.rs` (`OtelLogsConfig`, `init_logs` / `shutdown_logs`, record mapping)
- `lorica/src/reload.rs` (`apply_log_sinks_from_store` + bundle wiring)
- `lorica/src/proxy_wiring.rs` (access-log publish with trace context)
- `lorica/src/proxy_wiring/filters.rs` (WAF event publish)
- `lorica/src/startup/single.rs`, `lorica/src/startup/worker.rs` (boot-time sink install)
- `lorica-dashboard/frontend/` (Log export tab, api client, validators - see frontend commit)
- `tests-e2e-docker/` (`log-sinks` profile - see e2e commit)
- `README.md` (observability section + API table)
- `CHANGELOG.md` (`[Unreleased]` Added entries)

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-08-23 | 0.1 | Story drafted from the revised Epic 9 PRD. Syslog hand-rolled rather than added as a dependency; OTLP logs via a feature flip on already-pinned crates; sink execution model promoted to an acceptance criterion. Status Draft. | Romain G. |
| 2026-09-01 | 0.2 | Implemented: config fields + KV projection + secret scrub/reject; sink hub + RFC 5424 syslog sink in `lorica-api/src/log_sinks/`; OTLP logs exporter behind the existing `otel` feature; reload + boot wiring in all three process modes; hot-path publish with trace context; settings validation, JSON masking, 2 test endpoints + openapi; dashboard "Log export" tab; `log-sinks` e2e profile (phase 8). Rust unit tests (567 in lorica-api) and all four frontend gates green; CI-equivalent clippy + audit pending final run. Status Review. | Romain G. |
| 2026-09-01 | 1.0 | QA iteration 1 (5 parallel auditors): 5 High fixed (PUT secret masking, worker counter aggregation, shutdown drain, lane lifecycle + PUT-time TLS validation, test-fixture raw control byte), plus the Medium/Low batch (message ceilings + truncation, at-rest encryption of sink secrets, cleartext warnings, test-endpoint audit records, SD hardening, dedups). Deferred items -> backlog #49-#55. All gates green incl. e2e 23/23 after rebuild. Status Done. | Romain G. |
