# Story 9.8: Syslog Sink and OTLP Logs Signal

**Epic:** 9 (v1.7.0)
**Status:** Draft
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

- [ ] AC #1: RFC 5424 encoder + three transports + per-kind toggles.
- [ ] AC #2: `logs` feature flip, exporter wiring, span-context
      correlation.
- [ ] AC #3: node identity fields on both sinks.
- [ ] AC #4: bounded queue + drop counters.
- [ ] AC #5: decide the execution model, document it, implement.
- [ ] AC #6: Settings tab + test endpoints.
- [ ] AC #7: hot reload through the two-phase path.
- [ ] AC #8: scrubbing on JSON and TOML paths.
- [ ] AC #9: docs.

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

(empty)

### Completion Notes

(empty)

## File List

Anticipated:

- `lorica-notify/src/channels/syslog.rs` (new, RFC 5424)
- `lorica/src/otel.rs` (logs exporter + span correlation)
- `lorica/Cargo.toml` (`logs` feature on the three otel crates)
- `lorica-api/src/settings.rs` (sink config + test endpoints)
- `lorica-dashboard/frontend/src/routes/Settings.svelte` (Log export tab)
- `tests-e2e-docker/` (`log-sinks` profile)

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-08-23 | 0.1 | Story drafted from the revised Epic 9 PRD. Syslog hand-rolled rather than added as a dependency; OTLP logs via a feature flip on already-pinned crates; sink execution model promoted to an acceptance criterion. Status Draft. | Romain G. |
