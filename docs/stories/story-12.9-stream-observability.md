# Story 12.9: Stream Observability

**Epic:** [Epic 12 - TCP and UDP Stream Proxying (v1.11.0 and v1.12.0)](../prd/epic-12-v1.11.0.md)
**Status:** InProgress
**Priority:** P0
**Author:** Romain G.
**Depends on:**
- Story 12.1 (Review): the closed end-reason set (`StreamEndReason`,
  `StreamEndKind`, `StreamRefusal` in `lorica-config/src/models/stream.rs`)
  and canonical format 3, inside which this story adds one replicated
  setting.
- Story 12.2 (InProgress): the stream plane driver
  (`lorica/src/startup/stream_plane.rs`), its alert sender and the
  `stream_bind_failed` alert (AC #5's first item, already delivered),
  the bind state per stream, the drain reasons `config_removed` and
  `node_shutdown`.
- Story 12.3 (InProgress, Lots C and D2 landed): `StreamCounters`,
  `CountersSnapshot`, `ConnectionRecord`, the `ConnectionObserver` seam
  and `LogObserver` (D-r), the breaker keyed `"stream:" + id` in the HTTP
  registry (D-g), the DNS `dns_failures` health event handed to this
  story (D-n, Resolved 3).
- Story 12.4 (Draft): `ConnectionRecord.tls: Option<TlsRecord>` and the
  TLS counters of its D-n (its D-m hands both to this story).
- Story 12.5 (InProgress, Lots A to E landed): the UDP counters,
  `DatagramDropReason`, `datagrams_upload` / `datagrams_download` on the
  record, the per-node session total read from the stream-caps region,
  the `ceiling_reached` edge (D-n), the breaker outcome per session (the
  basis of UDP availability here).
- Story 12.6 (Draft): `RefusalLogLimiter<K>` moved to
  `lorica_stream::refusal_log`, refused connections that hand no record
  to the observer (its D-j), the refusal reasons it adds, `pending` and
  `geoip_unknown`.
- Story 12.8 (InProgress): the per-worker counter aggregation it extended
  (`PER_WORKER_COUNTERS`), which this story generalises to gauges.

**Blocks:** Story 12.10 (the Streams page links to this story's log tab
and SLA section; the live counters it shows read this story's
aggregation), 12.11 (`drained_by_upgrade` rows and per-stream drain
counts use this story's row and metric shapes), 12.12 (the parity matrix's
"L4 access log" and "L4 metrics" rows are verified against this story),
12.15 (fills the `detected_protocol` column this story creates), 12.16
(a transferred connection writes one row, at its real end).

---

As an operator,
I want to see what my streams carry and why a connection ended,
so that layer 4 is not the blind spot of my monitoring.

## Problem

After Stories 12.3 to 12.6 every stream connection and UDP session is
counted per process and handed, at its end, to a `ConnectionObserver`
that only logs it at debug level (`LogObserver`, installed in
`lorica/src/stream_engine.rs`). Nothing of it reaches an operator: no
access-log row, no sink, no Prometheus series, no SLA, no notification
beyond the failed bind. In worker mode the counters live in the workers
and the supervisor's `/metrics` cannot see them, because only counters
named in `PER_WORKER_COUNTERS` cross the process boundary and only as
counters: the stream plane has gauges (active connections, pending
handshakes) and a histogram (connect latency) that the existing machinery
cannot carry. Backlog #53 (a) adds a requirement of the same shape: a
log sink that is down must be visible, from every process that ships logs.

## Acceptance Criteria

These are the PRD's, unchanged. They are the contract.

1. **An access-log row per TCP connection and per UDP session** at its end: stream, client address (after PROXY protocol where accepted), backend, bytes each way, duration, TLS mode, SNI, detected protocol when Phase 2 applies, and one end reason from the enum of Story 12.1 AC #8.
2. **The rows reach the existing sinks** (`SinkKind`, `lorica-api/src/log_sinks/mod.rs`) through a new stream kind: syslog, OTLP logs, the dashboard log view.
3. **Prometheus metrics** under the `lorica` namespace: active connections and sessions, accepted, refused by reason, dropped datagrams by reason, bytes each way, connect latency to backend, per stream and per backend. No client address in a label.
4. **SLA per stream**: availability and backend connect latency. This extends the per-route SLA model and its dashboard view, and `sla:read` covers it.
5. **Notifications** through `lorica-notify` for a failed bind, a stream backend down, and a UDP ceiling reached.
6. **A sink that is down is visible** (backlog #53 (a)): a `lorica_log_sink_up{sink}` gauge from each sink consumer's connection state, for every sink kind, the stream kind included. Gauges are not aggregated across workers today (only counters are), so the story adds that aggregation and states which value the gauge takes when workers disagree.

## Integration Verification

- IV1: A refused connection, an idle-timeout close and a `config_removed` drain each produce a row with the right end reason, visible in the dashboard and in a syslog collector.

## What the code does today

Read on `feat/v1.11.0` at `377c9121`. Function names, not line numbers.
Read, not run, unless said otherwise.

- **The record and its observer.** `ConnectionRecord`
  (`lorica-stream/src/handler.rs`) carries stream id and name,
  `bind_gen`, client (after PROXY), socket peer, `proxied_from`, local
  address, backend id and address, attempts, bytes each way, datagram
  counts (`Option`, `None` on TCP), accepted, connected and ended
  instants, `end_reason: StreamEndReason`. No protocol field, no TLS
  field yet (12.4 Lot D adds `tls`), no detected protocol.
  `ConnectionObserver::observe` defaults to a debug line; `LogObserver`
  is what `stream_engine.rs` installs.
- **Counters.** `StreamCounters` (`lorica-stream/src/counters.rs`): per
  stream (`StreamStats`), per (stream, backend) (`LinkStats`), per
  backend (`BackendStats`), atomics, pruned by `retain` on table change,
  read through `snapshot() -> CountersSnapshot`. Bytes exist per stream
  only, not per link. Connect latency is a fixed-bucket histogram over
  `CONNECT_LATENCY_BUCKETS_S`. `session_cap_refused` raises the
  per-process `ceiling_reached` edge; `sessions_held` re-arms it below
  `CEILING_REARM_PERCENT`.
- **Access log.** `access-log.db` (`lorica-api/src/log_store.rs`) is
  opened by the supervisor and by every worker; its schema is created
  with `CREATE TABLE IF NOT EXISTS` plus `add_column_if_absent`, never
  through numbered migrations. `access_logs` is HTTP-shaped (method,
  path, status `NOT NULL`, indexes on host and status). Retention is a
  row count (`access_log_retention`, default 100,000, replicated through
  `CanonicalConfig`). `log_writer.rs` fronts it with one bounded queue
  for access rows and WAF events and a drop counter
  `lorica_log_write_dropped_total{kind}`.
- **Sinks.** `SinkKind` has `Access`, `Waf`, `Audit`, `Capture`; each
  lane carries one flag per kind; the flags are node-local
  `GlobalSettings` fields (`syslog_<kind>_enabled`,
  `otlp_logs_<kind>_enabled`). The syslog consumer connects lazily on
  the first event and backs off from 1 s to 30 s; while it backs off,
  events are dropped and counted. The OTLP lane hands records to the
  SDK's batch exporter, whose export outcome nobody observes
  (`emit_sink_event`, `lorica/src/otel.rs`). `body_json` stamps `v` and
  `kind`; OTLP adds the `lorica.kind` attribute.
- **Metrics across processes.** Workers serve no `/metrics`. They ship
  `GenericCounterTuple`s for the names in `PER_WORKER_COUNTERS`; the
  supervisor applies deltas so counters stay monotone across worker
  restarts. The only gauge that crosses is `lorica_log_store_up`, smuggled
  in the same list and read back by name in
  `apply_worker_generic_counters`, kept as one series per process.
- **SLA.** `SlaConfig` / `SlaBucket` (`lorica-config/src/models/sla.rs`)
  are keyed by `route_id`; `lorica_bench::SlaCollector` records per
  request in each process and flushes minute buckets to the config DB with
  an additive upsert, so workers' buckets sum; breach evaluation with a
  notifier runs where the flush task was given one. Management routes
  under `/api/v1/sla/...`; automation `GET /automation/v1/sla/overview`
  and `/sla/routes/{id}` under `sla:read`; MCP `lorica_sla_overview`,
  `lorica_sla_route`; cluster `SlaPull` keyed by `route_id`.
- **Alerts.** `AlertType::StreamBindFailed` exists (12.2) with its
  migration 74 subscribing explicit channels. `backend_down` is raised
  by the health loop on a confirmed flip of the shared backend health
  and names no stream. The breaker (`CircuitBreaker::bump_failure`,
  `lorica/src/proxy_wiring/lb.rs`, and `SupervisorBreakerRegistry` in
  `supervisor.rs`) logs its Closed-to-Open transition and reports it to
  nobody.
- **Fleet.** Followers push access rows, WAF events, bans and audit rows
  to the control plane in `TelemetryPush`
  (`lorica-cluster/src/messages.rs`), stored in `fleet_access_logs` and
  siblings (`lorica-fleet/src/telemetry_store.rs`). The upgrade order of
  1.11.0 is followers first, then the control plane (12.1 D-3).

## Decisions taken in this story

### D-a. One row shape, built in the binary, from the record

- **`StreamLogEntry`** (`lorica-api/src/stream_logs.rs`), the dashboard,
  store and sink shape, mirrors the record. Fields, in this order:
  `id`, `timestamp` (the end, RFC 3339), `entry` (`ended` or
  `refusals_suppressed`, see D-c), `stream_id`, `stream_name`,
  `protocol` (`tcp` or `udp`), `listen_port` (the local port, which is
  what tells the ports of a range stream apart), `client_ip`,
  `client_port` (after PROXY where accepted), `proxied_from` (the socket
  peer when a PROXY header was accepted, empty otherwise), `backend_id`,
  `backend_address` (the address actually connected), `attempts`,
  `bytes_upload`, `bytes_download`, `datagrams_upload`,
  `datagrams_download` (null on TCP), `duration_ms` (accepted to end),
  `connect_ms` (accepted to connected, null when nothing connected),
  `tls_mode` (`none`, `passthrough`, `terminate`), `sni`, `alpn` (the
  negotiated ALPN on a terminated stream, the first offered one in
  passthrough), `client_cert` (`absent`, `verified`, or null when the
  stream does not verify), `detected_protocol` (null in 1.11.0, Story
  12.15 fills it), `end_reason` (a `StreamEndKind` word), `refusal_reason`
  (a `StreamRefusal` word when `end_reason` is `refused`, else empty),
  `suppressed` (the count on a `refusals_suppressed` row, else 0).
- **Every word comes from the enums' `as_str` / `VARIANTS`**
  (`.claude/rules/derived-not-transcribed.md`); a test builds one row per
  `StreamEndKind` variant and per `StreamRefusal` variant and checks the
  word round-trips through the store and `body_json`.
- **The client certificate subject is not logged**, only the outcome
  12.4 records, for parity with HTTP (Resolved 4). Verified at
  `377c9121`: the HTTP access row is built in `lorica/src/proxy_wiring.rs`
  (the `LogEntry { .. }` literal after `sinks_want_access`) and
  `LogEntry` (`lorica-api/src/logs.rs`) has no certificate field at all,
  so a request on an mTLS route logs neither subject nor outcome. The
  stream row keeps the outcome because 12.4 hands it over and it carries
  no personal data; the subject stays out like HTTP's.
- **The conversion lives in the binary** (`lorica/src/stream_log.rs`):
  `lorica-api` does not depend on `lorica-stream`, and the record type
  belongs to the engine. The binary implements `ConnectionObserver` as
  `StreamLogObserver`, replacing `LogObserver` at both construction
  sites of `stream_engine.rs`.
- **Lot A adds to the record** what the row needs and the record lacks:
  `protocol: StreamProtocol` (inferring UDP from `datagrams_upload.is_some()`
  would be a contract nobody wrote down), and
  `detected_protocol: Option<String>` (always `None` until 12.15). `tls`
  is 12.4's.

### D-b. Storage: a table of its own in `access-log.db`

- **`stream_access_logs`**, a new table in `access-log.db`, not a `kind`
  column on `access_logs`. *Why:* every `access_logs` column after `id`
  and `timestamp` is HTTP (`method`, `path`, `status NOT NULL`), its
  indexes are on host and status, `AccessRowForFanIn` mirrors the wire
  field for field, and a kind column would make every existing HTTP query,
  export and retention pass filter on it. Columns are the fields of D-a;
  indexes on `timestamp`, `(stream_id, timestamp)` and `end_reason`.
  Created with `CREATE TABLE IF NOT EXISTS` in `LogStore::open`, after the
  existing tables, following the schema rule written there: no numbered
  migration, since `access-log.db` has none. A test opens a file written
  by the 1.10.6 schema (`log_store_upgrade.rs`) and one written by this
  story, and a 1.10.6-shaped open of the new file still succeeds (an
  extra table is invisible to it), so a hot-upgrade rollback keeps its
  log store.
- **Retention**: a new `stream_access_log_retention` setting, a row
  count, default 100,000, `0` unlimited, enforced in the same retention
  pass as `access_log_retention` by the same span-estimate algorithm.
  Its own setting because a chatty UDP stream must not evict HTTP rows,
  nor the reverse. Replicated through `CanonicalConfig` exactly as
  `access_log_retention` is, inside 12.1's format-3 decision.
- **Its own writer queue.** `log_writer.rs` gains `enqueue_stream` on a
  second bounded queue of the same capacity, drained by the same writer
  thread, with drops counted as `lorica_log_write_dropped_total{kind="stream"}`.
  *Why:* one shared queue would let a stream flood shed HTTP rows. The
  writer alternates between the queues so neither starves the other.
- **Management API**: `GET /api/v1/stream-logs` (filters: `stream_id`,
  `end_reason`, `refusal_reason`, `client_ip`, `from`, `to`; pagination
  as `/api/v1/logs`), `GET /api/v1/stream-logs/export` (JSON and CSV as
  the HTTP export), `DELETE /api/v1/stream-logs`, each with the role
  requirement of its `/api/v1/logs` counterpart. No WebSocket: the
  stream tab polls with the log view's existing refresh control.
- **Dashboard**: `Logs.svelte` gains an "HTTP / Streams" switch; the
  Streams view lists the D-a columns (bytes humanised, duration, end
  reason as a badge, refusal reason beside it, SNI and TLS mode, the
  suppressed count on `refusals_suppressed` rows) with the filters above.

### D-c. Refusals and pre-forwarding ends go through the refusal limiter, and become rows

12.6 D-j ruled that a refused connection hands no record to the observer,
so an attacker cannot choose the access log's write rate, and logs a
rate-limited `warn` line instead. IV1 needs a refused connection to
produce a row. Both hold at once:

- **The limiter's admitted refusals are rows.** `ConnectionObserver`
  gains two defaulted methods, `refused(RefusalRecord)` and
  `refusals_suppressed(SuppressedRecord)`. `RefusalRecord` is what the
  engine knows at refusal: stream id and name, protocol, listen port,
  client (judged as 12.6 D-b judges it), `proxied_from`, the
  `StreamRefusal`, the instant. Where 12.6 writes the `warn` line for an
  admitted refusal, the engine calls `refused`; where it writes "N
  refusals suppressed", it calls `refusals_suppressed` (stream, protocol,
  reason, count, window end). The `warn` line goes to `debug`: the row
  is now the operator's record, and a journald line per admitted refusal
  beside it would double the bounded rate for nothing.
  `StreamLogObserver` turns them into `entry = ended`,
  `end_reason = refused` rows and `entry = refusals_suppressed` rows.
- **Pre-forwarding ends join the same limiter** (12.6's recommendation,
  accepted here): a record whose end is `proxy_header_invalid`,
  `clienthello_timeout`, 12.4's invalid ClientHello end or
  `detection_timeout` is passed through the limiter before it becomes a
  row. These ends are chosen by the client before any backend work, so
  they are the same write-rate lever as a refusal. The limiter's key for
  streams widens from `(stream index, StreamRefusal)` to
  `(stream index, StreamLogKey)`, `StreamLogKey` being `Refused(StreamRefusal)`
  or `PreForwarding(StreamEndKind)`; a suppressed pre-forwarding end
  writes a `refusals_suppressed` row whose `end_reason` is that end.
  Counters are untouched: every end and refusal is still counted
  (NFR5), only rows are limited.
- **Every other end writes its row unconditionally**, as an HTTP request
  does. Its rate is bounded by the stream's own admission (12.6 rates and
  caps), not by the client's choice of how to fail.
- UDP refusals (per datagram of a refused session) use the same path,
  which is the reason 12.5 kept them recordless.

### D-d. The stream sink kind

- **`SinkKind::Stream`**, label `stream`, which is also the syslog MSGID
  and the `lorica.kind` OTLP attribute, and `SinkPayload::Stream(StreamLogEntry)`.
  `publish_stream(entry)` follows `publish_access` (no trace context: a
  stream has no request span).
- **Toggles**: `syslog_stream_enabled` and `otlp_logs_stream_enabled`,
  node-local `GlobalSettings` fields beside the four existing pairs,
  default `true` like every kind (no 1.10.6 operator has stream traffic,
  so the default surprises nobody). `SinkKindToggles`, `SyslogSinkConfig`
  and `SinkLane` gain the flag; `register_lane` takes it.
- **Field mapping.** The body is `body_json`: the D-a fields flattened,
  plus `v` (`SINK_BODY_VERSION` stays 1: a new kind is additive, which is
  what the `kind` key is for) and `kind = "stream"`. Syslog: severity
  `syslog_severity_access` (a stream row is an access row; no new
  severity setting), MSGID `stream`, the existing SD parameters, the
  same per-transport body ceilings. OTLP: severity `INFO`, timestamp from
  the row, the body as for every kind, and `lorica.kind`. No further
  attributes: the other kinds put everything in the body, and two shapes
  for one exporter would drift.

### D-e. Prometheus: names, labels, and how workers reach the scrape

**Labels.** `stream_id` and `backend_id`, never names (a rename would
split a series) and never a client address, port, SNI or ALPN (all
client-chosen). A `lorica_stream_info{stream_id, stream_name, protocol} 1`
series gives the join to names. Reason labels take the closed enums'
words.

**Series** (all under `lorica_`, built with `lorica_metrics::register_*`):

| Name | Type | Labels | Source |
|---|---|---|---|
| `stream_info` | gauge | `stream_id`, `stream_name`, `protocol` | table |
| `stream_listener_up` | gauge | `stream_id` | supervisor bind state (12.2) |
| `stream_active` | gauge | `stream_id` | TCP: sum of workers; UDP: the region's per-node total (12.5 D-n) |
| `stream_pending` | gauge | `stream_id` | the region's per-node pending total (12.6) |
| `stream_accepted_total` | counter | `stream_id` | `accepted` |
| `stream_ended_total` | counter | `stream_id`, `reason` | `ended` (`StreamEndKind`) |
| `stream_refused_total` | counter | `stream_id`, `reason` | `refused` (`StreamRefusal`) |
| `stream_datagrams_dropped_total` | counter | `stream_id`, `reason` | `dropped` (`DatagramDropReason`) |
| `stream_bytes_total` | counter | `stream_id`, `direction` | `bytes_upload`, `bytes_download` |
| `stream_datagrams_total` | counter | `stream_id`, `direction` | UDP datagram counts |
| `stream_connect_attempts_total` | counter | `stream_id` | `connect_attempts` |
| `stream_retries_total` | counter | `stream_id` | `retries` |
| `stream_breaker_denied_total` | counter | `stream_id` | `breaker_denied` |
| `stream_candidates_skipped_total` | counter | `stream_id`, `reason` | `local_destination`, `source_family_mismatch`, `source_bind_failed` |
| `stream_proxy_header_total` | counter | `stream_id`, `outcome` | `ProxyHeaderOutcome` |
| `stream_ceiling_reached_total` | counter | `stream_id` | `ceiling_reached` |
| `stream_geoip_unknown_total` | counter | `stream_id` | 12.6 |
| `stream_clienthello_total`, `stream_tls_handshakes_total` | counter | `stream_id`, `outcome` | 12.4 D-n |
| `stream_no_sni_matched_total`, `stream_ech_offered_total`, `stream_sni_mismatch_total` | counter | `stream_id` | 12.4 D-n |
| `stream_rule_matched_total` | counter | `stream_id`, `rule` (the rule's position) | 12.4 D-n |
| `stream_backend_active` | gauge | `stream_id`, `backend_id` | sum of workers |
| `stream_backend_connects_total` | counter | `stream_id`, `backend_id` | `connects` |
| `stream_backend_connect_failures_total` | counter | `stream_id`, `backend_id`, `kind` | `ConnectFailureKind` |
| `stream_backend_bytes_total` | counter | `stream_id`, `backend_id`, `direction` | new per-link bytes (Lot A) |
| `stream_backend_connect_seconds` | histogram | `stream_id`, `backend_id` | the link histogram, `CONNECT_LATENCY_BUCKETS_S` |
| `stream_backend_upstream_tls_failures_total` | counter | `stream_id`, `backend_id`, `kind` | 12.4 D-n |
| `stream_backend_dns_failures_total`, `stream_backend_dns_local_excluded_total` | counter | `backend_id` | `BackendStats` |

The table is a design statement; the code registers each family from the
enums it labels, and the test of Lot C2 iterates the enums, never a copy
of this table.

**Cardinality bound.** Per stream: the sum over families of their
closed label sets, a constant. Per link: likewise. The number of streams
on a node is bounded by the fd budget's listening-socket cap (12.2 AC #5),
links by the backends per stream. **Series of a deleted stream or link are
removed** from the supervisor's registry on the table change that removes
it (the same `retain` the counters do), so a churn of streams does not
grow `/metrics`. A range stream has no port label: its ports share one
series set.

**Aggregation: a typed report, a collector, monotone sums.** The
generic-counter list cannot carry a histogram, and 30 families of
hand-registered `PER_WORKER_COUNTERS` entries would be a transcription of
the snapshot type. Instead:
- `MetricsReport` (`lorica-command/src/messages.rs`) gains
  `stream_counters`, a typed encoding of `CountersSnapshot` (cumulative
  values per stream, link and backend, histogram buckets included). Worker
  and supervisor are always the same binary, so the field needs no
  version negotiation; a report without it (none can exist) reads as
  empty.
- `lorica-api/src/stream_metrics.rs` holds `StreamMetricsCollector`, a
  `prometheus::core::Collector` registered once, which renders every
  family above at scrape time from the supervisor's aggregate:
  - **counters and histogram buckets**: `retired + sum(live workers)`.
    When a worker's reported value for a series goes down (the worker
    restarted, or the series was pruned and recreated) or the worker is
    forgotten, its last value is folded into `retired` first. The sum is
    therefore monotone, which is what `rate()` needs; the existing
    delta machinery gives the same guarantee for the generic counters.
  - **gauges** (`active` on TCP, `backend_active`): sum over live
    workers. A forgotten worker's share leaves at once: its connections
    died with it.
  - **node-exact gauges** (`active` on UDP, `pending`): read from the
    stream-caps region by the supervisor, not summed.
- Single-process mode: the collector reads the process's own
  `CountersSnapshot` at scrape as its only "worker".
- `retired` and the per-worker maps are pruned with the series on table
  change.

### D-f. Gauges across workers, and `lorica_log_sink_up{sink}` (AC #6)

- **A generic per-worker gauge mechanism** in `lorica-metrics`:
  `PER_WORKER_GAUGES: &[(&str, GaugeAggregation)]` in
  `lorica-api/src/metrics.rs`, `GaugeAggregation` being `Min`, `Max` or
  `Sum`. A worker appends its gauges' current values to the existing
  generic list (the path `lorica_log_store_up` already rides, so no wire
  change); the supervisor keeps each worker's last value per label set and
  sets its own gauge to the aggregate of its local value and every
  worker's, recomputed on every report and on `forget`. A name the
  counter machinery does not know is skipped there, as today.
  `lorica_log_store_up` keeps its per-process series (its own decision,
  documented where it is defined); it is not moved.
- **`lorica_log_sink_up{sink}`**, `sink` in {`syslog`, `otlp`}, aggregated
  with **`Min`**: the node's value is 0 as soon as one process that has
  that sink configured reports it down. *Why min:* each worker ships its
  own share of the access, WAF, capture and stream rows and the
  supervisor ships the audit rows, so one process with a dead sink loses
  that process's share; `Max` would read "up" while a worker's rows are
  lost, and an average is not a state. Which process is down is in the
  logs (the consumer's own warn line) and, per kind, in
  `lorica_log_sink_dropped_total`.
- **Who reports.** A process reports a value for a sink when its
  `LogSinksConfig` configures that sink (syslog endpoint set; OTLP lane
  requested), whatever the kind toggles. A configured sink whose consumer
  failed terminally (invalid TLS material, runtime build, thread spawn,
  `init_logs` failure) reports 0, never nothing: a lane that disappears
  must not read as "not configured". No process configured: no series.
- **A dead worker**'s last value stands until its replacement, which
  takes the same id, reports: the reason `forget_worker_generic_counters`
  gives for the log-store gauge applies unchanged (forgetting it would
  read "up" for the length of a respawn). Sum gauges do the opposite
  (D-e) because a dead process holds no connection.
- **What "up" means per transport:**
  - syslog TCP and TLS: a connection is established. The consumer now
    connects at start and, while backing off, retries on its backoff
    timer even without events, so the gauge returns to 1 when the
    collector does, not at the next event. Events during backoff are
    still dropped and counted as today.
  - syslog UDP: the socket is open and the last send did not error. UDP
    proves no delivery; `docs/` says so.
  - OTLP: the last export call returned `Ok`, observed by a thin
    `LogExporter` wrapper around the SDK exporter in `otel.rs` (the batch
    processor calls `export`; the wrapper records the outcome and
    delegates). 1 from a successful `init_logs` until the first export.
    With no traffic the value is the last export's, which the docs say.
- **"For every sink kind"**: the gauge is per sink, not per kind, because
  a lane is per sink and all its kinds share one connection; the stream
  kind rides the same lanes and is covered by the same series. A kind
  toggled off changes nothing about the connection.

### D-g. SLA per stream

- **Definitions.** An SLA bucket judges connections, not bytes.
  - **TCP**: a connection is *judged* once it reaches backend selection
    (past admission and every pre-forwarding phase). It is a *success*
    when it connects within `max_connect_latency_ms`, a *failure* when it
    ends `connect_failed` or `no_healthy_backend`, or connects slower than
    the bound. Refusals and pre-forwarding ends are not judged: they say
    nothing about the backends. Connect latency is accepted-to-connected
    of the attempt that connected, retries included, which is what the
    client waited.
  - **UDP**: a session is judged when 12.5's breaker outcome is known:
    success at the first backend datagram, failure on an ICMP error
    before any or a no-response idle on a stream with
    `responses_per_request >= 1`. A session of a stream that expects no
    response (syslog, NetFlow: `responses_per_request = 0`, or responses
    unbounded, the engine's `expects_responses` being false) is judged
    at its end: a success unless it ended on an ICMP error
    (`connect_failed`). No latency on UDP (there is no connect); the
    latency columns stay null and the view shows availability only
    (Resolved 2).
  - *Amendment (maintainer, 2026-11-16, after Lot D):* the first text
    judged such a session only on an ICMP failure and never otherwise.
    Every judged session was then a failure, so any window in which the
    stream judged something read 0 %, and a single ICMP error raised
    `sla_breached`. Judging the session at its end gives the silent
    sessions their success, and availability is again the share of
    sessions the backend did not refuse.
- **Recorded at the decision, not at the end.** A TCP connection can
  last hours; judging it at its end would put its availability in the
  wrong bucket. `ConnectionObserver` gains a defaulted
  `connect_outcome(stream_id, protocol, ConnectOutcome)` called by the
  engine where the connect phase resolves (TCP) and where the breaker
  outcome is reported (UDP). `StreamLogObserver` forwards it to the
  collector. The one session judged at its end is the UDP session that
  expects no response (amendment above): `StreamLogObserver` reports it
  from `observe`, from the record's end reason, and ignores its
  `connect_outcome`.
- **Storage**, in the config DB as the route SLA is: `stream_sla_configs`
  (`stream_id` primary key, foreign key to `streams` with `ON DELETE
  CASCADE`, `target_pct` default 99.9, `max_connect_latency_ms` default
  500, the route defaults), and `stream_sla_buckets` (`stream_id`,
  `bucket_start`, `source`, `judged_count`, `success_count`,
  `failure_count`, `connect_latency_sum_ms`, `_min_ms`, `_max_ms`,
  `p50/p95/p99` as the route bucket has them, and the `cfg_*` snapshot
  columns), unique on `(stream_id, bucket_start, source)`, no foreign
  key, for the reason migration 55 gives for `sla_buckets`. New tables,
  not new keys in the route tables: every route query, the overview and
  `SlaPull` would otherwise have to tell the two apart. One migration,
  next free number at implementation time; a 1.10.6 binary opens the
  result (12.1 AC #3's rollback test is extended).
- **Collector**: `lorica_bench::passive_sla::StreamSlaCollector`, a
  sibling of `SlaCollector` with the same minute buckets, the same
  additive upsert (so workers' buckets sum), the same flush task, and
  breach evaluation where the flush task has a notifier (supervisor and
  single process), edge-triggered as for routes. Purge: the existing
  `sla_purge_*` settings cover both bucket tables.
- **Breach alerts** are the existing `sla_breached` / `sla_recovered`,
  with details `target = stream`, `stream_id`, `stream_name` in place of
  the route keys. No new alert type.
- **API**: `GET /api/v1/sla/streams/{id}`, `/buckets`, `GET`/`PUT
  /config`, `/export`, `DELETE /data`, mirroring the route routes and
  their roles; `/api/v1/sla/overview` gains a `streams` array beside the
  routes. Automation (`sla:read`): `GET /automation/v1/sla/streams/{id}`
  and the same `streams` array in `/automation/v1/sla/overview`. MCP read
  tier: `lorica_sla_stream`. Cluster: `SlaPull` gains `stream_id` (a new
  prost tag), answered from `stream_sla_buckets`; the 1.11.0 order
  (followers first) means a new control plane never asks an old follower.
- **Dashboard**: `Sla.svelte` gains a Streams section: availability per
  window, connect latency percentiles for TCP, target, breach state, and
  the config editor.

### D-h. Notifications (AC #5)

- **Failed bind**: delivered by 12.2 (`stream_bind_failed`), counted here,
  untouched.
- **Stream backend down: two sources, one per kind of evidence.**
  - *Active health* (a backend with an active check, shared or not):
    the existing `backend_down` from the health loop, whose details gain
    `streams`, the names of the streams linked to the backend (at most
    20, then `and N more`), beside the routes it already implies. A
    stream operator learns it is theirs without a second alert for the
    same flip.
  - *Passive detection*: new `AlertType::StreamBackendDown`
    (`stream_backend_down`), raised when the breaker for a
    `"stream:" + id` key moves from Closed to Open. That is the only
    down signal a UDP backend has before Story 12.14, and the one that
    catches a TCP backend whose port answers but whose connects fail.
    `CircuitBreaker::record_failure` (and the supervisor registry's
    equivalent) returns whether it opened the circuit; HTTP callers ignore
    it. Raised in the supervisor (worker mode, where the registry is) or
    in the single process (the stream engine's breaker adapter), never in
    a worker. One alert per incident: a HalfOpen-to-Open re-trip is the
    same incident, and the incident ends when the circuit closes. At most
    one per (stream, backend) per 5 minutes (`STREAM_BACKEND_ALERT_HOLD`)
    so a flapping backend cannot become an alert storm. Details: stream
    id and name, backend id, name and address, node, the breaker
    threshold.
- **UDP ceiling reached**: new `AlertType::StreamUdpCeilingReached`
  (`stream_udp_ceiling_reached`), raised once per node per incident.
  Each worker's `ceiling_reached` edge is per process, so up to W edges
  fire per incident; the supervisor raises the alert when the aggregated
  `ceiling_reached` of a stream grows while the stream is not in its
  ceiling state, and re-arms when its own read of the region's per-node
  session total is below `CEILING_REARM_PERCENT` of `max_sessions`.
  Single process: the edge itself. Details: stream id and name, node,
  `max_sessions`, the limit that bound the node ceiling (12.5 AC #6).
- **DNS resolution failure** (handed over by 12.3): **no alert**. A
  failed resolution keeps the last known addresses (12.3 AC #13), so the
  backend is not down; an alert would page on a non-outage. It is a
  series (`lorica_stream_backend_dns_failures_total`) and a warn line per
  transition (12.3 D-n). When it does take a backend out (a name never
  resolved), connections end `no_healthy_backend`, which the stream SLA
  counts as failures and `sla_breached` reports (Resolved 3).
- **Every new type** goes everywhere `StreamBindFailed` went in 12.2:
  `AlertType` (`as_str`, `ALL`, `FromStr`, the position test), channel
  emoji maps, `lorica-api/src/vocabulary.rs` (labels; no recovery pair),
  `openapi.yaml`, the dashboard's notification form if it lists types,
  and a migration (next free number at implementation time, the pattern
  of migration 74) subscribing every channel saved with an explicit list
  to both types.

### D-i. The fleet: stream rows and stream SLA reach the control plane

- `TelemetryPush` gains `repeated TelemetryStreamRow stream` (a new prost
  tag), drained from `stream_access_logs` with its own cursor, under the
  push caps the access rows use, and stored by the control plane in
  `fleet_stream_logs` (`lorica-fleet/src/telemetry_store.rs`, `CREATE
  TABLE IF NOT EXISTS`, with `node_id`), retention and per-node quota as
  `fleet_access_logs`. The control plane's stream log view and API read
  local and fleet rows as the HTTP view does.
- Mixed versions: followers upgrade first, and a 1.10.6 control plane
  ignores the unknown tag (prost drops unknown fields), so a follower's
  stream rows pushed during the mixed window are lost to the fleet view,
  never to the follower's own store. `docs/cluster.md` says so.
- Stream SLA crosses through `SlaPull.stream_id` (D-g).
- *Why in this story:* streams are targeted at followers by
  `node_selector`, so on a fleet most stream traffic is on followers; a
  stream log the control plane cannot show is a blind spot in exactly the
  deployment the epic aims at. Kept (Resolved 1).

### D-j. Automation and MCP reads of stream rows

- `GET /automation/v1/stream-logs` requires **both `logs:read` and
  `streams:read`** (12.10 adds the latter): `logs:read` is documented as
  "access-log rows", which stream rows are, and a stream row names a
  stream, which only `streams:read` may reveal. A token confined by
  `allowed_hostnames` receives no stream row (a stream has no hostname to
  match), the rule 12.10 applies to `streams:read`. MCP read tier:
  `lorica_stream_logs`, paginated and capped like `lorica_logs`. The
  audit reason and both OpenAPI documents move with it (Resolved 5).

### D-k. Shutdown order

A stop drains streams for `worker_drain_timeout_s` and closes the rest
with `node_shutdown` (12.2 AC #7). Those rows are written after the drain,
so the stream runtime's drain must finish before the log writer's flush
and `log_sinks::shutdown_and_drain` run, in the worker and in the single
process. A test stops a single process with a live connection and finds
its `node_shutdown` row in the store.

## Tasks

Lots with hard file allowlists. A Lot touches only its files; two Lots
that share a file are sequential, never parallel, and say so. Every Lot
that runs cargo ends on a tree that passes the gate chain CI runs
(`cargo fmt --all -- --check`, the workspace clippy with `--all-targets
--features lorica/otel -- -D warnings` under `CARGO_BUILD_WARNINGS=deny`,
the CI `cargo test` lines, `cargo audit`), through Docker on Linux. No
agent runs `git checkout`, `git restore`, `git stash` or `git reset` in
the shared tree. No new dependency.

**Order.** A after 12.4 Lot D and 12.6 Lot C (the record's `tls`, the
limiter's move and the refusal hooks are what A edits). B in parallel
with A, after any open Lot editing `lorica-config/src/store/mod.rs`
(12.6 Lot B, any open 12.7 Lot). C2 after B. C1 after B and C2 (it
calls C2's `set_log_sink_up`). D after B, in parallel with C1 and C2. C3 after
C1 (shared `server.rs`, `openapi.yaml`) and D. E after A. F after A, C1,
C2, C3, D and E, and after 12.4 Lot E, 12.5 Lot F and 12.6 Lot D (all edit
`worker.rs`, `single.rs`, `supervisor.rs` or `stream_engine.rs`). G after
C1 and C3. H after C1 and C3, and after 12.10's Streams page Lot if it
is open (shared `api.ts`). I after F, G and H. J after F, and after 12.2
Lot H and 12.6 Lot I (their e2e harness edits).

### Lot A: the record, the observer hooks, per-link bytes (`lorica-stream`) - cargo

Allowlist: `lorica-stream/src/handler.rs`, `lorica-stream/src/counters.rs`,
`lorica-stream/src/refusal_log.rs`, `lorica-stream/src/tcp/*.rs`,
`lorica-stream/src/udp/*.rs`, `lorica-stream/src/lib.rs`.

- [x] `ConnectionRecord` gains `protocol` and `detected_protocol` (D-a).
- [x] `ConnectionObserver` gains defaulted `refused`, `refusals_suppressed`,
      `connect_outcome` (D-c, D-g), with `RefusalRecord`,
      `SuppressedRecord`, `ConnectOutcome`; the engines call them where
      12.6 writes its refusal line and where the connect phase or UDP
      breaker outcome resolves.
- [x] `StreamLogKey` and the widened stream limiter key; pre-forwarding
      ends pass the limiter before `observe` (D-c).
- [x] `LinkStats` gains bytes each way, in the snapshot (D-e).
- [x] Tests: each hook fires exactly once per connection or session with
      the right values (TCP connected, connect_failed, no_healthy_backend;
      UDP success, ICMP, no-response, `K = 0`); a refusal flood past the
      window yields `limit` `refused` calls and one `refusals_suppressed`
      with the right count; a pre-forwarding end flood the same; per-link
      bytes add up to the stream's.

### Lot B: settings, SLA model and storage, alert types (`lorica-config`, `lorica-notify`) - cargo

Allowlist: `lorica-config/src/models/settings.rs`,
`lorica-config/src/models/sla.rs`, `lorica-config/src/models/mod.rs`,
`lorica-config/src/store/mod.rs`, `lorica-config/src/store/settings.rs`,
`lorica-config/src/store/sla.rs`, `lorica-config/src/canonical.rs`,
`lorica-config/src/tests.rs`, `lorica-config/tests/config_db_upgrade.rs`,
`lorica-notify/src/events.rs`, `lorica-notify/src/channels/*.rs`.

- [x] `stream_access_log_retention` (replicated, canonical),
      `syslog_stream_enabled`, `otlp_logs_stream_enabled` (node-local),
      defaults, KV load and save (D-b, D-d).
- [x] `StreamSlaConfig`, `StreamSlaBucket`, `StreamSlaSummary`; store
      functions mirroring the route ones; migration for the two tables
      (D-g).
- [x] `StreamBackendDown`, `StreamUdpCeilingReached` in `AlertType` and
      every match on it in `lorica-notify`; the subscription migration
      (D-h).
- [x] Tests: settings round-trip and canonical classification; migrations
      idempotent; a 1.10.6-shaped open of the migrated DB; bucket upsert
      sums two writers; config cascade on stream delete; alert type
      round-trip through `ALL`.

### Lot C1: stream log store, writer, API, sinks (`lorica-api`) - cargo

Allowlist: `lorica-api/src/stream_logs.rs` (new), `lorica-api/src/log_store.rs`,
`lorica-api/src/log_writer.rs`, `lorica-api/src/log_sinks/mod.rs`,
`lorica-api/src/log_sinks/syslog.rs`, `lorica-api/src/lib.rs`,
`lorica-api/src/server.rs` (stream-log routes only),
`lorica-api/src/settings.rs`, `lorica-api/openapi.yaml`,
`lorica-api/tests/log_store_upgrade.rs`.

- [x] `StreamLogEntry`, `stream_access_logs`, insert, query, export,
      clear, retention (D-a, D-b).
- [x] `enqueue_stream` on its own queue (D-b).
- [x] `SinkKind::Stream`, payload, toggles, `publish_stream`; syslog
      eager connect, timer-driven reconnect, per-sink up state published
      through C2's `set_log_sink_up` (D-d, D-f).
- [x] Settings API validation of the three new settings.
- [x] Tests: one row per `StreamEndKind` and `StreamRefusal` word
      round-trips store and `body_json`; retention trims stream rows only;
      the queues do not starve each other; the sink's MSGID and toggle; the
      syslog up state follows a collector that goes away and comes back
      without traffic; old-file open.

### Lot C2 (listed after C1, runs before it): metrics, gauge aggregation, the stream collector (`lorica-api`, `lorica-metrics`) - cargo

Allowlist: `lorica-api/src/metrics.rs`, `lorica-api/src/stream_metrics.rs`
(new), `lorica-metrics/src/*.rs`.

- [x] `PER_WORKER_GAUGES`, `GaugeAggregation`, supervisor-side per-worker
      gauge state and recompute on report and forget (D-f).
- [x] `lorica_log_sink_up{sink}` with `Min`, and
      `set_log_sink_up(sink: &str, up: bool)`, called by C1's syslog
      consumer and F's OTLP wrapper. `metrics.rs` is this Lot's file
      alone.
- [x] `StreamMetricsCollector` with every family of D-e, built from the
      enums; monotone `retired` folding; pruning on table change; the
      single-process path.
- [x] Tests: min across workers with one down; a dead worker's last value
      stands for `Min` and leaves for `Sum`; a worker restart does not
      make a counter go down; histogram buckets sum; a removed stream's
      series disappear; no family has a label outside the allowed set
      (iterate the registry, assert no `client`, `sni`, `alpn`, `port`
      label).

### Lot D: the stream SLA collector (`lorica-bench`) - cargo

Allowlist: `lorica-bench/src/passive_sla/stream.rs` (new),
`lorica-bench/src/passive_sla/mod.rs`, `lorica-bench/src/lib.rs`.

- [x] `StreamSlaCollector` (record, flush, breach evaluation with
      `sla_breached` / `sla_recovered` carrying stream details) (D-g).
- [x] Tests: judged, success, failure and latency-bound counting for TCP;
      UDP with and without expected responses; breach edge once; two
      collectors flushing into one bucket sum.

### Lot C3: SLA API, alert vocabulary, automation and MCP reads (`lorica-api`, `lorica-mcp`) - cargo

Allowlist: `lorica-api/src/sla.rs`, `lorica-api/src/vocabulary.rs`,
`lorica-api/src/server.rs` (SLA routes only), `lorica-api/src/automation/read.rs`,
`lorica-api/src/automation/mcp.rs`, `lorica-api/src/automation/audit.rs`,
`lorica-api/openapi.yaml`, `lorica-api/openapi-automation.yaml`,
`lorica-mcp/src/tools.rs`. Sequential after C1 (`server.rs`,
`openapi.yaml`).

- [x] Stream SLA management routes and overview field (D-g; the field
      built as `GET /api/v1/sla/streams`, Resolved 9). The
      cluster pull for `stream_id` is Lot G's, which edits
      `answer_sla_pull` after this Lot.
- [x] Labels for the two new alert types.
- [x] Automation `sla/streams/{id}`, the overview field, `stream-logs`
      with the D-j scope and confinement rule; MCP `lorica_sla_stream`,
      `lorica_stream_logs`; audit reasons; both OpenAPI documents (the
      overview field as `GET /automation/v1/sla/streams` and
      `lorica_sla_streams`, Resolved 9).
- [x] Tests: contract tests green; a `logs:read` token without
      `streams:read` gets 403 on stream logs; a hostname-confined token gets
      an empty page; `sla:read` reads a stream SLA.

### Lot E: the metrics report carries stream counters (`lorica-command`) - cargo

Allowlist: `lorica-command/src/messages.rs`, the proto file it is
generated from if any, `lorica-command/src/lib.rs`.

- [x] `MetricsReport.stream_counters` and its message types mirroring
      `CountersSnapshot` (D-e).
- [x] Tests: encode/decode round-trip of a snapshot with every map
      non-empty.

### Lot F: wiring in the binary (`lorica`) - cargo

Allowlist: `lorica/src/stream_log.rs` (new), `lorica/src/stream_engine.rs`,
`lorica/src/lib.rs`, `lorica/src/startup/worker.rs`,
`lorica/src/startup/single.rs`, `lorica/src/startup/supervisor.rs`,
`lorica/src/startup/stream_plane.rs`, `lorica/src/startup/mod.rs`,
`lorica/src/otel.rs`, `lorica/src/reload.rs`, `lorica/src/health.rs`,
`lorica/src/proxy_wiring/lb.rs`, `lorica/tests/*` (new files only).

- [x] `StreamLogObserver`: record to row, store, sinks, SLA collector
      (D-a, D-c, D-g); installed at both `stream_engine.rs` sites.
- [x] Worker: `stream_counters` and the sink gauges in each metrics report;
      supervisor: apply to `StreamMetricsCollector`, prune on table change,
      `stream_listener_up` and `stream_info` from the stream plane, UDP
      `active` and `pending` from the region.
- [x] `record_failure` returns the open transition; `stream_backend_down`
      from the supervisor registry and the single-process adapter, with
      the hold; `stream_udp_ceiling_reached` from the aggregate (D-h).
- [x] `backend_down` details gain `streams` (D-h).
- [x] OTLP: `SinkPayload::Stream` in `emit_sink_event`, the export-outcome
      wrapper, the stream toggle in `init_logs` / `register_lane` (D-d,
      D-f); reload carries the new toggles.
- [x] Shutdown order (D-k).
- [x] Tests: a TCP connection through a single process writes one row with
      every D-a field right; `node_shutdown` row on stop; a refused flood
      writes the bounded rows; the supervisor aggregate of two simulated
      workers; the breaker alert once per incident and held; the ceiling
      alert once for two workers' edges.

### Lot G: fleet fan-in (`lorica-cluster`, `lorica-fleet`, drain) - cargo

Allowlist: `lorica-cluster/src/messages.rs`, the proto it is generated
from if any, `lorica-fleet/src/telemetry_store.rs`,
`lorica-fleet/tests/cluster_telemetry_upgrade.rs`, the telemetry drain
module that builds `TelemetryPush` today (locate it at implementation
time; name it in the File List), `lorica-api/src/log_store.rs` (the
stream drain cursor only; sequential after C1), `lorica-api/src/sla.rs`
(`answer_sla_pull` only; sequential after C3), `lorica-api/src/stream_logs.rs`
(the fleet read only; sequential after C1).

- [ ] `TelemetryStreamRow`, the stream drain with its cursor,
      `fleet_stream_logs`, retention and quota; the control plane's stream
      log read merges local and fleet rows (D-i).
- [ ] `SlaPull.stream_id` and its answer (D-g).
- [ ] Tests: a follower's rows reach the control plane store; an old
      control plane decoding a new push ignores the field; the 1.10.6
      telemetry DB opens.

### Lot H: dashboard - frontend gates

Allowlist: `lorica-dashboard/frontend/src/routes/Logs.svelte`,
`lorica-dashboard/frontend/src/routes/Sla.svelte`,
`lorica-dashboard/frontend/src/lib/api.ts`, the settings component that
holds the syslog and OTLP kind toggles, their `*.test.ts`, new test files.

- [x] Logs: HTTP / Streams switch, the stream table and filters (D-b).
- [x] SLA: Streams section with config editor (D-g).
- [x] Settings: the two stream toggles and the retention field.
- [x] Gates: `tsc`, `svelte-check`, ESLint, Vitest (per
      `.claude/rules/lorica-frontend.md`); `pnpm-lock.yaml` untouched (no
      dependency).

### Lot I: documentation - no cargo

Allowlist: `docs/streams.md`, `docs/cluster.md`, the docs page that
describes log export (Story 9.8's), the docs page that lists metrics,
`docs/security/threat-model.md` (log amplification entry),
`docs/backlog.md` (#53 (a) row removed, #53 kept for its other items if
any), `CHANGELOG.md`, `README.md` (feature list).

- [ ] Row fields, end reasons (rendered from the enum list the API
      publishes, not retyped), the limiter, retention, the sink kind and
      toggles, every metric family, the SLA definitions, the three
      notifications and why DNS has none, `lorica_log_sink_up` and its
      `Min` rule, UDP "up" proving no delivery, OTLP "up" being the last
      export, the fleet's mixed-version window.

### Lot J: end-to-end, IV1 - Docker e2e

Allowlist: `tests-e2e-docker/docker-compose.yml`,
`tests-e2e-docker/entrypoint-stream-observability.sh` (new, LF),
`tests-e2e-docker/test-runner/run-stream-observability-smoke.sh` (new,
LF), `tests-e2e-docker/run.sh`, a Python TCP backend fixture if 12.3 Lot
G's is not reusable.

- [ ] Profile `stream-observability`: one node with `--workers 2`, the
      existing `syslog-collector` and logs-only OTel collector joined to
      the profile, a Python TCP backend.
- [ ] IV1, each case asserted in `GET /api/v1/stream-logs` (what the
      dashboard reads) and as a syslog frame with MSGID `stream`:
      - refused: a stream whose deny CIDR holds the runner's address;
        one connect gives `end_reason = refused` with 12.6's reason word;
        a burst gives at most the limiter's rows plus one
        `refusals_suppressed` row;
      - idle timeout: a stream with a 2 s idle timeout, a connection that
        sends nothing, `end_reason = idle_timeout`;
      - `config_removed`: `worker_drain_timeout_s = 3`, an open connection,
        the backend removed from the stream, `end_reason = config_removed`
        within the drain plus 2 s.
- [ ] Metrics: `lorica_stream_ended_total{reason="idle_timeout"}` on the
      supervisor's `/metrics` (a worker-only value, so aggregation is
      proven), `lorica_stream_bytes_total` above zero,
      `lorica_log_sink_up{sink="syslog"}` 1, then 0 within 10 s of the
      collector being stopped, then 1 within 40 s of its restart with no
      traffic in between.
- [ ] Stream SLA: after the cases, `GET /api/v1/sla/streams/{id}` has
      judged connections.

## Dev Notes

### Where to extend, verified on `377c9121`

- `lorica-stream/src/handler.rs`: `ConnectionRecord`, `ConnectionObserver`,
  `LogObserver`, `Engines`.
- `lorica-stream/src/counters.rs`: `StreamStats`, `LinkStats`
  (`connected`, `session_opened`), `snapshot`, `retain`,
  `CONNECT_LATENCY_BUCKETS_S`, `CEILING_REARM_PERCENT`.
- `lorica/src/stream_engine.rs`: the `LogObserver` construction and the
  `Engines` it fills.
- `lorica-api/src/log_store.rs`: `LogStore::open` (the schema rule
  comment), `enforce_retention`, `ACCESS_LOG_SPAN_SQL`, the drain cursor
  plumbing; `log_writer.rs`: `LogWriteHandle`, `spawn_log_writer`.
- `lorica-api/src/log_sinks/mod.rs`: `SinkKind`, `SinkKindToggles`,
  `SinkPayload`, `SinkLane::wants`, `install`, `register_lane`,
  `publish_access`; `syslog.rs`: `consumer_loop`, `connect`,
  `encode_rfc5424` (MSGID by kind, severity by kind).
- `lorica/src/otel.rs`: `init_logs`, `emit_sink_event`.
- `lorica-api/src/metrics.rs`: `PER_WORKER_COUNTERS`,
  `resolve_per_worker_counter`, `apply_worker_generic_counters`,
  `forget_worker_generic_counters`, the `LOG_STORE_UP` block (the model
  for D-f).
- `lorica-bench/src/passive_sla/`: `collector.rs`, `bucket.rs`,
  `persistence.rs` (the breach edge); `lorica-config/src/store/sla.rs`
  (the upsert); `lorica-api/src/sla.rs` (`answer_sla_pull`,
  `get_sla_overview`).
- `lorica/src/proxy_wiring/lb.rs`: `CircuitBreaker::bump_failure`;
  `supervisor.rs`: `SupervisorBreakerRegistry`.
- `lorica-config/src/store/mod.rs`: `STREAM_ALERT_TYPES`,
  `subscribe_explicit_channels`, migration 74's test.
- `lorica-cluster/src/messages.rs`: `TelemetryPush`, `SlaPull`;
  `lorica-fleet/src/telemetry_store.rs`: `fleet_access_logs`.

### Pitfalls

- **The stream runtime has one thread per process.** The observer runs
  on it: `observe` builds the row and hands it to bounded queues with
  `try_send`; it never touches SQLite or a socket.
- **Never a client-chosen value in a label**: SNI and ALPN are
  client-controlled strings; the rule label is the configured rule's
  position.
- **Counters must stay monotone across worker restarts** (D-e); test it
  with a worker whose value drops.
- **`access-log.db` is opened by every process**: the new table follows
  the busy-timeout and "column after CREATE" rules written in `open`.
- **Gauge and counter names share the generic list**: a gauge name must
  never be added to `PER_WORKER_COUNTERS`, or the delta machinery will
  treat its drops as resets.
- **Shell scripts LF**, and heredocs with apostrophes break the Bash tool:
  scripts through the Write tool.
- **The e2e suite needs the machine alone**; tear down orphan containers
  first.

### Tests per Lot

Listed in each Lot. Lots A to G need Linux and run through the
`run-tests` skill in Docker. Lot J is the e2e suite. What no automated
test here proves: that the dashboard renders the rows (Vitest covers the
component, not a browser session), and the behaviour of a real SIEM
parsing the stream body.

### Amendment to Story 12.6 (accepted by the maintainer, 2026-11-15)

Story 12.6's file must be read with this amendment; its D-j text is not
edited here.
- **12.6 Lot C** (admission in the engines, owner of the new
  `lorica-stream/src/refusal_log.rs` and of "the stream rows and the
  suppressed task") emits the limiter's output in the shape of D-c, not
  as a `warn` line: it adds to `ConnectionObserver`
  (`lorica-stream/src/handler.rs`, which joins its allowlist) the
  defaulted `refused(RefusalRecord)` and
  `refusals_suppressed(SuppressedRecord)` with the fields D-c lists,
  calls `refused` for each admitted refusal and `refusals_suppressed`
  where it would write "N refusals suppressed", and keeps the `warn` line
  at `debug`. Its test of "one log row and one suppressed row for 1,000
  refusals" asserts those two calls on a recording observer.
- If 12.6 Lot C has landed with the `warn` line before this story
  starts, this story's Lot A makes that change instead, and `handler.rs`
  and `refusal_log.rs` are already in its allowlist.
- In either case this story's Lot A owns the rest of D-c: the widened
  key `StreamLogKey` and the pre-forwarding ends passed through the
  limiter.

### Handed to other stories

- **12.10**: the Streams page links each stream to the log tab filtered
  on it and to its SLA; its live counters read `StreamMetricsCollector`'s
  aggregate through an API it defines; the `allowed_hostnames` rule for
  `streams:read` that D-j relies on.
- **12.11**: `drained_by_upgrade` rows need nothing new; the per-stream
  drain counts on `lorica_hot_upgrade_total` are its own.
- **12.12**: the L4 log and metrics rows of the parity matrix.
- **12.14**: once UDP backends have active checks, their flips raise
  `backend_down` with the `streams` detail like any backend.
- **12.15**: fills `detected_protocol` in the record; the column and the
  field already exist.

## Resolved (maintainer, 2026-11-15)

1. **Fleet fan-in of stream rows and stream SLA is kept** (D-i, Lot G):
   a stream is a full citizen, observed fleet-wide.
2. **UDP SLA is availability only** in 1.11.0 (D-g); `docs/streams.md`
   says so.
3. **No alert on a DNS resolution failure** (D-h); the series and the
   stream SLA cover it.
4. **The client certificate subject follows the HTTP access log**, which
   records none (verified in code, D-a): stream rows do not log it. The
   verification outcome stays, as 12.4 hands it over.
5. **Stream rows on automation and MCP need both `logs:read` and
   `streams:read`**, and a hostname-confined token receives none (D-j).
6. **Stream rows use the access log's syslog severity** (D-d); no new
   setting.
7. **The 12.6 conflict resolution is accepted** (D-c): refusal rows come
   from the limiter, with suppressed rows; Dev Notes record the
   amendment to 12.6 and the Lot that carries it.
8. **Stream SLA targets are replicated to followers** (raised by Lot B,
   2026-11-16), as route SLA targets are: a stream is a full citizen.
   `CanonicalConfig.stream_sla_configs` (serde default, format stays 3,
   shape digest moved) is cut per recipient with its stream, and the
   replica apply writes the targets of the streams the follower keeps.
9. **The stream SLA overview is a read of its own** (raised by Lot C3,
   2026-11-18), not a `streams` field: `GET /api/v1/sla/overview`
   answers a bare array of route rows and `/automation/v1/sla/overview`
   a page of them, so neither has an object to carry the field. `GET
   /api/v1/sla/streams` answers every stream this node holds with a
   stored target or recorded data, its windows, at the route overview's
   role (Viewer); `GET /automation/v1/sla/streams` under `sla:read` and
   the MCP read tool `lorica_sla_streams`, paged and capped like the
   route overview's; both OpenAPI documents.

## Dev Agent Record

### Debug Log

- Lot B, 2026-11-15/16, on `875b3d80`: paused once on 2026-11-15 with
  the settings fields written, resumed the next day. The open question
  it raised (stream SLA targets were not replicated, route ones are)
  was answered by the maintainer as Resolved 8.
- SQLite's scalar `MIN(a, b)` and `MAX(a, b)` answer NULL when either
  argument is NULL, so the stream bucket merge wraps each in
  `COALESCE(MIN(a, b), a, b)`; a sum is `COALESCE(a + b, a, b)`. A slice
  where nothing connected therefore leaves the other slice's latencies
  as they were (`stream_sla_slices_of_one_minute_add_up`).
- `apply_replica_streams` deletes every local stream, which cascades
  every local stream SLA target away; the target pass after it only
  inserts the blob's targets for the kept streams, with the blob's
  timestamps, so a follower re-encodes the control plane's bytes.
- Lot B gates, `rust:1-bookworm` with `CARGO_BUILD_WARNINGS=deny`, on
  each committed tree (the config half alone, then the whole Lot): the
  CI chain (`cargo fmt --check`, workspace clippy with `lorica/otel`,
  the three `cargo test` lines and the TLS-featured one) green, and
  `cargo audit` clean. Whole Lot: 3,552 product, 948 `lorica`, 910
  forked and 592 TLS-featured tests.
- Lot D, 2026-11-16, on `90ac7ba4`: the route `SlaCollector::record`
  replaced a route's bucket when the minute changed, before the 60 s
  flush task had taken it, so under steady traffic most completed route
  minutes were dropped unflushed. The stream collector does not copy
  that: it keys a minute by `(stream_id, minute start)` and a minute
  stays until a flush takes it
  (`the_current_minute_waits_and_a_past_one_survives_a_new_minute`).
- The route loss was then proven and fixed in the same cycle, at the
  maintainer's request (allowlist widened to `lorica-bench/**` and
  `CHANGELOG.md`): `a_finished_minute_reaches_the_store_when_the_next_one_starts_before_the_flush`
  failed on the old code (0 buckets flushed, the finished minute
  replaced) and passes once `SlaCollector` keys its buckets by
  `(route_id, minute start)`. The replacement dates from `288ff10e`, the
  commit that created `lorica-bench`; every tag from `v0.1.2` to
  `v1.10.6` contains it.
- Lot D gates, `rust:1-bookworm` with `CARGO_BUILD_WARNINGS=deny`: the
  CI chain (`cargo fmt --check`, workspace clippy with `lorica/otel`,
  the three `cargo test` lines and the TLS-featured one) green, and
  `cargo audit` clean. `lorica-bench`: 69 tests, 9 of them Lot D's.
- Lot C2, 2026-11-16, on `eb607591`: `lorica-api` already depends on
  `lorica-stream`, so the collector takes `CountersSnapshot` itself and
  the report's typed field (Lot E) only has to round-trip that type.
  No `Backend` or `StreamMatchRule` constructor exists; the collector
  tests build both from their serialised form with the required fields
  only, so a new defaulted field does not touch them.
- The existing counter delta machinery swallows a restarted worker's
  values until they climb past the old high-water mark unless `forget`
  ran first; the stream collector does not share that gap, since a drop
  of any series folds the old value into `retired`
  (`a_worker_restart_or_death_never_makes_a_counter_go_down`).
- Lot C2 gates, `rust:1-bookworm` with `CARGO_BUILD_WARNINGS=deny`, on
  each committed tree (the gauges alone, then the collector): the CI
  chain green and `cargo audit` clean. Whole Lot: 3,611 product, 948
  `lorica`, 910 forked and 592 TLS-featured tests. One run of the first
  tree failed three `lorica-stream` `tcp_engine` tests on a timeout
  (`Elapsed`), a crate this Lot does not touch; they passed twice in
  isolation and in the full rerun.
- Lot A, 2026-11-16, on `46d802c6`: the stream limiter lives in
  `lorica-stream/src/admission.rs` (`RefusalLog`, since 12.6 Lot C), not
  in `refusal_log.rs`, which holds only the generic `RefusalLogLimiter`;
  the widened key had to be built there. A suppressed pre-forwarding end
  needs no record kept back: the window's report is built from the
  stream id, name and protocol alone, as a refusal's is.
- Existing `tcp_engine` tests read three `proxy_header_invalid` records
  in one window from one stream; under D-c only the first is a record,
  so they now read the end from the counters
  (`a_trusted_peer_header_that_is_oversized_or_dgram_is_refused`,
  `an_untrusted_peer_header_forwards_nothing_and_ping_is_forwarded`).
- Lot A gates, `rust:1-bookworm` with `CARGO_BUILD_WARNINGS=deny`: the
  CI chain (`cargo fmt --check`, workspace clippy with `lorica/otel`,
  the three `cargo test` lines and the TLS-featured one) green, and
  `cargo audit` clean: 3,615 product, 955 `lorica`, 910 forked and 592
  TLS-featured tests.
- The `tcp_engine` timeouts of the Lot C2 gate, reproduced: copies of
  the test binary in parallel on one core (32 at a time, 24 test
  threads each) failed 191 of 192 runs; 16 at a time on two cores, 0 of
  80. Every failure was the tests' own assumption, none an engine
  defect: `refusing()` released the port it named, so another listener
  on the host (another test, another copy) took it and answered connects
  meant to be refused, and other copies' engines reached this one's
  listeners; the open-rate test assumed ten connects land within one
  second of burst and settled on the `active` gauge, which counts a
  connection being refused as admitted; wall-clock upper bounds on the
  idle, total, header and bandwidth timers measured the host; the
  bandwidth clocks started after the connect, so they read short. Fixed
  in the tests, separate commit: the port held bound and never
  listening, the open-rate bound read from the clock and settled on the
  backend's accepts, lower bounds only in the integration tests and
  three paused-clock forwarder tests for the windows, `WAIT` 60 s. Under
  the same 32-on-one-core contention: 0 failures in 800 runs.
- Not fixed, outside this Lot: the same contention at the moderate level
  (16 copies on two cores) fails `tests/runtime.rs`
  `one_receive_buffer_serves_a_64_port_range` in 49 of 80 runs (63 to
  66 datagrams where 64 are expected, so foreign datagrams arrive, the
  signature of the released-port pattern) and `tests/udp_engine.rs` in
  4 of 80 runs (late replies, a session counted twice);
  `tls_engine.rs` 0 of 80. Gate runs share the host's loopback with
  other agents' test binaries, so these can fail a gate the same way.
- Those two, fixed 2026-11-18 in the tests, separate commit. The cause
  of the foreign datagrams, proven by a probe: a UDP socket with
  `SO_REUSEPORT` bound to port 0 may be handed a port another
  `SO_REUSEPORT` socket of the same user holds (37 of 20,000 autobinds
  landed on one of 64 held ports; TCP, 0 of 20,000), and the kernel then
  splits the datagrams between the two. The tests bound their slots so.
  Production cannot: a stream's port is validated non-zero. Second cause:
  ports released while datagrams were still on their way (the ICMP
  tests send to a closed port on purpose, late answers reach an ended
  session's port) were autobound by another test's client or backend.
  Every UDP slot, backend and client of `runtime.rs` and `udp_engine.rs`
  now binds a port of `lorica/tests/common/mod.rs`'s reservation scheme
  (included by `#[path]`), the ICMP-after-answer test joins its backend
  task instead of sleeping 100 ms, the two open-rate tests bound the
  sessions served by the time measured, the least-sessions test keeps
  its first session open until a detach (a 1 s idle timeout ended it
  before the second picked its backend), and the hang bounds are 60 s.
  After: 0 failures in 400 runs at 16 copies on two cores and in 800 at
  32 on one core, for each of `runtime` and `udp_engine`.
- **Lot B.** Settings: `stream_access_log_retention` (default
  `GlobalSettings::DEFAULT_STREAM_ACCESS_LOG_RETENTION`, 100,000, `0`
  unlimited) replicated through `CanonicalGlobalSettings` with a serde
  default to the shipped value; `syslog_stream_enabled` and
  `otlp_logs_stream_enabled` (default `true`) node-local. All three are
  key/value rows, no migration; a stored retention that is not a number
  reads as `Corrupt`. No API validation or OpenAPI field yet: Lot C1.
- **Stream SLA storage.** Migration 79 creates `stream_sla_configs`
  (cascades from `streams`) and `stream_sla_buckets` (no foreign key,
  unique on `(stream_id, bucket_start, source)`). Store functions mirror
  the route ones: `get_`/`upsert_`/`list_stream_sla_config(s)`,
  `merge_stream_sla_bucket` (additive), `query_stream_sla_buckets`,
  `compute_stream_sla_summary`, `delete_stream_sla_buckets`,
  `export_stream_sla_data`. `prune_sla_buckets` now prunes both bucket
  tables, so the `sla_purge_*` settings cover stream history with no
  caller change. Constructors for Lot D: `StreamSlaConfig::default_for_stream`,
  `StreamSlaBucket::empty`, `StreamSlaConfig::connect_within_bound`.
- **Deviation, accepted by the maintainer:** `stream_sla_buckets` carries
  `connected_count`, beside the D-g columns. A judged connection that
  failed to connect has no connect latency, so the mean divides by what
  connected, not by what was judged; the latency columns are NULL where
  nothing connected (every UDP bucket).
- **Replication (Resolved 8).** `CanonicalConfig.stream_sla_configs`
  (serde default), cut with its stream in `restrict_for_recipient`,
  applied for the kept streams (`ReplicaOutcome.stream_sla_configs`).
  `CANONICAL_SHAPE_DIGEST` moved, `CANONICAL_FORMAT_VERSION` stays 3.
- **Alerts.** `AlertType::StreamBackendDown` (`stream_backend_down`) and
  `StreamUdpCeilingReached` (`stream_udp_ceiling_reached`), last in
  `ALL`; migration 80 subscribes every channel with an explicit list to
  both. Labels "Stream backend down" and "UDP session ceiling reached",
  tone problem, no recovery pair. Nothing raises them yet: Lot F.
- **Outside the allowlist, approved as for 12.2 Lot E1:**
  `lorica-api/src/vocabulary.rs` (exhaustive matches),
  the `alert_types` line of `lorica-api/openapi.yaml` (read by
  `lorica-notify`'s test), `adcs.generated.ts` (pinned by
  `adcs_vocabulary_fixture.rs`). Also `lorica-config/src/store/replica.rs`,
  which Resolved 8 needs.
- **Lot D.** `lorica_bench::StreamSlaCollector`
  (`lorica-bench/src/passive_sla/stream.rs`), one per process, and
  `StreamSlaOutcome`, the collector's own vocabulary so `lorica-bench`
  takes no dependency on `lorica-stream`. What Lot F calls:
  `record(stream_id, outcome)` from the observer's `connect_outcome`
  (in-memory map, brief lock, no store); `load_configs(store)` at start
  and on reload; `set_sla_config` and `clear_stream` from the SLA API
  (Lot C3); `start_flush_task(store, dispatcher)` with a dispatcher in
  the supervisor and the single process, `None` in a worker. `flush`
  and `check_thresholds` are public for a caller that drives them.
- **Definitions as implemented.** `TcpConnected { connect_latency_ms }`
  is judged, a success when `StreamSlaConfig::connect_within_bound`
  holds (inclusive), and is a latency sample either way;
  `TcpNotConnected` (`connect_failed`, `no_healthy_backend`) is a
  failure with no sample. On a UDP stream that expects responses (the
  engine's `Bounds::expects_responses`: `responses_per_request >= 1`
  and responses not unbounded), Lot F maps Lot A's `ConnectOutcome`
  onto `UdpAnswered` (success), `UdpIcmpError` and `UdpNoResponse`
  (failures). On one that expects none, Lot F ignores the
  `connect_outcome` and reports `UdpUnansweredEnded { icmp_error }` from
  `observe`, `icmp_error` being an end reason of `connect_failed`: a
  success unless `icmp_error` (the D-g amendment). Every variant is one
  judged connection, so each is reported once. No latency on UDP: the
  latency columns stay `None`.
- **Breach evaluation** mirrors the route one: every stream with a
  stored target, the last hour of `passive` buckets, an alert only on a
  state edge, a stream that judged nothing keeps its state. Details:
  `target = stream`, `stream_id`, `stream_name`, `sla_pct`,
  `target_pct` (the summary's, the bucket snapshot), `judged_count` in
  place of the route's `total_requests`. Each breach edge also counts
  in `lorica_stream_sla_breach_total{stream_id, threshold_kind}`
  (`lorica-bench/src/metrics.rs`), a sibling of the route family rather
  than a `stream_id` label on it, so no route series carries an empty
  `stream_id`. It lives in the supervisor or the single process, where
  the evaluation runs, and needs no per-worker aggregation. Lot F calls
  `lorica_bench::metrics::forget_stream_sla_breaches(stream_id)` on the
  table change that removes a stream, as D-e asks of every stream
  series.
- **D-g amended after Lot D** (maintainer): a UDP stream that owes no
  response was judged on ICMP failures only, so any window in which it
  judged something read 0 %. Its sessions are now judged at their end,
  a success unless an ICMP error ended them
  (`udp_without_expected_responses_is_a_success_at_its_end_unless_icmp_failed_it`).
- **Lot C2, gauges.** `lorica_metrics::AggregatedGauge` with
  `GaugeAggregation` (`Min`, `Max`, `Sum`): each process sets its own
  value (`set_local` / `clear_local`), a worker ships it with
  `snapshot_local` (zeros included) in the generic list, the supervisor
  records each report as the worker's whole state for that gauge
  (`apply_worker`) and renders the aggregate of its own value and every
  worker's. `forget_worker` drops a `Sum` worker's share at once; a
  `Min`/`Max` worker's last value stands until its replacement reports
  (`GaugeAggregation::outlives_its_worker`).
- **Deviation:** `PER_WORKER_GAUGES` is `&[&Lazy<AggregatedGauge>]`, not
  `&[(&str, GaugeAggregation)]`: the aggregation lives on the gauge, so
  no resolver keyed by name has to stay in step with the list.
  `apply_worker_generic_counters` and `forget_worker_generic_counters`
  drive every listed gauge, so the supervisor side needs no new call.
- **`lorica_log_sink_up{sink}`**, `Min`: `set_log_sink_up(sink, up)`
  and, beside it, `clear_log_sink_up(sink)` for a process whose
  configuration no longer sets the sink up (a reload). What Lot F adds
  to the worker report: `.chain(lorica_api::metrics::snapshot_per_worker_gauges())`
  beside `snapshot_per_worker_counters()`.
- **Lot C2, streams.** `lorica_api::stream_metrics::StreamMetricsCollector`,
  registered on the process registry by `stream_metrics()`. The family
  list is `StreamFamily::VARIANTS` (name, type, labels, help per
  variant); label words come from the keys of the snapshot maps, so from
  the enums. `CandidateSkip` and `Direction` are new enums for the two
  label sets that had no enum. The rule label is the rule's 0-based
  position in `match_rules`, read from the last table.
- **The report shape for Lot E** is `lorica_stream::CountersSnapshot`,
  unchanged: streams, links, backends and rules, every
  `StreamCountersSnapshot`, `LinkCountersSnapshot` (histogram included:
  cumulative `le` per bound of `CONNECT_LATENCY_BUCKETS_S`, `count`,
  `sum`), `BackendCountersSnapshot` and `RuleCountersSnapshot` field,
  keyed maps by their enum word. The supervisor decodes it back and calls
  `stream_metrics().apply_worker(worker_id, &snapshot)`.
- **What Lot F calls.** Supervisor: `apply_worker` per report;
  `retain(&table)` on every table change (it also feeds
  `lorica_stream_info`); `set_bind_states(states)` once;
  `set_node_gauges` with `NodeStreamGauges::udp(sessions, pending)` or
  `::tcp(pending)` per stream from the regions; `counter_total(StreamFamily::CeilingReached, &[id])`
  for the ceiling alert. A dead worker is already forgotten by
  `forget_worker_generic_counters`. Single process:
  `set_local_counters(counters)` and `retain(&table)`.
- **Not rendered:** `lorica_stream_backend_bytes_total`. `LinkStats` has
  no bytes until Lot A adds them; Lot A's change to `LinkCountersSnapshot`
  will not compile here until the family is added, which is the intent
  of the whole-struct destructuring.
- **Outside the allowlist:** `lorica-api/src/lib.rs`, one line
  (`pub mod stream_metrics;`), which the new module needs.
- **Lot A, the record.** `ConnectionRecord.protocol: StreamProtocol` and
  `ConnectionRecord.detected_protocol: Option<String>` (always `None`
  until 12.15). `TlsRecord.client_certificate` is now `None` on a stream
  that does not verify client certificates, where it read `Absent`: D-a
  wants the row's `client_cert` null there, and the record is the row's
  only source. `Absent` and `Verified` remain for a verifying stream; no
  subject is recorded.
- **Lot A, the observer.** `ConnectionObserver` keeps `refused` and
  `refusals_suppressed` (12.6 Lot C) and gains
  `connect_outcome(stream_id: &str, protocol: StreamProtocol, outcome: ConnectOutcome)`,
  defaulted to nothing. `ConnectOutcome` is `Connected { latency }` (TCP),
  `NotConnected` (the connect phase ended `connect_failed` or
  `no_healthy_backend`, either protocol), and `Answered`, `IcmpError`,
  `NoResponse` (UDP, exactly where the breaker outcome is reported). It
  is reported at most once per connection or session, before the record;
  a refusal, a pre-forwarding end, and a connect phase cut short by a
  drain or the total timeout report none. A UDP stream owing no response
  reports nothing at its idle end, so Lot F judges it from `observe`, as
  the D-g amendment says. Lot F's mapping onto Lot D's
  `StreamSlaOutcome`: `Connected` to `TcpConnected`, `NotConnected` to
  `TcpNotConnected` (a failure without a sample, on either protocol),
  the three UDP outcomes to their namesakes.
- **Lot A, `StreamLogKey`.** `Refused(StreamRefusal)` or
  `PreForwarding(StreamEndKind)`; `StreamLogKey::of(reason)` is an
  exhaustive match on `StreamEndReason`, so a new end reason does not
  compile until it is classed. Pre-forwarding: `clienthello_timeout`,
  `proxy_header_invalid`, `detection_timeout`; 12.4's invalid ClientHello
  end is `refused(invalid_clienthello)` and already a refusal. The
  limiter key is `(stream index, StreamLogKey)`. Both engines hand every
  finished record to `AdmissionControl::ended`: a refusal becomes a
  refusal row, a pre-forwarding end is observed only when the limiter
  admits it, any other end is observed unconditionally.
  `SuppressedRecord.refusal` became `SuppressedRecord.key`
  (`key.end_kind()`, `key.refusal()` give the row's two columns); the
  debug line is "stream log rows suppressed".
- **Lot A, per-backend bytes.** `LinkStats::add_upload` /
  `add_download` and `LinkCountersSnapshot.bytes_upload` /
  `bytes_download`, added per completed write as the stream's are: the
  TCP forwarder counts both through `Forwarder::counting_link`, a UDP
  session through `Session::counting_link` set before its held
  datagrams are sent. `lorica_stream_backend_bytes_total{stream_id,
  backend_id, direction}` is rendered by `StreamMetricsCollector` (the
  `BackendBytes` family; the whole-struct destructuring made it a
  compile error until then).
- **Deviation:** `Connected.latency` runs from the start of the connect
  phase, not from the accept as D-g words it. The pre-forwarding reads
  (PROXY header, ClientHello, a terminating handshake) are paced by the
  client and bounded by `clienthello_timeout_ms` (up to 60 s): counted
  in, a slow client or an mTLS prompt would breach a backend's 500 ms
  target. On a stream with no pre-forwarding read the two are the same.
  The row's `connect_ms` (accepted to connected) is unaffected. One line
  to change in `connect_and_forward` if the maintainer prefers the text.
- **For Lot F, a gap in D-g, not decided here:** a UDP session of a
  stream owing no response that ends `no_healthy_backend` is judged a
  success by `UdpUnansweredEnded { icmp_error: false }`. The engine
  reports `NotConnected` for it; Lot F can use it to judge a failure.
- **Outside the allowlist:** `lorica-stream/src/admission.rs` (the
  limiter, see the Debug Log), `lorica-stream/tests/tcp_engine.rs`,
  `udp_engine.rs`, `tls_engine.rs` (Lot A's tests, and the `Absent`
  assertion above), and `lorica-api/src/stream_metrics.rs` (the bytes
  family, as Lot C2 planned).
- Lot C1, 2026-11-16 to 2026-11-18, started on `13e35fe0`, paused once
  (PC shutdown), rebased onto Lot A (`be1800cf`) after its first commit.
  `lorica-api` already depends on `lorica-stream` (Lot C2's finding), so
  the record-to-row conversion is in `lorica-api/src/stream_logs.rs`, not
  in the binary as D-a planned: Lot F's `StreamLogObserver` calls
  `StreamLogEntry::from_connection`, `from_refusal` and
  `from_suppressed` and hands the row to `enqueue_stream` and
  `publish_stream`. The record types are spelled out once each, in
  `stream_logs::test_support`, so a field the records gain changes one
  constructor and no test.
- The writer waits on both queues from a current-thread runtime of its
  own thread (a blocking `recv` waits on one queue only); each round
  takes up to `BATCH_MAX` writes from each queue and `flush` barriers
  both. `StreamWrite::Row` and `SinkPayload::Stream` are boxed: clippy's
  `large_enum_variant` refused them unboxed.
- Lot C1 gates, `rust:1-bookworm` with `CARGO_BUILD_WARNINGS=deny`, on
  each committed tree: the CI chain green and `cargo audit` clean. Last
  tree: 3,645 product, 957 lorica, 910 forked and 592 TLS-featured tests.
- **Lot C1, the row.** Fields as D-a, words as strings so a row a later
  release wrote reads back after a rollback. Mapped from
  `ConnectionRecord`: `ended_at` (timestamp, RFC 3339 UTC with
  milliseconds, fixed width so the time filters compare as text),
  `stream_id`, `stream_name`, `protocol`, `local.port()` (listen_port),
  `client` (ip, port), `proxied_from`, `backend_id`, `backend_address`,
  `attempts`, both byte and datagram counts, `accepted_at` to `ended_at`
  (duration_ms) and to `connected_at` (connect_ms), `tls.mode` (`none`
  without TLS), `tls.server_name`, the ALPN (negotiated when terminating,
  first offered in passthrough), `tls.client_certificate` (outcome word,
  null when the stream does not verify), `detected_protocol`, the end
  kind and, for `refused`, the refusal. Not mapped: `bind_gen`, `peer`
  (beyond `proxied_from`), `tls.rule`, `tls.ech_offered`,
  `tls.upstream_tls`. `RefusalRecord`: `at`, stream, `protocol`,
  `listen_port`, `client`, `proxied_from`, `refusal`; `tls_mode` is empty
  (the record carries none). `SuppressedRecord`: `reported_at`, stream,
  `protocol`, `key.end_kind()` and `key.refusal()`, `suppressed`; no
  client, port 0.
- **Store and API.** `stream_access_logs` created whole in
  `LogStore::open`; `insert_stream_batch`, `query_stream_logs`,
  `export_stream_logs`, `clear_stream_logs`, `stream_log_count`,
  `enforce_stream_retention(max, drain_cursor)` (the HTTP span
  estimate; `undrained` for Lot G's cursor). `GET /api/v1/stream-logs`
  (`stream_id`, `end_reason`, `refusal_reason`, `client_ip`, `from`,
  `to`, `limit`, `after_id`, `before_id`; an unknown word or time is a
  400), `/export` (CSV with the HTTP formula guard, or JSON) and
  `DELETE` (audited `stream_logs.clear`, its own rate bucket), at the
  roles of their `/api/v1/logs` counterparts with no change to the
  authorize middleware (a test compares them). No log store: an empty
  page.
- **Sinks.** `SinkKind::Stream`, `SinkPayload::Stream`, `publish_stream`
  (no trace context), syslog at `syslog_severity_access`, MSGID
  `stream`. `register_lane` takes a `SinkKindToggles` (`ALL`, `only`).
  The syslog consumer connects at start, retries on its backoff timer
  without events and reads a TCP or TLS connection to see the collector
  close it; `lorica_log_sink_up{sink="syslog"}` is 0 from a lane's
  install until it connects, 0 for a configured sink whose consumer
  cannot start, cleared when no syslog is configured, and only the
  installed lane's consumer publishes it.
- **What Lot F wires:** the observer (rows to `enqueue_stream` and
  `publish_stream`), `enforce_stream_retention` in the retention loop
  beside `enforce_retention` (skipping `0`), the OTLP export-outcome
  wrapper and `set_log_sink_up("otlp", ..)`, and the reload carrying the
  two stream toggles (it already compares `LogSinksConfig`, which now
  holds them).
- **Outside the allowlist:** `lorica-api/src/logs.rs` (`csv_escape` and
  `EXPORT_MAX_ENTRIES` made `pub(crate)` for the stream export),
  `lorica/src/otel.rs` (the `register_lane` call, and the
  `SinkPayload::Stream` arm its exhaustive match needs: severity INFO,
  the row's timestamp, as D-d says) and `lorica/src/capture/sink.rs`
  (four `register_lane` calls in its tests).
- **Not done here:** `stream_access_log_retention` is not in the
  automation plane's admin settings allowlist
  (`lorica-automation-policy`), which `access_log_retention` is in.
- Lot C3 (part), 2026-11-18, on `0e93f5ca`. Built: the stream SLA
  management routes (`GET /api/v1/sla/streams/{id}`, `/buckets`, `GET`
  and `PUT /config`, `/export`, `DELETE /data`, at the route floors,
  audited `sla.config_update` and `sla.data_clear` with target type
  `stream`), the automation read `GET /automation/v1/sla/streams/{id}`
  (`sla:read`) and the MCP read tool `lorica_sla_stream`, in both
  OpenAPI documents. The alert labels were Lot B's (`vocabulary.rs`),
  checked here. Not built, and why:
  - **The overview `streams` array (D-g) is not buildable as written.**
    `GET /api/v1/sla/overview` answers `data` as a bare array of route
    summaries (the dashboard reads it as `SlaSummary[]`, the `?node=`
    pull fills it from `SlaPull`), and `/automation/v1/sla/overview`
    answers the paginated `{items, page}` envelope over the route rows.
    Neither has an object to put a `streams` key beside. Recommended
    instead (maintainer to decide): a sibling read, `GET
    /api/v1/sla/streams` (1h and 24h per stream) and its automation
    and MCP counterparts, which keeps each answer one shape.
  - **`/automation/v1/stream-logs` and `lorica_stream_logs` (D-j)** need
    `streams:read`, which Story 12.10 Lot B adds (12.10 Resolved 7 puts
    this Lot after it). Not started; the audit reason and the 403 and
    confinement tests go with them.
  - **No `?node=` on the stream SLA routes**: `SlaPull` cannot name a
    stream until Lot G, so a follower's figures cannot be read yet. Lot
    G's allowlist names `answer_sla_pull` only; the requesting side
    (the stream handlers here) needs it too.
- **`stream_access_log_retention` is still not in the admin settings
  allowlist** (the Lot C1 note above). Story 11.3 AC #3 requires every
  allowlisted key to be undoable on the dashboard's settings form, and
  `every_allowlisted_setting_is_a_field_the_dashboard_form_edits_and_the_document_carries`
  fails for a key no settings tab binds; the dashboard gains the stream
  retention field in Lot H. The entry (raise-only, `1..=RETENTION_TIER_CEILING_ROWS`,
  fleet, live), its `SettingsPatch` property, the `docs/mcp.md` row,
  the retention ceiling test and the "three retentions" wording of
  `openapi-automation.yaml` and `docs/mcp.md` belong with that field.
- `AppState.stream_sla_collector` (`Option<Arc<StreamSlaCollector>>`)
  is what the PUT and DELETE call `set_sla_config` and `clear_stream`
  on. It is `None` in `single.rs` and `supervisor.rs` until Lot F
  builds the collector and puts it there, as it does the route one.
- The route `update_sla_config` does not call `notify_config_changed`;
  the stream one mirrors it. Whether a replicated target change should
  wake the replication round was not examined here.
- `lorica_bench::results::SlaWindow::ALL` is the window list, read by
  `compute_all_windows` and the new `compute_all_stream_windows`, so
  the stream reads and their tests derive the windows rather than
  restating them.
- Lot C3 gates: see the Change Log row; `rust:1-bookworm` with
  `CARGO_BUILD_WARNINGS=deny`, the CI chain and `cargo audit`.
- **Outside the allowlist:** `lorica-bench/src/results.rs`
  (`SlaWindow::ALL`, `compute_all_stream_windows`),
  `lorica-api/src/automation/scope.rs` and `router.rs` (the path, its
  scope and its mount), `lorica-api/src/sla/stream_tests.rs` (new),
  `lorica-api/src/automation/test_support.rs` (the read fixture seeds a
  stream), `read/plane_tests.rs` and `mcp/plane_tests.rs` (the sweeps
  reach the stream read; the committed field names gain the stream
  summary's), `lorica-api/src/automation/tests.rs`
  (`no_automation_path_reaches_a_stream` becomes
  `no_automation_write_path_reaches_a_stream`: the SLA read names a
  stream and writes nothing), every `AppState` literal (the new field),
  `lorica-automation-policy/src/scope.rs` (the `sla:read` doc),
  `docs/automation.md` and `docs/mcp.md` (one line each).
- Lot C3 (the stream log), 2026-11-18, with Story 12.10 Lot B, which
  added `streams:read`. Built: `GET /automation/v1/stream-logs`, paged
  as `/automation/v1/logs` is (newest first, `before_id` the cursor the
  answer names, `offset` to `LOGS_QUERY_MAX_ROWS`), the filters and
  their validation `StreamLogsQuery`'s own, no match count
  (`LogStore::stream_log_rows`); the MCP tool `lorica_stream_logs`;
  both OpenAPI documents. Scopes: `streams:read` is the path's scope in
  the matrix and `scope::companion_scope` adds `logs:read`, read by the
  gate and by the audit refusal reason, so a token lacking either gets
  a 403 naming it and a row `automation.request.forbidden:<scope>`. No
  word enters `AUTOMATION_AUDIT_REASONS`: the reason is a scope
  spelling, published by derivation. A principal that
  `carries_grants()` (hostname-confined) gets an empty page, the store
  unread. Tests: `the_stream_log_names_the_scope_a_token_lacks_in_the_refusal_and_the_audit_row`,
  `the_layer_refuses_the_stream_log_to_a_token_missing_either_scope_naming_it`,
  `a_principal_carrying_grants_reads_an_empty_page_on_every_stream_read`,
  `the_stream_log_pages_newest_first_by_the_cursor_and_validates_its_filters`.
  Story 12.10's record has the design note. Still open in C3: the
  overview `streams` field (maintainer to decide, above).
- Lot C3 (the stream SLA overview, Resolved 9), 2026-11-18, with Story
  12.10 Lots C1 and C2, on `18c4cd64`. Built:
  `sla::local_stream_sla_overview(state, window)`, the sibling of
  `local_sla_overview`: every stream this node holds (store order) with
  a stored target (`list_stream_sla_configs`) or a passive bucket
  (`ConfigStore::list_stream_ids_with_sla_buckets`, new, one `SELECT
  DISTINCT` on `stream_sla_buckets`), one row per window of
  `STREAM_OVERVIEW_WINDOWS` (`SlaWindow::OneHour` and
  `TwentyFourHours` of `lorica-bench`, the route overview's pair), the
  rows before the window skipped uncomputed. `GET /api/v1/sla/streams`
  (`get_stream_sla_overview`, Viewer as the GET default, no `?node=`
  as for every stream SLA read), `GET /automation/v1/sla/streams`
  (`read::stream_sla_overview`, `sla:read`, `PageQuery` with one row
  past the window as the route overview), the MCP read tool
  `lorica_sla_streams`, both OpenAPI documents, one line of
  `docs/automation.md`. Decisions:
  - **Windows: 1h and 24h**, the two the route overview answers and the
    ones the C3 record recommended; `lorica_sla_stream` and
    `/sla/streams/{id}` keep every window for one stream.
  - **"With a target or data"**: a stream with neither is left out (its
    rows would read 0 % judged on nothing), and a bucket of a stream
    this node no longer holds is left out too, as the per-stream read
    answers 404 for it.
  - **Rows name the stream by id only**, as the per-stream read does,
    which is why `sla:read` alone reaches the list; listing ids it does
    reveal which streams carry SLA figures, the same disclosure the
    route overview makes of route ids.
  Tests: `the_stream_overview_lists_every_held_stream_with_a_target_or_data_and_no_other`
  (`sla/stream_tests.rs`, the expected rows derived from the store's
  order and `STREAM_OVERVIEW_WINDOWS`), the Viewer read added to
  `a_viewer_reads_a_stream_sla_and_changes_nothing`,
  `sla_read_alone_pages_the_stream_overview_by_id_and_the_window_is_its_slice`
  (`read/plane_tests.rs`), and
  `the_streams_with_sla_buckets_are_listed_per_source_held_or_not`
  (`lorica-config`). The read sweep and the MCP catalogue tests reach
  the new path and tool through `READ_SURFACE` and the catalogue.
  **Outside the 12.9 C3 allowlist:** `lorica-config/src/store/sla.rs`
  and `lorica-config/src/tests.rs` (the bucket id query),
  `automation/scope.rs` and `router.rs` (the path, its scope, its
  mount, `READ_SURFACE`), `sla/stream_tests.rs`,
  `read/plane_tests.rs`, `docs/automation.md`.

- Lot E, 2026-11-18, on `91c045d1`. `MetricsReport.stream_counters`
  (tag 16, `Option<Box<StreamCountersReport>>`) and its entries
  (`StreamCountersEntry`, `StreamLinkCountersEntry` with the histogram as
  `latency_le`, `latency_count`, `latency_sum_ns`,
  `StreamBackendCountersEntry`, `StreamRuleCountersEntry`), every keyed
  family a `btree_map<string, uint64>` keyed by the enum's word, so
  `lorica-command` takes no dependency on `lorica-stream`. Boxed:
  clippy's `large_enum_variant` refused the report in `Response`'s
  payload enum once it grew by four vectors. The conversion both ways
  is Lot F's (`lorica/src/stream_report.rs`), the one crate that sees
  both types. The gauges need no wire change: they ride the generic
  list (C2). `proto/command.proto` documents no `MetricsReport` and is
  left alone.
- Lot E gates, `rust:1-bookworm` with `CARGO_BUILD_WARNINGS=deny`: the
  CI chain green (3,665 product, 957 `lorica`, 915 forked, 592
  TLS-featured tests) and `cargo audit` clean.
- Lot F, 2026-11-18, on Lot E (`6062c8e8`). What each hand-off became:
  - **Observer (A, C1, D).** `lorica::stream_log::StreamLogObserver`
    replaces `LogObserver` (both `stream_engine.rs` construction sites
    are one function, `stream_engines`, which now takes it). Every
    record, admitted refusal and suppressed count becomes a row through
    `StreamLogEntry::from_*`, offered to `publish_stream` and to the
    process writer's `enqueue_stream` (the `LogStoreSlot`'s, so a store
    that opens late is written from then on). `connect_outcome` maps
    onto `StreamSlaOutcome` as Lot A proposed; a UDP stream owing no
    response is judged in `observe` from its end reason. The observer
    learns which streams owe none from the UDP engine's table: the
    engine is wrapped (`ObservedUdp`) so the observer is told every
    table the engine is. Lot A's gap, decided here: such a session that
    ends `no_healthy_backend` is a failure (`TcpNotConnected`, which
    Lot D documents as "connect_failed or no_healthy_backend").
  - **Report (E, C2).** `lorica::stream_report` converts
    `CountersSnapshot` to the wire type and back; a worker installs its
    engines' counters at start and `WorkerMetricsCtx::build_report`
    (both report paths) carries them, with
    `snapshot_per_worker_gauges()` chained beside the counters. The
    supervisor applies them with `apply_worker_report` at both report
    sites; `forget_worker_generic_counters` already forgets a dead
    worker's stream counters.
  - **Plane (C2).** `PlaneWatch` on `StreamPlaneHandle`: after every
    pass (before and after a commit, the retry tick, a health refresh)
    the table, read as the plane reads it, goes to
    `StreamMetricsCollector::retain` and the stream alerts, and the SLA
    breach series of a stream that left are dropped
    (`forget_stream_sla_breaches`); every caps tick (1 s) sets the
    node gauges (`NodeStreamGauges::udp`/`::tcp`) from the regions and
    checks each UDP stream's ceiling. `set_bind_states` once at start.
    Both modes: single-process also gets `set_local_counters`.
  - **SLA (D, C3).** `start_alerting_stack` builds the stream
    collector beside the route one, loads its targets, starts its flush
    task with the dispatcher (supervisor and single process) and puts
    it in `AppState.stream_sla_collector`. A worker builds its own,
    flushes with `None`. Every process registers its collector with
    `reload::register_stream_sla_collector`, and
    `apply_per_process_reload_state`, which every reload path of the
    three modes already runs, reloads its targets.
  - **Retention (C1).** `enforce_stream_retention` in the hourly loop
    beside the access-log pass, skipped at `0`, no drain cursor (Lot G).
  - **OTLP (C1, C2).** `ObservedLogExporter` wraps the SDK exporter:
    each export call's outcome sets `lorica_log_sink_up{sink="otlp"}`;
    a successful `init_logs` sets 1, a failed one 0, an unconfigured
    OTLP lane clears it. A generation counter keeps a replaced
    exporter's last batch from overwriting its successor's state.
  - **Alerts (A, B).** `lorica::stream_alerts::StreamAlerts`, one per
    node. `CircuitBreaker::record_failure` and the supervisor registry's
    `report` return whether they opened a closed circuit (a failed
    half-open probe is the same incident); the registry's
    `report_outcome` and, in single-process mode,
    `StreamBreakerGate::with_alerts` pass a stream's opening on. Held
    5 minutes per (stream, backend). `stream_udp_ceiling_reached`: the
    node's aggregated `counter_total(CeilingReached)` (supervisor) or
    the process's own counter (single process) growing while the
    stream is not at its ceiling; re-armed below
    `CEILING_REARM_PERCENT` of the region's session count; the detail
    `ceiling_bound_by` is the budget's `CeilingBound` at the last pass.
    `backend_down` gains `streams` (sorted names, 20 then `and N more`),
    only for a backend some stream links.
  - **Shutdown (D-k).** Single process: the drain, `stream_runtime.stop()`
    (joins the stream thread, so every drained record has been
    observed), then `flush_rows_at_exit` (the writer's barrier, 3 s at
    most), then `otel::shutdown` (sinks). Worker: the drain watcher's
    exit, then the same flush, then the sinks, in both exit paths.
- **Residual, outside this Lot's files:** the engines finish a
  connection's tracker entry before they hand its record to the
  observer (`tcp/engine.rs`, `udp/engine.rs`: `finish`, then
  `admission.ended`), so a worker's drain watcher polling the tracker
  can see it empty a few instructions before the last `observe` runs.
  The process test finds its `node_shutdown` row in both modes, but the
  window is not closed by construction; closing it means reporting the
  end before the entry leaves the tracker, a `lorica-stream` change.
- **Deviations.** Three new modules rather than one (`stream_log.rs`,
  `stream_report.rs`, `stream_alerts.rs`): the wire conversion and the
  alert state are not the observer's. `UdpSettings::expects_responses`
  (`lorica-config`) now holds the rule `Bounds::expects_responses`
  (`lorica-stream/src/udp/session.rs`) held privately, so the observer
  reads the same predicate the engine applies; `NodeCapsRegions::pending`
  (`lorica-stream/src/caps.rs`) sums the regions' pending counts as
  `sessions` sums their totals. `worker_rpc.rs` (the report builder) and
  `lorica/tests/stream_tls_wiring.rs` (the new `stream_engines`
  argument) are outside the allowlist and needed.
- **Tests.** `lorica/tests/stream_observability_process_test.rs`, both
  modes: a refused connection's row (`source_denied`, client, port), a
  burst of 20 more bounded to one `ended` row per refusing process plus
  `refusals_suppressed` counts adding up to 21, an idle-timeout row
  with every D-a field checked, a `config_removed` row after a stream
  `DELETE` through the API, `lorica_stream_ended_total`,
  `lorica_stream_refused_total` and `lorica_stream_bytes_total` above
  zero on `/api/v1/metrics` (worker mode: from the workers' reports),
  and a `node_shutdown` row in the store after `SIGTERM`. Unit tests:
  the report round trip with every enum word, two workers summing,
  the observer's verdicts, the breaker edge (`lb.rs`), the registry's
  alert once per incident and held (`supervisor.rs`), the backend hold
  and the ceiling alert once for two workers' edges
  (`stream_alerts.rs`), the OTLP wrapper's generations (`otel.rs`), the
  `streams` detail (`health.rs`), `NodeCapsRegions::pending`.
- Lot F gates, `rust:1-bookworm` with `CARGO_BUILD_WARNINGS=deny`: the
  CI chain green (3,665 product, 976 `lorica`, 915 forked, 592
  TLS-featured tests) and `cargo audit` clean.
- **Lot H (dashboard), 2026-11-18.** Logs page: an HTTP / Streams
  switch in the header; the stream table is `StreamLogView.svelte`
  (new), polling `GET /api/v1/stream-logs` every 5 s while the page's
  auto-refresh is on (no live tail exists for stream rows), with the
  filters of `StreamLogsQuery` (stream, end reason, refusal reason,
  client prefix, a time range sent as `from`, the page size), export
  through `/api/v1/stream-logs/export` with the same filters, and Clear
  for `canWrite` behind a confirmation. The HTTP live tail and poll
  stop while the stream table shows.
- **No reason vocabulary in the dashboard.** The two reason filters
  are text inputs whose suggestions are the words the rows on screen
  carry; a word not offered can be typed, and the server's 400, which
  names the words it accepts, is shown as it is. No end-reason or
  refusal list is copied into the frontend. Badge tone is structural:
  a row with a `refusal_reason` reads red, a `refusals_suppressed` row
  orange, every other end neutral.
- **SLA page:** a Streams section (`StreamSlaSection.svelte`, new)
  below the routes: one card per stream from the 24h row of
  `GET /api/v1/sla/streams`, names and protocols from
  `GET /api/v1/streams/status` (the overview rows carry only the id);
  the detail reads the four windows, the minute buckets and the target;
  latency columns and the latency bound are hidden on UDP and never
  sent there; Configure (target, and the bound on TCP), export CSV and
  JSON, and Clear for `canWrite`. No range is copied: the server's 400
  is shown in the dialog. On a control plane with a follower picked in
  the node filter the section is replaced by a sentence, since the
  stream reads have no `?node=` (Lot G).
- **Settings:** `stream_access_log_retention` in Global Configuration
  beside the two other retentions (its floor from `/settings/schema`),
  `syslog_stream_enabled` and `otlp_logs_stream_enabled` in Log Export.
  The retention field is now an editable binding of the settings tabs,
  which is what `every_allowlisted_setting_is_a_field_the_dashboard_form_edits_and_the_document_carries`
  reads: the automation allowlist entry (Lot C1's note) can be added.
- **Links (for Story 12.10 Lot D1):** `lib/stream-links.ts` builds and
  reads them: `#/logs?view=streams&stream=<id>` and
  `#/sla?stream=<id>`. `lib/router.ts` now splits the hash into a path
  and a query (`splitHash`, `currentQuery`), so the loader map and the
  sidebar key on the path alone. Outside the allowlist: `router.ts`,
  the two new components and their tests, `Logs.test.ts`,
  `Settings.svelte` (the form defaults), `GlobalConfigTab.svelte`
  (the retention field lives there, not in the sink tab), and the
  `StreamStatus` types and `getStreamStatus` in `api.ts`, which Story
  12.10 Lot D1 reuses.
- Lot H gates, `node:22` with `CI=true` and `pnpm install
  --frozen-lockfile`: `pnpm run check` 0 errors and 0 warnings, `pnpm
  run lint` clean, Vitest green (see the Change Log row).

## File List

- `lorica-config/src/models/settings.rs`
- `lorica-config/src/models/sla.rs`
- `lorica-config/src/models/mod.rs`
- `lorica-config/src/store/mod.rs` (migrations 79 and 80)
- `lorica-config/src/store/settings.rs`
- `lorica-config/src/store/sla.rs`
- `lorica-config/src/store/replica.rs`
- `lorica-config/src/canonical.rs`
- `lorica-config/src/tests.rs`
- `lorica-config/tests/config_db_upgrade.rs`
- `lorica-notify/src/events.rs`
- `lorica-notify/src/channels/slack.rs`
- `lorica-api/src/vocabulary.rs`
- `lorica-api/openapi.yaml` (the `alert_types` description line)
- `lorica-dashboard/frontend/src/lib/adcs.generated.ts`
- `lorica-bench/src/passive_sla/stream.rs` (new, Lot D)
- `lorica-bench/src/passive_sla/mod.rs`
- `lorica-bench/src/lib.rs`
- `lorica-bench/src/passive_sla/collector.rs`, `persistence.rs`,
  `tests.rs` (the route minute fix)
- `CHANGELOG.md` (the route minute fix, `[Unreleased]` Fixed)
- `lorica-bench/src/metrics.rs` (`lorica_stream_sla_breach_total`)
- `lorica-metrics/src/lib.rs` (Lot C2, `AggregatedGauge`)
- `lorica-api/src/metrics.rs` (Lot C2, `PER_WORKER_GAUGES`, `lorica_log_sink_up`)
- `lorica-api/src/stream_metrics.rs` (new, Lot C2)
- `lorica-api/src/lib.rs` (Lot C2, the module line)
- `lorica-stream/src/handler.rs`, `lib.rs`, `admission.rs`, `counters.rs`
  (Lot A)
- `lorica-stream/src/tcp/engine.rs`, `tcp/forward.rs`, `udp/engine.rs`,
  `udp/session.rs` (Lot A)
- `lorica-stream/tests/tcp_engine.rs`, `udp_engine.rs`, `tls_engine.rs`
  (Lot A)
- `lorica-api/src/stream_metrics.rs` (Lot A, `lorica_stream_backend_bytes_total`)
- `lorica-stream/tests/tcp_engine.rs`, `lorica-stream/src/tcp/forward.rs`
  (the load-proof tests)
- `lorica-api/src/stream_logs.rs` (new, Lot C1)
- `lorica-api/src/log_store.rs`, `log_writer.rs`, `logs.rs`, `lib.rs`,
  `server.rs`, `settings.rs`, `openapi.yaml` (Lot C1)
- `lorica-api/src/log_sinks/mod.rs`, `log_sinks/syslog.rs` (Lot C1)
- `lorica-api/tests/log_store_upgrade.rs` (Lot C1)
- `lorica/src/otel.rs`, `lorica/src/capture/sink.rs` (Lot C1,
  `register_lane`)
- `lorica-api/src/sla.rs`, `lorica-api/src/sla/stream_tests.rs` (new),
  `server.rs`, `openapi.yaml`, `openapi-automation.yaml` (Lot C3)
- `lorica-api/src/automation/read.rs`, `scope.rs`, `router.rs`,
  `tests.rs`, `test_support.rs`, `read/plane_tests.rs`,
  `mcp/plane_tests.rs` (Lot C3)
- `lorica-mcp/src/tools.rs` (Lot C3, `lorica_sla_stream`)
- `lorica-bench/src/results.rs` (Lot C3, `SlaWindow::ALL`)
- `lorica-automation-policy/src/scope.rs` (Lot C3, the `sla:read` doc)
- `lorica-api/src/acme/tests.rs`, `automation/audit.rs`,
  `automation_tokens/tests.rs`, `oidc_issuers/tests.rs`, `tests.rs`,
  `lorica/src/startup/single.rs`, `supervisor.rs` (Lot C3, the
  `AppState` field)
- `docs/automation.md`, `docs/mcp.md` (Lot C3)
- `lorica-api/src/automation/read.rs`, `scope.rs`, `router.rs`,
  `audit.rs`, `mod.rs`, `tests.rs`, `read/plane_tests.rs`,
  `lorica-api/src/stream_logs.rs`, `lorica-mcp/src/tools.rs`, both
  OpenAPI documents (Lot C3, the stream log, with Story 12.10 Lot B)
- `lorica-command/src/messages.rs`, `lorica-command/src/lib.rs` (Lot E)
- `lorica/src/stream_log.rs`, `stream_report.rs`, `stream_alerts.rs`
  (new), `lorica/src/lib.rs`, `stream_engine.rs`, `otel.rs`,
  `reload.rs`, `health.rs`, `proxy_wiring/lb.rs`,
  `proxy_wiring/worker_rpc.rs` (Lot F)
- `lorica/src/startup/mod.rs`, `single.rs`, `supervisor.rs`,
  `worker.rs`, `stream_plane.rs` (Lot F)
- `lorica/tests/stream_observability_process_test.rs` (new),
  `lorica/tests/stream_tls_wiring.rs` (Lot F)
- `lorica-config/src/models/stream.rs` (`UdpSettings::expects_responses`),
  `lorica-stream/src/udp/session.rs`, `lorica-stream/src/caps.rs`
  (`NodeCapsRegions::pending`) (Lot F)
- `lorica-api/src/sla.rs`, `sla/stream_tests.rs`, `server.rs`,
  `automation/read.rs`, `scope.rs`, `router.rs`, `read/plane_tests.rs`,
  both OpenAPI documents, `lorica-mcp/src/tools.rs`,
  `lorica-config/src/store/sla.rs`, `lorica-config/src/tests.rs`,
  `docs/automation.md` (Lot C3, the stream SLA overview, Resolved 9)

- `lorica-dashboard/frontend/src/lib/api.ts`, `lib/router.ts`,
  `lib/stream-links.ts` (new), `lib/stream-links.test.ts` (new),
  `routes/Logs.svelte`, `routes/Logs.test.ts` (new), `routes/Sla.svelte`,
  `routes/Settings.svelte`, `components/StreamLogView.svelte` (new),
  `components/StreamLogView.test.ts` (new),
  `components/StreamSlaSection.svelte` (new),
  `components/StreamSlaSection.test.ts` (new),
  `components/settings-tabs/GlobalConfigTab.svelte`, `GlobalConfigTab.test.ts`,
  `LogExportTab.svelte`, `LogExportTab.test.ts` (Lot H)

## Change Log

| Date | Version | Description | Author |
|---|---|---|---|
| 2026-11-15 | 0.1 | Draft: row shape and its own table, refusal and pre-forwarding rows through the 12.6 limiter, the stream sink kind, the Prometheus families with a typed report and a monotone collector, per-worker gauge aggregation with `Min` for `lorica_log_sink_up`, stream SLA tables and definitions, `stream_backend_down` and `stream_udp_ceiling_reached`, fleet fan-in, Lots A to J. | Romain G. |
| 2026-11-15 | 0.2 | Maintainer answers folded in as Resolved 1 to 7: fan-in kept, UDP SLA availability only, no DNS alert, no certificate subject (the HTTP access log records none, verified), stream rows on automation and MCP need `logs:read` and `streams:read`, access severity on syslog, the 12.6 amendment accepted and assigned to 12.6 Lot C (or this story's Lot A if C landed first). Status Draft. | Romain G. |
| 2026-11-16 | 0.3 | Lot B: the three settings, the stream SLA model and storage (migration 79, with `connected_count`), stream SLA targets replicated with their stream (Resolved 8), `stream_backend_down` and `stream_udp_ceiling_reached` with migration 80. Status InProgress. | Romain G. |
| 2026-11-16 | 0.4 | Lot D: `StreamSlaCollector` and `StreamSlaOutcome` in `lorica-bench`, minutes kept until flushed, the D-g judging rules, breach and recovery on `sla_breached` / `sla_recovered` with stream details. | Romain G. |
| 2026-11-16 | 0.5 | Route SLA minute loss proven and fixed (`SlaCollector` keeps a finished minute until flushed). D-g amended: a UDP session that expects no response is judged at its end, a success unless an ICMP error ended it. | Romain G. |
| 2026-11-16 | 0.6 | Lot C2: `AggregatedGauge` and `GaugeAggregation` in `lorica-metrics`, `PER_WORKER_GAUGES` and `lorica_log_sink_up{sink}` with `Min`; `StreamMetricsCollector` rendering the D-e families from `CountersSnapshot` with monotone retired totals, node gauges and table pruning. The per-link bytes family waits for Lot A. | Romain G. |
| 2026-11-16 | 0.7 | Lot A: `protocol` and `detected_protocol` on the record, `client_certificate` null on a stream that does not verify, `connect_outcome` and `ConnectOutcome`, `StreamLogKey` widening the limiter key with pre-forwarding ends passed through it, per-backend bytes and `lorica_stream_backend_bytes_total`. | Romain G. |
| 2026-11-16 | 0.8 | The `tcp_engine` timeouts traced to the tests (a released port answered by strangers, a burst assumed to fit one second, wall-clock upper bounds); fixed in the tests, 0 failures in 800 contended runs. | Romain G. |
| 2026-11-18 | 0.10 | Lot C3, in part: the stream SLA management routes, `GET /automation/v1/sla/streams/{id}` under `sla:read` and the MCP tool `lorica_sla_stream`, both OpenAPI documents. The overview `streams` field is not buildable as D-g words it (maintainer to decide); the stream-log reads wait for 12.10 Lot B. Gates on the final tree: the CI chain green (3,653 product, 957 `lorica`, 910 forked, 592 TLS-featured tests) and `cargo audit` clean after lettre 0.11.24. | Romain G. |
| 2026-11-18 | 0.11 | Lot C3, the stream log: `GET /automation/v1/stream-logs` behind `streams:read` and `logs:read`, empty for a hostname-confined token, the 403 and the audit row naming the scope missing, and the MCP tool `lorica_stream_logs`, both OpenAPI documents; shipped with Story 12.10 Lot B. The overview `streams` field stays open. | Romain G. |
| 2026-11-18 | 0.12 | Lot E: the worker metrics report carries the stream counters, typed, every keyed family by its enum's word. | Romain G. |
| 2026-11-18 | 0.13 | Lot F: the stream observer writes rows and judges the SLA, workers report their stream counters and gauges, the plane prunes and sets the node gauges, `stream_backend_down` and `stream_udp_ceiling_reached` raised, `backend_down` names its streams, OTLP export outcome in `lorica_log_sink_up`, stream retention, rows flushed before the sinks at a stop; process tests in both modes. | Romain G. |
| 2026-11-18 | 0.14 | Lot C3 closed: the overview `streams` field built as a read of its own (Resolved 9), `GET /api/v1/sla/streams` (Viewer), `GET /automation/v1/sla/streams` under `sla:read` and the MCP read tool `lorica_sla_streams`, the 1h and 24h windows of every held stream with a target or data, rows naming the stream by id, paged with the window pushed into the computation; both OpenAPI documents. Gates on the final tree: the CI chain green (3,687 product, 957 `lorica`, 915 forked, 592 TLS-featured tests), `cargo audit` clean. | Romain G. |
| 2026-11-18 | 0.9 | Lot C1: `stream_access_logs` with its own retention and writer queue, `StreamLogEntry` built from the stream records, `/api/v1/stream-logs` with export and clear, the three settings in the settings API, the `stream` sink kind, and a syslog up state that follows the collector without traffic. | Romain G. |
| 2026-11-18 | 0.15 | Lot H: the Logs page's HTTP / Streams switch with the stream table, its filters, export and clear; the SLA page's Streams section with windows, buckets, target editor, export and delete; the stream retention and the two stream sink toggles in the settings forms; `#/logs?view=streams&stream=<id>` and `#/sla?stream=<id>` links. Frontend gates green (check, lint, Vitest 904). | Romain G. |
