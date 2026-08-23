# Story 9.6: Telemetry Fan-In

**Epic:** 9 (v1.7.0)
**Status:** Draft
**Author:** Romain G.

**Depends on:** Stories 9.1, 9.2, 9.3.

## Story

As an on-call engineer,
I want every node's WAF events, health, bans and audit entries in one
place, filterable by node,
so that I stop opening three SSH tunnels to correlate one incident.

## Acceptance Criteria

1. Every node stamps a stable `node_id` and a display-only `node_name`
   on access-log rows, WAF events, SLA samples, probe results, bans and
   audit entries. Standalone nodes keep working with an empty node
   identity. `sla_buckets`' UNIQUE constraint gains `node_id`.
2. Fan-in lands in a separate `cluster-telemetry.db` with its own
   connection, never in the control plane's own log store.
3. Retention is a per-node quota, not a global row cap. Retention gains
   a chunked delete loop that releases the lock between chunks, and the
   WAF retention `COUNT(*)` is replaced by the `MIN(id)`/`MAX(id)`
   estimate already used on the access-log path.
4. A documented node-count and rps ceiling for access-log fan-in. Beyond
   it, the documented topology is WAF events, audit, health and bans
   fanned in, with access logs going to the Story 9.8 sinks.
5. A two-stage queue on the follower: the request path writes to a
   per-kind drop-oldest ring buffer via a non-blocking `try_send`, and a
   separate drain task is the only producer into the RPC queue. Overflow
   increments `lorica_cluster_telemetry_dropped_total{node_id, kind}`.
6. The sink execution model is named: whether fan-out happens on the
   existing non-tokio OS thread or on a parallel tokio task fed by a
   second queue.
7. The worker-mode path is named: the follower supervisor reads the
   shared log store rather than adding a per-request worker-to-supervisor
   RPC.
8. A per-node ingest quota on the control plane: rate and byte quotas
   with excess dropped and counted per node, plus a global storage
   watermark that sheds telemetry before it can affect configuration or
   audit writes.
9. `GET /api/v1/cluster/logs` and `GET /api/v1/cluster/waf-events` with
   `node`, `route`, `from`, `to` filters and cursor pagination, backed
   by a `(node_id, timestamp)` composite index and no per-page
   `COUNT(*)`.
10. Bans fan in for visibility and the control plane can issue a
    fleet-wide ban. Automatic per-node auto-ban stays local, and
    `docs/cluster.md` explains why.
11. New `docs/cluster.md` covering topology, the security model of the
    two listeners, enrollment, what replicates and what does not, the CA
    key trust model, blast radius, failure modes including break-glass,
    the access-log fan-in ceiling, a worked Prometheus federation config,
    and the standalone-to-cluster migration path.

## Tasks / Subtasks

- [ ] AC #1: six table migrations + `sla_buckets` UNIQUE change; hot-path
      row-growth measurement.
- [ ] AC #2: separate telemetry store and connection.
- [ ] AC #3: per-node quota, chunked deletes, MIN/MAX estimate.
- [ ] AC #4: measure the ceiling, document it.
- [ ] AC #5: ring buffer + drain task + drop counters.
- [ ] AC #6: decide and document the execution model.
- [ ] AC #7: supervisor-side reader over the shared store.
- [ ] AC #8: ingest quota + storage watermark.
- [ ] AC #9: endpoints, index, pagination without COUNT.
- [ ] AC #10: ban fan-in + fleet-wide ban push.
- [ ] AC #11: `docs/cluster.md`.

## Dev Notes

**AC #2 and #3 exist because SQLite is not a fleet log sink, and the
first draft pretended otherwise.**

`LogStore` is one connection behind one mutex (`lorica-api/src/log_store.rs:20`,
`conn: Mutex<Connection>`). Every insert, dashboard query, retention pass
and audit verify serialises on it; WAL mode (`:145`) buys nothing with a
single connection. Writes are batched off the hot path by one OS thread,
queue 8192, batch 256, ~300 bytes per entry
(`lorica-api/src/log_writer.rs:30-36`, `:100-139`).

Retention today is count-based, hourly and **global**:
`enforce_retention(access_log_retention)` and
`enforce_waf_retention(waf_event_retention)` from a 3600 s loop
(`lorica/src/startup/mod.rs:271`, `:288`, `:316`), defaults 100 000 rows
each (`lorica-config/src/models/settings.rs:468-475`). With five nodes
sharing one global cap, the fleet view is 20k rows deep per node,
**shallower than each node's own local log**, and a single noisy edge
evicts every quiet edge's rows. That is exactly the incident-correlation
case this story exists for.

Retention is also the contention hotspot. `enforce_waf_retention` opens
with a full `SELECT COUNT(*) FROM waf_events` (`log_store.rs:678-680`),
the pattern the access-log path deliberately avoided with the reason
written at `log_store.rs:437-444` ("could freeze the writer's
`Mutex<Connection>` for hundreds of milliseconds at millions of rows").
`enforce_retention` then issues a single `DELETE ... LIMIT` sized at an
hour of overflow (`:462-470`). `spawn_blocking` moves the wait off the
async executor but does **not** release the SQLite mutex, so the ingest
writer thread stalls and its 8192-slot queue fills, firing the drop
counter for a reason unrelated to the network.

Write amplification is exactly N: every request is written once on its
own node and once on the control plane, which also serves its own
traffic. A 3-node fleet at 2 000 rps is ~8 000 row-inserts/s through one
mutexed connection, above what `log_writer.rs:6-9` documents as SQLite's
ceiling even with 256-row batching, once retention deletes and dashboard
queries contend for the same lock. Hence AC #4: state the ceiling in the
product rather than discover it in production.

**AC #5: the first draft asserted a property the transport does not
have.** `RpcEndpoint`'s outbound queue is a bounded tokio `mpsc` whose
overflow semantics are *await*, not drop (`lorica-command/src/rpc.rs:67`,
`:297-322`). Any producer reaching `tx_out.send()` from a request-serving
task blocks when a stalled control plane fills the 256 slots, which
violates the epic's one hard invariant. `log_writer.rs:1-25` already
implements the correct bounded / `try_send` / drop /
`lorica_log_write_dropped_total{kind}` contract and is the model to copy.

**AC #6 is a real fork in the road, not documentation.**
`log_writer.rs:20-23` states the consumer is deliberately "a plain OS
thread, not a tokio task, so the writer behaves identically in
supervisor, worker, and single-process modes regardless of which runtime
(if any) is current at spawn time". A cluster fan-out and the Story 9.8
sinks both want async I/O. Decide before writing code.

**AC #7 was an unsolved design gap in the first draft.** Each worker
opens its own `LogStore` on the shared data dir
(`lorica/src/startup/worker.rs:720-721`) and the supervisor sets
`log_writer: None` (`supervisor.rs:977`), so the supervisor produces no
telemetry of its own. But the follower's single outbound cluster
connection lives in the supervisor. There is no path from N worker
processes to that connection. Adding a per-request worker-to-supervisor
RPC would run through a channel whose in-flight map is documented as
unsuitable for that volume (`rpc.rs:79-89`). Reading the shared store
from the supervisor is the cheaper answer; note that it makes AC #5's
ring buffer a supervisor-side construct on that path, not a per-request
one.

**AC #8: the follower-side bound protects the follower, not the control
plane.** Nothing today caps what the control plane accepts, so one
compromised node can stream fabricated rows at line rate, fill the disk,
and make SQLite fail writes for every other node and for the audit
chain. Day-based retention does not help within the day.

**AC #9**: the existing logs query computes
`SELECT COUNT(*) FROM access_logs {where}` on **every page**
(`log_store.rs:291`), and the existing indexes are timestamp / host /
status / host+timestamp (`log_store.rs:46-49`), none of which serve a
`node` filter. On an aggregated table that is a full scan per page under
the single mutex, i.e. the dashboard stalls the ingest writer.

**AC #1 hides a constraint violation.** `sla_buckets`
(`003_sla_metrics.sql:14`) and `probe_results` (`015_probe_results.sql:2`)
live in the **config** DB, not the log DB, with
`UNIQUE(route_id, bucket_start, source)` (`003_sla_metrics.sql:29`).
Fanning N nodes' buckets into one table violates it on every node past
the first. `purge_probe_results(1000)` (`startup/mod.rs:312`) also
becomes a global cap across the fleet with the same starvation problem
as retention.

**On metrics, do not add a `node` label to data-plane counters.** The
project's discipline is explicit (`lorica-api/src/metrics.rs:17-18`) and
every labelled counter carries a written bound; `PER_IP_CONNECTION_REFUSED_TOTAL`
is deliberately label-less (`:122`). The existing cross-worker
aggregation **collapses** the dimension rather than labelling it:
`lorica-metrics/src/lib.rs:302-410` applies per-worker deltas into a
single supervisor-side counter with no `worker` label, across the 13
counters listed at `lorica-api/src/metrics.rs:562-586`. Adding a `node`
label at fleet level is the inverse of the pattern the project chose for
the identical problem one level down, and the arithmetic is bad:
`lorica_ai_bot_total{crawler, route_id, action}` is ~268 x routes x 4
(`metrics.rs:90-94`), so ~21k series per node at 20 routes, ~214k on a
10-node fleet, before `lorica_geoip_block_total`. `/metrics` is also
pass-through by default (`server.rs:470-480`), which would put the whole
fleet's traffic profile on an unauthenticated endpoint. Only the
cluster-plane series carry `node_id`, bounded by fleet size; per-node
scrape or Prometheus federation is the documented topology, hence the
worked federation config in AC #11.

## Dev Agent Record

### Debug Log

(empty)

### Completion Notes

(empty)

## File List

Anticipated:

- `lorica-cluster/src/telemetry.rs` (ring buffer, drain, ingest quota)
- `lorica-api/src/cluster_telemetry_store.rs` (new, separate DB)
- `lorica-api/src/log_store.rs` (chunked retention, MIN/MAX estimate)
- `lorica-config/src/migrations/` (node identity columns, sla_buckets
  UNIQUE)
- `lorica-api/src/cluster.rs` (log + WAF event endpoints)
- `docs/cluster.md`

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-08-23 | 0.1 | Story drafted from the revised Epic 9 PRD. Separate telemetry store, per-node quotas and a documented fan-in ceiling replace the first draft's reuse of the single-node retention plumbing; fleet /metrics aggregation dropped in favour of federation. Status Draft. | Romain G. |
