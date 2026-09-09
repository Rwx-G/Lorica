# Story 9.6: Telemetry Fan-In

**Epic:** 9 (v1.7.0)
**Status:** Review
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

Reshaped by the Phase 1 review; see D2, D3, D4 and D5 for why three of
the original tasks are smaller than drafted and one is larger.

- [x] AC #1 + D2: `node_id` in the TELEMETRY schema only, stamped by
      the control plane from the session. No migration on
      `access_logs`, `waf_events`, `sla_buckets` or `probe_results`;
      the `UNIQUE(node_id, ...)` lands on the fan-in copy.
- [x] AC #2: `cluster-telemetry.db`, its own connection, migration 55.
- [x] AC #3 + D9: per-node quota, chunked deletes that release the
      lock, and `enforce_waf_retention`'s `COUNT(*)` replaced by the
      `MIN(id)`/`MAX(id)` estimate the access-log path already uses.
- [~] AC #4: the envelope and the beyond-it topology ARE stated in
      `docs/cluster.md`, but the figure is DERIVED from the documented
      SQLite write ceiling, not measured on hardware. The doc says so
      in those words rather than presenting a number that looks
      measured. Measuring it is backlog #64.
- [x] AC #5 + AC #7 + D5: supervisor-side drain task walking the
      shared store by rowid cursor. No new hot-path queue on the
      access-log and WAF paths.
- [x] AC #5 + D3: the ban snapshot, the one kind with
      no shared store behind it.
- [x] AC #6 + D6: tokio task, not the log-writer OS thread; recorded
      in the module doc.
- [x] AC #8 + D8: per-node rate and byte quota at ingest, plus the
      global storage watermark that sheds telemetry before
      configuration or audit writes.
- [x] AC #9: `/cluster/logs` and `/cluster/waf-events`, composite
      `(node_id, timestamp)` index, cursor pagination, no per-page
      `COUNT(*)`.
- [x] AC #10 + D3: ban snapshot fan-in and a fleet-wide ban push;
      automatic per-node auto-ban stays local, with the reason
      written down.
- [x] AC #11 + D1: EXTEND `docs/cluster.md` (fan-in ceiling, worked
      Prometheus federation config, standalone-to-cluster migration,
      ban rationale), replacing the Story 9.8 stub.
- [ ] D12: the `cluster` e2e profile, which covers Stories 9.2-9.6.
      Tracked apart from the code tasks so a partial outcome shows.
      NOT DONE: this is the one piece of the story that did not land,
      and it is inherited debt rather than new. Backlog #66.

Explicitly NOT in this story, with the reason recorded:

- Audit fan-in (D4): Story 9.9 AC #2/#3 own the separate insert path,
  the per-node seals and the partitioned verify.
- Flipping `metrics_require_auth` (D10): a release-level deliverable
  with a release-note obligation, done at the epic close.

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

- **Phase 1 decisions.** Every Dev Notes claim was re-verified against
  the current tree before any of this was decided; stories 9.1-9.5 and
  9.8 landed after this story was drafted, so every line number in the
  Dev Notes is stale even where the claim itself still holds. The
  substantive claims all survived: one mutexed `Connection`
  (`log_store.rs:19-21`), an OS-thread writer with
  `QUEUE_CAP = 8192` / `BATCH_MAX = 256` and a `try_send`/drop contract
  (`log_writer.rs:33,36,62-72`), an outbound RPC queue that awaits
  rather than drops (`rpc.rs:123,545-560`), global count-based
  retention at 100 000 rows (`settings.rs:541-547`), `COUNT(*)` on
  every logs page (`log_store.rs:291`), and no `node_id` on any
  non-cluster table.

  - **D1 - `docs/cluster.md` is EXTENDED, not created.** AC #11 says
    "New `docs/cluster.md`" and the File List repeats it. The file has
    existed since Story 9.3 and now carries eight major sections
    through Story 9.5. What AC #11 actually still owes: the access-log
    fan-in ceiling, a worked Prometheus federation config, the
    standalone-to-cluster migration path, and the ban rationale AC #10
    asks for. `## Node Identity in Telemetry` is a nine-line stub from
    Story 9.8 that this story replaces with the real treatment.

    Worth knowing before writing: `## Ports and Listeners` already
    states as settled doctrine that "telemetry (Story 9.6) rides its
    own connection". That was written ahead of the implementation, so
    it is a claim this story has to make true rather than a
    description of anything.

  - **D2 - `node_id` lives ONLY in the telemetry database, and the
    control plane stamps it from the SESSION.** This deviates from
    AC #1 as written, deliberately, on two grounds.

    First, cost. AC #1 asks for the column on access-log rows, WAF
    events, SLA samples, probe results, bans and audit entries, and
    names the per-row growth on the hot path as a known cost. But
    AC #2 puts fan-in in a separate `cluster-telemetry.db`. In a
    per-node database the node id is a CONSTANT: every row in that
    file came from that node. Paying per-row storage on the hot path
    to record a constant, on six tables, is waste. The node is
    identified once per batch on the wire instead.

    Second, and this is the one that settles it: a `node_id` written
    by the node is a node-supplied identity, and Story 9.5's D15 is
    the whole lesson about what that costs. The control plane stamps
    every fanned-in row with the `node_id` the mutual-TLS session
    already proves, and never reads an identity out of the payload.
    Taking the column from the sender would let a compromised
    follower file rows under another node's name, which is exactly
    the confusion an incident-correlation view must not have.

    So: zero migrations on `access_logs`, `waf_events`, `sla_buckets`
    and `probe_results`. The `UNIQUE(node_id, route_id, bucket_start,
    source)` AC #1 asks for is created in the TELEMETRY schema, where
    many nodes' buckets genuinely do coexist; the config database's
    `UNIQUE(route_id, bucket_start, source)`
    (`003_sla_metrics.sql:27`) is correct for a single node's own
    buckets and is left alone.

  - **D3 - there is no bans table, so there is no ban migration.**
    AC #1 counts bans among "six table migrations". Bans are an
    in-memory `DashMap<String, BanRecord>` (`lorica-api/src/ban.rs:33`)
    rebuilt from nothing on restart; only the auto-ban THRESHOLDS are
    persisted, as two columns on `routes`
    (`009_cache_and_protection.sql:6-7`). AC #10's "bans fan in for
    visibility" is therefore a periodic snapshot of live state, not a
    row stream off a table, and it is inherently lossy across a
    restart. That is acceptable for a visibility feature and is said
    out loud in the docs rather than papered over.

  - **D4 - audit fan-in belongs to Story 9.9 and is not built here.**
    AC #1 lists audit entries. Story 9.9 AC #2 and AC #3 specify the
    separate insert path that must not chain through `insert_audit`,
    the per-node `retention_seal:<node_id>` seals, and the partitioned
    verify. Building half of that here would either duplicate 9.9 or
    corrupt the control plane's own chain. 9.6 stops at the telemetry
    kinds it owns.

  - **D5 - the drain reads the shared store; there is NO new hot-path
    queue for access logs and WAF events.** This collapses AC #5,
    AC #6 and AC #7 into one design and is the decision the story
    turns on.

    AC #7 already requires the follower supervisor to read the shared
    log store rather than add a worker-to-supervisor RPC per request.
    Take that seriously and the rest follows: `access-log.db` IS the
    ring buffer. It is already written off the hot path by
    `log_writer`'s OS thread, already bounded by retention, already
    has a drop counter for overflow
    (`lorica_log_write_dropped_total{kind}`), and is already shared
    across worker processes under WAL
    (`worker.rs:723-728`). A second in-process ring buffer in front of
    it would duplicate a bound that exists, add a second drop
    counter for the same event, and still not solve worker mode.

    So the fan-in producer is a supervisor-side tokio task that walks
    the shared store by rowid cursor and ships batches. The request
    path is not touched at all, which satisfies the epic's one hard
    invariant by construction rather than by a bound that has to be
    argued about.

    AC #5's ring buffer is not discarded: it still applies to the
    kinds that are NOT already in a shared store, which after D3 and
    D4 is the ban snapshot. That path is low-volume and periodic.

  - **D6 - the execution model (AC #6) is a tokio task, and it has to
    be.** `log_writer`'s consumer is deliberately a plain OS thread so
    it behaves identically in all three process modes regardless of
    which runtime is current at spawn
    (`log_writer.rs:19-23`). Fan-out cannot live there: it sends on
    `RpcEndpoint`, which is tokio, and the supervisor's cluster
    connection is a tokio construct. Under D5 the question mostly
    dissolves, since the drain's input is a SQLite cursor rather than
    a channel from that thread, so nothing crosses the runtime
    boundary at all.

  - **D7 - the outbound queue must never be reached from a request
    task, and under D5 it cannot be.** `RpcEndpoint`'s outbound path
    tries `try_send` and then falls back to `send(frame).await`
    inside a `select!` that only adds a warning timer
    (`rpc.rs:545-560`): it awaits, it does not drop. The Dev Notes
    were right that asserting drop-oldest over it would be untrue.
    `ClusterConnection`'s own doc already states the rule consumers
    must follow ("treat that as control plane unreachable right now
    and not queue", `dialer.rs:359-360`). The drain task is the only
    producer, it holds a cursor rather than a backlog, and a
    disconnected control plane means it simply stops advancing.

  - **D8 - ingest is quotaed per node and shed globally, and the
    quota is enforced on the CONTROL PLANE.** Nothing today caps what
    a control plane accepts. The follower-side bound protects the
    follower. Per-node rate and byte quotas with excess dropped and
    counted, plus a storage watermark that sheds telemetry before it
    can affect configuration or audit writes, because those two are
    the writes that must never fail.

  - **D9 - retention is per node, and the WAF `COUNT(*)` is fixed on
    the way past.** `enforce_waf_retention` still opens with
    `SELECT COUNT(*) FROM waf_events` (`log_store.rs:676-691`) while
    the access-log path deliberately avoids exactly that with a
    `MIN(id)`/`MAX(id)` estimate and a comment explaining that a
    count "could freeze the writer's `Mutex<Connection>` for hundreds
    of milliseconds at millions of rows" (`:436-444`). The reasoning
    applies verbatim to the path that still does it.

    The contention argument has also got worse since the story was
    drafted, and the Dev Notes predate it: the same hourly loop
    iteration now additionally runs the expired-ACME-challenge purge
    (Story 9.5), audit-log retention, the probe-result purge and the
    daily SLA purge. Chunked deletes that release the lock between
    chunks matter more than the story assumed.

  - **D10 - `metrics_require_auth` has NOT been flipped, and it is not
    this story's to flip.** `settings.rs` documents the field as
    flipping "to `true` in v1.7.0 with a release-note migration
    paragraph", and the default is still `false` (`:696`), with
    `/metrics` pass-through (`server.rs:479-489`). Nothing in 9.1-9.5
    or 9.8 scheduled it. It is a release-level deliverable with a
    release-note obligation, not a telemetry change, so it is done at
    the epic close rather than buried here. Recorded so it is not
    dropped; AC #11's argument for federation over a fleet-wide
    `/metrics` does not depend on it either way, since the
    cardinality argument stands on its own.

  - **D11 - a correction to carry forward.** The Dev Notes state the
    cross-worker aggregation covers 13 counters. It covers 16: Story
    9.8 added `lorica_log_sink_dropped_total`,
    `lorica_log_sink_sent_total` and `lorica_log_sink_truncated_total`
    (`metrics.rs:1207-1214`). The argument the number supports (the
    project collapses the per-worker dimension rather than labelling
    it, so labelling `node` at fleet level would invert its own
    precedent) is unaffected and still correct.

  - **D13 (audit iteration 1) - two Critical findings, and both were
    the same class of mistake: a rule that was right somewhere else,
    copied to a place where its premise did not hold.**

    The per-node retention quota sized a node's overflow with
    `MAX(id) - MIN(id) + 1`, lifted from `log_store.rs`. That estimate
    is correct there, on a single-writer table where the only id gaps
    come from earlier deletes. On the fan-in table `id` is ONE
    autoincrement shared by every node, so a node's span is inflated
    by every interleaved row from every other node and the estimate
    overstates by roughly the fleet size. The quota therefore pruned
    nodes that were comfortably inside their allowance: the exact
    "a noisy edge evicts a quiet edge's rows" failure AC #3 exists to
    prevent, reintroduced by the mechanism meant to prevent it, and
    live in the only condition that matters, a fleet with more than
    one active node.

    It now seeks the exact cut through a new `(node_id, id)` index.
    The test that missed it wrote all of one node's rows before any of
    the other's, so ids never interleaved and the estimate happened to
    be right; there is now one that interleaves three nodes.

    The drain shipped one batch per tick, 512 rows per ten seconds,
    about 51 rows a second, against an envelope this story itself
    documented as a few hundred rps per node. A node above that could
    never catch up, and the backlog grew until local retention evicted
    rows the cursor had not reached, which is silent permanent loss
    rather than lag. Worth noting that the story wrote the ceiling and
    the drain cadence in separate commits and never multiplied them
    together; the arithmetic that exposes it takes one line.

    The remaining findings, all fixed: ban rows bypassed the ingest
    quota entirely (storage stayed bounded because snapshots replace,
    but the WORK did not); the storage watermark shed bans silently
    while a comment three lines below claimed bans are never shed; the
    drain called SQLite synchronously on the async executor for every
    cursor and row read, which is the discipline D5-D7 spend three
    decisions establishing; `BanPush.duration_s` was bounded at the
    API but not at the wire decode boundary where this crate bounds
    everything else; `IngestQuota::forget` existed, was tested, and
    was never called, leaking one entry per historical node id;
    AC #10's visibility half had storage, ingest and retention but no
    read path; `FleetAccessRow.status` truncated `u32` to `u16` on the
    round trip; and ingest compiled a fresh statement per row, up to
    1024 per batch, under the lock every other node waits on.

  - **D12 - the `cluster` e2e profile does not exist, and that is an
    epic-level debt this story inherits rather than creates.**
    `tests-e2e-docker/run.sh:51` lists fifteen profiles; none is
    `cluster`. The PRD designates one `cluster` profile to absorb
    transport, enrollment, configuration replication, certificate
    distribution and telemetry, and Story 9.5's record says plainly
    that it "ships on unit tests only". So the Integration
    Verification for 9.2 through 9.5 has never run. Building it once
    here covers five stories at once, which is the cheapest point to
    pay it. Tracked separately from the code tasks below so that a
    partial outcome is visible rather than hidden.

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
| 2026-09-09 | 1.0 | Implementation and audit iteration 1. Telemetry rides tags 40-41; the fan-in database, the per-node quota, the drain, the ingest path, both fleet query endpoints, the fleet-wide ban and the documentation all landed. Four auditors returned two Criticals, both cases of a rule that was right elsewhere being copied where its premise did not hold: the per-node retention estimate assumed a single-writer id space and so pruned nodes that were inside their quota, and the drain shipped one batch per tick, capping it at roughly a fifth of the throughput this story documented as supported. Both fixed, with the interleaving test that would have caught the first. Also fixed: bans bypassed the ingest quota, the watermark shed bans while a comment denied it, the drain blocked the async executor on SQLite, `duration_s` was unbounded at the wire, `IngestQuota::forget` was never called, AC #10 had no read path, and `status` truncated on the round trip. Three clippy gates and the full suite clean. The `cluster` e2e profile did NOT land (backlog #66) and the fan-in ceiling is derived rather than measured (backlog #64), so both are marked partial rather than done. Status Review. | Romain G. |
| 2026-09-09 | 0.2 | Phase 1 review: twelve decisions recorded, every Dev Notes claim re-verified against the current tree first (all substantive claims held; every line number was stale, and the cross-worker counter list is 16 not 13 since Story 9.8). Four AC corrections. AC #1's six migrations become zero on the hot-path tables: node_id belongs to the telemetry schema only and is stamped by the control plane from the mutual-TLS session, never taken from the payload (the Story 9.5 D15 lesson). AC #1 counts bans among the migrations, but bans have no table (in-memory DashMap), so AC #10 is a live-state snapshot. AC #1 counts audit entries, which are Story 9.9's. AC #11 says "new docs/cluster.md", which has existed since 9.3 and now has eight sections. The story's centre of gravity: AC #5, #6 and #7 collapse into one design where the shared access-log store IS the ring buffer and a supervisor-side tokio task drains it by rowid cursor, leaving the request path untouched. Also inherits the epic-level debt that the `cluster` e2e profile has never existed, so 9.2-9.5 Integration Verification has never run. Status InProgress. | Romain G. |
| 2026-08-23 | 0.1 | Story drafted from the revised Epic 9 PRD. Separate telemetry store, per-node quotas and a documented fan-in ceiling replace the first draft's reuse of the single-node retention plumbing; fleet /metrics aggregation dropped in favour of federation. Status Draft. | Romain G. |
