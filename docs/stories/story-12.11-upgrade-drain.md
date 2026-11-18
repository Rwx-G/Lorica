# Story 12.11: Upgrades and Reloads Drain Streams Cleanly

**Epic:** [Epic 12 - TCP and UDP Stream Proxying (v1.11.0 and v1.12.0)](../prd/epic-12-v1.11.0.md)
**Status:** InProgress
**Priority:** P0
**Author:** Romain G.
**Depends on:**
- Story 12.2 (InProgress): `worker_drain_timeout_s` (1 to 3,600 s,
  `GlobalSettings::WORKER_DRAIN_TIMEOUT_MAX_S`), the drain watcher and
  `stored_drain_timeout` of `lorica/src/startup/drain.rs`, the `quiesce`
  message of `lorica-worker/src/stream_ctl.rs`, the TCP stream listeners
  in the upgrade transfer table (`stream-tcp:`, D-j), adoption by the new
  supervisor (`StreamPlane::adopt_inherited`), the zombie-reaping
  `shutdown_all_with_timeout`, `node_shutdown` on the stop path.
- Story 12.3 (InProgress): the tracker closes a connection in any phase
  with the reason it is given (D-b), a close is `shutdown(Both)` then
  drop, so peers see a FIN.
- Story 12.4 (Draft): `Stream::drains_on_upgrade()` (D-j), true for
  every stream in 1.11.0.
- Story 12.5 (Lot F landed): UDP slot sockets per worker in a
  `SO_REUSEPORT` group, drain mode (D-m), the stream-caps regions, and
  its hand-off on what an upgrade does to UDP bindings.
- Story 12.9 (Draft): `StreamMetricsCollector` and the `stream_active`
  aggregate (D-e), the stream access-log rows that carry an end reason,
  the `stream_id` label convention.
- Story 12.10 (Draft): `GET /api/v1/streams/status` may serve the
  preview's per-stream figures (its "Handed to other stories").

**Blocks:** Story 12.12 (IV1 below is one of the named scenarios of its
L4 phase), Story 12.16 (a connection that does not transfer drains on the
path this story builds; the UDP socket handover of D-e is the affinity
foundation of its AC #5).

---

As an operator,
I want an upgrade to give my long-lived streams the time I choose and tell me what it closed,
so that an upgrade never cuts a database session at an arbitrary 30 s.

## Problem

Since Story 12.2 a stop drains for `worker_drain_timeout_s` and every
connection it closes says `node_shutdown`. A hot upgrade does not: the
old supervisor still drains for a hard-coded 30 s, its workers learn of
the upgrade only through a SIGTERM and close what is left with
`node_shutdown`, the UDP groups of both generations merge in the kernel
and reshuffle every client, the fd transfer that carries the stream
listeners breaks past 32 sockets, and the counters that describe the
drain die with the process that recorded them. Nothing tells an
operator, before the upgrade, which streams hold connections and how
long they will get.

## Acceptance Criteria

These are the PRD's, AC #2 as amended on 2026-11-15 (Resolved 1). They
are the contract.

1. **Hot upgrade uses `worker_drain_timeout_s`** (Story 12.2 AC #7) for HTTP and streams, replacing the hard-coded 30 s in `drain_for_handoff`. `docs/hot-upgrade.md` and `docs/installation.md` describe the setting as it now exists.
2. **Every connection an upgrade closes** ends with `drained_by_upgrade`, distinct from every other end reason, and a dedicated counter, `lorica_hot_upgrade_stream_connections_total{stream_id,outcome}`, counts per stream the connections an upgrade drained and those that finished on their own, beside the unchanged `lorica_hot_upgrade_total`.
3. **Preview before upgrade**: per stream, the number of established connections and the drain delay that will apply.

## Integration Verification

- IV1: With `worker_drain_timeout_s` set to 120 s, an SSH session through a stream survives a hot upgrade for up to 120 s after the upgrade starts and then ends with `drained_by_upgrade` in the log.

## What the code does today

Read on `feat/v1.11.0` at `a0a12d01`. Function names, not line numbers.
Read, not run, unless said otherwise.

- **The 30 s is still there.** `WorkerManager::drain_for_handoff`
  (`lorica-worker/src/manager.rs`) is
  `self.shutdown_all_with_timeout(Duration::from_secs(30))`. The
  supervisor's `HandoffDecision::Drain` arm (`lorica/src/startup/supervisor.rs`)
  calls it after shutting the cluster planes and the worker monitor down.
  It sends no `quiesce`: each worker learns of the upgrade from SIGTERM,
  Pingora's `GracefulTerminate` phase arms the drain watcher through
  `StreamRuntimeHandle::terminate(fallback_drain())`, which drains with
  the stored setting and `node_shutdown`. With a setting above 30 s the
  watcher would wait longer than the supervisor, which SIGKILLs at 30 s:
  connections die without an end reason.
- **`quiesce` has one reason.** `QuiesceReason` has only `Shutdown`; the
  runtime's `quiesce` ignores the reason and drains with
  `StreamEndReason::NodeShutdown`, and `DrainProbe::close_remaining`
  hard-codes `node_shutdown` at the deadline. The `quiesced()` watch
  carries the drain duration only.
- **`drained_by_upgrade` exists and is never written.** It is in the
  closed set of 12.1 AC #8 (`StreamEndReason::DrainedByUpgrade`); no code
  path produces it.
- **TCP stream listeners cross the upgrade** (12.2 D-j) under
  `stream-tcp:<stream_id>:<bind_gen>:<addr>`; UDP slot sockets do not:
  the new generation binds its own group, which joins the old one.
- **The fd transfer is one message with fixed buffers.**
  `Fds::send_to_sock` and `get_fds_from`
  (`lorica-core/src/server/transfer_fd/mod.rs`, called from
  `serve_listener_fds_blocking` and `pull_inherited_listeners`) send the
  whole table in one `sendmsg`: keys space-joined into a 2,048-byte
  buffer (`serialize_vec_string`, whose `Write` on a slice truncates
  silently, under a `TODO: check the buf is large enough`), and a
  receive control buffer sized for `MAX_FDS = 32` descriptors. A TCP
  stream on a 40-port range, or about 25 stream listeners with UUID keys,
  overflows one or the other: the keys arrive truncated or the extra
  descriptors are dropped by the kernel (`MSG_CTRUNC`), and
  `Fds::deserialize` asserts that the counts match. Verified by reading,
  not by a run; Lot A pins it with a failing test first.
- **The drain metrics die with the old process.** `drain_timeout` and
  `lorica_hot_upgrade_drain_seconds` are recorded by the old supervisor
  right before `std::process::exit(0)`. Only `completed` is recorded in
  the new process (the comment there says why: "the old's dies on
  exit"). During the drain, scrapes land on either process, since both
  accept on the shared management socket.
- **The old supervisor keeps serving its management API for the whole
  drain.** `api_handle.abort()` runs after `drain_for_handoff`, and the
  management listener is shared with the new supervisor, so a request
  reaches the old binary with even odds until the drain ends. With 30 s
  this was a nuisance; with a drain of up to an hour it is a second
  control plane on an outgoing binary.
- **`drain_timeout` no longer means what its doc says.** Its doc in
  `lorica-api/src/metrics.rs` explains that idle upstream keepalives make
  the drain reach the window routinely. Since Story 12.2 the watcher ends
  a worker as soon as no request and no stream connection is in flight,
  so a worker reaches the deadline only when traffic was still open.
  `lorica_hot_upgrade_drain_seconds` buckets stop at 60 s.
- **No preview exists.** The dashboard's `BinaryUpgradeTab.svelte`
  confirm dialog says "In-flight traffic drains over up to 30 seconds";
  `lorica upgrade` (`lorica/src/main.rs`) uploads with no preview;
  `docs/hot-upgrade.md` already names `worker_drain_timeout_s` as if it
  applied to upgrades.
- **The worker count is equal on both sides by construction:**
  `hot_upgrade_argv` passes the resolved count, never `auto`.

## Decisions taken in this story

### D-a. What "upgrade" and "reload" cover, and which path writes which reason

| Event | Path | End reason of a closed stream connection |
|---|---|---|
| Hot upgrade, handoff succeeded | supervisor `Drain` arm, `quiesce reason=upgrade` | `drained_by_upgrade` |
| Hot upgrade rolled back | none: nothing drains, the old generation never stopped | none |
| Stop (`systemctl stop`, SIGTERM, single-process shutdown) | 12.2 D-f, `quiesce reason=shutdown` | `node_shutdown` |
| `systemctl restart` | a stop then a start | `node_shutdown` |
| Configuration change, stream or backend removed | 12.2 AC #8, `detach` or `refresh` | `config_removed` |
| A worker SIGTERMed without a `quiesce` | `terminate(fallback)` | `node_shutdown` |

"Reload" in the title means a hot upgrade: Lorica has no `ExecReload`,
and configuration reloads are Story 12.2 AC #8. The last row is a
degraded path (a `quiesce` that did not reach a worker); it is logged
with the worker id and stays `node_shutdown`, because the worker cannot
tell an upgrade from a stop without the message.

The reason travels with the message: `QuiesceReason` gains `Upgrade`
(`reason=upgrade`); the runtime's `quiesce` takes the reason and maps it
(`Shutdown` to `node_shutdown`, `Upgrade` to `drained_by_upgrade`); the
`quiesced()` watch carries `(Duration, QuiesceReason)` (as built: a
`Quiesced { drain, reason }` struct, and `lorica_stream::quiesce_end_reason`
is the one mapping), and the watcher's
deadline close uses that reason instead of the hard-coded one. A
connection already draining for another reason (`config_removed`) keeps
it, as 12.2 D-g already does. A connection that ends on its own during
the drain keeps its natural reason. Only the first quiesce counts: a
later `quiesce` is acknowledged with a count of 0 and `terminate` is
ignored, so the SIGTERM that follows an upgrade quiesce changes neither
the reason nor the deadline (amended in Lot B1).

### D-b. The drain delay, and the old supervisor's sequence

At the `Drain` decision, in this order:

1. Shut the cluster planes down, set `shutting_down`, abort the monitor
   (as today).
2. **Stop serving the management and automation APIs** (abort their
   servers) and begin `lorica_api::shutdown` for the periodic
   control-plane tasks. The new supervisor holds its own copies of those
   listening sockets, so no request is refused; every request now reaches
   the new binary. Tasks the draining workers still need stay up; Lot C
   lists them from the code (the candidates are the metrics pull and any
   log or telemetry fan-in from workers) and says which.
3. `D = stored_drain_timeout(store)`, read once here: the drain an
   operator previewed is the one applied, unless the setting changed in
   between, which the preview says.
4. `StreamPlane::quiesce_for_upgrade(D)`: `quiesce reason=upgrade
   drain_ms=D` to every worker. No `stream.release` audit row: the ports
   do not close, the new generation holds them. The plane takes no
   binding afterwards (as for a stop).
5. `drain_for_handoff(D + WORKER_KILL_MARGIN)`: SIGTERM (Pingora stops
   HTTP accept, the watcher is already armed by step 4 so `terminate` is
   a no-op), then wait, reaping, SIGKILL past the bound. The watcher ends
   each worker as soon as it has no request and no stream connection in
   flight, or at `D`.
6. Collect the workers' drain reports (D-g), write the generation's
   drain report for the new supervisor (D-g), `drain_for_exit`, exit 0.

`drain_for_handoff` takes the duration as a parameter; no constant
remains. No `EXTEND_TIMEOUT_USEC` on this path (12.2 D-f: the old
supervisor is no longer the unit's main PID once it has acked).

HTTP gets the same `D`: a request still in flight at the deadline is cut
when the worker exits. HTTP has no end-reason column and gets no new
field: the worker's drain report counts those requests, the generation
report carries the sum, and the new supervisor's summary log line states
it (Resolved 2).

### D-c. TCP streams across an upgrade: no connection served by both

- The listening socket is one kernel object held by both generations
  (12.2 D-j). The kernel hands each connection to exactly one `accept`,
  so a connection belongs to the generation that accepted it, for life.
- On `quiesce reason=upgrade` an old worker stops its accept loops and
  closes its own descriptor of each listener with `close`, never
  `shutdown`: a `shutdown` on a listening socket acts on the socket, and
  would stop the new generation's accepts too. The port stays open
  through the new generation's descriptors.
- Between the new generation's attach and the old one's `quiesce` (the
  readiness handshake, typically under a second) both accept from the
  same queue. A connection the old one accepts in that window drains
  like the others.
- Every established connection is marked draining with
  `drained_by_upgrade` and `deadline = now + D`, in any phase (12.3 D-b):
  forwarding, connecting, or a pending PROXY header, ClientHello or
  detection read. TLS-terminating and TLS-originating streams drain the
  same way (D8). *Amended in Lot B1:* `drains_on_upgrade()` is not true
  for every stream: since Story 12.4 it is true only for a stream that
  terminates or originates TLS, the streams live transfer (12.16) will
  never move. In 1.11.0 every stream drains whatever it says, so the
  engine reads `Stream::upgrade_policy()` (`drain` for every TCP stream),
  and the preview shows `drains_on_upgrade` beside it as the 12.16
  exclusion.

### D-d. The fd transfer becomes chunked, and stays compatible

The table moves to a Lorica-owned transfer in
`lorica/src/startup/fd_transfer.rs` (new); the fork's `transfer_fd` is
not changed, so `FORK.md` gets no entry.

- **Framing.** Over the same `SOCK_STREAM` unix socket at
  `transfer.sock`, the sender writes a header message carrying a format
  token (`lorica-fds/2`) and the entry count, then chunks of at most 32
  descriptors whose keys fit an 8 KiB payload, each acknowledged by the
  receiver with one byte before the next is sent (stop-and-wait: unix
  stream sockets do not frame `SCM_RIGHTS`, and an acknowledged chunk
  cannot merge with the next one).
- **Compatibility, both ways.** The receiver reads the first message:
  if it starts with the format token it loops; otherwise it is the
  legacy single message and is parsed as today. The sender uses the
  legacy single message whenever the table fits it (at most 32
  descriptors and keys within 2,048 bytes), so a node without streams
  still hot-downgrades to a 1.10.x binary. A table that does not fit is
  sent chunked; a 1.10.x receiver then fails, the new process never
  signals ready, and the upgrade rolls back (`exec_failed`), which is
  the safe failure. The docs say so.
- **The receiver closes on error.** Any framing error, a short chunk or
  a count mismatch closes every descriptor received so far and fails the
  pull; the new supervisor exits and the old one rolls back.

### D-e. UDP across an upgrade: the group is handed over, not merged

12.5's recommendation is **not taken as written** (Resolved 5); the
reasons first.

Without a handover, the new generation's group joins the old one, the
group doubles, and reuseport selection (a hash of the 4-tuple scaled to
the group size) remaps nearly every client (12.2 Dev Notes). In drain
mode an old socket drops every new client hashed to it
(`binding_draining`), which is 12.5's concern; but the remap also sends
most established sessions' next datagrams to another socket, often in
the new generation, which opens a second backend session for the same
client. Drain mode therefore keeps no continuity for unbounded streams
either, and it serves one client flow from two generations, which D5
forbids. Closing the slot sockets at once for bounded streams, as 12.5
proposed, avoids the drops but resizes the group a second time.

**Decision.** UDP slot sockets ride the transfer table under
`stream-udp:<stream_id>:<bind_gen>:<slot>:<addr>`, slot `k` being worker
`k`'s socket. The new supervisor adopts a group only when its slot count
equals its worker count (guaranteed by `hot_upgrade_argv`; a mismatch at
this boundary between two binaries is logged, the inherited sockets are
closed and a fresh group is bound) and attaches slot `k` to its worker
`k`. The group size never changes, no client is remapped, no datagram
meets an unbound port, and a client's datagrams keep reaching the same
slot across the upgrade, which Story 12.16 AC #5 builds on.

On `quiesce reason=upgrade` an old worker's UDP binding:

- **stops reading** its slot sockets (the new generation reads them now)
  but keeps them open, so a session can still send its responses from
  the address and port the client wrote to;
- **unbounded responses** (`unbounded_responses`): ends every session at
  once with `drained_by_upgrade`. There is no request and response
  pairing to finish, and a session kept open would answer a client whose
  new datagrams now open a session in the new generation: one flow, two
  generations.
- **bounded responses**: a session keeps its upstream socket only to
  relay responses already owed. It ends at its request or response bound
  with its natural reason (it was complete), otherwise at the earlier of
  its idle timeout and `D`, with `drained_by_upgrade`. The idle timer is
  what measures "nothing more is owed"; ending it as `idle_timeout` would
  hide that the upgrade starved it of requests.

*Amended in Lot B1:* the split is on `UdpSettings::expects_responses()`
rather than `unbounded_responses` alone. A one-way stream
(`responses_per_request = 0`, syslog) is owed nothing either, so it
closes at once like an unbounded one; `Stream::upgrade_policy()` is
`relay_in_flight` only when responses are bounded and at least one per
request. "Stops reading but keeps them open" is built as: the receive
loops stop and drop their handle, and each live session keeps its own
handle on its slot socket until it ends, so the old worker's last
descriptor closes with its last session.

The invariant for UDP is per exchange: each client datagram is read by
exactly one generation and its responses come back through that
generation. In the attach-to-`quiesce` window both generations read the
group; a datagram the old one reads is answered by the old one, which
the invariant allows. During the overlap each generation counts in its
own caps region, as 12.5 D-d already documents.

### D-f. The preview (AC #3)

- **API:** `GET /api/v1/system/upgrade/preview` on the management API,
  behind the same role check as `POST /api/v1/system/upgrade`. Never on
  the automation API or MCP (D9: upgrades are management-plane only).
  Response:
  - `drain_timeout_s`: the stored setting, the delay that will apply;
  - `handoff_available`: false in single-process mode (no supervisor to
    fork a replacement; the upload then stages only, as today);
  - `previous_generation`: `null`, or `{ pid }` while an earlier
    generation of this node is still draining (D-h);
  - `streams`: one entry per stream bound on this node, `{ stream_id,
    name, protocol, established, on_upgrade, drains_on_upgrade }`, where
    `on_upgrade` is `drain` (TCP), `relay_in_flight` (UDP, bounded) or
    `close` (UDP, unbounded or one-way, D-e as amended), derived by one function
    `Stream::upgrade_policy()` beside `drains_on_upgrade()` so the
    preview, the engine and the docs cannot disagree;
  - `as_of`: when the figures were read.
- **`established`** is 12.9's `stream_active` aggregate (TCP: sum over
  workers; UDP: the region's per-node total). The handler triggers the
  same bounded refresh `/metrics` uses (`MetricsRefresher`) before
  reading, so the figure is as of the request, not of the last pull. If
  12.10's `GET /api/v1/streams/status` is in place when Lot D starts and
  serves the same figure, the handler reads it there instead of building
  a second join.
- **Per node.** An upgrade is node-local, so is its preview: the node
  whose API is called.
- **Dashboard:** `BinaryUpgradeTab.svelte` loads the preview when the
  confirm dialog opens and shows the drain delay from the setting (the
  "up to 30 seconds" text goes), a table of streams with established
  connections and what happens to them, and a warning line when
  `previous_generation` is set.
- **CLI:** `lorica upgrade` prints the preview to stderr before it
  uploads, without prompting (scripts are unchanged), and gains
  `--preview`, which prints it and exits without uploading.

### D-g. Drain reports, and how the counts reach a live `/metrics`

**Worker to supervisor.** At the end of an upgrade drain, before it
exits, a worker's watcher sends its report on the stream control
channel: `drained <entry>...` messages packed to the payload buffer,
each entry `<closed>:<finished>:<stream_id>` (the id last, since an id
is an unvalidated string), then `drained_end <end> http_cut=<n>
entries=<n>`, `end` being `idle` or `deadline`. `closed` counts the
stream's connections and sessions that ended with `drained_by_upgrade`,
`finished` those marked draining for the upgrade that ended on their
own. The tracker counts both per stream from the `quiesce` on. Sends
use `MSG_DONTWAIT`: a worker never blocks on its report; a send that
would block ends it, and the end marker says `truncated`. The supervisor
reads these messages from each worker's control socket after the worker
has exited (data queued in the supervisor's end survives the peer's
close); a worker with no `drained_end` (SIGKILLed, crashed) is counted
as unreported.

*Amended in Lot B1, the wire as built* (`lorica-worker/src/stream_ctl.rs`):
both messages carry the seq of the `quiesce reason=upgrade` they
answer, so they decode as `StreamCtlMsg::Drained` and
`StreamCtlMsg::DrainedEnd` beside `ack` and `nack` and keep `seq()`
total: `drained <seq> <closed>:<finished>:<stream_id>...` and
`drained_end <seq> <idle|deadline> http_cut=<n> entries=<n>
report=<complete|truncated>`. `end` keeps idle and deadline apart from
truncation, which is its own token; `entries` counts the entries sent
before the marker. A `drained` send that would block stops the entries
and the marker says `truncated` (a short marker can still fit where an
8 KiB message did not); a marker that cannot be sent either leaves the
worker unreported. `StreamRuntimeHandle::send_drain_report(end,
http_cut)` builds the report from the tracker and sends it through the
runtime thread, waiting at most `DRAIN_REPORT_TIMEOUT` (1 s) for that
thread; it refuses (`NotUpgrading`) when no upgrade quiesce arrived.

**Old generation to new generation.** The old supervisor writes
`<data_dir>/upgrade/drain-report.<new_pid>.json` (0600, temp file then
rename): old and new pid, `drain_timeout_s`, `drain_secs`, `end`
(`idle`, `deadline` or `killed`), `workers_unreported`, `http_cut`, and
per stream `{ closed, finished }`. The new supervisor, after recording
`completed`, polls for its own report every second, bounded by
`WORKER_DRAIN_TIMEOUT_MAX_S + WORKER_KILL_MARGIN + 60 s`, then records
the metrics below, logs one summary line, and deletes the file. No
report by then is a warning, not an error. A supervisor at start deletes
report files addressed to another pid that are older than that bound
(leftovers of a crash), never a younger one, which a chained upgrade may
still be waiting for.

**Metrics, recorded by the new generation only:**

- **`lorica_hot_upgrade_stream_connections_total{stream_id, outcome}`**,
  a new counter (Resolved 1), registered with
  `lorica_metrics::register_int_counter_vec` beside the hot-upgrade
  family. `outcome` is a closed set of two words, rendered from one
  enum: `drained` (incremented by a report's `closed`: connections and
  sessions the upgrade ended with `drained_by_upgrade`) and `finished`
  (incremented by `finished`: those that ended on their own during the
  drain). It counts connections; nothing else on it counts upgrades.
- **`lorica_hot_upgrade_total` is unchanged**: same `outcome` label,
  same five values, no new label.
- **Cardinality:** two series per stream, the number of streams on a
  node being bounded by the listening-socket cap (12.2 AC #5); a stream
  id is never client-chosen, and the label follows 12.9 D-e (`stream_id`,
  never the name). Series of a deleted stream are removed on the table
  change that removes it, through the same pruning hook as 12.9's
  collector. A report naming a stream the new table no longer holds is
  logged, not recorded.
- `drain_timeout` is recorded when `end` is `deadline` or `killed`, so
  it now means "the drain reached `worker_drain_timeout_s` with traffic
  still open". Its doc is rewritten; the "idle keepalives" explanation
  is gone with the cause.
- `lorica_hot_upgrade_drain_seconds` is observed from `drain_secs`, its
  buckets extended past 60 s with 120, 300, 600, 1,200, 1,800 and 3,600.
- This also fixes the loss of the two existing drain metrics described
  above, by the same path.

**The log.** Each closed connection's access-log row is written by the
old worker with `end_reason=drained_by_upgrade` through 12.9's path
(12.9 "Handed to other stories": nothing new there). The old worker
also logs one `warn` line per stream at the deadline with the count it
closed.

### D-h. A second upgrade while a generation still drains

Allowed. The new supervisor knows its predecessor by the parent pid it
had at start, and considers it draining until its report has arrived or
that pid is no longer its parent. The preview shows it, the dashboard
warns, nothing refuses: a security upgrade must not wait up to an hour.
The cost is a third generation holding its connections' descriptors
until its own deadline (Resolved 3).

### D-i. A stop during a previous generation's drain

The unit's `KillMode=mixed` sends SIGTERM to the main process (the new
supervisor), then SIGKILL to the rest of the cgroup once it has exited.
A draining old generation is in that rest: its connections are cut
without an end reason when the new supervisor's stop completes. The new
supervisor's own stop path is unchanged; `docs/hot-upgrade.md` says that
a stop ends an earlier generation's drain. Changing this would mean a
stop waiting for a process it does not own; not done.

## Tasks

Lots with hard file allowlists. A Lot touches only its files; two Lots
that share a file are sequential, never parallel, and say so. Every Lot
that runs cargo ends on a tree that passes the gate chain CI runs
(`cargo fmt --all -- --check`, the workspace clippy with
`--all-targets --features lorica/otel -- -D warnings` under
`CARGO_BUILD_WARNINGS=deny`, the CI `cargo test` lines, `cargo audit`),
through Docker on Linux. No agent runs `git checkout`, `git restore`,
`git stash` or `git reset` in the shared tree.

**Order.** A and B1 first, in parallel (disjoint files). B2 after B1.
C after A and B2. D after B1 and after 12.9's collector Lot (the
`stream_active` aggregate) and 12.10's API Lot if the preview reads
`streams/status`. E after D. F after C, D and E. G after C and D, and
after 12.2 Lot H and 12.9's log Lot (the scenario reads the stream log).

### Lot A: chunked fd transfer, UDP slot sockets in the table - cargo

Allowlist: `lorica/src/startup/fd_transfer.rs` (new),
`lorica/src/startup/mod.rs` (the module line),
`lorica/src/startup/hot_upgrade.rs` (`build_fds_table`,
`serve_listener_fds_blocking`, `pull_inherited_listeners`,
`partition_inherited_fds`, the `stream-udp:` key family and its parser,
`StreamUdpFd`; nothing else).
Depends on: nothing in this story.

- [x] **First, before any change, the failing test on the current
      tree**, committed with the fix but run and recorded red first in
      the Debug Log: through today's `serve_listener_fds_blocking` and
      `pull_inherited_listeners`, (a) a table of 33 descriptors loses
      descriptors past 32 (`MSG_CTRUNC`) and (b) a table whose joined
      keys exceed 2,048 bytes arrives with truncated keys or trips the
      count assertion of `Fds::deserialize`. The same test then passes
      on the chunked transfer below, unchanged.
- [x] `fd_transfer.rs`: header, chunks of at most 32 descriptors and
      8 KiB of keys, one-byte acknowledgement per chunk; legacy single
      message when the table fits; receiver accepts both; every received
      descriptor closed on any error (D-d).
- [x] `stream-udp:<stream_id>:<bind_gen>:<slot>:<addr>` key, parser
      (same "id may hold colons" rule as `parse_stream_tcp_key`),
      `StreamUdpFd`, its arm above the proxy catch-all.
- [x] Tests: 1, 32, 33 and 1,100 descriptors round-trip with their keys;
      a table that fits is sent as the legacy message and read by the
      fork's `get_fds_from` unchanged (downgrade compatibility); a legacy
      message is read by the new receiver; a truncated chunk and a count
      mismatch fail the pull and leak no descriptor (count open fds
      before and after); malformed `stream-udp:` keys are refused.

### Lot B1: the upgrade quiesce in the worker crates - cargo

Allowlist: `lorica-worker/src/stream_ctl.rs`,
`lorica-stream/src/runtime.rs`, `lorica-stream/src/tracker.rs`,
`lorica-stream/src/listener.rs` (the TCP stop path only),
`lorica-stream/src/udp/` (the engine's upgrade branch),
`lorica-stream/tests/runtime.rs`,
`lorica-config/src/models/stream.rs` (`upgrade_policy()` and its enum
only).
Depends on: nothing in this story; sequential with any open 12.6 or 12.9
Lot editing `lorica-stream/src/udp/` or `tracker.rs`.

- [x] `QuiesceReason::Upgrade` (`reason=upgrade`), wire round-trip.
- [x] `drained` and `drained_end` worker-to-supervisor messages (D-g),
      encode and decode, packing to `PAYLOAD_BUF_SIZE`, `truncated`.
- [x] Runtime `quiesce(drain, reason)`; `quiesced()` carries
      `(Duration, QuiesceReason)`; `terminate` stays `Shutdown` and is a
      no-op once quiesced.
- [x] TCP: stop accept loops, `close` (never `shutdown`) the worker's
      listener descriptors, drain with the mapped reason (D-c).
- [x] UDP: on `Upgrade`, stop reading, keep sockets for sends, the two
      policies of D-e. On `Shutdown`, unchanged (drain mode, 12.5 D-m).
- [x] Tracker: per-stream `closed` and `finished` counts from the
      upgrade quiesce on, read by the watcher.
- [x] `Stream::upgrade_policy()` returning `Drain`, `RelayInFlight` or
      `Close`, serialised as the preview's words.
- [x] Tests: a TCP connection in each phase ends with
      `drained_by_upgrade` at the deadline and one that closes earlier
      keeps its reason; a `config_removed` connection keeps it across an
      upgrade quiesce; a listener closed by an old worker still accepts
      through another descriptor of the same socket (proves `close`, not
      `shutdown`); UDP unbounded sessions end at once, bounded ones relay
      an owed response then end on bound or idle with the reasons of
      D-e; after an upgrade quiesce the worker reads no datagram from its
      slot socket; counts match the ends.

### Lot B2: the watcher and the worker's report - cargo

Allowlist: `lorica/src/startup/drain.rs`, `lorica/src/startup/worker.rs`
(the drain arming and the exit closure only),
`lorica/src/startup/single.rs` (only if the watcher's signature change
reaches it).
Depends on: B1.

- [x] The watcher reads the reason from `quiesced()`; the deadline close
      uses it; `DrainProbe` takes it.
- [x] On an upgrade drain, the report of D-g sent with `MSG_DONTWAIT`
      before `exit`, with `http_cut` from `http_in_flight` at the
      deadline.
- [x] Doc comments that say "the upgrade path until Story 12.11" are
      rewritten to say what is true now.
- [x] Tests: an upgrade-armed watcher closes leftovers with
      `drained_by_upgrade` and a shutdown-armed one with `node_shutdown`;
      the report is sent on both `idle` and `deadline` ends; a full
      socket buffer does not block the exit.

### Lot C: the supervisor, both generations, the metrics - cargo

Allowlist: `lorica/src/startup/supervisor.rs` (the `Drain` arm and the
new side's post-`completed` block),
`lorica/src/startup/stream_plane.rs` (`quiesce_for_upgrade`,
`udp_handoff_fds`, UDP adoption, report collection),
`lorica/src/startup/hot_upgrade.rs` (the drain-report section only:
path, `DrainReport`, writer, reader, stale-file rule),
`lorica-worker/src/manager.rs` (`drain_for_handoff(drain)` and its doc),
`lorica-api/src/metrics.rs` (the new
`lorica_hot_upgrade_stream_connections_total` family with its record and
prune functions; the `drain_timeout` doc and the histogram buckets of
the existing family; `lorica_hot_upgrade_total` itself untouched),
`lorica-api/src/tests.rs` (a reader helper for the new family, beside
the existing one).
Depends on: A (shares `hot_upgrade.rs`), B2.

- [ ] Before editing: list the supervisor tasks draining workers depend
      on (metrics pull, log or telemetry fan-in) and record the finding
      in the Debug Log; step 2 of D-b keeps exactly those.
- [ ] The `Drain` arm in the order of D-b; `drain_for_handoff(D +
      WORKER_KILL_MARGIN)`; no audit release rows on upgrade.
- [ ] UDP groups in the handoff and their adoption by slot (D-e).
- [ ] Worker reports collected after exit, generation report written;
      the new side's polling reader, metrics recorded there only (D-g).
- [ ] `previous_generation` state for the preview (D-h).
- [ ] Tests: the `Drain` arm sends `quiesce reason=upgrade` before
      SIGTERM and waits `D + margin` (driver test with a fake manager or
      the existing plane test harness); an adopted UDP group is attached
      slot by slot, a mismatched one is closed and rebound; the report
      round-trips and stale-file deletion spares a young file;
      `lorica_hot_upgrade_stream_connections_total{stream_id,outcome}`
      increments by the report's `closed` (`drained`) and `finished`
      (`finished`), its outcomes iterated from the enum, and its series
      are removed with the stream; `lorica_hot_upgrade_total` renders
      exactly its five outcomes with the single `outcome` label;
      `drain_timeout` follows `end`.

### Lot D: the preview API and the CLI - cargo

Allowlist: `lorica-api/src/upgrade.rs` (the preview handler and its
response type), `lorica-api/src/server.rs` (the route only),
`lorica-api/openapi.yaml` (the preview path),
`lorica-api/src/tests.rs` (preview tests; sequential with Lot C, which
edits the same file), `lorica/src/main.rs` and `lorica/src/cli.rs` (the
`upgrade` command: preview print and `--preview`).
Depends on: B1 (`upgrade_policy`), C (`previous_generation`, and the
shared `tests.rs`), 12.9's collector Lot.

- [ ] Handler, role check identical to the upload's, `MetricsRefresher`
      before reading, `handoff_available` (D-f).
- [ ] CLI: preview to stderr before upload; `--preview` exits after it.
- [ ] Tests: a role below the upload's gets 403; single-process mode
      returns `handoff_available: false`; a TCP and a bounded and an
      unbounded UDP stream report `drain`, `relay_in_flight`, `close`;
      `established` follows the aggregate; the response matches
      `openapi.yaml` (the existing spec test).

### Lot E: the dashboard - frontend gates

Allowlist:
`lorica-dashboard/frontend/src/components/settings-tabs/BinaryUpgradeTab.svelte`,
`lorica-dashboard/frontend/src/lib/api.ts` (the preview call and type),
`lorica-dashboard/frontend/src/lib/api.test.ts`, the tab's test file if
one exists or a new one beside it.
Depends on: D.

- [ ] Preview loaded on dialog open; drain delay from the response; the
      streams table; the previous-generation warning; the stale
      "30 seconds" text gone from both places.
- [ ] Vitest: the dialog text uses the response's delay; an empty
      stream list shows no table; the warning appears with
      `previous_generation`.
- [ ] Gates of `lorica-frontend.md`; light and dark checked by eye before
      the release PR (no browser in the agent environment).

### Lot F: documentation - no cargo

Allowlist: `docs/hot-upgrade.md`, `docs/installation.md`,
`docs/streams.md` (its upgrade section; created by an earlier Lot of
this epic), `docs/worker-mode.md` (the drain paragraph only),
`CHANGELOG.md` (`[Unreleased]`).
Depends on: C, D, E.

- [ ] `hot-upgrade.md`: the drain step with `D` from the setting, read
      at the handoff; what happens per stream kind (D-c, D-e) and to
      HTTP; the reasons table of D-a; the preview (API, dashboard, CLI);
      the drain report, `lorica_hot_upgrade_stream_connections_total`
      (what `drained` and `finished` count) and the unchanged
      `lorica_hot_upgrade_total` with `drain_timeout`'s new meaning; chained
      upgrades (D-h); a stop ends an earlier generation's drain (D-i); a
      chunked table cannot hot-downgrade to 1.10.x (D-d); the old
      binary stops serving the management API at the handoff.
- [ ] `installation.md`: `TimeoutStopSec` and the drain as they now
      relate (a stop extends its own timeout, an upgrade involves no
      stop job).
- [ ] `streams.md`: the upgrade section, "every stream drains in
      1.11.0", the UDP policy and why.
- [ ] `CHANGELOG.md`: Added (preview,
      `lorica_hot_upgrade_stream_connections_total`), Changed
      (upgrade drain from the setting, `drain_timeout` meaning, histogram
      buckets, old API stops at handoff, UDP sockets handed over), Fixed
      (fd transfer past 32 sockets, drain metrics lost with the old
      process).

### Lot G: end-to-end, IV1 and the handover scenarios - Docker e2e

Allowlist: `tests-e2e-docker/docker-compose.yml` (the `hot-upgrade`
profile's services only), `tests-e2e-docker/ssh-backend/` (new),
`tests-e2e-docker/test-runner/run-hot-upgrade-smoke.sh` (a new section
appended; the existing section changed only where it assumes 30 s),
`tests-e2e-docker/test-runner/Dockerfile` (the SSH client package),
`tests-e2e-docker/entrypoint-hot-upgrade.sh` (only if the profile needs
a seed), `tests-e2e-docker/run.sh` (only if the profile's wait changes).
Depends on: C, D, 12.2 Lot H, 12.9's log Lot. Every `.sh` written stays
LF.

The new section runs after the existing 8.4 assertions, as a second
upgrade of the same binary, so those assertions stay as they are.

- [ ] **IV1, `stream-ssh-drained-by-upgrade`.** An `ssh-backend` service
      (Debian `openssh-server`, key generated at runtime on the shared
      volume, Resolved 4). Set `worker_drain_timeout_s=120` through
      `PUT /api/v1/settings`; create a TCP stream to it; open
      `ssh ... 'while sleep 1; do date +%s; done'` through the stream;
      read the preview and assert `drain_timeout_s=120`, the stream with
      `established=1` and `on_upgrade=drain`; upload the upgrade at `T0`.
      Assert the session still prints at `T0 + 115 s`, ends before
      `T0 + 150 s` (ready handshake, 200 ms poll and the 1 s close grace
      included), ssh reports "closed by remote host" (a FIN, not a
      reset), the stream log lists the connection with
      `end_reason=drained_by_upgrade`, and once the report has arrived
      the new generation's `/metrics` shows
      `lorica_hot_upgrade_stream_connections_total{stream_id="<id>",outcome="drained"} 1`
      and `lorica_hot_upgrade_total{outcome="completed"}` incremented.
- [ ] **`stream-new-connection-after-upgrade`.** A second SSH session
      opened at `T0 + 10 s` is served by the new generation and is still
      alive at `T0 + 150 s`: no connection is served by the old one
      after the handoff.
- [ ] **`udp-across-upgrade`.** A bounded UDP stream to the UDP
      stand-in of 12.5 Lot I; a client sending one query every 50 ms
      across the upgrade gets every answer (no timeout, no
      `binding_draining` drop in the counters).
- [ ] **`fd-transfer-past-32`.** A TCP stream on a 64-port range and a
      UDP stream exist during the upgrade; the upgrade completes and
      every port answers afterwards.
- [ ] The full suite passes with the machine to itself; the run time
      added (about three minutes) is noted in the Completion Notes.

## Dev Notes

### Where to extend, verified on `a0a12d01`

- `lorica/src/startup/supervisor.rs`: the `HandoffDecision::Drain` arm;
  the new side's `handshake_ready_with_old` block where `completed` is
  recorded.
- `lorica-worker/src/manager.rs`: `drain_for_handoff`,
  `shutdown_all_with_timeout` (reaps with `child_exited`; keep it).
- `lorica-worker/src/stream_ctl.rs`: `QuiesceReason`, message encoding,
  `PAYLOAD_BUF_SIZE` (8,192) and `MAX_FDS` (32) in `fd_passing.rs`.
- `lorica-stream/src/runtime.rs`: `quiesce`, `terminate`, `quiesced()`,
  `drain_open`, `stop_binding`.
- `lorica/src/startup/drain.rs`: `DrainProbe::close_remaining`,
  `wait_for_drain`, `arm_worker_drain`, `WORKER_KILL_MARGIN`,
  `DEADLINE_CLOSE_GRACE`.
- `lorica/src/startup/hot_upgrade.rs`: `build_fds_table`,
  `serve_listener_fds_blocking`, `pull_inherited_listeners`,
  `partition_inherited_fds`, `stream_tcp_fds_key`, `RollbackReason`.
- `lorica/src/startup/stream_plane.rs`: `quiesce`, `adopt_inherited`,
  `tcp_handoff_fds`.
- `lorica-core/src/server/transfer_fd/mod.rs`: `Fds`, `send_to_sock`,
  `get_fds_from` (read only; the legacy format D-d stays compatible
  with).
- `lorica-api/src/metrics.rs`: `HOT_UPGRADE_TOTAL` and
  `record_hot_upgrade` (unchanged), `HOT_UPGRADE_DRAIN_SECONDS`; the new
  family sits beside them.
- `lorica-api/src/upgrade.rs`: `upgrade_binary`; `server.rs`, the
  `/api/v1/system/upgrade` route.

### Pitfalls

- **`shutdown(2)` on a shared listening socket** stops it for every
  holder. Old workers `close` their descriptors; nothing calls
  `shutdown` on a listener on this path.
- **`SCM_RIGHTS` on a unix stream socket** is attached to bytes, not to
  messages. Without the per-chunk acknowledgement two chunks can be read
  as one and descriptors attributed to the wrong keys.
- **The old process's registry dies.** Any metric recorded in the old
  generation after the handoff is invisible. Record in the new one.
- **The quiesce must not precede the `Drain` decision.** A rollback
  after a quiesce would leave the old generation serving no streams.
- **The tracker's `drain_all` keeps an earlier reason.** Do not
  "fix" it into overwriting `config_removed`.
- **Shell scripts written by a tool keep CRLF** despite `.gitattributes`;
  the e2e image copies the working tree and bash dies on `\r`.
- **The e2e suite needs the machine alone.** IV1 is timing-bound.

### Tests per Lot

Listed in each Lot. What no automated test here proves: the dashboard
dialog in both themes (Lot E), and a real systemd unit (the e2e runs
without systemd; D-b sends nothing to it on this path by design).

### Handed to other stories

- **12.12:** IV1 and the three scenarios of Lot G are named scenarios
  of its L4 phase; the SSH backend image is listed among its approved
  artefacts (its AC #6).
- **12.16:** the UDP group handover of D-e (same slot, same worker
  index) is the affinity base of its AC #5; the drain report's
  `closed` and `finished` gain a `transferred` count (and
  `lorica_hot_upgrade_stream_connections_total` a `transferred` outcome,
  if that story counts transfers there); the preview's
  `on_upgrade` gains `transfer`; a connection that fails to transfer
  drains on this story's path with `drained_by_upgrade`.

## Resolved (maintainer, 2026-11-15)

1. **A dedicated metric.** Per-stream drain counts go on a new counter,
   `lorica_hot_upgrade_stream_connections_total{stream_id,outcome}`
   (outcomes `drained` and `finished`), and `lorica_hot_upgrade_total`
   is unchanged. Putting connection counts on the upgrade counter would
   have mixed units in one family. PRD AC #2 is amended to say so; the
   AC copy above quotes the amended text. Applied in D-g and Lots C, F
   and G.
2. **HTTP requests cut at the deadline** are counted in the drain report
   (`http_cut`) and the summary log line, with no new HTTP field. AC #2's
   end reason is the stream enum of 12.1 AC #8. Applied in D-b and D-g.
3. **Chained upgrades** while an older generation drains are allowed,
   with a warning in the preview and the dashboard (D-h). Refusing would
   make a security upgrade wait up to an hour.
4. **Test artefacts approved:** Debian bookworm's `openssh-server` (in
   the new `ssh-backend` image) and `openssh-client` (in the test-runner
   image), in the e2e images only. 12.12 lists them with its artefacts.
5. **12.5's UDP recommendation reversed, accepted.** The slot sockets
   are handed over instead of the groups merging, for the reasons
   recorded in D-e: a merged group remaps nearly every client, so drain
   mode keeps no continuity and serves one flow from two generations,
   while a handover keeps the group size, drops no new client and
   preserves slot affinity for Story 12.16. 12.5's hand-off note is
   superseded by D-e.

## Dev Agent Record

### Debug Log

**Lot A, red run on the unchanged transfer** (`7a0170ed` plus the three
tests only, `cargo test -p lorica --features otel --bin lorica`, Docker
`rust:1-bookworm`). Each descriptor is a distinct file and is matched to
its key through `/proc/self/fd`, so a pairing error would fail too.

```
test startup::hot_upgrade::tests::a_table_whose_keys_exceed_2048_bytes_crosses_the_upgrade_socket ... FAILED
test startup::hot_upgrade::tests::a_table_of_33_descriptors_crosses_the_upgrade_socket ... FAILED

---- a_table_whose_keys_exceed_2048_bytes_crosses_the_upgrade_socket stdout ----
thread '<unnamed>' panicked at lorica-core/src/server/transfer_fd/mod.rs:64:9:
assertion `left == right` failed
  left: 14
 right: 21

---- a_table_of_33_descriptors_crosses_the_upgrade_socket stdout ----
thread '<unnamed>' panicked at lorica-core/src/server/transfer_fd/mod.rs:193:29:
called `Result::unwrap()` on an `Err` value: ENOBUFS

test startup::hot_upgrade::tests::tables_of_1_32_and_1100_descriptors_cross_the_upgrade_socket ... FAILED
the old side serves the table: "failed to serve listener FDs on /tmp/.tmpZtTEWX/upgrade/transfer.sock: EINVAL: Invalid argument"
```

(a) 33 descriptors: the receive control buffer holds 32, the kernel
flags `MSG_CTRUNC` and the fork's receiver panics in the new
supervisor. (b) 21 descriptors whose keys join to more than 2,048
bytes: the sender's `Write` on the slice stops at 2,048 bytes, 14 keys
survive, `Fds::deserialize` asserts. 1,100 descriptors do not even
leave the sender: one `sendmsg` carries at most `SCM_MAX_FD` (253). The
same three tests pass unchanged on the chunked transfer.

**Which releases could reach it.** The fork's limits date from the
first hot upgrade (v1.6.0, `d339459c`), but no released table comes
near them: up to 1.10.6 it holds the HTTP and HTTPS listeners, the
management listener, at most one cluster listener (`--cluster-listen`
is a single `Option`) and at most one automation listener
(`--automation-listen`, idem), five short keys. Only the
`stream-tcp:` family of this cycle (`d9740fe4`, 12.2 Lot H, unreleased)
makes the table grow with configuration. No CHANGELOG line: the defect
never shipped. Lot F's planned "Fixed (fd transfer past 32 sockets)"
line should go, or move to Changed as the transfer format.

**Lot A, how the `lorica` crate sends `SCM_RIGHTS`.** The crate does
not depend on `nix` and std's ancillary-data API is unstable. Rather
than adding a dependency, `lorica-worker/src/fd_passing.rs` (outside
the allowlist) exposes what it already had: `MAX_FDS` and
`ReceivedRights` become `pub`, and two thin wrappers are added,
`send_with_rights` and `recv_with_rights_cloexec` (the existing
`recv_with_rights`, which also salvages and closes the descriptors of a
`MSG_CTRUNC` read, always with `MSG_CMSG_CLOEXEC` as the fork's
receiver does). The legacy sender is the fork's own
`Fds::send_to_sock`, so the bytes a 1.10.x receiver reads are the ones
it has always read; the fork is unchanged.

**Lot A, notes for Lot C.** Nothing sends `stream-udp:` keys yet:
`stream_udp_fds_key`, `StreamUdpFd` and `InheritedListeners::stream_udp`
carry `#[allow(dead_code)]` with a comment naming Lot C, which removes
them. Sending the UDP group needs `HandoffArgs`, `run_old_side_handoff`,
`build_fds_table` and `serve_listener_fds_blocking` to take the
`StreamUdpFd` list; Lot C's allowance in `hot_upgrade.rs` is the drain
report only, so it must be widened to those (or a small Lot A2 added).
Until the new side adopts or closes `inherited.stream_udp`, the old side
must not send it: an inherited slot socket nobody reads would swallow
the datagrams hashed to it.

**Lot A gates** (Docker, `CARGO_BUILD_WARNINGS=deny`): fmt, workspace
clippy, `lorica --features otel`, the forked crates, the rustls line
and `cargo audit` clean. The product-crate line has one failure that
predates Lot A and that its diff cannot reach:
`lorica-api` `streams::tests::the_published_udp_ranges_defaults_and_words_are_the_models`,
`openapi.yaml`'s `StreamRefusal` lacks the four TLS words
(`invalid_client_hello`, `no_certificate`, `tls_handshake`,
`client_certificate`) the enum now carries. Every other test of that
line passes (`--no-fail-fast`).

**Lot B1, what the code had become.** Read on `feat/v1.11.0` at
`3a2663e0`. Three shapes of the story no longer matched and are amended
in place (D-a, D-c, D-e, D-g, each marked "amended in Lot B1"):
`drains_on_upgrade()` is the 12.16 transfer exclusion (TLS terminate or
origin only), not "true for every stream", so the engine reads the new
`upgrade_policy()` instead; a one-way UDP stream is owed nothing and
closes like an unbounded one; the report messages carry the quiesce's
seq and a `report=` token. Nothing in the decisions was wrong against
the code; no stop was needed.

**Lot B1, how it is built.**

- `QuiesceReason::Upgrade`; `lorica_stream::quiesce_end_reason` maps
  `Shutdown` to `node_shutdown` and `Upgrade` to `drained_by_upgrade`.
  `quiesced()` is a `watch` of `Option<Quiesced { drain, reason }>`.
- Runtime `quiesce(drain, reason, seq)`: a no-op once quiesced (a later
  message is acked 0, `terminate` ignored). On `Upgrade` every binding,
  TCP and UDP, goes through `stop_binding`: a TCP loop drops its
  listener (`close`, the accept loop's doc says why never `shutdown`),
  a UDP loop stops reading and drops its handle while each session keeps
  its own `Arc` on the slot socket to answer from. Entries whose
  snapshot's policy is `close` are drained with a deadline of now, then
  everything with `now + D`, both with the mapped reason; `drain_all`
  keeps an earlier reason, so `config_removed` stays. On `Shutdown`
  nothing changed (UDP drain mode of 12.5 D-m).
- UDP engine: a session whose tracker entry the upgrade marked and that
  idles out ends `drained_by_upgrade` (`idle_end`); ends on its bound
  keep their natural reason. The bounded/unbounded split lives in
  `upgrade_policy()` only.
- Tracker: `TrackedConnection::finish` records the reason it reported,
  and the entry's removal counts it per stream when its drain reason is
  `drained_by_upgrade` (only the upgrade sets it): `closed` if it ended
  with that reason, `finished` otherwise. `drain_reason()` exposes the
  mark to the engines. `upgrade_drain_counts()` is what the report reads.
- `send_drain_report` runs on the runtime thread through a `Command`,
  over `ActiveTransport::try_send_report` (seqpacket: `MSG_DONTWAIT`;
  in-process: `try_send`, `Full` read as `EAGAIN`).

**Lot B1, files outside the allowlist**, each the smallest edit the
Lot needed: `lorica-config/src/models/mod.rs` (re-export
`UpgradePolicy`), `lorica-stream/src/lib.rs` (re-exports),
`lorica-stream/src/transport.rs` (`try_send_report`),
`lorica-stream/tests/udp_engine.rs` (the three UDP upgrade tests, which
need the real engine and that file's fake seams),
`lorica-stream/tests/tcp_engine.rs` (the each-phase drain test runs for
`drained_by_upgrade` as well as `config_removed`),
`lorica/src/startup/drain.rs` (the watcher reads `Quiesced.drain`, its
test the new type; Lot B2 then reworks it) and
`lorica/src/startup/stream_plane.rs` (one test assertion on the
`quiesced()` type).

**Lot B1, for Lot C.** A `quiesce reason=upgrade` must not go out
before the UDP slot sockets ride the handoff: an old worker's slot
socket now stays open while its sessions live and is read by nobody, so
in a merged group (no handover) the datagrams hashed to it would be
lost until its last session ends. Send both in the same Lot. The
supervisor reads `Drained` and `DrainedEnd` with the ordinary
`recv_msg`; today `StreamPlane::late_answer` would log them as
unexpected, so the collection after exit must read them before (or
instead of) that path.

**Lot B1 gates** (Docker `rust:1-bookworm`, `CARGO_BUILD_WARNINGS=deny`,
the `ci.yml` cargo lines in order): fmt, workspace clippy with
`lorica/otel`, the product crates, `lorica --features otel`, the forked
crates, the rustls line and `cargo audit`, all clean. The `lorica-api`
openapi failure Lot A recorded no longer occurs on this base.

**Lot B2, how it is built.** `arm_worker_drain` waits for `Quiesced`
and builds `DrainProbe::new(http_in_flight, tracker, reason)`, whose
deadline close uses `quiesce_end_reason(reason)`. `wait_for_drain` now
returns `DrainOutcome { end, http_cut }`, `http_cut` read from
`http_in_flight` at the deadline (0 on an idle end). On an upgrade
drain the watcher, before `exit`: at a deadline end logs one `warn`
per stream with the count the upgrade closed and one for the HTTP
requests cut, then calls `StreamRuntimeHandle::send_drain_report(end,
http_cut)` and logs what went (`truncated` or an error at `warn`: the
supervisor then counts the worker unreported). A stop sends no report.
`DrainEnd` is now `lorica_worker::stream_ctl::DrainEnd`, the wire's,
re-exported from `drain.rs`, so the watcher and the report cannot
disagree. `exit` still takes the `DrainEnd`; `worker.rs` changed only
in its two comments, `single.rs` only in building the probe.

**Lot B2, the shape Lot C consumes.** After a worker exits, its
supervisor end of the stream control socketpair holds, in order, the
`ack` of the upgrade quiesce, zero or more `StreamCtlMsg::Drained { seq,
entries }` and one `StreamCtlMsg::DrainedEnd { seq, end, http_cut,
entries, truncated }`, `seq` being the quiesce's. Read them with
`recv_msg` until `DrainedEnd` or `Closed`; no `DrainedEnd` is an
unreported worker. Sum `closed` and `finished` per `stream_id` across
workers, `http_cut` across workers, and take the generation's `end` as
`deadline` when any worker says so.

**Lot B2, the full-buffer test.** Nobody reads the supervisor's end and
the test floods `refresh` messages until its own send would block: the
runtime thread is then stuck sending acks, so the report cannot even be
handed to it. The exit still comes, bounded by drain + the 1 s close
grace + `DRAIN_REPORT_TIMEOUT`.

**Lot B2 gates**: the same chain as B1, all clean, `cargo audit`
included.

### Completion Notes

## File List

- `lorica/src/startup/fd_transfer.rs` (new, Lot A)
- `lorica/src/startup/mod.rs` (module line, Lot A)
- `lorica/src/startup/hot_upgrade.rs` (transfer, `stream-udp:` family, Lot A)
- `lorica-worker/src/fd_passing.rs` (`send_with_rights`, `recv_with_rights_cloexec`, Lot A)
- `lorica-worker/src/stream_ctl.rs` (`QuiesceReason::Upgrade`, `DrainEnd`, the drain report messages, Lot B1)
- `lorica-config/src/models/stream.rs` (`UpgradePolicy`, `Stream::upgrade_policy`, Lot B1)
- `lorica-config/src/models/mod.rs` (re-export, Lot B1)
- `lorica-stream/src/runtime.rs` (quiesce reason, `Quiesced`, `send_drain_report`, Lot B1)
- `lorica-stream/src/tracker.rs` (upgrade counts, `drain_reason`, Lot B1)
- `lorica-stream/src/listener.rs` (TCP stop path doc, Lot B1)
- `lorica-stream/src/transport.rs` (`try_send_report`, Lot B1)
- `lorica-stream/src/lib.rs` (re-exports, Lot B1)
- `lorica-stream/src/udp/engine.rs` (idle end under an upgrade, Lot B1)
- `lorica-stream/tests/runtime.rs` (Lot B1)
- `lorica-stream/tests/tcp_engine.rs` (Lot B1)
- `lorica-stream/tests/udp_engine.rs` (Lot B1)
- `lorica/src/startup/stream_plane.rs` (one test assertion, Lot B1)
- `lorica/src/startup/drain.rs` (the `Quiesced` type, Lot B1; the watcher's reason and the drain report, Lot B2)
- `lorica/src/startup/worker.rs` (comments of the drain arming and the exit closure, Lot B2)
- `lorica/src/startup/single.rs` (`DrainProbe::new`, Lot B2)
- `docs/stories/story-12.11-upgrade-drain.md`

## Change Log

| Date | Version | Description | Author |
|---|---|---|---|
| 2026-11-15 | 0.1 | Draft: decisions D-a to D-i, Lots A to G, five open questions. | Romain G. |
| 2026-11-15 | 0.2 | Maintainer answers folded in as Resolved 1 to 5: a dedicated `lorica_hot_upgrade_stream_connections_total{stream_id,outcome}` with `lorica_hot_upgrade_total` unchanged (AC #2 copy updated to the amended PRD text, D-g and Lots C, F, G rewritten); HTTP cuts in the report and log only; chained upgrades allowed with a warning; SSH packages approved for the e2e images; the UDP handover of D-e accepted. Lot A opens with the failing 32-fd / 2,048-byte test on the current tree. Status Draft. | Romain G. |
| 2026-11-15 | 0.3 | Lot A: chunked `lorica-fds/2` transfer with a one-byte acknowledgement per header and chunk, legacy single message kept whenever the table fits, receiver reading both and closing everything on error; `stream-udp:` key family parsed into `StreamUdpFd`. Red run recorded. Status InProgress. | Romain G. |
| 2026-11-18 | 0.4 | Lot B1: `quiesce reason=upgrade` mapped to `drained_by_upgrade`, `Quiesced { drain, reason }`, first quiesce stands; old workers close their own listener and slot descriptors, UDP sessions relay what they are owed or close by `Stream::upgrade_policy()`; tracker counts `closed` and `finished` per stream; `drained` / `drained_end` report messages sent without waiting. D-a, D-c, D-e, D-f and D-g amended where the code had moved (`drains_on_upgrade` is the 12.16 exclusion, one-way UDP closes, the report wire carries the quiesce seq). | Romain G. |
| 2026-11-18 | 0.5 | Lot B2: the drain watcher closes leftovers with the quiesce's end reason, returns `DrainOutcome { end, http_cut }`, and on an upgrade logs the per-stream closes at the deadline and sends the worker's drain report before `exit`, never blocking on it; `DrainEnd` is the wire's. | Romain G. |
