# Story 12.5: The UDP Stream Engine

**Epic:** [Epic 12 - TCP and UDP Stream Proxying (v1.11.0 and v1.12.0)](../prd/epic-12-v1.11.0.md)
**Status:** InProgress
**Priority:** P0
**Author:** Romain G.
**Depends on:**
- Story 12.1 (done): the `Stream` model, `StreamProtocol::Udp`, the
  UDP-only backend rule (`check_backend_attachments`, D-6), the end-reason
  enum and `StreamRefusal` (D-7), the stream store with its explicit
  column list (`STREAM_COLUMNS`), canonical format 3 (D-3: later stories
  add fields inside it and move `CANONICAL_SHAPE_DIGEST` on purpose), the
  `StreamResponse` view built field by field (D-10).
- Story 12.2 (Lots A, B, C1, D done; C2, E1, E2, E3, F, G, H open on the
  branch): the per-worker `SO_REUSEPORT` UDP group kept at constant size by
  the supervisor (D-c), the stream control channel and its stop-and-wait
  flow (D-a), `lorica-stream` with the UDP receive loop, `DatagramHandler`,
  `Datagram`, the tracker, the fd budget and its generic
  `ceiling x fds_per_unit` input (D-e), the reconcile diff with the UDP
  overlap refusal, the stream plane driver (`lorica/src/startup/stream_plane.rs`),
  the budget view (Lot E3, Lot F) and the heartbeat `StreamPlaneReport`
  (Lot E2). Lots below name which open 12.2 Lot they wait for.
- Story 12.3 (TCP engine, Draft, `docs/stories/story-12.3-tcp-engine.md`):
  the seams of its D-a (`BackendSelector`, `BreakerGate` over the breaker
  keyed `stream:<id>`, `Resolve`), the shared `select_index` of D-e, the
  backup flag of D-f, the stream table with backends and
  `table_changed` of D-i, the PROXY encoder of D-j, `source_addresses` of
  D-l, the local-backend check and `BoundPorts` of D-m, the resolver cache
  of D-n, `held_fds` of D-p, the stream fields of D-q, and
  `StreamCounters` and the connection record with its
  `ConnectionObserver` of D-r. What this story uses of each, and every
  edit one of the two stories must make so they fit, is in "Interface with
  Story 12.3"; every Lot that needs it says so.

**Blocks:** Story 12.6 (its per-node caps live on the stream-caps region
built here, AC #3; the allowlist half of the listen-address rule, D-k),
12.9 (the UDP counters, drop reasons and the "ceiling reached" edge), 12.10
(the unbounded-responses badge and flag on every surface), 12.11 (what an
upgrade does to UDP bindings, see "Handed to later stories"), 12.12 (IV1,
IV2, the fd-reserve scenario, the UDP performance phase), 12.14 (UDP
active checks feed the health state the selector reads), 12.16 (the
session state and the region a transfer re-registers in).

---

As an operator,
I want to forward UDP traffic (DNS, syslog, RADIUS, game or VoIP signalling) with session semantics and safe defaults,
so that I can front UDP services without building an amplifier.

## Acceptance Criteria

These are the PRD's, unchanged. They are the contract.

1. **Sessions keyed on the client address and port**, each bound to one backend and served by one worker for that worker's lifetime (D4), with round robin, random, consistent hash on source and least sessions.
2. **The D6 defaults**, each documented next to the survey's values: response datagrams per request, response bytes relative to request bytes, requests per session, idle timeout, per-source datagram and byte rate, per-source session cap, total session cap per stream. A session closes as soon as its request or response bound is reached (`request_bound_reached`, `response_bound_reached`).
3. **Listen address rule (D6).** A UDP stream on any address other than loopback, RFC 1918 or ULA is refused unless it has a source allowlist or a per-source cap at or below the documented maximum.
4. **Unbounded responses are explicit**: a separate field, a permanent badge, a flag in API and MCP listings.
5. **Per-node caps on dedicated tables.** Stream caps are per node, shared across workers, on `lorica-shmem` tables of their own (not the WAF tables), sized per stream. A full table refuses new sessions on that stream only, counted as its own refusal reason. A concurrency slot is never evicted while it is held. The shared-memory layout version bump is part of this story.
6. **A ceiling derived from the host.** Each session holds one connected upstream socket, so the per-node session ceiling defaults below the fd budget left after the HTTP reserve (Story 12.2 AC #5) and below the usable ephemeral port count per source address (about 28,000 with the default `ip_local_port_range`). It is recomputed on every stream change, reported with the limit that bound it, and a change that would break it is refused. Several UDP streams on one node share that budget: each stream's session cap is a share of the node ceiling, the shares cannot add up to more than the ceiling, and the split is shown in the budget view. Receive buffers are shared per worker, never allocated per session.
7. **PROXY protocol v2 (DGRAM transport) prefixed to every datagram** sent to the backend where enabled; the per-datagram convention and the backends known to accept it are documented.
8. **Datagram size** is bounded; oversized datagrams are dropped and counted.

## Integration Verification

- IV1: With default settings, a flood from many spoofed sources aimed at reflecting towards one victim address keeps the reflected byte rate towards that address under the documented bound, and a legitimate client from another address is still served.
- IV2: A DNS stream in front of two resolvers, driven at a query rate above the documented capacity formula with default settings, answers every query with no refusal, because each session closes on its response.

## What the code does today

Read on `feat/v1.11.0` at `0a891772`. Function names, not line numbers.
Read, not run.

- **The receive loop** (`receive_loop`, `lorica-stream/src/listener.rs`)
  allocates one `DATAGRAM_BUF_SIZE` (64 KiB) buffer **per socket**, reads
  with `recv_from`, copies the payload into a fresh `Vec<u8>` per
  datagram, builds a `Datagram` (payload, source, `Arc<UdpSocket>` of the
  slot, `bind_gen`, the table's `Arc<Stream>`, the tracker) and **awaits**
  `DatagramHandler::handle` before reading the next datagram. A 1,024-port
  UDP range therefore holds 64 MiB of receive buffers per worker today.
  `ECONNREFUSED` / `ECONNRESET` on the slot socket are skipped without
  pause. No engine is installed (`Engines::default()`): every datagram is
  dropped at debug.
- **`DatagramHandler`** (`lorica-stream/src/handler.rs`) returns a
  `HandlerFuture`; its doc already warns that it "must hand off rather
  than wait on a backend". 12.2's Completion Notes leave the shape to this
  story ("Story 12.5 may revisit").
- **The tracker** (`lorica-stream/src/tracker.rs`) registers one entry per
  connection or session with its snapshot and backend id, drains by
  predicate with a pending reason, and signals the close; the engine
  closes and calls `finish(natural)`. `detach` today stops the binding's
  loops and closes its sockets at once (`runtime.rs`, 12.2 D-g).
- **The budget** (`lorica-stream/src/budget.rs`): `StreamDemand::of` sets
  `held: None` for every stream; `HeldFds { ceiling, fds_per_unit }` is
  the input this story fills; `BudgetViolation` has three constraints
  (`listen_socket_cap`, `worker_fds`, `supervisor_fds`). The view carries
  `ceiling` and `fds_per_unit` as `null`.
- **UDP slot sockets** (`bind_udp_group`, `lorica-worker/src/stream_sockets.rs`)
  set `SO_REUSEPORT` before bind and the `IPV6_V6ONLY` rule; no
  `IP_PKTINFO` / `IPV6_RECVPKTINFO`. `process_fd_limit` reads the soft
  `RLIMIT_NOFILE`. Nothing reads `ip_local_port_range`.
  `BindFailureKind` is `address_in_use`, `permission_denied`,
  `address_not_available`, `reserved_port`, `fd_budget`, `other`.
- **`lorica-shmem`** holds one compile-time region, `SharedRegion`
  (`region.rs`): a 64-byte header (`MAGIC`, `LAYOUT_VERSION = 1`, the
  SipHash key) and two `AtomicHashTable<WAF_SLOTS>` (128 Ki slots of 64
  bytes, 16 MiB in all). `AtomicHashTable<const N>` (`table.rs`) is
  open addressing with `MAX_PROBE = 16`, a claim that subtracts the
  left-over value, `reset` by CAS on the key, and `SATURATED` as a
  fail-closed answer. The eviction walker (`eviction.rs`, every 60 s,
  stale after 5 min) releases a slot by CAS on its key whatever its value,
  and accepts "at most one stale increment per slot reuse". The region is
  created in `run_supervisor` and passed to workers in the fork bundle;
  **single-process mode has no region** (`shmem: None`). The hot-upgrade
  transfer table carries no memfd: each generation creates its own region.
- **The model** (`lorica-config/src/models/stream.rs`): `Stream` has no
  protocol-specific field. `StreamRefusal` is `NoMatch` only.
  `StreamEndReason::RequestBoundReached` and `ResponseBoundReached` are
  documented as "the per-connection request/response **byte** bound",
  which is not what AC #2 means by the request bound (a count). Migrations
  end at 73 (`migrate_cluster_node_reserved_ports`).
- **Balancing and passive detection** live in the binary crate:
  `LoadBalancing` (`round_robin`, `consistent_hash`, `random`,
  `peak_ewma`, `least_conn`, `lorica-config/src/models/enums.rs`),
  `CircuitBreaker` keyed by `(route_id, addr)` strings
  (`lorica/src/proxy_wiring/lb.rs`). `lorica-stream` cannot depend on
  `lorica`; Story 12.3 D-a exposes them to the stream plane through
  traits implemented in `lorica/src/stream_engine.rs`, and this story
  uses the same traits.
- **PROXY protocol**: `lorica_core::protocols::proxy_protocol` is a
  sans-IO parser (v1 and v2, `DGRAM` transports recognised on parse,
  Story 12.8 Lot A). There is no encoder yet; Story 12.3 Lot A adds
  `encode_v1` and `encode_v2` with transport `STREAM` only.

## Decisions taken in this story

Each with its reason and what it costs.

### D-a. A session is a worker-local entry plus one connected upstream socket; no client-side socket (12.2 Resolved #7)

**Key.** `(bind_gen, local, client)`: the binding, the local address and
port the datagram reached (the slot socket's port, and for a wildcard
listen address the destination address from `IP_PKTINFO`, D-g), and the
client address and port, IPv4-mapped addresses canonicalised to IPv4.
Two listen ports of a range, or two local addresses of a wildcard
listener, are two sessions for one client port, which is what a range
(port N to backend port N) and a correct reply source need.

**Table.** A per-worker `HashMap` owned by the engine, never shared:
the `SO_REUSEPORT` group hashes the 4-tuple and 12.2 D-c keeps the group
size constant across worker deaths, so a client's datagrams reach one
worker for that worker's lifetime and no cross-worker lookup is ever
needed. What crosses workers is accounting only (D-d). A worker that dies
loses its sessions (its process and its upstream sockets are gone); the
supervisor releases their counts before the respawn replay (D-d), and a
client hashed to that slot starts a new session on the respawned worker.
No access-log row is written for them: a crash, as 12.2 D-a already
documents for TCP.

**Upstream socket.** Each session opens one `SOCK_DGRAM` socket,
non-blocking and `SOCK_CLOEXEC`, bound to one of the stream's
`source_addresses` with port 0 when it sets any (D-f) and otherwise left
to the kernel, then
`connect`ed to the chosen backend address. A connected socket makes the
kernel filter responses to that backend's address and port, assigns an
ephemeral port at `connect`, and turns an ICMP port unreachable into
`ECONNREFUSED` on the session (passive detection, D-i). `SO_RCVBUF` is set
to 32 KiB (the kernel doubles it): a session never queues more than its
response bound allows, and the default `rmem_default` times 28,000 sessions
is gigabytes of kernel memory an amplifying backend could fill. Backends
must answer from the address they were sent to; one that answers from
another address is filtered by the kernel, as with nginx. **`fds_per_unit`
is 1.**

**No client-side connected socket.** A second socket per session, bound
to the listen address and connected to the client, would let the kernel
demultiplex per session and could carry a session across a worker or
generation change (12.16). It is rejected for 1.11.0:

- it doubles fds per session, halving the node ceiling for every UDP
  stream, for a benefit only Story 12.16 would use;
- the worker would bind the listen port itself, which D4 reserves to the
  supervisor (privileged ports, and the group the supervisor keeps at
  constant size);
- to share the port it must set `SO_REUSEPORT`, which enrols it in the
  slot group. I am fairly sure, without having run it, that Linux counts
  connected members in the group's selection array, so every session
  opened would change the group size and remap the unconnected clients
  of every other worker, the exact failure 12.2 D-c exists to prevent.

*Cost:* Story 12.16 transfers a UDP session as its entry and its upstream
socket, and the client's next datagram must still reach the generation
that holds it through the slot sockets. The 12.16 spike is where the
connected-socket variant is measured again, on evidence; this story's
types do not preclude it (the session owns its sockets behind one
struct).

### D-b. Session lifecycle and the bounds of AC #2

Per session: `q` requests forwarded, `r` responses forwarded, request
bytes `qb`, response bytes `rb`. Per stream (D-l): `R`
(`udp.requests_per_session`), `K` (`udp.responses_per_request`),
`ratio` (`udp.response_bytes_ratio`), `idle` (12.3's `idle_timeout_s`,
10 s by default on a UDP stream) and `udp.unbounded_responses`.

- **A client datagram** on an open session: `q += 1`, `qb += len`,
  forwarded. When `q == R` the session is **retired**: it leaves the key
  map, takes no more requests, and waits for the responses it is owed.
  The client's next datagram on that key opens a new session (subject to
  every cap). This is nginx's `proxy_requests` semantics, and it is what
  keeps a load generator or a stub resolver that pipelines several
  queries on one source port from being dropped.
- **A backend datagram** is forwarded only while `r < K x q` and
  `rb + len <= ratio x qb`; otherwise it is dropped and counted
  (`response_count_bound`, `response_byte_bound`). With
  `unbounded_responses` neither test applies.
- **The session ends**, unless `unbounded_responses` is set:
  - when `K >= 1` and `r == K x q` (every response owed has arrived):
    `request_bound_reached` if `q == R`, `response_bound_reached`
    otherwise. A DNS query with `K = 1` therefore closes on its answer,
    which is what IV2 proves;
  - when a response is dropped for the byte bound: `response_bound_reached`
    (the allowance is spent; nothing more can be forwarded until another
    request, and a client that wants more opens a new session);
  - when `K == 0` (no response expected: syslog, NetFlow) and `q == R`:
    `request_bound_reached`, right after the forward. Responses on such a
    session are dropped (`response_count_bound`). Closing after every
    datagram, as one could read nginx's `proxy_responses 0`, would write
    one access-log row per syslog message (Story 12.9), so a `K = 0`
    session lives for `R` datagrams or until idle;
  - after `idle` with no datagram either way: `idle_timeout`;
  - after 12.3's optional `total_timeout_s`, from the session's first
    datagram: `total_timeout`;
  - on an ICMP error from the backend: `connect_failed` if no response was
    ever received, `backend_close` otherwise (D-i);
  - by the tracker: `config_removed`, `node_shutdown`, `backend_down`
    (12.3's `close_on_backend_down`), `drained_by_upgrade` (12.11).
- **With `unbounded_responses`**, a session ends only on `R` (when set),
  idle, total duration, an ICMP error or the tracker: the stateful mode
  games and VoIP signalling need, where a backend speaks without being
  asked and a new upstream port would look like a new client.

The doc comments of `StreamEndReason::RequestBoundReached` and
`ResponseBoundReached` are reworded to this meaning (request count bound
reached; response count or byte allowance reached). The variants and their
words do not change.

### D-c. The engine never waits inside the receive loop: `DatagramHandler` becomes synchronous

12.2's loop awaits the handler, which is right: a loop that spawned per
datagram would queue unbounded work under a flood. So the handler must not
wait, and this story makes that a property of the type rather than of a
doc comment. `DatagramHandler::handle` changes to

```rust
fn handle(&self, datagram: Datagram<'_>);
```

with `Datagram<'a> { payload: &'a [u8], source, local, socket, bind_gen,
snapshot, tracker, bound_ports }`: no future, the payload borrowed from
the worker's receive buffer (D-h), `bound_ports` the same handle 12.3
D-m has the accept loop put in `AcceptedConnection` for the connect-time
local check. `DatagramHandler` also gains the defaulted
`table_changed(&self, table: &StreamTable)` that 12.3 D-i gives
`StreamHandler`, so the UDP engine prunes per-stream state on the same
signal. Everything `handle` does is a non-blocking syscall or an atomic:
the cap checks (D-d), the selection and the breaker admission (12.3's
seams; the selector reads the table and the resolver cache, never
resolves on this path: a backend whose name is not resolved yet is not a
candidate for this session, and its first resolution is started off the
path), `socket` + `bind` + `connect`
on a UDP socket (none of them waits on the network), `try_send` on the
session socket (a full send buffer drops and counts `send_failed`, UDP
being lossy anyway), and `tokio::spawn` of the session task for a new
session. The session task, not the loop, waits on the backend.

*Cost:* the 12.2 signature changes (`handler.rs`, `listener.rs`, the
runtime tests' echo handler). No engine implements it yet, so nothing
else moves. A test pins the property: with a backend that never answers
and the session socket's send buffer full, the loop keeps serving a
second client.

### D-d. The stream-caps region: one memfd per UDP stream, sized from the stream, versioned on its own

AC #5 asks for tables "sized per stream" on `lorica-shmem`. `SharedRegion`
is a compile-time struct: it cannot be sized per stream at runtime, and
putting per-stream tables in it would also let one stream's flood fill
another's slots. So this story adds a **second region type,
`StreamCapsRegion`** (`lorica-shmem/src/stream_caps.rs`): one anonymous
memfd per UDP stream on the node, created by the supervisor (or the
single-process driver), mapped `MAP_SHARED` by every worker, sized from
the stream's settings and the worker count.

**Layout** (little-endian, every table 64-byte aligned):

| Part | Content | Size |
|---|---|---|
| Header | `STREAM_CAPS_MAGIC` ("LORICASC"), `STREAM_CAPS_LAYOUT_VERSION` (1), SipHash key (fresh per region), `workers` W, `rate_slots`, `shard_slots`, `caps_gen` | one cache line |
| Stream total | `total: AtomicU64`, then `per_worker: [AtomicU64; W]` attribution | 8 x (W + 1), padded |
| Rate table | `rate_slots` cells of 64 bytes: `key`, `datagram_tat`, `byte_tat`, `last_seen_ns` | `rate_slots x 64` |
| Session shards | W shards of `shard_slots` slots of 16 bytes: `key`, `sessions` | `W x shard_slots x 16` |

`rate_slots = next_pow2(max(4 x max_sessions, 1,024))`,
`shard_slots = next_pow2(max(2 x max_sessions, 256))`. At the default
`max_sessions` of 4,096 and 8 workers: 1 MiB of rate table and 1 MiB of
shards. At 28,000 sessions and 64 workers: 8 MiB and 64 MiB, which
`docs/streams.md` states; memfd pages are only backed once touched.

**What each part counts, and why it is safe:**

- **Stream total, exact.** A new session does `total.fetch_add(1)`; if the
  result exceeds `max_sessions` it subtracts and refuses
  (`session_cap`); otherwise it adds 1 to `per_worker[slot]`. The end of a
  session subtracts from both. Exact across workers, never evicted.
- **Per-source sessions, sharded per worker.** Each worker writes only its
  own shard (single writer: plain atomic stores, no CAS race), and the
  per-source check sums the source's count over the W shards. The owner
  releases a shard slot when its count returns to 0. **Nothing else ever
  releases a shard slot**: the eviction pass never reads shards for
  release, so a concurrency slot is never evicted while it is held.
  *Cost (Resolved 5):* two workers creating a session for the same source
  in the same instant can both pass the check. The formula
  `docs/streams.md` carries: the sessions one source key holds on a node
  are at most `source_session_cap + (W - 1)`, W being the node's worker
  count; in single-process mode (W = 1) the cap is exact, and each worker
  on its own never exceeds `source_session_cap`. The stream total, which
  bounds fds and ports, is exact, so the fd budget of D-e holds. A session
  creation reads W shards, once per session, never per datagram.
- **Per-source rates, shared GCRA cells.** One cell per source key, two
  generic-cell-rate theoretical arrival times (datagrams, bytes), each
  advanced by CAS against `now_ns()` (`CLOCK_MONOTONIC`, comparable across
  processes). Burst is one second of rate. A cell is claimed for a source
  the first time it sends; the stream's eviction pass releases a cell
  whose two arrival times are both in the past (the bucket is full again,
  there is nothing to remember) **and** whose source holds no session in
  any shard. A rate cell is not a concurrency slot; the WAF table's
  accepted race (one stale update per reuse) is acceptable here for the
  same reason.
- **A full table** (the probe chain of a new key saturated, in the rate
  table or the worker's shard) refuses the new session on this stream only
  with `session_table_full`: every stream has its own region, so a flood
  that fills one cannot touch another. A random-source spoofed flood can
  fill a stream's rate table and refuse new sources on that stream while
  it lasts; sources with sessions keep their cells and keep being served.
  That is the AC's behaviour, documented in the threat model with its
  mitigations (an allowlist and the per-stream new-session rate limit of
  Story 12.6).

**Source key (Resolved 3).** IPv4: the address. IPv6: the /64 prefix,
because one host holds a whole /64 and per-address keys would let it
multiply every per-source control by 2^64. *Cost:* hosts sharing a /64
share the per-source budget. Hashed with the region's own SipHash key.
The key serves the per-source caps and rates only; balancing hashes the
client address as 12.3 does (D-i).

**Worker death.** Before the respawn replay of 12.2 D-a, the supervisor
(which keeps every region mapped) zeroes the dead slot's shard and
subtracts `per_worker[slot]` from `total`, then sets it to 0. The dead
worker is not writing; nobody else writes that shard or that counter.

**Transport to workers.** A new stream-control message
`caps <seq> <stream_id> <caps_gen> slot=<i>` with one `SCM_RIGHTS` fd,
under a new typed tag `FdKind::StreamCaps { caps_gen }` (wire
`stream-caps:<caps_gen>`). The supervisor sends it before the stream's
first `attach`, in the respawn replay before the `attach` replay, and when
the region is replaced. The worker maps it, verifies magic and version,
closes the fd, and hands the mapping to the engine as the stream's current
region; `slot=<i>` is the worker's shard index, which the worker does not
otherwise know. A version mismatch (a worker respawned from a newer binary
on disk) answers `nack adopt_failed`, and the binding reports `k/W`
serving, as a bad `attach` does.

**Lifetime.** One region per UDP stream on the node, not per binding, so
caps stay exact across a rebind's drain (old and new bindings count in one
region). An edit of `max_sessions` that changes `rate_slots` or
`shard_slots` makes the supervisor create a new region (`caps_gen + 1`)
and send `caps`; sessions keep an `Arc` of the region they were counted
in, the cap check sums `total` over the stream's live regions, and the
supervisor drops a retired region once its `total` is 0. An edit within
the same table sizes changes nothing: limits are read from the snapshot,
only sizes live in the region. Deleting the stream retires its region the
same way.

**Single-process mode** creates the same region (memfd, W = 1, slot 0)
and passes it over the in-process transport, so there is one code path.

**`LAYOUT_VERSION` and the upgrade consequence.** AC #5's "shared-memory
layout version bump" is satisfied by the new region's own layout version
(Resolved 1): the WAF region's layout is untouched, so `SharedRegion`'s
`LAYOUT_VERSION` stays 1, and bumping it without a layout change would
only make its check lie. The new layout carries its own
`STREAM_CAPS_LAYOUT_VERSION`, introduced at 1, checked by every worker at
map time and listed in `docs/BUMP-CHECKLIST.md` beside the existing one.
Regions are never shared across generations (the hot-upgrade table carries
no memfd), so a version change has no consequence across a hot upgrade.
What an upgrade does change, and `docs/streams.md` says: during the drain
overlap the old and the new generation each count in their own regions,
so a stream can hold up to twice its `max_sessions` on the node for that
window, and the ephemeral ports (shared by the host) can run short, which
shows as `connect_failed`. Story 12.16 re-registers transferred sessions
in the new generation's region (its AC #3); this story builds no transfer
path, only a region API that does not preclude one (a permit is an owned
value that can be created against another region).

### D-e. The node session ceiling (AC #6)

Inputs, read by the supervisor (and the single-process driver):

- `S`, the stream budget of 12.2 D-e (`L - 1,024 - L/2`);
- `U`, the **usable UDP source ports per source address**: the size of
  `net.ipv4.ip_local_port_range` (which also governs IPv6), minus the
  ports of `net.ipv4.ip_local_reserved_ports` inside it, minus
  `EPHEMERAL_PORT_MARGIN` = 1,024 left to the host's own UDP clients (its
  resolver, health probes, other processes). 28,232 - 1,024 = 27,208 at the
  default range. TCP ports are a separate space: Story 12.3's connections
  do not consume `U`. Read at start and at every reconcile (cheap
  `/proc` reads), so a sysctl change is picked up without a restart; the
  fd limit cannot change without one.

Each UDP stream declares `HeldFds { ceiling: udp.max_sessions,
fds_per_unit: 1 }` through 12.2's accountant. 12.3 D-p computes the TCP
figure in `lorica_stream::tcp::held_fds(&Stream)`, called by the driver's
`demand_of` and the API's budget check; this story adds
`lorica_stream::udp::held_fds` and replaces both call sites with one
protocol-neutral `lorica_stream::held_fds(&Stream)` that dispatches on the
protocol, so the two paths still cannot disagree (Interface edit E5). The
constraints a set of streams must meet on a node:

1. **fds** (12.2's `worker_fds`, now with UDP held fds counted): listening
   sockets + TCP held fds + the sum of UDP `max_sessions` `<= S`;
2. **source ports**, new `BudgetViolation::SourcePorts { pool, committed,
   usable }`: for each source pool (each address of any stream's
   `source_addresses`, and one `default` pool for streams without any),
   the sum over the streams using it of
   `ceil(max_sessions / pools_of_that_stream)` `<= U` (a stream with
   several source addresses spreads its sessions evenly, D-f);
3. **supervisor** fds: 12.2's, plus one memfd per UDP stream.

The **node ceiling** reported is `min(S - other committed fds,
U x pools)`, with `bound_by` = `fd_budget` or `source_ports`. Each stream's
share is its `max_sessions`; the shares cannot add up past the ceiling
because constraints 1 and 2 refuse it. A create or update that breaks one
is refused by the management API with the node, the constraint and the
numbers (on a control plane, for every reporting targeted node, from the
heartbeat), and by the node at bind as the backstop with a new
`BindFailureKind::SourcePorts` (`source_ports`, retried on change only,
like `fd_budget`). A sysctl narrowed under bound streams does not unbind
them (no cut traffic): the view flags the node `over_ceiling`, and every
change that raises the demand is refused until it fits again; changes
that lower it pass.

Overshoot of the per-source cap (D-d) does not touch these: they bound the
stream total, which is exact. The upgrade overlap of D-d can exceed `U`
for its duration; the docs say so.

**The default share** is `max_sessions = 4,096`, not "an equal part of the
ceiling": a share that moved whenever another stream was added would
change the behaviour of streams nobody edited, and differ per node in a
fleet. At the packaged `LimitNOFILE` and default range, six default UDP
streams fit a node without `source_addresses`; the seventh is refused with
the numbers and the remedies (lower shares, add source addresses, or
raise the limits per the hardening guide).

**Heartbeat and view.** `StreamPlaneReport` (12.2 Lot E2) gains
`usable_source_ports` at its next free tag. `NodeBudgetView` gains
`usable_source_ports`, `session_ceiling`, `session_ceiling_bound_by`,
`udp_sessions_committed`, `over_ceiling` and a `source_pools` list
(`{ pool, committed, usable }`); `StreamBudgetView.ceiling` and
`fds_per_unit` are filled for UDP streams (`fds_per_unit: 1`). The
dashboard budget panel of 12.2 Lot F shows the ceiling, what bound it and
each UDP stream's share.

### D-f. `source_addresses` (nginx's `proxy_bind`) on UDP, and ephemeral port use

The field is Story 12.3's `source_addresses: Vec<IpAddr>` (its D-l: at
most 16 unicast literals, neither unspecified nor IPv4-mapped; Resolved
8). 12.3 refuses it on UDP until this story gives it a UDP meaning, which
it does here:

- **Choice per session**, as 12.3 chooses per attempt: the next address in
  turn (the per-stream rotating counter) whose family matches the chosen
  backend address. Rotation spreads a stream's sessions evenly over its
  addresses, which is what the pool arithmetic of D-e assumes.
- **Bind** to `address:0`, then `connect`. Unlike 12.3, no
  `IP_BIND_ADDRESS_NO_PORT`: it lets TCP share a port across destinations,
  and UDP's autobind never shares one (Dev Notes), so the option would buy
  nothing and blur the accounting.
- **`EADDRINUSE`** (the pool is exhausted, other host users included)
  tries the next address of the family; all of them failing ends the
  session `connect_failed`, counted `source_bind_failed` (12.3's counter),
  not a breaker failure. **`EADDRNOTAVAIL`** (the address is not on this
  node) is the same `source_bind_failed`.
- **No address of the backend's family**: the candidate is skipped for
  this session and counted `source_family_mismatch` (12.3's counter);
  12.3's validation refusing a list with no family in common with an
  IP-literal backend applies to UDP streams unchanged.
- An empty list leaves the source to the kernel (the `default` pool of
  D-e).

### D-g. Replies leave from the address the client targeted

A UDP stream on `0.0.0.0` or `[::]` receives on every local address, and a
reply sent from that socket with `sendto` gets the source address the
routing table picks, which on a multi-homed host is not always the one the
client sent to; the client then drops the reply. `bind_udp_group` sets
`IP_PKTINFO` (IPv4) or `IPV6_RECVPKTINFO` (IPv6, including the IPv4-mapped
traffic of a dual-stack `[::]` socket, which I am fairly sure Linux
reports through `IPV6_PKTINFO`; Lot A pins it with a test) on wildcard
listen addresses only. The receive loop then reads with `recvmsg` and
carries the destination address in `Datagram::local`, and the session
replies with `sendmsg` carrying `IP_PKTINFO` / `IPV6_PKTINFO` with that
source. A specific listen address needs neither. `local` is also the
PROXY v2 destination (D-j) and part of the session key (D-a).

### D-h. One receive buffer per worker, never one per socket or per session

The engine and the loops share **one 64 KiB scratch buffer per runtime
thread** (`thread_local!`), borrowed only between two awaits: a loop
awaits `readable()`, then `try_recv` / `recvmsg` into the buffer, calls the
synchronous handler with a borrowed slice (D-c), and releases it before
its next await. The session task does the same for responses. The stream
runtime has one worker thread (12.2 D-b), so a worker holds one buffer,
plus a second 64 KiB scratch for building a PROXY header in front of a
payload when `sendmsg` with two iovecs is not used. A 1,024-port range no
longer costs 64 MiB per worker (today's per-socket buffer), and 28,000
sessions cost no buffer at all. No datagram is ever larger than the
buffer: UDP payloads stop at 65,507 bytes.

### D-i. Selection, health and passive detection on UDP, through 12.3's seams

The UDP engine uses the seams 12.3 D-a defines and implements in
`lorica/src/stream_engine.rs`, with no second implementation:

- **`BackendSelector`** over 12.3 D-e's `select_index`. Candidates are
  12.3's: linked backends, primaries before backups (12.3 D-f, which this
  story lifts on UDP: backup links are allowed on a UDP stream),
  `health_status != Down`, `lifecycle_state == Normal`, a resolved
  address, not refused as local. Per algorithm, as 12.3 gives them:
  `round_robin` (smooth weighted, per stream), `random` (uniform),
  `consistent_hash` (ketama over the resolved `ip:port`, weighted, keyed
  on the **canonical client IP as text**, exactly 12.3's key; the /64 of
  D-d is for caps and rates, not for balancing), and `least_conn` read as
  **least sessions**: the selector's per-process `BackendConnections`,
  told of a session's start and end through the same connect and close
  hooks 12.3 uses per connection, once per session, never per datagram.
  `peak_ewma` is **refused** on a UDP stream at validation: there is no
  connect latency to feed the selector's tracker, and a request-to-response
  time would measure the protocol's think time.
- **`BreakerGate`**, the breaker keyed (`"stream:" + stream_id`, backend
  address as configured), coordinated across workers by the supervisor's
  registry (12.3 D-g). Order as 12.3: select one candidate, then
  `admit`; a `Deny` removes it for this session and selection runs again.
  An `AllowProbe` makes the session the probe; its outcome is reported
  with `was_probe = true`. Fail open on an RPC timeout, as 12.3.
  - **Failure**: an ICMP error on the session socket (`ECONNREFUSED`,
    `EHOSTUNREACH`, `ENETUNREACH`), or a session that reaches its idle
    timeout with `K >= 1` having received no response at all.
  - **Success**: the session's first response.
  - **Not reported**, as 12.3 D-g: a local-address refusal, an unresolved
    name, a failed source bind, a session drained before any outcome.
- **No retry.** A session is never moved to another backend once its
  first datagram is sent (the UDP twin of 12.3's "never retried once
  bytes have flowed"); there is no handshake that could fail first.
  Selection before that (a `Deny`, a family mismatch, a local refusal)
  re-selects as 12.3 D-h does, bounded by the candidate list; with none
  left the session ends `no_healthy_backend`.
- **Health.** A UDP backend has active checks off until Story 12.14
  (12.1 AC #4). 12.3 D-i's `refresh_tables` on a health flip reaches the
  UDP engine through `table_changed`, and its `backend_down` drain
  (`close_on_backend_down` in the accepted snapshot, backend `Down` in the
  new table) applies to sessions, which register in the tracker with
  `set_backend` like connections.
- **Local backends** (12.3 D-m): 12.3's connect-time check, with the
  node's interface set, `ReservedPorts` and `Datagram::bound_ports`, runs
  at every session creation against the resolved address, before
  `connect`; a refusal is counted `local_destination_refused` and is not a
  breaker failure. 12.3's IV4 reading (a name resolving to a local address
  leaves that stream's candidates) holds for UDP streams unchanged.
- **Resolution** (12.3 D-n): the same per-process `ResolverCache`, shared
  by both engines (Interface edit E3).

### D-j. PROXY protocol v2 over UDP, per datagram (AC #7)

When the stream's `proxy_protocol_send` (12.3 D-j, `StreamProxyProtocol`)
is `v2`, **every** datagram to the backend is prefixed with a complete v2
header: command `PROXY`, transport `DGRAM` over `AF_INET` (`0x12`) or
`AF_INET6` (`0x22`), source the client address and port, destination
`Datagram::local` (the address the client targeted, D-g), both
canonicalised, no TLV. Each header is 28 bytes (IPv4) or 52 bytes (IPv6).
A session's client and local address never change, so the header is
**encoded once at session creation** and kept with the session; every
datagram then goes out as one `sendmsg` with two iovecs (header, payload),
so nothing is allocated or copied per datagram. A payload whose length
plus the header exceeds 65,507 is dropped as `request_oversize`. Responses
carry no header. `v1` is refused on a UDP stream at validation: the v1
text format has no UDP transport. The client and local addresses always
share a family once canonicalised (one socket received the datagram, and
a dual-stack socket reports both IPv4-mapped), so the `AF_UNSPEC`
fallback 12.3 D-j needs for carried addresses cannot arise here; a test
pins it for a dual-stack `[::]` stream. 12.3 Lot A's `encode_v2` encodes
transport `STREAM` only; this story adds `encode_v2_dgram(source,
destination) -> Vec<u8>` beside it in the same module (Interface edit
E4). `docs/streams.md` states the convention (one header per datagram, no
session-level header, which is how receivers that accept PROXY on UDP
expect it) and lists the receivers known to accept it. The list is written
from each product's own documentation at Lot H time and only names what
was verified there; the candidates are dnsdist, PowerDNS Recursor, Knot
Resolver and Unbound.

### D-k. The listen-address rule (AC #3) and its documented maximum

A UDP stream whose `listen_address` is not in `127.0.0.0/8`, `::1`,
`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` or `fc00::/7` is
**exposed**. An unspecified address (`0.0.0.0`, `[::]`) is exposed: it
binds every address of the host, public ones included. Link-local and
shared address space (100.64.0.0/10) are exposed too, as the PRD reads
literally. An exposed UDP stream is refused unless it has a source
allowlist (Story 12.6 AC #1) or an **explicit** `source_session_cap` at or
below `UDP_EXPOSED_SOURCE_SESSION_CAP_MAX` = **64**. The default per-source
cap (256, D-l) does not count: it is absent from the stored stream
(`None`), so the rule makes the operator choose a number on purpose, as D6
says.

Why 64: it bounds how many upstream sockets one spoofed address can pin on
a node (64 fds, 1.5 % of a default share), while leaving room for a NATed
site with dozens of queries in flight.

The rule is one pure function, `udp_exposure_check(stream,
has_source_allowlist: bool)` in `lorica-config/src/models/stream.rs`,
called by `Stream::validate` with `false` until Story 12.6 adds the
allowlist and passes the real value. The refusal names the address, the
rule and both remedies. No release carries the interim: 12.6 lands in the
same cycle.

### D-l. The new fields: one `udp` object on `Stream`, absent on TCP, and 12.3's fields on UDP

`Stream` gains `udp: Option<UdpSettings>`, required (filled with the
defaults on create when omitted) for `protocol = udp` and refused for
`tcp`, so no UDP field is ever stored on a TCP stream or ignored on one.
Stored as columns of `streams` (NULL on TCP rows), added by one migration
at **the next free number at implementation time** (after 73, after 12.2
Lot E1's subscription migration and after 12.3 D-q's, expected 76 if
those take 74 and 75; recorded in the Completion Notes), read through
`STREAM_COLUMNS`. Carried by the
canonical config inside format 3 with `#[serde(default)]` and a deliberate
`CANONICAL_SHAPE_DIGEST` update (12.1 D-3), by the TOML export and import,
by `compute_diff`, and by `StreamResponse` field by field (12.1 D-10).

| Field | Default | Range | What it bounds | Survey (PRD, 2026-09-28) |
|---|---|---|---|---|
| `udp.max_sessions` | 4,096 | 1 to 1,048,576, and the node ceiling (D-e) | total sessions per stream per node, the stream's share | not surveyed as a per-listener default |
| `udp.source_session_cap` | `null`, meaning 256 | 1 to 65,535; at most 64 to satisfy D-k | concurrent sessions per source key per node, plus at most W - 1 (D-d) | nginx `limit_conn` (no default); HAProxy Enterprise and Envoy not surveyed for UDP |
| `idle_timeout_s` (12.3's field) | **10 on a UDP stream** (600 on TCP) | 1 to 3,600 on UDP | a session with no datagram either way | Traefik 3 s, HAProxy Enterprise 10 s, caddy-l4 30 s, Envoy 1 min; nginx `proxy_timeout` 10 min |
| `udp.requests_per_session` | 64 | 1 to 65,535, or `null` (no bound) | client datagrams per session before it is retired (D-b) | nginx `proxy_requests`, default 0 (unbounded) |
| `udp.responses_per_request` | 1 | 0 to 64; 0 = no response expected | backend datagrams forwarded per client datagram | nginx `proxy_responses` (unbounded unless set); HAProxy Enterprise exposes a bound; Traefik, Envoy, caddy-l4 none |
| `udp.response_bytes_ratio` | **32** | 1 to 64 | response bytes forwarded per request byte, per session | no surveyed product bounds bytes (D6 extends the field here) |
| `udp.unbounded_responses` | false | | lifts the two response bounds (AC #4) | |
| `udp.source_datagram_rate` | 1,000 /s | 1 to 1,000,000 | client datagrams per second per source key per node, burst one second | none in the survey |
| `udp.source_byte_rate` | 524,288 B/s (512 KiB/s) | 1,024 to 1,073,741,824 | client bytes per second per source key per node, burst one second | none in the survey |
| `udp.max_datagram_bytes` | 8,192 | 512 to 65,507 | payload size, both directions (AC #8) | not surveyed |

The idle timeout is 12.3's one `idle_timeout_s` field, not a second
UDP-only one: an operator reads one idle setting per stream. Its default
depends on the protocol, filled by the create path (and by the migration
for UDP rows that exist when it runs); its UDP range stops at 3,600 s, the
TCP one at 86,400 s (Interface edit E1).

Notes the docs carry next to the table:

- **`response_bytes_ratio` and DNS (Resolved 2).** DNS is a headline UDP
  use case: a DNSSEC or large TXT answer (DKIM keys) to a query of about
  50 bytes, inside the 1,232-byte EDNS buffer the 2020 DNS flag day
  recommends, is about 25 times the query. The default of 32 serves it, so
  a validating resolver or a mail server behind Lorica works on the first
  day. What it gives up: a default UDP stream may amplify up to 32 times
  in bytes for one response. The hard limits on reflection stay the
  per-source rates and the reflection bound below, which do not move with
  the ratio. A response over the allowance is dropped and counted
  `response_byte_bound`, never silently; a stream that never needs large
  answers (RADIUS, NTP) lowers the ratio.
- **`responses_per_request = 0`** is the setting for one-way protocols
  (syslog); `unbounded_responses` is the setting for stateful protocols
  (games, VoIP signalling, where responses are not answers).
- **`requests_per_session = null`** is allowed without a badge: the
  request bound shortens a session's life, it does not bound reflection,
  which is the response bounds' job.
- **With `unbounded_responses`**, `responses_per_request` and
  `response_bytes_ratio` keep their stored values and are not applied;
  the response shows them beside the flag, and clearing the flag applies
  them again (Resolved 6).
- **The reflection bound (IV1's "documented bound").** Towards one source
  key, per node, per second, Lorica forwards at most

  `B = min(source_byte_rate x response_bytes_ratio,
           source_datagram_rate x responses_per_request x max_datagram_bytes)`

  response bytes, plus one second's worth again as burst (the rate cells'
  burst). With the defaults: `min(524,288 x 32, 1,000 x 1 x 8,192)` =
  `min(16,777,216, 8,192,000)` = **8,192,000 bytes per second** (about
  7.8 MiB/s, 65.5 Mbit/s), at most 16,384,000 bytes in any one second
  including the burst. `B` is the worst case over request sizes: with
  requests averaging `a` bytes, at most `min(32 x 1,000 x a, B)` bytes per
  second come back, so `B` is reached only by requests of 256 bytes or
  more, and small requests reflect at most 32 times their own bytes, which
  the per-session ratio enforces whatever the rates. Across a fleet the
  bound is per node that binds the stream. `docs/streams.md` gives the
  formula and the computed default, and the threat model says that the
  per-source controls bound reflection only per source key and per node,
  never per victim network.

**Fields of Story 12.3 on a UDP stream.** 12.3 D-q makes every one of its
fields hold its default on a UDP stream, refuses backup links there, and
leaves to this story the ones it gives a UDP meaning. This story lifts:
`load_balancing` (without `peak_ewma`, D-i), `idle_timeout_s` (UDP
default and range above), `total_timeout_s`, `close_on_backend_down`,
`allow_local_backend`, `proxy_protocol_send` (`off` or `v2`, D-j),
`source_addresses` (D-f), and backup links. These keep 12.3's
"must hold its default on a UDP stream" rule: `connect_timeout_ms`,
`max_connect_attempts`, `backend_keepalive`, `backend_keepalive_idle_s`,
`upload_rate_bps`, `download_rate_bps`, `max_connections` (the UDP cap is
`udp.max_sessions`, per node and exact, where 12.3's is per worker until
Story 12.6), `proxy_protocol_trusted_cidrs`; and `proxy_protocol_accept`
stays refused on UDP for good (12.3 D-k).

**The flag on every surface (AC #4).** The management API returns
`udp.unbounded_responses`; `openapi.yaml` documents it. The automation
`streams:read` resource, the MCP read tools and the dashboard badge are
Story 12.10's (its AC #1 lists the badge; D9 already keeps every write of
it off the automation and MCP surfaces, since streams have no write scope
there). AC #4 is checked off when 12.10 lands, as 12.2 did for its
failed-bind badge (12.2 Resolved #5).

### D-m. UDP bindings drain with their sockets open (amends 12.2 D-g for UDP)

A UDP session can only be served through the slot socket its client
reaches, and a reply can only leave through it. 12.2's `detach` closes the
binding's sockets at once, which for UDP would end every session the
moment AC #8 of 12.2 promises them a drain. So for a UDP binding:

- **`detach`** (stream deleted, disabled, rebound, node deselected): the
  receive loops switch to **drain mode**: datagrams of existing sessions
  are forwarded, a datagram that would open a session is dropped and
  counted `binding_draining`, and no session is created. Sessions are
  marked draining with `config_removed` as today. A worker closes its slot
  sockets when the binding's last session ends or at the drain deadline,
  whichever comes first. The `ack` count of a UDP `detach` is the sockets
  put in drain.
- **The supervisor** closes its own copies at once (as today) and keeps
  the binding in its registry as `draining` until `deadline + 2 s`, so the
  UDP overlap rule of the reconcile diff keeps treating the port as held
  until every worker has let it go. A rebind of the same address and port
  waits for that through the existing `address_in_use` retry. *Cost
  (Resolved 4):* an edit that rebinds a UDP stream on the same port (a
  listen-address change that keeps the port) leaves it unserved for new
  clients for up to `worker_drain_timeout_s` plus the 10 s retry interval;
  `docs/streams.md` says so and recommends a short drain where UDP rebinds
  are common.
- **`quiesce reason=shutdown`**: the same drain mode, ending with
  `node_shutdown`.
- **`refresh`** (a backend removed): unchanged, the sockets stay, the
  sessions to that backend drain.
- **Hot upgrade** is Story 12.11's, see "Handed to later stories".

### D-n. Counters for Story 12.9, kept by the engine

In 12.3 D-r's `StreamCounters` (`lorica_stream::counters`, one per
process, snapshot through `StreamRuntimeHandle::counters()`), not a second
structure. Atomics only, no label carries a client address. A UDP stream
uses 12.3's words with their session meaning, and adds its own:

- reused per stream: `active` (live sessions in this process), `accepted`
  (sessions created), `ended` per `StreamEndKind`, `refused` per
  `StreamRefusal`, `bytes_upload` (client to backend) and
  `bytes_download` (backend to client), counted on what is forwarded,
  `breaker_denied`, `local_destination_refused`,
  `source_family_mismatch`, `source_bind_failed`;
- reused per (stream, backend): `active`, `connects` (sessions opened on
  it), `connect_failures` per kind (`refused` and `unreachable` from ICMP;
  the no-response failure of D-i counts as a new kind `no_response`);
- added per stream: `datagrams_upload`, `datagrams_download`, `dropped`
  per `DatagramDropReason`, a new closed enum in
  `lorica-config/src/models/stream.rs` (`request_oversize`,
  `response_oversize`, `source_datagram_rate`, `source_byte_rate`,
  `response_count_bound`, `response_byte_bound`, `binding_draining`,
  `send_failed`) with `strum::VariantArray` so every surface derives the
  word list (`.claude/rules/derived-not-transcribed.md`), and
  `ceiling_reached` (below).
- not used on UDP: `connect_attempts`, `retries`, `proxy_header`, the
  connect-latency histogram (there is no connect to time).

`StreamRefusal` gains `session_cap`, `source_session_cap`,
`session_table_full`. A datagram whose session is refused is counted once,
as the refusal, never also as a drop. **Active sessions per node** are read
by the supervisor from each region's `total`, exact, so the one gauge
Story 12.9 needs does not depend on aggregating gauges across workers.
**The "UDP ceiling reached" edge** (12.9 AC #5): the first `session_cap`
refusal after the stream was below 90 % of `max_sessions` raises
`ceiling_reached` once; it re-arms below 90 %. The engine exposes a
snapshot of all of it; Story 12.9 turns it into Prometheus series, log
rows and the alert.

**Session records** are 12.3 D-r's connection record, handed to the same
`ConnectionObserver`: stream id and name, `bind_gen`, client address,
socket peer (the same for UDP), `proxied_from` (always none: PROXY accept
is refused on UDP), local address (`Datagram::local`), backend id and the
address used, attempts (1), bytes each way, accepted (first datagram),
connected (upstream socket connected, the same instant) and ended
instants, end reason. The record gains `datagrams_upload` and
`datagrams_download` as `Option<u64>`, `None` on TCP (Interface edit E6).
No second record type.

## Tasks

Lots with hard file allowlists. A Lot touches only its files; two Lots
that share a file are sequential, never parallel, and say so. Every Lot
that runs cargo ends on a tree that passes the gate chain CI runs
(`cargo fmt --all -- --check`, the workspace clippy with `--all-targets
--features lorica/otel -- -D warnings` under `CARGO_BUILD_WARNINGS=deny`,
`cargo test --workspace` or the CI per-crate lines, `cargo audit`), through
Docker on Linux. No agent runs `git checkout`, `git restore` or
`git stash`. No new dependency: nix, socket2 and tokio are already in
the workspace, and `lorica-shmem` carries its own SipHash (`hash.rs`).

**Order.** A and B first, in parallel (no dependency outside this story).
C after 12.3 Lot B (same files). D after A, B, C and 12.3 Lot C (12.3's
engine Lot edits `handler.rs`, `listener.rs`, `runtime.rs`, `table.rs`
and creates `counters.rs`). E after D, after 12.3 Lot A (the encoder
file) and 12.3 Lot D1 (the shared selection). F after E and after 12.3
Lot D2 (`stream_engine.rs`, `worker.rs`, `single.rs`). G after C, after
12.2 Lots E2 and E3 and after 12.3 Lot E (`streams.rs`, `openapi.yaml`).
J after G and 12.2 Lot F. H after F and G. I after F, G and 12.3 Lot G
(the `streams` profile both extend).

### Lot A: sockets, ports and the caps message (`lorica-worker`) - cargo

Allowlist: `lorica-worker/src/fd_passing.rs`, `lorica-worker/src/stream_ctl.rs`,
`lorica-worker/src/stream_sockets.rs`, `lorica-worker/tests/stream_ctl.rs`,
`lorica/src/startup/worker.rs` (the exhaustive `FdKind` match arm only).
Depends on: nothing.

- [x] `FdKind::StreamCaps { caps_gen }` (`stream-caps:<caps_gen>`) with
      token round trip; `recv_listener_fds` filters it; the arm in
      `run_worker`'s match closes a stray one with a warning, like
      `StreamSocket`.
- [x] `StreamCtlMsg::Caps { seq, stream_id, caps_gen, slot }` with exactly
      one fd; encode/decode; a count mismatch closes what arrived.
- [x] `bind_udp_group`: `IP_PKTINFO` / `IPV6_RECVPKTINFO` on unspecified
      addresses only.
- [x] `usable_udp_source_ports()`: range size from
      `/proc/sys/net/ipv4/ip_local_port_range`, minus reserved ports in it
      (`ip_local_reserved_ports`, comma and range syntax), minus
      `EPHEMERAL_PORT_MARGIN` (1,024), saturating; a parse failure is an
      error the caller reports, never a guessed figure.
- [x] `BindFailureKind::SourcePorts` (`source_ports`).
- [x] Tests (Linux): `caps` round trip with a memfd; reserved-port parsing
      (single ports, ranges, outside the range, empty); `[::]` with
      `IPV6_RECVPKTINFO` reports the IPv4 destination of an IPv4 datagram
      (pins the D-g assumption; if it fails, set `IP_PKTINFO` on the v6
      socket as well and pin that).

### Lot B: the stream-caps region (`lorica-shmem`) - cargo

Allowlist: `lorica-shmem/src/**`.
Depends on: nothing. Parallel with A.

- [x] Factor the probe logic of `AtomicHashTable<N>` into functions over
      a slot slice, `AtomicHashTable<N>` delegating to them; the WAF
      tables' behaviour and every existing test unchanged.
- [x] `stream_caps.rs`: `StreamCapsRegion::create(max_sessions, workers,
      caps_gen)` (memfd, `ftruncate`, map, header, fresh SipHash key) and
      `open(fd)` (verify magic, `STREAM_CAPS_LAYOUT_VERSION`, sizes against
      the file size); `layout_for(max_sessions, workers)` as a pure
      function the budget and the docs use.
- [x] `admit_session(slot, source_key, source_cap, stream_cap) ->
      Result<SessionPermit, CapRefusal>` (exact total with rollback,
      shard sum check, own-shard claim, `TableFull`), `SessionPermit`
      releasing on drop (shard count, slot released at 0 by its owner,
      total and attribution); `charge_rate(source_key, bytes, now) ->
      RateVerdict` (GCRA on both arrival times, claim on first use,
      `TableFull`); `release_worker(slot)`; `evict_rates(now) -> stats`
      (released only when both times are past and no shard holds the
      key); `total()`.
- [x] Source key derivation: IPv4 address, IPv6 /64, IPv4-mapped
      canonicalised first.
- [x] Tests: exact total under 8 threads at the cap; shard overshoot never
      above W - 1 (8 threads hammering one source); a held key is never
      released by `evict_rates` however old; `release_worker` restores
      `total` and empties the shard; GCRA admits one second of burst then
      the rate (fake clock); `TableFull` on a small table with colliding
      keys; a second process (`fork`) sees the same counts through `open`;
      version and size mismatches are refused.

### Lot C: the model, its storage and validation (`lorica-config`) - cargo

Allowlist: `lorica-config/src/models/stream.rs`, `lorica-config/src/models/mod.rs`,
`lorica-config/src/store/streams.rs`, `lorica-config/src/store/mod.rs`
(the migration only), `lorica-config/src/canonical.rs`,
`lorica-config/src/diff.rs`, `lorica-config/src/export.rs`,
`lorica-config/src/import.rs`.
Depends on: 12.3 Lot B (same files; the fields of 12.3 D-q must exist).

- [ ] `UdpSettings` with the fields, defaults and ranges of D-l as
      associated constants; `Stream.udp`; validation: required for UDP
      (defaults filled by the create path), refused for TCP, ranges.
- [ ] 12.3's fields on UDP (D-l): lift the "must hold its default" rule
      for the fields this story gives a UDP meaning and for backup links;
      `peak_ewma` and `proxy_protocol_send = v1` refused on UDP;
      `idle_timeout_s` with its protocol default (10 UDP, 600 TCP) through
      one `Stream::default_idle_timeout_s(protocol)` the create path, the
      import and the migration use, and its UDP range (Interface edit E1).
- [ ] `udp_exposure_check` (D-k) with
      `UDP_EXPOSED_SOURCE_SESSION_CAP_MAX = 64`, called from
      `Stream::validate` with `has_source_allowlist = false`.
- [ ] `StreamRefusal::{SessionCap, SourceSessionCap, SessionTableFull}`;
      `DatagramDropReason` with `VariantArray`; the two end-reason doc
      comments reworded (D-b).
- [ ] Migration at the next free number: the UDP columns on `streams`,
      NULL for TCP rows, idempotent; existing UDP rows get the defaults,
      including `idle_timeout_s = 10` where it still holds 12.3's 600.
- [ ] Canonical (`#[serde(default)]`, shape digest moved on purpose, a
      blob without `udp` decodes), diff, export and import.
- [ ] Tests: every bound at both ends and one past; exposure rule over
      each private range, loopback, ULA, `0.0.0.0`, `[::]`, a public v4
      and v6, with the cap absent, at 64 and at 65; refusal words derived
      from the enums.

### Lot D: budget, receive path, caps adoption, drain mode (`lorica-stream`) - cargo

Allowlist: `lorica-stream/src/budget.rs`, `lorica-stream/src/handler.rs`,
`lorica-stream/src/listener.rs`, `lorica-stream/src/runtime.rs`,
`lorica-stream/src/state.rs`, `lorica-stream/src/table.rs`,
`lorica-stream/src/lib.rs`, `lorica-stream/tests/runtime.rs`,
`lorica-stream/Cargo.toml` (`lorica-shmem` path dependency), `Cargo.lock`.
Depends on: A, B, C; 12.3 Lot C (same files).

- [ ] Budget (D-e): `lorica_stream::held_fds(&Stream)` dispatching to
      12.3's `tcp::held_fds` and the new `udp::held_fds` (Interface edit
      E5; the callers switch in Lots F and G);
      `NodeBudgetInputs.usable_source_ports`; `BudgetViolation::SourcePorts`
      with pools from `source_addresses`; the supervisor memfd per UDP
      stream; the node ceiling with `bound_by`, `over_ceiling` (refuse
      raises, allow lowers), the view fields.
- [ ] `DatagramHandler` synchronous with `Datagram<'_>` (D-c), `local`
      from `IP_PKTINFO` on wildcard sockets (D-g), `bound_ports` filled by
      the receive loop as 12.3's accept loop fills it, and the defaulted
      `table_changed` called by the runtime after every reload, as for
      `StreamHandler`.
- [ ] One thread-local scratch buffer per runtime thread (D-h); the
      per-socket buffer and the per-datagram `Vec` are gone.
- [ ] The `caps` message: map the region, hand it to the engine through a
      `CapsRegistry` the engine reads (stream id to current region and
      slot); `nack adopt_failed` on a bad region.
- [ ] Drain mode of D-m for UDP bindings on `detach` and `quiesce`; the
      `ack` count; sockets closed at last session or deadline.
- [ ] Tests: budget with UDP shares at the packaged limit and at the
      default range (six default streams fit, the seventh is refused with
      `source_ports`), with two source addresses, with a narrowed
      range (`over_ceiling`); the loop never allocates per datagram (one
      buffer for a 64-port range, asserted by a counting allocator or by
      construction); drain mode forwards an existing session's datagram
      and drops a new client's with `binding_draining`; sockets close at
      the last session.

### Lot E: the UDP engine (`lorica-stream`) - cargo

Allowlist: `lorica-stream/src/udp/**` (new: `mod.rs`, `engine.rs`,
`session.rs`), `lorica-stream/src/counters.rs` (the UDP additions of
D-n), `lorica-stream/src/handler.rs` (the record's datagram fields,
Interface edit E6), `lorica-stream/src/lib.rs`,
`lorica-stream/tests/udp_engine.rs` (new),
`lorica-core/src/protocols/proxy_protocol.rs` (`encode_v2_dgram` and its
round-trip tests only, Interface edit E4),
`fuzz/fuzz_targets/fuzz_proxy_protocol.rs` (the new function in 12.3 Lot
A's round-trip arm), `FORK.md` (the parser's divergence entry names the
new function), and, only if
12.3 has not placed them protocol-neutral, the move of
`lorica-stream/src/tcp/{seams,resolver,local}.rs` to
`lorica-stream/src/{seams,resolver,local}.rs` with their `use` sites
(Interface edits E2 and E3).
Depends on: D; 12.3 Lots A, C and D1.

- [ ] The move of E2 and E3 first, as a `refactor(proxy)` commit of its
      own with no behaviour change, if 12.3 left the modules under `tcp`.
- [ ] `encode_v2_dgram` beside `encode_v2`; every encoded header parses
      back to the same addresses and transport.
- [ ] `UdpEngine: DatagramHandler`: oversize, rate charge, session lookup,
      admit (region of D-d), selection and admission through
      `BackendSelector` and `BreakerGate` (D-i), local check, upstream
      socket (D-a, D-f), the session's PROXY v2 header (D-j), `try_send`,
      session task spawn, tracker registration and `set_backend`,
      `table_changed` pruning.
- [ ] Session task: readiness on the upstream socket, response bounds of
      D-b, `sendmsg` with the reply source (D-g), idle and total timers,
      tracker close, ICMP handling, breaker reports, the connection record
      to the `ConnectionObserver`, permit release.
- [ ] Counters of D-n in `StreamCounters` and the `ceiling_reached` edge.
- [ ] Tests (loopback, Linux): each end of D-b (`K = 1` closes on the
      answer with `response_bound_reached`; `R` retires and a pipelined
      client opens a second session; `K = 0` ends at `R`; byte bound drop
      and close; idle; total; ICMP before and after a response);
      `unbounded_responses` lifts both bounds; oversize both ways; the
      exact PROXY v2 bytes for IPv4 and IPv6 and the 65,507 limit; each
      refusal (`session_cap`, `source_session_cap`, `session_table_full`)
      counted once; the never-blocking property of D-c (black-holing
      backend, full send buffer, a second client still served); a reply
      to a client that sent to `127.0.0.2` on a `0.0.0.0` stream leaves
      from `127.0.0.2` (the client uses a socket connected to it);
      consistent hash keeps one client address on one backend; least
      sessions; a breaker `Deny` re-selects without opening a socket; an
      ICMP refusal and a no-response idle each report one failure, a first
      response one success; the record carries datagram counts and
      `proxied_from` none; a dual-stack `[::]` stream's v2 header carries
      IPv4 addresses for an IPv4 client.

### Lot F: supervisor and single-process wiring (`lorica`) - cargo

Allowlist: `lorica/src/startup/stream_plane.rs`, `lorica/src/startup/worker.rs`,
`lorica/src/startup/single.rs`, `lorica/src/startup/supervisor.rs`,
`lorica/src/stream_engine.rs` (one `ResolverCache` and one selector per
process handed to both engines, Interface edit E3), `lorica/Cargo.toml`,
`Cargo.lock`.
Depends on: E; 12.3 Lot D2 (same files).

- [ ] Regions: create per UDP stream on first bind, `caps` before
      `attach`, replace on a size change, retire at `total == 0`, the
      supervisor memfd counted; single-process over the in-process
      transport.
- [ ] Respawn: `release_worker(slot)` on every live region of the slot,
      then `caps` replay, then the `attach` replay of 12.2 D-a.
- [ ] A 1 s stream-caps tick: `evict_rates` on every region, retired
      regions dropped.
- [ ] The UDP `draining` registry state and its expiry (D-m).
- [ ] Node backstop: the D-e check before every bind through
      `lorica_stream::held_fds` in the driver's `demand_of`,
      `source_ports` failure kind, `usable_udp_source_ports` read at each
      reconcile.
- [ ] Install `UdpEngine` in `Engines.udp` in `run_worker` and
      `run_single_process`.
- [ ] Tests against 12.2's fake transport: `caps` precedes `attach`;
      respawn order (release, `caps`, `attach`); a size change sends a new
      `caps` and keeps the old region until its total is 0.

### Lot G: API and heartbeat - cargo

Allowlist: `lorica-api/src/streams.rs`, `lorica-api/src/streams/tests.rs`,
`lorica-api/src/stream_budget.rs`, `lorica-api/openapi.yaml`,
`lorica-cluster/src/messages.rs`, `lorica-cluster/proto/cluster.proto`,
`lorica/src/startup/cluster_follower.rs`.
Depends on: C; 12.2 Lots E2 and E3 and 12.3 Lot E (same files).

- [ ] `StreamResponse.udp` field by field (the key-set test of 12.1 D-10
      moves with it); create fills the defaults; refusals as `400` with
      the rule's text.
- [ ] Budget check on create and update with the D-e constraints, per
      reporting targeted node; `usable_source_ports` on
      `StreamPlaneReport` at its next free tag, decode test without it.
- [ ] `openapi.yaml`: the `udp` object with bounds and defaults, the
      refusal and drop words from their enums, the budget fields, and
      `source_ports` in the `StreamBindFailureKind` enum (Lot A added the
      kind; nothing pins that enum to `BindFailureKind::ALL` yet, so this
      Lot derives or tests it); contract test green.

### Lot J: dashboard budget panel - frontend gates

Allowlist: `lorica-dashboard/frontend/src/lib/api.ts`,
`lorica-dashboard/frontend/src/components/StreamBudget.svelte` (+ `.test.ts`).
Depends on: G; Story 12.2 Lot F (same files).

- [ ] Types (the bind failure-kind union gains `source_ports`); the
      panel shows the node ceiling, `bound_by`, `over_ceiling`,
      the source pools and each UDP stream's share; Vitest for each.
- [ ] The stream form and the unbounded-responses badge are Story 12.10's
      (D-l); nothing here.

### Lot H: documentation - no cargo

Allowlist: `docs/streams.md` (the UDP sections), `docs/security/threat-model.md`
(UDP reflection and amplification), `docs/security/hardening-guide.md`
(raising UDP session capacity), `docs/architecture/worker-shared-state.md`
(the stream-caps region), `docs/BUMP-CHECKLIST.md`,
`.claude/skills/bump-version/bump-checklist.md` (the region version line,
both copies), `CHANGELOG.md`.
Depends on: F and G (documents what was built).

- [ ] `docs/streams.md`: the D-l table with the survey column, the session
      lifecycle of D-b, the reflection bound, the capacity formula
      (`max_sessions / idle_timeout_s` sessions per second for a protocol
      whose backend never answers; IV2 shows why answered request/response
      traffic goes past it), the node ceiling and its preconditions
      (`LimitNOFILE`, wider `ip_local_port_range`, several
      `source_addresses`), the per-source cap formula
      `source_session_cap + (W - 1)`, the region memory figures, the
      listen-address rule, the
      PROXY v2 convention and the verified receivers, reply source on
      wildcard addresses, drain mode and the rebind gap, the upgrade
      overlap.
- [ ] Threat model: reflection and amplification (what is bounded, by
      which field, per node; the random-source table fill and its
      mitigations; per-source controls are courtesy, D6).
- [ ] `CHANGELOG.md` `[Unreleased]`: Added (UDP streams), Security (the
      default bounds).

### Lot I: end-to-end, IV1 and IV2 - Docker e2e

Allowlist: `tests-e2e-docker/test-runner/run-streams-udp-smoke.sh` (new,
LF), `tests-e2e-docker/test-runner/udp_tools.py` (new, LF, Python
standard library only: a spoofing sender over a raw socket, an amplifying
UDP backend, a minimal DNS responder, a DNS load generator matching ids),
`tests-e2e-docker/test-runner/Dockerfile` (the `COPY` and `chmod` lines),
`tests-e2e-docker/docker-compose.yml`, `tests-e2e-docker/run.sh`.
Depends on: F, G; 12.2 Lot H's `streams` profile and 12.3 Lot G (which
extends it too; sequential on `docker-compose.yml`). The machine to
itself, orphan containers torn down first.

- [ ] **IV1.** Services on one compose network (RFC 1918, so the default
      stream passes D-k): Lorica in worker mode (2 workers) with a UDP
      stream at default settings in front of an amplifying backend that
      answers every request with 10 datagrams of 1,800 bytes (within the
      1,920-byte allowance a 60-byte request earns at ratio 32, so the
      count bound and not the byte bound is what holds it); a `victim`
      container recording bytes per second received from Lorica; a
      `spoofer` (root, `cap_add: NET_RAW`) sending 60-byte datagrams with
      the victim's address as source and random source ports at 20,000
      per second for 30 s; a legitimate client on another address sending
      one request every 100 ms. Expected with the defaults: at most about
      1,000 accepted requests per second from the victim's key, one
      response each, so about 1.8 MB/s at the victim. Assert: the 30 s
      mean at the victim is at most the documented bound `B` = 8,192,000
      bytes per second and every 1 s window at most `2 x B` (bound plus
      burst); the victim's bytes are at most 32 times the request bytes
      Lorica accepted from that source key and its datagrams at most 1 per
      accepted request (read from the counters); `source_datagram_rate`
      and `response_count_bound` drops are non-zero; the legitimate client
      gets every answer.
- [ ] **Byte bound.** The same flood against a backend answering one
      datagram of 4,000 bytes: every response exceeds the 1,920-byte
      allowance, the victim receives nothing, and the drops are
      `response_byte_bound`.
- [ ] **Table isolation (AC #5).** The spoofer switches to random source
      addresses on stream A; a second UDP stream B keeps serving a
      client, and A's refusals are `session_table_full` only.
- [ ] **IV2.** Two DNS responders behind a UDP stream at default settings;
      the load generator sends at twice the capacity formula
      (`2 x 4,096 / 10` = 820 queries per second, under the default
      per-source rate) for 60 s across 64 source ports from one address.
      Assert: every query answered within 2 s, zero refusals, zero drops,
      zero `idle_timeout` ends, every end `response_bound_reached` or
      `request_bound_reached`, and the session gauge far below
      `max_sessions`.
- [ ] **Reply source.** A stream on `0.0.0.0`; a client sends to a second
      address of Lorica's container and receives the reply from it.
- [ ] **Worker death.** `kill -9` one worker under IV2's load: the region
      `total` returns to the live sessions (no leaked count), and the
      respawned worker serves its slot's clients.
- [ ] **Budget.** `ulimits: nofile` set so that two default UDP streams
      exceed the fd constraint: the second is refused naming `worker_fds`
      and the numbers.

## Interface with Story 12.3

Aligned with the 12.3 draft (`docs/stories/story-12.3-tcp-engine.md`,
Draft, 2026-11-14). First what this story uses as 12.3 defines it, then
every mismatch as a concrete edit, naming the story that makes it.

### Used as 12.3 defines it

- **Seams** (12.3 D-a), implemented once in `lorica/src/stream_engine.rs`:
  `BackendSelector` (pick one candidate, learn of connects and closes),
  `BreakerGate` (`admit(stream_id, backend) -> Admission`,
  `record(stream_id, backend, success, was_probe)`), `Resolve`. UDP calls
  the selector's connect and close hooks once per session (the
  least-sessions count) and never feeds an EWMA sample (`peak_ewma` is
  refused on UDP).
- **Selection** (12.3 D-e): `select_index`, candidates, smooth WRR per
  stream, ketama keyed on the canonical client IP as text, per-process
  `BackendConnections`; select then admit, `Deny` re-selects.
- **Breaker key** (12.3 D-g): (`"stream:" + stream_id`, backend address
  as configured), the supervisor's registry, thresholds 5 and 10 s, fail
  open. UDP's failure and success signals are D-i's.
- **Backups** (12.3 D-f): `StreamBackend.backup`, primaries first, at
  least one primary.
- **Health and drains** (12.3 D-i): `StreamTable::with_backends`,
  `refresh_tables` on a flip, `table_changed`, the `backend_down` drain.
- **Local backends** (12.3 D-m): `is_local_ip`, rules A and B, the
  connect-time check with `ReservedPorts` from `--reserved-ports`,
  `BoundPorts`.
- **Resolution** (12.3 D-n): the per-process `ResolverCache`, TTL clamped
  to 5 to 60 s, last good list kept.
- **Fields** (12.3 D-q): `load_balancing`, `idle_timeout_s`,
  `total_timeout_s`, `close_on_backend_down`, `allow_local_backend`,
  `proxy_protocol_send` (`StreamProxyProtocol`), `source_addresses`
  (Resolved 8: the list nginx calls `proxy_bind`, at most 16), and the
  "must hold its default on a UDP stream" rule for the rest (D-l).
- **Counters and record** (12.3 D-r): `StreamCounters`,
  `StreamRuntimeHandle::counters()`, the connection record and
  `ConnectionObserver`.
- **Refusals:** 12.3 adds `connection_cap`; this story adds
  `session_cap`, `source_session_cap`, `session_table_full`. No overlap.
- **The TCP cap:** 12.3's `max_connections` stays per worker until Story
  12.6 AC #3 moves it onto the stream-caps region built here (12.3
  Resolved 1). `admit_session` and its owned permit are protocol-neutral
  for that reason; 12.6 may bump `STREAM_CAPS_LAYOUT_VERSION` to add TCP
  and per-backend counters, with no upgrade consequence (D-d).

### Edits, and who makes them

- **E1, `idle_timeout_s` default by protocol (12.5 Lot C; nothing for
  12.3 if it follows the note).** 12.3 D-q gives `idle_timeout_s` a
  default of 600 and requires UDP streams to hold every 12.3 default. This
  story keeps the one field and gives it a UDP default of 10 and a UDP
  range of 1 to 3,600 (D-l). 12.5 Lot C adds
  `Stream::default_idle_timeout_s(protocol)` and makes the create path,
  the import and its migration use it. *Note for 12.3:* if Lot B's
  "holds its default" check on UDP compares against a constant rather
  than a function of the protocol, 12.5 Lot C replaces that comparison;
  no other 12.3 code changes.
- **E2, protocol-neutral seams and local check (12.3 Lot C preferred;
  otherwise 12.5 Lot E).** 12.3 places `seams.rs` and `local.rs` under
  `lorica_stream::tcp`. The UDP engine uses both. Preferred: 12.3 Lot C
  creates them as `lorica_stream::seams` and `lorica_stream::local`,
  which costs it nothing now. Otherwise 12.5 Lot E moves them first, in a
  `refactor(proxy)` commit with no behaviour change.
- **E3, one resolver cache and one selector per process for both engines
  (12.3 Lot C and D2 preferred; otherwise 12.5 Lots E and F).** 12.3 D-n
  holds the `ResolverCache` inside the TCP engine, and D-e the stream
  selector. A UDP stream and a TCP stream naming one backend host must not
  resolve it twice per worker, and least connections and the WRR state
  are per stream, not per engine. Preferred: 12.3 builds the cache
  (`lorica_stream::resolver`) and the selector in `stream_engine.rs` and
  hands them to its engine as `Arc`s, so 12.5 Lot F hands the same ones to
  the UDP engine. Otherwise 12.5 does that move.
- **E4, PROXY v2 over `DGRAM` (12.5 Lot E).** 12.3 Lot A's `encode_v2`
  encodes transport `STREAM` only. 12.5 adds `encode_v2_dgram(source,
  destination) -> Vec<u8>` beside it, extends the fuzz target's
  round-trip arm and the `FORK.md` entry. 12.3's functions are not changed;
  the per-session encoding of D-j makes the `Vec` return acceptable.
- **E5, one `held_fds` for both protocols (12.5 Lots D, F, G).** 12.3 D-p
  defines `lorica_stream::tcp::held_fds(&Stream)`, called by the driver's
  `demand_of` and by the API's budget check. 12.5 adds
  `lorica_stream::udp::held_fds` (`fds_per_unit: 1`) and a dispatching
  `lorica_stream::held_fds(&Stream)`, and switches both call sites to it,
  so the driver and the API still cannot disagree.
- **E6, the connection record and counters on UDP (12.5 Lot E).** The
  record gains `datagrams_upload` and `datagrams_download` as
  `Option<u64>`, `None` on TCP; `connect_failures` gains the kind
  `no_response`; `StreamCounters` gains `datagrams_upload`,
  `datagrams_download`, `dropped` per `DatagramDropReason` and
  `ceiling_reached` (D-n). No second record or counter structure.
- **E7, `Datagram` gets what `AcceptedConnection` gets (12.5 Lot D).**
  12.3 adds `BoundPorts` to `AcceptedConnection` and a defaulted
  `table_changed` to `StreamHandler`; 12.5 adds the same `bound_ports` to
  `Datagram` and the same defaulted method to `DatagramHandler` (D-c).
- **E8, UDP meanings lifted (12.5 Lot C).** 12.3 D-q refuses backup links
  and non-default values of its fields on UDP "naming Story 12.5". 12.5
  lifts exactly the set D-l lists, and its validation messages replace
  12.3's for those fields; the others keep 12.3's refusal.
- **E9, source binding on UDP (none; recorded so nobody aligns it).** 12.3
  D-l sets `IP_BIND_ADDRESS_NO_PORT` before `connect`. UDP does not (D-f):
  its autobind gives one port per local address whatever the destination,
  so the option buys nothing and the D-e pool arithmetic assumes one port
  per session. Rotation, the family rule and the `source_bind_failed` /
  `source_family_mismatch` counters are 12.3's, unchanged.
- **Sequencing on shared files**, already in the Order of Tasks:
  `lorica-config` model and store (12.3 Lot B, then 12.5 Lot C);
  `handler.rs`, `listener.rs`, `runtime.rs`, `table.rs`, `counters.rs`
  (12.3 Lot C, then 12.5 Lots D and E); `proxy_protocol.rs` and the fuzz
  target (12.3 Lot A, then 12.5 Lot E); `stream_engine.rs`, `worker.rs`,
  `single.rs` (12.3 Lot D2, then 12.5 Lot F); `streams.rs` and
  `openapi.yaml` (12.3 Lot E, then 12.5 Lot G); the e2e compose (12.3 Lot
  G, then 12.5 Lot I).

## Handed to later stories

- **Story 12.6:** the source allowlist feeds `udp_exposure_check`
  (D-k); per-node per-source, per-stream and per-backend caps for TCP move
  onto the stream-caps region; the per-stream new-session rate limit is
  the mitigation the threat model names for a random-source table fill;
  refusal log rows are rate-limited there (a spoofed UDP flood would
  otherwise choose the write rate of the sinks).
- **Story 12.9:** the counters, drop reasons, exact per-node session gauge
  and `ceiling_reached` edge of D-n; access-log rows for sessions.
- **Story 12.10:** the `udp` object on the automation `streams:read`
  resource and the MCP read tools, the unbounded-responses badge, the UDP
  fields in the stream form.
- **Story 12.11:** what a hot upgrade does to UDP bindings. 12.2 D-j lets
  the new generation's group join the old one for the overlap (same user,
  `SO_REUSEPORT`). If the old generation keeps its slot sockets in drain
  mode (D-m), every new client hashed to an old socket is dropped
  (`binding_draining`) for the whole drain, about half the new traffic
  with equal worker counts. Recommendation for 12.11: on
  `quiesce reason=upgrade`, a UDP binding whose stream has bounded
  responses closes its slot sockets at once and ends its sessions with
  `drained_by_upgrade` (request/response clients retry and reach the new
  generation), while a stream with `unbounded_responses` drains in drain
  mode, where continuity matters more than new clients. The `quiesce`
  message carries the reason already; the engine needs one branch.
- **Story 12.12:** IV1 and IV2 replayed with the approved artefacts (a
  real DNS resolver image, a DNS load generator) instead of the
  standard-library stand-ins of Lot I. The UDP performance phase "holds"
  sessions only if they do not close on answers: its streams set
  `unbounded_responses` (or use a backend that never answers with
  `responses_per_request >= 1`) and a `max_sessions` at 80 % of the
  derived ceiling, which the default 4,096 is not. Resident memory per
  1,000 sessions is read from the worker RSS minus the region pages.
- **Story 12.14:** UDP active checks feed the health state the selector
  already reads; nothing in the engine changes.
- **Story 12.16:** a UDP session is its key, counters, timers, the region
  it is counted in and one upstream fd (D-a); transfer re-registers it
  with `admit_session` in the new generation's region before the old permit is
  released (its AC #3). The connected client-socket variant is the
  spike's to measure (D-a).

## Dev Notes

### Where to extend, verified

- `lorica-stream/src/listener.rs`: `receive_loop`, `DATAGRAM_BUF_SIZE`,
  `adopt` (sets non-blocking; PKTINFO is already set by the supervisor),
  the ICMP skip.
- `lorica-stream/src/handler.rs`: `DatagramHandler`, `Datagram`, `Engines`.
- `lorica-stream/src/runtime.rs`: message dispatch (`attach`, `detach`,
  `refresh`, `quiesce`), `drain_duration`, the per-binding stop channel.
- `lorica-stream/src/tracker.rs`: `register`, `set_backend`, `closed`,
  `finish`; unchanged by this story.
- `lorica-stream/src/budget.rs`: `StreamDemand::of`, `HeldFds`,
  `FdBudget::check`, `BudgetViolation`, `NodeBudgetView::build`.
- `lorica-worker/src/stream_sockets.rs`: `bind_udp_group`,
  `process_fd_limit` (the model for the port-range reader),
  `BindFailureKind`.
- `lorica-worker/src/stream_ctl.rs` and `fd_passing.rs`: the message enum,
  `ATTACH_MAX_SOCKETS`, `FdKind`, the size assertion.
- `lorica-shmem/src/table.rs` (`increment`, `reset`, `MAX_PROBE`,
  `tagged_hash`, `now_ns`), `region.rs` (`create_supervisor`,
  `open_worker`, `map_region`, the header checks), `hash.rs` (SipHash-1-3
  and `random_key`), `eviction.rs` (the pass to mirror for rate cells).
- `lorica/src/startup/stream_plane.rs`: `StreamPlane`, the bind path, the
  respawn `replay`, the retry loop, `SeqpacketLink`, `InProcessLink`.
- `lorica-config/src/models/stream.rs`: `Stream`, `Stream::validate`,
  `StreamRefusal`, `StreamEndReason` (doc comments only), `StreamEndKind`.
- `lorica-config/src/store/streams.rs`: `STREAM_COLUMNS` and the row
  mapping.

### Linux pitfalls

- **Connected UDP and ICMP.** Only a connected socket receives ICMP errors
  as `ECONNREFUSED`; they surface on the next `recv` or `send`, once.
  The slot socket (unconnected) can also report them on Linux; 12.2's loop
  already skips them.
- **Ephemeral ports.** `connect` on an unbound UDP socket autobinds a port
  from `ip_local_port_range`, unique per local address whatever the
  destination; UDP does not share ports across destinations as TCP's
  `connect` can. Hence one port per session per source address (D-e).
- **`IP_PKTINFO`** on receive gives `ipi_addr` (the destination) and
  `ipi_spec_dst`; on send, setting `ipi_spec_dst` selects the source
  address. `IPV6_RECVPKTINFO` is the receive option, `IPV6_PKTINFO` the
  ancillary type. tokio's `UdpSocket` has no ancillary API: use
  `UdpSocket::try_io` around `nix::sys::socket::recvmsg` / `sendmsg`.
- **`SO_RCVBUF`** is doubled by the kernel and capped by `rmem_max`; set
  it before `connect` so no early response lands in a larger buffer.
- **Datagrams over 65,507 bytes** do not exist on IPv4; IPv6 jumbograms
  are out of scope. A 64 KiB buffer never truncates, so `MSG_TRUNC` is not
  needed for the oversize check: compare the length.
- **memfd sizing.** `ftruncate` creates a sparse file; pages are backed on
  first write. The probe pattern touches pages at hashed spots, so a busy
  region ends up backed; the docs give the full size, not the sparse one.
- **`SO_REUSEPORT` and connected sockets** (D-a): do not create any socket
  bound to the listen port in a worker.
- **Raw sockets in the e2e spoofer** need `CAP_NET_RAW` and root in that
  container only; Docker's bridge does not filter forged sources between
  containers of one network, and the destination's reverse-path filter
  accepts a source on its own subnet.

### Tests per Lot

Listed in each Lot. Everything in `lorica-shmem`, `lorica-worker`,
`lorica-stream` and the startup code needs Linux and runs through the
`run-tests` skill in Docker. IV1 and IV2 are automated in Lot I with
standard-library stand-ins and replayed by Story 12.12 with the real
artefacts. Not covered by an automated test here: behaviour under the
real systemd unit (none of this story's code depends on it) and kernels
older than the test image's.

## Resolved (maintainer, 2026-11-14)

1. **AC #5's "shared-memory layout version bump"** is satisfied by the new
   stream-caps region's own `STREAM_CAPS_LAYOUT_VERSION`, introduced at 1:
   the WAF region's layout is untouched, so its `LAYOUT_VERSION` stays 1
   (D-d).
2. **`response_bytes_ratio` defaults to 32**, not 10. DNS is a headline
   UDP use case, and a DNSSEC or large TXT answer to a query of about 50
   bytes inside a 1,232-byte EDNS buffer is about 25 times the query; a
   default that silently broke validating resolvers would be the first
   support ticket. The per-source byte rate (512 KiB/s) and the per-node
   reflection bound stay the hard limits; the bound with the defaults is
   8,192,000 bytes per second, and IV1 asserts it (D-l, Lot I).
3. **IPv6 sources are keyed on their /64** for the per-source caps and
   rates (D-d).
4. **UDP drain mode** keeps a draining binding's sockets open and so
   delays a same-port rebind by up to the drain; documented (D-m).
5. **The per-source cap may be exceeded by at most W - 1**, documented as
   `source_session_cap + (W - 1)` per node (D-d).
6. **Response bounds keep their stored values** while
   `unbounded_responses` is set, shown beside the flag and applied again
   when it is cleared (D-l).
7. **The default set of D-l is accepted**, with the ratio at 32.
8. **The source-address list comes from Story 12.3** as
   `source_addresses`, at most 16 (nginx's `proxy_bind`); this story uses
   that name (D-f).

## Open questions for the maintainer

None open. The edits of "Interface with Story 12.3" marked "preferred"
(E2, E3) are a coordination choice between the two drafts, not a product
decision.

## Dev Agent Record

### Debug Log

### Completion Notes

**Lot A (`lorica-worker`).**

- Wire. `FdKind::StreamCaps { caps_gen }` is the token
  `stream-caps:<caps_gen>` (decimal digits only, a sign refused).
  `StreamCtlMsg::Caps { seq, stream_id, caps_gen, slot: u32, region:
  OwnedFd }` is `caps <seq> <stream_id> <caps_gen> slot=<i>
  stream-caps:<caps_gen>` with exactly one `SCM_RIGHTS` fd: the payload
  carries the fd's typed token as `attach` does, and a token whose
  generation is not the header's is `malformed`. Zero or two fds are
  `FdCountMismatch { tokens: 1 }`; every fd that arrived is closed on any
  refusal. A compile-time assertion keeps the longest `caps` inside the
  payload buffer, and a test pins the bound against the real rendering.
- `IP_PKTINFO` (IPv4) and `IPV6_RECVPKTINFO` (IPv6) are set by
  `bind_udp_group` on the unspecified address only. D-g's assumption
  holds and is pinned
  (`ipv6_wildcard_reports_the_ipv4_destination_of_an_ipv4_datagram`): on
  a dual-stack `[::]` socket, `IPV6_RECVPKTINFO` alone reports an IPv4
  datagram's destination IPv4-mapped, so no `IP_PKTINFO` on the v6
  socket. The IPv4 test sends to `127.0.0.2` and reads `127.0.0.2`.
- `usable_udp_source_ports() -> Result<u32, PortRangeError>` reads both
  `/proc` files at every call; the arithmetic is the pure
  `usable_source_ports_from(range, reserved)`, which merges overlapping
  reserved entries and clips them to the range. `EPHEMERAL_PORT_MARGIN`
  (1,024) and the two paths are public constants. A file that cannot be
  read or parsed is `PortRangeError::{Read, Parse}` naming the file.
- `BindFailureKind::SourcePorts` (`source_ports`) is in `ALL`, so
  `from_name` and the heartbeat's kind mapping know it. `openapi.yaml`'s
  `StreamBindFailureKind` enum and the dashboard's failure-kind union
  do not list it yet; Lots G and J now say so.
- Outside the allowlist, needed for the workspace to build:
  `lorica-stream/src/runtime.rs`, whose message match is exhaustive. Until
  Lot D maps regions, a `caps` is answered `nack adopt_failed` and its fd
  closes with the message; no supervisor sends one before Lot F.

**Lot B (`lorica-shmem`).**

- Probe factored. `table.rs` holds the window and the WAF slot
  operations as functions over a slice (`window_indices`, `window`,
  `holding`, `increment`, `read`, `last_update`, `reset`) behind a
  crate-private `Keyed` trait; `AtomicHashTable<N>` delegates and keeps
  its compile-time shape assertion. Every existing test passes unchanged.
- API (`lorica_shmem::stream_caps`, re-exported at the crate root):
  `StreamCapsRegion::create(max_sessions: u64, workers: u32, caps_gen:
  u64) -> Result<(StreamCapsRegion, OwnedFd), StreamCapsError>`;
  `StreamCapsRegion::open(OwnedFd)` (magic, `STREAM_CAPS_LAYOUT_VERSION`,
  the header's shape, and the file length against the layout the header
  describes; the fd closes on return, the mapping stays);
  `layout_for(max_sessions, workers) -> StreamCapsLayout` (offsets, sizes,
  `rate_table_bytes()`, `shard_bytes()`); `region.worker(slot) ->
  Option<WorkerCaps>` and `WorkerCaps::admit_session(SourceKey,
  source_cap, stream_cap) -> Result<SessionPermit, CapRefusal>`
  (`SessionCap`, `SourceSessionCap`, `TableFull`); `charge_rate(SourceKey,
  bytes, RateLimits, now_ns) -> RateVerdict` (`Allowed`, `DatagramRate`,
  `ByteRate`, `TableFull`); `release_worker(slot) -> Option<u64>`;
  `evict_rates(now_ns) -> RateEvictionStats { occupied, evicted, held }`;
  `total()`, `worker_sessions(slot)`, `source_sessions(SourceKey)`;
  `SourceKey::of(IpAddr)`.
- Two refinements of the Task's signatures. The slot is bound once in a
  `WorkerCaps` handle (`worker(slot)` refuses one the region has not), so
  `admit_session` has no out-of-range case. `charge_rate` takes the
  `RateLimits`: only sizes live in the region, the limits come from the
  snapshot at each charge, as D-d says.
- Shard cells are safe with any number of writers, not only their owner:
  a count rises only from a non-zero value and only the claimer sets it
  from 0 to 1, so a cell a release brought to 0 is never revived and the
  release that did it owns the cell until it clears the key. Only the
  owner writes its shard all the same; `release_worker` empties a dead
  slot's shard (counts, then keys) and subtracts its attribution.
- Counting order. A session adds to the total, then claims its shard
  cell, then adds its attribution; a permit gives back the cell, the
  attribution, then the total. A worker dying between two steps leaves
  the total one too high, never too low, and `release_worker` never
  subtracts more than was added.
- Rate cells. GCRA with a one-second burst on both arrival times; a
  datagram refused on the byte rate gives its datagram token back. A
  released cell keeps arrival times in the past, which reads as a full
  bucket, so a claim needs no reset. Eviction also skips a cell claimed
  or charged in the last `RATE_CELL_GRACE_NS` (1 s), closing the window
  between a claim and its first charge. Shard cells are never read for
  release by eviction. The IPv6 /64 key hashes under a derived key, so an
  IPv4 address and a /64 of the same numeric value never share a cell.
- A burst of one second means a datagram larger than one second of byte
  rate never passes. Lot C refuses `udp.source_byte_rate` below
  `udp.max_datagram_bytes`.
- Several live regions of one stream (a size change): `admit_session`
  takes the cap left for this region; the engine passes `max_sessions`
  minus the other live regions' totals (Lot E).
- Commit scope `proxy`: the region serves the stream proxy's caps, not
  the WAF, whose region is untouched.

## File List

Lot B:

- `lorica-shmem/src/stream_caps.rs` (new), `lorica-shmem/src/table.rs`,
  `lorica-shmem/src/lib.rs`
- `lorica-shmem/tests/stream_caps.rs` (new, outside the `src/**`
  allowlist: the multi-process tests the Lot asks for)
- `docs/stories/story-12.5-udp-engine.md`

Lot A:

- `lorica-worker/src/fd_passing.rs`, `lorica-worker/src/stream_ctl.rs`,
  `lorica-worker/src/stream_sockets.rs`, `lorica-worker/tests/stream_ctl.rs`
- `lorica/src/startup/worker.rs` (the `FdKind` arm)
- `lorica-stream/src/runtime.rs` (the `caps` arm, outside the allowlist)
- `docs/stories/story-12.5-udp-engine.md`

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-11-14 | 0.1 | Story drafted from the Epic 12 PRD and the Dev Agent Records of Stories 12.1 and 12.2. Status Draft. | Romain G. |
| 2026-11-14 | 0.2 | Maintainer answers folded in (Resolved 1 to 8: ratio 32 and the reflection bound recomputed, `source_addresses`); aligned with the Story 12.3 draft (seams, breaker key, fields, counters, record) with the remaining mismatches listed as edits E1 to E9. Status Draft. | Romain G. |
| 2026-11-15 | 0.3 | Lot A landed: the `caps` message and its `stream-caps` fd tag, `IP_PKTINFO` / `IPV6_RECVPKTINFO` on wildcard UDP groups (the dual-stack assumption of D-g pinned), `usable_udp_source_ports`, `BindFailureKind::SourcePorts`. Status InProgress. | Romain G. |
| 2026-11-15 | 0.4 | Lot B landed: the stream-caps region (`StreamCapsRegion`, its own layout version, per-stream sizing, exact totals, per-worker session shards never evicted, shared GCRA rate cells), the probe factored out of `AtomicHashTable`, multi-process tests. | Romain G. |
