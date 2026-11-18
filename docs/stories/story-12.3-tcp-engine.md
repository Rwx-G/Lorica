# Story 12.3: The TCP Stream Engine

**Epic:** [Epic 12 - TCP and UDP Stream Proxying (v1.11.0 and v1.12.0)](../prd/epic-12-v1.11.0.md)
**Status:** InProgress
**Priority:** P0
**Author:** Romain G.
**Depends on:**
- Story 12.1 (Review): the `Stream` model, `stream_backends`, the
  end-reason enum and `StreamRefusal`, `check_backend_attachments` and
  its `AttachmentSnapshot`, `backend_address_port`, the reserved-port
  and listen-address rules of `lorica-config/src/listen_ports.rs`
  (`ReservedPorts`, `NodePorts`, `stream_port_conflicts`), the stream
  CRUD handlers in `lorica-api/src/streams.rs`, canonical format 3.
- Story 12.2 (InProgress): `lorica-stream` (`StreamHandler`,
  `AcceptedConnection`, `ConnectionTracker`, `TrackedConnection`,
  `StreamTable`, `StreamRuntime`, `Engines`, the fd budget's `HeldFds`),
  the stream plane driver in `lorica/src/startup/stream_plane.rs`, the
  drain semantics of D-g. Lots E1, E2, E3 and H of 12.2 are still open
  and share files with this story; each Lot below names the ordering.
- Story 12.8 (InProgress): the PROXY parser
  `lorica_core::protocols::proxy_protocol` (Lot A, landed as
  `0a891772`); Lot C1's CIDR-list rules for a PROXY trust list (not yet
  landed, see Lot B).

**Blocks:** Story 12.4 (TLS at layer 4 plugs its ClientHello read into
the pre-forwarding phase of D-b and its upstream TLS into the connect
step), 12.6 (its filters and caps run at the accept hook of D-b and read
the counters of D-r), 12.9 (logs the connection record and exposes the
counters of D-r), 12.11 (`drained_by_upgrade` reaches connections
through the tracker, the preview reads the active gauge), 12.12 (the
L4 and performance phases measure this engine), 12.13 (weighted P2C
joins the shared selection function of D-e), 12.15 (detection is a
pre-forwarding phase; the 443 hairpin is the one exception to D-m),
12.16 (the quiesce point of D-c and the record of D-r are what moves).

---

As an operator,
I want Lorica to forward TCP connections to my backends with the balancing, timeouts and source-address handling I expect from nginx or HAProxy,
so that moving a TCP service behind Lorica loses nothing.

## Problem

After Story 12.2 a stream's port opens on every targeted node, and an
accepted connection is closed at once: no engine is installed
(`Engines::default()` at every `StreamRuntime::spawn` site). This story
is the engine. It forwards bytes both ways, picks a backend with the
algorithms routes already use, fails over on connect failure, honours
backend health and the circuit breaker shared with HTTP, speaks PROXY
protocol both ways, connects from a chosen source address, refuses to
reach the node's own services, limits bandwidth, re-resolves hostnames,
and stays inside the fd budget 12.2 set. It also fixes the shape later
stories build on: where a TLS or detection read slots in (12.4, 12.15),
what a connection reports when it ends (12.9), and where its bytes are
observably at rest (12.16).

## Acceptance Criteria

These are the PRD's, unchanged. They are the contract.

1. **Bidirectional byte forwarding** with half-close handled in both directions.
2. **Load balancing** with the algorithms Lorica already exposes (`LoadBalancing`, `lorica-config/src/models/enums.rs`), as they behave today: round robin (weighted), consistent hash on the source address for persistence (weighted, `lorica-ketama`), random (uniform), least connections, and peak EWMA for latency-aware selection. Weights apply to round robin and consistent hash; the documentation says so.
3. **Backup backends**, used only when every primary backend is down.
4. **Passive failure detection** reuses the circuit breaker (`CircuitBreaker`, `lorica/src/proxy_wiring/lb.rs`), keyed per (stream, backend) as it is keyed per (route, backend) for HTTP, counting connect failures and timeouts, coordinated across workers.
5. **Retry on connect failure** to another backend, bounded by a per-stream attempt count, ending with `connect_failed` or `no_healthy_backend`. Once bytes have flowed, a connection is never retried.
6. **Timeouts**: connect, idle and optional total duration, per stream, with documented defaults. **TCP keepalive** towards the backend, configurable.
7. **Live connections and backend health.** A backend marked down stops receiving new connections and does not cut established ones, unless the stream sets `close_on_backend_down` (default off, the equivalent of HAProxy's `on-marked-down shutdown-sessions`), in which case they close with `backend_down`.
8. **PROXY protocol send**, v1 or v2 per stream.
9. **PROXY protocol accept on TCP streams**, v1 and v2, only from a per-stream list of trusted source CIDRs. The header is bounded in size (4 KiB) and in time; a header from an untrusted source, an oversized one or a late one closes the connection with `proxy_header_invalid`. PROXY accept on UDP streams is refused in writing: a UDP source address is spoofable, so "trusted source" means nothing.
10. **Chosen source address** (`proxy_bind`): a stream can connect from a configured local address, which is also how UDP session capacity is raised past one address's ephemeral ports.
11. **Local backends are refused, at validation and at every connect.** A backend that resolves to a loopback, link-local or other local address on a reserved port (Story 12.1 AC #7) or on any stream listen port of the node is refused, which also prevents forwarding loops. The one exception is the port 443 hairpin of Story 12.15 AC #5. Other local backends need an explicit per-stream `allow_local_backend` flag, badge-visible, never settable from the automation or MCP surfaces. The check runs again after every DNS resolution, so a hostname that re-resolves to a local address is marked down, not connected.
12. **Bandwidth limits** per stream, upload and download, per connection.
13. **Upstream DNS re-resolution** on a TTL-bounded schedule; a resolution failure keeps the last known addresses and raises a health event.
14. **Bounded resources.** Per-connection buffers are fixed-size; a slow reader applies backpressure to the other side, never unbounded buffering. A per-stream cap on concurrent TCP connections has a documented default.

## Integration Verification

- IV1: A TCP stream in front of three PostgreSQL backends balances connections by the configured algorithm and survives one backend being killed with no failed new connection after the breaker trips; a `psql` session opened before the kill on a surviving backend is unaffected.
- IV2: A backend shared by an HTTP route and a TCP stream is marked down: it leaves selection for both, and an established stream connection to it stays open.
- IV3: A backend receiving PROXY v2 sees the real client address; a client outside the trusted CIDRs sending a PROXY header is disconnected.
- IV4: A stream pointed at `127.0.0.1:<management port>` is refused at creation; a hostname backend that re-resolves to `127.0.0.1` is marked down and never connected.

## What the code does today

Read on `feat/v1.11.0` at `0a891772`. Function names, not line numbers.
Read, not run, unless said otherwise.

- **No engine.** `run_worker` (`lorica/src/startup/worker.rs`),
  `run_single_process` (`single.rs`) and the test drivers in
  `stream_plane.rs` and `drain.rs` all spawn `StreamRuntime` with
  `Engines::default()`. The accept loop (`accept_loop`,
  `lorica-stream/src/listener.rs`) reads the stream's snapshot from the
  current table, registers the connection in the tracker
  (`ConnectionTracker::register(bind_gen, snapshot)`) and `tokio::spawn`s
  `StreamHandler::handle(AcceptedConnection { stream, peer, bind_gen,
  tracked })` on the stream runtime, which has **one** worker thread per
  process (12.2 D-b).
- **The tracker signals, the engine closes.** `TrackedConnection::closed()`
  resolves with the drain reason at its deadline; `set_backend` records
  the chosen backend id so a `refresh` that unlinks it drains the
  connection; `finish(natural)` returns the tracker's reason if it closed
  the connection, `natural` otherwise.
- **The stream table holds streams and links only.**
  `StreamTable::new(streams, links)` (`lorica-stream/src/table.rs`);
  `holds(stream_id, backend_id)` is the drain test. No `Backend` row,
  so no address, weight or health, reaches a worker's stream table.
  `StoreStreamTable::load` (`stream_plane.rs`) reads `list_streams` and
  `list_stream_backends`. The runtime reloads it on `refresh` and on an
  `attach` for an unknown stream (`runtime.rs`, `refresh`, `attach`).
- **Health flips never reach the stream plane.** The health loop
  (`health_check_loop`, `lorica/src/health.rs`) writes a confirmed flip
  to the store, then signals its `config_reload_tx`. In the supervisor
  that sender is `reload_bc_tx`, the legacy per-worker broadcast
  (`spawn_health_check_loop(..., Some(reload_bc_tx.clone()))`,
  `supervisor.rs`), which reloads the workers' HTTP `ProxyConfig` and
  does not pass through `ConfigReloadBridge::apply_config_change`, the
  only path that sends the stream `refresh`. In single-process mode the
  loop gets `None` and reloads the proxy config itself. A stream table
  loaded today would therefore keep a backend's health as of the last
  configuration change.
- **HTTP selection** is inline in `LoricaProxy::upstream_peer`
  (`lorica/src/proxy_wiring.rs`): skip `Down` and lifecycle other than
  `Normal`; ask the breaker for **every** remaining backend
  (`circuit_breaker_engine.admit(route_id, address)`, an RPC each in
  worker mode), a `Probe` admission moved to the head; then a `match` on
  `LoadBalancing`: `PeakEwma` is `EwmaTracker::select_best`; `Random`
  hashes `ctx.start_time` with `DefaultHasher`; `LeastConn` takes the
  minimum of `BackendConnections::get(address)`; `ConsistentHash` is
  `pick_consistent_hash(&[(address, weight)], client_ip)`
  (`proxy_wiring/helpers.rs`, a ketama `Continuum` built per call over
  addresses that parse as `SocketAddr`, falling back to WRR when none
  does); `RoundRobin` is `SmoothWrrState::next`
  (`proxy_wiring/config.rs`, per `RouteEntry`, worker offset from the
  pid, carried across reloads by `reload.rs`). `Degraded` and `Unknown`
  backends are eligible. Weights (`Backend.weight`, `max(1)`) reach WRR
  and ketama only.
- **`BackendConnections`** (`lorica-api/src/connections.rs`) is a
  per-process map of address to `AtomicU64`; each worker has its own
  (`worker_backend_conns`, `run_worker`). HTTP least-conn is therefore
  per worker today.
- **`EwmaTracker`** (`proxy_wiring/lb.rs`) is a plain EWMA (alpha 0.3)
  of HTTP response latency keyed by address, with bounded exploration of
  unscored backends.
- **The breaker.** `CircuitBreaker` (`lb.rs`) is the in-process state
  machine (single-process, `BreakerEngine::local(5, 10)` in
  `LoricaProxy::new`). In worker mode `BreakerEngine::Rpc`
  (`proxy_wiring/engines.rs`) sends `BreakerQuery` / `BreakerReport`
  (`lorica-command/src/messages.rs`, fields `route_id`, `backend`,
  `success`, `was_probe`) with a 500 ms timeout and fails open; the
  supervisor's `SupervisorBreakerRegistry::new(5, 10 s)` keys entries
  `"{route_id}|{backend}"` and never prunes them. The worker installs the
  RPC engine after `RpcEndpoint::from_raw_fd`, which runs well **after**
  `StreamRuntime::spawn` in `run_worker`. `RpcEndpoint` is a handle over
  channels (`Arc<Inner>` with an mpsc queue), so a call from the stream
  runtime's thread is a channel send, not a cross-runtime poll.
- **No backend DNS cache exists.** HTTP builds `HttpPeer::new(&backend.address, ...)`
  per request; I'm fairly sure it resolves through std's synchronous
  resolver there (not traced further). `hickory-resolver` is already a
  dependency of `lorica` (`bot_rdns.rs` builds a `TokioResolver` from
  the system configuration).
- **The PROXY parser** (`lorica-core/src/protocols/proxy_protocol.rs`):
  `parse`, `classify_prefix`, `Header`, `Addresses::{Unspecified, Tcp,
  Udp, Unix}`, `ParseError`, `MAX_HEADER_LEN = 4096`,
  `HEADER_READ_TIMEOUT = 5 s`, `V1_SIGNATURE`, `V2_SIGNATURE`. No
  encoder. `lorica-stream` does not depend on `lorica-core` yet; Story
  12.8's Dev Notes checked that the edge creates no cycle.
- **What a worker knows of its node's ports.** `run_worker` receives
  `https_port` only (`--https-port` in `WorkerManager`'s exec arguments,
  `lorica-worker/src/manager.rs`). The process's `ReservedPorts`
  (`lorica-config/src/listen_ports.rs`) exists in the supervisor
  (`AppState.reserved_ports`) and in single-process mode, not in workers.
- **The budget input.** `StreamDemand::with_held(HeldFds { ceiling,
  fds_per_unit })` exists (`lorica-stream/src/budget.rs`); the driver's
  `demand_of` (`stream_plane.rs`) builds every demand without it, so TCP
  streams count only their listening sockets today.
- **Model hooks 12.1 left for this story.** `StreamRefusal` has
  `NoMatch` only. 12.1 D-1 reserved the backup flag as a column of
  `stream_backends` and a field of `StreamBackend`.
  `check_backend_attachments` (`models/stream.rs`) is the one rule every
  management write, replica apply and import runs over an
  `AttachmentSnapshot { backends, streams, stream_backends,
  route_backends }`. `backend_address_port` (`models/backend.rs`)
  reads the port of `host:port`, `[v6]:port` and the portless forms.
- **Migrations.** `MIGRATIONS` ends at `(73,
  migrate_cluster_node_reserved_ports)`; 12.2 Lot E1 claims the next
  number for its alert subscription.
- **Automation can repoint a backend.** `update_backend`
  (`lorica-api/src/automation/write.rs`) lets a token with
  `backends:write` change any backend whose address stays inside its
  `allowed_backend_cidrs` (`ensure_backend_row_granted`), including a
  backend linked to a stream.

## Decisions taken in this story

Each with its reason and what it costs.

### D-a. The engine lives in `lorica-stream`, with three seams implemented in `lorica`

The engine is a new module tree `lorica_stream::tcp`, implementing
`StreamHandler`. Everything that is plain socket work lives there: the
connection pipeline (D-b), the forwarding loop (D-c), timers (D-d),
retry orchestration (D-h), PROXY accept and send (D-j, D-k), source
binding (D-l), the connect-time local check (D-m), the resolver cache
and schedule (D-n), bandwidth (D-o), the per-stream cap (D-p), counters
and the connection record (D-r).

Three things it needs live in the binary crate, which `lorica-stream`
cannot depend on (`lorica` depends on it). Each is a narrow trait in
`lorica_stream::tcp::seams`, implemented in a new
`lorica/src/stream_engine.rs`:

- `BackendSelector`: pick one candidate for a stream, and learn of
  connects and closes (least-conn counts, EWMA samples). Implemented
  over the HTTP selection function extracted in D-e, so the algorithms
  exist once.
- `BreakerGate`: `admit(stream_id, backend) -> Admission` and
  `record(stream_id, backend, success, was_probe)`, implemented over the
  process's `BreakerEngine` (D-g).
- `Resolve`: `lookup(host) -> Result<(Vec<IpAddr>, ttl), ResolveError>`,
  implemented over `hickory-resolver` (D-n).

*Why not the binary crate:* 12.2 D-b's reasons hold (12.4, 12.5, 12.6,
12.15 and 12.16 extend this code; the binary is the slowest crate to
build and the hardest to test alone), and 12.8 already planned the
`lorica-core` edge on `lorica-stream` for the parser. With fakes for the
three seams, every AC except the cross-worker breaker is testable inside
`lorica-stream` on real sockets.
*Why not move HTTP's selection code into `lorica-stream`:* HTTP would
then import its balancing from a crate named for streams, and
`lorica-stream` would gain `dashmap`, `parking_lot` and `lorica-ketama`
edges. A trait over an extracted function shares the code with no new
edge.
*Cost:* one indirection per connection for each seam, and the
end-to-end behaviour of a seam is tested in `lorica`, not in the crate.

`lorica-stream` gains one dependency edge, `lorica-core = { version =
"0.1.0", path = "../lorica-core", default-features = false }`, already
in the lockfile. No new third-party crate anywhere.

### D-b. The connection pipeline and its phases

One task per accepted connection, on the stream runtime:

1. **Admit.** Canonicalise the peer (`IpAddr::to_canonical`: a
   dual-stack `[::]` listener reports IPv4 clients as IPv4-mapped).
   Take a slot of the per-stream cap (D-p) or end
   `refused(connection_cap)`. Story 12.6's filters plug in here, before
   any byte is read.
2. **Pre-forwarding.** Reads that must finish before a backend is
   chosen, each bounded in bytes and time, each keeping the bytes it
   read past its own need in a **preamble** buffer that is replayed to
   the backend first. In this story: the PROXY header from a trusted
   peer (D-k). Story 12.4 adds the ClientHello read, Story 12.15
   detection; both append to the same preamble under their own ceilings.
3. **Connect.** Plan and run attempts (D-e, D-f, D-g, D-h): resolve,
   check locality, bind the source, connect under the connect timeout,
   set socket options, write the PROXY header to the backend (D-j), then
   the preamble. `TrackedConnection::set_backend` is called once an
   attempt connects.
4. **Forward** (D-c) until both directions are closed, a timer fires, or
   the tracker closes the connection.
5. **End.** `finish(natural)` gives the end reason; the connection
   record (D-r) goes to the observer; the cap slot and the counters are
   released by drop.

The tracker's `closed()` is selected beside every await in phases 2 to
4, so a drain (`config_removed`, `node_shutdown`, and from 12.11
`drained_by_upgrade`) ends a connection in any phase. Closing means
`shutdown(Both)` on both sockets, then drop: the peers see a FIN, not a
reset. The client is never read during phase 3 except by the
pre-forwarding reads: a client-first protocol's bytes wait in the kernel
receive buffer, which is what makes a retry safe (D-h).

### D-c. The forwarding loop: fixed buffers, half-close, backpressure, no splice

- **One task, two directions.** Client to backend ("upload") and
  backend to client ("download"), each a small state machine over the
  two `TcpStream`s (borrowed halves through `TcpStream::split`, no
  `Arc`), each owning **one fixed buffer of 16 KiB**
  (`FORWARD_BUFFER_SIZE`, a constant, nginx's `proxy_buffer_size`
  default). 32 KiB per connection, allocated once at the start of
  phase 4 and never grown.
- **Read only into an empty buffer.** A direction reads, then writes
  the whole chunk, and reads again only once the buffer is empty. A
  slow reader on one side leaves its direction in "writing", so the
  other side's socket is not read, its kernel receive buffer fills and
  TCP flow control pushes back on the sender. There is no queue
  anywhere: memory per connection is the two buffers, whatever the
  peers do (AC #14, NFR2).
- **Half-close.** A read of 0 bytes (FIN) on one side ends that
  direction: the engine calls `shutdown(Write)` on the other socket,
  which forwards the FIN, and keeps the opposite direction running. The
  connection ends when both directions have ended. A reset or error on
  a read or write ends both. The natural end reason is `client_close`
  if the client side ended first (FIN, reset or error), `backend_close`
  otherwise.
- **`TCP_NODELAY` on both sockets**, nginx `stream`'s default
  (`tcp_nodelay on`): interactive protocols (SSH, database
  request/response) must not wait on Nagle.
- **No `splice(2)`, no zero-copy, in 1.11.0.** Reasons: a splice
  pipeline needs a pipe per direction, two fds each, so 6 fds per
  connection instead of 2, a threefold cut in what the fd budget of
  12.2 D-e admits; tokio exposes no splice, so it would mean raw
  `nix` calls and readiness juggling under `#![deny(unsafe_code)]`;
  bytes sitting in a pipe are held by the process yet invisible to
  userspace, which blurs the quiesce point 12.16 needs; and the parity
  reference, nginx `stream`, copies through userspace buffers too.
  *Cost:* CPU per GiB forwarded, which Story 12.12 measures against
  nginx with the same copying design (threshold 1.15 x). If 12.12
  misses it, splice is the lever, with its fd cost stated.
- **The quiesce point (for 12.16).** Each direction's state is
  explicit (`Reading`, `Writing { filled, written }`, `Closed`), and its
  held bytes are `filled - written`, readable through
  `DirectionState::held_bytes()`. A connection is at its quiesce point
  exactly when both directions are in `Reading` or `Closed` with 0 held
  bytes and the preamble is drained: no forwarded byte is in userspace.
  12.3 does not stop there; it makes the state a value a test can read,
  and states the invariant 12.16 will park on: between "write
  completed" and "next read issued". A connection still in phase 2 is
  never at the quiesce point (12.16 AC #2).

### D-d. Timeouts, keepalive and their defaults

| Setting (stream field) | Lorica default | Range | nginx `stream` | HAProxy `mode tcp` | Envoy `tcp_proxy` | Traefik TCP |
|---|---|---|---|---|---|---|
| Connect, per attempt (`connect_timeout_ms`) | 5,000 ms | 100 to 60,000 ms | 60 s (`proxy_connect_timeout`) | no default, warns (`timeout connect`) | 5 s (cluster `connect_timeout`) | 30 s (`dialTimeout`) |
| Idle, no byte either way (`idle_timeout_s`) | 600 s | 1 to 86,400 s | 10 min (`proxy_timeout`) | no default, warns (`timeout client` / `timeout server`) | 1 h (`idle_timeout`) | not verified |
| Total from accept (`total_timeout_s`) | off | 1 to 604,800 s | none | none | unset (`max_downstream_connection_duration`) | none |
| Connect attempts (`max_connect_attempts`) | 3 | 1 to 10 | every server (`proxy_next_upstream_tries 0`) | 3 (`retries`) | 1 (`max_connect_attempts`) | not verified |
| Backend keepalive (`backend_keepalive`, `backend_keepalive_idle_s`) | on, 60 s | 1 to 7,200 s | off (`proxy_socket_keepalive`) | off (`option srvtcpka`) | off | 15 s (`dialKeepAlive`) |

The competitor values are recalled from the vendors' documentation, not
re-read for this draft, and are **not** to be quoted as they stand. Lot
F checks each one against the sources the PRD links ("Sources" under
"Prior Art"), writes the URL it was read from beside every value in
`docs/streams.md`, corrects this table where a value differs, and
writes "not documented" where the source states none (Resolved 9).

*Note (2026-11-18):* two HAProxy cells of the table are not in the
HAProxy 3.4 configuration manual. Its `retries` section states no
default (and its value counts retries after a failure, not attempts),
and its `option srvtcpka` section states no default either. "3
(`retries`)" and "off (`option srvtcpka`)" are recollections; the
survey table of `docs/streams.md`, which Lot F wrote from the sources,
says "not documented" for both. Lorica's own defaults do not depend on
either value.

- **Connect 5 s, in milliseconds.** With retries, a failover costs at
  most `attempts x connect timeout`; nginx's 60 s would hold a client
  for three minutes before `connect_failed`. Milliseconds because LAN
  backends answer a SYN in well under a second and operators of
  databases tune below 1 s.
- **Idle 600 s**, nginx's value: operators migrating from nginx keep
  their behaviour. Not unlimited: an idle connection holds two fds and a
  cap slot (NFR2). Idle is measured on forwarded bytes in either
  direction, checked on a 1 s tick against a last-activity instant, so
  it fires within one second of its value without re-arming a timer per
  read. It ends with `idle_timeout`.
- **Total off by default**, as everywhere in the survey. When set, it
  runs from accept and ends with `total_timeout`.
- **Keepalive on by default**, unlike nginx and HAProxy (Resolved 7): a
  stream that may sit idle for 600 s through a cloud NAT gateway or a
  stateful firewall loses its mapping without it, and a backend host
  that died without a FIN is otherwise only noticed at the idle
  timeout. *Cost:* a probe every 10 s on each idle backend connection
  after 60 s, and a default that differs from the two references
  operators migrate from, which `docs/streams.md` states. Idle is
  configurable; interval (10 s) and probe count (3) are constants, as
  HTTP's upstream keepalive constants are. The keepalive is set on the
  backend socket only; client-side keepalive is not an AC of this
  story.
- Pre-forwarding reads have their own bounds (D-k), counted from accept.

### D-e. Balancing: one selection function for HTTP and streams

**The extraction.** The `match entry.route.load_balancing` block of
`upstream_peer` moves, unchanged in behaviour, into
`lorica::proxy_wiring::lb::select_index`:

```rust
pub struct SelectionState<'a> {
    pub wrr: &'a SmoothWrrState,
    pub ewma: &'a EwmaTracker,
    pub connections: &'a BackendConnections,
}

pub fn select_index(
    algorithm: &LoadBalancing,
    candidates: &[&Backend],
    ring_addresses: &[&str],
    client_ip: Option<&str>,
    random_seed: u64,
    state: SelectionState<'_>,
) -> usize
```

HTTP passes its addresses as `ring_addresses` and the hash of
`ctx.start_time` it computes today as `random_seed`, so its choice is
bit-for-bit what it was; the existing selection tests pin it and gain
nothing. This is a `refactor(proxy)` commit of its own (Lot D1), before
any stream code calls it. Names are the contract; Lot D1 may refine a
parameter and records why.

**Per algorithm, for streams:**

- `round_robin`: smooth weighted round robin, one `SmoothWrrState` per
  stream id held by the selector (worker offset from the pid, as HTTP),
  pruned when the stream leaves the table (D-i's `table_changed`).
- `consistent_hash`: ketama over the candidates, weighted, keyed on the
  client IP as text (after PROXY accept when one was accepted, D-k).
  The ring is built over each candidate's **resolved** `ip:port` (the
  listen port N for a range stream), so hostname backends take part,
  where HTTP falls back to round robin for them. *Cost:* a backend
  whose address re-resolves remaps its clients, as nginx's `hash` does.
- `random`: uniform over candidates, weights ignored, seeded from the
  accept instant hashed the way HTTP hashes `start_time`.
- `least_conn`: the candidate with the fewest open stream connections
  **in this process**, counted in a `BackendConnections` instance owned
  by the stream selector, keyed by backend address. Per process because
  that is how HTTP's least-conn counts today, and because a per-node
  count needs the shared tables Story 12.5 creates; with the kernel
  spreading accepts over workers, per-process minima converge on a
  per-node balance to within one connection per worker. The instance is
  not HTTP's: sharing it would change HTTP least-conn on a backend a
  route and a stream share, which "HTTP behaviour unchanged" forbids.
- `peak_ewma`: an `EwmaTracker` instance of the stream selector, fed
  with **connect latency** (SYN to established) per backend address,
  the meaning nginx gives `least_time connect`. Not HTTP's tracker:
  response latency and connect latency on one address would blur each
  other. HTTP's EWMA is not "peak" in the strict sense; the stream one
  behaves the same way, as the AC asks.
- Weights: round robin and consistent hash only, `max(1)` as today.
  `docs/streams.md` says so in one sentence beside the algorithm list.

**Order: select, then admit.** HTTP asks the breaker about every
backend, then selects. In worker mode that is one RPC per backend per
request. A stream selects one candidate, then asks the breaker about it
alone; a `Deny` removes it from this connection's candidates and
selection runs again. One RPC per connection in the common case, which
matters for Story 12.12's accept-to-connect p99. *Cost:* while a
breaker is open, round robin's state advances past a denied backend,
so the distribution over the others is very slightly uneven during the
cooldown.

**Candidates** for an attempt: backends linked to the stream, primary
or backup per D-f, with `health_status != Down`, `lifecycle_state ==
Normal`, a known resolved address (D-n), not refused as local (D-m),
not already tried by this connection (D-h). `Degraded` and `Unknown`
are eligible, as for HTTP.

### D-f. Backup backends

`stream_backends` gains `backup INTEGER NOT NULL DEFAULT 0`, and
`StreamBackend` gains `backup: bool` (12.1 D-1 reserved this place).
Selection uses primaries; **backups are candidates only when no primary
is a candidate**, by the rule of D-e. A primary tried and failed by
this connection counts as unavailable for it, so a connection whose
primaries all refuse it reaches the backups within its attempt budget,
as nginx does. A stream with backends must have at least one primary:
a stream whose every link is a backup is refused by
`check_backend_attachments` (a new `AttachmentRule`). Backups use the
stream's algorithm among themselves.

### D-g. The circuit breaker: the HTTP registry, keyed per (stream, backend)

- **Key.** The breaker key is (`"stream:" + stream_id`, backend
  address as configured). The existing `BreakerQuery` and
  `BreakerReport` carry it unchanged in their `route_id` and `backend`
  fields: no wire change, no new RPC. The prefix keeps the stream and
  route namespaces apart by construction rather than by the improbability
  of two UUIDs colliding, and the supervisor's registry, which never
  prunes, needs no change. One entry per (stream, backend), so a range
  stream's failures on several ports count against one backend, as a
  route's do across paths.
- **Coordinated across workers** by being the same registry: worker
  mode goes through `BreakerEngine::Rpc` to `SupervisorBreakerRegistry`
  (threshold 5, cooldown 10 s); single-process mode through the local
  `CircuitBreaker` (5, 10), the same instance HTTP uses. The thresholds
  are HTTP's; no stream setting.
- **What counts.** A failure: connect refused, unreachable, reset
  during connect, or the connect timeout. A success: an established
  connection. Not counted: a local-address refusal (D-m), an unresolved
  name (D-n), a failed source bind (D-l): none of these says anything
  about the backend's health. Nothing after connect counts: a backend
  closing a connection later is not a passive failure.
- **Probes.** An `AllowProbe` admission makes that attempt the probe;
  its outcome is reported with `was_probe = true`.
- **Fail open**, as HTTP: a breaker RPC that times out (500 ms) or
  fails admits.
- **The worker's late RPC endpoint.** `StreamRuntime::spawn` runs
  before `RpcEndpoint::from_raw_fd` in `run_worker`. The `BreakerGate`
  adapter holds an `ArcSwapOption<BreakerEngine>` filled right after
  the endpoint is created; until then it admits (fail open, the same
  policy as an RPC failure). The window is the worker's start-up, before
  its first `refresh`.

### D-h. Retry semantics

- An **attempt** is one connect to one address of one backend.
  `max_connect_attempts` bounds attempts per connection, the first one
  included.
- After a failed attempt, the next attempt selects again among
  candidates not yet tried by this connection, immediately (no backoff),
  under a fresh connect timeout.
- **Ends.** No candidate at the first selection: `no_healthy_backend`.
  At least one attempt made and none connected, because the attempts
  are spent or no untried candidate is left: `connect_failed`.
- **Never retried once bytes have flowed.** The decision point is the
  established connect: after it, the attempt is committed, even if
  writing the PROXY header or the preamble fails (that ends the
  connection with `backend_close`). Before it, no client byte has been
  consumed except the pre-forwarding preamble, which the engine holds
  and replays to whichever attempt connects; so a retry never loses or
  repeats a client byte.
- A connection's whole connect phase is bounded by `attempts x
  connect_timeout_ms` (at most 10 x 60 s) plus resolution of names not
  yet resolved, itself bounded by the connect timeout of the attempt
  that needs it.

### D-i. Backend health reaches the stream table, and `close_on_backend_down`

- **The table carries backends.** `StreamTable` gains the `Backend`
  rows linked to any stream, as `Arc<Backend>`, and the `backup` flag of
  each link; `StoreStreamTable::load` reads `list_backends` and keeps the
  linked ones. The constructor is additive
  (`StreamTable::with_backends(streams, links, backends)`, `new` kept),
  so the tree compiles at the end of Lot C before Lot D2 switches the
  loader.
- **Health flips refresh the stream plane.** `health_check_loop` gains
  an `on_change: Option<Arc<dyn Fn() + Send + Sync>>` called after it
  persists a confirmed flip or a lifecycle transition, beside the
  existing signal. In the supervisor it calls a new
  `StreamPlaneHandle::refresh_tables()`, which sends `refresh` (with
  the current `drain_ms`) to every worker and binds or detaches nothing;
  in single-process mode the same call on the single-process driver.
  Not the configuration watch (`config_reload_tx`): that would run a
  two-phase reload of every worker and wake the control plane's
  replication round for a change that is not configuration. *Cost:* a
  `refresh` re-reads the stream table from the store in every worker on
  each confirmed flip; flips are rare by construction (3 confirmations,
  `HEALTH_FLIP_THRESHOLD`).
- **New connections** see the new health at their next selection. An
  established connection keeps its socket: a backend going `Down` cuts
  nothing (AC #7).
- **`close_on_backend_down`** (stream field, default false). After each
  table reload, the runtime drains, with deadline now and reason
  `backend_down`, every connection whose **accepted snapshot** sets the
  flag and whose backend is `Down` in the **new** table. The snapshot
  decides because established connections keep the settings they were
  accepted with (12.2 AC #8); the table decides the health because
  health is not a setting. Lifecycle `Closing` and `Closed` do not
  trigger it: they are an operator's drain, which already keeps
  established connections.
- `StreamHandler` gains a defaulted method `table_changed(&self,
  table: &StreamTable)`, called by the runtime after every reload, so
  the engine prunes per-stream state (WRR, counters of deleted streams)
  and updates the resolver's host set (D-n) without polling.

### D-j. PROXY protocol send

- **Field** `proxy_protocol_send`: `off` (default), `v1`, `v2`, a new
  enum `StreamProxyProtocol` in `models/stream.rs`.
- **Encoder** beside the parser, in the same Lorica-only module of the
  fork: `encode_v1(source, destination) -> Vec<u8>` and
  `encode_v2(source, destination) -> Vec<u8>` (command `PROXY`,
  transport `STREAM`, no TLV), plus `encode_v1_unknown()` and
  `encode_v2_unspec()` for the case below. Every encoded header parses
  back through `parse` to the same addresses, in unit tests and in the
  existing fuzz target, which gains a round-trip arm.
- **Addresses.** Source: the client, after PROXY accept when one was
  accepted (D-k), otherwise the socket peer; destination: the carried
  destination when a header was accepted, otherwise the accepted
  socket's local address. Both canonicalised. When the two families
  still differ (a carried header can only hold one family, but a
  socket peer and a carried destination could disagree), v1 sends
  `PROXY UNKNOWN\r\n` and v2 an `AF_UNSPEC` header: the backend falls
  back to the socket addresses, which is what the specification says
  these forms mean.
- Written after connect, before the preamble, on every attempt that
  connects. Not counted in the forwarded byte counters (D-r).
- The fork divergence entry for the parser in `FORK.md` is extended to
  name the encoder; nothing outside that file changes in `lorica-core`.

### D-k. PROXY protocol accept on TCP streams

- **Fields** `proxy_protocol_accept: bool` (default false) and
  `proxy_protocol_trusted_cidrs: Vec<String>` (default empty, at most
  256 entries). Validation: the list's rules are Story 12.8 D-d's
  (every entry parses, a bare IP is a host prefix, `0.0.0.0/0` and
  `::/0` are refused, accept on with an empty list is refused), from the
  same function in `lorica_config::connection_filter`. **Replicated**
  with the stream, unlike HTTP's node-local list: a stream is already a
  replicated perimeter object (a control plane that can write this list
  can as well open the port), so per-node trust would add a write path
  without removing a power.
- **Trusted peer** (canonical socket peer inside the list): the header
  is **required**. It is read in phase 2, before any backend is chosen,
  with `parse`, at most `MAX_HEADER_LEN` (4,096) bytes and within
  `HEADER_READ_TIMEOUT` (5 s) of accept, the constants of the parser
  module, shared with the HTTP listeners. Bytes past the header go to
  the preamble. `PROXY` over `STREAM` with `AF_INET`/`AF_INET6`: the
  carried addresses become the client and destination for everything
  downstream (selection hash, PROXY send, the record, 12.6's filters).
  `LOCAL`, `AF_UNSPEC` and `AF_UNIX`: the socket addresses stay, as
  12.8 D-e. `DGRAM` transport: `Unsupported`. Any refusal (malformed,
  oversized, unsupported, missing at the deadline) ends with
  `proxy_header_invalid`.
- **Untrusted peer on an accepting stream**: a direct client, served
  with its socket address, which may not send a header (IV3). It is not
  sniffed before connect, because a server-first protocol (SMTP, MySQL,
  FTP) has a silent client and would stall. Instead, the first bytes
  the client sends go through `classify_prefix` before they are
  forwarded: `V1` or `V2` ends the connection with
  `proxy_header_invalid` and nothing is forwarded; `NotProxy` forwards
  them; `NeedMore` holds at most the 11 bytes of an unfinished signature
  until it resolves. *Cost:* a backend sees a connect, possibly a PROXY
  send header, and a close for a spoofing attempt.
- **Accept off**: no read, no sniff; a PROXY header is client bytes,
  as on an HTTP listener with mode `off`.
- **No `optional` mode** on streams in 1.11.0 (Resolved 4): under it, a
  server-first protocol behind a silent trusted peer would wait the 5 s
  header timeout for its banner. A trusted peer sends a header or is
  closed.
- **UDP**: `proxy_protocol_accept = true` on a UDP stream is refused at
  validation, permanently, with the AC #9 reason in the message.
- Refusal counters per stream and outcome (D-r). The per-source pending
  cap of Story 12.6 AC #5 applies to phase 2 from that story on.

### D-l. Chosen source addresses (`proxy_bind`)

- **Field** `source_addresses: Vec<IpAddr>`, default empty (the kernel
  chooses), at most 16, each a unicast literal that is neither
  unspecified nor IPv4-mapped. A list rather than nginx's single
  address because the AC names raising capacity past one address's
  ephemeral ports, which one address cannot do (Resolved 8).
- **Use.** Per attempt, the next address in turn (per-stream rotating
  counter) whose family matches the destination. The socket is bound to
  it with `IP_BIND_ADDRESS_NO_PORT` before `connect`, so the kernel
  picks the ephemeral port per destination 4-tuple instead of reserving
  one per source address at bind: the usable port space then scales with
  the number of distinct (source, destination) pairs.
- **No family match** for a destination (an IPv4-only list and an IPv6
  backend): the attempt is not made, the candidate is skipped for this
  connection, counted `source_family_mismatch`, and the breaker is not
  told. Validation refuses a list with no family in common with an
  IP-literal backend of the stream; hostname backends are checked at
  connect only.
- A bind failure (`EADDRNOTAVAIL`: the address is not on this node) is
  a failed attempt, counted `source_bind_failed`, not a breaker failure.
- Story 12.5 gives the field its UDP meaning; until then it is refused
  on UDP streams (D-q).

### D-m. Local backends: one definition, three checks

**"Local"**, in one function `lorica_config::local_address::is_local_ip`
plus the node's interface set:

- loopback (`127.0.0.0/8`, `::1`), unspecified (`0.0.0.0`, `::`),
  link-local (`169.254.0.0/16`, `fe80::/10`), each also in its
  IPv4-mapped form (checked after `to_canonical`);
- the names `localhost` and `*.localhost` (RFC 6761), as hostnames;
- at connect only: any address assigned to an interface of this node
  (`getifaddrs`, refreshed every 30 s by the resolver tick, D-n), since
  `10.0.0.5:<management port>` on the node itself is the management API
  exactly as `127.0.0.1` is.

**Two rules**, after the AC:

- **Rule A, local needs the flag.** A local backend on a stream whose
  `allow_local_backend` (new field, default false) is off is refused.
- **Rule B, never a node port.** A local backend whose port (each port
  N of a range stream) is a reserved port of a node binding the stream
  or a listen port of any stream that node binds is refused, flag or
  not. This is also the forwarding-loop guard. A consequence stated in
  the docs: a portless local backend on a range stream always hits rule
  B (port N is the stream's own port).
- The 443 hairpin of Story 12.15 AC #5 is the only exception; it does
  not exist in this story.

**Where each runs:**

1. **Validation, pure, every writer.** Rule A for IP literals and
   `localhost` names in `check_backend_attachments` (a new
   `AttachmentRule::LocalBackend`), so management writes (stream and
   backend), replica apply and import all refuse it. Hostnames are not
   resolved at validation: the control plane's resolver is not the
   node's, a DNS-rebinding name defeats a write-time check by design,
   and a blocking lookup has no place in a store transaction. The
   connect-time check is what holds for names.
2. **Validation, per node, at the API.** Rule B beside
   `stream_port_conflicts`, over the same `&[NodePorts]` (D-5 of 12.1):
   a new `local_backend_conflicts` in `listen_ports.rs`, run by stream
   create and update, by backend update for every stream the backend
   is linked to, and by import. Interface addresses of other nodes are
   unknown here; rule B at validation covers loopback, unspecified and
   link-local literals.
3. **Every connect, on the node.** After resolution and before the
   source bind, the engine checks the exact destination against both
   rules with the node's interface set, the process's `ReservedPorts`
   and the listen ports of the bindings attached in this process (TCP
   and UDP alike, as the AC says "any stream listen port"). A refused
   destination is not connected, is counted
   `local_destination_refused`, and is not a breaker failure.

**IV4's "marked down", stream-scoped.** A hostname whose resolution
contains a local address that rule A or B refuses is excluded from that
stream's candidates until a later resolution no longer does (D-n), and
the transition is a health event (warn line, counter). It is **not**
written to the shared `health_status`: the same name on an HTTP route
is a legitimate local backend (HTTP has no such rule), and one stream's
policy must not take a route's backend out (Resolved 2).
`docs/streams.md` states this reading of the PRD's "marked down".

**The worker learns its reserved ports.** The worker command line gains
`--reserved-ports`, built by `WorkerManager` from the supervisor's
`ReservedPorts` (management, http, https, then cluster, enrollment and
automation or `-`), parsed into the same type and passed to
`run_worker`. A respawned or upgraded worker gets it the same way.

**D9 on the automation and MCP surfaces.** The flag is a stream field,
and streams have no automation or MCP write path, so it cannot be set
there. But a token with `backends:write` can repoint a backend a stream
uses. So: an automation or MCP write that changes the address of a
backend linked to any stream with `allow_local_backend` on is refused
(403, naming the stream, never the address), in `write.rs` beside
`ensure_backend_row_granted`, the path the MCP backend tool also takes
(to confirm in Lot E). Narrow on purpose: tokens keep managing backends
of ordinary streams, whose rule A still refuses a local address.

*Amendment (maintainer, 2026-11-18, with Story 12.10's D-i):* the 403
names the stream **only to a token holding `streams:read`**; any other
token reads the stream's id and that it lacks `streams:read`, on REST,
both MCP transports, apply and dry run. Reason: Story 12.10 D-j keeps
stream names out of the reads for a token without `streams:read`, which
is every config-tier token (the tier rule refuses that scope beside a
write scope), and a refusal must not hand the name out instead. The
spelling is one helper, `streams_as_seen_by` in `automation/write.rs`,
shared with 12.10's backend delete refusal.

### D-n. DNS re-resolution

- **Per process**, inside the engine: one `ResolverCache` per worker
  (and per single process), shared by every stream of that process,
  keyed by host name, holding the last good address list, its expiry,
  the consecutive failure count and the interface set of D-m. Workers
  resolve independently, as nginx workers do. *Cost:* `W` queries per
  name per interval, and `W` log lines per transition; with a few dozen
  hostnames at the interval below, both are negligible. Supervisor-side
  resolution was considered: one query and one event per node, but a
  new stream control message, a replay on respawn and a consistency
  window of its own.
- **Through `hickory-resolver`** behind the `Resolve` seam (D-a),
  configured from the system (`/etc/resolv.conf`) with the hosts file
  honoured, because it returns record TTLs, which a TTL-bounded
  schedule needs and `getaddrinfo` does not give. Implemented in
  `lorica/src/stream_engine.rs`, where `hickory-resolver` already is a
  dependency. *Cost:* NSS sources other than files and DNS (LDAP, mDNS)
  are not consulted for stream backends, while HTTP's resolution goes
  through the C library; `docs/streams.md` says so.
- **Schedule.** A name is re-resolved at its record TTL clamped to
  [5 s, 60 s] (`DNS_MIN_INTERVAL`, `DNS_MAX_INTERVAL`, constants): the
  floor keeps a TTL of 0 from hammering the resolver, the ceiling bounds
  staleness after a failover, HAProxy-like (`hold valid 10s` by
  default) rather than nginx-like (TTL as given). A name used for the
  first time is resolved on demand within the connect timeout. Names
  leave the cache when no stream of the table uses them
  (`table_changed`). IP literals are never resolved.
- **Failure keeps the last addresses.** A failed or empty resolution
  leaves the cached list in place and retries at the floor; the first
  failure after a success, and the first success after failures, each
  log one warn line (stream-independent: the backend id and name) and
  count `dns_failures` per backend: that is the "health event" of AC
  #13. A name never resolved has no address and is not a candidate.
  No notification is raised in this story (Resolved 3): whether a
  resolution failure joins the "stream backend down" notification is
  an input to Story 12.9 AC #5.
- **Locality after every resolution**: D-m runs on the new list; a
  local address is dropped from the list for the streams whose rules
  refuse it, and a list left empty excludes the backend from those
  streams (IV4).
- Address choice within a backend: round robin over its usable
  addresses per attempt; a failed address is not tried again by the
  same connection.

### D-o. Bandwidth limits

- **Fields** `upload_rate_bps` and `download_rate_bps`, bytes per
  second per connection, nullable (unlimited, the default, as nginx's
  `proxy_upload_rate` / `proxy_download_rate` 0), from 1,024 to
  10,000,000,000.
- **Mechanism.** A token bucket per direction per connection, refilled
  at the rate, capacity `min(rate, FORWARD_BUFFER_SIZE)`, so the burst
  is at most one second's worth and at most one buffer. Before each
  read the direction waits until at least one token is available, then
  reads at most `min(tokens, buffer)` bytes and spends what it read. The
  limit throttles reads, never queues writes, so it composes with the
  backpressure of D-c and holds no extra memory.
- Upload is client to backend (reads from the client), download backend
  to client. The PROXY header and the preamble are not charged.

### D-p. The per-stream connection cap and the fd budget

- **Field** `max_connections`, default **1,024**, range 1 to 65,535,
  enforced **per worker process in this story**: each worker (and the
  single process) counts the stream's open connections in an atomic per
  stream and refuses the next one at admit with
  `refused(connection_cap)`, counted, the socket closed at once. A new
  `StreamRefusal::ConnectionCap` (`connection_cap`). Refused rather than
  left in the backlog, so overload is visible as a counter instead of
  as latency.
- **Per worker now, per node from Story 12.6, one field throughout
  (Resolved 1).** A per-node count needs the shared tables Story 12.5
  creates, and a synchronous supervisor round trip per accept would
  cost the connect latency Story 12.12 measures. So this story enforces
  the cap per process, as the interim. When Story 12.6 AC #3 moves the
  per-stream cap onto the dedicated shared-memory tables, **the same
  `max_connections` field** becomes the per-node cap: no second field,
  no rename, no migration of meaning beyond the documentation. The
  field's doc comment, the `openapi.yaml` description and
  `docs/streams.md` all say "per worker process until Story 12.6, per
  node from then on", and 12.6 updates the three.
- **The interim's cost:** until 12.6, a node with `W` workers can hold
  up to `W x max_connections` connections of one stream. Each process
  stays within its own fd budget, which is what AC #14 and NFR2 bound.
- **The budget.** A TCP stream declares `HeldFds { ceiling:
  max_connections, fds_per_unit: 2 }` (client and backend sockets; the
  connect phase holds at most one backend socket at a time). One
  function, `lorica_stream::tcp::held_fds(&Stream) -> Option<HeldFds>`,
  used by the driver's `demand_of` and by the API's budget check (12.2
  Lot E3), so the two cannot disagree. At the packaged
  `LimitNOFILE=65536` (`S` = 31,744 per worker), the default admits
  about fifteen TCP streams per node before the budget refuses one; the
  refusal names the stream, the numbers and the constraint, and the
  budget view shows each stream's share.

*Note (2026-11-18):* the interim above is over. Story 12.6 (D-f) moved
the cap onto the stream-caps region, so `max_connections` is the most
concurrent connections of the stream on one node, counted across its
workers, as the field's doc comment, `openapi.yaml` and the settings
table of `docs/streams.md` now say. A node no longer holds
`W x max_connections`. The fd budget still sizes each worker for the
stream's whole cap, since one worker may hold all of it.

### D-q. The new fields, the migration, and every surface they reach

**`Stream`** gains, each with its default, in `models/stream.rs`:

| Field | Type | Default |
|---|---|---|
| `load_balancing` | `LoadBalancing` | `round_robin` |
| `connect_timeout_ms` | `u32` | 5,000 |
| `idle_timeout_s` | `u32` | 600 |
| `total_timeout_s` | `Option<u32>` | none |
| `max_connect_attempts` | `u8` | 3 |
| `backend_keepalive` | `bool` | true |
| `backend_keepalive_idle_s` | `u32` | 60 |
| `close_on_backend_down` | `bool` | false |
| `proxy_protocol_send` | `StreamProxyProtocol` | `off` |
| `proxy_protocol_accept` | `bool` | false |
| `proxy_protocol_trusted_cidrs` | `Vec<String>` | empty |
| `source_addresses` | `Vec<IpAddr>` | empty |
| `allow_local_backend` | `bool` | false |
| `upload_rate_bps` | `Option<u64>` | none |
| `download_rate_bps` | `Option<u64>` | none |
| `max_connections` | `u32` | 1,024 |

and `StreamBackend` gains `backup: bool` (false). Ranges are D-d to D-p's,
as associated constants beside `STREAM_PORT_RANGE_MAX`, enforced by
`Stream::validate`.

- **One migration**, at the next free number of `MIGRATIONS`: **75** if
  12.2 Lot E1's subscription migration (74) has landed first, as
  planned; whichever number is free when Lot B commits, recorded in the
  Completion Notes. `add_column_if_absent` per column on `streams`
  (scalars as `INTEGER` / `TEXT NOT NULL DEFAULT ...`, the two lists as
  JSON `TEXT NOT NULL DEFAULT '[]'`, nullable columns without default)
  and `stream_backends.backup INTEGER NOT NULL DEFAULT 0`. No `CHECK` on
  enumerated text (`load_balancing` grows in 12.13), validation in code,
  12.1 D-1's rule. Idempotent by construction; a test runs it twice.
  `STREAM_COLUMNS` extended; the store never reads `SELECT *`.
- **Rollback to 1.10.6** stays safe for 12.1 D-2's reasons: 1.10.6
  never names `streams` or `stream_backends`.
- **Canonical config:** the fields ride format version 3 (12.1 D-3),
  each `#[serde(default)]` so a TOML file from an earlier 1.11.0 build
  still imports; `CANONICAL_SHAPE_DIGEST` updated deliberately, with the
  version-3 rider test's message unchanged.
- **Diff and export/import:** `compute_diff` reports the new fields and
  the backup flag; `[[streams]]` and `[[stream_backends]]` carry them.
- **UDP streams:** every field above must hold its default on a UDP
  stream, and a backup link is refused there, with a message naming
  Story 12.5, which lifts the ones it gives a UDP meaning.
  `proxy_protocol_accept` stays refused on UDP for good (D-k).
- **Management API.** `CreateStreamRequest` and `UpdateStreamRequest`
  gain every field (optional, defaults as above); `StreamResponse` gains
  them, field by field like the existing ones; backups travel as
  `backup_backend_ids` beside `backend_ids` (primaries), a backend in
  neither list twice. `STREAM_WITHHELD_FIELDS` stays empty: nothing here
  is a secret, and the trusted CIDRs and the local flag are exactly what
  an operator reviewing a stream must see. 400 for validation, 409 for
  rule B (a conflict with a node's ports, like 12.1's port conflicts).
- **`lorica-api/openapi.yaml`**: the stream schemas gain the fields,
  ranges and enums; `StreamProxyProtocol` and the refusal enum (now
  with `connection_cap`) derived from the Rust enums where the contract
  test can check them. `openapi-automation.yaml` is untouched: streams
  reach the automation surface in Story 12.10.
- **Dashboard**: none in this story. The Streams page and its form,
  including the "local backend" badge, are Story 12.10 AC #1.

### D-r. What the engine exposes for Story 12.9, and what it does not do

12.3 counts and reports; 12.9 names metrics, aggregates workers and
writes logs.

- **`StreamCounters`** (`lorica_stream::counters`), one per process,
  readable as a snapshot through `StreamRuntimeHandle::counters()`.
  Atomics, created per stream and per (stream, backend) on first use,
  pruned on `table_changed`:
  - per stream: `active` (gauge), `accepted`, `ended` per
    `StreamEndKind`, `refused` per `StreamRefusal`, `bytes_upload`,
    `bytes_download`, `connect_attempts`, `retries`,
    `breaker_denied`, `proxy_header` per outcome (accepted v1, v2,
    local; refused malformed, oversized, unsupported, timeout,
    untrusted_peer), `local_destination_refused`,
    `source_family_mismatch`, `source_bind_failed`;
  - per (stream, backend): `active`, `connects`, `connect_failures`
    per kind (refused, timeout, unreachable, reset), and connect latency
    as a fixed-bucket histogram (bucket bounds a constant slice, the
    same shape the existing request-latency histogram uses);
  - per backend: `dns_failures`, `dns_local_excluded`.
  Bytes are added per completed write, so a long connection's traffic
  is visible while it lasts. Words come from the enums' `as_str` /
  `VARIANTS`, never typed out (`.claude/rules/derived-not-transcribed.md`).
- **The connection record**, built once at end and handed to a
  `ConnectionObserver` trait (`lorica_stream::handler`), whose default
  logs it at debug: stream id and name, `bind_gen`, client address
  (after PROXY), socket peer, `proxied_from` (the socket peer when a
  header was accepted), local address, backend id and the address
  connected, attempts, bytes each way, accepted, connected and ended
  instants, end reason. 12.9 installs the access-log writer; 12.16
  carries the same values across a transfer.
- **Not done here:** Prometheus names, `PER_WORKER_COUNTERS` entries,
  the access-log row and its sinks, the SLA view, notifications. All
  are 12.9's ACs.

### D-s. What later stories rely on, stated so they need not reopen this one

- **12.4:** a TLS read is a phase-2 reader with its own ceiling into
  the same preamble; the PROXY header (D-j) is written in plaintext on
  the backend socket right after connect, before any TLS handshake (as
  HAProxy and nginx do), and upstream TLS then wraps the socket, so the
  preamble and every forwarded byte travel inside TLS; TLS-terminated
  forwarding reuses D-c over the TLS stream (and so loses the plain
  socket quiesce point, which D8 accepts).
- **12.6:** filters and caps run at D-b step 1; refusals use
  `StreamRefusal` variants of their own; the counters of D-r are where
  they count; `max_connections` moves onto the shared tables and
  becomes per node (D-p), with `connection_cap` as its refusal.
- **12.11:** the tracker already ends connections with whatever reason
  `quiesce` carries; the preview reads `active` per stream.
- **12.13:** weighted P2C is a new arm of `select_index`, reached by
  HTTP and streams at once.
- **12.15:** detection is a phase-2 reader; the hairpin exception is a
  named case of rule B, added to `local_backend_conflicts` and the
  connect-time check together.
- **12.16:** the quiesce point and `held_bytes` of D-c, the record of
  D-r, and the token buckets of D-o (whose state moves with the
  connection, 12.16 AC #3).

## Tasks

Lots with hard file allowlists. A Lot touches only its files; two Lots
that share a file are sequential, never parallel, and say so. Every Lot
that runs cargo ends on a tree that passes the gate chain CI runs
(`cargo fmt --all -- --check`, the workspace clippy with
`--all-targets --features lorica/otel -- -D warnings` under
`CARGO_BUILD_WARNINGS=deny`, the CI `cargo test` lines, `cargo audit`),
through Docker on Linux. No agent runs `git checkout`, `git restore`,
`git stash` or `git reset` in the shared tree.

**Order.** A, B and D1 first, in parallel (disjoint files). C after A
and B. E after B, and after 12.2 Lot E3 (both edit
`lorica-api/src/streams.rs` and `openapi.yaml`). D2 after C and D1,
after 12.2 Lot E3 (`supervisor.rs`, `single.rs` construction sites),
after 12.8 Lot D (`worker.rs`, `single.rs`) and after any open 12.7 Lot
that edits `lorica/src/health.rs`. F after C, D2 and E. G after D2, E
and 12.2 Lot H (whose `streams` profile it extends).

### Lot A: the PROXY encoder in `lorica-core` - cargo

Allowlist: `lorica-core/src/protocols/proxy_protocol.rs`,
`fuzz/fuzz_targets/fuzz_proxy_protocol.rs`, `FORK.md` (the parser's
divergence entry only).
Depends on: nothing from this story; sequential with 12.8 Lot B if that
Lot is editing `FORK.md` at the same time.

- [x] `encode_v1`, `encode_v2`, `encode_v1_unknown`, `encode_v2_unspec`
      (D-j), doc comments, one runnable example.
- [x] Tests: every encoded header round-trips through `parse` to the
      same addresses and `consumed == len`; IPv4, IPv6, ports 0 and
      65,535; v1 lengths within `V1_MAX_LEN`.
- [x] Fuzz target: a round-trip arm (addresses derived from the input
      bytes, encode, parse, compare).
- [x] `FORK.md`: the parser entry names the encoder.

### Lot B: model, schema, validation - cargo

Allowlist: `lorica-config/src/models/stream.rs`,
`lorica-config/src/models/mod.rs`, `lorica-config/src/models/backend.rs`
(a host-part reader beside `backend_address_port` only),
`lorica-config/src/local_address.rs` (new), `lorica-config/src/lib.rs`
(the module line), `lorica-config/src/listen_ports.rs`,
`lorica-config/src/connection_filter.rs` (only if 12.8 Lot C1 has not
landed the trust-list rule; otherwise read only),
`lorica-config/src/store/mod.rs` (the migration only),
`lorica-config/src/store/streams.rs`, `lorica-config/src/store/row_helpers.rs`,
`lorica-config/src/canonical.rs`, `lorica-config/src/diff.rs`,
`lorica-config/src/export.rs`, `lorica-config/src/import.rs`,
`lorica-config/src/tests.rs`, and every file holding a `Stream { .. }`
or `StreamBackend { .. }` literal that the new fields break, as `grep`
lists them when the Lot starts (on `0a891772`:
`lorica-stream/src/{reconcile,table,tracker}.rs`,
`lorica-stream/tests/runtime.rs`,
`lorica/src/startup/{drain,stream_plane}.rs`,
`lorica-api/src/{streams.rs,streams/tests.rs,backends.rs}`; literal
sites only, no behaviour).
Depends on: 12.1 (landed). Preferably after 12.8 Lot C1 (shared rule in
`connection_filter.rs`); if before, this Lot adds the rule there and
12.8 C1 reuses it. Runs alone: it is the shape change every later Lot
compiles against.

- [x] The fields and defaults of D-q, `StreamProxyProtocol`,
      `StreamBackend::backup`, the range constants,
      `StreamRefusal::ConnectionCap`.
- [x] `Stream::validate`: ranges, the trust-list rules (D-k), the
      source-address rules (D-l), the UDP rule (D-q).
- [x] `local_address.rs`: `is_local_ip`, `is_local_host_name` (D-m).
- [x] `check_backend_attachments`: `AttachmentRule::LocalBackend`
      (rule A), the all-backups rule (D-f), the source-family rule for
      IP-literal backends (D-l).
- [x] `listen_ports.rs`: `local_backend_conflicts` (rule B, D-m) over
      `&[NodePorts]`.
- [x] Migration, store columns, `STREAM_COLUMNS`, the backup column in
      `set_stream_backends` and its readers; canonical digest; diff;
      export and import.
- [x] Tests: each default; each range at both bounds and one past;
      every validation refusal named by its rule; rule A with
      `127.0.0.1`, `::1`, `::ffff:127.0.0.1`, `169.254.1.1`, `fe80::1`,
      `0.0.0.0`, `localhost`, `db.localhost`, and acceptance of the same
      with the flag; rule B for a reserved port, another stream's port,
      the stream's own range with a portless local backend; migration
      idempotence; a 12.1-shaped TOML export imports with defaults;
      canonical round trip.

### Lot C: the engine in `lorica-stream` - cargo

Allowlist: `lorica-stream/src/tcp/**` (new: `mod.rs`, `engine.rs`,
`forward.rs`, `connect.rs`, `proxy_header.rs`, `seams.rs`,
`resolver.rs`, `local.rs`, `bandwidth.rs`, `cap.rs`),
`lorica-stream/src/counters.rs` (new), `lorica-stream/src/handler.rs`,
`lorica-stream/src/table.rs`, `lorica-stream/src/runtime.rs`,
`lorica-stream/src/listener.rs`, `lorica-stream/src/lib.rs`,
`lorica-stream/Cargo.toml` (the `lorica-core` edge; `socket2` features
if needed), `lorica-stream/tests/tcp_*.rs` (new),
`lorica-worker/src/stream_sockets.rs` (an interface-address reader
only, `nix` `ifaddrs`), `lorica-worker/Cargo.toml` (that `nix` feature
only), `Cargo.lock`.
Depends on: A, B.

- [x] Seams (D-a), with in-crate fakes for tests.
- [x] Pipeline (D-b), forwarding (D-c, with `DirectionState` and
      `held_bytes`), timers (D-d), retry (D-h), PROXY accept and send
      (D-j, D-k), source binding (D-l), connect-time local check (D-m,
      with `BoundPorts` filled by the accept loop into
      `AcceptedConnection`), resolver cache and schedule over the
      `Resolve` seam (D-n), token buckets (D-o), cap and `held_fds`
      (D-p), counters and record (D-r).
- [x] `StreamTable::with_backends`, backup flags, accessors; runtime:
      `table_changed` after every reload, the `backend_down` drain
      (D-i); `StreamHandler::table_changed` defaulted.
- [x] `ConnectionObserver` with a debug-logging default.
- [x] Tests (Linux, real sockets, fake seams): echo through the engine
      both ways; half-close each way (client FIN then backend still
      sends; backend FIN then client still sends) with the right end
      reason; a non-reading client stalls the backend writer and the
      engine's memory stays at two buffers (a 64 MiB transfer with the
      reader paused: `held_bytes` never above 16 KiB per direction);
      idle, total and connect timeouts each end with their reason;
      retry: first backend refuses, second accepts, client bytes sent
      before connect arrive once; all refuse gives `connect_failed`,
      none eligible gives `no_healthy_backend`; backups only after
      primaries are exhausted; a `Deny` re-selects without an attempt;
      PROXY: trusted v1 and v2 carry the address into the record and
      into a v2 send, a trickled header past 5 s, 4,097 bytes, `DGRAM`,
      and an untrusted peer's v1 and v2 each end `proxy_header_invalid`
      with nothing forwarded, while an untrusted `PING` is forwarded;
      v1 and v2 send with family mismatch; local destination refused
      with and without the flag, on a reserved port and on a bound
      stream port; resolver: TTL clamped both ways, failure keeps the
      last list, a re-resolution to `127.0.0.1` excludes the backend
      and nothing connects to it; bandwidth: 64 KiB at 16 KiB/s takes
      between 3 and 5 s each way; cap: connection 1,025 of a 1,024 cap
      is refused and counted; `close_on_backend_down` closes with
      `backend_down` only when the accepted snapshot sets it; a tracker
      drain ends a connection in each phase with the drain reason.

### Lot D1: the shared selection function - cargo

Allowlist: `lorica/src/proxy_wiring/lb.rs`, `lorica/src/proxy_wiring.rs`
(the selection block of `upstream_peer` only),
`lorica/src/proxy_wiring/tests.rs`, `lorica/benches/circuit_breaker.rs`
(only if it calls what moved).
Depends on: nothing. A `refactor(proxy)` commit of its own.

- [x] `select_index` and `SelectionState` (D-e); `upstream_peer` calls
      it with the values it computes today.
- [x] Tests: the existing selection tests pass unchanged; one new test
      per algorithm asserting `select_index` returns what the former
      inline block returned for the same inputs (round robin sequence
      for weights 5,1,1; ketama index for a fixed IP; least-conn tie;
      random for a fixed seed; EWMA exploit).

### Lot D2: wiring in the binary - cargo

Allowlist: `lorica/src/stream_engine.rs` (new), `lorica/src/lib.rs` or
`lorica/src/main.rs` (the module line, wherever `startup` is declared),
`lorica/src/startup/worker.rs`, `lorica/src/startup/single.rs`,
`lorica/src/startup/supervisor.rs`, `lorica/src/startup/stream_plane.rs`,
`lorica/src/startup/mod.rs` (`spawn_health_check_loop`),
`lorica/src/health.rs` (the `on_change` hook only), `lorica/src/cli.rs`
(the worker's `--reserved-ports`), `lorica/src/main.rs`,
`lorica-worker/src/manager.rs` (the exec arguments only),
`lorica/tests/stream_engine_*.rs` (new), `Cargo.lock`.
Depends on: C, D1; after 12.8 Lot D, 12.2 Lot E3 and any open 12.7 Lot
on `health.rs`.

- [x] `stream_engine.rs`: `BackendSelector` over `select_index` with
      per-stream WRR, its own `BackendConnections` and `EwmaTracker`;
      `BreakerGate` over `BreakerEngine` with the `stream:` key and the
      late-bound slot (D-g); `Resolve` over `hickory-resolver` from the
      system configuration with the hosts file (D-n).
- [x] `run_worker`: build the engine, install it in `Engines.tcp`, fill
      the breaker slot after `RpcEndpoint::from_raw_fd`.
      `run_single_process`: same, with the local `BreakerEngine` clone.
      The test drivers in `stream_plane.rs` and `drain.rs` keep
      `Engines::default()`.
- [x] `StoreStreamTable::load` reads the linked backends;
      `demand_of` declares `held_fds` (D-p).
- [x] `StreamPlaneHandle::refresh_tables()` and its single-process
      twin; `health_check_loop`'s `on_change` wired to them (D-i).
- [x] `--reserved-ports` from `WorkerManager` to `run_worker` (D-m).
- [x] Tests: two workers' worth of breaker traffic through a real
      `SupervisorBreakerRegistry` and RPC pair trip the (stream,
      backend) entry and leave a route entry with the same backend
      address closed; a health flip written to the store reaches a
      worker's stream table through `refresh_tables`; the hickory
      adapter against an in-test UDP responder returns the TTL; the
      worker parses `--reserved-ports` back to the supervisor's value.

### Lot E: API surfaces - cargo

Allowlist: `lorica-api/src/streams.rs`, `lorica-api/src/streams/tests.rs`,
`lorica-api/src/backends.rs`, `lorica-api/src/config.rs` (the import's
port check only), `lorica-api/src/automation/write.rs`,
`lorica-api/src/automation/tests.rs`, `lorica-mcp/src/tools.rs` (tests
only), `lorica-api/openapi.yaml`, `lorica-api/src/tests.rs`.
Depends on: B; after 12.2 Lot E3 (same files).

- [x] Request and response fields, `backup_backend_ids` (D-q).
- [x] Rule B (`local_backend_conflicts`) on stream create and update,
      backend update (each linked stream) and import, answering 409.
- [x] The automation guard of D-m, and confirmation that the MCP backend
      tool reaches it (Completion Notes say how).
- [x] `openapi.yaml`, contract test green; the `max_connections`
      description reads "per worker process until Story 12.6, per node
      from then on" (Resolved 1).
- [x] Tests: IV4's first half (`127.0.0.1:<management port>` refused at
      creation, with and without the flag); a backend update moving a
      linked backend onto a stream port refused; the automation guard
      refuses a token's address change on a backend of a flagged stream
      and allows it on an unflagged one; the response key set test
      updated by the model's fields.

### Lot F: documentation - no cargo

Allowlist: `docs/streams.md` (the TCP engine sections),
`docs/security/threat-model.md`, `docs/security/hardening-guide.md`
(source addresses and capacity), `CHANGELOG.md`.
Depends on: C, D2, E.

- [x] **Verify the survey values first (Resolved 9).** For every
      competitor value in D-d's table, open the source the PRD links
      ("Sources" under "Prior Art") for that product and setting, read
      the documented default, and record value and URL. A value the
      source does not state is written "not documented", never filled
      from memory. Correct D-d's table in this story where a value
      differs, and list each check (setting, product, value, URL) in
      the Completion Notes.
- [x] `docs/streams.md`: the pipeline; algorithms with the weights
      sentence and the per-process least-conn note; backups; breaker;
      retry and the two end reasons; the defaults table of D-d with
      the URL it was verified from beside every competitor value;
      keepalive on by default and why it differs from nginx and
      HAProxy; PROXY send and accept with the untrusted-peer behaviour,
      no `optional` mode, and the reason UDP accept is refused; source
      addresses and `IP_BIND_ADDRESS_NO_PORT`; local backends, both
      rules, the interface-address check, what validation cannot see,
      and that a local re-resolution excludes the backend from the
      stream only; DNS and the NSS limitation; bandwidth;
      `max_connections` as "per worker process until Story 12.6, per
      node from then on" with its budget arithmetic; buffers and why no
      splice.
- [x] Threat model: a stream exposing local services; forwarding loops
      (same node refused; across nodes not detected, bounded by caps);
      DNS rebinding of stream backends; PROXY-header spoofing on
      streams.
- [x] `CHANGELOG.md` `[Unreleased]`: Added (the TCP engine), Security
      (local backends refused, PROXY trust per stream).

### Lot G: end-to-end, IV1 to IV4 - Docker e2e

Delivered by Story 12.12 Lot C.

Allowlist: `tests-e2e-docker/test-runner/run-streams-tcp.sh` (new, LF),
`tests-e2e-docker/test-runner/tcp_backend.py` (new),
`tests-e2e-docker/test-runner/dns_responder.py` (new),
`tests-e2e-docker/test-runner/Dockerfile` (the `COPY` and `chmod` lines),
`tests-e2e-docker/docker-compose.yml` (the `streams` profile only),
`tests-e2e-docker/run.sh` (one call).
Depends on: D2, E, 12.2 Lot H. The machine to itself, orphan containers
torn down first.

- [ ] `tcp_backend.py` (stdlib): echo with an identity prefix, a mode
      that parses a PROXY v2 header and echoes the carried source, a
      mode that closes its listening socket while keeping established
      connections.
- [ ] IV1 with three Python backends (the `psql` form is Story 12.12's,
      Resolved 6): balancing per algorithm over 300 connections;
      kill one backend; every new connection after the breaker trips
      succeeds; a connection opened before the kill on a survivor keeps
      echoing.
- [ ] IV2: one backend linked to a route and a stream; its listener
      closes; after the health thresholds both the route and the stream
      stop selecting it; the stream connection established before is
      still echoing.
- [ ] IV3: v2 send seen by the backend with the runner's address; with
      the runner outside the trusted list, a v1 and a v2 header are
      disconnected and counted.
- [ ] IV4 second half: `dns_responder.py` answers a test name with a
      runner-reachable address, then `127.0.0.1`, with a 5 s TTL; the
      Lorica service's `dns:` points at the runner; after the switch no
      connection reaches the backend and the exclusion is logged. If the
      Docker embedded DNS does not forward as expected, the half is
      proved by Lot D2's hickory test against the in-test responder, and
      the Completion Notes say so.

## Dev Notes

### Where to extend, verified on `0a891772`

- `lorica-stream/src/listener.rs`: `accept_loop` (registration before
  the spawn; where `BoundPorts` joins `AcceptedConnection`),
  `LoopContext`, `adopt` (the socket's local address gives the bound
  port).
- `lorica-stream/src/runtime.rs`: `StreamRuntime::run`, `reload_table`,
  `refresh` (the `config_removed` drain the `backend_down` drain goes
  beside), `attach` (reloads the table for an unknown stream), `reap`.
- `lorica-stream/src/tracker.rs`: `register`, `drain_where`,
  `TrackedConnection::{closed, set_backend, finish}`.
- `lorica-stream/src/table.rs`: `StreamTable::{new, stream, holds}`,
  `StreamTableSource`.
- `lorica-stream/src/budget.rs`: `HeldFds`, `StreamDemand::with_held`;
  `lorica/src/startup/stream_plane.rs`: `demand_of`, `StoreStreamTable`,
  `StreamPlaneHandle`.
- `lorica/src/proxy_wiring.rs`: `upstream_peer` (the eligibility loop,
  the breaker loop, the selection `match`, the keepalive constants
  15/5/3 on `peer.options.tcp_keepalive`).
- `lorica/src/proxy_wiring/lb.rs` (`EwmaTracker`, `CircuitBreaker`),
  `config.rs` (`SmoothWrrState`), `helpers.rs` (`pick_consistent_hash`),
  `engines.rs` (`BreakerEngine`, `BreakerAdmission`).
- `lorica/src/startup/supervisor.rs`: `SupervisorBreakerRegistry`,
  `handle_breaker_query`, `handle_breaker_report`, the
  `spawn_health_check_loop` call, `ConfigReloadBridge`.
- `lorica/src/health.rs`: `health_check_loop` (Phase C and the
  `changed` tail where `on_change` goes).
- `lorica/src/startup/worker.rs`: `run_worker` (`StreamRuntime::spawn`
  early, `RpcEndpoint::from_raw_fd` late, `BreakerEngine::rpc`).
- `lorica-worker/src/manager.rs`: the exec argument list of a worker.
- `lorica-config/src/models/stream.rs`: `Stream`, `StreamBackend`,
  `StreamRefusal`, `StreamEndReason`, `AttachmentSnapshot`,
  `AttachmentRule`, `check_backend_attachments`;
  `models/backend.rs`: `backend_address_port`;
  `listen_ports.rs`: `ReservedPorts`, `NodePorts`,
  `stream_port_conflicts`; `connection_filter.rs`: `parse_cidr`,
  `validate_cidr_list`.
- `lorica-core/src/protocols/proxy_protocol.rs`: the parser surface.
- `lorica-api/src/streams.rs`: `StreamResponse`, `CreateStreamRequest`,
  `UpdateStreamRequest`; `automation/write.rs`: `update_backend`,
  `ensure_backend_row_granted`.
- `lorica/src/bot_rdns.rs`: how a `TokioResolver` is built from the
  system configuration with hickory 0.26.

### Pitfalls

- **The stream runtime has one thread per process.** A blocking call
  in the engine (std DNS, a `std::sync::Mutex` held across an await, a
  store read) stalls every stream of the worker. Resolution goes
  through hickory; nothing in the engine touches the store.
- **`IP_BIND_ADDRESS_NO_PORT`** must be set before `bind`. I'm not sure
  `socket2` 0.6 exposes it; if not, `nix`'s socket option or a
  `setsockopt` in `lorica-worker` (which already uses `nix`), never an
  `unsafe` block in `lorica-stream`.
- **Server-first protocols.** No phase may wait for client bytes
  unless the stream asked for it (trusted PROXY accept). The untrusted
  sniff is in-flight (D-k), not before connect.
- **IPv4-mapped peers** on `[::]` listeners: canonicalise before the
  trust check, the hash key, PROXY send and the record.
- **`shutdown(Write)` on a socket whose peer already reset** returns
  `ENOTCONN`; that is an end, not an error to log.
- **A drained connection in phase 3** may have a connect in flight:
  dropping the future closes the half-open socket; report nothing to
  the breaker for it.
- **Breaker key collisions with HTTP** are impossible by the `stream:`
  prefix; do not "simplify" it away.
- **Heredocs with apostrophes break the Bash tool** (project memory):
  write scripts with the Write tool; keep `.sh` files LF.

### Tests per Lot

Listed in each Lot. Lots A to D2 need Linux and run through the
`run-tests` skill in Docker. Lot G is the e2e suite, run alone on the
machine. What no automated test here proves: throughput, CPU per GiB
and accept-to-connect p99 against nginx, which are Story 12.12's
performance phase.

### Handed to other stories

- **12.9:** `StreamCounters` and the connection record (D-r); as an
  input to its AC #5, whether a backend's DNS resolution failure (the
  `dns_failures` event of D-n) joins the "stream backend down"
  notification. 12.3 raises no alert for it.
- **12.10:** the form for every field of D-q and the "local backend"
  badge.
- **12.12:** IV1 with `psql` against real PostgreSQL backends, under
  the image approval of its AC #6; the performance thresholds; the
  decision on splice if CPU per GiB misses.
- **12.6:** AC #3 moves `max_connections` onto the dedicated
  shared-memory tables, where the same field becomes the per-node cap,
  and updates its doc comment, the `openapi.yaml` description and
  `docs/streams.md` accordingly (D-p). No second field.

## Resolved (maintainer, 2026-11-14)

1. **The connection cap** is enforced per worker process in this story,
   as the interim, through one field, `max_connections`, whose meaning
   becomes per node when Story 12.6 AC #3 moves it onto the dedicated
   shared-memory tables. The decision (D-p), the field's doc comment,
   the `openapi.yaml` description and `docs/streams.md` say so, so no
   second field appears later.
2. **A hostname re-resolving to a local address** is marked down for
   the stream only (excluded from its candidates, with a health event),
   never in the shared `health_status` (D-m).
3. **No alert for a DNS resolution failure** in 12.3. Recorded as an
   input to Story 12.9 AC #5 (D-n, "Handed to other stories").
4. **No `optional` PROXY accept mode** on streams in 1.11.0 (D-k).
5. **Selection is shared through a trait** implemented over the
   extracted `select_index`; no `lorica-balance` crate (D-a, D-e).
6. **IV1 runs with Python TCP backends** in this story's e2e (Lot G);
   the `psql` form runs in Story 12.12, under its AC #6 image approval.
7. **Backend keepalive on by default** (60 s), for the NAT-mapping and
   dead-host reasons stated in D-d.
8. **`source_addresses` is a list** of at most 16 (D-l).
9. **Survey values quoted from memory do not reach the docs
   unverified.** Lot F checks each competitor value of D-d against the
   sources the PRD links, writes the URL beside each value in
   `docs/streams.md`, and corrects this story's table where a value
   differs.

## Dev Agent Record

### Debug Log

### Completion Notes

**Lot E (API surfaces).**

- Status codes follow the house rule the stream handlers already
  documented, not D-q's "400 for validation": a body that parses and
  breaks a model rule (a range, the trust list, the UDP rule, rule A,
  the backup and source-family rules, a backend in both lists) is
  `422`, as `ConfigError::Validation` maps it; rule B is `409` with a
  code of its own, `stream_local_backend`, beside `stream_port_conflict`,
  so a client tells a local backend on a node's port from a listener
  conflict. A refusal names the first conflict only, as a port conflict
  does.
- API shape. `StreamResponse` carries the sixteen settings field by field
  under their model names (`load_balancing` snake_case,
  `proxy_protocol_send` `off`/`v1`/`v2`, `total_timeout_s`,
  `upload_rate_bps` and `download_rate_bps` `null` for no limit,
  `source_addresses` as canonical text), `backend_ids` (primaries) and
  `backup_backend_ids`, each sorted. `CreateStreamRequest` and
  `UpdateStreamRequest` take every setting as optional; an absent one
  is `Stream::new`'s default on create and the stored value on update,
  and `null` lifts the three nullable limits on update (`Option<Option<_>>`
  through a `nullable` deserializer). One `EngineSettings` type applies
  the settings for both bodies. On update `backend_ids` replaces the
  primaries and `backup_backend_ids` the backups; a list left out keeps
  its stored half. `STREAM_WITHHELD_FIELDS` stays empty.
- Update write order. When the links change, the update unlinks, writes
  the row, then writes the new links, in one transaction. The former
  order (links, then row) judged the new links against the old row, so
  setting `allow_local_backend` together with the local backend it
  allows was refused; the reverse order would refuse dropping both.
  Unlinking first means each check sees the final row against the final
  links.
- Rule B, where it runs. `refuse_local_backends` on stream create and
  update, under the store lock, after the port check and before the
  budget: the candidate's own local backends against the nodes that
  would bind it (`local_backend_conflicts` over `nodes_checking`, the
  nodes of the port check), and the other way round, every stored
  stream's local backend that would now reach a port the candidate
  takes (the stream being written moved onto a port another stream
  forwards to through loopback); the refusal names the stream whose
  backend it is. Backend update (`update_backend_as`, so every plane,
  automation included, and its preview): `refuse_local_backend_on_its_streams`
  checks the backend as it would be written as a link of each stream
  linking it. Import and its preview: `check_imported_streams` runs
  `first_local_backend_conflict` per file stream over the file's own
  backends and links, after the port check.
- IV4's first half, `lorica-api/src/streams/tests.rs`: a stream whose
  backend is `127.0.0.1:<management port>` is refused `409`
  `stream_local_backend` at creation with and without the flag, as a
  backup too, and spelled `localhost:` and `[::1]:`; a loopback backend
  on a free port is `422` without the flag and created with it. Rule B
  both ways on stream ports, the stream's own port included; a backend
  update moving a linked backend onto another stream's port, its own
  stream's port or the management port refused, nothing moved; an
  import and its preview refusing alike.
- D9 on automation and MCP. `backend_guard` (`automation/write.rs`)
  gains `ensure_not_moved_under_a_local_stream`: a token's write that
  changes the address of a backend linked to any stream with
  `allow_local_backend` is `403`, naming the backend id and the stream,
  never an address; the preview runs the same guard. The MCP backend
  tool reaches it because the in-process MCP binding dispatches each
  tool to its plane path (`lorica_backend_update` and its preview build
  `PUT /automation/v1/backends/{id}`, pinned in `lorica-mcp`'s
  `no_tool_reaches_a_stream_or_offers_the_local_backend_flag`), and
  `automation::tests::a_token_cannot_move_a_backend_a_stream_allowing_local_backends_forwards_to`
  drives both tools through the MCP endpoint and gets the `403` text.
  The field itself: no automation route path names a stream
  (`no_automation_path_reaches_a_stream`, over `route_table()`), and no
  MCP tool calls a stream path or declares `allow_local_backend` at any
  depth of its schema, a body naming it being refused before a request
  leaves.
- Budget, the Lot D2 hand-off. `StreamDemand::of` itself now declares
  `tcp::held_fds`, so it is the one demand function: the API's write
  check, the heartbeat's committed totals and the budget view build on
  it, and the driver's `demand_of` is `StreamDemand::of` of the stream
  with the binding's protocol and ports (a binding whose stream is gone
  still declares nothing). Its test asserts `demand_of == StreamDemand::of`.
  `adds_no_demand` (a write never refused on a node already over budget)
  also requires no more fds at the cap, so raising `max_connections` is
  new demand and lowering it is not. Tests in `stream_budget.rs`: at the
  packaged limit a single-port TCP stream with `(S - 1) / 2` connections
  passes and one more is refused, the API's verdict equal to the
  arithmetic over `StreamDemand::of` either way; fifteen default TCP
  streams fit and the sixteenth is refused `worker_fds` (D-p's "about
  fifteen"); and through the API at 4,096 fds, 511 connections fit and
  512 are refused on create and on update.
- `openapi.yaml`: the stream schemas carry every field, its range, enum
  and default; `StreamProxyProtocol` is a schema (`"off"` quoted, a YAML
  1.1 boolean otherwise); the request schemas reference the response's
  property definitions rather than repeating them. Tests read the
  document: the response, create and update schemas name exactly the
  fields the API answers and accepts (the create and update bodies are
  also fed the whole written view back, so a view field neither takes
  fails), every view field is required, each published range and
  `maxItems` is the model's constant, each published default is
  `Stream::new`'s, and both enums are the Rust enums'. The refusal enum
  (`connection_cap`) is not published: no endpoint answers it before
  Story 12.9's metrics and logs. `openapi-automation.yaml` is untouched,
  as D-q says, though its backend update can now answer the D9 `403`;
  the refusal's message carries the reason.
- The view key-set test drops the `TCP_ENGINE_FIELDS` filter Lot B left.
- Not fixed here, seen while writing the stream enum: the route schemas
  of `openapi.yaml` publish `load_balancing` without `least_conn`.

**Lot C (the engine in `lorica-stream`).**

- Layout. Story 12.5 Interface edits E2 and E3 are done here: the
  seams, the local check, the resolver cache and the counters are
  protocol-neutral modules at the crate root, `lorica_stream::{seams,
  local, resolver, counters}`, not under `tcp`, so 12.5 Lot E has no
  move to make. `lorica_stream::tcp` holds `engine.rs` (the pipeline of
  D-b), `connect.rs` (D-e to D-h, D-l, D-m), `forward.rs` (D-c, D-d),
  `proxy_header.rs` (D-j, D-k), `bandwidth.rs` (D-o) and `cap.rs` (D-p,
  `held_fds`).
- Seams (`lorica_stream::seams`): `BackendSelector { select(&SelectionRequest)
  -> usize, connected(stream_id, &Backend, SocketAddr, connect_latency),
  closed(stream_id, &Backend, SocketAddr), table_changed(&StreamTable) }`,
  where `SelectionRequest { stream, candidates: &[Candidate { backend,
  ring_address }], client: IpAddr, accepted_at: std::time::Instant }`;
  `BreakerGate { admit(stream_id, &Backend) -> Admission, record(stream_id,
  &Backend, success, was_probe) }` with `Admission::{Allow, AllowProbe,
  Deny}`; `Resolve { lookup(host) -> Result<Resolved { addresses, ttl },
  ResolveError> }`. The async methods return `SeamFuture` (a boxed
  future); no `async-trait` edge.
- Entry point: `TcpEngine::new(TcpEngineParts { selector, breaker,
  resolver: Arc<ResolverCache>, counters: Arc<StreamCounters>, observer:
  Arc<dyn ConnectionObserver>, reserved_ports: Option<ReservedPorts> })`,
  a `StreamHandler`. `ResolverCache::new(Arc<dyn Resolve>,
  Arc<StreamCounters>)` is built once per process and handed to both
  engines as an `Arc` (E3); so is the selector.
- `Engines` gains `counters: Arc<StreamCounters>`, which
  `StreamRuntimeHandle::counters()` snapshots: the `Arc` handed to the
  engine must be the same one. `lorica-stream/tests/runtime.rs` builds
  `Engines` with `..Engines::default()` now (two literal sites, outside
  the allowlist, no behaviour).
- `AcceptedConnection` gains `table: Arc<StreamTable>` (the table read at
  accept: backends, links, health) beside `bound_ports: BoundPorts`. The
  runtime counts every adopted socket's port in `BoundPorts` on attach
  and forgets it when the binding stops.
- `StreamHandler::table_changed` is called after every load (start,
  `refresh`, `attach` of an unknown stream); the engine prunes counters,
  caps, rotations and exclusions, tells the selector, and has the
  resolver track the table's host names. The runtime then drains with
  `backend_down`, deadline now, every connection whose accepted snapshot
  sets `close_on_backend_down` and whose backend is `Down` in the new
  table.
- `ConnectionRecord` and `ConnectionObserver` (debug-logging default
  method, `LogObserver`) are in `lorica_stream::handler`. A refused
  connection (cap, PROXY) gets a record too.
- Order inside the connect loop: select, local check, source family,
  then `admit`, so a half-open breaker's probe is never spent on a
  destination the engine would not connect. A breaker `Deny`, a local
  refusal and a family mismatch each remove the backend for this
  connection without an attempt. Each backend is tried at most once per
  connection (D-e); D-n's "a failed address is not tried again" is
  therefore met by construction, and the address within a backend
  rotates across connections through one process-wide counter. Zero
  attempts made ends `no_healthy_backend`, otherwise `connect_failed`.
- IV4's exclusion is per (stream, backend) and reported (warn line,
  `dns_local_excluded`) at the first connection that finds every
  address refused, not at the resolution: the rule depends on the
  stream's flag and the port, which the resolver does not know. A backend
  with some local and some remote addresses keeps the remote ones.
- `dns_failures` counts every failed or empty resolution; the warn line
  is per transition, as D-n says. On-demand resolution (a name used
  before the schedule reached it) happens only while no resolution of
  the name was tried yet: a name whose resolutions all failed is left to
  the schedule, so a dead name in a stream's list does not hold every
  new connection for its connect timeout.
- Token buckets wait for `min(1_024, capacity)` tokens before a read
  rather than one: a per-byte wake-up at 16 KiB/s would be 16,384 wakes
  a second. The smallest rate is 1,024 B/s, so the wait stays under a
  second; 64 KiB at 16 KiB/s still measures 3.0 s.
- Untrusted sniff: a client that sends FIN inside an unfinished
  signature gets its held bytes forwarded, then the FIN (it sent no
  header). A trusted peer that closes before a complete header counts
  `refused_malformed`; an accepted header without addresses (`LOCAL`,
  `UNKNOWN`, `AF_UNSPEC`, `AF_UNIX`) counts `accepted_local`.
- The quiesce point: `Forwarder::run` is cancel-safe at every await, so
  it can be dropped and resumed with nothing lost; `upload()` and
  `download()` expose `DirectionState::held_bytes()`,
  `at_quiesce_point()` reads both. The 64 MiB paused-reader test lives
  in `tcp::forward`'s unit tests for that reason (it parks the loop and
  reads the states). The family-mismatch send is a unit test of
  `proxy_header::send_header`: a real socket's peer and local address
  share a family, so no integration case reaches it.
- Counters' keyed families are `HashMap`s: `StreamEndKind` and
  `StreamRefusal` derive no `Ord`, and `lorica-config` is outside this
  Lot. `ProxyHeaderOutcome::ALL` and `ConnectFailureKind::ALL` carry
  their own word lists.
- `lorica-worker/src/stream_sockets.rs` gains
  `set_bind_address_no_port` beside the interface reader: `socket2` 0.6
  does not expose `IP_BIND_ADDRESS_NO_PORT`, and Pitfalls names this
  file for the `nix` call. `nix` gains the `net` feature for both.
- What Lot D2 implements: the three seams in `lorica/src/stream_engine.rs`
  (the selector over `select_index` with `ring_addresses` from each
  `Candidate::ring_address`, `client` as text, `lb::random_seed` of
  `accepted_at`, per-stream `SmoothWrrState` pruned in its
  `table_changed`, least-conn counted in `connected` / `closed`, EWMA fed
  the connect latency in `connected`; the breaker with the `stream:` key
  and the late-bound slot; hickory with TTLs); one `ResolverCache` and
  one selector per process; `Engines { tcp: Some(Arc::new(engine)),
  counters, ..Engines::default() }` with the same counters `Arc`;
  `StoreStreamTable::load` through `StreamTable::with_backends`;
  `demand_of` through `lorica_stream::tcp::held_fds`; the reserved ports
  into `TcpEngineParts::reserved_ports`.

**Lot D2 (wiring in the binary).**

- `lorica::stream_engine` is declared in `lib.rs`, not `main.rs`: it
  calls `proxy_wiring` (library), and the integration tests under
  `lorica/tests/` can only reach the library. The startup code uses it
  as `lorica::stream_engine`.
- `StreamSelector`: `select_index` with `ring_addresses` built from
  each `Candidate::ring_address` only for `consistent_hash` (no
  allocation for the other algorithms), the client as text,
  `lb::random_seed(accepted_at)`, one `SmoothWrrState` per stream id
  seeded with the process id as HTTP's route states are, its own
  `BackendConnections` (incremented in `connected`, decremented in
  `closed`) and its own `EwmaTracker` fed the connect latency in
  microseconds. Both are keyed by the configured address, which is what
  `select_index` reads. `table_changed` drops the round-robin state of
  streams the table no longer holds and the latency scores of addresses
  no linked backend has; `BackendConnections` has no removal API, so a
  deleted backend keeps a zero counter (bounded by the backends ever
  linked).
- `StreamBreakerGate`: an `ArcSwapOption<BreakerEngine>`, key
  `stream_breaker_key(id)` (`STREAM_BREAKER_PREFIX` and the id) with the
  backend's configured address; `Probe` maps to `AllowProbe`. Empty, it
  admits and records nothing. Worker: built empty before
  `StreamRuntime::spawn` and filled with the same `BreakerEngine::rpc`
  HTTP gets right after `RpcEndpoint::from_raw_fd`; when that fails or
  no RPC fd came, it is filled with the proxy's local engine, as HTTP
  falls back. Single process: `with_engine` over a clone of
  `LoricaProxy`'s local engine, the same `Arc<CircuitBreaker>`.
- `HickoryResolve`: `read_system_conf`, `use_hosts_file = Always`, a
  per-attempt timeout of 2 s with one retry so a lookup ends inside the
  cache's `DNS_RESOLVE_TIMEOUT`. The TTL is what is left of
  `LookupIp::valid_until`, so an answer from hickory's own cache is not
  taken as fresher than its record. An unreadable system configuration
  is one warn line and a resolver whose every lookup fails (IP-literal
  backends never call it). `with_config` exists for tests.
- `tcp_engines(breaker, resolver, reserved_ports)` builds the one
  selector, one `ResolverCache` and one counters `Arc` of a process and
  returns `Engines { tcp: Some(..), counters, ..Engines::default() }`.
  The observer is `LogObserver` until Story 12.9.
- `StoreStreamTable::load` reads `list_backends` and builds through
  `StreamTable::with_backends`, which keeps the linked rows only.
- `demand_of(key, Option<&Stream>)` adds `tcp::held_fds` of the stream
  the pass reads; a held binding whose stream is absent from the pass
  declares nothing (that same pass detaches it). Held bindings now
  carry their stream's name in the demand instead of an empty one.
- `StreamPlane::refresh_all` is the refresh-every-worker block
  `bind_desired` already ran on a change, factored out.
  `StreamPlaneHandle::refresh_tables` reads `drain_ms` from the settings
  and calls it; `refresh_hook()` wraps it in a spawned task for the
  health loop's `on_change: Option<Arc<dyn Fn() + Send + Sync>>`, so
  the loop never waits on a worker. The handle is generic over the
  link, so the single-process twin is the same method over
  `InProcessLink`.
- Supervisor: the health loop spawn moved below the stream plane's
  construction, which the hook needs; it still starts before the first
  reconcile and keeps its `reload_bc_tx` signal unchanged.
- `--reserved-ports` is `management,http,https,cluster,enrollment,automation`,
  `-` for a listener that is off (`cli::reserved_ports_arg`,
  `cli::parse_reserved_ports_arg`). `WorkerConfig` gains
  `reserved_ports: Option<String>`: `lorica-worker` does not depend on
  `lorica-config`, so the manager carries the encoded value. The
  supervisor builds it before forking, from the CLI: the cluster binds
  through `validate_cluster_listen` as the plane will validate them (an
  invalid bind stops the process when the plane starts), the automation
  port through `requested_port`. The argument is optional: a worker
  execed without it warns once and its engine refuses only the stream
  listen ports.
- Tests. `lorica/src/startup/supervisor.rs`: two workers' breaker
  traffic through real RPC socketpairs served by `handle_breaker_query`
  and `handle_breaker_report` over one `SupervisorBreakerRegistry` trips
  the `stream:<id>|<address>` entry, seen as `Deny` by both workers'
  gates, while a route on the same address stays `Allow`; a gate admits
  before its engine is installed. `lorica/src/startup/stream_plane.rs`:
  a health flip written to the store reaches a real stream runtime's
  table (over `StoreStreamTable`) through `refresh_hook`; a TCP
  binding's demand declares `held_fds`. `lorica/src/cli.rs`:
  `--reserved-ports` round-trips the supervisor's value with and
  without the optional listeners, is optional, and refuses malformed
  values. `lorica/tests/stream_engine_adapters.rs` (a real `TcpEngine`
  and `StreamRuntime` over the binary's seams): per-stream round robin
  and its pruning, least-conn counting and the EWMA sample, consistent
  hash stability; the hickory adapter against an in-test UDP DNS
  responder returns the record TTL and a silent server is a
  `ResolveError`; IV4 at this level: a name the responder resolves to
  `127.0.0.1` is never connected (`no_healthy_backend`, zero attempts,
  zero accepts), and a backend on the node's management port is never
  connected even with `allow_local_backend` while the same backend on a
  port no listener holds is; IV2's stream half: a backend going `Down`
  through a `refresh` leaves selection (`no_healthy_backend`, no new
  accept) while the connection established before keeps echoing.
  IV4's first half (refused at creation) is Lot E's API; IV2's HTTP
  half is `upstream_peer`'s unchanged eligibility filter, and both
  halves on one shared backend are Lot G's.
- End to end: `lorica/tests/stream_engine_process_test.rs` starts the
  real binary (`CARGO_BIN_EXE_lorica`) in single-process mode
  (`--workers 0`) and in worker mode (`--workers 2`) over a store seeded
  with a TCP stream linked to a loopback echo backend, connects to the
  stream port and gets the bytes back on two connections, then stops
  the node with SIGTERM. The worker-mode run also checks that no worker
  started without `--reserved-ports`.

**Lot D1 (the shared selection function).**

- `lorica::proxy_wiring::lb::select_index(algorithm: &LoadBalancing,
  candidates: &[&Backend], ring_addresses: Option<&[&str]>, client_ip:
  Option<&str>, random_seed: u64, state: SelectionState<'_>) -> usize`,
  with `SelectionState { wrr, ewma, connections }` as D-e names them, and
  `lb::random_seed(&Instant) -> u64`, the `DefaultHasher` of the
  instant HTTP has always seeded `random` with.
- One refinement, recorded as D-e allows: `ring_addresses` is an
  `Option`. HTTP passes `None` (the configured addresses, no
  allocation); a slice would have cost HTTP a vector per request. The
  stream selector passes its resolved `ip:port` list, index for index.
  The round-robin fallback of `consistent_hash` stays keyed on the
  backends' configured addresses, so a re-resolution does not reset a
  stream's WRR state.
- `select_index` returns 0 for no candidate; `upstream_peer` only calls
  it with at least one.
- Proof HTTP is unchanged: the existing selection tests
  (`test_smooth_wrr_*`, `test_least_conn_*`, `test_pick_consistent_hash_*`,
  `test_ewma_tracker_*`) are untouched and pass. Five new tests keep the
  former inline block verbatim as `former_inline_selection` and assert
  index equality, round by round with separate state copies, for round
  robin with weights 5, 1, 1 (14 rounds, 10/2/2), ketama for a fixed IP
  and its no-IP fallback, the least-connections tie, random over 64
  instants and a fixed seed, and EWMA exploitation with the explore
  schedule.
- `lorica/benches/circuit_breaker.rs` calls nothing that moved.


- API, in `lorica_core::protocols::proxy_protocol`, each returning the
  header as `Vec<u8>`: `encode_v1(source: SocketAddr, destination:
  SocketAddr)`, `encode_v2(source, destination)` (`PROXY`, `STREAM`, no
  TLV), `encode_v2_dgram(source, destination)` (`DGRAM`, Story 12.5
  Interface edit E4, done here since it is one constant away),
  `encode_v1_unknown()` and `encode_v2_unspec()` (`PROXY` over
  `AF_UNSPEC`).
- The encoders canonicalise both addresses and fall back to the
  address-less header themselves when the families still differ, so the
  D-j rule lives in one place and the engine passes the two addresses
  it has whatever they are.
- Tests: round trip of each encoder over IPv4, IPv6, ports 0 and
  65,535, IPv4-mapped spellings, the widest v1 line (within
  `V1_MAX_LEN`), the family mismatch, the v2 lengths per family, and
  20,000 random address pairs. The fuzz target gains the round-trip
  arm; it was type-checked on stable (`cargo check` in `fuzz/`), not
  run, since `cargo fuzz` needs nightly; the unit tests exercise the
  same assertions.


- Migration **75** (`migrate_stream_engine_settings`): 74 was taken by
  12.2 Lot E1's alert subscription. Sixteen `streams` columns
  (`STREAM_ENGINE_COLUMNS`, the D-q fields, each `NOT NULL DEFAULT` the
  model's default or nullable where `None` means no limit) and
  `stream_backends.backup INTEGER NOT NULL DEFAULT 0`. A test drops the
  columns back to the 12.1 shape, runs 75 twice and reads the row back
  as `Stream::new` builds it; the existing additive and second-run
  guards cover it too.
- `Stream::new(id, name, protocol, listen_address, port_first,
  port_last, at)` is the one place a writer takes defaults from. The
  literal sites of `lorica-stream`, `lorica` and `lorica-api` (including
  the API's create handler, edited at the literal only) now build
  through it, so a later field touches no site.
- Ranges and defaults are associated constants on `Stream`
  (`CONNECT_TIMEOUT_MS_RANGE`, `DEFAULT_MAX_CONNECTIONS`, ...).
- The UDP rule is a table, `TCP_ENGINE_FIELDS`: each entry names its
  field, says how its default is judged and carries an `OnUdp`
  (`UntilStory12_5`, or `Refused(reason)` for `proxy_protocol_accept`).
  It runs first in `validate` so a UDP stream is told the setting does
  not apply. A test moves each entry alone on a default UDP stream by
  its serde name.
- Interface with 12.5, honoured now: E1, `idle_timeout_s`'s default and
  range are functions of the protocol (`Stream::default_idle_timeout_s`,
  `Stream::idle_timeout_s_range`), returning the TCP values for UDP
  until 12.5 changes their UDP arm; the UDP rule compares against the
  function, and `Stream::new` fills it by protocol. The serde default
  has no protocol context and takes the TCP value; 12.5 owns the UDP
  import and migration fill. E8, every field states the protocols it
  applies to in its doc comment and its `OnUdp` in the table, so 12.5
  lifts an entry where it is declared. E4 (`encode_v2_dgram`) is done
  in Lot A.
- Trust list: `validate_proxy_protocol(Off, Off, list)` of 12.8 C1
  (already landed, `connection_filter.rs` read only) gives the parse
  and `/0` rules with the same messages; the stream adds the 256 cap
  and "accept on with no non-blank entry". A list with accept off is
  accepted, as on the HTTP listeners.
- Source addresses also refuse multicast, broadcast and duplicates.
- `check_backend_attachments` gains `LocalBackend` (rule A over
  `backend_address_host`, the new host-part reader, and
  `local_address::is_local_host`), `NoPrimaryBackend`,
  `BackupOnUdpStream` and `SourceFamilyMismatch`.
- `local_backend_conflicts(candidate, backends, nodes, others)` in
  `listen_ports.rs` returns every rule-B conflict (reserved listener or
  bound stream port, any protocol, the candidate's own ports included);
  a node that never reported its reserved ports is checked against its
  streams only, since `stream_port_conflicts` already refuses it there.
  Lot E wires it to the API and decides how many conflicts a 409 names.
- Store: `set_stream_backends` keeps its signature (primaries only) and
  delegates to the new `set_stream_backend_links(stream, primaries,
  backups)`; `link_stream_backend_unchecked` takes the whole
  `StreamBackend`, so the replica apply (`store/replica.rs`, one line,
  outside the Lot's allowlist) carries the flag. The import refuses a
  pair listed twice: the store keeps the first row, so a duplicate
  primary/backup pair would be checked as one thing and stored as the
  other.
- `compute_diff` reports a link whose backup flag changed as modified;
  stream fields were already compared whole by `stream_eq`.
- Canonical: format stays 3, digest updated, the reason written beside
  it; `a_blob_without_the_stream_engine_settings_decodes_to_their_defaults`
  pins the serde defaults.
- `StreamRefusal::ConnectionCap` (`connection_cap`).
- `the_view_publishes_every_model_field_but_the_withheld_ones`
  (`lorica-api/src/streams/tests.rs`) fails by design on a model field
  the view lacks. Until Lot E publishes the engine settings it filters
  out the names of `TCP_ENGINE_FIELDS` (derived, not listed), with a
  comment saying Lot E drops the filter. Lot E must remove it.

- Lot F, security, operations and architecture documentation, 2026-11-18: Threat model T12: a stream exposing local services (rules A and B, the three checks), forwarding loops (same node refused by rule B, across nodes bounded and not detected), DNS rebinding of stream backends (connect-time check after every resolution, the per-stream exclusion that is not written to the shared health), PROXY-header spoofing on streams. The hardening guide's capacity section covers source addresses. The survey check and the `docs/streams.md` sections are the other agent's and stay open. The other documentation agent of this cycle owns `docs/streams.md`, `README.md` and `CHANGELOG.md`; the items of this Lot in those files are theirs and stay unticked here until they land. Commits `9473b7d6` (security), `c17ff277` (worker), `df122844` (cluster), `619b55bb` (mcp), `5e4d0d69` (security, `stream_listen_socket_cap`).

**Lot F, the parts in `docs/streams.md` and `CHANGELOG.md` (2026-11-18).**

- Survey values verified against the PRD's sources (nginx stream module pages as published on 2026-11-18, the HAProxy 3.4 configuration manual (3.4.7), Envoy `latest` (1.41.0-dev), Traefik 3.7, the caddy-l4 repository; each value and its URL is in `docs/streams.md`, "Defaults compared"). Each check, setting / product / documented value:
  - connect: nginx `proxy_connect_timeout` 60 s; HAProxy `timeout connect` unset means infinite, with a startup warning; Envoy cluster `connect_timeout` 5 s; Traefik `dialTimeout` 30 s;
  - idle: nginx `proxy_timeout` 10 min; HAProxy `timeout client` / `timeout server` unset means infinite, with a warning; Envoy `idle_timeout` 1 h; Traefik: not documented for TCP routers (only `respondingTimeouts.idleTimeout`, described as keep-alive);
  - total: nginx none; HAProxy none; Envoy `max_downstream_connection_duration` unset; Traefik not documented;
  - attempts: nginx `proxy_next_upstream_tries 0` (no limit); HAProxy `retries`: no default stated in its section; Envoy `max_connect_attempts` 1; Traefik not documented;
  - backend keepalive: nginx `proxy_socket_keepalive off`; HAProxy `option srvtcpka`: no default stated; Envoy not documented; Traefik `dialKeepAlive` 15 s.
- Differences from D-d's table, recorded here rather than by rewriting the Decision: HAProxy `retries` 3 and `srvtcpka` off are not stated by the 3.4 manual and are written "not documented"; Traefik's idle and attempts, "not verified" in D-d, are not documented. Every other value matched.
- `docs/streams.md` (new) covers, under "TCP streams": the pipeline, the algorithms with the weights sentence and the per-worker `least_conn` / `peak_ewma` note, candidates, backups, the breaker, retry and its two end reasons, timeouts, keepalive and why it is on, `close_on_backend_down`, buffers, half-close and why no splice, PROXY send, PROXY accept (untrusted peer, no `optional` mode, UDP refused and why), source addresses and `IP_BIND_ADDRESS_NO_PORT`, local backends (rules A and B, the interface check, what validation cannot see, the stream-only exclusion), DNS and the NSS limit, bandwidth, and `max_connections` with its budget arithmetic. `max_connections` is documented as per node: Story 12.6 made it so and the code's doc comment says it, so the interim "per worker process until Story 12.6" wording appears nowhere. The defaults table cites the constant beside each Lorica value.
- `CHANGELOG.md` `[Unreleased]`: Added (TCP streams) and Security (local backends refused, PROXY trusted per stream).
- The threat-model entries the other documentation pass of this cycle covered (commit `11b46697` and those it names).

- **Decisions checked against the code, 2026-11-18.** Two dated notes, the Decisions left as written: under D-p, `max_connections` is per node since Story 12.6 D-f (the field's doc comment, `openapi.yaml`, `docs/streams.md`), and the fd budget still counts a stream's whole cap in any one worker; under D-d, the HAProxy `retries` 3 and `option srvtcpka` off defaults are stated nowhere in the HAProxy 3.4 configuration manual (both sections re-read), as `docs/streams.md` already says.

## File List

Lot E:

- `lorica-api/src/streams.rs`, `lorica-api/src/streams/tests.rs`
- `lorica-api/src/backends.rs` (rule B on backend update)
- `lorica-api/src/config.rs` (rule B on import)
- `lorica-api/src/automation/write.rs`, `lorica-api/src/automation/tests.rs`
- `lorica-mcp/src/tools.rs` (a test)
- `lorica-api/openapi.yaml`
- `lorica-api/src/stream_budget.rs`, `lorica-stream/src/budget.rs`,
  `lorica-stream/src/tcp/cap.rs` (doc), `lorica/src/startup/stream_plane.rs`
  (the Lot D2 budget hand-off, outside the Lot's allowlist)
- `docs/stories/story-12.3-tcp-engine.md`

Lot C:

- `lorica-stream/src/seams.rs`, `lorica-stream/src/local.rs`,
  `lorica-stream/src/resolver.rs`, `lorica-stream/src/counters.rs` (new,
  crate root per Story 12.5 Interface edits E2 and E3)
- `lorica-stream/src/tcp/{mod,engine,connect,forward,proxy_header,bandwidth,cap}.rs`
  (new)
- `lorica-stream/src/handler.rs`, `lorica-stream/src/table.rs`,
  `lorica-stream/src/runtime.rs`, `lorica-stream/src/listener.rs`,
  `lorica-stream/src/lib.rs`, `lorica-stream/Cargo.toml`
- `lorica-stream/tests/tcp_engine.rs`, `lorica-stream/tests/tcp_runtime.rs`
  (new)
- `lorica-stream/tests/runtime.rs` (the two `Engines` literal sites)
- `lorica-worker/src/stream_sockets.rs`, `lorica-worker/Cargo.toml`
- `Cargo.lock`
- `docs/stories/story-12.3-tcp-engine.md`

Lot D2:

- `lorica/src/stream_engine.rs` (new), `lorica/src/lib.rs`
- `lorica/src/startup/worker.rs`, `lorica/src/startup/single.rs`,
  `lorica/src/startup/supervisor.rs`, `lorica/src/startup/stream_plane.rs`,
  `lorica/src/startup/mod.rs`
- `lorica/src/health.rs` (the `on_change` hook)
- `lorica/src/cli.rs`, `lorica/src/main.rs`
- `lorica-worker/src/manager.rs` (`WorkerConfig::reserved_ports` and the
  exec argument)
- `lorica/tests/stream_engine_adapters.rs`,
  `lorica/tests/stream_engine_process_test.rs` (new)
- `docs/stories/story-12.3-tcp-engine.md`

Lot D1:

- `lorica/src/proxy_wiring/lb.rs`
- `lorica/src/proxy_wiring.rs` (the selection block of `upstream_peer`)
- `lorica/src/proxy_wiring/tests.rs`

Lot A:

- `lorica-core/src/protocols/proxy_protocol.rs`
- `fuzz/fuzz_targets/fuzz_proxy_protocol.rs`
- `FORK.md` (the parser's entry)

Lot B:

- `lorica-config/src/local_address.rs` (new)
- `lorica-config/src/lib.rs`
- `lorica-config/src/models/stream.rs`
- `lorica-config/src/models/backend.rs`
- `lorica-config/src/models/mod.rs`
- `lorica-config/src/listen_ports.rs`
- `lorica-config/src/store/mod.rs`
- `lorica-config/src/store/streams.rs`
- `lorica-config/src/store/replica.rs` (the link write only)
- `lorica-config/src/canonical.rs`
- `lorica-config/src/diff.rs`
- `lorica-config/src/import.rs`
- `lorica-stream/src/reconcile.rs`, `lorica-stream/src/table.rs`,
  `lorica-stream/src/tracker.rs`, `lorica-stream/tests/runtime.rs`
  (literal sites)
- `lorica/src/startup/drain.rs`, `lorica/src/startup/stream_plane.rs`
  (literal sites)
- `lorica-api/src/backends.rs`, `lorica-api/src/stream_budget.rs`,
  `lorica-api/src/streams.rs`, `lorica-api/src/streams/tests.rs`
  (literal sites)
- `docs/stories/story-12.3-tcp-engine.md`
- `docs/security/threat-model.md`, `docs/security/hardening-guide.md` (Lot F, threat model and hardening part)
- `docs/streams.md` (new), `CHANGELOG.md` (Lot F, the TCP engine parts)

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-11-14 | 0.1 | Story drafted from the Epic 12 PRD. Status Draft. | Romain G. |
| 2026-11-14 | 0.2 | Maintainer answers folded in as Resolved 1 to 9: `max_connections` per worker now and per node from Story 12.6 with one field, stream-scoped local exclusion, no DNS alert (input to 12.9 AC #5), no `optional` PROXY accept, selection through a trait, Python backends for IV1, keepalive on by default, `source_addresses` as a list, survey values verified with URLs in Lot F. Status Draft. | Romain G. |
| 2026-11-14 | 0.3 | Lot B landed: the D-q fields, migration 75, validation, rule A and the backup and source-family rules, `local_backend_conflicts`, store, canonical digest, diff, export and import. D-s corrected: the PROXY header is written in plaintext right after connect and before any upstream TLS handshake. Status InProgress. | Romain G. |
| 2026-11-14 | 0.4 | Lot A landed: the PROXY v1 and v2 encoder beside the parser, with `encode_v2_dgram` for Story 12.5, round-trip tests and fuzz arm, FORK.md entry. | Romain G. |
| 2026-11-14 | 0.5 | Lot D1 landed: HTTP's selection block extracted into `lb::select_index`, behaviour unchanged, `ring_addresses` refined to an `Option`. | Romain G. |
| 2026-11-15 | 0.7 | Lot D2 landed: the selector, breaker gate and hickory resolver in `lorica::stream_engine`, the engine installed in worker and single-process modes, the stream table carrying backends, `held_fds` in the budget, health flips refreshing every stream table, `--reserved-ports` for workers; the real binary forwards a TCP stream in both modes. | Romain G. |
| 2026-11-15 | 0.8 | Lot E landed: the engine settings and `backup_backend_ids` on the stream API and in `openapi.yaml`, rule B (`stream_local_backend`, 409) on stream writes both ways, backend updates and imports, the D9 automation guard reached by the MCP backend tool, and one budget demand function for the API and the node. | Romain G. |
| 2026-11-15 | 0.6 | Lot C landed: the TCP engine in `lorica_stream::tcp`, the protocol-neutral seams, local check, resolver cache and counters at the crate root (Story 12.5 E2, E3), `StreamTable::with_backends`, `table_changed` and the `backend_down` drain, the connection record and its observer. | Romain G. |
| 2026-11-18 | 0.9 | D9 amended: the local-backend refusal of a token's address change names the stream only to a token holding `streams:read` and its id otherwise, through `streams_as_seen_by`, the helper Story 12.10's backend delete refusal uses; reason: 12.10 D-j keeps stream names from a config-tier token and the refusal must not undo it. Tests both ways on REST, the stdio-shaped request and both MCP tools, apply and preview. Gates: the CI chain green, `cargo audit` clean. | Romain G. |
| 2026-11-18 | 0.10 | Lot F, threat-model part: local services, forwarding loops, DNS rebinding and PROXY-header spoofing on streams in T12; source addresses in the hardening guide. The survey check, `docs/streams.md` and `CHANGELOG.md` stay open. | Romain G. |
| 2026-11-18 | 0.11 | Lot F, the `docs/streams.md` and CHANGELOG parts: survey values verified with a URL each (two D-d values not documented by HAProxy 3.4, recorded in the Completion Notes), the TCP engine documented; with the other documentation pass's boxes, every box of the Lot is ticked. Status InProgress. | Romain G. |
| 2026-11-18 | 0.12 | Dated notes under D-d (HAProxy `retries` and `srvtcpka` defaults not in the 3.4 manual) and D-p (`max_connections` per node since Story 12.6). | Romain G. |
