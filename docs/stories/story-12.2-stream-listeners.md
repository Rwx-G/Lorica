# Story 12.2: Stream Listeners on a Running Process

**Epic:** [Epic 12 - TCP and UDP Stream Proxying (v1.11.0 and v1.12.0)](../prd/epic-12-v1.11.0.md)
**Status:** InProgress
**Priority:** P0
**Author:** Romain G.
**Depends on:**
- The `lorica-fleet` extraction, committed as `4e864593`. The fleet
  runtime is now `lorica-fleet/src/runtime.rs` (`evaluate_drift`,
  `drain_detached`), the telemetry store
  `lorica-fleet/src/telemetry_store.rs`, the ingest policy
  `lorica-fleet/src/ingest.rs`; `lorica-api/src/cluster/mod.rs` keeps
  the handlers and `node_responses`, with `cluster/boundary.rs` mapping
  the fleet's errors. Every path below was re-checked against it.
- Story 12.1: the `Stream` model (id, name, group name, protocol
  `tcp`/`udp`, `enabled`, one listen address, a port or a port range,
  backends, `node_selector`), the closed end-reason enum (AC #8,
  `config_removed` and `node_shutdown` included), the store listing and
  `node_selector` resolution, the shared reserved-port rule (AC #7, the
  CLI's `refuse_reserved` extracted so both sides use one rule) and the
  per-node conflict rule for addresses on one port, the reserved ports
  in the heartbeat, the release's canonical-format decision (AC #5), the
  release's first migrations (71 onwards), and the stream CRUD handlers
  (AC #9, writes at the Operator role like routes). Each Lot below names
  which of these it waits for.

**Blocks:** Stories 12.3 and 12.5 (their engines plug into the accept
loop and the connection tracker built here), 12.6 (the accept hook
for filters and caps), 12.9 (the bind-failure alert already exists
after this story), 12.10 (bind state per node, the failed-bind badge),
12.11 (the drain setting, the drain watcher, the `quiesce` message, the
TCP stream handoff family), 12.12 (the L4 e2e phase starts from this
story's profiles).

---

As an operator,
I want a stream's port to open when I create it and close when I delete it,
so that I never restart Lorica to add a layer-4 service and no port stays open without a reason.

## Acceptance Criteria

These are the PRD's, unchanged (AC #7 as amended on 2026-11-14). They
are the contract.

1. **Runtime bind by the supervisor (D4)** over a new runtime fd channel per worker, with a new typed tag. TCP: one listener shared by the workers. UDP: one socket per worker in a `SO_REUSEPORT` group. Deleting or disabling a stream closes its sockets in every worker and in the supervisor.
2. **A stream accept loop outside Pingora** serves stream sockets in every worker.
3. **Privileged ports work** without changing the systemd unit.
4. **A bind failure is a configuration error, not a crash.** Port in use, permission denied or address not available is reported on the stream (API, dashboard, audit, a notification through `lorica-notify`) with the OS error; the stream stays in a failed state and every other listener is unaffected.
5. **An fd budget that protects HTTP.** A per-node cap on total stream listening sockets (default documented) and an fd reserve for HTTP that the stream plane can never consume, derived from the process fd limit. A stream create that would break the reserve is refused. A **per-node budget view** in the management API and the dashboard shows the process fd limit, the HTTP reserve, and each stream's share: its listening sockets and, for UDP, its session ceiling. An operator sees the contention between streams before it shows up as refused sessions. This is also where caps on the HTTP listeners are decided, so this story ports or rules out the two upstream commits the 1.10.5 sync deferred to it: `5104a3e0` (accept limits per listening endpoint: handshake timeout, open-connection and pending-handshake caps) and `4a9d66d8` (a listener `Tracer` reporting connection lifetime from accept). Both act on Pingora's listeners, which serve HTTP only; the decision and its reason go in `FORK.md`, and backlog #81 drops them.
6. **Single-process mode** binds and releases stream listeners the same way.
7. **The drain delay exists.** `worker_drain_timeout_s`, already named in `docs/hot-upgrade.md`, becomes a real global setting with the current 30 s as default and a documented hard maximum. A stop drains for it too: while a stop drains, the supervisor extends systemd's stop timeout through `sd_notify` `EXTEND_TIMEOUT_USEC`, so the unit's `TimeoutStopSec` never cuts a drain short and no drop-in is needed for longer drains. The process's own shutdown waits are set from the same setting, so no stop path waits on a hard-coded delay. A connection a stop closes ends with `node_shutdown`. Story 12.11 uses the setting for upgrades; this story uses it for configuration changes and stops.
8. **Reconfiguration without cutting traffic.** Established connections and sessions keep the settings they were accepted with; an edit applies to new connections only. Removing a backend from a stream, deleting the backend, or disabling or deleting the stream drains established connections for `worker_drain_timeout_s`, then closes them with `config_removed`. Changing a stream's listen address or port rebinds, and connections on the old socket drain the same way.
9. **Every bind and release is visible per node** in the audit chain and in the fleet view from this story on, including a node that starts matching a stream's `node_selector` at enrollment; the enrollment preview lists the ports the node will open.

## Integration Verification

- IV1: Creating a TCP stream on port 5432 through the management API makes `ss -ltn` show it on the node within 5 s; deleting it removes it within 5 s, with no restart and no dropped HTTP request in between.
- IV2: Creating a stream on a port already held by another process leaves the stream in a failed state with the OS error, and HTTP traffic is unaffected.

## What the code does today

Read on `feat/v1.11.0` at `7358a5ae`. Function names, not line numbers.
Read, not run, unless said otherwise.

- `WorkerManager::create_listen_sockets` (`lorica-worker/src/manager.rs`)
  binds the HTTP and HTTPS listeners once. `spawn_worker` creates two
  `SOCK_STREAM` socketpairs per worker (legacy `cmd`, pipelined `rpc`)
  and sends ONE `SCM_RIGHTS` bundle (`send_worker_fds`) at fork: the
  shmem memfd, the RPC end, the listeners. Nothing crosses afterwards.
  `restart_worker` rebinds the HTTP sockets if `listen_fds` is empty
  and returns `(cmd, rpc)`.
- The legacy channel is consumed by `CommandChannel::from_raw_fd` on a
  dedicated thread in `run_worker` (`lorica/src/startup/worker.rs`) and
  the RPC channel by `RpcEndpoint::from_raw_fd`. Both are framed byte
  streams with no ancillary data path.
- `FdKind` (`lorica-worker/src/fd_passing.rs`) has `Listener { addr }`,
  `Shmem`, `Rpc`. `run_worker` matches it exhaustively, and
  `recv_listener_fds` lists the non-listener variants by name: a new
  variant breaks both at compile time. `MAX_FDS = 32`,
  `MAX_TOKEN_LEN = 128`, `PAYLOAD_BUF_SIZE = 4096`, with a compile-time
  assertion tying them.
- **The 300 s wait.** Lorica builds a `ServerConf` in `run_worker` and
  in `run_single_process`, but only hands it to
  `lorica_proxy::http_proxy_service`. The `Server` itself is created with
  `lorica_core::server::Server::new(None)`, which builds its own
  `ServerConf::new()` with `grace_period_seconds: None` and
  `graceful_shutdown_timeout_seconds: None`. `Server::run` reads both
  from `self.configuration`: after SIGTERM it sleeps
  `grace_period_seconds.unwrap_or(EXIT_TIMEOUT)` (300 s), unconditionally,
  then shuts its runtimes down within
  `graceful_shutdown_timeout_seconds.unwrap_or(5)`. So:
  - a worker never exits on its own inside the supervisor's 30 s window;
    `shutdown_all` and `drain_for_handoff` end in SIGKILL every time and
    every upgrade records `drain_timeout`;
  - single-process mode runs Pingora with `run_forever` on a side thread
    while the main runtime awaits `shutdown_signal()`; on SIGTERM the
    main path runs `drain_for_exit` (at most 10 s) and returns from
    `main`, which ends the process while Pingora is still in its grace
    sleep: in-flight HTTP is not drained at all.
  The fork already offers the fix: `Server::new_with_opt_and_conf(opt,
  conf)` takes Lorica's own `ServerConf`. No change to `lorica-core`.
- `shutdown_all` and `drain_for_handoff` both hard-code 30 s. The
  supervisor's SIGTERM path calls `shutdown_all()` while holding the
  manager's `std::sync::Mutex`, with the `shutting_down` flag keeping
  the monitor from respawning.
- `sd_notify_ready` (`lorica/src/startup/hot_upgrade.rs`) sends
  `notify_payload(pid)` (`READY=1\nMAINPID=<pid>\n`) on a fresh
  `UnixDatagram` to `$NOTIFY_SOCKET`, returns `Ok(false)` when the
  variable is unset and also for an abstract-namespace socket (`@`
  prefix). It is the only notify helper.
- `ConfigReloadBridge::apply_config_change` (`lorica/src/startup/supervisor.rs`)
  runs `reload_workers` (two-phase `coordinate_config_reload`, legacy
  broadcast fallback), then refreshes the supervisor's own state. It is
  the one place every configuration change passes through, the
  follower's replicated commits included.
- The hot-upgrade transfer table (`build_fds_table`,
  `partition_inherited_fds` in `lorica/src/startup/hot_upgrade.rs`)
  keys proxy listeners by their bare address and ends in a catch-all
  arm: a new listener family needs its own key prefix and an arm ABOVE
  the catch-all, or its sockets are adopted as HTTP listeners.
- `dist/lorica.service`: `Type=notify`, `NotifyAccess=all`,
  `KillMode=mixed`, `TimeoutStopSec=90`, `LimitNOFILE=65536`,
  `CapabilityBoundingSet=` and `AmbientCapabilities=CAP_NET_BIND_SERVICE`,
  `SystemCallFilter=~@privileged @resources` (setrlimit is killed;
  reading the limit is not), `RestrictAddressFamilies` includes
  `AF_UNIX`. No code reads `RLIMIT_NOFILE` today.
- `GlobalSettings` is a key/value table: a new setting needs no
  migration (`store/settings.rs`). Replicated settings also live in
  `CanonicalGlobalSettings` (`lorica-config/src/canonical.rs`).
- `active_connections` (`LoricaProxy`, `lorica/src/proxy_wiring.rs`) is
  incremented per request in the request path and decremented in
  `logging`: it counts in-flight HTTP requests, not idle keepalive
  connections, which is what an idle check needs.
- The fleet view's per-node session data rides the protobuf
  `Heartbeat` (`lorica-cluster/src/messages.rs`), is sampled by
  `FollowerHandler::resources` (implemented by `ReplicaHandler` in
  `lorica/src/startup/cluster_follower.rs`), recorded by
  `roster.rs` (`record_resources`) and rendered by `node_responses`
  in `lorica-api/src/cluster/mod.rs`, where `resources` is withheld
  from Viewers (Story 9.7) and drift comes from
  `lorica_fleet::runtime::evaluate_drift`. The pending-node review
  there (`selected_for_hostnames`, `certificate_ids`) is what AC #9
  calls the enrollment preview.
- The HTTP accept path already has: the CIDR connection filter and the
  per-IP live-connection cap at accept (`GlobalConnectionFilter`,
  `AcceptPermit`, Story 8.9), a fixed 60 s TLS handshake timeout
  (`lorica-core/src/services/listening.rs`), `header_timeout_s`,
  `downstream_idle_timeout_s`, `max_global_connections`.

## Decisions taken in this story

Each with its reason and what it costs.

### D-a. The runtime fd channel: a third socketpair per worker, `SOCK_SEQPACKET`

Each worker gets a third socketpair, created in `spawn_worker` beside
`cmd` and `rpc`, of type `SOCK_SEQPACKET` (still `AF_UNIX`, still
`SOCK_CLOEXEC`). Its worker end travels in the existing fork bundle
under a new tag `FdKind::StreamCtl` (wire token `stream-ctl`); the
supervisor end stays on the `WorkerHandle` (`take_stream_ctl_fd`).

*Why not reuse a channel:* `cmd` and `rpc` are framed `SOCK_STREAM`
byte streams read by codecs that ignore ancillary data. On a stream
socket, `SCM_RIGHTS` attaches to a byte position and a reader that
does not expect it drops or misattributes the fds. Teaching
`RpcEndpoint` about ancillary data rewrites the pipelined dispatcher
for one message family. `SOCK_SEQPACKET` keeps one message, its tokens
and its fds atomic, so the existing `FdKind` token discipline carries
over unchanged. *Cost:* one more fd per worker in the supervisor and
in each worker, and a third reader.

**Message format.** One message is a text payload of space-separated
tokens, plus, for `attach` only, one `SCM_RIGHTS` fd per socket token,
in order. Supervisor to worker:

| Message | Payload | Fds |
|---|---|---|
| `attach` | `attach <seq> <stream_id> <bind_gen> <token>...` | one per token, at most 32 |
| `detach` | `detach <seq> <stream_id> <bind_gen> drain_ms=<n>` | none |
| `refresh` | `refresh <seq> drain_ms=<n>` | none |
| `quiesce` | `quiesce <seq> reason=<shutdown> drain_ms=<n>` | none |

Worker to supervisor: `ack <seq> <count>` or `nack <seq> <reason>`
(`reason` is a fixed token, never free text). Story 12.11 adds
`reason=upgrade` to `quiesce`.

The socket token is the new typed tag `FdKind::StreamSocket { proto,
bind_gen, addr }`, on the wire `stream:<tcp|udp>:<bind_gen>:<addr>`
(`bind_gen` a `u64`). The longest form,
`stream:udp:18446744073709551615:[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535`,
is under `MAX_TOKEN_LEN`; the compile-time assertion is extended to
`header + 32 tokens <= PAYLOAD_BUF_SIZE` with a bounded stream id length
(the bound comes from 12.1's id validation). `bind_gen` is assigned by
the supervisor, never reused in a supervisor's life, and names one
binding of one stream (all its sockets). A rebind takes a new
`bind_gen`, so `detach` never needs to list sockets.

*Flow control:* stop-and-wait per worker. The supervisor sends the next
message to a worker only after the previous one's `ack`/`nack` or its
2 s timeout (the Prepare timeout). A 1,024-port range on a dual-stack
address is 1,024 sockets per slot, so it is chunked into `attach`
messages of at most 32 fds, the kernel's per-message ceiling
(`SCM_MAX_FD`, 253) being far above. Stop-and-wait also bounds the fds
in flight to 32 per worker, which matters because in-flight
`SCM_RIGHTS` fds are charged to the sending user and refused with
`ETOOMANYREFS` past its `RLIMIT_NOFILE` (see Dev Notes).

*A worker respawned after streams exist:* `restart_worker` creates a
fresh `stream-ctl` pair like the other two. The supervisor's monitor
branch takes the new end and replays one `attach` per live binding
(TCP: a dup of the shared listener; UDP: that worker slot's sockets,
see D-c), then a `refresh`, before the worker counts as serving. The
connections the dead worker held are gone with its process and end
without an access-log row; that is a crash, documented as such.

*Ordering between bind and worker ready:* the supervisor binds and
`listen`s first, then attaches. A TCP client arriving between the two
waits in the backlog; nothing is lost. The messages queue in the
socketpair until the worker's stream thread reads them, so the
supervisor never waits for a worker to be "ready" before sending. A
binding reports `bound` once the supervisor holds its sockets, with
`workers_serving = k/W` from the acks; the fleet view shows both.
At cold boot the first reconcile runs before `sd_notify READY=1`,
bounded by the ack timeout, so `systemctl start` returns with streams
listening; a bind failure does not delay READY.

### D-b. The stream accept loop lives in a new crate `lorica-stream`, on its own tokio runtime

A new product crate **`lorica-stream`** (version on the product line)
holds: the worker-side `StreamRuntime` (applies `attach` / `detach` /
`refresh` / `quiesce`), the TCP accept loop and the UDP receive loop,
the `StreamHandler` / `DatagramHandler` traits the engines of Stories
12.3 and 12.5 implement, the connection tracker (D-g), the fd budget
arithmetic and its view types (D-e), the bind-state types (D-h), and
the pure reconcile diff (D-d). It depends on `lorica-worker` (for the
message types of D-a, so both modes speak one type), `lorica-config`
(the `Stream` model and end reasons) and `tokio`. `lorica-api` depends
on it for the view types; `lorica` for everything.

*Why a crate and not `lorica/src/stream/`:* five later stories add to
this code; the binary crate is the slowest to compile and the hardest
to test in isolation; `lorica-api` needs the bind-state and budget
types without depending on the binary. *Cost:* the new-crate chores of
`.claude/rules/lorica-rust.md`, all of them: workspace `members`, the
three Dockerfiles (`Dockerfile`, `Dockerfile.dev`,
`tests-e2e-docker/Dockerfile`), the three crate lists in
`.github/workflows/ci.yml`, both bump checklists
(`docs/BUMP-CHECKLIST.md`, `.claude/skills/bump-version/bump-checklist.md`),
the crate tables in `README.md`, `FORK.md`, `CONTRIBUTING.md`,
`docs/architecture/source-tree.md`,
`docs/architecture/component-architecture.md`,
`.claude/rules/lorica-project.md`, the `run-tests` and `build-deb`
skills, and the README product-crate test count. Nothing in `dist/`:
no binary. `4e864593` shows each of these for `lorica-fleet`.

*Runtime:* in a worker, `StreamRuntime` runs on a dedicated OS thread
(`lorica-stream`) with its own `tokio` multi-thread runtime of one
worker thread, the same share Pingora's service gets
(`ServerConf::threads` is 1 in workers). It is started in `run_worker`
before `server.run(...)`, beside the command-channel thread. It
coexists with Pingora by sharing nothing but the process: no listener
in Pingora's set, no task on Pingora's runtimes. It subscribes to
`Server::watch_execution_phase()` so a SIGTERM that arrives without a
`quiesce` (the upgrade path until Story 12.11) still stops its accept
loops and arms the drain watcher (D-f).

*Before Story 12.3 lands on the branch,* the worker installs no engine:
the accept loop closes an accepted TCP connection at once and drops a
datagram, both logged at debug. 12.3 and 12.5 replace that with their
handlers in the same cycle; no release carries the interim (Resolved
#6).

### D-c. TCP shared listener vs UDP `SO_REUSEPORT` group, and the IPv6 rule

- **One listen address per stream** (12.1). **`[::]` binds dual-stack**
  (`IPV6_V6ONLY` off) and so takes every IPv4 and IPv6 address on that
  port and protocol: it conflicts with any other stream there, which
  12.1's control-plane rule refuses and the kernel refuses at bind as
  the backstop (`EADDRINUSE`). **Any other IPv6 literal binds with
  `IPV6_V6ONLY` on**, so it never takes IPv4 by accident whatever
  `net.ipv6.bindv6only` says. `0.0.0.0` behaves as the kernel says: it
  conflicts with every IPv4 address on the port. The option is set
  explicitly in both directions, never left to the sysctl.
- **TCP:** one socket per (binding, port), `SO_REUSEADDR` on,
  **`SO_REUSEPORT` off**, backlog 65535 (clamped by `somaxconn`, as the
  HTTP listeners). Every worker gets a dup; one accept queue. With
  `SO_REUSEPORT` off, a bind on a port any other socket holds fails with
  `EADDRINUSE` whoever holds it, which is what IV2 needs and what keeps
  a stale socket from silently sharing the port. *Cost:* a hot upgrade
  cannot rebind the port while the old generation holds it, so the TCP
  stream listeners ride the upgrade transfer table (D-j).
- **UDP:** per (binding, port), the supervisor creates **W sockets, one
  per worker slot**, each with `SO_REUSEPORT` set before `bind` and the
  same `IPV6_V6ONLY` rule. Worker `i` receives slot `i`'s socket.
  **The supervisor keeps every slot socket for the binding's whole
  life, across worker deaths.** The kernel picks a socket in the group
  by `hash(4-tuple)` scaled to the group size, and closing one moves
  the last into its place: keeping the group size constant is what
  keeps every other client on its worker when one worker dies.
  *Cost:* while a slot's worker is down (respawn backoff, up to 30 s),
  the clients hashed to it are black-holed into that socket's receive
  buffer; a reuseport BPF steering program would fix it and is out of
  scope (`bpf()` is in `@privileged` anyway). How a UDP session's
  datagrams reach its owner beyond that (for instance a connected
  socket per session) is Story 12.5's decision, not this one's
  (Resolved #7).
- **Lifecycle:** bind all sockets of a binding or none: a range where
  one port fails closes the ports already bound and reports the
  failing port. Release closes the supervisor's copies at once and
  sends `detach`; the port is free when the last worker closes its copy
  on `detach`.

### D-d. How the supervisor learns of changes and reconciles

The hook is `ConfigReloadBridge::apply_config_change`, so local API
writes, follower commits and the GeoIP-triggered reloads all pass
through it. It becomes three steps:

1. **Before** `reload_workers`: compute the desired set from the store
   (streams with `enabled` set whose `node_selector` matches this node,
   by 12.1's resolution) and diff it against the bound set
   (`lorica_stream::reconcile::diff`, pure). Send `detach` for every
   binding that is no longer desired or whose bind key changed. The
   bind key is (stream id, protocol, listen address, port or range);
   any other field change is not a rebind.
2. `reload_workers()` as today (two-phase, legacy fallback).
3. **After**: bind and `attach` the new bindings, then send `refresh`
   to every worker, which reloads its stream table from the store and
   starts the backend-removal drains of D-g.

Detaching before the commit means an accept never meets a stream the
committed config no longer has; attaching after it means an accept
never meets a stream the config does not have yet. Failed bindings
whose error is `address_in_use` or `address_not_available` are
retried every 10 s (`STREAM_BIND_RETRY_INTERVAL`) as well as on every
change; `permission_denied`, `reserved_port` and `fd_budget` are
retried only on a change. The node-side backstop runs before every
bind: the shared reserved-port rule of 12.1 against this node's own
ports, then the budget of D-e.

### D-e. The fd budget

Read once at startup in the supervisor (and in single-process mode):
`L` = the process's soft `RLIMIT_NOFILE`. Workers inherit the same
limit through `fork`/`exec`; each logs it at start.

- `B` = 1,024, a fixed base reserve for the process's own plumbing
  (databases, log stores, channels, management and cluster sockets).
- `H` = `L / 2`, the **HTTP reserve**, never usable by streams.
- `S` = `L - B - H`, the stream budget per process: 31,744 at the
  packaged `LimitNOFILE=65536`.
- Per worker: `sum over streams of (listen_sockets + held_fds) <= S`.
  `listen_sockets` is one per port of the binding. `held_fds` is what
  the engine declares the stream may hold at its ceiling, through one
  generic accountant input: `connections_or_sessions_ceiling x
  fds_per_connection_or_session`. Story 12.3 declares its TCP connection
  cap and 2 fds per connection; Story 12.5 declares its session ceiling
  and however many fds its design holds per session. This story
  assumes no figure for either; until they land the input is absent
  and counts 0. Caps are per node, so the worst case puts them all on
  one worker, and that is what is counted.
- In the supervisor: `TCP ports + UDP ports x W <= S`. The supervisor
  holds every UDP slot (D-c), so many workers and a wide UDP range hit
  this first, and the refusal says so.
- Per node: total stream listening sockets `<= stream_listen_socket_cap`,
  a new replicated global setting, **default 2,048**, range 1 to 16,384.

A create or update that breaks any of these is refused with the
constraint, the numbers and the node. On a control plane the check runs
for every targeted node from the `fd_limit` and `worker_count` each
follower reports in its heartbeat (D-i); a node that has not reported
yet is not checked at the API, the response carries a warning, and the
node refuses at bind (`fd_budget`). `B` and the halving are constants,
not settings (Resolved #9): an operator who wants more stream capacity
raises `LimitNOFILE`, which grows both halves, and the hardening guide
says so. *Cost:* half the fds are held back from streams even on a node
that serves no HTTP.

**The budget view.** `GET /api/v1/streams/budget`, Operator and
SuperAdmin only (Viewers do not get node capacity, the Story 9.7
reasoning for `resources`). Standalone and on a follower it returns the
local node; on a control plane, every node with a report:

```json
{
  "nodes": [{
    "node_id": "<UUID>", "node_name": "edge01", "reported_at": "<RFC 3339>",
    "fd_limit": 65536, "base_reserve": 1024, "http_reserve": 32768,
    "stream_budget": 31744, "worker_count": 8,
    "listen_socket_cap": 2048, "listen_sockets_used": 3,
    "worker_fds_committed": 3, "supervisor_fds_committed": 17,
    "worker_drain_timeout_s": 30,
    "streams": [{
      "id": "<UUID>", "name": "pg", "protocol": "tcp",
      "listen_sockets": 1, "ceiling": null, "fds_per_unit": null,
      "fds_committed": 1, "bind_state": "bound"
    }]
  }]
}
```

`ceiling` is the connection cap of a TCP stream or the session ceiling
of a UDP one; it and `fds_per_unit` are `null` until Stories 12.3 and
12.5 fill them through the same accountant.

### D-f. `worker_drain_timeout_s`, the stop path, and the 300 s wait

**The setting.** A replicated global setting (`GlobalSettings` and
`CanonicalGlobalSettings`, `#[serde(default)]` inside 12.1's
canonical-format decision), default **30**, range **1 to 3,600 s**
(`WORKER_DRAIN_TIMEOUT_MAX_S`). The hard maximum is one hour because a
draining generation holds its fds and memory next to the live one for
that long, an upgrade or a stop that needs more is a session-transfer
problem (Story 12.16), not a drain problem, and one hour is the ceiling
`header_timeout_s` and `downstream_idle_timeout_s` already use. It is
not on the automation admin tier (`lorica-automation-policy/src/settings.rs`
is an allowlist; the new setting stays out): it decides how long a stop
takes and when reconfiguration cuts connections.

**Where it is read.** By the supervisor (and the single-process
driver), which sends the value as `drain_ms` in every message that
starts a drain (`detach`, `refresh`, `quiesce`), so a worker never
drains on a value the supervisor did not send. One exception, the
fallback of D-b: a worker that receives SIGTERM without a `quiesce`
(the upgrade path until Story 12.11) reads the stored value itself.

**The drain watcher** (new, `lorica/src/startup/drain.rs`). Armed in a
worker by `quiesce` or by Pingora's `GracefulTerminate` phase, and in
single-process mode by the shutdown signal. It polls every 200 ms and
ends the process (after `lorica::otel::shutdown()`) as soon as
`active_connections` is 0 and the stream tracker is empty, or when the
deadline passes, having first let the tracker close what is left with
`node_shutdown` (D-g). This is how a stop takes as long as the traffic
needs and no longer, and how an edit of the setting applies to the
next stop without restarting workers.

**Pingora's own waits, from the same setting.** Lorica builds the
`Server` with `Server::new_with_opt_and_conf(None, conf)` in
`run_worker` and in `run_single_process`, `conf` carrying
`grace_period_seconds = WORKER_DRAIN_TIMEOUT_MAX_S` and
`graceful_shutdown_timeout_seconds = 5`. Pingora's grace becomes the
setting's bound, a backstop the watcher always beats, instead of the
300 s `EXIT_TIMEOUT`. It is the bound and not the current value because
a `ServerConf` is frozen into the `Server` at worker start while the
setting changes at runtime; the watcher carries the current value.
*Cost:* if the watcher failed, a worker could sleep up to the bound;
the supervisor still SIGKILLs it at its own deadline, below. The fork
is not changed.

**The stop path, supervisor mode.** On SIGTERM: start the stop
keepalive (below); shut the cluster planes down as today; set
`shutting_down`; send `quiesce reason=shutdown drain_ms=<D>` to every
worker; then `shutdown_all(D + 10 s)`, whose SIGKILL now only meets a
worker whose watcher failed; then `drain_for_exit` as today. `D` is the
setting read at that moment.

**The stop path, single-process mode.** The proxy thread calls
`server.run(RunArgs::default())` instead of `run_forever` (whose
`exit(0)` would race the main path). On the shutdown signal: start the
keepalive, `quiesce` the stream runtime, run the watcher to its end
(idle or `D`), then `drain_for_exit` and return. In-flight HTTP is now
drained in single-process mode, which it was not.

**`EXTEND_TIMEOUT_USEC`.** The notify helper in `hot_upgrade.rs` is
generalised to send any payload (`sd_notify(payload)`, with
`sd_notify_ready` kept on top of it). On the stop path only, a
dedicated thread (not a runtime task, so a blocked runtime cannot
starve it) sends `EXTEND_TIMEOUT_USEC=30000000` every 10 s until the
process exits: each message asks systemd for 30 s more, sent three
times inside that window, so systemd never SIGKILLs a drain in
progress, whatever `TimeoutStopSec` says. The unit's
`TimeoutStopSec=90` stays and keeps its meaning for a stop that makes
no progress: a supervisor that hangs stops sending and is killed 30 s
after its last extension or at `TimeoutStopSec`, whichever is later.
`dist/lorica.service` is unchanged and no drop-in is needed.
`EXTEND_TIMEOUT_USEC` needs systemd 236 or later; Debian 12, Ubuntu
22.04 and 24.04 and RHEL 9 all ship later ones. `Type=notify` and
`NotifyAccess=all` are already set.
- **Under a hot upgrade** there is no stop job: the old supervisor is
  no longer the unit's main PID once it has acked, and its drain is
  bounded by `drain_for_handoff` (Story 12.11's). It sends no
  extension; sent outside a stop, `EXTEND_TIMEOUT_USEC` would extend the
  runtime timeout instead, which is meaningless here, so the keepalive
  is started from the SIGTERM path and nowhere else.
- **Without systemd** (`$NOTIFY_SOCKET` unset: Docker, a manual run),
  the helper is a no-op and whatever stops the process bounds the
  drain. `docker stop` sends SIGKILL after 10 s by default; the docs
  tell Docker users to set `stop_grace_period` above the drain, and the
  e2e compose does.
- An abstract-namespace `$NOTIFY_SOCKET` (`@` prefix) is skipped, as the
  existing helper already does; systemd's own socket is a path.

### D-g. Draining established connections

Every connection or session registers in the worker's tracker with its
stream id, `bind_gen`, backend id (set by the engine once chosen), the
`Arc` of the stream snapshot it was accepted with, and a close handle.
An edit never touches a live entry's snapshot: `refresh` swaps the
table new accepts read, nothing else (AC #8, first sentence).

- `detach`: stop the binding's accept loops, close its sockets, mark
  its connections draining with `deadline = now + drain_ms`, end reason
  `config_removed`.
- `refresh`: after reloading the table, mark draining with
  `config_removed` every connection whose stream is gone or no longer
  `enabled`, or whose backend left the stream's list or was deleted.
- `quiesce reason=shutdown`: stop every accept loop, mark everything
  draining with `node_shutdown`.
- At its deadline a draining connection is closed by the tracker with
  its pending reason, so the end reason is written by the worker, never
  left to a SIGKILL. A connection that ends on its own while draining
  keeps its natural reason.

### D-h. Bind state and how a failure is reported

Per (stream, node): `pending`, `bound { workers_serving, workers }`,
`failed { kind, os_error, port, since }`, where `kind` is one of
`address_in_use` (`EADDRINUSE`), `permission_denied` (`EACCES`,
`EPERM`), `address_not_available` (`EADDRNOTAVAIL`), `reserved_port`,
`fd_budget`, `other`, and `os_error` is the OS error's text
(`Address already in use (os error 98)`). Held in memory by the
supervisor's registry (`lorica_stream::state`), recomputed by the next
reconcile after a restart: a failure that persists after a restart is
reported again; one that cleared is not invented.

- **API:** the stream resource of 12.1 gains `bind` (this node's state)
  on GET and list; the fleet per node is on the cluster nodes response
  (D-i).
- **Dashboard:** the budget view on the System page, the per-node
  stream section of the Cluster page's node drawer; the per-stream
  badge on the Streams page arrives with Story 12.10 AC #1 (Resolved #5).
- **Audit**, actor `AuditContext::node("stream-plane")`, target
  (`stream`, id): `stream.bind`, `stream.release` (with the cause:
  `deleted`, `disabled`, `rebind`, `node_deselected`, `shutdown`),
  `stream.bind_failed` once per entry into `failed`, and `stream.bind`
  again on recovery. The hashed payload carries node, address, ports,
  protocol, `bind_gen` and, for a failure, kind and OS error. Each node
  writes its own rows; the existing audit fan-in brings followers' rows
  to the control plane, which is how a node that starts matching a
  selector at enrollment shows its binds.
- **Notification:** a new `AlertType::StreamBindFailed`
  (`stream_bind_failed`), raised once per entry into `failed`, never per
  retry, carrying stream id, name, node, kind and OS error. A migration
  subscribes channels saved with an explicit type list, the migration
  63 pattern, at the next number after 12.1's. Story 12.9 AC #5 counts
  this event as delivered (Resolved #10).
- **Every other listener unaffected:** a failure is a value in the
  registry. No `?` on the reconcile path returns from the supervisor,
  and a failing binding never blocks the others in the same pass.

### D-i. Per-node visibility: heartbeat, fleet view, enrollment preview

- The `Heartbeat` gains, at the next free tags after 12.1's, a
  `StreamPlaneReport`: `fd_limit`, `worker_count`, `listen_sockets_used`,
  `bound_count`, and the **non-bound** bindings only (`pending` and
  `failed`, at most 256, with `truncated`). Sending every bound
  binding would make the heartbeat grow with the stream count. The
  control plane derives `bound` for a targeted stream a node does not
  list when `lorica_fleet::runtime::evaluate_drift` shows that node in
  sync; otherwise the state reads `unknown`.
- `roster.rs` records the report per session, like `resources`; the
  cluster nodes response gains `stream_plane` (bind summary for every
  role; `fd_limit` and the budget figures Operator and above only).
- The pending-node review gains `stream_ports`: every stream the node
  will bind once active, `{ id, name, protocol, listen_address, ports }`,
  fleet-wide streams included (unlike `selected_for_hostnames`): a port
  a node opens is a perimeter change whether one node or all open it.
- `lorica-fleet` is read, not changed, by this story: the bind report
  is session state carried by `lorica-cluster` like `resources`, and the
  follower's provider is `ReplicaHandler` in the binary.

### D-j. Hot upgrade and the TCP stream listeners

The TCP stream listeners join the upgrade transfer table under a new
key family `stream-tcp:<stream_id>:<bind_gen>:<addr>`, with its arm
above the catch-all in `partition_inherited_fds`. The new supervisor
adopts them into its registry before its first reconcile, which treats
an adopted socket matching a desired binding as already bound and
closes one that is not desired. Without this, the new generation would
meet `EADDRINUSE` (D-c) on every TCP stream port until the old one
exits. UDP slot sockets are not handed over in this story: the new
generation binds its own group, which joins the old group (same user,
`SO_REUSEPORT`) for the overlap. What that does to UDP sessions during
an upgrade is for Stories 12.5 and 12.11 to settle.

### D-k. Single-process mode

`run_single_process` builds the same `StreamRuntime` on its own thread
and a single-process driver of the same reconcile code. Transport is
an in-process `tokio::sync::mpsc` carrying the same `lorica_worker`
message type with owned fds instead of `SCM_RIGHTS`; `W = 1`, so a UDP
binding is one socket. The reload task's three steps match D-d, and
the stop path is D-f's single-process one.

### D-l. Upstream `5104a3e0` and `4a9d66d8`: both ruled out

- **`5104a3e0`** (opt-in accept limits per listening endpoint: handshake
  timeout, open-connection and pending-handshake caps). Ruled out. The
  HTTP listeners already bound what it bounds: the per-IP live-connection
  cap is charged at accept and held through the handshake (Story 8.9
  `AcceptPermit`), the handshake has a fixed 60 s timeout, and
  `header_timeout_s` / `downstream_idle_timeout_s` bound what follows.
  Porting it would put a second, per-endpoint and per-process cap on the
  same accept path, counted and refused apart from the one operators
  configure, on code Story 12.8 reorders for PROXY protocol in this same
  cycle. The HTTP reserve of this story is subtracted from what streams
  may use; it needs no cap on HTTP itself, so this story adds none. *Cost:*
  later upstream commits building on it will not apply, and each sync
  rules them out with it.
- **`4a9d66d8`** (listener `Tracer` for downstream connection lifetime
  from accept). Ruled out: no HTTP consumer exists, and the stream plane
  measures connection lifetime in its own accept loop (Story 12.9's rows
  carry duration from accept). *Cost:* no per-connection lifetime for
  HTTP; port it the day one is wanted.
- `FORK.md` records both as ruled out in 1.11.0 (Story 12.2) in place
  of "Deferred to Epic 12"; backlog #81 drops them from its deferred
  list.

## Tasks

Lots with hard file allowlists. A Lot touches only its files; two Lots
that share a file are sequential, never parallel, and say so. Every
Lot that runs cargo ends on a tree that passes the gate chain CI runs
(`cargo fmt --all -- --check`, the workspace clippy with `--all-targets
--features lorica/otel -- -D warnings` under `CARGO_BUILD_WARNINGS=deny`,
`cargo test --workspace` or the CI per-crate lines, `cargo audit`),
through Docker on Linux. Lot F runs the frontend gates of
`.claude/rules/lorica-frontend.md`. No agent runs `git checkout`,
`git restore` or `git stash`.

**Can start before Story 12.1 lands:** A, C1. **Wait for 12.1:** B
(model, end reasons), C2 (canonical Lot), D (store listing, selector
resolution, reserved-port rule), E1 (migrations), E2 (heartbeat Lot),
E3 (CRUD handlers), then F, G, H.

Order: A and C1 first, in parallel. B after A. D after A, B and C1.
C2 after C1 and 12.1's canonical Lot. E1 in parallel with D. E3 after
D, C2 and E1. E2 after E3. F after E1, E2 and E3. H after D and E3.
G's crate lists right after B, its final pass after H.

### Lot A: the runtime fd channel and stream sockets (`lorica-worker`) - cargo

Allowlist: `lorica-worker/src/fd_passing.rs`, `lorica-worker/src/stream_ctl.rs` (new),
`lorica-worker/src/stream_sockets.rs` (new), `lorica-worker/src/manager.rs`,
`lorica-worker/src/lib.rs`, `lorica-worker/Cargo.toml`,
`lorica-worker/tests/stream_ctl.rs` (new), `lorica/src/startup/worker.rs`
(the one `FdKind::StreamCtl` match arm only), `Cargo.lock`.
Depends on: nothing. Before 12.1.

- [x] `FdKind::StreamCtl` (`stream-ctl`) and `FdKind::StreamSocket { proto,
      bind_gen, addr }` with token round-trip tests, including the
      longest IPv6 form; `recv_listener_fds` filters both. Extend the
      compile-time size assertion to the `attach` header plus 32 tokens.
- [x] `stream_ctl.rs`: the message enum of D-a (`Attach`, `Detach`,
      `Refresh`, `Quiesce`, `Ack`, `Nack`), encode/decode, `send_msg` /
      `recv_msg` over a `SOCK_SEQPACKET` fd with `SCM_RIGHTS` for
      `Attach`, `MSG_CMSG_CLOEXEC` on receive, the truncation and
      count-mismatch paths closing every received fd (the `OwnedFd`
      idiom of `recv_worker_fds`), chunking of a socket list into
      messages of at most 32 fds. `create_seqpacket_pair()`.
- [x] `stream_sockets.rs`: `bind_tcp_stream_listener(addr)` (reuseaddr,
      no reuseport, backlog 65535), `bind_udp_group(addr, slots)`
      (reuseport before bind), both applying the IPv6 rule of D-c
      (`IPV6_V6ONLY` off for `[::]`, on for every other IPv6 literal,
      set explicitly), `bind_range` all-or-nothing,
      `BindFailureKind::from_io_error` (the errno map of D-h), and
      `process_fd_limit()` (soft `RLIMIT_NOFILE` through
      `nix::sys::resource`; enable nix's `resource` feature, an existing
      dependency).
- [x] `manager.rs`: the third pair in `spawn_worker`, worker end sent as
      `StreamCtl` in the fork bundle, supervisor end on `WorkerHandle`
      with `take_stream_ctl_fd()`; `restart_worker` keeps its return
      type and leaves the new end on the handle for the caller to take.
- [x] `worker.rs`: the `StreamCtl` arm adopts the fd and reports it in
      the "received worker FDs" log line (wired to the runtime in Lot D).
- [x] Tests (Linux): message round trip with real sockets attached;
      a 1,024-socket list round-trips in 32-fd chunks; a truncated
      message closes its fds (count open fds via `/proc/self/fd`);
      TCP: a second bind on the same port fails `address_in_use`;
      UDP: a group of 4 binds and a fifth non-reuseport socket fails;
      `[::]:p` refuses a later `0.0.0.0:p` and `127.0.0.1:p` on the same
      protocol; `[::1]:p` and `127.0.0.1:p` coexist; `getsockopt`
      confirms `IPV6_V6ONLY` per case; `BindFailureKind` per errno.

### Lot B: the `lorica-stream` crate - cargo

Allowlist: `lorica-stream/**` (new), `Cargo.toml` (workspace members),
`Dockerfile`, `Dockerfile.dev`, `tests-e2e-docker/Dockerfile` (the crate
`COPY` line only, before the `tinyufo` line), `.github/workflows/ci.yml`
(the three crate lists), `Cargo.lock`.
Depends on: A; 12.1's model Lot (`Stream` with `enabled`, the
end-reason enum with `config_removed` and `node_shutdown`).

- [ ] `state.rs`: `BindState`, `BindFailureKind` re-export, `StreamBindStates`
      (the supervisor registry: snapshot for readers, transitions with
      `since`).
- [ ] `budget.rs`: the D-e arithmetic as pure functions
      (`FdBudget::from_limit`, `check(desired, workers, cap)` returning
      the violated constraint with its numbers), the generic
      `ceiling x fds_per_unit` input, and the serde view types of the
      budget endpoint.
- [ ] `reconcile.rs`: pure `diff(desired, bound) -> Actions { detach,
      bind }` keyed by the bind key of D-d.
- [ ] `tracker.rs`: registration with snapshot `Arc` and backend id,
      `drain_binding`, `drain_where`, `drain_all`, each with a pending
      end reason; deadline close with it; natural end keeps its reason;
      `is_empty()` for the drain watcher.
- [ ] `handler.rs`: `StreamHandler` (accepted `TcpStream`, peer, snapshot,
      tracker entry) and `DatagramHandler` (datagram, source, socket).
- [ ] `listener.rs` / `runtime.rs`: `StreamRuntime` on its own thread and
      runtime (D-b), applying the four messages, acking each, accept and
      receive loops per socket, stop on `detach` / `quiesce` /
      `GracefulTerminate`, the interim no-engine behaviour of D-b.
- [ ] Unit and integration tests (Linux): budget arithmetic at the
      packaged limit, at 4,096 and with W = 64 hitting the supervisor
      constraint, and with a declared `fds_per_unit` of 1, 2 and 3
      (the accountant assumes none); diff: backend-only edit is no
      action, port change is detach + bind, `enabled` false is detach;
      tracker: an edited snapshot leaves a live entry's `Arc` untouched
      (pointer equality), a draining entry closes at its deadline with
      `config_removed`, a quiesced one with `node_shutdown`, one ending
      earlier keeps its own reason; runtime with an echo test handler:
      attach then connect works, detach stops new accepts while an
      established echo keeps working until the deadline; UDP: two
      runtimes sharing a 2-slot group each receive only their slot's
      datagrams.

### Lot C1: the two settings (backend) - cargo

Allowlist: `lorica-config/src/models/settings.rs`,
`lorica-config/src/store/settings.rs`, `lorica-api/src/settings.rs`.
Depends on: nothing. Before 12.1.

- [x] `worker_drain_timeout_s` (default 30, `WORKER_DRAIN_TIMEOUT_MAX_S`
      = 3,600 next to it with the reason of D-f) and
      `stream_listen_socket_cap` (default 2,048, range 1 to 16,384) on
      `GlobalSettings`, read and written by the store like
      `downstream_idle_timeout_s`.
- [x] `lorica-api/src/settings.rs`: both fields in GET (defaults block)
      and PUT (`apply_ranged`), tests at both bounds and one past each.

### Lot C2: the settings in the canonical config - cargo

Allowlist: `lorica-config/src/canonical.rs`, `lorica-config/src/diff.rs`.
Depends on: C1; 12.1's canonical Lot (same file).

- [ ] Both settings in `CanonicalGlobalSettings` with `#[serde(default)]`,
      `CANONICAL_SHAPE_DIGEST` updated, a test decoding a blob without
      them; `diff.rs` reports their changes.

### Lot D: supervisor, worker and single-process integration, stop path - cargo

Allowlist: `lorica/src/startup/stream_plane.rs` (new),
`lorica/src/startup/drain.rs` (new), `lorica/src/startup/supervisor.rs`,
`lorica/src/startup/worker.rs`, `lorica/src/startup/single.rs`,
`lorica/src/startup/mod.rs` (module declarations),
`lorica/src/startup/hot_upgrade.rs`, `lorica/Cargo.toml`,
`lorica-worker/src/manager.rs` (`shutdown_all` signature only),
`Cargo.lock`.
Depends on: A, B, C1; 12.1's store Lot (stream listing, selector
resolution) and the shared reserved-port rule. `lorica-core` is not
in the allowlist: the 300 s fix uses the fork's existing
`Server::new_with_opt_and_conf`.

- [ ] `stream_plane.rs`: the supervisor driver (registry, `bind_gen`
      counter, per-worker stop-and-wait senders, the three steps of D-d,
      node backstop, retry tick, audit rows and the alert of D-h through
      handles passed in) and the single-process driver over `mpsc`
      (D-k). The transport is a trait so the driver is unit-tested with
      a fake worker that acks, nacks and times out.
- [ ] `drain.rs`: `pingora_server_conf(base)` (sets
      `grace_period_seconds = WORKER_DRAIN_TIMEOUT_MAX_S` and
      `graceful_shutdown_timeout_seconds = 5`), the drain watcher of D-f
      (idle check on `active_connections` and the tracker, deadline,
      OTel flush, exit through an injected function so tests do not
      exit), and the stop keepalive thread (`EXTEND_TIMEOUT_USEC=30000000`
      every 10 s, target socket injected for tests).
- [ ] `hot_upgrade.rs`: `sd_notify(payload)` with `sd_notify_ready` on
      top of it and `extend_timeout_payload(usec)`; the `stream-tcp:` key
      family of D-j, its arm above the catch-all, adoption into the
      registry; pure tests that a `stream-tcp:` key never lands in
      `proxy`.
- [ ] `worker.rs`: build the `Server` with `new_with_opt_and_conf(None,
      pingora_server_conf(...))`; start `StreamRuntime` on its thread with
      the stream-ctl fd, the store and `server.watch_execution_phase()`;
      arm the drain watcher on `quiesce` or `GracefulTerminate`.
- [ ] `supervisor.rs`: take each worker's stream-ctl end at start and in
      the monitor's respawn branch (replay of D-a); the three steps
      inside `ConfigReloadBridge::apply_config_change`; first reconcile
      before `sd_notify READY=1`; the stop path of D-f (keepalive,
      `quiesce`, `shutdown_all(D + 10 s)`, `stream.release` rows with
      cause `shutdown`); the registry handed to `AppState` in Lot E3.
      `drain_for_handoff` is left to Story 12.11.
- [ ] `single.rs`: `new_with_opt_and_conf`, `server.run` instead of
      `run_forever`, runtime and driver, the three steps in the reload
      task, the single-process stop path of D-f.
- [ ] `manager.rs`: `shutdown_all(drain: Duration)`.
- [ ] Tests: `pingora_server_conf` sets both fields (and a test that
      greps `lorica/src` for `Server::new(` so no `Server` is built
      without Lorica's conf again); the watcher exits at once when idle,
      waits while a request or a tracked connection is in flight, and
      exits at the deadline; the keepalive sends at least three
      well-formed `EXTEND_TIMEOUT_USEC` datagrams to a test socket
      within 25 s and sends nothing when no target is set;
      `extend_timeout_payload` format; the reconcile driver against the
      fake transport (respawn replay, ack timeout, partial range
      failure rolls back).

### Lot E1: the alert type - cargo

Allowlist: `lorica-notify/src/**`, `lorica-config/src/store/mod.rs`
(the migration only), `lorica-api/tests/adcs_vocabulary_fixture.rs` if it
needs the new type, `lorica-dashboard/frontend/src/lib/adcs.generated.ts`
(regenerated, never hand-edited).
Depends on: 12.1's migration Lot (same `MIGRATIONS` list). Parallel to D.

- [ ] `AlertType::StreamBindFailed` (`stream_bind_failed`), `ALL`
      extended, every exhaustive match in `lorica-notify` updated.
- [ ] The subscription migration at the next free number, sharing the
      migration 63 helper as 65 does; idempotence test.
- [ ] Regenerate the vocabulary file the fixture pins.

### Lot E3: API surfaces - cargo

Allowlist: the stream handlers module 12.1 creates (expected
`lorica-api/src/streams.rs`), `lorica-api/src/stream_budget.rs` (new),
`lorica-api/src/server.rs`, `lorica-api/src/middleware/authorize.rs`,
`lorica-api/src/lib.rs`, `lorica-api/Cargo.toml`, `lorica-api/openapi.yaml`
(sole owner in this story), `lorica-api/src/tests.rs`,
`lorica/src/startup/supervisor.rs` and `lorica/src/startup/single.rs`
(the `AppState` field initialisation only), `Cargo.lock`.
Depends on: D, C2, E1; 12.1's CRUD Lot.

- [ ] `AppState` gains the stream-plane handle (registry snapshot, budget
      inputs); every construction site updated.
- [ ] `bind` on the stream GET and list responses.
- [ ] Budget check of D-e on stream create and update, which are
      Operator writes like routes (12.1's `required_role` rule, unchanged
      here): the local node, and every reporting targeted node on a
      control plane, a warning for the others; the refusal names node,
      constraint and numbers.
- [ ] `GET /api/v1/streams/budget`, Operator and SuperAdmin, with a
      `required_role` table test; a follower answers its own node.
- [ ] `openapi.yaml`: the budget path, `bind` on the stream schema, both
      settings with their bounds, `stream_bind_failed` in the alert enum,
      the `stream_plane` and `stream_ports` fields of Lot E2. Contract
      test green.

### Lot E2: heartbeat, fleet view, enrollment preview - cargo

Allowlist: `lorica-cluster/src/messages.rs`, `lorica-cluster/src/dialer.rs`,
`lorica-cluster/src/roster.rs`, `lorica-cluster/src/bridge.rs`,
`lorica-api/src/cluster/mod.rs`, `lorica-api/src/cluster/tests.rs`,
`lorica/src/startup/cluster_follower.rs`. `lorica-fleet/**` and
`lorica-api/src/cluster/boundary.rs` are read, not edited.
Depends on: E3 (the `AppState` handle, `openapi.yaml` already carries the
fields); 12.1's heartbeat Lot (same files).

- [ ] `StreamPlaneReport` on `Heartbeat` (D-i), additive tags, a
      decode test of a heartbeat without it.
- [ ] `FollowerHandler::stream_plane()` defaulted to `None` like
      `resources`; `ReplicaHandler` fills it from the registry.
- [ ] `roster.rs` records it; `node_responses` renders `stream_plane`
      (budget figures withheld from Viewers, tested), `unknown` when
      `lorica_fleet::runtime::evaluate_drift` reports drift, and the
      control plane's own node from the local registry.
- [ ] `stream_ports` on the pending-node review, fleet-wide streams
      included; test with one selected and one fleet-wide stream.

### Lot F: dashboard - frontend gates

Allowlist: `lorica-dashboard/frontend/src/lib/api.ts`,
`lorica-dashboard/frontend/src/routes/System.svelte` (+ `.test.ts`, new
if absent), `lorica-dashboard/frontend/src/components/StreamBudget.svelte`
(+ `.test.ts`, new), `lorica-dashboard/frontend/src/routes/Cluster.svelte`
(+ `Cluster.test.ts`), `lorica-dashboard/frontend/src/components/settings-tabs/GlobalConfigTab.svelte`
(+ `.test.ts`), `lorica-dashboard/frontend/src/components/settings/SettingsNotifications.svelte`
and `components/settings-tabs/NotificationHistoryTab.svelte` (+ tests) if
the new alert type needs a label.
Depends on: E1, E2, E3.

- [ ] Types and calls; `StreamBudget.svelte` (fd limit, reserves, each
      stream's share; a `null` ceiling renders as a dash whose tooltip
      names it, never as 0), mounted on the System page for Operators
      and above.
- [ ] Cluster node drawer: bound count, pending and failed bindings with
      kind and OS error, `unknown` under drift; `stream_ports` in the
      pending-node review.
- [ ] Both settings in the global config tab with their bounds.
- [ ] Vitest: role gating of the budget panel, failed binding rendering,
      the drain field's bounds.

### Lot G: documentation and crate lists - no cargo

Allowlist: `docs/hot-upgrade.md`, `docs/installation.md`,
`docs/security/hardening-guide.md`, `docs/architecture/worker-shared-state.md`,
`docs/architecture/source-tree.md`, `docs/architecture/component-architecture.md`,
`docs/BUMP-CHECKLIST.md`, `.claude/skills/bump-version/bump-checklist.md`,
`.claude/rules/lorica-project.md`, `.claude/skills/run-tests/**`,
`.claude/skills/build-deb/**`, `README.md`, `FORK.md`, `CONTRIBUTING.md`,
`docs/backlog.md`, `CHANGELOG.md`, `docs/streams.md` (the budget,
bind-state and listen-address sections).
Depends on: B for the crate lists; its final pass after H.

- [ ] Every crate list of D-b, the README product-crate test count.
- [ ] `worker_drain_timeout_s` and `stream_listen_socket_cap` as they now
      exist: `installation.md` (`TimeoutStopSec=90` is no longer "must
      exceed the drain": the stop keepalive extends it; systemd 236+),
      `hot-upgrade.md` (the upgrade drain stays 30 s until 12.11), the
      hardening guide (no drop-in needed for longer drains; why
      `TimeoutStopSec` stays; `LimitNOFILE` as the way to grow stream
      capacity; Docker's `stop_grace_period`).
- [ ] `docs/streams.md`: the budget formula, bind states, and the
      listen-address rule of D-c (`[::]` is dual-stack and exclusive on
      its port).
- [ ] `worker-shared-state.md`: a section for the stream control channel
      (D-a), its flow control and its crash behaviour.
- [ ] `FORK.md` and backlog #81 per D-l; `CHANGELOG.md` `[Unreleased]`
      (Added: stream listeners, the two settings, the alert; Fixed:
      stops waited on a hard-coded delay and single-process mode did not
      drain HTTP).

### Lot H: end-to-end, IV1, IV2 and the stop path - Docker e2e

Allowlist: `tests-e2e-docker/entrypoint-streams.sh` (new, LF),
`tests-e2e-docker/test-runner/run-streams-smoke.sh` (new, LF),
`tests-e2e-docker/docker-compose.yml`, `tests-e2e-docker/Dockerfile`
(the entrypoint `COPY` and `chmod` lines only, after Lot B's line),
`tests-e2e-docker/test-runner/Dockerfile` (`iproute2` added, approved),
`tests-e2e-docker/run.sh`.
Depends on: D, E3. The machine to itself, orphan containers torn down
first.

- [ ] A `streams` profile in worker mode and a `streams-single` profile,
      each with a runner sharing Lorica's network and pid namespaces
      (`network_mode` and `pid` set to `service:<lorica service>`), so
      the runner can run `ss` and signal processes, and a
      `stop_grace_period` above the drain under test.
- [ ] IV1: an HTTP load loop runs throughout; create a TCP stream on
      5432 through the API; poll `ss -ltnH 'sport = :5432'` until present,
      assert within 5 s and a TCP connect accepted; delete; poll until
      absent, assert within 5 s; assert the HTTP loop saw zero failures.
- [ ] IV2: a squatter process listening on 6000 in Lorica's namespace;
      create a stream on 6000; assert `bind.state = failed`,
      `kind = address_in_use`, the OS error text, a `stream.bind_failed`
      audit row, HTTP still 200; stop the squatter; assert `bound` within
      the retry interval plus 5 s.
- [ ] AC #3: the profile's entrypoint starts as root and drops to
      `lorica` with `setpriv --ambient-caps +net_bind_service`, the way
      systemd does; a stream on port 853 binds.
- [ ] AC #1 respawn: a UDP stream on 2 workers; `kill -9` one worker; after
      respawn `ss -uan` still shows the same number of sockets on the
      port and a client that was served before is served again.
- [ ] Dual stack: a stream on `[::]:7000` refuses a second one on
      `0.0.0.0:7000`, and IPv4 and IPv6 clients both reach the first.
- [ ] Stop, both modes: with no traffic, SIGTERM ends the process in
      under 10 s (the 300 s and the fixed 30 s are gone); with
      `worker_drain_timeout_s = 20` and an HTTP request to a backend that
      answers after 8 s, the request completes and the process exits
      shortly after it, before 20 s.
- [ ] Budget: a compose `ulimits: nofile` of 4,096 makes a 1,024-port UDP
      range refused with the supervisor constraint named.

## Dev Notes

### Where to extend, verified

- `lorica-worker/src/fd_passing.rs`: `FdKind`, `to_token` / `from_token`,
  `recv_listener_fds` (lists variants by name), `MAX_FDS`,
  `MAX_TOKEN_LEN`, `PAYLOAD_BUF_SIZE` and their `const` assertion,
  `create_socketpair` (`SockType::Stream`; the new pair is
  `SockType::SeqPacket`).
- `lorica-worker/src/manager.rs`: `spawn_worker` (the bundle), `WorkerHandle`
  (`take_cmd_fd`, `take_rpc_fd`), `restart_worker` (returns `(cmd, rpc)`,
  keep it), `shutdown_all` / `shutdown_all_with_timeout`,
  `drain_for_handoff` (12.11's), `handoff_listen_fds`.
- `lorica/src/startup/worker.rs`: `run_worker`, the exhaustive `match
  entry.kind`, the command-channel thread as the pattern for the stream
  thread, the `server_conf` built for `http_proxy_service`, and
  `Server::new(None)` + `server.run(RunArgs::default())` at the end.
- `lorica/src/startup/single.rs`: `run_single_process`, its own
  `server_conf`, the proxy thread with `Server::new(None)` and
  `run_forever`, the reload task, the shutdown tail.
- `lorica-core/src/server/mod.rs` (read only): `Server::new`,
  `Server::new_with_opt_and_conf`, `Server::run` (reads
  `grace_period_seconds` and `graceful_shutdown_timeout_seconds` from
  `self.configuration`), `EXIT_TIMEOUT`, `Server::watch_execution_phase`,
  `ExecutionPhase::GracefulTerminate`. `ServerConf` fields in
  `lorica-core/src/server/configuration/mod.rs`.
- `lorica/src/startup/supervisor.rs`: `run_supervisor` (`worker_fds`
  extraction before the runtime, the monitor's restart branch,
  the SIGTERM `select!` arm, the upgrade `Drain` arm),
  `ConfigReloadBridge::apply_config_change`, `coordinate_config_reload`
  (its 2 s Prepare timeout is the ack timeout's model),
  `spawn_supervisor_rpc_handler` (the "one helper for both spawn paths"
  pattern the stream channel must follow).
- `lorica/src/startup/hot_upgrade.rs`: `sd_notify_ready`,
  `notify_payload`, `build_fds_table`, `partition_inherited_fds`,
  `InheritedListeners`, the key-prefix constants.
- `lorica/src/startup/mod.rs`: `drain_for_exit` (now calling
  `lorica_fleet::runtime::drain_detached`), `shutdown_signal`,
  `BACKGROUND_TASK_DRAIN_TIMEOUT`.
- `lorica/src/proxy_wiring.rs`: `LoricaProxy::active_connections`.
- `lorica-api/src/audit.rs`: `AuditContext::node`, `record_with_store`.
- `lorica-notify/src/events.rs`: `AlertType`, `as_str`, `ALL`.
- `lorica-config/src/models/settings.rs` and `store/settings.rs`: follow
  `downstream_idle_timeout_s` through every site grep finds;
  `lorica-api/src/settings.rs`: `apply_ranged`, the defaults block.
- `lorica-cluster/src/messages.rs` (`Heartbeat`, `NodeResources` as the
  model), `dialer.rs` (`node_resources`, `FollowerHandler::resources`),
  `roster.rs` (`record_resources`), `bridge.rs`;
  `lorica-api/src/cluster/mod.rs` (`node_responses`, `NodeResponse`,
  `selected_hostnames`); `lorica-fleet/src/runtime.rs`
  (`evaluate_drift`, read only).

### Linux pitfalls

- **`SCM_RIGHTS` limits.** At most `SCM_MAX_FD` (253) fds per message;
  this story sends 32. Fds in flight count against the sending user's
  `RLIMIT_NOFILE` and past it `sendmsg` fails with `ETOOMANYREFS`
  (unless the sender holds `CAP_SYS_RESOURCE`, which Lorica does not).
  Queuing every socket to every worker at once at boot would hit it with
  wide ranges and many workers: hence stop-and-wait. Receive with
  `MSG_CMSG_CLOEXEC`; a `MSG_CTRUNC` means fds were lost, treat it as an
  error and close what arrived.
- **`SOCK_SEQPACKET`** preserves boundaries; a receive buffer smaller
  than the message truncates it (`MSG_TRUNC`). Size the buffer from the
  same constant as the assertion.
- **`SO_REUSEPORT` groups** form among sockets with the option set
  before `bind`, on the same address and port, owned by the same
  effective UID. Selection without a BPF program is a hash of the 4-tuple
  scaled to the group size; any size change remaps nearly every client,
  and closing a member moves the last member into its slot. Keep the
  group size constant (D-c). Same-UID joining is also why the new
  generation's UDP group merges with the old one during an upgrade.
- **TCP without `SO_REUSEPORT`** gets a real `EADDRINUSE` from any other
  holder; `SO_REUSEADDR` only lets a listener bind over `TIME_WAIT`.
- **IPv6.** `IPV6_V6ONLY` must be set before `bind`. Its default comes
  from `net.ipv6.bindv6only` (0 on the distributions Lorica targets, but
  a host may differ), which is why D-c sets it both ways. A dual-stack
  `[::]` socket reports IPv4 peers as IPv4-mapped addresses
  (`::ffff:192.0.2.10`); anything that logs or filters on the peer
  (Stories 12.6 and 12.9) must canonicalise them.
- **`CAP_NET_BIND_SERVICE`.** The unit grants it as an ambient
  capability, which `execve` preserves for an unprivileged user, so the
  workers hold it too; D4 still has the supervisor bind, because only the
  supervisor can build a UDP group and keep its slots. Do not rely on a
  worker binding. Single-process mode binds in the one process, which
  holds it. `net.ipv4.ip_unprivileged_port_start` can make a test pass
  for the wrong reason: the e2e asserts with the capability, not the
  sysctl.
- **`EADDRNOTAVAIL`** for an address not (yet) on the host, a VIP for
  instance. No `IP_FREEBIND`: the binding fails and the 10 s retry picks
  it up when the address appears.
- **`RLIMIT_NOFILE`:** read the soft limit. The unit kills `setrlimit`
  (`@resources`) and grants no `CAP_SYS_RESOURCE`, so never try to raise
  it. Reading goes through `getrlimit` / `prlimit64`, which I'm fairly
  sure `@system-service` allows; the deb install job runs under the real
  unit and is where to confirm it, since the e2e suite does not run
  systemd.
- **`EXTEND_TIMEOUT_USEC`** is honoured only while a job is running for
  the state it extends (here the stop job), and each message must arrive
  before the previous extension runs out; the 10 s interval against a
  30 s extension leaves two misses of slack. It needs systemd 236. It is
  a datagram to `$NOTIFY_SOCKET`: no reply, so a mistake is silent; the
  keepalive logs a send error once and keeps trying.
- **`fork` from the supervisor's runtime thread** at respawn already
  happens (`restart_worker`); the stream sockets are created
  `SOCK_CLOEXEC` (socket2's default), so they never leak into an
  `execv`'d worker except through the channel.

### Tests per Lot

Listed in each Lot. All `lorica-worker`, `lorica-stream` and drain
tests need Linux and run through the `run-tests` skill in Docker. IV1,
IV2 and the stop path are automated in Lot H. Two things are not
covered by an automated test here, because the e2e suite does not run
systemd: that seccomp allows reading the fd limit, and that systemd
honours the extension end to end. Both are checked in the deb install
CI job under the real unit (a stop with a held request and a drain
longer than 90 s), or by hand on a VM if that job cannot be extended;
the Completion Notes say which.

## Resolved (maintainer, 2026-11-14)

1. **`enabled`** is a Story 12.1 field (PRD amended). D-d and D-g read it.
2. **`node_shutdown`** joins 12.1's end-reason enum (PRD amended). A
   stop closes with it (D-g).
3. **A plain stop uses `worker_drain_timeout_s`** from this story on
   (D-f; AC #7 amended to say so).
4. **The 300 s `EXIT_TIMEOUT` is fixed in this story, not in the fork.**
   Lorica builds its `Server` with its own `ServerConf` through
   `Server::new_with_opt_and_conf`, setting `grace_period_seconds` and
   `graceful_shutdown_timeout_seconds` (D-f). Implementation note: the
   grace is set to the setting's hard maximum rather than to the value
   read at worker start, because that `ServerConf` is frozen for the
   worker's life while the setting changes at runtime; the drain watcher
   applies the current value and exits as soon as traffic is gone. The
   other stop paths were checked: the supervisor's SIGTERM path and the
   upgrade path waited on Pingora's 300 s through their workers (both
   now bounded by the watcher, the upgrade's own 30 s staying until
   12.11), and single-process mode did not wait at all and now drains.
   Tested in Lot D and Lot H.
5. **The per-stream failed badge** waits for Story 12.10's Streams page;
   AC #4's dashboard half is checked off then.
6. **The branch-only interim** (accepted connections closed at once until
   12.3 and 12.5) is accepted.
7. **UDP session sockets** are Story 12.5's decision, with the 12.16
   spike as evidence. This story counts whatever a session holds through
   a generic `fds_per_unit` input (D-e) and assumes no figure.
8. **The stop timeout** uses `EXTEND_TIMEOUT_USEC` during a stop drain
   instead of a cap below `TimeoutStopSec` (D-f): no environment
   variable, no drop-in, a hard maximum of 3,600 s for NFR2. Hot upgrade
   (no stop job) and runs without systemd (no `$NOTIFY_SOCKET`) are
   covered in D-f.
9. **Budget defaults** accepted: HTTP reserve `L / 2`, base reserve 1,024,
   2,048 listening sockets per node.
10. **Story 12.9 AC #5** counts the failed-bind alert as delivered here.
11. **`iproute2`** in the e2e runner image only: approved (Lot H).
12. **Dual stack:** a stream has one listen address. `[::]` binds with
    `IPV6_V6ONLY` off and conflicts with every address on its port and
    protocol; any other IPv6 literal binds `IPV6_V6ONLY` on (D-c).

Also decided: stream writes are Operator, like routes (12.1's rule);
the budget view stays Operator and SuperAdmin.

## Dev Agent Record

### Debug Log

- Lot A, `MSG_CTRUNC`: nix's `RecvMsg::cmsgs()` returns `ENOBUFS` on a
  control buffer flagged `MSG_CTRUNC` instead of iterating it, while the
  kernel has already installed the fds that fit. `recv_worker_fds`
  propagated that error and leaked them (reproduced with 33 fds against a
  32-fd buffer). Both receivers now go through
  `fd_passing::recv_with_rights`, which walks the `SCM_RIGHTS` headers
  itself on `MSG_CTRUNC` and owns every installed fd. Committed apart as
  a fix, since the fork bundle had the leak before this story.
- Lot A, UDP and the kernel backstop of D-c: verified in the
  `rust:1-bookworm` container that the kernel does **not** refuse a
  second same-user `SO_REUSEPORT` UDP socket on a port a `[::]` group
  holds, whether on `0.0.0.0`, `127.0.0.1` or `[::]` itself: it joins or
  shadows the group. Only a socket without `SO_REUSEPORT`, or one of
  another user, gets `EADDRINUSE`. D-c's "the kernel refuses at bind as
  the backstop" holds for TCP only. Lot D's node-side backstop must
  therefore refuse a UDP binding that overlaps one in its own registry
  before binding; the kernel will not. The test
  `udp_reuseport_groups_of_one_user_are_not_refused_by_the_kernel` pins
  that fact; the `[::]` refusal test covers TCP and, for UDP, a plain
  socket.

### Completion Notes

- Lot A done (`lorica-worker` and the one `worker.rs` arm). Public API:
  `fd_passing::{StreamProto, FdKind::StreamCtl, FdKind::StreamSocket}`;
  `stream_ctl::{StreamCtlMsg, StreamSocket, QuiesceReason, NackReason,
  StreamCtlError, send_msg, recv_msg, chunk_sockets,
  create_seqpacket_pair, ATTACH_MAX_SOCKETS, MAX_STREAM_ID_LEN}`;
  `stream_sockets::{bind_tcp_stream_listener, bind_udp_group,
  bind_range, BoundPort, BindError, BindFailureKind, process_fd_limit,
  TCP_STREAM_BACKLOG}`; `WorkerHandle::take_stream_ctl_fd`;
  `WorkerError::StreamCtl`.
- `PAYLOAD_BUF_SIZE` went from 4,096 to 8,192 bytes: the old value held
  exactly 32 tokens of 128 bytes without their separators, so the
  `attach` header could not fit beside them. The assertion now counts
  the header and one separator per token.
- `MAX_STREAM_ID_LEN` is 64, set here because 12.1's id validation has
  not landed: stream ids are generated UUIDs (36 bytes). Lot B or 12.1
  may tighten it; the assertion follows the constant.
- `NackReason` is a closed set (`malformed`, `unknown_binding`,
  `adopt_failed`, `shutting_down`) chosen for the runtime of Lot B, which
  may extend it.
- `worker.rs` carries two arms, not one: the match is exhaustive, so
  `StreamSocket` needs one too. A stream socket arriving in the fork
  bundle is closed with a warning; it only ever travels over the stream
  control channel. Until Lot D the worker holds its stream control end
  for its whole life and reads nothing from it; the supervisor's end
  stays on the `WorkerHandle`.
- `recv_listener_fds` (test wrapper) now closes the fds of the entries it
  filters out instead of dropping the raw numbers.
- Lot C1 done. `GlobalSettings::worker_drain_timeout_s` (seconds,
  default 30, 1 to 3,600) and `GlobalSettings::stream_listen_socket_cap`
  (listening sockets per node, default 2,048, 1 to 16,384), stored as
  key/value rows like `downstream_idle_timeout_s` (no migration; an
  unparseable stored value is `ConfigError::Corrupt`). The bounds are
  associated constants, `GlobalSettings::{DEFAULT_WORKER_DRAIN_TIMEOUT_S,
  WORKER_DRAIN_TIMEOUT_MAX_S, DEFAULT_STREAM_LISTEN_SOCKET_CAP,
  STREAM_LISTEN_SOCKET_CAP_MAX}`, not free ones: the free-constant
  re-export list is in `models/mod.rs`, a Story 12.1 file, and the type
  is already exported. Lot D builds `grace_period_seconds` from
  `GlobalSettings::WORKER_DRAIN_TIMEOUT_MAX_S`.
- The story gives no reason for the socket cap's 16,384 ceiling; its
  doc comment calls it a sanity bound on operator input, since the fd
  budget of D-e is what decides what a node can hold.
- `canonical.rs`'s `every_global_setting_is_explicitly_routed` is an
  exhaustive destructure, so `lorica-config`'s tests did not compile
  without the two fields. They are listed there on the replicated side,
  as D-f decides; Lot C2 still owes them in `CanonicalGlobalSettings`
  and `diff.rs`. Not on the automation admin tier (D-f).

## File List

- `lorica-worker/Cargo.toml` (nix `resource` feature)
- `lorica-worker/src/fd_passing.rs`
- `lorica-worker/src/lib.rs`
- `lorica-worker/src/manager.rs`
- `lorica-worker/src/stream_ctl.rs` (new)
- `lorica-worker/src/stream_sockets.rs` (new)
- `lorica-worker/tests/stream_ctl.rs` (new)
- `lorica/src/startup/worker.rs` (the `StreamCtl` and `StreamSocket` arms)
- `lorica-config/src/models/settings.rs`
- `lorica-config/src/store/settings.rs`
- `lorica-config/src/canonical.rs` (the routing test's destructure only)
- `lorica-api/src/settings.rs`

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-11-14 | 0.1 | Story drafted from the Epic 12 PRD. Status Draft. | Romain G. |
| 2026-11-14 | 0.2 | Maintainer answers folded in: AC #7 as amended, `EXTEND_TIMEOUT_USEC` stop path, the 300 s fix through Lorica's `ServerConf`, the drain watcher, the dual-stack rule, a generic per-session fd input, paths re-checked after `4e864593`. Status Draft. | Romain G. |
| 2026-11-14 | 0.3 | Lot A implemented: stream control channel, stream socket binding, third socketpair per worker; `MSG_CTRUNC` fd leak fixed; UDP kernel-backstop gap recorded for Lot D. Status InProgress. | Romain G. |
| 2026-11-14 | 0.4 | Lot C1 implemented: `worker_drain_timeout_s` and `stream_listen_socket_cap` on `GlobalSettings`, the store and `PUT /api/v1/settings`. Status InProgress. | Romain G. |
