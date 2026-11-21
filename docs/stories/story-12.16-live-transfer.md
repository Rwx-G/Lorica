# Story 12.16: Live Transfer Across Hot Upgrades

**Epic:** [Epic 12 - TCP and UDP Stream Proxying (v1.11.0 and v1.12.0)](../prd/epic-12-v1.11.0.md)
**Status:** Spike done
**Priority:** P1 (Phase 2, v1.12.0)
**Author:** Romain G.
**Depends on:** Story 12.11 (the drain a connection falls back to, the
UDP slot handover of its D-e), Story 12.3 (the forwarding loop and its
quiesce point), Story 12.5 (UDP sessions).

---

As an operator,
I want an upgrade to hand my SSH connections and UDP sessions to the new binary,
so that an upgrade stops being a maintenance window for them.

The Acceptance Criteria and Integration Verifications are the PRD's
(`docs/prd/epic-12-v1.11.0.md`, "Story 12.16"). The 1.12.0 cycle drafts
the rest of this story from the outcome below; nothing here is a
decision of that cycle until it adopts it.

## Spike outcome

**Status:** Spike done (2026-11-18), on `feat/v1.11.0` at `77212d46`.
**Prototype:** `spikes/12.16-live-transfer/` (standalone Cargo project,
excluded from the workspace, no production code touched).

### Recommendation: ships reduced

The core mechanism works and is not the risk the PRD feared. Passing a
connected socket with `SCM_RIGHTS` moves the kernel's whole TCP state
with it (receive and send queues, retransmission queue, SACK and window
state, a pending FIN or RST): across 21,798 connection transfers and
2,240 UDP session transfers under 1 % loss with reordering, about 3.9 GB
was checked byte for byte in both directions with no byte lost,
duplicated or reordered, one end row per connection, and every injected
fault in the handover protocol fell back to the old generation without
losing a connection. What did not hold up is three things the PRD
wrote, so the story ships with these changes and only these:

1. **AC #2 is amended: no quiesce wait.** Waiting until "no forwarded
   bytes are held in userspace" makes the park time the time the
   slowest peer takes to accept one buffer, which under loss is a TCP
   retransmission timeout or more, and never ends for a reader that
   stopped reading. A connection should instead park at once and carry
   the bytes its two buffers hold (at most one buffer per direction) in
   the transfer message. The handover pause drops from a p50 of 74 ms
   and a p95 of 238 ms (bounded only by `transfer_timeout`, reached in
   the runs) to a p50 of 1.3 ms and a maximum of 2.4 ms, and the "not
   quiesced in time" fallback disappears. `transfer_timeout` remains, as
   the bound on the new generation's `READY`, not on the connection.
   Connections in a PROXY-header, ClientHello or detection read still
   drain, as the PRD says (that is a choice of scope, not a limit the
   spike found).
2. **AC #5 is reduced to the upgrade.** The supervisor replaces a worker
   only after it has exited (`restart_worker`, called from the worker
   monitor in `lorica/src/startup/supervisor.rs`): its established
   connections and session sockets died with it, and nothing remains to
   hand over. "A worker the supervisor replaces hands its sessions over
   the same way" cannot be built; the slot-to-worker affinity across an
   upgrade (12.11 D-e) is what remains, and it holds.
3. **IV4 is reduced for UDP.** "No byte lost" cannot be asserted for
   datagrams under injected loss. The verifiable claim is: no datagram
   duplicated, no session re-created on the backend (one source port per
   client for the whole run), and datagrams dropped by the handover
   counted (`UdpRcvbufErrors`) and bounded. The bound is the pause times
   the client datagram rate against the slot socket's receive buffer; it
   was zero at 2,000 datagrams/s and about 870 datagrams per upgrade at
   25,000 datagrams/s with 1,000 TCP connections transferred alongside.

Two ordering rules come with it, both found by the spike and both
contradicting text written before it:

- **UDP: the new generation must not read a slot socket before the
  sessions on it are adopted.** Story 12.11 D-e lets both generations
  read the group between the new generation's attach and the old one's
  `quiesce`. For a stream that transfers, every client datagram read by
  the new generation in that window opens a second backend session; the
  `udp-naive` scenario reproduces it (249 sessions re-created over 20
  upgrades, 32 clients).
- **TCP: the new generation's abort path closes, it never shuts down.**
  Lorica closes a connection with `shutdown(Both)` then drop
  (`lorica-stream/src/tcp/engine.rs`); on sockets the old generation is
  about to resume, a `shutdown` acts on the shared socket. The
  `abort-shutdown` negative control breaks 8 connections out of 8.

Everything else in the PRD's ACs (#1, #3, #4, #6, #7, #8) is not
contradicted by the spike; #3's cap permits and bandwidth budget were
not prototyped (see "What remains unknown").

### Method

One Rust binary, two roles. `harness` runs a TCP backend, a UDP backend
and every client in one process, starts generation 0 of the proxy, and
checks the outcome. `proxy` is one generation. Generation `n` serves for
`--interval-ms`, then spawns generation `n+1` itself with one end of a
`SOCK_SEQPACKET` socketpair on fd 3 (the way the old supervisor execs
the new binary), hands over, drains what did not transfer and exits.
Every generation is a separate process with its own fd table and epoll
instance; 50 consecutive upgrades is 51 processes in a chain.

The forwarding loop mirrors `lorica-stream/src/tcp/forward.rs`: one
fixed buffer per direction (16 KiB), one read then the whole chunk
written before the next read, so "both directions reading or closed" is
the PRD's quiesce point. `--carry-held 1` parks at once instead and
serializes the unwritten part of each buffer.

The handover, old generation O, new generation N:

1. N sends `HELLO`. O stops accepting and stops reading the UDP slot
   socket, and sends `LISTENERS` (TCP listener, UDP slot socket).
2. O asks every forwarding connection to park. A connection parks by a
   compare-and-swap `PARK_REQ -> PARKED`; at `transfer_timeout` O swaps
   `PARK_REQ -> DRAIN`. Exactly one of the two wins. Each parked
   connection deregisters from O's epoll (`into_std`) before its fds
   leave. UDP session tasks stop and give back their upstream socket.
3. O sends one message per connection (state and both sockets) and per
   session (state and upstream socket), then `END` with the counts.
4. N answers `READY` once it holds everything; it forwards nothing yet.
   O sends `COMMIT`; N answers `COMMITTED` and only then forwards. O
   keeps its own descriptors until it reads `COMMITTED`.
5. No `READY` within the bound, or EOF before `COMMITTED`: O kills and
   reaps N, then resumes everything it parked (N provably never
   forwarded). A `COMMIT` without answer in time: O kills and reaps N,
   then reads what N had queued: `COMMITTED` there means N forwarded and
   O must not resume. N treats `ABORT` as "close what you received" and
   a bare EOF after `READY` (O died without deciding) as a commit, which
   is safe because O sends `ABORT` before it ever resumes.

State that crosses: connection id, client address, both direction
states (reading, closed, or with `--carry-held` the held bytes), byte
counters, start time, last activity and the total-duration deadline as
absolute `CLOCK_MONOTONIC` values, the hop count. A session crosses with
its client address, counters and times.

Traffic, all at once in each scenario: long connections (1 MB/s each way,
paced, until the run ends, then the backend sends a 64 KiB tail after the
client's FIN); churn connections (16 workers opening connections of
0 to 256 KiB each way at full speed, closing in either order, so
half-closed connections cross handovers, and 10 % aborted with an RST
after 0 to 60 ms); UDP clients (one 64-byte request every 2 ms, one
response each). Every byte is a deterministic stream both ends generate,
compared byte for byte and hashed (FNV-1a) per direction; UDP requests
carry a sequence number and the backend records the source ports it
sees per client. Every generation logs `TRANSFER` events and `END` rows;
the harness checks one `END` row per connection whose counters equal
what the two ends counted.

Network: `tc netem` on the container's loopback (MTU set to 1500), TCP
only unless `NETEM_UDP=1`. "Lossy" is `delay 2ms 1ms loss 1%
reorder 5%`; "harsh" is `delay 5ms 3ms loss 5% duplicate 1% reorder
25%`. The kernel's `TcpRetransSegs` is reported per run so the
retransmissions during handovers are a fact, not an assumption (tens of
thousands per run).

`run-all.sh` builds and runs every scenario; `run.sh` is the in-container
entry point. Cargo runs in `rust:1-bookworm`; the scenarios run in
`debian:bookworm-slim` with `iproute2`, `--init` and `NET_ADMIN` on that
container only. Dependencies: tokio, nix and libc, all at the versions
the workspace `Cargo.lock` pins (checked: the spike's lockfile is a
subset of the workspace's).

### Machine

Intel Core Ultra 9 285K, 24 logical CPUs visible to Docker, 95 GiB RAM,
Windows 11 host, Docker 29.9.3 on WSL2, Linux kernel
6.18.33.2-microsoft-standard-WSL2, Rust 1.99.1, tokio 1.54.1. Client,
proxy and backend share one container's loopback: no NIC, no second
host.

### Measurements

All runs 2026-11-18, every TCP connection checked byte for byte.
"Pause" is the time from the old generation's park request to the new
generation's adoption, which is what every transferred connection sees.
"Protocol" is `END` sent to `COMMITTED` received.

| Scenario | Upgrades | TCP transfers | UDP transfers | Failed | Pause p50 / p95 / max (ms) | Protocol p50 (ms) | UDP lost by handover |
|---|---|---|---|---|---|---|---|
| `baseline` (no upgrade, lossy) | 0 | 0 | 0 | 0 of 1,818 | - | - | 0 |
| `main` (lossy, quiesce wait) | 50 | 631 | 200 | 0 of 2,173 | 74 / 238 / 1,002 | 0.38 | 3,521 of 26,004 |
| `main-carry` (lossy) | 50 | 653 | 200 | 0 of 2,504 | 1.28 / 1.78 / 2.28 | 0.33 | 0 of 26,004 |
| `harsh` (quiesce wait) | 50 | 368 | 128 | 0 of 391, 2 fallbacks | 216 / 862 / 1,002 | 0.35 | 11,273 of 26,000 |
| `harsh-carry` | 50 | 752 | 200 | 0 of 505 | 1.79 / 2.20 / 2.35 | 0.37 | 0 of 26,004 |
| `udp-netem` (netem on UDP too) | 50 | 131 | 400 | 0 of 253 | 33 / 217 / 377 | 0.32 | 5,387 (plus netem's own) |
| `scale` (1,000 long, quiesce wait) | 10 | 9,544 | 500 | 0 of 1,000 | 37 / 44 / 44 | 2.82 | 8,724 of 288,950 |
| `scale-carry` | 10 | 9,409 | 500 | 0 of 1,000 | 43 / 52 / 52 | 2.91 | 12,703 of 289,200 |
| `stall` (reader pauses 2.5 s, quiesce wait) | 12 | 46 | 24 | 0 of 512, 1 fallback | 39 / 68 / 1,002 | 0.34 | 781 of 10,262 |
| `stall-carry` | 12 | 52 | 24 | 0 of 469 | 0.89 / 1.09 / 1.09 | 0.30 | 0 of 10,262 |
| `faults` (9 injected faults) | 20 | 176 | 64 | 0 of 725 | 65 / 205 / 232 | 0.32 | 6,662 of 14,204 |
| `total-timeout` (3 s cap) | 15 | 36 | 0 | 0 of 4 | 0.58 / 24 / 31 | 0.28 | - |
| `udp-naive` (negative control) | 20 | 0 | 640 | 249 sessions re-created | 1.7 / 3.0 / 16 | 0.34 | 31 |
| `abort-shutdown` (negative control) | 6 | 24 | 0 | 8 of 8 | - | - | - |

`scale` is from a rerun after the harness's backend listen backlog was
raised: the first run lost 4 connections at startup, before any upgrade
(`hops=0`), to the default backlog. Every other row is from one full
run of `run-all.sh`.

Reading the table:

- **Transfer success**: every handover that was not sabotaged committed
  (50/50, 12/12, 10/10, 15/15). Under `faults`, 8 handovers aborted on
  purpose and their retries committed; one commit was presumed after
  the old generation died after `READY`. No connection was lost,
  duplicated or served by two generations.
- **Bytes**: zero lost, duplicated or reordered in both directions in
  every non-control scenario, with up to 178 MB of kernel in-queue bytes
  summed across parked sockets in one run (`main`), and 2.5 MB of
  userspace bytes carried in `harsh-carry`.
- **Accounting**: exactly one `END` row per connection in every run,
  counters equal to what both ends counted, `TRANSFER` rows in between,
  up to 50 hops for one connection. A handful of RST-ing clients per run
  never reached any generation (the kernel dropped them from the accept
  queue); `baseline` shows the same without an upgrade.
- **Timers**: in `total-timeout` the 4 capped connections ended
  `total_timeout` within 3.0 to 4.1 s of their start after 9 hops each
  (the check interval is 1 s).
- **Scale**: the pause grows by about 40 to 50 microseconds per
  connection (deregister, ioctls, re-register, task spawn): 43 ms for
  1,000 connections, with the protocol itself 3 ms.
- **UDP**: one source port per client at the backend in every
  non-control run. The losses in the table are all `UdpRcvbufErrors`
  (the slot socket's queue overflowing while nobody reads it), so they
  follow the pause, not the transfer.

### Races found, and how each was handled

| # | Race | Found how | Handled in the prototype | For 1.12.0 |
|---|---|---|---|---|
| 1 | Bytes read but not yet written (the userspace buffer) | `main`, `harsh`, `stall` | Quiesce wait (as written) or carry the held bytes | Carry the held bytes (AC #2 amended) |
| 2 | One handover batch waits for its slowest connection, and UDP reading stops for the whole TCP park | pause = slowest connection; `UdpRcvbufErrors` | Carrying makes the park immediate | Hand UDP in its own phase, do not stop slot reads for the TCP park; decide slot `SO_RCVBUF` |
| 3 | A connection reaching the quiesce point as the deadline fires | design, then `main` (a park at 1,002 ms, no fallback) | Compare-and-swap on a per-connection mode, one winner | Same |
| 4 | An accept in flight, a connection still connecting to its backend | design | Not eligible, drains on the old generation (up to 97 per run) | Same; stop accept by a flag, never by aborting the task (an aborted task drops an accepted socket) |
| 5 | Half-closed connections | churn connections close in both orders | Each direction's state (reading, closed) crosses | Same |
| 6 | FIN or RST arriving mid-handover | churn and RST clients | Nothing to do: the kernel holds it, the owner reads it after adoption | Same. A lost RST leaves a connection to its idle timeout, as without an upgrade |
| 7 | Kernel buffers and TCP retransmission state | in/out-queue bytes at park, `TcpRetransSegs` | Nothing to do: they are the socket, and the socket moves | Same |
| 8 | An fd left registered in the old generation's epoll | design (`epoll(7)`: an interest entry goes away only when every fd on the open file description is closed) | Deregister before sending (`into_std`) | Same. Not tested in the negative |
| 9 | State shared by both generations' descriptors: `O_NONBLOCK`, socket options | design | Both generations non-blocking | Never change file status flags or socket options on a socket being transferred |
| 10 | Readiness of a socket registered a moment ago | smoke run: 2 datagrams dropped | UDP sends by the syscall (`send`, `sendto`), not tokio's `try_send` | Lorica's `udp/session.rs` already sends with `sendmsg`; keep it that way on adopted sockets |
| 11 | Abort path shutting down shared sockets | `abort-shutdown`: 8 of 8 broken | The new generation only closes on abort | The engine's close (`shutdown(Both)`) must not run on an abort |
| 12 | Split ownership: who forwards when the handshake fails | `faults`: 9 points | `READY` / `COMMIT` / `COMMITTED`; O keeps its fds until `COMMITTED`; kill and reap before resuming; presumed commit on bare EOF | Same protocol |
| 13 | UDP: a datagram read by the new generation before its session arrives | `udp-naive` | New generation reads slot sockets only after adoption | Changes 12.11 D-e's overlap for transferring streams |
| 14 | UDP: ephemeral source port of the upstream socket | backend port sets | The upstream fd moves, the 4-tuple stays | Same |
| 15 | Timers: idle and total | `total-timeout` | Absolute `CLOCK_MONOTONIC` deadlines cross; the parked time counts as idle | Same; both generations must share the time namespace (they do under one unit) |
| 16 | Access-log row ownership | every run | `TRANSFER` event rows; the generation that ends the connection writes the one `END` row, with cumulative counters | Same; metrics must count only what each generation forwarded, the log row the cumulative total |
| 17 | Descriptors in flight | design | Not exercised (container limit far above 2,000 in flight) | `SCM_RIGHTS` in flight count against the sender's `RLIMIT_NOFILE` (`lorica-worker/src/stream_ctl.rs`); chunk with stop-and-wait as `stream_ctl` does |

### What remains unknown

- **Lorica's topology.** The prototype has one process per generation.
  In Lorica a connection lives in a worker, and today fds travel only
  supervisor to supervisor (`transfer.sock`) and supervisor to worker
  (`stream_ctl`); nothing carries a socket from a worker back out. The
  1.12.0 cycle has to choose between a direct old-worker-to-new-worker
  channel (slot `k` to worker `k`) and two hops through the supervisors,
  and the extra latency of either is unmeasured.
- **Cap permits and the bandwidth budget (AC #3).** The per-generation
  caps regions of Story 12.5 D-d and the token bucket were not
  prototyped. Re-registering a permit before releasing the old one is
  plain bookkeeping on paper; it has not run.
- **Other kernels and a real network.** Only WSL2's 6.18 kernel on
  loopback. `SCM_RIGHTS` and socket state are decades old and stable,
  but Debian 12 (6.1), Ubuntu 24.04 (6.8) and RHEL 9 (5.14) were not
  run, and no NIC offload, conntrack or second host was involved.
- **UDP at high datagram rates.** The pause is short but not zero; how
  much a slot socket must queue (and whether Lorica raises its
  `SO_RCVBUF`, which needs `net.core.rmem_max` or `CAP_NET_ADMIN` for
  `SO_RCVBUFFORCE`) is a decision, not a finding.
- **The Integration Verifications as written.** IV1 (an interactive SSH
  session) and IV2 (a DNS client) were not run; the spike used
  synthetic, checksummed streams, which are stricter on bytes but say
  nothing about a real client's timers.

## Constraints from the Phase 1 audit (2026-11-21)

Recorded in the PRD under "Story 12.16", "Constraints recorded by the
Phase 1 audit"; the 1.12.0 cycle starts from them with the outcome
above.

- **AC #3 holds for transferred connections only.** The caps regions
  are per generation, so the connections that drain keep the
  up-to-twice-the-caps window of the threat model's residual risk #19,
  and each upgrade gives every source a fresh rate burst. This answers
  half of "Cap permits and the bandwidth budget" above: the permit of a
  transferred connection moves, the drained remainder does not.
- **The worker-to-worker path above is a channel of its own**, not an
  extension of `stream_ctl`: length-prefixed, able to carry the held
  bytes of the no-quiesce park (outcome item 1) and fds out of a
  worker, with `stream_ctl`'s stop-and-wait flow control and its bound
  on fds in flight.

## Change Log

- 2026-11-18: Spike outcome recorded (Romain G.). Status: Spike done.
- 2026-11-21: Constraints from the Phase 1 audit recorded (A-M4 on AC
  #3, A-L4 on the transfer channel) (Romain G.).
