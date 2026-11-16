# Story 12.6: Protecting Stream Listeners

**Epic:** [Epic 12 - TCP and UDP Stream Proxying (v1.11.0 and v1.12.0)](../prd/epic-12-v1.11.0.md)
**Status:** InProgress
**Priority:** P0
**Author:** Romain G.
**Depends on:**
- Story 12.3 (InProgress): the TCP pipeline of its D-b (admit, then
  phase 2 pre-forwarding reads, connect, forward, end), the per-process
  `max_connections` cap of D-p (`lorica-stream/src/tcp/cap.rs`), the
  PROXY accept of D-k (the carried client becomes the address every
  later check judges), `StreamCounters` and the `ConnectionObserver` of
  D-r, the seams of D-a (`lorica-stream/src/seams.rs`).
- Story 12.5 (InProgress, Lots A to E landed): the stream-caps region
  (`lorica-shmem/src/stream_caps.rs`, `StreamCapsRegion`, `WorkerCaps`,
  `SessionPermit`, `SourceKey`, the GCRA rate cells), its two sides in
  `lorica-stream/src/caps.rs` (`NodeCapsRegions`, `CapsRegistry`), the
  UDP new-session path in `lorica-stream/src/udp/engine.rs`, and
  `udp_exposure_check(stream, has_source_allowlist)`. Its Lot F
  (supervisor and single-process region lifecycle), Lot G (the
  `udp_exposure_check` call in `Stream::validate`, the API), Lot H
  (docs) and Lot I (UDP e2e) are still open; each Lot below names the
  ordering.
- Story 12.4 (Draft): the ClientHello read and the terminate handshake
  run inside 12.3's phase 2 (its D-m), which this story's pending slot
  wraps; `Stream::no_sni_needs_acknowledgement(has_source_allowlist)`
  (its D-c), which this story calls with the real value.
- Story 12.8 (InProgress, Lot D landed): `RefusalLogLimiter` in
  `lorica/src/connection_filter.rs` (its D-j), which this story
  generalises and reuses.

**Blocks:** Story 12.9 (exports the refusal counters per stream and
reason, the pending gauge and `geoip_unknown`; its access log honours
the refusal-row limiter of D-j), 12.10 (the form for every field of
D-k, the per-link `max_active`, the "allowlist" state the D6 and D7
badges read), 12.12 (the security phase measures IV3 at scale), 12.15
(the "silent client after N ms" matcher calls `has_source_allowlist`;
detection reads run inside the pending slot of D-f).

---

As an operator,
I want the source-address, geography and rate controls Lorica applies to HTTP to protect my streams as well,
so that opening a layer-4 port does not open a hole in my perimeter.

## Problem

A stream listener today admits any source the kernel hands it. The
global connection filter, the IP blocklist and GeoIP run on the HTTP
listeners only; a TCP stream's only bound is `max_connections`, counted
per worker process, so a node with `W` workers holds `W x` the value;
a TCP connection reading a PROXY header (and, from 12.4, a ClientHello)
holds an fd and a buffer for up to 5 s with nothing bounding how many
do so at once; a UDP stream has per-source caps and rates but no source
filter, and the listen-address rule of D6 and the "no SNI" rule of D7
cannot be met with an allowlist because no allowlist exists. Refusals
are counted, but a UDP refusal before a region exists is not, and
nothing bounds the rate at which refusals reach the logs.

## Acceptance Criteria

1. **Allow and deny CIDRs per stream**, evaluated before any byte is forwarded (TCP, at accept) or any session is created (UDP), in addition to the global connection filter, which applies to stream listeners too.
2. **GeoIP country allow/deny per stream** through `lorica-geoip`, and the global IP blocklist applied to stream traffic.
3. **Concurrent connection caps** per source address, per stream and per backend, per node on the dedicated tables of Story 12.5 AC #5. The settings UI states that the existing global per-IP cap is per process while stream caps are per node.
4. **New-connection rate limit** per source address and per stream (TCP connections, UDP session creations), on local or asynchronously synced token buckets, never a synchronous cluster round trip per connection.
5. **Pre-forwarding caps.** Connections still reading a PROXY header, a ClientHello or, in Phase 2, detection bytes count against the per-source cap from accept, and a per-stream cap bounds how many may be pending at once.
6. **No refusal is uncounted.** Every refusal increments a counter per stream and reason. Refusal log rows are rate-limited per stream and reason, with a periodic "N refusals suppressed" row, so an attacker cannot choose the write rate of the log sinks.

## Integration Verification

- IV1: A source over its new-connection rate is refused at accept while another source on the same stream is served.
- IV2: A client from a denied country is refused on a TCP stream and on a UDP stream.
- IV3: 10,000 connections that never send a ClientHello leave the stream serving other clients and never exceed the pending cap.

## What the code does today

Read on `feat/v1.11.0` at `8a7e075a`.

- **TCP admit** (`lorica-stream/src/tcp/engine.rs`, `Inner::serve`):
  canonicalises the peer, counts `accept`, then
  `ConnectionCaps::try_acquire(stream_id, max_connections)`, a
  per-process `AtomicU32` per stream (`tcp/cap.rs`); a refusal ends
  `refused(connection_cap)` and still builds a `ConnectionRecord` that
  goes to the observer (`LogObserver`, debug). The module comment marks
  the spot: "Story 12.6's filters go here."
- **TCP phase 2** (`Inner::pipeline`): a trusted peer's PROXY header,
  bounded by `HEADER_READ_TIMEOUT` (5 s) from accept and 4 KiB. Nothing
  counts how many connections sit in it.
- **UDP new session** (`lorica-stream/src/udp/engine.rs`, the
  new-session path around `charge_rate` and `admit_session`): no region
  yet drops the datagram at debug, **uncounted**; then `charge_rate`
  (per-source datagram and byte GCRA, claiming a rate cell for a new
  source), then `admit_session` (stream total exact, per-source summed
  over per-worker shards, `source_cap + (W - 1)` at most), refusals
  `session_cap`, `source_session_cap`, `session_table_full`, counted, no
  record.
- **The region** (`lorica-shmem/src/stream_caps.rs`, layout version 1):
  one memfd per **UDP** stream, header, totals with per-worker
  attribution, rate cells (`key`, `datagram_tat`, `byte_tat`,
  `last_seen_ns`: 32 of 64 bytes used), per-worker session shards of
  16-byte cells (`key`, `sessions`). `release_worker(slot)` frees a dead
  worker's shard and attribution. `NodeCapsRegions` and `CapsRegistry`
  (`lorica-stream/src/caps.rs`) create, replace by `caps_gen` and retire
  regions; the supervisor lifecycle is 12.5 Lot F, not landed.
- **Global filter** (`lorica/src/connection_filter.rs`,
  `GlobalConnectionFilter`): CIDR allow/deny (`ConnectionFilterPolicy`
  in `lorica-config/src/connection_filter.rs`, deny wins, a non-empty
  allow list must match) and the Story 8.9 per-IP cap, **per process**
  (`DashMap<IpAddr, AtomicU32>`). Called by the pingora accept loop of
  the HTTP listeners only; no stream code reads it.
- **IP blocklist** (`lorica-waf/src/ip_blocklist.rs`, `IpBlocklist::
  is_blocked`) and the global WAF whitelist that exempts from it
  (`lorica/src/proxy_wiring.rs`, `check_ban_and_blocklist`): HTTP only.
- **GeoIP** (`lorica-geoip`, `GeoIpResolver::lookup_country`, held per
  process by `LoricaProxy.geoip_resolver`): per-route `GeoIpConfig`
  (`lorica-config/src/models/route.rs`, `blocks(country)`); an unknown
  country passes. Country-code validation lives in
  `lorica-api/src/routes/crud.rs` (`validate_geoip`), so the config
  import and cluster paths do not run it for anything but routes.
- **Refusal log limiter** (`lorica/src/connection_filter.rs`,
  `RefusalLogLimiter`, `REFUSAL_LOG_WINDOW` = 10 s): keyed by
  `(HttpListener, ProxyHeaderOutcome)`, in the binary crate, so
  `lorica-stream` cannot use it as it stands.
- **The interim calls**: `udp_exposure_check(stream, false)` (12.5 D-k,
  wired by its Lot G) and `no_sni_needs_acknowledgement(false)` (12.4
  D-c, not yet written). Both stories state that no release carries the
  `false`.
- **Settings UI** (`lorica-dashboard/frontend/src/components/
  settings-tabs/NetworkTab.svelte`): the "Connection limit per IP" hint
  does not say it is per process, nor that streams do not use it.

## Decisions taken in this story

### D-a. One admission sequence, evaluated before any byte or any table write

Every check runs in this order, cheapest and table-free first, so a
refused source never claims a rate cell or a shard cell (the
random-source table fill of 12.5 D-d stays bounded to sources that pass
the filters):

| # | Check | Refusal (`StreamRefusal`) | Writes shared state |
|---|---|---|---|
| 1 | The stream's region is present | `caps_unavailable` | no |
| 2 | Global connection filter (CIDR allow/deny) | `connection_filter` | no |
| 3 | Global IP blocklist, unless the global WAF whitelist holds the client | `ip_blocklist` | no |
| 4 | Stream deny CIDRs, then stream allow CIDRs | `source_denied` | no |
| 5 | Stream GeoIP | `geoip` | no |
| 6 | Per-stream open rate, then per-source open rate | `open_rate`, `source_open_rate` | GCRA cells |
| 7 | Per-stream cap, then per-source cap | `connection_cap` / `session_cap`, `source_connection_cap` / `source_session_cap` | totals, shard |
| 8 | (TCP, when phase 2 has work) pending cap, then per-source pending share | `pending_cap`, `source_pending_cap` | pending totals, shard |

A probe window full in the rate table or a shard refuses with
`connection_table_full` (TCP) or the existing `session_table_full`
(UDP), this stream only.

- **TCP**: steps 1 to 7 at 12.3 D-b step 1, before the socket is read;
  step 8 when phase 2 starts. A refusal closes the socket as 12.3 closes
  (shutdown, drop).
- **UDP**: steps 1 to 7 on the new-session path, before `charge_rate`
  (steps 1 to 5) and around it (step 6, D-g). A datagram of a live
  session is never re-filtered: it was admitted with its session.
- **Order cost:** the open rate is charged before the caps, so a
  connection refused by a cap has spent a token. Charging after would
  let a source at its cap probe for free; HAProxy's `tcp-request
  connection` rules have the same order.
- **Live connections keep running when a filter changes** (Resolved 1):
  stream CIDRs, GeoIP, the global filter, the blocklist and the rates
  apply to connections and sessions admitted after the change, as the
  HTTP connection filter does. *Why:* re-judging live connections on
  every `table_changed` would need a new end reason and a pass over the
  tracker on each edit, and would make a blocklist refresh cut
  connections on every node at once; the HTTP plane does not do it
  either, so both planes behave alike. *Cost:* adding an attacker's
  address to a deny list does not end the connection or UDP session it
  already holds; the operator must disable and re-enable the stream (or
  wait for the idle or total timeout) to cut it. `docs/streams.md` says
  so plainly (Lot H).

### D-b. Which address is judged: the socket peer, or the client a trusted PROXY header carries

12.3 D-k makes the carried client the address for "12.6's filters".
At accept the header is not read yet, so:

- **Untrusted peer, or PROXY accept off**: steps 1 to 8 on the socket
  peer, at accept.
- **Trusted PROXY peer** (inside `proxy_protocol_trusted_cidrs`): at
  accept only the per-stream checks run (1, the stream open rate of 6,
  the stream cap of 7, the stream pending cap of 8); the peer is a load
  balancer funnelling many clients and is not judged, rated or capped
  as one source. Once the header is accepted, the source checks run on
  the carried client: 2 to 5, the per-source rate of 6, the per-source
  cap of 7 and the per-source pending share of 8, in that order, still
  before any byte is forwarded. `LOCAL` and `AF_UNSPEC` headers carry no
  client: the source checks run on the socket peer, as 12.8 D-e keeps
  the socket addresses for them.
- The region API therefore splits the stream part of an admission from
  the source part (D-e): `admit_stream` at accept, `admit_source` on
  the permit when the source is known.

This matches the HTTP listeners since 12.8, which run the connection
filter on the carried client.

### D-c. Allow and deny CIDRs per stream (AC #1)

- **Fields** `source_allow_cidrs: Vec<String>` and
  `source_deny_cidrs: Vec<String>`, default empty, at most 1,024
  entries each. Every entry goes through `lorica_config::
  connection_filter::validate_cidr_list` (a bare IP is a host prefix);
  `0.0.0.0/0` and `::/0` are refused in both lists (an allow /0 is no
  allowlist, a deny /0 is `enabled = false`), with the messages 12.8
  D-d uses for its trust list.
- **Semantics** are `ConnectionFilterPolicy`'s, built once per stream in
  `table_changed`, never per connection: a deny hit refuses; a non-empty
  allow list refuses a miss. IPv4-mapped peers are canonicalised first.
- **Replicated** with the stream, as `proxy_protocol_trusted_cidrs` is
  (12.3 D-k): a stream is a replicated perimeter object.
- **`Stream::has_source_allowlist()`**: true when `source_allow_cidrs`
  is non-empty. The one definition the D6 and D7 rules read (D-l). A
  GeoIP allowlist does not count (a country is not an address range, and
  an unknown country passes, D-d), nor does the PROXY trust list (it
  names who may speak for a client, not which clients may connect).
  No minimum prefix length (Resolved 6): `0.0.0.0/1` plus
  `128.0.0.0/1` (or the two `::/1` halves) passes the rule while
  admitting every address. That is accepted as a deliberate operator
  act, visible in the stream's own review and in its listing; the rule
  stops an accidental open relay, not an operator who chooses one.

### D-d. GeoIP per stream, the global filter and the blocklist (AC #1, #2)

- **Field** `geoip: Option<GeoIpConfig>`, the route type unchanged
  (`mode` allowlist or denylist, `countries`). Its validation moves from
  `lorica-api/src/routes/crud.rs` into `lorica-config` as
  `GeoIpConfig::normalised(&self) -> Result<GeoIpConfig, String>` (two
  ASCII letters, uppercased, deduplicated, at most 300, an empty
  allowlist refused), called by the route handlers and by
  `Stream::validate`, so the import and replication paths validate a
  stream's GeoIP as the API does. Route behaviour and messages are
  unchanged; the route tests prove it.
- **Unknown country passes**, as on routes (a DB miss, an unlisted
  range, or no database loaded on this node): one rule for both planes.
  Counted per stream as `geoip_unknown` (a counter, not a refusal), so
  an allowlist stream on a node without a database is visible.
  `docs/streams.md` says that a country allowlist is not an address
  allowlist and does not satisfy D6 or D7.
- **The global connection filter** applies to every stream listener:
  the same `ConnectionFilterPolicy` snapshot the HTTP accept loop reads
  in the same process, so a reload reaches both on the next accept.
- **The Story 8.9 per-IP cap does not apply to streams.** It is per
  process and keyed per address; streams have per-node per-source caps
  keyed per `SourceKey` (D-e). Applying both would make a TCP client's
  limit depend on which worker accepted it. The settings UI says so
  (D-k).
- **The global IP blocklist** applies to stream traffic when enabled,
  with the HTTP exemption: a client inside the global WAF whitelist is
  not checked against it. One answer per address on both planes.
- **The WAF auto-ban list does not apply to streams** (Resolved 2).
  *Why:* a ban is earned by HTTP behaviour (WAF rule hits, rate-limit
  violations on routes); applying it to a TCP or UDP stream would cut a
  database or DNS client for something it did on a website, possibly
  through a shared NAT address, and the AC names the blocklist only.
  *Cost:* an address banned for attacking the HTTP listeners can still
  open stream connections; an operator who wants it off the streams
  too adds it to the stream's `source_deny_cidrs` or the global
  connection filter. `docs/streams.md` says so plainly (Lot H).
- **How the engine reaches them: a fourth seam.** `lorica-stream` does
  not depend on `lorica-waf` or `lorica-geoip`. `seams.rs` gains

  ```rust
  pub trait SourceGate: Send + Sync {
      /// Steps 2 and 3 of D-a for `client`, canonical.
      fn global(&self, client: IpAddr) -> Option<StreamRefusal>;
      /// The ISO 3166-1 alpha-2 code of `client`, uppercase, `None` when unknown.
      fn country(&self, client: IpAddr) -> Option<[u8; 2]>;
  }
  ```

  synchronous because the UDP receive path is (12.5 D-c). `lorica`
  implements it in `lorica/src/stream_engine.rs` over the process's
  `GlobalConnectionFilter::snapshot()`, `waf_engine.ip_blocklist()`,
  the whitelist from the proxy config, and `geoip_resolver`, the same
  instances HTTP reads, so a hot reload of any of them reaches streams
  with no stream message. `country` is called only for a stream with a
  `geoip` config.

### D-e. The stream-caps region becomes protocol-neutral: layout version 2

12.5 D-d built one region per UDP stream and said 12.6 "may bump
`STREAM_CAPS_LAYOUT_VERSION` to add TCP and per-backend counters". It
does, and keeps the type: `StreamCapsRegion` serves both protocols,
one region per stream, TCP included.

| Part | Version 1 | Version 2 |
|---|---|---|
| Header | magic, version, W, hash key, `rate_slots`, `shard_slots`, `caps_gen` | adds `backend_slots` |
| Totals | `total`, `per_worker[W]` | unchanged (TCP connections or UDP sessions), plus `pending`, `pending_per_worker[W]`, and one stream GCRA cell (`open_tat`) on its own cache line |
| Rate cell (64 B) | `key`, `datagram_tat`, `byte_tat`, `last_seen_ns` | adds `open_tat` (per-source open rate), same 64 bytes |
| Source shard cell | 16 B: `key`, `sessions` | 32 B: `key`, `active`, `pending`, padding |
| Backend shards | none | W shards of `backend_slots` 16-byte cells: `key` (hash of the backend id), `active` |

- **Sizes.** TCP: `rate_slots = next_pow2(max(4 x max_connections,
  1,024))`, `shard_slots = next_pow2(max(2 x max_connections, 256))`;
  UDP unchanged from `udp.max_sessions`. `backend_slots =
  next_pow2(max(2 x links, 16))`; a link count crossing it replaces the
  region with the next `caps_gen`, through the replacement 12.5 already
  has. At the TCP default (1,024 connections) and 8 workers: 256 KiB of
  rate cells and 512 KiB of shards; `docs/streams.md` gives the formula.
- **Exactness.** The stream total and the pending total are exact
  (`fetch_add`, back off past the cap), attributed per worker so
  `release_worker` subtracts a dead worker's share of both. Per-source
  active and pending counts and per-backend counts live in per-worker
  shards, summed over W at each check, with 12.5's bound: at most
  `cap + (W - 1)` on the node, exact with one process. A held cell is
  never evicted; `evict_rates` frees a rate cell only when its three
  buckets are full again and no shard holds its source.
- **API, additive first.** `WorkerCaps::admit_stream(stream_cap,
  pending: bool, pending_cap) -> Result<StreamPermit, CapRefusal>` and
  `StreamPermit::admit_source(source, source_cap, source_pending_cap)`;
  `StreamPermit::end_pending()` when phase 2 ends;
  `WorkerCaps::claim_backend(backend_key, cap) -> Option<BackendSlot>`;
  `StreamCapsRegion::charge_open(source: Option<SourceKey>, limits,
  now_ns) -> OpenVerdict`. `admit_session` stays as a thin wrapper
  until Lot C moves the UDP path, then is removed. `CapRefusal` gains
  `PendingCap`, `SourcePendingCap`.
- **Regions per TCP stream.** `NodeCapsRegions` creates one for every
  stream, sized from `max_connections` on TCP; the `caps` message, the
  respawn order (release, `caps`, `attach`) and the 1 s eviction tick of
  12.5 Lot F cover TCP with no new message.
- **Version 2 has no upgrade consequence**: regions are never shared
  across process generations (12.5 D-d). During a hot upgrade's drain
  the old and new generations each count their own connections, so a
  stream may briefly hold up to twice its caps on the node; Story 12.11
  documents it beside the drain.

### D-f. `max_connections` becomes per node, the pending cap, the per-source cap (AC #3, #5)

- **`max_connections` per node, the same field (12.3 Resolved 1).**
  The region's exact stream total replaces `tcp::cap::ConnectionCaps`,
  which is deleted; the refusal stays `connection_cap`. No rename, no
  migration; the doc comment, the `openapi.yaml` description and
  `docs/streams.md` change from "per worker process until Story 12.6,
  per node from then on" to "per node". The fd budget is untouched:
  one worker may still hold the whole cap, so `held_fds` keeps
  `ceiling: max_connections` per process.
- **Per-source cap, TCP**: new field `source_max_connections:
  Option<u32>`, range 1 to 65,535, **default none** (bounded by
  `max_connections` only). TCP sources are not spoofable and an
  application server's pool commonly holds hundreds of connections to
  one database; a default would break that silently. Pending
  connections count against it from accept (AC #5). UDP keeps
  `udp.source_session_cap`; `source_max_connections` holds its default
  on UDP (the 12.3 D-q rule, through `TCP_ENGINE_FIELDS`). Open
  Resolved 5.
- **Pending cap**: new field `max_pending_connections: u32`, **default
  256**, range 1 to 65,535, effective `min(max_pending_connections,
  max_connections)`. A connection takes a pending slot when phase 2 has
  work (a trusted PROXY header, a ClientHello from 12.4, detection from
  12.15) and gives it back when phase 2 ends (backend chosen) or the
  connection ends; a plain TCP stream never holds one. The slot wraps
  12.3's phase 2 scope as one unit, PROXY read to backend choice, the
  12.4 terminate handshake included (12.4 D-m). TCP-only; holds its
  default on UDP.
- **Per-source pending share, derived**: a source may hold at most
  `max(1, effective_pending / 8)` pending connections (32 at the
  default). Without it one source fills the pending cap and every other
  TLS client is refused until its reads time out, which is IV3's
  failure; with it, filling the cap takes eight sources. A constant
  (`PENDING_SOURCE_SHARE_DIVISOR = 8`) rather than a field. Open
  Resolved 4.
- **NFR2.** The pending phase per stream per node is bounded by
  `effective_pending` fds and `effective_pending x` the largest phase-2
  buffer (17 KiB for a ClientHello, 12.4 D-b): 4.3 MiB at the default.
  `docs/streams.md` states both.

### D-g. Open rates per source and per stream (AC #4)

- **Fields** `source_open_rate: Option<u32>` and `open_rate:
  Option<u32>`, openings per second (TCP connections admitted, UDP
  sessions created), range 1 to 1,000,000, **default none** on both
  protocols. Burst: one second of rate (`RATE_BURST_NS`).
- **Off by default**, because the right value depends on the protocol:
  a DNS stream opens a session per query (12.5 IV2 answers every query
  at the capacity formula's rate with defaults) and any default low
  enough to matter would refuse it. D6's UDP bounds stay on by default.
  Resolved 7.
- **Where the buckets live**: GCRA arrival times in the stream's region
  (D-e), advanced by CAS against `CLOCK_MONOTONIC`, shared by every
  worker of the node. That is AC #4's "local" bucket: exact across the
  node's workers, no message, no cluster round trip. Rates and caps are
  **per node**: a stream placed on three nodes admits up to three times
  each, which `docs/streams.md` states beside the caps.
- **UDP**: `charge_open` and the existing `charge_rate` share the rate
  cell; the source open rate is charged with the first datagram of a new
  session, in the same CAS sequence, and a datagram refused on either
  is charged on neither, as 12.5 does for its two rates.
- **A region replacement** (`caps_gen`) starts with full buckets: one
  burst more after a cap change. Stated, not worked around.

### D-h. Per-backend caps: a property of the link (AC #3)

- **Field** `StreamBackend.max_active: Option<u32>`, range 1 to 65,535,
  default none: the most connections (TCP) or sessions (UDP) this stream
  holds to this backend on one node. On the link, not on `Backend`: a
  backend is shared with HTTP routes (D2), which would not count against
  it, so a cap on the backend row would promise more than it bounds.
  Resolved 8.
- **Behaviour**: nginx's `max_conns`. A backend at its cap leaves the
  candidate set for this connection before selection (a consistent-hash
  client moves, as nginx does); a race lost at `claim_backend` removes
  it and selects again, not counted as a connect attempt and not
  reported to the breaker. No candidate left: `refused(backend_cap)`.
  The slot is held from the claim to the end of the connection or
  session, released on a failed attempt before the retry.
- **API**: `backend_max_active: {backend_id: n}` beside `backend_ids`
  and `backup_backend_ids`, an id outside both lists refused.

### D-i. Refusal reasons and counters (AC #6)

`StreamRefusal` gains, in this order after the existing variants:
`connection_filter`, `ip_blocklist`, `source_denied`, `geoip`,
`open_rate`, `source_open_rate`, `source_connection_cap`, `pending_cap`,
`source_pending_cap`, `backend_cap`, `connection_table_full`,
`caps_unavailable`. Words from `as_str` / `VARIANTS`, never typed out.

- Every refusal increments `refused[reason]` of its stream in
  `StreamCounters` (12.3 D-r). `caps_unavailable` closes 12.5's one
  uncounted path (a datagram before the region arrived); TCP uses it
  too now that it needs a region.
- New per-stream values: `pending` (gauge, this process's connections
  in phase 2) and `geoip_unknown` (counter). The per-node pending total
  is readable from the region, as the session total is.
- `openapi.yaml` publishes the refusal enum from the Rust enum where the
  contract test checks it.

### D-j. The refusal log: one row per stream and reason per window, then a count (AC #6)

- **One limiter, two users.** 12.8's `RefusalLogLimiter` becomes
  generic over its key, `RefusalLogLimiter<K: Hash + Eq + Copy>`, and
  moves to `lorica_stream::refusal_log` with `REFUSAL_LOG_WINDOW`
  (10 s) and the `Write { suppressed }` / `Suppress { first,
  window_ends }` decisions unchanged. `lorica/src/connection_filter.rs`
  keys it by `(HttpListener, ProxyHeaderOutcome)` as today; the
  streams key it by `(stream index, StreamRefusal)`, the index being
  the stream's position in the current table so the key stays `Copy`.
  12.8's tests move with the type and still pass. Resolved 3.
- **Rows**: a `warn` line naming the stream id and name, the protocol,
  the reason and the judged client address (D-b); the first held-back
  refusal of a window spawns one task on the stream runtime that writes
  "N refusals suppressed" (stream, reason, count) when the window
  closes, with 12.8's once-only handover.
- **Per process.** Each worker has its own windows, so a node writes at
  most `W` rows per stream and reason per 10 s, plus `W` count rows.
  Bounded and independent of the attacker's rate; a shared-memory
  limiter would buy a factor of W for a cross-process lock.
- **Refused TCP connections no longer hand a record to the observer.**
  12.3 built a `ConnectionRecord` for a refused connection; that record
  is what Story 12.9's access log writes, so it would give an attacker
  the log's write rate back. A connection that ends `refused(_)` is
  counted (`refused` and `ended`) and goes through the limiter; no
  record. TCP now matches UDP (12.5 records none). Pre-forwarding ends
  that are not refusals (`proxy_header_invalid`, 12.4's
  `clienthello_timeout`, `invalid_client_hello`) keep their record;
  whether 12.9 limits their access-log rows with this type is handed to
  it.
- The map is pruned in `table_changed` with the counters.

### D-k. The settings UI and the stream form (AC #3)

- **Settings, Network tab**: the "Connection limit per IP" hint gains:
  "Counted per worker process: with N workers a client can hold up to N
  times this value. Stream listeners do not use this limit; each stream
  has its own per-node caps." `NetworkTab.test.ts` asserts the text.
- **The stream form** (every field of D-c, D-d, D-f, D-g and the link's
  `max_active`) is Story 12.10 AC #1, which labels every cap "per node".
  This story delivers the API and the documentation it reads.

### D-l. The listen-address rule and the D7 acknowledgement, completed

- `Stream::validate` calls `udp_exposure_check(self,
  self.has_source_allowlist())` (12.5 D-k) and
  `no_sni_needs_acknowledgement(self.has_source_allowlist())` (12.4
  D-c) instead of `false`. Both messages already name the allowlist as
  a remedy; they now name the field, `source_allow_cidrs`.
- **Removing the allowlist later** from a stream that relies on it is
  refused by the same validation, on every write path (API, import,
  replication apply), with the rule's message.
- **Story 12.15** calls `has_source_allowlist()` for its "silent client"
  matcher; nothing else defines an allowlist.
- **No release carries the interim**: Lot F lands before the 1.11.0
  bump, after 12.4 Lot C and 12.5 Lot G.

### D-m. The new fields, the migration, and every surface they reach

**`Stream`** gains:

| Field | Type | Default | Protocols |
|---|---|---|---|
| `source_allow_cidrs` | `Vec<String>` | empty | both |
| `source_deny_cidrs` | `Vec<String>` | empty | both |
| `geoip` | `Option<GeoIpConfig>` | none | both |
| `source_max_connections` | `Option<u32>` | none | TCP (default on UDP) |
| `max_pending_connections` | `u32` | 256 | TCP (default on UDP) |
| `source_open_rate` | `Option<u32>` | none | both |
| `open_rate` | `Option<u32>` | none | both |

and `StreamBackend` gains `max_active: Option<u32>` (none). Ranges as
associated constants beside 12.3's, enforced by `Stream::validate`.

- **One migration at the next free number of `MIGRATIONS`** when Lot B
  commits (76 is the last entry at `8a7e075a`; 12.4 and 12.5 may take
  the next ones first), recorded in the Completion Notes.
  `add_column_if_absent` per column: the two lists as JSON `TEXT NOT
  NULL DEFAULT '[]'`, `geoip` as nullable JSON `TEXT`,
  `max_pending_connections INTEGER NOT NULL DEFAULT 256`, the options as
  nullable `INTEGER`, `stream_backends.max_active` nullable `INTEGER`.
  Idempotent; a test runs it twice. `STREAM_COLUMNS` extended.
- **Rollback to 1.10.6** is safe for 12.1 D-2's reason (1.10.6 never
  names these tables).
- **Canonical config** (format 3, 12.1 D-3): each field
  `#[serde(default)]`; `CANONICAL_SHAPE_DIGEST` updated deliberately;
  `compute_diff`, export and import carry them.
- **Management API**: create and update requests take every field
  (optional), `StreamResponse` returns them field by field;
  `STREAM_WITHHELD_FIELDS` stays empty (an allowlist is what a reviewer
  must see). 400 for validation. `openapi.yaml` gains the fields,
  ranges, the link map and the refusal enum.
- **Automation and MCP**: unchanged here. Stream writes stay on the
  management plane (D9); the `streams:read` view and MCP read tools are
  Story 12.10's, which publish these fields with the rest.

## Tasks

Lots with hard file allowlists. A Lot touches only its files; two Lots
that share a file are sequential, never parallel, and say so. Every Lot
that runs cargo ends on a tree that passes the gate chain CI runs
(`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets
--features lorica/otel -- -D warnings` under `CARGO_BUILD_WARNINGS=deny`,
the CI `cargo test` lines, `cargo audit`), through Docker on Linux. No
agent runs `git checkout`, `git restore`, `git stash` or `git reset` in
the shared tree.

**Order.** A and G first, in parallel. B after any open Lot editing
`lorica-config/src/models/stream.rs` (12.4 Lot C, 12.5 Lot G), one at a
time. C after A and B, and sequential with 12.4 Lot D in either order
(`tcp/engine.rs`, `tcp/connect.rs`, `counters.rs`, `handler.rs`). D
after C and 12.5 Lot F, sequential with 12.4 Lot E. E after B,
sequential with 12.5 Lot G and 12.4 Lot F (`streams.rs`,
`openapi.yaml`). F after B, 12.4 Lot C and 12.5 Lot G (folded into B
when both have landed before B starts). H after C, D, E, F, and after
12.4 Lot G and 12.5 Lot H (same documents). I after D, E, F, 12.3 Lot
G, 12.4 Lot H and 12.5 Lot I (same compose profile and runner image).

### Lot A: the region, layout version 2 (`lorica-shmem`) - cargo

Allowlist: `lorica-shmem/src/stream_caps.rs`, `lorica-shmem/src/lib.rs`.
Depends on: nothing (12.5 Lot B landed).

- [x] Layout version 2 of D-e: `backend_slots`, pending totals with
      per-worker attribution, the stream `open_tat` cell, `open_tat` in
      the rate cell, 32-byte source shard cells, backend shards;
      `STREAM_CAPS_LAYOUT_VERSION = 2`; `layout_for` takes the link
      count.
- [x] `admit_stream`, `admit_source`, `end_pending`, `claim_backend`,
      `charge_open`, `CapRefusal::{PendingCap, SourcePendingCap}`;
      `admit_session` kept as a wrapper so the UDP engine compiles
      unchanged.
- [x] `release_worker` frees pending attribution and backend shards;
      `evict_rates` keeps a cell whose `open_tat` bucket is not full.
- [x] Tests: exact stream and pending totals under N threads; the
      `cap + (W - 1)` bound for source, source pending and backend
      counts with W simulated slots; a refusal undoes everything counted
      before it; `admit_source` after `admit_stream` on a trusted path;
      no held cell evicted; dead-worker release; version mismatch
      refused on `open`.

### Lot B: model, schema, validation (`lorica-config`) - cargo

Allowlist: `lorica-config/src/models/stream.rs`,
`lorica-config/src/models/route.rs` (`GeoIpConfig::normalised` only),
`lorica-config/src/models/mod.rs`, `lorica-config/src/store/streams.rs`,
`lorica-config/src/store/mod.rs` (the migration only),
`lorica-config/src/canonical.rs`, `lorica-config/src/diff.rs`,
`lorica-config/src/export.rs`, `lorica-config/src/import.rs`,
`lorica-api/src/routes/crud.rs` (`validate_geoip` delegating to
`normalised`, messages unchanged).
Depends on: 12.4 Lot C and 12.5 Lot G if open (same `stream.rs`).

- [x] The fields of D-m with ranges and defaults; `max_active` on
      `StreamBackend`; `TCP_ENGINE_FIELDS` entries for the two TCP-only
      fields.
- [x] Validation: CIDR lists (D-c), `/0` refused in both, 1,024 cap;
      `geoip` through `normalised`; ranges; `max_active` keys.
- [x] `has_source_allowlist()`; the `StreamRefusal` variants of D-i;
      `max_connections` doc comment says "per node".
- [x] Migration, `STREAM_COLUMNS`, canonical digest, diff, export,
      import.
- [x] Tests: each refusal message; defaults on create; the migration
      twice; a canonical round trip; route GeoIP behaviour unchanged.

### Lot C: admission in the engines (`lorica-stream`) - cargo

Allowlist: `lorica-stream/src/seams.rs`, `lorica-stream/src/caps.rs`,
`lorica-stream/src/refusal_log.rs` (new),
`lorica-stream/src/admission.rs` (new: the D-a sequence shared by both
engines), `lorica-stream/src/tcp/engine.rs`, `lorica-stream/src/tcp/cap.rs`
(the cap removed, `held_fds` kept), `lorica-stream/src/tcp/connect.rs`
(backend caps in candidate selection), `lorica-stream/src/tcp/mod.rs`,
`lorica-stream/src/udp/engine.rs`, `lorica-stream/src/counters.rs`,
`lorica-stream/src/handler.rs`, `lorica-stream/src/lib.rs`,
`lorica-stream/tests/tcp_engine.rs`, `lorica-stream/tests/udp_engine.rs`,
`lorica-stream/tests/admission.rs` (new), `lorica-shmem/src/stream_caps.rs`
(removing the `admit_session` wrapper only).
Depends on: A, B; sequential with 12.4 Lot D.

- [x] `SourceGate` seam (D-d); test fake in the tests.
- [x] `admission.rs`: the D-a order, per-stream policies built in
      `table_changed`, the D-b split for trusted PROXY peers.
- [x] `NodeCapsRegions` creates TCP regions from `max_connections`
      and passes the link count; `CapsRegistry` unchanged otherwise.
- [x] TCP: admit at D-b step 1, pending slot around phase 2, source
      checks after an accepted header, backend claims, refused
      connections without a record (D-j).
- [x] UDP: steps 1 to 5 before `charge_rate`, open rates, `caps_unavailable`
      counted, backend claims; then the `admit_session` wrapper is
      removed from `lorica-shmem/src/stream_caps.rs` (that removal is
      the only edit this Lot makes there; Lot A has landed before).
- [x] Generic `RefusalLogLimiter<K>` and its tests (12.8's, moved);
      the stream rows and the suppressed task.
- [x] Counters: refusals, `pending`, `geoip_unknown`.
- [x] Tests: each refusal reason on both protocols where it applies;
      trusted PROXY peer judged on the carried client; a source at its
      pending share refused while another is admitted; the pending
      total never past its cap under 2,000 concurrent silent
      connections; backend at cap skipped, all at cap `backend_cap`;
      one log row and one suppressed row for 1,000 refusals in a
      window.

### Lot D: wiring in the binary (`lorica`) - cargo

Allowlist: `lorica/src/stream_engine.rs`,
`lorica/src/startup/stream_plane.rs`, `lorica/src/startup/worker.rs`,
`lorica/src/startup/single.rs`, `lorica/src/startup/supervisor.rs`,
`lorica/src/connection_filter.rs` (the limiter switched to
`lorica_stream::refusal_log`, behaviour unchanged).
Depends on: C, 12.5 Lot F; sequential with 12.4 Lot E.

- [ ] `StreamSourceGate` over the process's filter, blocklist,
      whitelist and GeoIP resolver, handed to both engines.
- [ ] Regions for TCP streams on first bind, replaced on a size or link
      count change, through 12.5 Lot F's lifecycle.
- [ ] 12.8's limiter tests still green from their new home; the HTTP
      PROXY refusal log unchanged.
- [ ] Tests against the fake transport: a TCP stream's `caps` precedes
      its `attach`; a filter reload reaches the next stream accept.

### Lot E: API surfaces (`lorica-api`) - cargo

Allowlist: `lorica-api/src/streams.rs`, `lorica-api/src/streams/tests.rs`,
`lorica-api/openapi.yaml`.
Depends on: B; sequential with 12.5 Lot G and 12.4 Lot F.

- [ ] Requests and `StreamResponse` with every D-m field;
      `backend_max_active`; the view key-set test covers them.
- [ ] `openapi.yaml`: fields, ranges, the link map, the refusal enum,
      `max_connections` described "per node"; contract test green.

### Lot F: the allowlist hook-ups (`lorica-config`) - cargo

Allowlist: `lorica-config/src/models/stream.rs` (the two calls in
`Stream::validate` and their tests only).
Depends on: B, 12.4 Lot C, 12.5 Lot G.

- [x] `udp_exposure_check(self, self.has_source_allowlist())`.
- [x] `no_sni_needs_acknowledgement(self.has_source_allowlist())`.
- [x] Tests: an exposed UDP stream with an allowlist and no explicit
      cap passes; a `no_sni` stream with an allowlist and no
      acknowledgement passes; removing the allowlist from either is
      refused with the rule's message.

### Lot G: the settings hint - frontend gates

Allowlist: `lorica-dashboard/frontend/src/components/settings-tabs/NetworkTab.svelte`
(the hint only), `lorica-dashboard/frontend/src/components/settings-tabs/NetworkTab.test.ts`.
Depends on: nothing.

- [ ] The D-k text; a test asserting it. `pnpm` gates clean
      (`tsc`, `svelte-check`, `eslint`, `vitest`).

### Lot H: documentation - no cargo

Allowlist: `docs/streams.md` (a "Protecting a stream" section, and every
"per worker process until Story 12.6" sentence), `docs/security/threat-model.md`,
`docs/architecture/worker-shared-state.md` (region version 2),
`docs/BUMP-CHECKLIST.md` and `.claude/skills/bump-version/bump-checklist.md`
(the region version line), `CHANGELOG.md`.
Depends on: C, D, E, F; after 12.4 Lot G and 12.5 Lot H.

- [ ] `docs/streams.md`: the D-a order; which address is judged (D-b);
      per node, not per cluster; the defaults and why rates are off;
      the pending bound and its memory; the GeoIP unknown rule; what
      counts as an allowlist; the Story 8.9 cap does not apply.
- [ ] `docs/streams.md`, stated plainly where an operator looks for
      them, because both contradict what an operator will expect:
      "A filter change does not end connections already open: disable
      and re-enable the stream to cut them" (D-a), and "The WAF
      auto-ban list does not apply to streams: an address banned on the
      HTTP listeners can still connect to a stream; deny it on the
      stream or in the global connection filter" (D-d).
- [ ] Threat model: slow ClientHello and slow PROXY header (pending
      cap and per-source share), log amplification (D-j), random-source
      table fill (filters before tables, open rates), handshake CPU
      (12.4's pointer to the open rates).
- [ ] CHANGELOG under Added and Security.

### Lot I: end-to-end, IV1 to IV3 - Docker e2e

Allowlist: `tests-e2e-docker/test-runner/run-streams-protect.sh` (new,
LF), `tests-e2e-docker/test-runner/protect_tools.py` (new, LF, standard
library only: a silent-connection holder, a TLS client, a UDP query
client), `tests-e2e-docker/test-runner/Dockerfile` (the `COPY` and
`chmod` lines), `tests-e2e-docker/docker-compose.yml` (the `streams`
profile and one network), `tests-e2e-docker/run.sh` (one call).
Depends on: D, E, F, 12.3 Lot G, 12.4 Lot H, 12.5 Lot I. The machine to
itself, orphan containers torn down first.

- [ ] A second compose network `streams-geo`, subnet `214.78.120.0/24`,
      the runner at `214.78.120.5` (US in `GeoIP2-Country-Test.mmdb`,
      the value `run-geoip-smoke.sh` already relies on), Lorica attached
      to both networks, `geoip_db_path` set as the GeoIP smoke does.
- [ ] IV1: a TCP echo stream with `source_open_rate = 5`; 30 connects
      in one second from `214.78.120.5` are partly refused (closed
      before any echo); a connect from the runner's address on the
      default network at the same time echoes. The `source_open_rate`
      refusal row appears once in the log, then a suppressed row.
- [ ] IV2: `geoip` denylist `US` on a TCP stream and a UDP stream; from
      `214.78.120.5` the TCP connect closes with no echo and the UDP
      query gets no answer; from the default network both are served;
      the `geoip` refusal rows appear in the log.
- [ ] IV3: a TLS passthrough stream with defaults; 10,000 silent
      connections from `214.78.120.5`, held open: a TLS client from the
      default network completes its handshake throughout; the
      `source_pending_cap` refusal row and its suppressed counts appear;
      the holder counts, every 100 ms, its sockets Lorica has not
      closed (a refused one is closed at once, a pending one stays
      until its 5 s read expires): that count never passes the
      per-source share (32) from one address, nor 256 in the next
      step. Then
      eight source addresses added to the runner on `streams-geo`
      (`ip addr add`, the runner given `NET_ADMIN`, test only) fill the
      cap: connections established before keep echoing, new ones are
      refused `pending_cap` until the 5 s reads expire, then served.

## Dev Notes

### Where to extend, verified on `8a7e075a`

- `lorica-stream/src/tcp/engine.rs`: `Inner::serve` (admit, the record
  of a refusal), `Inner::pipeline` (phase 2, the trusted header and the
  carried client).
- `lorica-stream/src/udp/engine.rs`: the new-session path (`d.caps.get`,
  `charge_rate`, `admit_session`, the `CapRefusal` mapping).
- `lorica-stream/src/caps.rs`: `NodeCapsRegions`, `CapsRegistry::adopt`,
  `StreamCaps::stream_cap_left` (a pending equivalent is needed for
  retired regions).
- `lorica-shmem/src/stream_caps.rs`: `layout_for`, `admit_session`,
  `charge_rate`, `release_worker`, `evict_rates`, `ShardCell`,
  `RateCell`.
- `lorica/src/connection_filter.rs`: `GlobalConnectionFilter::snapshot`,
  `RefusalLogLimiter`, `ProxyProtocolGate::record` and
  `report_suppressed_at` (the spawn pattern to reuse).
- `lorica/src/proxy_wiring.rs` and `proxy_wiring/filters.rs`:
  `check_ban_and_blocklist` (the whitelist exemption),
  `check_geoip_filter` (the unknown-country rule).
- `lorica-config/src/connection_filter.rs`: `validate_cidr_list`,
  `ConnectionFilterPolicy::{from_cidrs, accepts}`.
- `lorica-config/src/models/stream.rs`: `udp_exposure_check`,
  `TCP_ENGINE_FIELDS`, `StreamRefusal`, `Stream::validate`.

### Pitfalls

- **The stream runtime has one thread per process** (12.3). No lock is
  held across an await; the GeoIP lookup and the blocklist check are
  synchronous and short; policies are built in `table_changed`.
- **IPv4-mapped peers**: canonicalise before every check and before
  `SourceKey::of`.
- **A trusted PROXY peer is not a source** (D-b); a test pins it, or a
  load balancer in front of a stream would be rate-limited as one
  client.
- **The pending slot must be released on every exit of phase 2**,
  drains and total timeouts included: make it a guard dropped at the
  end of the scope, not a call on the success path.
- **Backend-cap races** must not count as connect attempts nor reach
  the breaker.
- **Heredocs with apostrophes break the Bash tool**: scripts through
  the Write tool; `.sh` files LF.

### Handed to other stories

- **12.9**: export `refused` per reason, `pending`, `geoip_unknown`,
  the per-node pending total; decide whether access-log rows for
  pre-forwarding ends (`proxy_header_invalid`, `clienthello_timeout`,
  `invalid_client_hello`) go through `RefusalLogLimiter` (recommended).
- **12.10**: the form for the D-m fields and `max_active`, every cap
  labelled "per node", the allowlist state beside the D6 and D7 badges,
  the `streams:read` view and MCP read tools carrying the fields.
- **12.11**: the up-to-twice caps during an upgrade's drain (D-e).
- **12.12**: IV3 at scale in its security phase.
- **12.15**: detection reads inside the pending slot; the silent-client
  matcher calls `has_source_allowlist()`.

## Resolved (maintainer, 2026-11-15)

All eight recommendations of the draft accepted as written.

1. **Filters apply to new connections only.** A change to a stream's
   CIDRs, GeoIP, the global filter or the blocklist does not end live
   connections or sessions; disabling and re-enabling the stream cuts
   them. Reason and cost in D-a; `docs/streams.md` states it (Lot H).
2. **The WAF auto-ban list does not apply to streams.** Reason and cost
   in D-d; `docs/streams.md` states it with the remedy (Lot H).
3. **The generic refusal-log limiter lives in
   `lorica_stream::refusal_log`**, used by the HTTP listeners too (D-j).
4. **The per-source pending share is a derived constant**, 1/8 of the
   effective pending cap, not a field (D-f).
5. **No default per-source cap on TCP** (D-f); UDP keeps its 256.
6. **Any non-empty `source_allow_cidrs` counts as an allowlist** for D6
   and D7, with no minimum prefix length; two `/1` halves pass and are
   accepted as a deliberate operator act (D-c).
7. **Open rates are off by default** on both protocols (D-g).
8. **The per-backend cap is on the stream-to-backend link** (D-h).

## Dev Agent Record

### Debug Log

- Lot A, the join ABA. `table.rs` (9fc991f6) fixed a claim that
  adjusted a count read before its CAS. The shard claim never did that
  (it sets the count to 1), but its join did have an ABA of its own: a
  writer reads a cell's key, the cell is released and claimed for
  another key, and the writer's count CAS lands on that key. A
  reverse probe (the post-add key check removed) fails
  `churned_shard_cells_never_count_one_key_for_another` in 6 of 20
  runs; with the check, 0. In production a shard has one writer (its
  worker's single-threaded runtime), so the race needed test threads to
  show; the fix costs one load per join.
- Lot C, the region of a TCP stream. The engines refuse
  `caps_unavailable` without a region, and the binary created regions
  for UDP streams only, so Lot C alone would have left every TCP stream
  of a running node refusing every connection (the process tests
  `stream_engine_process_test` and `stream_tls_process_test` with it).
  The region part of Lot D (create, resize, retire and send a region for
  every stream) is folded into Lot C for that reason.
- Lot C, a paused clock and a wall-clock window. The refusal-log window
  opens on `std::time::Instant`, a little after a paused tokio clock's
  start, so a test sleeping exactly one window on the paused clock does
  not reach the window's end; the test sleeps one second past it.
- Lot C was paused once (2026-11-15) between its second and third
  commits and resumed the next day; the first gate run on the region
  commit failed only `udp_stream_process_test`, which looked for the
  release log line the commit had renamed (fixed in that commit).

### Completion Notes

**Lot A (`lorica-shmem`, layout version 2).**

- API, additive: `WorkerCaps::admit_stream(stream_cap, pending,
  pending_cap) -> Result<StreamPermit, AdmitRefusal>`,
  `StreamPermit::admit_source(self, source, source_cap,
  source_pending_cap)` (consumes the permit, so a refusal gives the
  stream part back with it), `StreamPermit::end_pending(&mut self)`
  (idempotent, also run by `Drop`), `WorkerCaps::claim_backend(BackendKey,
  cap) -> Option<BackendSlot>`, `StreamCapsRegion::charge_open(Option<
  SourceKey>, OpenLimits, now_ns) -> OpenVerdict`, and
  `charge_new_session(source, bytes, RateLimits, OpenLimits, now_ns) ->
  NewSessionVerdict` for D-g's "one CAS sequence" on UDP. Readers:
  `pending`, `worker_pending`, `source_pending`, `backend_active`.
  `BackendKey::of(id)` is a 64-bit FNV-1a of the backend id, rehashed
  with the region's SipHash key before placement.
- **Deviation, `CapRefusal`.** The story has `CapRefusal` gain
  `PendingCap` and `SourcePendingCap` *and* the UDP engine compile
  unchanged; `lorica-stream/src/udp/engine.rs` matches `CapRefusal`
  exhaustively, so both cannot hold. The new API refuses with a new
  `AdmitRefusal { StreamCap, PendingCap, SourceCap, SourcePendingCap,
  TableFull }`; `CapRefusal` keeps its three variants for the
  `admit_session` wrapper. Lot C removes the wrapper and `CapRefusal`
  with it (and may rename `AdmitRefusal` to `CapRefusal`).
  `SessionPermit` is a type alias of `StreamPermit` until then.
- **Deviation, `layout_for`.** Changing its signature would break
  `lorica-stream/src/caps.rs`. `layout_for(max, workers)` stays (no
  links) beside `layout_with_links(max, workers, links)`, and
  `StreamCapsRegion::create` beside `create_with_links`. Lot C switches
  `NodeCapsRegions` to the link-aware pair (and compares
  `backend_slots` when deciding a replacement).
- **Deviation, backend floor.** D-e's `max(2 x links, 16)` is below one
  probe window (`MAX_PROBE` = 32), which every table must hold, so the
  floor is `MIN_BACKEND_SLOTS` = 32: `next_pow2(max(2 x links, 32))`.
  512 bytes per worker.
- Sizes: TCP at 1,024 connections on 8 workers gives D-e's 256 KiB of
  rate cells and 512 KiB of source shards. The UDP default (4,096
  sessions, 8 workers) doubles its source shards to 2 MiB with the
  32-byte cell; Lot H's docs carry the new figure.
- Pending is a subset of active: a pending connection counts against
  `source_cap` from accept (AC #5), and a cell's `pending` is given
  back before its `active`, so the release that frees a cell never
  leaves a pending count behind.
- Order inside the split API: `admit_stream` checks the stream cap then
  the pending cap, `admit_source` the source cap then the source's
  pending share. On an untrusted path the refusal named when several
  apply is therefore `pending_cap` before `source_connection_cap`,
  where D-a's table lists step 7's source cap first. The counts are
  the same either way.
- A rate charge re-reads its cell's key after charging and takes the
  charge back if eviction gave the cell to another source meanwhile
  (`a_charge_on_a_cell_that_changed_hands_is_taken_back`).

**Lot B (`lorica-config`), with Lot F folded in.** 12.4 Lot C and 12.5
Lot G had both landed when Lot B started, so the two allowlist hook-ups
of Lot F ship here, as the Order paragraph provides.

- **Migration 78** (`migrate_stream_protection`, the next free number):
  `streams.source_max_connections` (nullable `INTEGER`),
  `max_pending_connections` (`INTEGER NOT NULL DEFAULT 256`),
  `source_allow_cidrs` and `source_deny_cidrs` (JSON `TEXT NOT NULL
  DEFAULT '[]'`), `geoip` (nullable JSON `TEXT`), `source_open_rate`
  and `open_rate` (nullable `INTEGER`); `stream_backends.max_active`
  (nullable `INTEGER`). Idempotent through `add_column_if_absent`; the
  test runs it twice on a 12.4-shaped row.
- **Canonical format stays 3**, digest updated. Every new field carries
  a serde default equal to the model's, so a blob without them decodes
  to streams with no source control and uncapped links
  (`a_blob_without_the_stream_protection_fields_decodes_to_their_defaults`);
  no released blob is stamped 3; a 1.10.x peer is refused by version
  and by schema before it meets the fields; a 1.11.0 build from before
  them is refused by schema (migration 78) at the handshake. A version
  step would protect nothing and tell a mixed fleet two incompatible
  things happened when one did. `GeoIpConfig` joined the shape
  inventory (reached through a stream now) with a `GeoIpMode` line.
- `GeoIpConfig::normalised` in `lorica-config` (with
  `GeoIpConfig::COUNTRIES_MAX`); `validate_geoip` in
  `routes/crud.rs` delegates to it, messages unchanged, the route
  tests unchanged and green. `Stream::canonicalise_geoip` stores a
  stream's list normalised on every store write and import, as
  `canonicalise_server_names` does.
- Validation beyond the story's letter, each with its test: a blank
  entry in either CIDR list is refused (the runtime parser skips
  blanks, so `["  "]` would count as an allowlist while admitting
  everyone); an IPv4-mapped IPv6 network is refused (clients are
  judged on their canonical address, so it would never match, failing
  open in a deny list). `/0` messages: "admits every address, which is
  no allowlist" and "refuses every address; set enabled to false".
- `StreamBackend::validate` (the `max_active` range) runs in
  `link_stream_backend_unchecked`, so the management write, the import
  and the replica apply all hold it; the import's preview checks it
  too. The API's `backend_max_active` key rule is Lot E's.
- `Stream::effective_pending_connections`, `source_pending_share` and
  `PENDING_SOURCE_SHARE_DIVISOR` (8) live on the model, for Lot C.
  `Stream::protection_field_names` names the seven fields (pinned to
  the type by `every_protection_field_is_a_wire_key_the_fixture_moves`).
- The two hook-ups name the field in their messages: "a source
  allowlist (source_allow_cidrs)". Removing the allowlist a stream
  relies on is refused by the same validation on every write path.
- `compute_diff` reports a link whose `max_active` changed (a link now
  compares whole); `stream_eq` already compared every field. Export
  needed no change: serde carries the fields.
- **Outside the Lot B allowlist, to keep the gates green:**
  `lorica-api/openapi.yaml` (the twelve new words in the
  `StreamRefusal` enum only, which `streams/tests.rs` pins to
  `StreamRefusal::VARIANTS`); `lorica-api/src/streams/tests.rs` (the
  view key-set test filters `protection_field_names()` until Lot E
  publishes them, as 12.4 Lot C did for its TLS fields); one
  `max_active: None` line in each `StreamBackend` literal of
  `lorica-stream/src/table.rs`, `lorica-stream/tests/{runtime,
  tcp_engine, tcp_runtime, udp_engine}.rs` and
  `lorica/tests/stream_engine_adapters.rs`, without which the
  workspace does not compile.

**Lot C (`lorica-stream`, admission in the engines).** Four commits on
the branch (see the Change Log); the region part of Lot D folded in
(Debug Log).

- **Check order as implemented** (`lorica-stream/src/admission.rs`):
  1 region present (`caps_unavailable`); 2-3 `SourceGate::global`
  (`connection_filter`, then `ip_blocklist`); 4 stream deny then allow
  CIDRs (`source_denied`); 5 stream GeoIP (`geoip`, unknown passes and
  counts `geoip_unknown`, `country` asked only when the stream has a
  list); 6 `charge_open` (stream rate, then source rate: `open_rate`,
  `source_open_rate`, full window `connection_table_full`); 7
  `admit_stream` (stream cap `connection_cap`, then the pending cap
  `pending_cap`), then `admit_source` (`source_connection_cap`, then
  the pending share `source_pending_cap`). Lot A's order inside the
  split API stands: `pending_cap` is named before
  `source_connection_cap` when both apply. UDP: steps 1 to 5, then
  `charge_new_session` (stream and source open rates with the source's
  datagram and byte rates in one charge; the two datagram rates stay
  drops), then the session caps (`session_cap`, `source_session_cap`,
  `session_table_full`).
- **D-b.** A trusted PROXY peer is admitted with steps 1, the stream
  open rate, the stream cap and the pending cap; once its header is
  accepted, `admit_carried` runs steps 2 to 5, the source open rate,
  the source cap and the pending share on the carried client, or on
  the peer for a `LOCAL` / `UNKNOWN` header.
- **Pending.** A connection is pending from accept when it has phase 2
  work: a trusted PROXY header or a ClientHello. The slot (region and
  this process's `pending` gauge) is given back when phase 3 starts,
  after a terminating handshake, or when the connection ends, whatever
  the exit (`Admitted` drops it). The connect phase is bounded by its
  own timeout, not by the pending cap.
- **`SourceGate`** (`seams.rs`): `global(client) ->
  Option<StreamRefusal>` and `country(client) -> Option<[u8; 2]>`,
  synchronous, on the canonical judged address. Lot D implements it in
  `lorica/src/stream_engine.rs` over `GlobalConnectionFilter::snapshot`
  (refusal `connection_filter`), `waf_engine.ip_blocklist()` with the
  global WAF whitelist exemption (`ip_blocklist`) and the process's
  `geoip_resolver`, and replaces `NodeControlsPending`, the pass-through
  gate the binary hands both engines meanwhile (a stream applies its
  own controls only until then).
- **Refusals.** Every refusal is counted once, under its reason, where
  it is decided (`caps_unavailable` on UDP included, which 12.5 dropped
  uncounted). A connection or session ending `refused(_)` hands no
  `ConnectionRecord`: that includes 12.4's own refusals (`no_match`,
  `invalid_client_hello`, `no_certificate`, `tls_handshake`,
  `client_certificate`), since `invalid_client_hello` is a refusal in
  the code, not a separate end as D-j's text assumed; the TLS engine
  tests read those as refusal rows now.
- **Observer, per the Story 12.9 amendment.** `ConnectionObserver`
  gains the defaulted `refused(RefusalRecord)` (stream id and name,
  protocol, listen port, judged client, `proxied_from`, refusal,
  instant) and `refusals_suppressed(SuppressedRecord)` (stream id and
  name, protocol, refusal, count, `reported_at`). Their defaults do
  nothing: the engine writes the former `warn` line at `debug` itself.
  The limiter key is `(stream index, StreamRefusal)`, the index stable
  per stream id while the table holds it; `RefusalKey` in
  `admission.rs` is the one place Story 12.9 widens to `StreamLogKey`.
- **Link caps.** Counted only on links with `max_active`; a backend at
  its cap leaves the candidates before selection (backups then serve);
  the claim before the first attempt is held to the end and given back
  on a failed attempt; a lost race is neither an attempt nor a breaker
  report; no candidate left with a cap among the reasons and no attempt
  made refuses `backend_cap`. The plane sizes every region for no links
  (`REGION_LINKS = 0`, the 32-cell floor per worker); passing the link
  count is Lot D's.
- **Removed:** `tcp::cap::ConnectionCaps` (`held_fds` stays, ceiling
  `max_connections` per process); `WorkerCaps::admit_session`,
  `CapRefusal`, `SessionPermit`.
- **IV1 and IV3 at this level.** IV1:
  `a_source_over_its_open_rate_is_refused_while_another_is_served`
  (TCP, ten connects from one loopback address, the ones past the burst
  refused at accept, another address served, one row then one
  suppressed row) and its UDP twin. IV3:
  `two_thousand_silent_connections_never_pass_the_pending_cap` (100
  sources of 20 silent TLS connections: the region's pending total
  never above 256, exactly 2,000 - 256 refused `pending_cap`) and
  `a_source_at_its_pending_share_is_refused_while_another_is_admitted`.
  The handshake of an outside client during the flood is Lot I's e2e.
- **Not covered by an engine test:** `connection_table_full` (it needs a
  probe window of the source shard filled, which the region tests of
  Lot A cover for the same refusal path).

## File List

Lot A:

- `lorica-shmem/src/stream_caps.rs` (modified)
- `lorica-shmem/src/lib.rs` (modified)
- `lorica-shmem/tests/stream_caps.rs` (modified; outside the Lot A
  allowlist, the multi-process tests the Lot asks for live there)

Lot B (and Lot F):

- `lorica-config/src/models/stream.rs` (modified)
- `lorica-config/src/models/route.rs` (modified, `GeoIpConfig::normalised`)
- `lorica-config/src/store/streams.rs` (modified)
- `lorica-config/src/store/mod.rs` (modified, migration 78)
- `lorica-config/src/canonical.rs` (modified)
- `lorica-config/src/diff.rs` (modified)
- `lorica-config/src/import.rs` (modified)
- `lorica-api/src/routes/crud.rs` (modified, `validate_geoip` delegates)
- `lorica-api/openapi.yaml` (modified, refusal enum only; outside the
  allowlist)
- `lorica-api/src/streams/tests.rs` (modified, interim view filter;
  outside the allowlist)
- `lorica-stream/src/table.rs`, `lorica-stream/tests/runtime.rs`,
  `lorica-stream/tests/tcp_engine.rs`, `lorica-stream/tests/tcp_runtime.rs`,
  `lorica-stream/tests/udp_engine.rs`, `lorica/tests/stream_engine_adapters.rs`
  (modified, `max_active: None` in link literals; outside the allowlist)

Lot C (and the region part of Lot D):

- `lorica-stream/src/admission.rs` (new)
- `lorica-stream/src/refusal_log.rs` (new)
- `lorica-stream/src/seams.rs`, `caps.rs`, `counters.rs`, `handler.rs`,
  `lib.rs`, `tcp/engine.rs`, `tcp/connect.rs`, `tcp/cap.rs`,
  `udp/engine.rs` (modified)
- `lorica-stream/tests/tcp_engine.rs`, `lorica-stream/tests/udp_engine.rs`
  (modified)
- `lorica-shmem/src/stream_caps.rs`, `lorica-shmem/src/lib.rs` (modified,
  the `admit_session` wrapper removed)
- Outside the allowlist: `lorica-stream/src/table.rs` (`max_active` on
  `LinkedBackend`), `listener.rs` (the caps registry into
  `AcceptedConnection`), `runtime.rs` (doc line);
  `lorica-stream/tests/{tls_engine, tcp_runtime, runtime}.rs`;
  `lorica-shmem/tests/stream_caps.rs`; `lorica/src/startup/stream_plane.rs`
  (regions for every stream, the region part of Lot D);
  `lorica/src/stream_engine.rs` (the interim gate);
  `lorica/tests/stream_engine_adapters.rs`, `lorica/tests/stream_tls_wiring.rs`,
  `lorica/tests/udp_stream_process_test.rs` (modified)

## Change Log

| Date | Version | Description | Author |
|---|---|---|---|
| 2026-11-15 | 0.1 | Draft: admission order, trusted-peer split, region version 2 for TCP and per-backend counts, per-node `max_connections`, pending cap and per-source share, open rates, link caps, refusal reasons and the shared refusal-log limiter, allowlist hook-ups for 12.4 and 12.5, Lots A to I, eight open questions. | Romain G. |
| 2026-11-15 | 0.2 | Maintainer answers folded in as Resolved 1 to 8: reasons and costs of new-connections-only filters and of no auto-ban on streams stated in D-a and D-d and made explicit in Lot H; the two `/1` halves accepted in D-c. Status Draft. | Romain G. |
| 2026-11-15 | 0.3 | Lot A: stream-caps region layout version 2 (pending totals, stream and source open rates, 32-byte source cells, backend shards), the split admission API, the join ABA closed and tested. Status InProgress. | Romain G. |
| 2026-11-15 | 0.4 | Lot B with Lot F folded in: the source controls on `Stream` and `max_active` on the link, their validation, `GeoIpConfig::normalised`, migration 78, canonical digest (format 3), diff and import; the two allowlist hook-ups. | Romain G. |
| 2026-11-16 | 0.5 | Lot C: the admission sequence in both engines, the `SourceGate` seam, per-node `max_connections`, the pending cap and per-source share, open rates, link caps, refusal rows through the generic limiter with the Story 12.9 observer methods, `caps_unavailable` counted on UDP; regions for every stream in the plane (the region part of Lot D). | Romain G. |
