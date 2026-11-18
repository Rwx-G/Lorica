# Worker shared-state architecture

Author: Romain G.
Status: Implemented. All phases (1, 2, 3, 4, 5, 6, 7) landed in
v1.3.0. Phase 8 multi-worker integration tests landed as per-phase
RPC round-trip tests plus the docker e2e worker-mode sections (19b
two-phase reload, 19c breaker cross-worker).

This document specifies the cross-process shared-state mechanisms
introduced to close the worker-parity audit findings WPAR-1 (rate
limits), WPAR-2 (forward-auth verdict cache), WPAR-3 (circuit
breaker), WPAR-7 (metrics freshness) and WPAR-8 (config reload
window). It is the design floor for ~14 days of implementation work
and should be reviewed before code lands.

---

## 1. Goals

1. **Functional parity**: a configuration that behaves a certain way
   in single-process mode (`--workers 0`) must behave the same way in
   worker mode (`--workers N >= 1`). No silent `× N` amplification.
   Until 1.11.0 two features broke this goal: the rate-limit auto-ban
   counted each client's violations per worker and banned on that
   worker only, and the flood defence compared each worker's own
   request rate to a proxy-wide threshold (§ 6 (c) and (d) describe
   what replaced them).
2. **High-perf hot path**: simple counters (the WAF and rate-limit
   auto-bans per client, the flood defence's request rate) must not
   pay an IPC round trip per request. Token bucket state
   (per-route) accepts a bounded ~100 ms imprecision in exchange for
   IPC-free hot path.
3. **Reusable infrastructure**: the new RPC layer and shared-memory
   layer must be primitives the rest of the codebase can build on for
   future cross-worker features (sticky sessions, distributed cache
   invalidation, etc.).
4. **Crash safety**: a supervisor crash leaves shared state in a
   recoverable shape; workers detect supervisor death and fall back
   to per-worker semantics until restart.

## 2. Non-goals

- **Cross-node sharing**. Lorica is single-node. No Redis, no etcd.
- **Hot-scalable workers** (WPAR-5). `N` stays fixed at startup.
- **Online schema migration of the mmap layout**. A layout change
  requires a supervisor restart.
- **Strict consistency for token buckets**. The worker-cached +
  supervisor-sync design admits a bounded imprecision of
  `100 ms * N_workers` on the global rate. At `N=4` and a 100 req/s
  cap, up to ~40 extra requests per second may slip through in
  the worst case. Acceptable for rate-limit semantics, not for
  billing or any accounting use case. This is a documented
  feature guarantee, surfaced in the admin docs.

---

## 3. Overview of components

```
+----------------------------------+
|           Supervisor             |
|                                  |
|  +---------+   +-------------+   |        +-------------------+
|  |   RPC   |   |   Atomic    |   |        |    Worker N       |
|  | router  |   |  hashtable  |   |        |                   |
|  |         |   |  in mmap    |   |   <--- |   RPC client +    |
|  |         |   |  region     |   |   ...  |   mmap consumer   |
|  +---------+   +-------------+   |        +-------------------+
|       ^                ^         |
|       |                |         |
|       +-- existing -----+        |
|       |  command        |        |
|       |  channel        |        |
|       |  (extended)     |        |
|       +-----------------+        |
+----------------------------------+
                |
        mmap region passed
        as FD at fork via
        existing SCM_RIGHTS
        socketpair
```

Three primitives:

- **(A) Extended `lorica-command` channel** - existing Unix
  socketpair, prost framing. Adds: pipelining (multiple in-flight
  requests per channel), per-request timeout, deduplication for
  /metrics scrape concurrency, new message types.
- **(B) `lorica-shmem` crate (new)** - opens a `memfd_create` region,
  passes the FD to workers at fork (alongside the existing listener
  FDs), exposes a fixed-layout open-addressing hashtable backed by
  atomics. Used only for high-frequency simple counters.
- **(C) Per-worker local cache + periodic sync** - workers keep a
  local view of token-bucket state and push deltas to the supervisor
  every 100 ms via the RPC channel. Supervisor merges deltas into the
  authoritative state and broadcasts the refreshed authoritative
  view back. Used for token-bucket-shaped state where atomics alone
  are insufficient.

## 4. Component (A): RPC framework

### 4.1 Why extend the existing channel

`lorica-command` already has the socketpair, the FD passing at fork,
the prost wire format with 8-byte LE size prefix, and a
sequence-number pattern (`Response::ok(seq)`). What it lacks for the
new use cases:

- **Pipelining**. Today, each command is sent and the reply is
  awaited inline before the next command. New use cases issue
  multiple concurrent requests per channel (rate-limit query +
  metrics pull + reload prepare can overlap).
- **Per-request timeout** that does not cancel adjacent requests on
  the same channel.
- **Dedup** so that two concurrent `MetricsRequest` issued by
  parallel `/metrics` scrapes coalesce into one supervisor->worker
  round trip.

### 4.2 Wire format changes

No breaking change to the prost schema. Existing messages keep their
encoding. New message variants are added under the existing
`Command` / `Response` oneofs:

```protobuf
// New supervisor -> worker:
message RateLimitQuery { string key = 1; uint32 cost = 2; }
message VerdictLookup  { string route_id = 1; string cookie = 2; }
message VerdictPush    { string route_id = 1; string cookie = 2;
                         Verdict verdict = 3; uint64 ttl_ms = 4; }
message BreakerQuery   { string route_id = 1; string backend = 2; }
message BreakerReport  { string route_id = 1; string backend = 2;
                         bool success = 3; }
message ConfigReloadPrepare { uint64 generation = 1; }
message ConfigReloadCommit  { uint64 generation = 1; }

// New worker -> supervisor:
message RateLimitDelta { repeated RateLimitEntry entries = 1; }
message RateLimitEntry { string key = 1; uint32 consumed = 2; }

// Supervisor -> worker, in reply:
message RateLimitSnapshot { string key = 1; uint32 remaining = 2;
                            bool untracked = 3; }
message RateLimitDeltaResult { repeated RateLimitSnapshot snapshots = 1; }
```

Sequence numbers stay strictly monotonic per channel direction. A
reply carries the request's sequence number; the dispatcher matches.

### 4.3 Worker-side dispatcher

```rust
pub struct ChannelClient {
    next_seq: AtomicU64,
    inflight: DashMap<u64, oneshot::Sender<Response>>,
    tx: mpsc::Sender<Command>,  // bounded, capacity 256
    // Background read loop owns the UnixStream
}

impl ChannelClient {
    pub async fn request(&self, cmd: CommandPayload, timeout: Duration)
        -> Result<Response, ChannelError>
    {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.inflight.insert(seq, tx);
        self.tx.send(Command::new(cmd, seq)).await?;
        let res = tokio::time::timeout(timeout, rx).await;
        // Always drop the inflight entry on any exit path so a dead
        // oneshot sender cannot linger in the map. On channel teardown
        // the background read loop also drains `inflight` wholesale.
        self.inflight.remove(&seq);
        match res {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_))   => Err(ChannelError::Closed),
            Err(_)       => Err(ChannelError::Timeout),
        }
    }
}
```

A single background task owns the read half of the socketpair and
dispatches incoming `Response` to the matching oneshot from
`inflight`.

The outbound queue is a bounded `tokio::sync::mpsc::channel(256)`.
Under supervisor slowness, `tx.send().await` backpressures the
caller; the per-request timeout then triggers and returns
`ChannelError::Timeout`. No silent unbounded queue growth. If
backpressure is observed (send future pending > 10 ms), the worker
logs a warning so operators can spot a stuck supervisor.

### 4.4 Supervisor-side handler

Each per-worker channel has its own handler task. The handler loops:
read a `Command`, route by variant to the right service handler
(rate-limit, verdict, breaker, reload, etc.), build a `Response`,
write back. Service handlers are `async fn` so multiple requests can
be in flight simultaneously per channel via `JoinSet`.

### 4.5 Dedup for /metrics

Single `Mutex<Option<watch::Receiver<MetricsSnapshot>>>` on
`AppState`. The first scrape issues the broadcast and publishes a
watch sender; concurrent scrapes await the same watch. Once the
result lands, the watch is dropped so the next scrape after a TTL
(say 250 ms) re-issues.

## 5. Component (B): `lorica-shmem` crate

### 5.1 Region creation and FD passing

Supervisor at startup:

```rust
let memfd = nix::sys::memfd::memfd_create(
    c"lorica-counters",
    MemFdCreateFlag::MFD_CLOEXEC,
)?;
nix::unistd::ftruncate(&memfd, REGION_SIZE)?;
let region: &'static SharedRegion = unsafe {
    let ptr = mmap(
        ptr::null_mut(),
        REGION_SIZE,
        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
        MapFlags::MAP_SHARED,
        &memfd,
        0,
    )?;
    &*(ptr as *const SharedRegion)
};
// Pass `memfd` to each worker at fork via the same SCM_RIGHTS
// machinery used for listener FDs.
```

Workers receive the fd, mmap, and cast to `&'static SharedRegion`.
Supervisor and workers see the **same physical pages** kernel-side.

### 5.2 Region layout

Fixed at compile time. Layout changes require a major version bump
and a supervisor restart (workers cannot adopt a new layout without
re-fork).

```rust
#[repr(C, align(64))]
pub struct SharedRegion {
    pub magic: u64,                   // 0x4c4f5249434153484d ("LORICASHM")
    pub layout_version: u32,
    pub _reserved: u32,
    /// siphash13 key, populated once at supervisor startup via
    /// `getrandom`. Prevents HashDoS on the probe chain. Read-only
    /// after fork. See § 5.3.
    pub hash_key: [u64; 2],

    pub rate_counters: AtomicHashTable<128 * 1024>,  // 8 MiB, § 6 (c)
    pub waf_auto_ban:  AtomicHashTable<128 * 1024>,  // 8 MiB, § 6 (a)
}

#[repr(C, align(64))]
pub struct AtomicHashTable<const N: usize> {
    pub slots: [Slot; N],
}

#[repr(C, align(64))]
pub struct Slot {
    /// 0 = empty, otherwise siphash13(ip) | 1 (LSB = "occupied" tag)
    pub key: AtomicU64,
    /// counter value (request count, ban count, etc.)
    pub value: AtomicU64,
    /// last update timestamp (monotonic ns since boot). Best-effort
    /// precision: concurrent writers race on the store, so the value
    /// is approximate within tens of microseconds. Only used to
    /// drive eviction, which tolerates that imprecision.
    pub last_update_ns: AtomicU64,
    // Cache-line pad follows (align(64)).
}
```

Three atomics = 24 B of data, padded to a 64 B cache line per slot
(`align(64)` on `Slot`). Total: 64 B * 128K slots * 2 tables =
16 MiB. Still trivial.

Note: earlier drafts carried a `version` seqlock field so readers
could observe (`value`, `last_update_ns`) atomically. The seqlock
is not safe with multiple concurrent writers (two writers racing
on `version.fetch_add(1)` can leave `version` even while both are
mid-update, misleading readers). It is also unnecessary: readers
consume `value` alone (a single `AtomicU64::load`), and
`last_update_ns` is informative for eviction only. The seqlock has
been removed. See § 8 for the full concurrency story.

### 5.3 Atomic operations

Two operations:

The siphash key is 128 bits, generated once by the supervisor at
startup via `getrandom`, and passed to each worker at fork through
the same `SharedRegion` header (reserved field, not shown in § 5.2
for brevity; added as `pub hash_key: [u64; 2]` right after
`layout_version`). This prevents HashDoS: an attacker cannot
pre-compute IPs that collide into the same probe chain and saturate
`MAX_PROBE`. The key is stable for the lifetime of the supervisor;
a supervisor restart rotates it (workers are re-forked).

```rust
pub fn increment(&self, key: u64, by: u64) -> u64 {
    let h = siphash13_with_key(self.hash_key, key) | 1;  // ensure non-zero
    let start = (h as usize) & (N - 1);
    for probe in 0..MAX_PROBE {
        let i = (start + probe) & (N - 1);
        let s = &self.slots[i];
        let cur_key = s.key.load(Ordering::Acquire);
        if cur_key == 0 {
            // Try to claim. On claim we reset `value` to `by` and
            // stamp `last_update_ns`. Reset matters because the slot
            // may have been evicted and is being reused for a new key.
            if s.key.compare_exchange(0, h, Acquire, Relaxed).is_ok() {
                s.value.store(by, Release);
                s.last_update_ns.store(now_ns(), Release);
                return by;
            }
            continue;  // someone else claimed; re-read
        }
        if cur_key == h {
            // Existing key: single commutative atomic add. No seqlock.
            let new = s.value.fetch_add(by, AcqRel) + by;
            s.last_update_ns.store(now_ns(), Release);
            return new;
        }
        // Collision: probe next slot.
    }
    // Region full: log + return a poison value. Caller treats as
    // "limit reached" to be safe.
    tracing::warn!(table = type_name::<Self>(),
                   "shmem hashtable saturated at probe limit");
    u64::MAX
}

pub fn read(&self, key: u64) -> Option<u64> {
    let h = siphash13_with_key(self.hash_key, key) | 1;
    let start = (h as usize) & (N - 1);
    for probe in 0..MAX_PROBE {
        let i = (start + probe) & (N - 1);
        let s = &self.slots[i];
        let k = s.key.load(Acquire);
        if k == 0 { return None; }
        if k != h { continue; }
        // Single atomic load, no seqlock. Readers only consume
        // `value`; `last_update_ns` is eviction-only.
        return Some(s.value.load(Acquire));
    }
    None
}
```

The code above is the original design. `lorica-shmem/src/table.rs`
is the reference: since 1.11.0 a claim stamps the slot before its
CAS, lookups scan the whole probe window and sum every slot holding
the key, and `MAX_PROBE` is 32. A refused key (`SATURATED`) fails
open: nothing is counted, and the table's own documentation states
the refusal rate at its sized load and the metrics that count them.

### 5.4 Eviction

Background task on the supervisor walks every slot once per minute.
A slot is evicted when `last_update_ns` is older than 5 minutes:
the supervisor CAS's `key` from `h` to 0 to release the slot. No
separate "active threshold" - staleness by age is the only
criterion, and it works uniformly for monotonically-growing
counters (WAF auto-ban) and per-window counts (§ 6 (c)), whose
key goes idle when its window ends.

`value` and `last_update_ns` are **not** reset at eviction time.
They are reset by the next `increment` that claims the slot (see
§ 5.3), which is safe because the claim CAS serialises reuse.

Race between eviction and a late writer: a writer may read
`cur_key == h`, the eviction CAS may then flip `key` to 0, a new
key `h'` may claim the slot and store its initial `by'`, and only
then the late writer's `value.fetch_add(by, AcqRel)` lands - now
polluting `h'`'s counter by `by`. The bound is **one stale
increment per slot reuse**, not a duration: at most a single
request's worth of count leaks from the evicted key to the
reclaiming key. Given eviction targets slots idle for 5 min, the
late-writer window is already vanishingly narrow (a writer that
read `cur_key` only to `fetch_add` > 5 min later is pathological).
Acceptable for WAF counters; would not be acceptable for billing.

### 5.5 Crash safety

If the supervisor crashes mid-`increment`, the worst case is that
a single atomic store (`value` or `last_update_ns`) completed while
the other did not - but each store is independently atomic, so
readers never observe a torn value. No seqlock means no mid-update
state to recover from.

If the supervisor never restarts, workers fall back to per-worker
behaviour after an RPC timeout (see § 7). The shmem region
continues to be usable by workers for read/write; only the
supervisor-driven eviction pauses until a new supervisor is elected
(today: systemd respawn).

The mmap region itself survives supervisor death: `MAP_SHARED` plus
`memfd` semantics keep the pages alive as long as any process holds
the FD. When the supervisor restarts, workers are killed and
re-forked with a fresh memfd; the old region is reclaimed.

## 6. WPAR-1 implementation

Four parts:

**(a) WAF auto-ban** -> shmem `waf_auto_ban` (component B). On every
WAF block a worker adds 1 to the client's count in the shared table
(`proxy_wiring/filters.rs`). No IPC, no lock, ~ns per call. The
worker forwards the event over `waf.sock`, and the supervisor, on
each forwarded event, reads the client's count against
`waf_ban_threshold`; on the crossing it resets the count, broadcasts
`BanIp` to every worker's command channel and raises one `ip_banned`
alert (`startup/waf_forward.rs`). The supervisor is the sole issuer
of WAF bans, so every worker holds the same ones.

A per-client "WAF flood" count was planned beside it and never
built; its table is the one (c) uses.

**(b) Per-route token buckets** -> worker-cached + supervisor sync
(component C). Worker hot path:

```rust
let (rule, limit) = resolve_request_limit(&route, path)?;   // None: unlimited
let key = bucket_key(&route.id, rule, &limit, scope_key(&limit, client_ip));
let allowed = local_buckets.get_or_init(key, limit.capacity)
    .try_consume(cost, now_ns);                         // local atomic
if !allowed { return Err(RateLimited); }
// background task syncs every 100 ms via RPC.RateLimitDelta and
// refreshes the local view from the authoritative reply.
```

The code lives in `lorica/src/proxy_wiring/rate_limit.rs`, shared by
both ends of the RPC.

- **Key.** `<route_id>|<rule>|<capacity>:<refill_per_sec>|<scope_key>`.
  `<rule>` is `-` for the route-level limit, or the position of the
  matched path rule when that rule sets `rate_limit_rps` or
  `rate_limit_burst`, so such a rule has a bucket of its own. The
  limit is part of the key: a reload that changes a limit or reorders
  rules yields a new key, and the old bucket goes idle and is evicted.
  Nothing is reset on reload. `<scope_key>` is the client IP for
  `per_ip` (`unknown` when the address is not an IP literal), or
  `__route__` for `per_route`.
- **Limit.** Both ends resolve it with `Route::effective_rate_limit`
  and `Route::effective_rate_limit_with(rule)`, so a route configured
  with the legacy `rate_limit_rps` / `rate_limit_burst` fields and a
  path-rule override get the same limit on both sides.
- **Sync.** Each tick a worker sends every bucket that has unpushed
  consumption or sits below capacity, the latter with `consumed = 0`.
  Refused requests consume nothing, so a drained bucket only learns
  about the refill from the reply. At most `SYNC_BATCH_MAX_ENTRIES`
  per tick, the RPC frame being capped at 1 MiB; a rotating cursor
  serves the rest on later ticks.
- **Reply.** The supervisor keeps one `AuthoritativeBucket` per key,
  sized from the route in its store (per-route policy cache, cleared on
  every config change), sums the consumption of every worker into it
  and returns the remaining count. A key whose route is gone, carries
  no limit, or resolves to another limit than the one the key encodes
  is answered `untracked`: the worker drops its bucket and the next
  request rebuilds it from its own config. "No limit" never reads as
  "0 tokens left" (issue #45).
- **Eviction.** Workers and the supervisor both drop buckets idle for
  `BUCKET_IDLE_TTL`. On a worker a refused request counts as activity,
  so a client hammering a drained bucket cannot earn a full one by
  waiting for eviction.

Imprecision is bounded at `100 ms × N_workers` worth of in-flight
consumption, in the direction "could let a few extra requests
through". Acceptable.

**(c) Rate-limit auto-ban** -> shmem `rate_counters` (component B),
since 1.11.0. A route's `auto_ban_threshold` is compared to the
client's refused requests per second over the latest completed
minute, the semantics `lorica_limits::rate::Rate` gives single-process
mode, which keeps using it. Before 1.11.0 worker mode used the same
per-process `Rate`: each worker weighed only the requests it served
itself, so a client whose connections spread over N workers needed
up to N times the threshold to be banned, and the ban held on the
worker that issued it alone, the client's connections to the other
workers carrying on.

- **Count.** A refused request adds 1 to the client's count for the
  current minute in `rate_counters`, through
  `lorica_shmem::WindowedCount`: one key per client and minute,
  windows numbered on `CLOCK_MONOTONIC`, which every process shares.
  The rate read is the previous minute's count over 60 s, summed over
  every worker.
- **Decide once.** Every worker can see the crossing; the one whose
  `take_completed` clears the previous minute's count decides the
  ban, and the others then read 0. The decider bans the client in its
  own ban list at once.
- **Apply everywhere.** The decider queues the ban
  (`RateLimitBanQueue`); its WAF forwarder writes it to `waf.sock` on
  the next tick (every 100 ms), ahead of its WAF events. The
  supervisor broadcasts `BanIp` with reason `rate_limit` to every
  worker and raises the one `ip_banned` alert, the path (a) uses.
  Workers decide because they hold the route's threshold and
  duration; the supervisor relays without counting.
- **Bounds.** Each worker refuses the client from the moment its
  `BanIp` lands, so a few more refused requests can be counted in the
  meantime; they fall in the current minute, whose count a new ban
  needs to cross on its own. A refused count (`SATURATED`) fails open
  and is counted on `lorica_rate_limit_auto_ban_uncounted_total`.

**(d) Flood defence** -> shmem `rate_counters` (component B), since
1.11.0. While the proxy takes more than `flood_threshold_rps` requests
per second (over the latest completed second), a per-IP rate-limited
request costs `flood_threshold_rps / flood_strict_rps` tokens instead
of 1. Single-process mode counts in its `Rate`. Before 1.11.0 worker
mode did too, per worker, so the defence engaged only once a single
worker's share passed the threshold: with N workers sharing the load,
at about N times the configured value.

Worker mode now adds every request to one key per second in
`rate_counters` (`WindowedCount` of kind `Requests`), and reads the
previous second's count, every worker's together. The request path
pays one atomic add on a cache line all workers share, the same
order of cost as the per-process `Rate` it replaces, which all of a
worker's threads already contended for. The supervisor's aggregate
was the alternative and was rejected: it only reaches the workers on
the metrics-report tick, seconds late, and would need a new push to
every worker, while a flood is decided second by second. Nothing is
counted while the defence is off (`flood_threshold_rps = 0`).

## 7. WPAR-2/3/7/8 implementation

All four use Component (A) only. No shmem.

### WPAR-2 (verdict cache)

Replace the per-process `FORWARD_AUTH_VERDICT_CACHE` static with
RPC. Worker hot path:

```rust
match rpc.verdict_lookup(route_id, cookie).await {
    Ok(Some(verdict)) => return verdict,        // hit
    _ => { /* fall through to actual auth call */ }
}
let verdict = call_auth_backend(...).await?;
let _ = rpc.verdict_push(route_id, cookie, verdict, ttl_ms).await;
```

Supervisor owns the cache map (`DashMap<String, (Verdict, Instant)>`)
with the same FIFO eviction the per-process cache uses today.

### WPAR-3 (circuit breaker)

Same shape, but the RPC surface must preserve the tri-state nature
of a breaker (Closed / Open / HalfOpen). The supervisor owns the
state machine; the worker only asks "should I send this request?"
and reports back.

```protobuf
enum BreakerDecision {
    ALLOW       = 0;  // Closed or first HalfOpen probe: send request
    DENY        = 1;  // Open: short-circuit with 503
    ALLOW_PROBE = 2;  // HalfOpen subsequent slot granted: send and
                     //   expect the Report to drive the transition
}
```

`BreakerQuery(route, backend)` returns `BreakerDecision`. The
supervisor decides when to admit a probe (HalfOpen) and which
worker gets the probe token; workers do not race on probe admission.
`BreakerReport(route, backend, success)` updates the supervisor's
state machine; on success after `ALLOW_PROBE`, the breaker closes.

Supervisor reuses the existing scoped breaker logic, just relocated
behind the RPC boundary.

### WPAR-7 (metrics pull)

`/metrics` handler issues a `MetricsRequest` to every worker via
RPC, awaits with `timeout(Duration::from_millis(500))`, falls back
to last cached value for non-responding workers. Concurrency dedup
via `Mutex<watch::Receiver>` (§ 4.5).

### WPAR-8 (config reload)

Supervisor coordinator:

```rust
const PREPARE_TIMEOUT: Duration = Duration::from_secs(2);
const COMMIT_TIMEOUT:  Duration = Duration::from_millis(500);

let gen = next_generation();

// Phase 1: Prepare. Per-worker timeout; any failure aborts.
let prepare = workers.iter().map(|w| async move {
    w.rpc.request(ConfigReloadPrepare { generation: gen }.into(),
                  PREPARE_TIMEOUT).await
});
let prepare_results = join_all(prepare).await;
if prepare_results.iter().any(Result::is_err) {
    // Identify and log the slow/failed workers, broadcast a no-op
    // drop for any worker that did reply Ok so they release their
    // `pending_proxy_config`. Surface the failure via API.
    abort_reload(gen, &workers, &prepare_results);
    return Err(ReloadError::PrepareFailed);
}

// Phase 2: Commit. Shorter timeout since work is a single ArcSwap.
let commit = workers.iter().map(|w| async move {
    w.rpc.request(ConfigReloadCommit { generation: gen }.into(),
                  COMMIT_TIMEOUT).await
});
join_all(commit).await;
```

Worker side: `ConfigReloadPrepare` reads the DB, builds a new
`ProxyConfig`, stores it in `ctx.pending_proxy_config`, replies Ok.
`ConfigReloadCommit` does the atomic ArcSwap. Window where workers
diverge collapses to RTT skew (microseconds on local UDS) instead
of 10-50 ms.

The 2-second Prepare timeout is deliberately generous because the
slow path involves a SQLite read and TLS material parsing. A worker
that exceeds the budget is treated as failed; the reload is
aborted rather than left in a half-committed state.

## 7a. The stream plane (v1.11.0)

Epic 12 added two cross-process mechanisms beside the three above, for
the stream listeners (`lorica-stream`). Neither reuses (A) or (B)
as they stood, for the reasons given in each part.

### 7a.1 The stream control channel

**Why a third channel.** The command and RPC channels are framed
`SOCK_STREAM` byte streams read by codecs that ignore ancillary data.
On a stream socket, `SCM_RIGHTS` attaches to a byte position, and a
reader that does not expect it drops or misattributes the descriptors.
Stream sockets are bound at runtime and must reach live workers, so
each worker gets a third socketpair, `AF_UNIX` / `SOCK_SEQPACKET` /
`SOCK_CLOEXEC`, created in `spawn_worker` beside `cmd` and `rpc`. Its
worker end travels in the fork bundle under its own typed tag; the
supervisor keeps the other end on the worker handle. A seqpacket
message keeps one payload, its tokens and its descriptors atomic, so the
typed-tag discipline of the fork bundle carries over unchanged.

**Messages.** A message is a text payload of space-separated tokens
plus, for the two messages that carry descriptors, one `SCM_RIGHTS`
descriptor per socket token. The supervisor attaches a binding's
sockets to a worker, detaches a binding, asks the worker to reload its
stream table (`refresh`), hands it a stream's caps region (`caps`, one
memfd, 7a.2), and quiesces it for a stop or an upgrade. The worker
answers each with an ack and a count, or a nack whose reason is a fixed
token, never free text; after an upgrade quiesce it also sends its
drain report. The message type, the tokens and their size bounds are
`lorica-worker/src/stream_ctl.rs`, shared by worker mode and
single-process mode, where the same type crosses an in-process channel
with owned descriptors instead of `SCM_RIGHTS`.

**Flow control.** Stop-and-wait per worker: the supervisor sends the
next message only after the previous one's answer or its 2 s timeout.
An attach carries at most 32 descriptors, so a 1,024-port range is
chunked, and stop-and-wait bounds the descriptors in flight to 32 per
worker. That matters because descriptors in flight are charged to the
sending user and refused (`ETOOMANYREFS`) past its `RLIMIT_NOFILE`.
Messages queue in the socketpair until the worker's stream thread reads
them, so the supervisor never waits for a worker to be ready before it
sends; a binding is `bound` once the supervisor holds its sockets, with
the count of workers serving it from the acks.

**Crash behaviour.**

- **A worker dies.** A respawned worker gets a fresh stream control
  pair like the other two. Before it counts as serving, the supervisor
  releases the dead worker's share of every caps region, sends the
  regions, replays one attach per live binding (a TCP stream's shared
  listener, a UDP stream's socket for that worker slot) and a refresh.
  The connections the dead worker held are gone with its process and
  end without an access-log row: that is a crash, not a drain.
- **UDP slots across a worker death.** The supervisor keeps every UDP
  slot socket for the binding's whole life. The kernel picks a socket
  of a `SO_REUSEPORT` group by a hash of the 4-tuple scaled to the
  group size, and closing one would move the others: keeping the group
  size constant is what keeps every other client on its worker. The
  cost: while a slot's worker is down (its respawn backoff), the clients
  hashed to it wait in that socket's receive buffer.
- **A worker `SIGTERM`ed without a quiesce** (the message did not reach
  it) still stops its accept loops and drains, on the stored drain
  setting, ending what remains with `node_shutdown`, and the worker
  logs it.
- **A hot upgrade** hands the stream listeners and the UDP slot
  sockets to the new generation in the upgrade transfer table, slot
  `k` to worker `k` ([hot-upgrade.md](../hot-upgrade.md#what-the-drain-does)).

### 7a.2 The stream-caps region

**Why not the WAF region.** `SharedRegion` (§ 5) is a compile-time
struct: it cannot be sized per stream at runtime, and per-stream tables
inside it would let one stream's flood fill another's slots. So a
second region type, `StreamCapsRegion` (`lorica-shmem/src/stream_caps.rs`),
holds the per-node caps and rates of one stream, TCP or UDP: one
anonymous memfd per stream on the node, created by the supervisor (or
the single-process driver), sized from the stream's cap, its backend
link count and the worker count, mapped `MAP_SHARED` by every worker.
Its layout and what each part counts are in the module's doc; it
carries its own magic and `STREAM_CAPS_LAYOUT_VERSION`, checked by
every worker when it maps a region, and the WAF region's
`LAYOUT_VERSION` is untouched by it.

**What is exact and what is not.**

- The stream total (connections or sessions) and the pending total are
  exact: an admission adds 1 by compare-and-swap only while the total
  is below the cap, attributed per worker so a dead worker's share can
  be subtracted.
- Per-source and per-backend counts live in per-worker shards: a
  worker writes only its own shard and a check sums the key over every
  shard. Two workers admitting the same key at the same instant can
  both pass, so a key holds at most `cap + (W - 1)` on the node, and
  exactly `cap` with one process.
- Rates are GCRA arrival times advanced by compare-and-swap against
  `CLOCK_MONOTONIC`, which is comparable across processes, so a rate is
  exact across the node's workers with no message.

**Never evicted while held.** A shard cell is freed only by the release
that brings its count to 0, or by the supervisor releasing a dead
worker's shards; the eviction pass, run every second, frees only rate
cells whose buckets are full again and whose source no shard holds. A
full probe window refuses the new source on that stream only.

**Lifetime.** One region per stream, not per binding, so caps stay
exact across a rebind's drain. A cap edit that changes the table sizes
creates a new region generation; live connections keep the region they
were counted in, the cap check sums the totals of the stream's live
regions, and a retired region is dropped once its total is 0. Regions
are never shared across process generations (the upgrade transfer table
carries no memfd), so a layout version change has no consequence across
a hot upgrade, and during an upgrade's drain each generation counts in
its own regions.

### 7a.3 What stays per process

The stream engines' counters (connections, bytes, refusals and the
rest) are per process, as HTTP's are, and reach the supervisor's
`/metrics` through the metrics report of § 7 (WPAR-7), aggregated there.
The one exception is the live session count of a UDP stream, which the
supervisor reads exactly from each region's total. The refusal-log
limiter is per process too: each worker writes at most one refusal row
per stream and reason per 10 s window, so a node writes at most `W`,
bounded and independent of the attacker's rate; a shared limiter would
buy a factor of `W` for a cross-process lock.

## 8. Concurrency invariants

Stated explicitly so reviewers can sanity-check.

1. **Shmem slot**: each field is an independent atomic. Readers
   perform a single `value.load(Acquire)` and observe some past
   committed value, never a torn read. Writers do not coordinate
   with each other beyond the slot's atomic ops; two concurrent
   `increment` on the same key race on `value.fetch_add`, which is
   correct (commutative). `last_update_ns` is best-effort: racing
   writers may overwrite each other's timestamp, but the value is
   always a real timestamp from one of them, bounded within a few
   microseconds of "now", which is sufficient for 5-minute
   eviction decisions. No seqlock: readers never consume
   (`value`, `last_update_ns`) as a pair, so there is nothing to
   tear across fields.
2. **RPC sequence**: per-direction monotonic. Requests with seq `n`
   are replied to with seq `n`. Workers and supervisor must never
   reuse a seq.
3. **Worker-cached token bucket**: local view is `eventually
   consistent` with supervisor authoritative state. Bound on
   inconsistency: 100 ms × (1 + N_workers) in the worst case.
4. **Reload generation**: monotonic. Workers reject any Prepare /
   Commit with a generation lower than the highest seen. Prevents
   reordering on a flaky channel.

## 9. Crash matrix

| Failure | Behaviour |
|---|---|
| Supervisor crashes, worker keeps running | Worker RPCs time out (500 ms). Worker falls back to local-only cached state for verdict/breaker/rate-limit. Shmem reads still succeed (region persists). Supervisor restart re-forks workers. |
| Worker crashes, supervisor keeps running | Supervisor restarts the worker (existing crash backoff). Worker restarts with empty local caches. Shmem state survives. Authoritative state on supervisor unaffected. |
| Channel goes silent (UDS broken) but processes alive | RPC requests time out. Worker logs warn + falls back. Supervisor's worker monitor will eventually kill + respawn the worker. |
| Shmem layout mismatch (binary upgrade with new layout) | Supervisor refuses to mmap a region with a different `magic` / `layout_version`, logs error, exits. systemd restarts; new layout fresh. |
| Stream-caps region version mismatch (a worker respawned from a newer binary on disk) | The worker answers the `caps` message with a nack; the binding reports fewer workers serving than it has, and the other workers serve on. |
| Worker dies while holding stream connections | Its connections end with the process, without an access-log row. The supervisor subtracts its share of every caps region before the respawned worker is attached again (§ 7a.1). |

## 10. Migration story

- Layout changes -> bump `layout_version` in the shmem header,
  document in `docs/BUMP-CHECKLIST.md`. No online migration. The
  stream-caps region (§ 7a.2) has its own version,
  `STREAM_CAPS_LAYOUT_VERSION`, bumped on a change of its own layout
  and never because the WAF region's moved.
- Wire format changes -> additive only (new oneof variants on the
  prost schema). Workers built against the old schema gracefully
  ignore unknown variants (prost default behaviour).
- Rollback to a single-process build -> all of these subsystems
  collapse to their per-process equivalents (the worker crate is
  conditionally compiled out). No state migration; the SQLite store
  is the only durable surface.

## 11. Implementation phases

Recap of the 14-day plan from the architecture discussion:

| Phase | Deliverable | Effort |
|---|---|---|
| 1 | RPC framework: extend `lorica-command` (pipelining, dispatch, dedup), tests | 2 d |
| 2 | `lorica-shmem` crate: memfd_create, FD passing, `AtomicHashTable`, eviction, multi-process crash-safety tests | 4 d |
| 3 | WPAR-1 hybrid: WAF flood + auto-ban migrate to shmem; per-route token buckets via worker-cache + supervisor sync | 3 d |
| 4 | WPAR-2: verdict cache RPC | 1 d |
| 5 | WPAR-3: breaker RPC | 1 d |
| 6 | WPAR-7: metrics pull on /metrics | 0.5 d |
| 7 | WPAR-8: ConfigReloadPrepare/Commit | 1 d |
| 8 | Multi-worker integration tests + load-test validation at 10k+ QPS | 1.5 d |

Each phase commits independently with its own tests; the doc and
the crate boundary make them reviewable in isolation.

## 12. Testing strategy

- **Unit tests**: per-component (RPC dispatcher, hashtable, eviction,
  worker-cache).
- **Multi-process integration tests** (new `lorica-shmem/tests/`):
  fork two test processes with a shared memfd, exercise concurrent
  increment + read + eviction, assert no torn reads, no lost
  updates beyond the expected commutative sum.
- **End-to-end parity tests** (new `lorica/tests/worker_parity_e2e.rs`):
  start a `--workers 4` Lorica in a Docker container, exercise rate
  limit / forward auth / circuit breaker / config reload, assert
  same-as-single-process semantics.
- **Load test** (new in `bench/`): 10k+ QPS against a `--workers 4`
  setup with rate limits + WAF + forward auth on; measure
  - p99 latency vs single-process baseline (target: < 10 % overhead)
  - rate-limit precision (configured 100 req/s -> measured <= 105 req/s globally, not 400)
  - shmem hashtable saturation rate (target: 0)
- **RPC hit-latency micro-bench** (new in `lorica-bench/`): measure
  the per-request cost added by the verdict-cache RPC on a
  cache-hit path. Today the local `DashMap` lookup is ~ns; the RPC
  path adds a UDS round trip (~10-50 us). The bench reports p50 /
  p99 hit latency under concurrent load and asserts it stays below
  100 us. Justification: WPAR-2 trades local cost for cross-worker
  consistency, and we want a visible number to defend that
  trade-off if it ever regresses.

## 13. Open questions for review

1. **Token-bucket sync interval**: 100 ms is a guess. Reviewer:
   acceptable, or do we need 50 ms? The documented guarantee is
   `100 ms * N_workers` of imprecision on the global rate (see
   § 2); halving the interval halves the imprecision at the cost
   of doubling the RPC rate for `RateLimitDelta`.
2. **Shmem table sizes**: 128 K slots = ~64 K live IPs at 50 % load.
   Lorica deployments typically see how many distinct client IPs
   concurrently? Confirm 128 K is enough.
3. **RPC channel ordering vs the existing single-flight pattern**:
   today Heartbeat / ConfigReload assume ordered single-flight.
   Switching to pipelined dispatcher is backward-compatible for
   messages that must complete in order (generation numbers in
   Prepare/Commit enforce the ordering explicitly, and Heartbeat
   has no ordering requirement); to verify in Phase 1 tests.

---

End of design draft. Implementation does not start until this is
reviewed.
