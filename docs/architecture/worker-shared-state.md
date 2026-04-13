# Worker shared-state architecture

Author: Romain G.
Status: Design draft (review before implementation).

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
2. **High-perf hot path**: simple per-IP counters (WAF flood, auto-ban)
   must not pay an IPC round trip per request. Token bucket state
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

    pub waf_flood:    AtomicHashTable<128 * 1024>,  // 8 MiB
    pub waf_auto_ban: AtomicHashTable<128 * 1024>,  // 8 MiB
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

`MAX_PROBE = 16`. With load factor 50% (64K live entries on 128K
slots) and a good hash, P(probe > 16) is well under 1e-9.

### 5.4 Eviction

Background task on the supervisor walks every slot once per minute.
A slot is evicted when `last_update_ns` is older than 5 minutes:
the supervisor CAS's `key` from `h` to 0 to release the slot. No
separate "active threshold" - staleness by age is the only
criterion, and it works uniformly for monotonically-growing
counters (WAF flood, WAF auto-ban) and hypothetical decaying
counters alike.

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

Two halves:

**(a) WAF flood + auto-ban** -> shmem (component B). Per-IP:

```rust
// On every WAF block from the request hot path:
let key = siphash13(client_ip);
let count = state.shmem.waf_auto_ban.increment(key, 1);
if count >= settings.waf_ban_threshold {
    state.ban_list.insert(client_ip, ban_until);
}
```

No IPC, no lock. ~ns per call.

**(b) Per-route token buckets** -> worker-cached + supervisor sync
(component C). Worker hot path:

```rust
let bucket = local_buckets.get_or_init((route_id, ip), defaults);
let allowed = bucket.try_consume(1);                // local atomic
if !allowed { return Err(RateLimited); }
// background task pushes accumulated `consumed` deltas every 100 ms
// via RPC.RateLimitDelta and refreshes local view from authoritative.
```

Supervisor maintains the authoritative bucket per `(route_id, ip)`.
On `RateLimitDelta`, sums consumed across workers, applies to the
authoritative state, returns a refreshed snapshot. Worker overwrites
its local view with the snapshot. Imprecision bounded at
`100 ms × N_workers` worth of in-flight consumption, in the
direction "could let a few extra requests through". Acceptable.

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

## 10. Migration story

- Layout changes -> bump `layout_version` in the shmem header,
  document in `docs/BUMP-CHECKLIST.md`. No online migration.
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
