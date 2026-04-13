# Worker shared-state architecture

Author: Romain G.
Status: Design draft (review before implementation).

This document specifies the cross-process shared-state mechanisms
introduced to close the worker-parity audit findings WPAR-1 (rate
limits), WPAR-2 (forward-auth verdict cache), WPAR-3 (circuit
breaker), WPAR-7 (metrics freshness) and WPAR-8 (config reload
window). It is the design floor for ~13 days of implementation work
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
- **Strict consistency for token buckets**. ~100 ms of skew per
  worker is acceptable for rate-limit semantics.

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
    tx: mpsc::Sender<Command>,
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
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_))   => Err(ChannelError::Closed),
            Err(_) => {
                self.inflight.remove(&seq);
                Err(ChannelError::Timeout)
            }
        }
    }
}
```

A single background task owns the read half of the socketpair and
dispatches incoming `Response` to the matching oneshot from
`inflight`.

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

    pub waf_flood:    AtomicHashTable<128 * 1024>,  // ~3 MiB
    pub waf_auto_ban: AtomicHashTable<128 * 1024>,  // ~3 MiB
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
    /// last update timestamp (monotonic ns since boot)
    pub last_update_ns: AtomicU64,
    /// version counter (incremented on each successful update; even =
    /// stable, odd = mid-update). Used as a seqlock.
    pub version: AtomicU64,
}
```

Total: 32 B / slot * 128K slots * 2 tables = 8 MiB. Trivial.

### 5.3 Atomic operations

Two operations:

```rust
pub fn increment(&self, key: u64, by: u64) -> u64 {
    let h = siphash13(key) | 1;          // ensure non-zero
    let start = (h as usize) & (N - 1);
    for probe in 0..MAX_PROBE {
        let i = (start + probe) & (N - 1);
        let s = &self.slots[i];
        let cur_key = s.key.load(Ordering::Acquire);
        if cur_key == 0 {
            // Try to claim
            if s.key.compare_exchange(0, h, Acquire, Relaxed).is_ok() {
                s.value.store(by, Release);
                s.last_update_ns.store(now_ns(), Release);
                s.version.fetch_add(2, Release);  // even -> even
                return by;
            }
            continue;  // someone else claimed; re-read
        }
        if cur_key == h {
            // Existing: update in place. Bump version odd-then-even.
            s.version.fetch_add(1, Release);  // mark mid-update
            let new = s.value.fetch_add(by, AcqRel) + by;
            s.last_update_ns.store(now_ns(), Release);
            s.version.fetch_add(1, Release);  // mark stable
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
    let h = siphash13(key) | 1;
    let start = (h as usize) & (N - 1);
    for probe in 0..MAX_PROBE {
        let i = (start + probe) & (N - 1);
        let s = &self.slots[i];
        let k = s.key.load(Acquire);
        if k == 0 { return None; }
        if k != h { continue; }
        // Seqlock read: spin while version is odd, retry if it changed
        loop {
            let v0 = s.version.load(Acquire);
            if v0 & 1 != 0 { std::hint::spin_loop(); continue; }
            let val = s.value.load(Acquire);
            let v1 = s.version.load(Acquire);
            if v0 == v1 { return Some(val); }
        }
    }
    None
}
```

`MAX_PROBE = 16`. With load factor 50% (64K live entries on 128K
slots) and a good hash, P(probe > 16) is well under 1e-9.

### 5.4 Eviction

Background task on the supervisor walks every slot once per minute.
For each slot whose `last_update_ns` is older than 5 min and whose
`value` is below the active threshold, CAS `key` from `h` to 0 to
release the slot. Workers will not see partial deletions thanks to
the seqlock.

### 5.5 Crash safety

If the supervisor crashes mid-`increment`, the slot can be left with
an odd `version`. Workers spin briefly in the seqlock and retry. If
the supervisor never restarts, workers fall back to per-worker
behaviour after a timeout (see § 7).

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

Same shape. `BreakerQuery(route, backend)` -> `bool` decides
availability; `BreakerReport(route, backend, success)` updates the
supervisor's state machine. Supervisor reuses the existing scoped
breaker logic, just relocated.

### WPAR-7 (metrics pull)

`/metrics` handler issues a `MetricsRequest` to every worker via
RPC, awaits with `timeout(Duration::from_millis(500))`, falls back
to last cached value for non-responding workers. Concurrency dedup
via `Mutex<watch::Receiver>` (§ 4.5).

### WPAR-8 (config reload)

Supervisor coordinator:

```rust
let gen = next_generation();
join_all(workers.map(|w| w.rpc.config_reload_prepare(gen))).await;
// If all Ok:
join_all(workers.map(|w| w.rpc.config_reload_commit(gen))).await;
// If any Err in prepare phase:
//   broadcast a no-op (drop pending). Operators see the failure
//   surfaced via API.
```

Worker side: `ConfigReloadPrepare` reads the DB, builds a new
`ProxyConfig`, stores it in `ctx.pending_proxy_config`, replies Ok.
`ConfigReloadCommit` does the atomic ArcSwap. Window where workers
diverge collapses to RTT skew (microseconds on local UDS) instead of
10-50 ms.

## 8. Concurrency invariants

Stated explicitly so reviewers can sanity-check.

1. **Shmem slot**: the seqlock guarantees readers either observe the
   pre-update or post-update value, never a torn read. Writers do
   not coordinate with each other beyond the slot's atomic ops; two
   concurrent `increment` on the same key race on `value.fetch_add`,
   which is correct (commutative).
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

Recap of the 13-day plan from the architecture discussion:

| Phase | Deliverable | Effort |
|---|---|---|
| 1 | RPC framework: extend `lorica-command` (pipelining, dispatch, dedup), tests | 2 d |
| 2 | `lorica-shmem` crate: memfd_create, FD passing, `AtomicHashTable`, eviction, crash-safety tests | 3 d |
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
  - p99 latency vs single-process baseline (target: < 10% overhead)
  - rate-limit precision (configured 100 req/s -> measured <= 105 req/s globally, not 400)
  - shmem hashtable saturation rate (target: 0)

## 13. Open questions for review

1. **Token-bucket sync interval**: 100 ms is a guess. Reviewer:
   acceptable, or do we need 50 ms?
2. **Shmem table sizes**: 128 K slots = ~64 K live IPs at 50 % load.
   Lorica deployments typically see how many distinct client IPs
   concurrently? Confirm 128 K is enough.
3. **RPC channel ordering vs the existing single-flight pattern**:
   today Heartbeat / ConfigReload assume ordered single-flight.
   Switching to pipelined dispatcher should be backward-compatible
   (those messages still complete in order from the supervisor's
   point of view) but we need to verify.
4. **Crash safety of the seqlock under high contention**: stress
   test in Phase 2.

---

End of design draft. Implementation does not start until this is
reviewed.
