// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Per-route token bucket with worker-cache + supervisor-sync semantics.
//!
//! Implements the rate-limiter shape described in
//! `docs/architecture/worker-shared-state.md` § 6:
//!
//! - [`LocalBucket`] lives on every worker. `try_consume` is lock-free
//!   on the request hot path: a CAS loop on a single `AtomicI64` holding
//!   the cached token count. Successful consumption is recorded in a
//!   separate `delta` counter.
//! - A background task on the worker calls [`LocalBucket::take_delta`]
//!   every ~100 ms, pushes the accumulated consumption to the
//!   supervisor via the pipelined RPC framework, and calls
//!   [`LocalBucket::refresh`] with the authoritative token count from
//!   the reply.
//! - [`AuthoritativeBucket`] lives in the supervisor. It applies the
//!   time-based refill, subtracts the batched consumption pushed by
//!   each worker, and returns the current token count.
//!
//! The consistency bound is documented in the design: at `N_workers`
//! and a 100 ms sync interval, the global rate may exceed the
//! configured cap by up to `100 ms * N_workers` worth of tokens under
//! adversarial timing. Acceptable for rate-limit semantics (protection
//! against runaway traffic, not an SLA).

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;

/// Fixed-point scale for token counts inside [`AuthoritativeBucket`].
/// Gives 6 decimals of sub-token precision, enough to track fractional
/// refill over millisecond intervals without drift.
const SCALE: i64 = 1_000_000;

/// Worker-side cached view of a route-scoped token bucket.
///
/// `try_consume` is used on the request hot path; it is lock-free and
/// uses a CAS loop on a single atomic. Successful consumption is
/// recorded separately so a background task can drain it via
/// [`Self::take_delta`] and push it to the supervisor.
#[derive(Debug)]
pub struct LocalBucket {
    /// Cached tokens as of the last `refresh`. Never negative:
    /// `try_consume` rejects when `cur < cost` before the CAS, so a
    /// decrement can only go through when the result is non-negative.
    /// `AtomicI64` (rather than `AtomicU64`) is a future-proofing choice
    /// so the supervisor can signal a "debt" state (e.g. the worker
    /// overdrew between syncs) by passing a negative starting value to
    /// `refresh` — not exercised today but preserves the headroom.
    tokens: AtomicI64,
    /// Accumulated successful consumption since the last `take_delta`.
    delta: AtomicU64,
}

impl LocalBucket {
    /// Construct a bucket with an initial token count.
    pub fn new(initial_tokens: u32) -> Self {
        Self {
            tokens: AtomicI64::new(initial_tokens as i64),
            delta: AtomicU64::new(0),
        }
    }

    /// Attempt to consume `cost` tokens. Returns `true` on success,
    /// `false` if there were not enough tokens in the local cache.
    ///
    /// Lock-free: uses a CAS loop on `tokens`. Successful consumption
    /// increments `delta`; rejection does not.
    pub fn try_consume(&self, cost: u32) -> bool {
        let c = cost as i64;
        loop {
            let cur = self.tokens.load(Ordering::Acquire);
            if cur < c {
                return false;
            }
            match self.tokens.compare_exchange_weak(
                cur,
                cur - c,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
        self.delta.fetch_add(cost as u64, Ordering::Relaxed);
        true
    }

    /// Take and reset the accumulated consumption since last call.
    /// Called by the background sync task before pushing to the
    /// supervisor.
    ///
    /// Direction-of-error under concurrency: a `try_consume` racing
    /// with this `swap(0, AcqRel)` either (a) lands before the swap
    /// and its increment is included in the returned value, or (b)
    /// lands after and its increment survives for the next call. No
    /// consumption is ever dropped; the only effect of a race is a
    /// one-tick delay in the supervisor observing it. That makes the
    /// authoritative bucket slightly more permissive than strict
    /// semantics for ~100 ms — the direction the design § 6 already
    /// documents as acceptable for rate-limiting.
    ///
    /// The `min(u32::MAX)` clamp is defensive: a pathological workload
    /// would need to fire > 4 × 10^9 successful consumptions inside a
    /// single 100 ms sync window to trip it (unreachable on current
    /// hardware), but the clamp keeps the return type narrow.
    pub fn take_delta(&self) -> u32 {
        let d = self.delta.swap(0, Ordering::AcqRel);
        d.min(u32::MAX as u64) as u32
    }

    /// Overwrite the cached token count with the authoritative value
    /// returned by the supervisor. Called by the background sync task
    /// after a successful push.
    pub fn refresh(&self, tokens: u32) {
        self.tokens.store(tokens as i64, Ordering::Release);
    }

    /// Current cached token count. Exposed for observability/tests.
    pub fn tokens(&self) -> i64 {
        self.tokens.load(Ordering::Acquire)
    }

    /// Current accumulated delta without draining. For observability.
    pub fn peek_delta(&self) -> u64 {
        self.delta.load(Ordering::Acquire)
    }
}

/// Supervisor-side authoritative bucket. Applies time-based refill
/// lazily (on each `snapshot` or `apply_delta` call) and serialises
/// updates via a per-bucket `Mutex` — contention is bounded by the
/// number of workers × one RPC per sync tick, well below the
/// frequency where lock-free would matter.
#[derive(Debug)]
pub struct AuthoritativeBucket {
    capacity: u32,
    refill_per_sec: u32,
    state: Mutex<State>,
    /// Monotonic timestamp of the most recent `try_consume` /
    /// `apply_delta` / `snapshot`. Used by the caller's eviction task
    /// to prune buckets that have been idle longer than some TTL.
    last_activity_ns: AtomicU64,
}

#[derive(Debug)]
struct State {
    /// Tokens in fixed-point units (tokens * SCALE). Clamped to
    /// `[0, capacity * SCALE]` on every update.
    tokens_fp: i64,
    /// Timestamp of the last refill (monotonic ns).
    last_refill_ns: u64,
}

impl AuthoritativeBucket {
    /// Construct a new bucket full at `capacity`. `now_ns` anchors the
    /// refill clock; pass `lorica_shmem::now_ns()` on Linux.
    pub fn new(capacity: u32, refill_per_sec: u32, now_ns: u64) -> Self {
        Self {
            capacity,
            refill_per_sec,
            state: Mutex::new(State {
                tokens_fp: (capacity as i64).saturating_mul(SCALE),
                last_refill_ns: now_ns,
            }),
            last_activity_ns: AtomicU64::new(now_ns),
        }
    }

    /// Monotonic timestamp of the last operation on this bucket. Used
    /// by the caller to decide when an entry is idle enough to evict
    /// from the per-key map.
    pub fn last_activity_ns(&self) -> u64 {
        self.last_activity_ns.load(Ordering::Acquire)
    }

    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    pub fn refill_per_sec(&self) -> u32 {
        self.refill_per_sec
    }

    /// Return the current token count after applying any pending refill.
    pub fn snapshot(&self, now_ns: u64) -> u32 {
        self.last_activity_ns.store(now_ns, Ordering::Release);
        let mut s = self.state.lock().expect("bucket state poisoned");
        self.refill_locked(&mut s, now_ns);
        Self::whole_tokens(s.tokens_fp, self.capacity)
    }

    /// Apply a batched consumption from a worker. Returns the current
    /// (post-delta, post-refill) authoritative token count, which the
    /// caller ships back to the worker as its next `refresh` value.
    pub fn apply_delta(&self, consumed: u32, now_ns: u64) -> u32 {
        self.last_activity_ns.store(now_ns, Ordering::Release);
        let mut s = self.state.lock().expect("bucket state poisoned");
        self.refill_locked(&mut s, now_ns);
        let drain_fp = (consumed as i64).saturating_mul(SCALE);
        s.tokens_fp = (s.tokens_fp - drain_fp).max(0);
        Self::whole_tokens(s.tokens_fp, self.capacity)
    }

    /// Attempt to consume `cost` tokens in a single atomic step under
    /// the bucket lock. Applies the time-based refill first. Returns
    /// `true` on success (tokens drained), `false` if there were not
    /// enough tokens at this instant.
    ///
    /// Used in single-process mode (and in multi-worker mode without
    /// supervisor sync) where the request hot path drives the bucket
    /// directly instead of the worker-cache + delta-push pattern.
    pub fn try_consume(&self, cost: u32, now_ns: u64) -> bool {
        self.last_activity_ns.store(now_ns, Ordering::Release);
        let mut s = self.state.lock().expect("bucket state poisoned");
        self.refill_locked(&mut s, now_ns);
        let cost_fp = (cost as i64).saturating_mul(SCALE);
        if s.tokens_fp >= cost_fp {
            s.tokens_fp -= cost_fp;
            true
        } else {
            false
        }
    }

    fn refill_locked(&self, s: &mut State, now_ns: u64) {
        if now_ns <= s.last_refill_ns {
            return;
        }
        let elapsed_ns = now_ns - s.last_refill_ns;
        // Tokens added (fp) = refill_per_sec * elapsed_ns / 1_000
        //                   = refill_per_sec * elapsed_ns * SCALE / 1_000_000_000
        // (since SCALE / 1_000_000_000 == 1 / 1_000)
        let add_fp = (self.refill_per_sec as i64).saturating_mul((elapsed_ns / 1_000) as i64);
        let cap_fp = (self.capacity as i64).saturating_mul(SCALE);
        s.tokens_fp = (s.tokens_fp.saturating_add(add_fp)).min(cap_fp);
        s.last_refill_ns = now_ns;
    }

    fn whole_tokens(fp: i64, cap: u32) -> u32 {
        let t = fp.max(0) as u64 / SCALE as u64;
        t.min(cap as u64) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE_SEC_NS: u64 = 1_000_000_000;

    #[test]
    fn local_try_consume_success_and_rejection() {
        let b = LocalBucket::new(10);
        assert!(b.try_consume(3));
        assert!(b.try_consume(5));
        assert_eq!(b.peek_delta(), 8);
        assert!(!b.try_consume(3)); // only 2 left
        assert!(b.try_consume(2));
        assert!(!b.try_consume(1));
    }

    #[test]
    fn local_take_delta_resets() {
        let b = LocalBucket::new(100);
        for _ in 0..10 {
            assert!(b.try_consume(1));
        }
        assert_eq!(b.take_delta(), 10);
        assert_eq!(b.peek_delta(), 0);
    }

    #[test]
    fn local_refresh_overwrites_tokens_not_delta() {
        let b = LocalBucket::new(100);
        assert!(b.try_consume(10));
        assert_eq!(b.tokens(), 90);
        assert_eq!(b.peek_delta(), 10);
        b.refresh(50);
        assert_eq!(b.tokens(), 50);
        // delta unchanged until take_delta
        assert_eq!(b.peek_delta(), 10);
    }

    #[test]
    fn local_try_consume_under_concurrent_threads() {
        use std::sync::Arc;
        use std::thread;
        let b = Arc::new(LocalBucket::new(1000));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let b = b.clone();
            handles.push(thread::spawn(move || {
                let mut ok = 0u32;
                for _ in 0..500 {
                    if b.try_consume(1) {
                        ok += 1;
                    }
                }
                ok
            }));
        }
        let total_ok: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(
            total_ok, 1000,
            "exactly `capacity` consumptions may succeed"
        );
        assert_eq!(b.take_delta(), 1000);
        assert_eq!(b.tokens(), 0);
    }

    #[test]
    fn authoritative_refill_linearly_over_time() {
        // capacity 100, refill 50/s, start empty.
        let b = AuthoritativeBucket::new(100, 50, 0);
        // Drain to zero.
        assert_eq!(b.apply_delta(100, 0), 0);
        // 1 second later: 50 tokens refilled.
        assert_eq!(b.snapshot(ONE_SEC_NS), 50);
        // Another second: reaches capacity (100, not 150).
        assert_eq!(b.snapshot(2 * ONE_SEC_NS), 100);
    }

    #[test]
    fn authoritative_delta_clamps_at_zero() {
        let b = AuthoritativeBucket::new(100, 0, 0);
        assert_eq!(b.apply_delta(200, 0), 0);
        // No refill rate, no clock movement -> still 0.
        assert_eq!(b.snapshot(1_000_000_000_000), 0);
    }

    #[test]
    fn authoritative_monotonic_clock_rewind_is_a_noop() {
        let b = AuthoritativeBucket::new(100, 10, 1_000_000_000);
        assert_eq!(b.apply_delta(50, 1_000_000_000), 50);
        // Clock goes backwards (should never happen with CLOCK_MONOTONIC
        // but we must be robust to it).
        assert_eq!(b.snapshot(900_000_000), 50);
    }

    #[test]
    fn authoritative_applies_delta_after_refill_not_before() {
        // capacity 100, refill 100/s, start full, drain 10 then wait
        // 0.5 s and apply another 10. Second apply should see the
        // refill first (+50) then subtract -> 100 - 10 - 10 + 50 = 130
        // clamped to capacity -> 100. But wait: 100 -10 = 90, refill
        // +50 over 500ms = 90+50 = 140 clamped to 100, then -10 = 90.
        let b = AuthoritativeBucket::new(100, 100, 0);
        assert_eq!(b.apply_delta(10, 0), 90);
        assert_eq!(b.apply_delta(10, 500_000_000), 90);
    }

    #[test]
    fn authoritative_try_consume_refills_and_rejects_when_empty() {
        // capacity 5, refill 10/s. Start full.
        let b = AuthoritativeBucket::new(5, 10, 0);
        // Drain exactly.
        for _ in 0..5 {
            assert!(b.try_consume(1, 0));
        }
        // Now empty.
        assert!(!b.try_consume(1, 0));
        // 200 ms later: 2 tokens refilled.
        assert!(b.try_consume(1, 200_000_000));
        assert!(b.try_consume(1, 200_000_000));
        assert!(!b.try_consume(1, 200_000_000));
    }

    #[test]
    fn whole_tokens_clamps_to_capacity() {
        let b = AuthoritativeBucket::new(50, 100, 0);
        // Simulate over-refill via very large elapsed time.
        assert_eq!(b.snapshot(10 * ONE_SEC_NS), 50);
    }
}
