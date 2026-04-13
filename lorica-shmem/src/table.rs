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

//! Fixed-layout open-addressing hashtable over shared memory.
//!
//! Each slot is 64 bytes (one cache line) and carries three independent
//! `AtomicU64` fields: the occupied key, the counter value, and the last
//! update timestamp. The table has no seqlock: readers consume only
//! `value`, and each `AtomicU64` is naturally atomic, so no torn reads
//! occur. Writers race on `value.fetch_add` (commutative) and on a
//! best-effort `last_update_ns.store`. See design doc § 5.2, § 5.3, § 8.
//!
//! Collision resolution: linear probing up to `MAX_PROBE = 16`. At load
//! factor 50 % (64 K entries in 128 K slots) with a good hash, the
//! probability of exceeding `MAX_PROBE` is well under `1e-9`.

use std::sync::atomic::{AtomicU64, Ordering};

/// Maximum probe distance before we give up and return a poison value.
/// Chosen so the failure probability is vanishing under the intended
/// load factor (50 %).
pub const MAX_PROBE: usize = 16;

/// Sentinel returned by [`AtomicHashTable::increment`] when the probe
/// chain is saturated. Callers treat it as "limit reached" so the
/// fail-safe semantics deny the request.
pub const SATURATED: u64 = u64::MAX;

/// A single table slot. 64-byte aligned so each slot occupies one
/// cache line, eliminating false sharing between neighbouring entries.
///
/// ABI is fixed: this type is mapped across process boundaries via
/// shared memory. Do not reorder or resize the fields.
#[repr(C, align(64))]
pub struct Slot {
    /// Occupied key. `0` means empty; any non-zero value is a tagged
    /// hash of the key (LSB set to 1 by [`tagged_hash`]). CAS from `0`
    /// to `h` claims the slot; CAS from `h` to `0` releases it.
    pub key: AtomicU64,
    /// Counter value. Under concurrent writers, updated via
    /// `fetch_add`; each read is a single `AtomicU64::load`.
    pub value: AtomicU64,
    /// Last-update timestamp in nanoseconds since some monotonic epoch
    /// (chosen by the caller via [`now_ns`]). Best-effort: racing
    /// writers overwrite each other, but the stored value is always a
    /// real timestamp from one of them and is sufficient for the
    /// eviction tick (5 min).
    pub last_update_ns: AtomicU64,
}

/// Ensure `Slot` stays exactly one cache line wide.
const _: () = {
    assert!(std::mem::size_of::<Slot>() == 64);
    assert!(std::mem::align_of::<Slot>() == 64);
};

impl Default for Slot {
    fn default() -> Self {
        Self::new()
    }
}

impl Slot {
    pub const fn new() -> Self {
        Self {
            key: AtomicU64::new(0),
            value: AtomicU64::new(0),
            last_update_ns: AtomicU64::new(0),
        }
    }
}

/// Fixed-capacity atomic hashtable with open addressing.
///
/// `N` must be a power of two. The compile-time assertions enforce that.
#[repr(C, align(64))]
pub struct AtomicHashTable<const N: usize> {
    pub slots: [Slot; N],
}

impl<const N: usize> AtomicHashTable<N> {
    /// Construct an empty table. Not typically used directly — in a
    /// shared-memory region the bytes are zero-initialised by
    /// `ftruncate` and cast to this layout, which is equivalent.
    pub fn new_zeroed() -> Box<Self> {
        // Build via Box<MaybeUninit<...>> to avoid requiring const
        // initialisers for the whole array. Zero-initialised bytes are
        // valid for every field (AtomicU64::new(0) is bitwise zero).
        let layout = std::alloc::Layout::new::<Self>();
        // SAFETY: layout has non-zero size; alloc_zeroed returns zeroed
        // memory of that layout; AtomicU64 bitwise-zero is the valid
        // value 0. We never expose the Box<Self> without initialised
        // contents.
        unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<Self>();
            if ptr.is_null() {
                std::alloc::handle_alloc_error(layout);
            }
            Box::from_raw(ptr)
        }
    }

    /// Atomically add `by` to the counter for `tagged_hash`, claiming a
    /// slot via CAS if necessary. Returns the new counter value, or
    /// [`SATURATED`] if the probe chain is saturated.
    ///
    /// `tagged_hash` must be non-zero. Use [`tagged_hash`] to derive it
    /// from a user key.
    pub fn increment(&self, tagged_hash: u64, by: u64, now_ns: u64) -> u64 {
        debug_assert!(tagged_hash != 0, "tagged_hash must be non-zero");
        let mask = N - 1;
        let start = (tagged_hash as usize) & mask;
        for probe in 0..MAX_PROBE {
            let i = (start + probe) & mask;
            let s = &self.slots[i];
            let cur = s.key.load(Ordering::Acquire);
            if cur == 0 {
                // Try to claim the slot for this key.
                if s.key
                    .compare_exchange(0, tagged_hash, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    // Slot may have been evicted; reset counter.
                    s.value.store(by, Ordering::Release);
                    s.last_update_ns.store(now_ns, Ordering::Release);
                    return by;
                }
                // Lost the race; re-read this slot (might be us now).
                continue;
            }
            if cur == tagged_hash {
                // Existing owner: commutative atomic add.
                let new = s.value.fetch_add(by, Ordering::AcqRel).wrapping_add(by);
                s.last_update_ns.store(now_ns, Ordering::Release);
                return new;
            }
            // Collision with a different key: probe next.
        }
        tracing::warn!(
            table_slots = N,
            start_slot = start,
            "shmem hashtable saturated at probe limit"
        );
        SATURATED
    }

    /// Read the counter for `tagged_hash`. Returns `None` if the key is
    /// not present within `MAX_PROBE` slots.
    pub fn read(&self, tagged_hash: u64) -> Option<u64> {
        debug_assert!(tagged_hash != 0, "tagged_hash must be non-zero");
        let mask = N - 1;
        let start = (tagged_hash as usize) & mask;
        for probe in 0..MAX_PROBE {
            let i = (start + probe) & mask;
            let s = &self.slots[i];
            let cur = s.key.load(Ordering::Acquire);
            if cur == 0 {
                return None;
            }
            if cur == tagged_hash {
                return Some(s.value.load(Ordering::Acquire));
            }
        }
        None
    }

    /// Read the last-update timestamp for `tagged_hash`, if present.
    /// Exposed for the eviction walker.
    pub fn last_update(&self, tagged_hash: u64) -> Option<u64> {
        debug_assert!(tagged_hash != 0);
        let mask = N - 1;
        let start = (tagged_hash as usize) & mask;
        for probe in 0..MAX_PROBE {
            let i = (start + probe) & mask;
            let s = &self.slots[i];
            let cur = s.key.load(Ordering::Acquire);
            if cur == 0 {
                return None;
            }
            if cur == tagged_hash {
                return Some(s.last_update_ns.load(Ordering::Acquire));
            }
        }
        None
    }

    /// Release the slot for `tagged_hash` by CAS-ing its key from
    /// `tagged_hash` back to `0`. Returns `true` if the slot was
    /// released, `false` if the key was not present or a concurrent
    /// writer claimed it already. Subsequent `increment` on the same
    /// key will reclaim a fresh slot with `value = by`.
    ///
    /// Used by the WAF auto-ban path to clear a counter after a ban
    /// has been issued — a repeat offender after ban expiry starts
    /// counting from zero rather than inheriting the previous run.
    pub fn reset(&self, tagged_hash: u64) -> bool {
        debug_assert!(tagged_hash != 0);
        let mask = N - 1;
        let start = (tagged_hash as usize) & mask;
        for probe in 0..MAX_PROBE {
            let i = (start + probe) & mask;
            let s = &self.slots[i];
            let cur = s.key.load(Ordering::Acquire);
            if cur == 0 {
                return false;
            }
            if cur == tagged_hash {
                return s
                    .key
                    .compare_exchange(tagged_hash, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok();
            }
        }
        false
    }

    /// Number of slots (capacity).
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Walk every slot, invoking `visit` with `(index, &Slot)`. Used by
    /// the eviction task.
    pub fn for_each_slot(&self, mut visit: impl FnMut(usize, &Slot)) {
        for (i, s) in self.slots.iter().enumerate() {
            visit(i, s);
        }
    }
}

/// Tag a raw hash so the LSB is set, reserving `0` as the empty sentinel.
///
/// Callers compute `h = siphash13_u64(hash_key, ip_or_key)` and pass the
/// result through this function before handing it to [`AtomicHashTable`].
#[inline]
pub fn tagged_hash(raw: u64) -> u64 {
    raw | 1
}

/// Current monotonic timestamp in nanoseconds, reading the Linux
/// kernel's `CLOCK_MONOTONIC` via `clock_gettime`.
///
/// Chosen over `SystemTime` / `UNIX_EPOCH` so a wall-clock adjustment
/// (NTP step, manual `settimeofday`, leap second) cannot make
/// `last_update_ns` appear in the future relative to the eviction
/// walker's `now_ns`, which would stall eviction until the clock
/// caught up.
///
/// `CLOCK_MONOTONIC`'s reference is the kernel's boot time, so values
/// written by the supervisor and by forked workers are directly
/// comparable — both processes read the same clock.
pub fn now_ns() -> u64 {
    use nix::sys::time::TimeValLike;
    use nix::time::{clock_gettime, ClockId};
    // clock_gettime(CLOCK_MONOTONIC) cannot fail in practice on Linux
    // with a valid clockid. Fall back to 0 if it ever does; eviction
    // walker will simply see every slot as "fresh" during that tick.
    clock_gettime(ClockId::CLOCK_MONOTONIC)
        .map(|ts| {
            // tv_nsec is i64 but POSIX constrains CLOCK_MONOTONIC to
            // 0..=999_999_999 — never negative in practice — so the
            // `as u64` cast is well-defined.
            (ts.num_seconds() as u64)
                .saturating_mul(1_000_000_000)
                .saturating_add(ts.tv_nsec() as u64)
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn increment_and_read_single_threaded() {
        let t: Box<AtomicHashTable<1024>> = AtomicHashTable::new_zeroed();
        let h = tagged_hash(12345);
        assert_eq!(t.read(h), None);
        assert_eq!(t.increment(h, 1, 100), 1);
        assert_eq!(t.increment(h, 4, 200), 5);
        assert_eq!(t.read(h), Some(5));
        assert_eq!(t.last_update(h), Some(200));
    }

    #[test]
    fn collision_probes_next_slot() {
        // N=1024, two keys that deliberately map to the same start.
        let t: Box<AtomicHashTable<1024>> = AtomicHashTable::new_zeroed();
        // Force collision on the same start slot: both hashes share
        // the low 10 bits (0x401) but differ in the high bits.
        let h1 = tagged_hash(0x0000_0000_0000_0401);
        let h2 = tagged_hash(0x8000_0000_0000_0401);
        assert_eq!((h1 as usize) & 1023, (h2 as usize) & 1023);
        assert_ne!(h1, h2);
        t.increment(h1, 3, 1);
        t.increment(h2, 7, 2);
        assert_eq!(t.read(h1), Some(3));
        assert_eq!(t.read(h2), Some(7));
    }

    #[test]
    fn saturation_returns_sentinel() {
        // A tiny table where we force the entire probe chain to fill.
        let t: Box<AtomicHashTable<16>> = AtomicHashTable::new_zeroed();
        // Tag every hash with the same low bits to force probe-chain
        // collisions.
        for i in 0..MAX_PROBE as u64 {
            let h = tagged_hash((i << 4) | 1); // low 4 bits all 1
            t.increment(h, 1, 0);
        }
        let h_extra = tagged_hash(((MAX_PROBE as u64) << 4) | 1);
        assert_eq!(t.increment(h_extra, 1, 0), SATURATED);
    }

    #[test]
    fn concurrent_writers_commutative_sum() {
        let t: Arc<AtomicHashTable<1024>> = Arc::from(AtomicHashTable::new_zeroed());
        let h = tagged_hash(0xdead_beef | 1);
        let mut handles = Vec::new();
        for _ in 0..8 {
            let t = t.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    t.increment(h, 1, 0);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(t.read(h), Some(8 * 1000));
    }

    #[test]
    fn concurrent_writers_different_keys_no_crosstalk() {
        let t: Arc<AtomicHashTable<1024>> = Arc::from(AtomicHashTable::new_zeroed());
        let mut handles = Vec::new();
        // Shift tid left by 1 so `tagged_hash` (which ORs in the LSB)
        // cannot collapse neighbouring tids onto the same tag.
        for tid in 0..16u64 {
            let t = t.clone();
            handles.push(thread::spawn(move || {
                let h = tagged_hash(0xA000_0000 + (tid << 1));
                for _ in 0..500 {
                    t.increment(h, 1, 0);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        for tid in 0..16u64 {
            let h = tagged_hash(0xA000_0000 + (tid << 1));
            assert_eq!(t.read(h), Some(500), "tid {tid}");
        }
    }

    #[test]
    fn reclaim_after_cas_to_zero_resets_counter() {
        let t: Box<AtomicHashTable<1024>> = AtomicHashTable::new_zeroed();
        let h1 = tagged_hash(1 | 1);
        let _ = t.increment(h1, 42, 100);
        assert_eq!(t.read(h1), Some(42));

        // Simulate eviction: CAS key back to 0 on its occupied slot.
        let mask = t.capacity() - 1;
        let start = (h1 as usize) & mask;
        let mut evicted = false;
        for probe in 0..MAX_PROBE {
            let s = &t.slots[(start + probe) & mask];
            if s.key.load(Ordering::Acquire) == h1
                && s.key
                    .compare_exchange(h1, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                evicted = true;
                break;
            }
        }
        assert!(evicted);

        // Reuse with a different key, starting fresh.
        let h2 = tagged_hash(0x5555 | 1);
        assert_eq!(t.increment(h2, 1, 200), 1);
        assert_eq!(t.read(h1), None);
    }

    #[test]
    fn slot_is_cache_line_sized() {
        assert_eq!(std::mem::size_of::<Slot>(), 64);
        assert_eq!(std::mem::align_of::<Slot>(), 64);
    }

    #[test]
    fn reset_releases_slot_and_next_increment_starts_fresh() {
        let t: Box<AtomicHashTable<1024>> = AtomicHashTable::new_zeroed();
        let h = tagged_hash(0xc0ffee);
        assert_eq!(t.increment(h, 10, 1), 10);
        assert_eq!(t.read(h), Some(10));
        assert!(t.reset(h));
        assert_eq!(t.read(h), None);
        // Next increment re-claims with a fresh counter.
        assert_eq!(t.increment(h, 3, 2), 3);
    }

    #[test]
    fn reset_returns_false_for_absent_key() {
        let t: Box<AtomicHashTable<1024>> = AtomicHashTable::new_zeroed();
        let h = tagged_hash(0xabcd);
        assert!(!t.reset(h));
    }
}
