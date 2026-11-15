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
//! Collision resolution: linear probing over a window of `MAX_PROBE`
//! slots. A key whose whole window holds other keys is refused with
//! [`SATURATED`]; the window is sized so that this stays rare at the
//! capacity [`WAF_SLOTS`](crate::region::WAF_SLOTS) documents, and a
//! fill test holds it there.
//!
//! Eviction and `reset` release a slot by clearing its key, which can
//! free a slot in front of keys placed further along the same window.
//! Lookups therefore never stop at a free slot: `read` sums every slot
//! of the window holding the key, and `increment` searches the whole
//! window before it claims. A claim racing a release can still give a
//! key a second slot; the sum keeps its count whole, and the slot no
//! longer written to ages out through eviction like any idle one.
//!
//! A claim holds the slot exclusively while it sets the count: it moves
//! the key from `0` to `CLAIMING`, stores the count, then publishes the
//! key. Since 1.10.3 a claim had instead subtracted the count it read
//! before taking the slot, which went wrong whenever another key claimed
//! and released the slot in between (an ABA on the free `0`): the new
//! key started off by the difference, wrapping to near `u64::MAX` when
//! the difference was negative. A claimer that dies mid-claim leaves the
//! slot `CLAIMING` with its stale stamp until eviction releases it;
//! writers waiting on it give up after a bounded spin.

use std::sync::atomic::{AtomicU64, Ordering};

/// Number of slots a key may occupy, from its start slot on. Refusals
/// grow steeply with the load factor and fall steeply with the window:
/// at half load, a window of 16 refused about one key in 3 000 and a
/// window of 32 about one in 300 000. The cost is the window scan an
/// `increment` of a new key and every `read` make, which only WAF
/// violations pay. Not part of the shared layout: each supervisor
/// creates its own region at startup (the memfd is close-on-exec, so a
/// hot upgrade's new supervisor never inherits the old one), and its
/// workers exec its own executable.
pub const MAX_PROBE: usize = 32;

/// Sentinel returned by [`AtomicHashTable::increment`] when every slot
/// of the key's probe window holds another key. Nothing was counted,
/// and the key reads as absent until eviction frees a slot in its
/// window, so a refusal fails open.
///
/// In Lorica the writers are the workers' auto-ban paths. For the WAF
/// auto-ban the request was already blocked by the WAF, and a refusal
/// only means the violation does not count toward a ban; it is counted
/// on the `lorica_waf_auto_ban_uncounted_total` metric, and the
/// supervisor reads a refused client as having no violations, so no
/// ban follows. The rate-limit auto-ban is the same with a request the
/// rate limit already refused, counted on
/// `lorica_rate_limit_auto_ban_uncounted_total`.
pub const SATURATED: u64 = u64::MAX;

/// A single table slot. 64-byte aligned so each slot occupies one
/// cache line, eliminating false sharing between neighbouring entries.
///
/// ABI is fixed: this type is mapped across process boundaries via
/// shared memory. Do not reorder or resize the fields.
#[repr(C, align(64))]
pub struct Slot {
    /// Occupied key. `0` means empty; an odd value is a tagged hash of
    /// the key (LSB set to 1 by [`tagged_hash`]); the even `CLAIMING`
    /// marks a claim in flight. A claim CASes `0` to `CLAIMING`, sets
    /// the count, then CASes to `h`; a release CASes `h` back to `0`.
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

/// A cell an open-addressing probe walks: one key word, `0` when free.
/// The WAF tables' [`Slot`] and the stream-caps region's cells share the
/// probe through it, so a window means the same thing in every table.
pub(crate) trait Keyed {
    /// The cell's key word.
    fn key(&self) -> &AtomicU64;
}

impl Keyed for Slot {
    fn key(&self) -> &AtomicU64 {
        &self.key
    }
}

/// Indices of the [`MAX_PROBE`] cells `tagged_hash` may occupy in a table
/// of `len` cells, in probe order. `len` is a power of two holding at
/// least one window, so a window never visits a cell twice; the fixed
/// tables assert it at compile time, the sized ones when they are laid
/// out.
pub(crate) fn window_indices(len: usize, tagged_hash: u64) -> impl Iterator<Item = usize> {
    debug_assert!(len.is_power_of_two() && len >= MAX_PROBE);
    let mask = len - 1;
    let start = (tagged_hash as usize) & mask;
    (0..MAX_PROBE).map(move |probe| (start + probe) & mask)
}

/// The cells of `tagged_hash`'s window, in probe order.
pub(crate) fn window<C>(cells: &[C], tagged_hash: u64) -> impl Iterator<Item = &C> {
    window_indices(cells.len(), tagged_hash).map(move |i| &cells[i])
}

/// The cells of the window currently holding `tagged_hash`. Lookups
/// never stop at a free cell: a release frees cells in the middle of a
/// window, and a key placed behind one is still there.
pub(crate) fn holding<C: Keyed>(cells: &[C], tagged_hash: u64) -> impl Iterator<Item = &C> {
    window(cells, tagged_hash).filter(move |c| c.key().load(Ordering::Acquire) == tagged_hash)
}

/// Key word of a slot being claimed. Even, so no tagged hash equals it:
/// readers, writers of any key and `reset` all see a key that is not
/// theirs, and only the claimer touches the slot until it publishes.
pub(crate) const CLAIMING: u64 = 2;

/// How long a writer waits, in spins, for a claim in flight on a slot it
/// wants to weigh. A claim is three stores, so the wait only runs long
/// when the claimer was descheduled; past the bound the writer probes on,
/// which can give its key a second slot, summed like any other.
const CLAIM_SPINS: u32 = 4_096;

/// [`AtomicHashTable::increment`] over a slice of slots.
pub(crate) fn increment(slots: &[Slot], tagged_hash: u64, by: u64, now_ns: u64) -> u64 {
    debug_assert!(
        tagged_hash != 0 && tagged_hash != CLAIMING,
        "tagged_hash must be a tagged hash"
    );
    // The whole window is searched before anything is claimed. A
    // release frees a slot in the middle of the window, so the first
    // free slot is no sign that the key lies nowhere beyond it, and
    // claiming it would split the key's count across two slots.
    if let Some(s) =
        window(slots, tagged_hash).find(|s| s.key.load(Ordering::Acquire) == tagged_hash)
    {
        return add(s, by, now_ns);
    }
    for s in window(slots, tagged_hash) {
        loop {
            match s.key.load(Ordering::Acquire) {
                0 => {
                    // Stamped before the claim: the slot still carries
                    // its previous occupant's stamp (0 if never used),
                    // and an eviction pass that saw the claim beside that
                    // stale stamp would release it at once. A claim lost
                    // to another key leaves it a fresher stamp, which at
                    // worst delays that slot's eviction by one pass.
                    s.last_update_ns.store(now_ns, Ordering::Release);
                    if s.key
                        .compare_exchange(0, CLAIMING, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        // A released slot keeps the count it had, and no
                        // one adds to a slot while it reads CLAIMING, so
                        // the count is set, not adjusted: an adjustment
                        // computed from a value read before the claim was
                        // wrong whenever another key claimed and released
                        // the slot in between.
                        s.value.store(by, Ordering::Release);
                        if s.key
                            .compare_exchange(
                                CLAIMING,
                                tagged_hash,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_ok()
                        {
                            return by;
                        }
                        // Evicted as a claim left unpublished: look again.
                    }
                }
                // Often this same key, claimed by another writer: weigh
                // what it publishes rather than probing on.
                CLAIMING => {
                    if !claim_settles(s) {
                        break;
                    }
                }
                k if k == tagged_hash => return add(s, by, now_ns),
                _ => break,
            }
        }
    }
    tracing::warn!(
        table_slots = slots.len(),
        start_slot = (tagged_hash as usize) & (slots.len() - 1),
        "shmem hashtable saturated at probe limit"
    );
    SATURATED
}

/// Wait for the claim in flight on `s` to publish its key or be evicted.
/// Returns `false` if it is still in flight after [`CLAIM_SPINS`].
fn claim_settles(s: &Slot) -> bool {
    for spin in 1..=CLAIM_SPINS {
        if s.key.load(Ordering::Acquire) != CLAIMING {
            return true;
        }
        if spin % 64 == 0 {
            std::thread::yield_now();
        } else {
            std::hint::spin_loop();
        }
    }
    false
}

/// [`AtomicHashTable::read`] over a slice of slots.
pub(crate) fn read(slots: &[Slot], tagged_hash: u64) -> Option<u64> {
    debug_assert!(tagged_hash != 0, "tagged_hash must be non-zero");
    holding(slots, tagged_hash)
        .map(|s| s.value.load(Ordering::Acquire))
        .reduce(u64::wrapping_add)
}

/// [`AtomicHashTable::last_update`] over a slice of slots.
pub(crate) fn last_update(slots: &[Slot], tagged_hash: u64) -> Option<u64> {
    debug_assert!(tagged_hash != 0);
    holding(slots, tagged_hash)
        .map(|s| s.last_update_ns.load(Ordering::Acquire))
        .max()
}

/// [`AtomicHashTable::reset`] over a slice of slots.
pub(crate) fn reset(slots: &[Slot], tagged_hash: u64) -> bool {
    debug_assert!(tagged_hash != 0);
    let released = holding(slots, tagged_hash)
        .filter(|s| {
            s.key
                .compare_exchange(tagged_hash, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        })
        .count();
    released > 0
}

/// Commutative add to a slot the key holds, then refresh its stamp.
fn add(s: &Slot, by: u64, now_ns: u64) -> u64 {
    let new = s.value.fetch_add(by, Ordering::AcqRel).wrapping_add(by);
    s.last_update_ns.store(now_ns, Ordering::Release);
    new
}

impl<const N: usize> AtomicHashTable<N> {
    /// Construct an empty table. Not typically used directly - in a
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
    /// slot via CAS if the key holds none in its probe window. Returns
    /// the value of the slot it added to, or [`SATURATED`] if every slot
    /// of the window holds another key.
    ///
    /// The returned value is a lower bound of the key's count, not the
    /// count: a claim racing a release (eviction or [`reset`]) in front
    /// of the key can leave the key in two slots, and only [`read`] adds
    /// them up. Use [`read`] when the count matters.
    ///
    /// `tagged_hash` must be non-zero. Use [`tagged_hash`] to derive it
    /// from a user key.
    ///
    /// [`read`]: Self::read
    /// [`reset`]: Self::reset
    pub fn increment(&self, tagged_hash: u64, by: u64, now_ns: u64) -> u64 {
        increment(self.cells(), tagged_hash, by, now_ns)
    }

    /// Read the counter for `tagged_hash`: the sum of every slot of its
    /// probe window holding the key, usually one. Returns `None` if no
    /// slot holds it.
    pub fn read(&self, tagged_hash: u64) -> Option<u64> {
        read(self.cells(), tagged_hash)
    }

    /// Read the latest update timestamp among the slots holding
    /// `tagged_hash`, if any.
    pub fn last_update(&self, tagged_hash: u64) -> Option<u64> {
        last_update(self.cells(), tagged_hash)
    }

    /// Release every slot holding `tagged_hash` by CAS-ing its key back
    /// to `0`. Returns `true` if at least one slot was released, `false`
    /// if the key was not present or a concurrent release took it first.
    /// Subsequent `increment` on the same key will reclaim a slot whose
    /// counter starts at `by`.
    ///
    /// Used by the WAF auto-ban path to clear a counter after a ban
    /// has been issued - a repeat offender after ban expiry starts
    /// counting from zero rather than inheriting the previous run.
    pub fn reset(&self, tagged_hash: u64) -> bool {
        reset(self.cells(), tagged_hash)
    }

    /// `N` is a power of two, so `N - 1` masks a slot index, and holds
    /// at least one window, so a window never visits a slot twice and
    /// `read` never counts one twice.
    const SHAPE_IS_VALID: () = assert!(N.is_power_of_two() && N >= MAX_PROBE);

    /// The slots as the probe functions take them, the shape checked at
    /// compile time.
    fn cells(&self) -> &[Slot] {
        let () = Self::SHAPE_IS_VALID;
        &self.slots
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
/// comparable - both processes read the same clock.
pub fn now_ns() -> u64 {
    use nix::sys::time::TimeValLike;
    use nix::time::{clock_gettime, ClockId};
    // clock_gettime(CLOCK_MONOTONIC) cannot fail in practice on Linux
    // with a valid clockid. Fall back to 0 if it ever does; eviction
    // walker will simply see every slot as "fresh" during that tick.
    // We surface the (extremely unlikely) error as a warn log instead
    // of silently degrading the eviction semantics - audit L-1.
    match clock_gettime(ClockId::CLOCK_MONOTONIC) {
        Ok(ts) => {
            // tv_nsec is i64 but POSIX constrains CLOCK_MONOTONIC to
            // 0..=999_999_999 (never negative in practice), so the
            // `as u64` cast is well-defined.
            (ts.num_seconds() as u64)
                .saturating_mul(1_000_000_000)
                .saturating_add(ts.tv_nsec() as u64)
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "lorica-shmem::now_ns: clock_gettime(CLOCK_MONOTONIC) failed; eviction disabled for this tick"
            );
            0
        }
    }
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
        // The smallest table a window fits in twice over, with every key
        // starting at the same slot, so the window fills.
        let t: Box<AtomicHashTable<{ MAX_PROBE * 2 }>> = AtomicHashTable::new_zeroed();
        let shift = (MAX_PROBE * 2).trailing_zeros();
        for i in 0..MAX_PROBE as u64 {
            let h = tagged_hash((i << shift) | 1);
            t.increment(h, 1, 0);
        }
        let h_extra = tagged_hash(((MAX_PROBE as u64) << shift) | 1);
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
    fn concurrent_first_increments_of_fresh_keys_lose_nothing() {
        // Every thread walks the same fresh keys in the same order, so
        // the first increment of each key is contended: one thread
        // claims the slot while the others add to it at once.
        const THREADS: u64 = 8;
        const KEYS: u64 = 20_000;
        let t: Arc<AtomicHashTable<65_536>> = Arc::from(AtomicHashTable::new_zeroed());
        let start = Arc::new(std::sync::Barrier::new(THREADS as usize));
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let t = t.clone();
                let start = start.clone();
                thread::spawn(move || {
                    start.wait();
                    for k in 0..KEYS {
                        t.increment(tagged_hash(k << 1), 1, 0);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let short: Vec<u64> = (0..KEYS)
            .filter(|&k| t.read(tagged_hash(k << 1)) != Some(THREADS))
            .collect();
        assert!(
            short.is_empty(),
            "{} of {KEYS} keys lost an increment, first {:?}",
            short.len(),
            &short[..short.len().min(5)]
        );
    }

    #[test]
    fn a_reclaimed_slot_starts_from_by_whatever_value_it_held() {
        let t: Box<AtomicHashTable<1024>> = AtomicHashTable::new_zeroed();
        let h = tagged_hash(0x7777);
        assert_eq!(t.increment(h, 1_000, 1), 1_000);
        assert!(t.reset(h));
        // The released slot still holds 1 000; the new claim must not
        // inherit it.
        assert_eq!(t.increment(h, 2, 2), 2);
        assert_eq!(t.read(h), Some(2));
        assert_eq!(t.increment(h, 3, 3), 5);
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

    /// Two tagged hashes that start probing at the same slot of a
    /// 1024-slot table, so the second one claimed sits behind the first.
    fn same_start_pair() -> (u64, u64) {
        let front = tagged_hash(0x0000_0000_0000_0401);
        let behind = tagged_hash(0x8000_0000_0000_0401);
        (front, behind)
    }

    #[test]
    fn resetting_a_key_keeps_the_count_of_the_key_behind_it() {
        let t: Box<AtomicHashTable<1024>> = AtomicHashTable::new_zeroed();
        let (front, behind) = same_start_pair();
        t.increment(front, 1, 1);
        for _ in 0..5 {
            t.increment(behind, 1, 1);
        }
        assert!(t.reset(front));
        assert_eq!(t.read(behind), Some(5));
        assert_eq!(t.increment(behind, 1, 2), 6);
        assert_eq!(t.read(behind), Some(6));
    }

    #[test]
    fn a_key_counted_in_two_slots_reads_as_their_sum() {
        // A claim racing a release can leave a key in two slots of its
        // window; `read` adds them up and `reset` releases both.
        let t: Box<AtomicHashTable<1024>> = AtomicHashTable::new_zeroed();
        let (front, behind) = same_start_pair();
        let h = behind;
        t.increment(front, 1, 1);
        t.increment(h, 3, 1);
        assert!(t.reset(front));
        let start = (h as usize) & 1023;
        t.slots[start].key.store(h, Ordering::Release);
        t.slots[start].value.store(4, Ordering::Release);
        assert_eq!(t.read(h), Some(7));
        assert!(t.reset(h));
        assert_eq!(t.read(h), None);
    }

    #[test]
    fn released_slots_in_front_of_a_key_lose_none_of_its_increments() {
        // Every key below starts probing at the same slot. While writers
        // count the stable keys, a churner keeps claiming and releasing
        // other keys in the same window, so free slots keep opening in
        // front of keys already placed. Whatever slot an increment lands
        // in, the stable keys must read every increment.
        const STABLE: u64 = 6;
        const WRITERS: u64 = 4;
        const PER_WRITER: u64 = 20_000;
        let t: Arc<AtomicHashTable<1024>> = Arc::from(AtomicHashTable::new_zeroed());
        let key = |n: u64| tagged_hash((n << 10) | 0x77);
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let churner = {
            let t = t.clone();
            let done = done.clone();
            thread::spawn(move || {
                let mut generation = 1_000u64;
                while !done.load(Ordering::Relaxed) {
                    let front = key(generation);
                    let other = key(generation + 1);
                    t.increment(front, 1, 0);
                    t.increment(other, 1, 0);
                    t.reset(front);
                    t.reset(other);
                    generation += 2;
                }
            })
        };
        let writers: Vec<_> = (0..WRITERS)
            .map(|_| {
                let t = t.clone();
                thread::spawn(move || {
                    for _ in 0..PER_WRITER {
                        for n in 0..STABLE {
                            t.increment(key(n), 1, 0);
                        }
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().unwrap();
        }
        done.store(true, Ordering::Relaxed);
        churner.join().unwrap();
        for n in 0..STABLE {
            assert_eq!(t.read(key(n)), Some(WRITERS * PER_WRITER), "key {n}");
        }
    }

    #[test]
    fn a_claim_racing_a_release_and_reclaim_of_its_slot_counts_exactly() {
        // A claim reads what a free slot holds, then takes the slot. A
        // churner keeps claiming and releasing the slots in front of the
        // claims, leaving 1 or 1 000 behind it in turn, so a claim that
        // took a slot another key had used and released in between
        // would start from the wrong count. Each round, every writer
        // adds 1 to a fresh key; the key must read one per writer.
        const WRITERS: usize = 4;
        const ROUNDS: u64 = 20_000;
        let t: Arc<AtomicHashTable<1024>> = Arc::from(AtomicHashTable::new_zeroed());
        let key = |n: u64| tagged_hash((n << 10) | 0x55);
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let churner = {
            let t = t.clone();
            let done = done.clone();
            thread::spawn(move || {
                let mut generation = 1_000_000u64;
                while !done.load(Ordering::Relaxed) {
                    let by = if generation.is_multiple_of(2) {
                        1
                    } else {
                        1_000
                    };
                    t.increment(key(generation), by, 0);
                    t.reset(key(generation));
                    generation += 1;
                }
            })
        };
        let round = Arc::new(std::sync::Barrier::new(WRITERS + 1));
        let writers: Vec<_> = (0..WRITERS)
            .map(|_| {
                let t = t.clone();
                let round = round.clone();
                thread::spawn(move || {
                    for n in 1..=ROUNDS {
                        round.wait();
                        t.increment(key(n), 1, 0);
                        round.wait();
                    }
                })
            })
            .collect();
        let mut wrong = Vec::new();
        for n in 1..=ROUNDS {
            round.wait();
            round.wait();
            let read = t.read(key(n));
            if read != Some(WRITERS as u64) {
                wrong.push((n, read));
            }
            t.reset(key(n));
        }
        for w in writers {
            w.join().unwrap();
        }
        done.store(true, Ordering::Relaxed);
        churner.join().unwrap();
        assert!(
            wrong.is_empty(),
            "{} of {ROUNDS} keys miscounted, first (round, read) {:?}",
            wrong.len(),
            &wrong[..wrong.len().min(5)]
        );
    }

    /// SplitMix64: a fixed stream of well-mixed keys, so a fill test
    /// gives the same result on every run.
    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    #[test]
    fn a_table_filled_to_its_documented_capacity_refuses_almost_no_key() {
        // The production table filled to half its slots, the capacity
        // `WAF_SLOTS` documents, eight times over. A refused key is a
        // client whose violations go uncounted, so refusals must stay
        // below one key in 100 000 there.
        use crate::region::WAF_SLOTS;
        const FILLS: u64 = 8;
        let keys_per_fill = (WAF_SLOTS / 2) as u64;
        let mut refused = 0u64;
        for fill in 0..FILLS {
            let t: Box<AtomicHashTable<WAF_SLOTS>> = AtomicHashTable::new_zeroed();
            let mut seed = fill;
            for _ in 0..keys_per_fill {
                if t.increment(tagged_hash(splitmix64(&mut seed)), 1, 0) == SATURATED {
                    refused += 1;
                }
            }
        }
        let keys = FILLS * keys_per_fill;
        assert!(
            refused * 100_000 < keys,
            "{refused} of {keys} keys refused at half load"
        );
    }

    #[test]
    fn reset_returns_false_for_absent_key() {
        let t: Box<AtomicHashTable<1024>> = AtomicHashTable::new_zeroed();
        let h = tagged_hash(0xabcd);
        assert!(!t.reset(h));
    }
}
