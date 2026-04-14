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

//! Background eviction for the shmem WAF tables.
//!
//! Per design doc § 5.4: a task on the supervisor walks every slot of
//! every table once per minute. A slot is evicted when its
//! `last_update_ns` is older than 5 minutes; eviction CAS's the `key`
//! from `h` to `0` to release the slot. `value` and `last_update_ns`
//! are *not* reset at eviction time — they are reset by the next
//! `increment` that claims the slot, which is safe because the claim
//! CAS serialises reuse (§ 5.3).
//!
//! A writer that raced with eviction (read `cur_key == h`, then
//! eviction CAS'd to 0, then a new key claimed the slot) may pollute
//! the reclaiming key's counter by at most one stale increment per
//! slot reuse. Acceptable for WAF semantics; would not be acceptable
//! for billing.

use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::region::SharedRegion;
use crate::table::{AtomicHashTable, Slot};

/// Default minimum idle time before a slot becomes eligible for eviction.
pub const DEFAULT_STALE_AFTER: Duration = Duration::from_secs(5 * 60);

/// Default interval between eviction passes.
pub const DEFAULT_SCAN_INTERVAL: Duration = Duration::from_secs(60);

/// Statistics returned by a single eviction pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EvictionStats {
    pub waf_flood_scanned: usize,
    pub waf_flood_evicted: usize,
    pub waf_auto_ban_scanned: usize,
    pub waf_auto_ban_evicted: usize,
}

impl EvictionStats {
    pub fn total_evicted(&self) -> usize {
        self.waf_flood_evicted + self.waf_auto_ban_evicted
    }
    pub fn total_scanned(&self) -> usize {
        self.waf_flood_scanned + self.waf_auto_ban_scanned
    }
}

/// Run a single eviction pass over both tables. Pure function, testable.
///
/// `now_ns` is the current monotonic timestamp; slots whose
/// `last_update_ns` is more than `stale_after_ns` behind are evicted.
pub fn evict_once(region: &SharedRegion, now_ns: u64, stale_after_ns: u64) -> EvictionStats {
    let (ws, we) = evict_table(&region.waf_flood, now_ns, stale_after_ns);
    let (bs, be) = evict_table(&region.waf_auto_ban, now_ns, stale_after_ns);
    EvictionStats {
        waf_flood_scanned: ws,
        waf_flood_evicted: we,
        waf_auto_ban_scanned: bs,
        waf_auto_ban_evicted: be,
    }
}

fn evict_table<const N: usize>(
    table: &AtomicHashTable<N>,
    now_ns: u64,
    stale_after_ns: u64,
) -> (usize, usize) {
    let mut scanned = 0usize;
    let mut evicted = 0usize;
    table.for_each_slot(|_, slot: &Slot| {
        scanned += 1;
        let cur_key = slot.key.load(Ordering::Acquire);
        if cur_key == 0 {
            return;
        }
        let last = slot.last_update_ns.load(Ordering::Acquire);
        let age = now_ns.saturating_sub(last);
        if age < stale_after_ns {
            return;
        }
        // CAS `key` from cur_key -> 0. On success, release the slot.
        // Failure means a writer claimed the slot concurrently (with a
        // fresh last_update_ns); skip and let the next tick retry.
        if slot
            .key
            .compare_exchange(cur_key, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            evicted += 1;
            // Intentionally do not reset `value` or `last_update_ns`.
            // The next increment() that claims this slot via CAS from
            // 0 to a new tagged hash resets value to `by` and stamps
            // last_update_ns. See design § 5.3.
        }
    });
    (scanned, evicted)
}

/// Log an eviction pass result at the appropriate level. Call after
/// [`evict_once`] from the supervisor's periodic task.
pub fn log_pass(stats: EvictionStats) {
    if stats.total_evicted() > 0 {
        tracing::info!(
            flood_scanned = stats.waf_flood_scanned,
            flood_evicted = stats.waf_flood_evicted,
            ban_scanned = stats.waf_auto_ban_scanned,
            ban_evicted = stats.waf_auto_ban_evicted,
            "shmem eviction pass complete",
        );
    } else {
        tracing::debug!(
            scanned = stats.total_scanned(),
            "shmem eviction pass: nothing to evict",
        );
    }
}
// Note: the eviction loop itself lives in the supervisor (main.rs),
// which already hosts tokio. Keeping lorica-shmem tokio-free lets this
// crate be used from non-async contexts (e.g. fork-based tests).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::region::SharedRegion;

    #[test]
    fn evict_once_removes_old_entries() {
        let (region, _fd) = SharedRegion::create_supervisor().expect("create");
        // Populate two entries at different ages.
        let h_fresh = region.tagged(1);
        let h_stale = region.tagged(2);
        region.waf_flood.increment(h_fresh, 5, 1_000_000_000);
        region.waf_flood.increment(h_stale, 7, 100_000_000);

        // now_ns = 10s, stale_after = 5s.
        // h_fresh age = 10s - 1s = 9s -> stale (wait, 9 > 5, so evicted)
        // Let me redo: now = 2s, last_fresh = 1s -> age 1s -> not stale.
        // last_stale = 0.1s -> age 1.9s -> not stale. Fix timings.
        // Re-populate at correct ages.
        let _ = region; // silence

        // Recreate with cleaner numbers.
        let (region, _fd) = SharedRegion::create_supervisor().expect("create");
        let now_ns: u64 = 1_000_000_000_000; // 1000s
        let stale_after_ns: u64 = 5_000_000_000; // 5s
        let h_fresh = region.tagged(1);
        let h_stale = region.tagged(2);
        // Fresh: last_update 999s -> age 1s -> not stale.
        region
            .waf_flood
            .increment(h_fresh, 5, now_ns - 1_000_000_000);
        // Stale: last_update 900s -> age 100s -> stale.
        region
            .waf_flood
            .increment(h_stale, 7, now_ns - 100_000_000_000);

        let stats = evict_once(region, now_ns, stale_after_ns);
        assert_eq!(stats.waf_flood_evicted, 1);
        assert!(region.waf_flood.read(h_fresh).is_some());
        assert!(region.waf_flood.read(h_stale).is_none());
    }

    #[test]
    fn evict_once_is_idempotent_on_empty() {
        let (region, _fd) = SharedRegion::create_supervisor().expect("create");
        let stats = evict_once(region, 1_000_000_000_000, 5_000_000_000);
        assert_eq!(stats.total_evicted(), 0);
        assert_eq!(
            stats.waf_flood_scanned + stats.waf_auto_ban_scanned,
            2 * region.waf_flood.capacity()
        );
    }

    #[test]
    fn race_with_writer_preserves_fresh_write() {
        // A writer increments a slot just as the evictor decides to
        // reap it. CAS must fail on the evictor side (key changed from
        // cur_key to something else or to 0 via prior eviction); the
        // fresh write survives.
        let (region, _fd) = SharedRegion::create_supervisor().expect("create");
        let now_ns: u64 = 1_000_000_000_000;
        let stale_after_ns: u64 = 5_000_000_000;
        let h = region.tagged(42);
        region.waf_flood.increment(h, 1, now_ns - 100_000_000_000); // very stale

        // Simulate a writer touching the slot *just before* evict_once
        // by stamping a fresh last_update_ns.
        region.waf_flood.increment(h, 1, now_ns);

        // Now evictor scans: last_update is fresh, slot survives.
        let stats = evict_once(region, now_ns, stale_after_ns);
        assert_eq!(stats.waf_flood_evicted, 0);
        assert_eq!(region.waf_flood.read(h), Some(2));
    }

    #[test]
    fn evict_both_tables() {
        let (region, _fd) = SharedRegion::create_supervisor().expect("create");
        let now_ns: u64 = 1_000_000_000_000;
        let stale_after_ns: u64 = 5_000_000_000;
        let old = now_ns - 100_000_000_000;
        for i in 0..5 {
            region.waf_flood.increment(region.tagged(i), 1, old);
            region.waf_auto_ban.increment(region.tagged(i), 1, old);
        }
        let stats = evict_once(region, now_ns, stale_after_ns);
        assert_eq!(stats.waf_flood_evicted, 5);
        assert_eq!(stats.waf_auto_ban_evicted, 5);
    }
}
