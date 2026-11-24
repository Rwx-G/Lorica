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

//! The circuit states the supervisor publishes for the workers' stream
//! admissions (Story 12.3 D-g, amended 2026-11-24).
//!
//! The supervisor's breaker registry stays the only authority. Each time
//! one of its stream circuits changes state, it writes the new state
//! here, under the lock it changed it under, before it answers the
//! worker that caused the change. A worker reads the state with atomic
//! loads before it asks anything: a closed circuit admits and an open one
//! inside its cooldown refuses without a round trip, and only an open
//! circuit past its cooldown, a half-open one, or a key this table cannot
//! hold goes to the supervisor, which arbitrates the single probe.
//!
//! **Cells.** Open addressing over a [`MAX_PROBE`] window, 32 bytes per
//! cell: the key's tagged hash, a second, independent hash of the key
//! that a lookup also compares (so a match needs 128 bits to agree, and a
//! circuit of one stream never answers for another's), and one state
//! word. The state and the end of an open circuit's cooldown share that
//! word, so a reader never sees one without the other and the table needs
//! no seqlock.
//!
//! **Only the supervisor writes, and a cell is never freed.** A key gets a
//! cell the first time its circuit leaves `Closed` and keeps it, closed
//! again or not, until the region goes with its supervisor. Since nothing
//! frees a cell, a key's cell always lies before the first free cell of
//! its window, and a lookup that reaches a free cell knows the key was
//! never published: its circuit has always been closed. A window full of
//! other keys reads as unknown, and the worker asks the supervisor as it
//! did before this table existed. Only circuits that opened at least once
//! since the supervisor started hold a cell.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::hash::siphash13_u64;
use crate::table::{tagged_hash, window, CLAIMING, MAX_PROBE};

/// Cells of the published-state table. A power of two holding at least
/// one window. At half load the window refuses a new key about once in
/// 300 000 (the figure [`MAX_PROBE`] documents for the WAF tables, which
/// probe the same way), and a refused key costs a round trip, not a
/// wrong answer.
pub const BREAKER_SLOTS: usize = 4096;

const _: () = assert!(BREAKER_SLOTS.is_power_of_two() && BREAKER_SLOTS >= MAX_PROBE);

/// XORed into the first half of the hash key for the check hash, so the
/// two hashes of a key are independent.
const CHECK_DOMAIN: u64 = 0x6272_6b5f_6368_6b31;

/// The two high bits of a state word: the state.
const STATE_SHIFT: u32 = 62;
/// The low bits of a state word: an open circuit's cooldown end.
const UNTIL_MASK: u64 = (1 << STATE_SHIFT) - 1;
const TAG_OPEN: u64 = 1;
const TAG_HALF_OPEN: u64 = 2;

/// How often, in spins, a publication waiting on another key's claim in
/// flight yields its thread. A claim is three stores by another thread
/// of the same supervisor, so the wait only lasts while that thread is
/// descheduled, and a claimer cannot die alone: its process is the
/// waiter's.
const CLAIM_YIELD_EVERY: u32 = 64;

/// One key's published state. ABI fixed: mapped across processes.
#[repr(C, align(32))]
pub struct BreakerCell {
    /// Tagged hash of the key, `0` when free, `CLAIMING` while the
    /// supervisor writes the cell for the first time.
    key: AtomicU64,
    /// Second hash of the key, written before the key is published.
    check: AtomicU64,
    /// The state, see [`BreakerState`]'s encoding.
    state: AtomicU64,
    _pad: u64,
}

const _: () = assert!(std::mem::size_of::<BreakerCell>() == 32);

/// The published-state table: [`BREAKER_SLOTS`] cells.
#[repr(C, align(64))]
pub struct BreakerStates {
    cells: [BreakerCell; BREAKER_SLOTS],
}

/// A circuit's state as the supervisor last published it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    /// Admits; the worker decides alone.
    Closed,
    /// Refuses until `until_ns` ([`now_ns`](crate::now_ns) nanoseconds),
    /// then the next admission is the supervisor's to grant as a probe.
    Open {
        /// End of the cooldown, saturated to 62 bits.
        until_ns: u64,
    },
    /// One probe is or may be in flight: only the supervisor decides.
    HalfOpen,
}

impl BreakerState {
    fn encode(self) -> u64 {
        match self {
            BreakerState::Closed => 0,
            BreakerState::Open { until_ns } => (TAG_OPEN << STATE_SHIFT) | until_ns.min(UNTIL_MASK),
            BreakerState::HalfOpen => TAG_HALF_OPEN << STATE_SHIFT,
        }
    }

    fn decode(word: u64) -> BreakerState {
        match word >> STATE_SHIFT {
            TAG_OPEN => BreakerState::Open {
                until_ns: word & UNTIL_MASK,
            },
            TAG_HALF_OPEN => BreakerState::HalfOpen,
            _ => BreakerState::Closed,
        }
    }
}

/// Where a breaker key lives in the table: its tagged hash and its check
/// hash, both keyed by the region's secret hash key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakerKey {
    tagged: u64,
    check: u64,
}

impl BreakerKey {
    /// The key of the circuit of `backend` under `route_id` (a route id,
    /// or a stream's `stream:<id>`), hashed with `hash_key`.
    pub fn new(hash_key: [u64; 2], route_id: &str, backend: &str) -> BreakerKey {
        let check_key = [hash_key[0] ^ CHECK_DOMAIN, hash_key[1]];
        BreakerKey {
            tagged: tagged_hash(digest(hash_key, route_id, backend)),
            check: digest(check_key, route_id, backend),
        }
    }
}

/// SipHash-1-3 chained over the key's bytes, eight at a time, from a
/// state seeded with both lengths, so `("ab", "c")` and `("a", "bc")`
/// never share an input.
fn digest(hash_key: [u64; 2], route_id: &str, backend: &str) -> u64 {
    let mut state = ((route_id.len() as u64) << 32) ^ backend.len() as u64;
    let mut word = 0u64;
    let mut filled = 0u32;
    for byte in route_id.bytes().chain(backend.bytes()) {
        word |= u64::from(byte) << (8 * filled);
        filled += 1;
        if filled == 8 {
            state = siphash13_u64(hash_key, state ^ word);
            word = 0;
            filled = 0;
        }
    }
    siphash13_u64(hash_key, state ^ word)
}

impl BreakerStates {
    /// Write `state` as `key`'s published state, giving the key a cell
    /// the first time. Returns `false`, writing nothing, when every cell
    /// of the key's window holds another key; the key then reads as
    /// unknown and its workers keep asking the supervisor.
    ///
    /// Publications of one key must not run concurrently (the supervisor
    /// publishes under the lock of the registry entry it changed);
    /// publications of different keys may.
    pub fn publish(&self, key: BreakerKey, state: BreakerState) -> bool {
        let word = state.encode();
        for cell in window(&self.cells, key.tagged) {
            loop {
                match cell.key.load(Ordering::Acquire) {
                    0 => {
                        if cell
                            .key
                            .compare_exchange(0, CLAIMING, Ordering::AcqRel, Ordering::Acquire)
                            .is_ok()
                        {
                            cell.check.store(key.check, Ordering::Release);
                            cell.state.store(word, Ordering::Release);
                            cell.key.store(key.tagged, Ordering::Release);
                            return true;
                        }
                    }
                    // Never passed while in flight: the key being claimed
                    // could be one a lookup would then find past a cell
                    // it reads as free.
                    CLAIMING => wait_for_claim(cell),
                    k if k == key.tagged && cell.check.load(Ordering::Acquire) == key.check => {
                        cell.state.store(word, Ordering::Release);
                        return true;
                    }
                    _ => break,
                }
            }
        }
        false
    }

    /// `key`'s published state: [`BreakerState::Closed`] for a key never
    /// published, `None` when the key's window is full of other keys and
    /// the table cannot tell.
    pub fn lookup(&self, key: BreakerKey) -> Option<BreakerState> {
        for cell in window(&self.cells, key.tagged) {
            match cell.key.load(Ordering::Acquire) {
                // A key's cell lies before every free cell of its window
                // (cells are never freed and a claim never passes one in
                // flight), so the key was never published, or is being
                // published for the first time: closed until now.
                0 | CLAIMING => return Some(BreakerState::Closed),
                k if k == key.tagged && cell.check.load(Ordering::Acquire) == key.check => {
                    return Some(BreakerState::decode(cell.state.load(Ordering::Acquire)));
                }
                _ => {}
            }
        }
        None
    }

    /// A zeroed table on the heap, for tests outside a region.
    pub fn new_zeroed() -> Box<BreakerStates> {
        let layout = std::alloc::Layout::new::<BreakerStates>();
        // SAFETY: the layout has a non-zero size, and zeroed bytes are a
        // valid table: every atomic reads 0, every cell is free.
        unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<BreakerStates>();
            if ptr.is_null() {
                std::alloc::handle_alloc_error(layout);
            }
            Box::from_raw(ptr)
        }
    }
}

/// Wait until the claim in flight on `cell` publishes its key.
fn wait_for_claim(cell: &BreakerCell) {
    let mut spins = 0u32;
    while cell.key.load(Ordering::Acquire) == CLAIMING {
        spins = spins.wrapping_add(1);
        if spins.is_multiple_of(CLAIM_YIELD_EVERY) {
            std::thread::yield_now();
        } else {
            std::hint::spin_loop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH_KEY: [u64; 2] = [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210];

    fn key(route: &str, backend: &str) -> BreakerKey {
        BreakerKey::new(HASH_KEY, route, backend)
    }

    #[test]
    fn a_key_never_published_reads_closed() {
        let t = BreakerStates::new_zeroed();
        assert_eq!(
            t.lookup(key("stream:s1", "192.0.2.10:5432")),
            Some(BreakerState::Closed)
        );
    }

    #[test]
    fn every_state_reads_back_as_published() {
        let t = BreakerStates::new_zeroed();
        let k = key("stream:s1", "192.0.2.10:5432");
        for state in [
            BreakerState::Open {
                until_ns: 123_456_789,
            },
            BreakerState::HalfOpen,
            BreakerState::Closed,
            BreakerState::Open { until_ns: u64::MAX },
        ] {
            assert!(t.publish(k, state));
            let expected = match state {
                BreakerState::Open { until_ns } => BreakerState::Open {
                    until_ns: until_ns.min(UNTIL_MASK),
                },
                other => other,
            };
            assert_eq!(t.lookup(k), Some(expected));
        }
    }

    #[test]
    fn keys_split_differently_hash_apart() {
        let t = BreakerStates::new_zeroed();
        assert_ne!(key("ab", "c"), key("a", "bc"));
        assert!(t.publish(key("ab", "c"), BreakerState::HalfOpen));
        assert_eq!(t.lookup(key("a", "bc")), Some(BreakerState::Closed));
    }

    #[test]
    fn a_key_with_the_same_tag_but_another_check_is_not_a_match() {
        let t = BreakerStates::new_zeroed();
        let k = key("stream:s1", "192.0.2.10:5432");
        assert!(t.publish(k, BreakerState::HalfOpen));
        let impostor = BreakerKey {
            tagged: k.tagged,
            check: k.check ^ 1,
        };
        assert_eq!(t.lookup(impostor), Some(BreakerState::Closed));
        // It takes a cell of its own rather than overwriting the first.
        assert!(t.publish(impostor, BreakerState::Open { until_ns: 5 }));
        assert_eq!(t.lookup(k), Some(BreakerState::HalfOpen));
        assert_eq!(t.lookup(impostor), Some(BreakerState::Open { until_ns: 5 }));
    }

    /// `n` distinct keys whose windows all start at the same cell.
    fn same_window_keys(n: usize) -> Vec<BreakerKey> {
        let start = (key("anchor", "x").tagged as usize) & (BREAKER_SLOTS - 1);
        (0..)
            .map(|i| key("stream:k", &format!("192.0.2.{i}:80")))
            .filter(|k| (k.tagged as usize) & (BREAKER_SLOTS - 1) == start)
            .take(n)
            .collect()
    }

    #[test]
    fn a_full_window_refuses_the_publication_and_reads_unknown() {
        let t = BreakerStates::new_zeroed();
        let keys = same_window_keys(MAX_PROBE + 1);
        for k in &keys[..MAX_PROBE] {
            assert!(t.publish(*k, BreakerState::HalfOpen));
        }
        let extra = keys[MAX_PROBE];
        assert_eq!(t.lookup(extra), None, "the table cannot tell");
        assert!(!t.publish(extra, BreakerState::HalfOpen));
        // Keys already placed keep their cells and states.
        for k in &keys[..MAX_PROBE] {
            assert_eq!(t.lookup(*k), Some(BreakerState::HalfOpen));
        }
    }

    #[test]
    fn concurrent_first_publications_of_distinct_keys_all_land() {
        let t: std::sync::Arc<BreakerStates> = std::sync::Arc::from(BreakerStates::new_zeroed());
        let keys = same_window_keys(MAX_PROBE / 2);
        let handles: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let t = std::sync::Arc::clone(&t);
                let k = *k;
                std::thread::spawn(move || {
                    assert!(t.publish(
                        k,
                        BreakerState::Open {
                            until_ns: i as u64 + 1
                        }
                    ));
                })
            })
            .collect();
        for h in handles {
            h.join().expect("a publisher");
        }
        for (i, k) in keys.iter().enumerate() {
            assert_eq!(
                t.lookup(*k),
                Some(BreakerState::Open {
                    until_ns: i as u64 + 1
                })
            );
        }
    }
}
