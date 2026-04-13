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

//! Monotonic generation gate for config reload ordering.
//!
//! See `docs/architecture/worker-shared-state.md` § 8 invariant (4):
//! "Workers reject any Prepare / Commit with a generation lower than the
//! highest seen. Prevents reordering on a flaky channel."
//!
//! Under the pipelined RPC framework, Prepare / Commit messages for the
//! same reload carry the same generation. The supervisor issues
//! generations strictly monotonically. A worker observing an out-of-order
//! lower generation rejects it; a repeat of the current or an earlier
//! already-committed generation is also rejected.

use std::sync::atomic::{AtomicU64, Ordering};

/// Rejection reason when a generation is not strictly greater than the
/// highest one seen so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StaleGeneration {
    #[error("generation {observed} is not newer than highest seen {highest}")]
    Stale { observed: u64, highest: u64 },
}

/// A monotonic generation gate. Workers call `observe(gen)` on each
/// ConfigReloadPrepare/Commit; the gate accepts strictly increasing
/// generations and rejects anything else.
///
/// The gate does not distinguish Prepare from Commit — both must carry
/// the same generation and both advance the highest-seen watermark on
/// acceptance. The caller is responsible for pairing a Commit with the
/// Prepare that preceded it (see WPAR-8 coordinator logic).
#[derive(Debug)]
pub struct GenerationGate {
    highest: AtomicU64,
}

impl Default for GenerationGate {
    fn default() -> Self {
        Self::new()
    }
}

impl GenerationGate {
    pub fn new() -> Self {
        Self {
            highest: AtomicU64::new(0),
        }
    }

    /// Current highest accepted generation.
    pub fn highest(&self) -> u64 {
        self.highest.load(Ordering::Acquire)
    }

    /// Observe a generation. Accepts if strictly greater than the current
    /// highest; updates the watermark atomically. Rejects otherwise.
    ///
    /// Uses a CAS loop so concurrent observers cannot both accept the
    /// same generation.
    pub fn observe(&self, gen: u64) -> Result<(), StaleGeneration> {
        let mut current = self.highest.load(Ordering::Acquire);
        loop {
            if gen <= current {
                return Err(StaleGeneration::Stale {
                    observed: gen,
                    highest: current,
                });
            }
            match self.highest.compare_exchange_weak(
                current,
                gen,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => current = actual,
            }
        }
    }

    /// Like `observe`, but accepts a generation equal to the current
    /// highest. Use for Commit when the same generation was already
    /// Prepared (and thus advanced the watermark) — this variant just
    /// verifies that the Commit is for the Prepared gen, not an older
    /// one.
    pub fn observe_commit(&self, gen: u64) -> Result<(), StaleGeneration> {
        let current = self.highest.load(Ordering::Acquire);
        if gen < current {
            Err(StaleGeneration::Stale {
                observed: gen,
                highest: current,
            })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_strictly_increasing() {
        let g = GenerationGate::new();
        assert!(g.observe(1).is_ok());
        assert!(g.observe(2).is_ok());
        assert!(g.observe(10).is_ok());
        assert_eq!(g.highest(), 10);
    }

    #[test]
    fn rejects_equal_or_lower() {
        let g = GenerationGate::new();
        assert!(g.observe(5).is_ok());
        assert!(matches!(
            g.observe(5),
            Err(StaleGeneration::Stale {
                observed: 5,
                highest: 5
            })
        ));
        assert!(matches!(
            g.observe(3),
            Err(StaleGeneration::Stale {
                observed: 3,
                highest: 5
            })
        ));
        assert_eq!(g.highest(), 5);
    }

    #[test]
    fn commit_accepts_equal() {
        let g = GenerationGate::new();
        g.observe(7).unwrap();
        assert!(g.observe_commit(7).is_ok());
        assert!(matches!(
            g.observe_commit(6),
            Err(StaleGeneration::Stale { .. })
        ));
    }

    #[test]
    fn concurrent_observers_race_correctly() {
        use std::sync::Arc;
        use std::thread;

        let g = Arc::new(GenerationGate::new());
        let mut handles = Vec::new();
        // Many threads racing to observe gen=1; only one should accept.
        for _ in 0..64 {
            let g = g.clone();
            handles.push(thread::spawn(move || g.observe(1).is_ok()));
        }
        let accepted: usize = handles
            .into_iter()
            .map(|h| if h.join().unwrap() { 1 } else { 0 })
            .sum();
        assert_eq!(accepted, 1);
        assert_eq!(g.highest(), 1);
    }
}
