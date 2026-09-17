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

//! The node-wide ceiling on bytes held for capture.
//!
//! A capture rule is a diagnostic an operator can enable on a node that
//! also terminates production TLS, so it must not be usable as a
//! memory-exhaustion primitive: without a ceiling, `rule count x
//! request rate x body cap` is unbounded. One counter covers every rule
//! and every in-flight request on the process, and a request that
//! cannot fit under it records nothing instead of allocating anyway.
//!
//! The counter is a process-wide static rather than a field on the
//! configuration snapshot, because a reservation outlives the snapshot
//! it was taken under: a configuration reload swaps the snapshot while
//! requests are mid-flight, and a per-snapshot counter would release
//! those bytes against a counter that no longer tracks them, drifting
//! upward until the ceiling refused everything.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use once_cell::sync::Lazy;

/// Bytes every in-flight capture on this process may hold at once,
/// across all rules: 64 MiB.
///
/// Sized to be irrelevant next to the node's working set (the HTTP
/// response cache alone is allowed 128 MiB) while still bounding the
/// worst case at a fixed number that does not scale with traffic.
pub const CAPTURE_MAX_INFLIGHT_BYTES: usize = 64 * 1024 * 1024;

/// A ceiling and the bytes currently reserved against it.
#[derive(Debug)]
pub struct CaptureBudget {
    ceiling: usize,
    in_flight: AtomicUsize,
    /// Whether this budget publishes `lorica_capture_inflight_bytes`.
    ///
    /// Only the process-wide one does. A budget a test built to exercise
    /// the ceiling would otherwise write the same gauge, reporting a
    /// reservation against a ceiling nothing on the node runs under.
    publishes: bool,
}

/// The process-wide budget every request reserves from.
static NODE_BUDGET: Lazy<Arc<CaptureBudget>> = Lazy::new(|| {
    Arc::new(CaptureBudget {
        ceiling: CAPTURE_MAX_INFLIGHT_BYTES,
        in_flight: AtomicUsize::new(0),
        publishes: true,
    })
});

/// The budget the proxy pipeline uses.
///
/// Tests that need to exercise the ceiling build their own
/// [`CaptureBudget`] instead, so they neither observe nor disturb the
/// accounting of a concurrently running test.
pub fn node_budget() -> &'static Arc<CaptureBudget> {
    &NODE_BUDGET
}

impl CaptureBudget {
    /// A fresh budget admitting `ceiling` bytes in total.
    pub fn new(ceiling: usize) -> Arc<Self> {
        Arc::new(Self {
            ceiling,
            in_flight: AtomicUsize::new(0),
            publishes: false,
        })
    }

    /// Mirror the current reservation into
    /// `lorica_capture_inflight_bytes` (Story 10.1 AC #9).
    ///
    /// Called after every change rather than sampled at scrape time
    /// because the counter is a process-wide static the metrics crate
    /// has no handle on, and in worker mode the scrape happens in a
    /// different process entirely.
    fn publish(&self) {
        if self.publishes {
            lorica_api::metrics::set_capture_inflight_bytes(self.in_flight() as i64);
        }
    }

    /// Bytes currently reserved.
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// The ceiling this budget admits.
    pub fn ceiling(&self) -> usize {
        self.ceiling
    }

    /// An empty reservation against this budget.
    ///
    /// Taking nothing always succeeds; a request pays only for the
    /// bytes it actually keeps, through [`CaptureReservation::grow`].
    pub fn reservation(self: &Arc<Self>) -> CaptureReservation {
        CaptureReservation {
            budget: Arc::clone(self),
            held: 0,
        }
    }
}

/// Bytes one request holds against a [`CaptureBudget`].
///
/// The release is the `Drop` impl and nothing else, so a request that
/// panics, is cancelled, or returns through a path nobody thought about
/// still gives its bytes back.
#[derive(Debug)]
pub struct CaptureReservation {
    budget: Arc<CaptureBudget>,
    held: usize,
}

impl CaptureReservation {
    /// Bytes this reservation currently holds.
    pub fn held(&self) -> usize {
        self.held
    }

    /// Reserve `extra` more bytes, all or nothing.
    ///
    /// Returns `false` when the budget is over its ceiling, in which
    /// case nothing was reserved and the caller must not buffer.
    pub fn grow(&mut self, extra: usize) -> bool {
        let ceiling = self.budget.ceiling;
        // Relaxed on both paths: the counter publishes no data, it only
        // has to be an accurate count under concurrent updates, which
        // the read-modify-write gives on its own.
        let outcome =
            self.budget
                .in_flight
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    let next = current.checked_add(extra)?;
                    (next <= ceiling).then_some(next)
                });
        if outcome.is_ok() {
            self.held += extra;
            self.budget.publish();
            true
        } else {
            false
        }
    }

    /// Give `bytes` back, for a buffer the request drops before it ends.
    ///
    /// Clamped to what is held so a double release cannot make the
    /// counter wrap and lock the node out of capturing.
    pub fn shrink(&mut self, bytes: usize) {
        let released = bytes.min(self.held);
        self.held -= released;
        self.budget.in_flight.fetch_sub(released, Ordering::Relaxed);
        self.budget.publish();
    }
}

impl Drop for CaptureReservation {
    fn drop(&mut self) {
        self.budget
            .in_flight
            .fetch_sub(self.held, Ordering::Relaxed);
        self.budget.publish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reservation_returns_its_bytes_when_dropped() {
        let budget = CaptureBudget::new(1024);
        {
            let mut reservation = budget.reservation();
            assert!(reservation.grow(600));
            assert_eq!(budget.in_flight(), 600);
            assert_eq!(reservation.held(), 600);
        }
        assert_eq!(budget.in_flight(), 0);
    }

    #[test]
    fn growth_past_the_ceiling_reserves_nothing() {
        let budget = CaptureBudget::new(1024);
        let mut reservation = budget.reservation();
        assert!(reservation.grow(1000));
        assert!(!reservation.grow(25));
        assert_eq!(budget.in_flight(), 1000);
        assert_eq!(reservation.held(), 1000);
        // The refusal is per request, not a latch: a smaller ask that
        // still fits is admitted.
        assert!(reservation.grow(24));
        assert_eq!(budget.in_flight(), 1024);
    }

    #[test]
    fn a_second_request_is_refused_while_the_first_holds_the_ceiling() {
        let budget = CaptureBudget::new(1024);
        let mut first = budget.reservation();
        assert!(first.grow(1024));
        let mut second = budget.reservation();
        assert!(!second.grow(1));
        drop(first);
        assert!(second.grow(1));
        assert_eq!(budget.in_flight(), 1);
    }

    #[test]
    fn shrinking_gives_bytes_back_without_ending_the_reservation() {
        let budget = CaptureBudget::new(1024);
        let mut reservation = budget.reservation();
        assert!(reservation.grow(500));
        reservation.shrink(500);
        assert_eq!(budget.in_flight(), 0);
        assert_eq!(reservation.held(), 0);
        // A release larger than what is held cannot wrap the counter.
        reservation.shrink(usize::MAX);
        assert_eq!(budget.in_flight(), 0);
        assert!(reservation.grow(10));
        assert_eq!(budget.in_flight(), 10);
    }

    #[test]
    fn an_absurd_ask_is_refused_instead_of_overflowing() {
        let budget = CaptureBudget::new(usize::MAX);
        let mut reservation = budget.reservation();
        assert!(reservation.grow(64));
        assert!(!reservation.grow(usize::MAX));
        assert_eq!(budget.in_flight(), 64);
    }
}
