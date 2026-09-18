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

//! A process-wide ceiling on bytes held in memory for one purpose.
//!
//! Two features buffer request bodies that no client is waiting on:
//! traffic capture ([`crate::capture`]) and WAF body inspection
//! ([`crate::proxy_wiring::waf_body_budget`]). Both would otherwise be a
//! memory-exhaustion primitive, because `feature enabled x request rate
//! x per-request cap` is unbounded. Both answer it the same way, so the
//! rule lives here once: one counter covers every in-flight request on
//! the process, and a request that cannot fit under it buffers nothing
//! instead of allocating anyway.
//!
//! The counter is a process-wide static rather than a field on the
//! configuration snapshot, because a reservation outlives the snapshot
//! it was taken under: a configuration reload swaps the snapshot while
//! requests are mid-flight, and a per-snapshot counter would release
//! those bytes against a counter that no longer tracks them, drifting
//! upward until the ceiling refused everything.
//!
//! The two budgets differ in exactly two ways, which is why this type
//! carries both as data rather than being copied twice:
//!
//! - The ceiling. Capture's is a compile-time constant; the WAF's comes
//!   from a global setting and moves on reload, hence [`AtomicUsize`]
//!   and [`ByteBudget::set_ceiling`] rather than a plain field.
//! - The gauge. Each budget publishes its own, so the publisher is a
//!   function pointer given at construction and `None` for a budget a
//!   test built, which must not write a node-wide gauge.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// A ceiling and the bytes currently reserved against it.
#[derive(Debug)]
pub struct ByteBudget {
    /// Bytes admitted in total. Atomic because a budget fed by a
    /// setting is re-pointed by a configuration reload while requests
    /// hold reservations against the previous value.
    ceiling: AtomicUsize,
    in_flight: AtomicUsize,
    /// The gauge this budget mirrors itself into, when it has one.
    ///
    /// Only a process-wide budget publishes. A budget a test built to
    /// exercise the ceiling would otherwise write the same gauge,
    /// reporting a reservation against a ceiling nothing on the node
    /// runs under.
    publish: Option<fn(i64)>,
}

impl ByteBudget {
    /// A fresh budget admitting `ceiling` bytes in total, publishing no
    /// gauge.
    ///
    /// This is what a test builds, so it neither observes nor disturbs
    /// the accounting of a concurrently running test.
    pub fn new(ceiling: usize) -> Arc<Self> {
        Arc::new(Self {
            ceiling: AtomicUsize::new(ceiling),
            in_flight: AtomicUsize::new(0),
            publish: None,
        })
    }

    /// A fresh budget that mirrors every change into `gauge`.
    ///
    /// Reserved for the process-wide budgets, one per purpose. The
    /// gauge is written after every change rather than sampled at
    /// scrape time because the budget is a process-wide static the
    /// metrics crate has no handle on, and in worker mode the scrape
    /// happens in a different process entirely.
    pub fn publishing(ceiling: usize, gauge: fn(i64)) -> Arc<Self> {
        Arc::new(Self {
            ceiling: AtomicUsize::new(ceiling),
            in_flight: AtomicUsize::new(0),
            publish: Some(gauge),
        })
    }

    /// Mirror the current reservation into this budget's gauge.
    fn publish_gauge(&self) {
        if let Some(gauge) = self.publish {
            gauge(self.in_flight() as i64);
        }
    }

    /// Bytes currently reserved.
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// The ceiling this budget admits.
    pub fn ceiling(&self) -> usize {
        self.ceiling.load(Ordering::Relaxed)
    }

    /// Point the budget at a new ceiling, for one fed by a setting.
    ///
    /// Reservations already taken are untouched: lowering the ceiling
    /// below what is held refuses the next `grow` rather than
    /// confiscating bytes a request is still using, and the counter
    /// walks back under the new ceiling as those requests end.
    pub fn set_ceiling(&self, ceiling: usize) {
        self.ceiling.store(ceiling, Ordering::Relaxed);
    }

    /// An empty reservation against this budget.
    ///
    /// Taking nothing always succeeds; a request pays only for the
    /// bytes it actually keeps, through [`ByteReservation::grow`].
    pub fn reservation(self: &Arc<Self>) -> ByteReservation {
        ByteReservation {
            budget: Arc::clone(self),
            held: 0,
        }
    }
}

/// Bytes one request holds against a [`ByteBudget`].
///
/// The release is the `Drop` impl and nothing else, so a request that
/// panics, is cancelled, or returns through a path nobody thought about
/// still gives its bytes back.
#[derive(Debug)]
pub struct ByteReservation {
    budget: Arc<ByteBudget>,
    held: usize,
}

impl ByteReservation {
    /// Bytes this reservation currently holds.
    pub fn held(&self) -> usize {
        self.held
    }

    /// Reserve `extra` more bytes, all or nothing.
    ///
    /// Returns `false` when the budget is over its ceiling, in which
    /// case nothing was reserved and the caller must not buffer.
    pub fn grow(&mut self, extra: usize) -> bool {
        let ceiling = self.budget.ceiling();
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
            self.budget.publish_gauge();
            true
        } else {
            false
        }
    }

    /// Give `bytes` back, for a buffer the request drops before it ends.
    ///
    /// Clamped to what is held so a double release cannot make the
    /// counter wrap and lock the node out of buffering.
    pub fn shrink(&mut self, bytes: usize) {
        let released = bytes.min(self.held);
        self.held -= released;
        self.budget.in_flight.fetch_sub(released, Ordering::Relaxed);
        self.budget.publish_gauge();
    }
}

impl Drop for ByteReservation {
    fn drop(&mut self) {
        self.budget
            .in_flight
            .fetch_sub(self.held, Ordering::Relaxed);
        self.budget.publish_gauge();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reservation_returns_its_bytes_when_dropped() {
        let budget = ByteBudget::new(1024);
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
        let budget = ByteBudget::new(1024);
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
        let budget = ByteBudget::new(1024);
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
        let budget = ByteBudget::new(1024);
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
        let budget = ByteBudget::new(usize::MAX);
        let mut reservation = budget.reservation();
        assert!(reservation.grow(64));
        assert!(!reservation.grow(usize::MAX));
        assert_eq!(budget.in_flight(), 64);
    }

    #[test]
    fn a_raised_ceiling_admits_what_it_refused() {
        let budget = ByteBudget::new(512);
        let mut reservation = budget.reservation();
        assert!(!reservation.grow(1024));
        budget.set_ceiling(2048);
        assert_eq!(budget.ceiling(), 2048);
        assert!(reservation.grow(1024));
        assert_eq!(budget.in_flight(), 1024);
    }

    #[test]
    fn a_lowered_ceiling_leaves_held_bytes_alone_and_refuses_the_next_ask() {
        // A reload that shrinks the budget must not confiscate bytes a
        // request is still reading from; it stops admitting new ones
        // and the counter walks back down as requests end.
        let budget = ByteBudget::new(4096);
        let mut reservation = budget.reservation();
        assert!(reservation.grow(4096));
        budget.set_ceiling(1024);
        assert_eq!(budget.in_flight(), 4096);
        assert!(!reservation.grow(1));
        drop(reservation);
        assert_eq!(budget.in_flight(), 0);
        let mut next = budget.reservation();
        assert!(next.grow(1024));
        assert!(!next.grow(1));
    }

    #[test]
    fn a_publishing_budget_mirrors_every_change_into_its_gauge() {
        use std::sync::atomic::AtomicI64;
        static GAUGE: AtomicI64 = AtomicI64::new(-1);
        fn publish(value: i64) {
            GAUGE.store(value, Ordering::Relaxed);
        }

        let budget = ByteBudget::publishing(1024, publish);
        {
            let mut reservation = budget.reservation();
            assert!(reservation.grow(256));
            assert_eq!(GAUGE.load(Ordering::Relaxed), 256);
            reservation.shrink(56);
            assert_eq!(GAUGE.load(Ordering::Relaxed), 200);
        }
        assert_eq!(GAUGE.load(Ordering::Relaxed), 0);
    }
}
