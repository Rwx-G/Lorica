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

//! Counts of events per fixed time window, shared by every worker.
//!
//! A `lorica_limits::rate::Rate` lives in one process, so in worker
//! mode each worker counted only the share of the traffic it served. A
//! [`WindowedCount`] keeps the same count in the region's
//! [`rate_counters`](crate::SharedRegion::rate_counters) table, one key
//! per subject and window, and reads it the way `Rate::rate` does: the
//! per-second rate of the latest completed window.
//!
//! Windows are numbered from the `CLOCK_MONOTONIC` epoch
//! ([`now_ns`](crate::now_ns)), which every process on the host
//! shares, so all workers agree on which window an event falls in. A
//! window's key is idle once the window is over and is evicted like any
//! idle key.

use std::time::Duration;

use crate::hash::siphash13_u64;
use crate::region::SharedRegion;
use crate::table::{tagged_hash, SATURATED};

/// What a [`WindowedCount`] counts. It is mixed into every key, so two
/// kinds never share one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CountKind {
    /// Requests refused by a route's rate limit, per client address:
    /// the evidence the rate-limit auto-ban weighs.
    RateLimitViolations = 1,
    /// Requests the proxy received, every client together: the
    /// proxy-wide rate the flood defence compares to its threshold.
    Requests = 2,
}

/// A count of `kind` events per subject and per window of fixed length.
#[derive(Debug, Clone, Copy)]
pub struct WindowedCount {
    kind: CountKind,
    window_ns: u64,
}

impl WindowedCount {
    /// Count `kind` events in windows of `window`, which must not be
    /// zero.
    pub const fn new(kind: CountKind, window: Duration) -> Self {
        assert!(!window.is_zero(), "a window has a length");
        Self {
            kind,
            window_ns: window.as_nanos() as u64,
        }
    }

    /// Count one event of `subject` in the window `now_ns` falls in.
    /// Returns `false` when the table refused it ([`SATURATED`]): the
    /// event is not counted, which errs toward a lower rate.
    pub fn observe(&self, region: &SharedRegion, subject: u64, now_ns: u64) -> bool {
        let key = self.key(region, subject, self.window(now_ns));
        region.rate_counters.increment(key, 1, now_ns) != SATURATED
    }

    /// Events of `subject` per second over the latest completed window,
    /// as every worker counted them; 0 when that window counted none.
    pub fn rate(&self, region: &SharedRegion, subject: u64, now_ns: u64) -> f64 {
        let Some(completed) = self.window(now_ns).checked_sub(1) else {
            return 0.0;
        };
        let count = region
            .rate_counters
            .read(self.key(region, subject, completed))
            .unwrap_or(0);
        count as f64 * 1e9 / self.window_ns as f64
    }

    /// Clear `subject`'s latest completed window, so its rate reads 0
    /// until the next window completes. Returns `true` for the caller
    /// that cleared it and `false` for any racing caller that found it
    /// cleared already, which lets exactly one worker act on a rate
    /// every worker can see. A claim racing an eviction can, rarely,
    /// leave the count in two slots that two callers clear one each.
    pub fn take_completed(&self, region: &SharedRegion, subject: u64, now_ns: u64) -> bool {
        match self.window(now_ns).checked_sub(1) {
            Some(completed) => region
                .rate_counters
                .reset(self.key(region, subject, completed)),
            None => false,
        }
    }

    fn window(&self, now_ns: u64) -> u64 {
        now_ns / self.window_ns
    }

    /// The key of `subject`'s count in `window`. Window numbers stay far
    /// below 2^56, so rotating them clears the low byte for the kind and
    /// no (window, kind) pair hashes the same input as another.
    fn key(&self, region: &SharedRegion, subject: u64, window: u64) -> u64 {
        let subject_hash = siphash13_u64(region.hash_key, subject);
        let window_hash = siphash13_u64(region.hash_key, window.rotate_left(8) ^ self.kind as u64);
        tagged_hash(subject_hash ^ window_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: u64 = 1_000_000_000;
    const MINUTE: Duration = Duration::from_secs(60);

    #[test]
    fn the_rate_is_the_latest_completed_window_per_second() {
        let (region, _fd) = SharedRegion::create_supervisor().expect("create");
        let violations = WindowedCount::new(CountKind::RateLimitViolations, MINUTE);
        let start = 1_000 * 60 * SECOND;
        for i in 0..120 {
            assert!(violations.observe(region, 7, start + i * 100_000_000));
        }
        // Still inside the window being counted: nothing completed yet.
        assert_eq!(violations.rate(region, 7, start + 59 * SECOND), 0.0);
        // The next window reads the 120 events over 60 s.
        assert_eq!(violations.rate(region, 7, start + 61 * SECOND), 2.0);
        // Two windows on, that window is no longer the latest completed.
        assert_eq!(violations.rate(region, 7, start + 121 * SECOND), 0.0);
    }

    #[test]
    fn subjects_keep_separate_counts() {
        let (region, _fd) = SharedRegion::create_supervisor().expect("create");
        let violations = WindowedCount::new(CountKind::RateLimitViolations, MINUTE);
        let now = 500 * 60 * SECOND;
        for _ in 0..60 {
            violations.observe(region, 1, now);
        }
        let next = now + 60 * SECOND;
        assert_eq!(violations.rate(region, 1, next), 1.0);
        assert_eq!(violations.rate(region, 2, next), 0.0);
    }

    #[test]
    fn kinds_keep_separate_counts_for_the_same_subject_and_window() {
        let (region, _fd) = SharedRegion::create_supervisor().expect("create");
        let violations = WindowedCount::new(CountKind::RateLimitViolations, MINUTE);
        let requests = WindowedCount::new(CountKind::Requests, MINUTE);
        let now = 700 * 60 * SECOND;
        for _ in 0..60 {
            requests.observe(region, 0, now);
        }
        let next = now + 60 * SECOND;
        assert_eq!(requests.rate(region, 0, next), 1.0);
        assert_eq!(violations.rate(region, 0, next), 0.0);
    }

    #[test]
    fn a_completed_window_is_taken_once() {
        let (region, _fd) = SharedRegion::create_supervisor().expect("create");
        let violations = WindowedCount::new(CountKind::RateLimitViolations, MINUTE);
        let now = 900 * 60 * SECOND;
        violations.observe(region, 3, now);
        let next = now + 60 * SECOND;
        assert!(violations.take_completed(region, 3, next));
        assert!(!violations.take_completed(region, 3, next));
        assert_eq!(violations.rate(region, 3, next), 0.0);
        // The window being counted is untouched.
        violations.observe(region, 3, next);
        assert_eq!(violations.rate(region, 3, next + 60 * SECOND), 1.0 / 60.0);
    }
}
