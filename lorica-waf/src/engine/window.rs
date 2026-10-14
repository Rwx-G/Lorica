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

//! Per-minute WAF event counts over the last day.
//!
//! The recent-event ring keeps the last few hundred events and drops the
//! oldest, so a count taken from it is bounded by its capacity: a burst
//! larger than the ring reads as exactly the ring's size. These counters
//! keep one number per category per minute instead of the events
//! themselves, which makes a windowed count exact whatever the traffic,
//! for a memory cost fixed by the window length.

use std::time::Duration;

use chrono::{DateTime, Utc};

/// The longest window [`EventWindow::counts_within`] answers. A longer
/// one is answered over this one.
pub const LONGEST_EVENT_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// One slot per minute of [`LONGEST_EVENT_WINDOW`], plus the minute in
/// progress: a window's first minute is only partly inside it and still
/// has to be held.
const SLOTS: usize = (LONGEST_EVENT_WINDOW.as_secs() / 60) as usize + 1;

/// WAF events counted over a window by [`crate::WafEngine::event_counts_within`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WindowCounts {
    /// Events recorded in the window.
    pub total: u64,
    /// `(category, count)` pairs, highest count first, ties by category.
    pub by_category: Vec<(String, u64)>,
}

#[derive(Debug, Clone)]
struct MinuteSlot {
    /// Minutes since the Unix epoch this slot counts, `i64::MIN` while
    /// it has never counted one.
    minute: i64,
    by_category: Vec<(&'static str, u64)>,
}

/// A ring of per-minute, per-category counters, indexed by the minute
/// modulo the ring length. A slot whose stored minute is not the one
/// asked about is stale and reads as empty.
#[derive(Debug)]
pub(super) struct EventWindow {
    slots: Vec<MinuteSlot>,
}

pub(super) fn minute_of(at: DateTime<Utc>) -> i64 {
    at.timestamp().div_euclid(60)
}

/// The minute an event stamped `timestamp` (RFC 3339) counts in, or
/// `None` when it is older than the longest window and is not counted.
///
/// The event's own stamp decides its minute, not `now`: an event a
/// worker forwarded arrives up to a second after it fired. A stamp that
/// does not parse counts at `now`, and one ahead of `now` (a worker
/// clock running ahead) counts at `now`.
///
/// Pure, so a caller parses before it takes the window's lock.
pub(super) fn minute_for(timestamp: &str, now: DateTime<Utc>) -> Option<i64> {
    let now_minute = minute_of(now);
    let minute = DateTime::parse_from_rfc3339(timestamp)
        .map(|at| minute_of(at.with_timezone(&Utc)))
        .unwrap_or(now_minute)
        .min(now_minute);
    (now_minute - minute < SLOTS as i64).then_some(minute)
}

impl EventWindow {
    pub(super) fn new() -> Self {
        Self {
            slots: vec![
                MinuteSlot {
                    minute: i64::MIN,
                    by_category: Vec::new(),
                };
                SLOTS
            ],
        }
    }

    /// Count one event of `category` stamped `timestamp` (RFC 3339), at
    /// the minute [`minute_for`] places it in.
    #[cfg(test)]
    pub(super) fn record(&mut self, timestamp: &str, category: &'static str, now: DateTime<Utc>) {
        if let Some(minute) = minute_for(timestamp, now) {
            self.count_at(minute, category, 1);
        }
    }

    /// Add `count` events of `category` to `minute`, a value
    /// [`minute_for`] or [`minute_of`] produced.
    pub(super) fn count_at(&mut self, minute: i64, category: &'static str, count: u64) {
        let slot = &mut self.slots[minute.rem_euclid(SLOTS as i64) as usize];
        // The minute was placed before the lock was taken; if the clock
        // crossed into the minute that reuses this slot meanwhile, the
        // event has aged out and must not wipe the newer minute.
        if slot.minute > minute {
            return;
        }
        if slot.minute != minute {
            slot.minute = minute;
            slot.by_category.clear();
        }
        match slot.by_category.iter_mut().find(|(c, _)| *c == category) {
            Some((_, total)) => *total += count,
            None => slot.by_category.push((category, count)),
        }
    }

    /// Events counted from the minute `window` before `now` up to `now`.
    ///
    /// Minute resolution: the window's start is rounded down to the
    /// minute it falls in, so the answer may include events up to one
    /// minute older than `window`, never fewer than the window holds.
    pub(super) fn counts_within(&self, window: Duration, now: DateTime<Utc>) -> WindowCounts {
        let window = window.min(LONGEST_EVENT_WINDOW);
        let now_minute = minute_of(now);
        let first_minute = (now.timestamp() - window.as_secs() as i64).div_euclid(60);
        let mut counts = WindowCounts::default();
        for slot in self
            .slots
            .iter()
            .filter(|slot| (first_minute..=now_minute).contains(&slot.minute))
        {
            for &(category, count) in &slot.by_category {
                counts.total += count;
                match counts.by_category.iter_mut().find(|(c, _)| c == category) {
                    Some((_, total)) => *total += count,
                    None => counts.by_category.push((category.to_string(), count)),
                }
            }
        }
        counts
            .by_category
            .sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        counts
    }

    pub(super) fn clear(&mut self) {
        for slot in &mut self.slots {
            slot.minute = i64::MIN;
            slot.by_category.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);

    fn at(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339)
            .expect("a valid stamp")
            .with_timezone(&Utc)
    }

    fn stamp(now: DateTime<Utc>, ago: chrono::Duration) -> String {
        (now - ago).to_rfc3339()
    }

    #[test]
    fn counts_split_on_the_window_edge() {
        let now = at("2026-10-14T12:30:30Z");
        let mut window = EventWindow::new();
        let inside = stamp(now, chrono::Duration::minutes(59));
        let outside = stamp(now, chrono::Duration::minutes(62));
        for _ in 0..3 {
            window.record(&inside, "xss", now);
        }
        for _ in 0..4 {
            window.record(&outside, "sql_injection", now);
        }

        let hour = window.counts_within(HOUR, now);
        assert_eq!(hour.total, 3);
        assert_eq!(hour.by_category, vec![("xss".to_string(), 3)]);
        let day = window.counts_within(LONGEST_EVENT_WINDOW, now);
        assert_eq!(day.total, 7);
        assert_eq!(
            day.by_category,
            vec![("sql_injection".to_string(), 4), ("xss".to_string(), 3)]
        );
    }

    #[test]
    fn the_window_start_rounds_down_to_its_minute() {
        // 12:30:30 minus an hour is 11:30:30; the 11:30 minute is held
        // whole, 11:29 is not.
        let now = at("2026-10-14T12:30:30Z");
        let mut window = EventWindow::new();
        window.record("2026-10-14T11:30:05Z", "xss", now);
        window.record("2026-10-14T11:29:59Z", "xss", now);
        assert_eq!(window.counts_within(HOUR, now).total, 1);
    }

    #[test]
    fn counts_expire_once_the_window_has_moved_past_them() {
        let start = at("2026-10-14T12:00:00Z");
        let mut window = EventWindow::new();
        for _ in 0..10 {
            window.record(&start.to_rfc3339(), "xss", start);
        }
        assert_eq!(window.counts_within(HOUR, start).total, 10);

        let later = start + chrono::Duration::minutes(61);
        assert_eq!(window.counts_within(HOUR, later).total, 0);
        assert_eq!(window.counts_within(LONGEST_EVENT_WINDOW, later).total, 10);

        let next_day = start + chrono::Duration::hours(24) + chrono::Duration::minutes(1);
        assert_eq!(
            window.counts_within(LONGEST_EVENT_WINDOW, next_day).total,
            0
        );
    }

    #[test]
    fn a_reused_slot_drops_the_day_old_minute_it_held() {
        let start = at("2026-10-14T12:00:00Z");
        let mut window = EventWindow::new();
        window.record(&start.to_rfc3339(), "xss", start);
        // The same slot, one full ring later.
        let wrapped = start + chrono::Duration::minutes(SLOTS as i64);
        window.record(&wrapped.to_rfc3339(), "sql_injection", wrapped);
        let day = window.counts_within(LONGEST_EVENT_WINDOW, wrapped);
        assert_eq!(day.by_category, vec![("sql_injection".to_string(), 1)]);
    }

    #[test]
    fn a_minute_placed_before_its_slot_was_reused_does_not_wipe_the_newer_minute() {
        let now = at("2026-10-14T12:00:00Z");
        let mut window = EventWindow::new();
        let aged = minute_for(
            &stamp(now, chrono::Duration::minutes(SLOTS as i64 - 1)),
            now,
        )
        .expect("still inside the longest window");
        window.record(&now.to_rfc3339(), "xss", now);
        let reused = now + chrono::Duration::minutes(1);
        window.record(&reused.to_rfc3339(), "xss", reused);
        window.count_at(aged, "sql_injection", 1);
        let day = window.counts_within(LONGEST_EVENT_WINDOW, reused);
        assert_eq!(day.by_category, vec![("xss".to_string(), 2)]);
    }

    #[test]
    fn stamps_out_of_range_or_unreadable_are_placed_sensibly() {
        let now = at("2026-10-14T12:00:00Z");
        let mut window = EventWindow::new();
        window.record("not a timestamp", "xss", now);
        window.record(&stamp(now, chrono::Duration::minutes(-5)), "xss", now);
        window.record(&stamp(now, chrono::Duration::hours(25)), "xss", now);
        assert_eq!(window.counts_within(HOUR, now).total, 2);
        assert_eq!(window.counts_within(LONGEST_EVENT_WINDOW, now).total, 2);
    }

    #[test]
    fn a_longer_window_is_answered_over_the_longest_held() {
        let now = at("2026-10-14T12:00:00Z");
        let mut window = EventWindow::new();
        window.record(&now.to_rfc3339(), "xss", now);
        let week = Duration::from_secs(7 * 24 * 3600);
        assert_eq!(window.counts_within(week, now).total, 1);
    }

    #[test]
    fn clear_empties_every_minute() {
        let now = at("2026-10-14T12:00:00Z");
        let mut window = EventWindow::new();
        window.record(&now.to_rfc3339(), "xss", now);
        window.clear();
        assert_eq!(
            window.counts_within(LONGEST_EVENT_WINDOW, now),
            WindowCounts::default()
        );
    }
}
