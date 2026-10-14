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

//! Coalescing of `waf_alert` events before they reach the broadcast.
//!
//! A WAF alert used to be one notification per matched request. Under
//! an attack that is thousands a second: the channels' send budgets are
//! spent in the first second, the history fills with one attacker, and
//! the single dispatcher falls behind the bounded broadcast and drops
//! whatever else was queued, a `log_store_unavailable` included.
//!
//! The scheme, per *source* (a category and a client address):
//!
//! - the first event from a source is alerted at once, so an operator
//!   still hears about a new attack within the second it starts;
//! - every later event from it is counted, and once per
//!   [`WAF_ALERT_WINDOW`] a source that kept firing gets one summary
//!   carrying the count; a source that went quiet for a whole window is
//!   forgotten and alerts afresh next time;
//! - at most [`WAF_ALERT_SOURCES`] sources are tracked at once; an
//!   event from any further source is counted into one overflow summary
//!   per window rather than alerted on its own, so a spray from many
//!   addresses cannot buy one notification per address.
//!
//! So whatever the traffic, one window raises at most one alert and one
//! summary per tracked source plus one overflow summary. What is lost is
//! the per-request detail (rule, path) of the events after the first,
//! which the WAF event log keeps.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::events::{AlertEvent, AlertType};

/// How long the events of one source are folded into one summary.
pub const WAF_ALERT_WINDOW: Duration = Duration::from_secs(60);

/// How many sources are tracked, and so alerted on individually, at
/// once.
pub const WAF_ALERT_SOURCES: usize = 16;

/// The detail a producer sets on a `waf_alert` that stands for more
/// than one event (a worker reporting events it could not forward one
/// by one). Absent means one.
pub const EVENTS_DETAIL: &str = "events";

/// A source: the category and the client address of a WAF alert.
type SourceKey = (String, String);

#[derive(Debug)]
struct SourceState {
    opened: Instant,
    suppressed: u64,
}

#[derive(Debug, Default)]
struct Overflow {
    events: u64,
    since: Option<Instant>,
}

/// Folds `waf_alert` events into the scheme described in the module
/// documentation. Every other alert type passes through untouched.
#[derive(Debug)]
pub(crate) struct WafAlertCoalescer {
    window: Duration,
    max_sources: usize,
    sources: HashMap<SourceKey, SourceState>,
    overflow: Overflow,
}

impl Default for WafAlertCoalescer {
    fn default() -> Self {
        Self::new(WAF_ALERT_WINDOW, WAF_ALERT_SOURCES)
    }
}

impl WafAlertCoalescer {
    pub(crate) fn new(window: Duration, max_sources: usize) -> Self {
        Self {
            window,
            max_sources,
            sources: HashMap::new(),
            overflow: Overflow::default(),
        }
    }

    /// The event to broadcast now for `event`, or `None` when it was
    /// folded into a later summary.
    pub(crate) fn admit(&mut self, event: AlertEvent, now: Instant) -> Option<AlertEvent> {
        if event.alert_type != AlertType::WafAlert {
            return Some(event);
        }
        let events = event
            .details
            .get(EVENTS_DETAIL)
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(1)
            .max(1);
        let key = (
            event.details.get("category").cloned().unwrap_or_default(),
            event.details.get("client_ip").cloned().unwrap_or_default(),
        );
        if let Some(source) = self.sources.get_mut(&key) {
            source.suppressed += events;
            return None;
        }
        if self.sources.len() >= self.max_sources {
            self.overflow.events += events;
            self.overflow.since.get_or_insert(now);
            return None;
        }
        self.sources.insert(
            key,
            SourceState {
                opened: now,
                suppressed: events - 1,
            },
        );
        Some(event.with_detail("coalesce_window_s", self.window.as_secs().to_string()))
    }

    /// The summaries owed at `now`: one per source whose window ended
    /// with events folded into it, and one for the overflow. Sources
    /// whose window ended quiet are forgotten.
    pub(crate) fn flush(&mut self, now: Instant) -> Vec<AlertEvent> {
        let window = self.window;
        let mut summaries = Vec::new();
        self.sources.retain(|(category, client_ip), source| {
            if now.duration_since(source.opened) < window {
                return true;
            }
            if source.suppressed == 0 {
                return false;
            }
            summaries.push(source_summary(
                category,
                client_ip,
                source.suppressed,
                window,
            ));
            source.opened = now;
            source.suppressed = 0;
            true
        });
        if let Some(since) = self.overflow.since {
            if now.duration_since(since) >= window {
                summaries.push(overflow_summary(
                    self.overflow.events,
                    self.max_sources,
                    window,
                ));
                self.overflow = Overflow::default();
            }
        }
        summaries
    }
}

fn source_summary(category: &str, client_ip: &str, events: u64, window: Duration) -> AlertEvent {
    AlertEvent::new(
        AlertType::WafAlert,
        format!(
            "WAF {category}: {events} more events from {client_ip} in the last {} s",
            window.as_secs()
        ),
    )
    .with_detail("category", category)
    .with_detail("client_ip", client_ip)
    .with_detail(EVENTS_DETAIL, events.to_string())
    .with_detail("coalesce_window_s", window.as_secs().to_string())
}

fn overflow_summary(events: u64, max_sources: usize, window: Duration) -> AlertEvent {
    AlertEvent::new(
        AlertType::WafAlert,
        format!(
            "WAF: {events} events in the last {} s from sources past the {max_sources} \
             alerted individually; see the WAF event log",
            window.as_secs()
        ),
    )
    .with_detail(EVENTS_DETAIL, events.to_string())
    .with_detail("coalesce_window_s", window.as_secs().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOW: Duration = Duration::from_secs(60);

    fn waf(category: &str, client_ip: &str) -> AlertEvent {
        AlertEvent::new(AlertType::WafAlert, "WAF match")
            .with_detail("category", category)
            .with_detail("client_ip", client_ip)
    }

    fn events_of(event: &AlertEvent) -> u64 {
        event
            .details
            .get(EVENTS_DETAIL)
            .and_then(|n| n.parse().ok())
            .unwrap_or(1)
    }

    #[test]
    fn other_alert_types_pass_untouched() {
        let mut coalescer = WafAlertCoalescer::new(WINDOW, 1);
        let start = Instant::now();
        for _ in 0..100 {
            let event = AlertEvent::new(AlertType::LogStoreUnavailable, "down");
            assert!(coalescer.admit(event, start).is_some());
        }
    }

    #[test]
    fn a_flood_from_one_source_is_one_alert_then_one_summary_per_window() {
        let mut coalescer = WafAlertCoalescer::new(WINDOW, 4);
        let start = Instant::now();
        let mut broadcast = 0;
        for _ in 0..10_000 {
            broadcast += usize::from(coalescer.admit(waf("xss", "192.0.2.10"), start).is_some());
        }
        assert_eq!(broadcast, 1, "only the first event is alerted at once");
        assert!(coalescer.flush(start + WINDOW / 2).is_empty());

        let summaries = coalescer.flush(start + WINDOW);
        assert_eq!(summaries.len(), 1);
        assert_eq!(
            events_of(&summaries[0]),
            9_999,
            "every folded event is counted"
        );

        // Still firing: the next window folds into the next summary.
        coalescer.admit(waf("xss", "192.0.2.10"), start + WINDOW);
        assert!(coalescer.flush(start + WINDOW + WINDOW / 2).is_empty());
        let next = coalescer.flush(start + WINDOW * 2);
        assert_eq!(next.iter().map(events_of).collect::<Vec<_>>(), vec![1]);

        // Quiet for a window: forgotten, so the next event alerts again.
        assert!(coalescer.flush(start + WINDOW * 3).is_empty());
        assert!(coalescer
            .admit(waf("xss", "192.0.2.10"), start + WINDOW * 3)
            .is_some());
    }

    #[test]
    fn categories_and_addresses_are_separate_sources() {
        let mut coalescer = WafAlertCoalescer::new(WINDOW, 4);
        let start = Instant::now();
        assert!(coalescer.admit(waf("xss", "192.0.2.10"), start).is_some());
        assert!(coalescer
            .admit(waf("sql_injection", "192.0.2.10"), start)
            .is_some());
        assert!(coalescer.admit(waf("xss", "192.0.2.11"), start).is_some());
        assert!(coalescer.admit(waf("xss", "192.0.2.10"), start).is_none());
    }

    #[test]
    fn sources_past_the_cap_fold_into_one_overflow_summary() {
        let max_sources = 3;
        let mut coalescer = WafAlertCoalescer::new(WINDOW, max_sources);
        let start = Instant::now();
        let sprayed = 1_000;
        let mut broadcast = 0;
        for host in 0..sprayed {
            let event = waf("xss", &format!("2001:db8::{host:x}"));
            broadcast += usize::from(coalescer.admit(event, start).is_some());
        }
        assert_eq!(broadcast, max_sources);

        let summaries = coalescer.flush(start + WINDOW);
        assert_eq!(summaries.len(), 1, "the tracked sources fired once each");
        assert_eq!(
            events_of(&summaries[0]),
            (sprayed - max_sources) as u64,
            "the overflow counts every event past the cap"
        );
    }

    #[test]
    fn an_event_standing_for_several_counts_as_several() {
        let mut coalescer = WafAlertCoalescer::new(WINDOW, 4);
        let start = Instant::now();
        let first = waf("xss", "192.0.2.10").with_detail(EVENTS_DETAIL, "5");
        assert!(coalescer.admit(first, start).is_some());
        let more = waf("xss", "192.0.2.10").with_detail(EVENTS_DETAIL, "7");
        assert!(coalescer.admit(more, start).is_none());
        let summaries = coalescer.flush(start + WINDOW);
        assert_eq!(
            summaries.iter().map(events_of).collect::<Vec<_>>(),
            vec![4 + 7]
        );
    }
}
