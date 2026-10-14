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

//! The two ends of the worker-to-supervisor WAF event stream (`waf.sock`).
//!
//! A worker polls its engine's numbered events and writes each new one
//! as a JSON line; the supervisor reads the lines, records each event in
//! its own engine and acts on it (WAF alert, global auto-ban check). The
//! worker has no notification sender of its own, so an event that never
//! crosses this stream raises no alert and triggers no auto-ban check.

use std::time::Duration;

use lorica_waf::{WafEngine, WafEvent};

/// How often a worker drains its new WAF events to the supervisor.
///
/// The worker reads them from its engine's bounded ring, so an event
/// survives only until that many newer ones push it out: draining every
/// 100 ms loses nothing below ten times the ring's capacity per second.
/// Past that rate the drop is counted and logged, see
/// [`WafForwardCursor::take_batch`].
pub(crate) const FORWARD_INTERVAL: Duration = Duration::from_millis(100);

/// A worker's position in its engine's event numbering.
#[derive(Debug, Default)]
pub(crate) struct WafForwardCursor {
    next: u64,
    lost: u64,
}

impl WafForwardCursor {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The events `engine` recorded since the last call, oldest first.
    ///
    /// Events the ring dropped before this call could read them are
    /// logged at WARN with the running total, since the supervisor will
    /// never alert on them nor check them against the auto-ban
    /// threshold.
    pub(crate) fn take_batch(&mut self, engine: &WafEngine) -> Vec<WafEvent> {
        let after = engine.events_after(self.next);
        self.next = after.next;
        if after.lost > 0 {
            self.lost += after.lost;
            tracing::warn!(
                lost = after.lost,
                lost_total = self.lost,
                "worker: WAF events dropped from the ring before reaching the supervisor"
            );
        }
        after.events
    }

    /// Events dropped before they could be forwarded, since the cursor
    /// was created.
    #[cfg(test)]
    fn lost(&self) -> u64 {
        self.lost
    }
}

/// One line of the stream, newline included.
pub(crate) fn encode_forwarded_event(event: &WafEvent) -> Option<String> {
    serde_json::to_string(event).ok().map(|json| json + "\n")
}

/// Decode one line a worker forwarded and record the event in the
/// supervisor's `engine`, so its recent events and its rolling hour and
/// day counts cover every worker's events. `None` for a line that is
/// not an event.
pub(crate) fn record_forwarded_event(engine: &WafEngine, line: &str) -> Option<WafEvent> {
    let event: WafEvent = serde_json::from_str(line).ok()?;
    engine.record_events(vec![event.clone()]);
    Some(event)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);

    fn event(rule_id: u32) -> WafEvent {
        WafEvent {
            rule_id,
            description: "test".into(),
            category: lorica_waf::RuleCategory::Xss,
            severity: 3,
            matched_field: "uri".into(),
            matched_value: "x".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            client_ip: "192.0.2.10".into(),
            route_hostname: "example.com".into(),
            action: "blocked".into(),
        }
    }

    #[test]
    fn an_event_recorded_once_the_ring_is_full_is_still_forwarded() {
        let engine = WafEngine::new();
        let mut cursor = WafForwardCursor::new();
        let mut forwarded = Vec::new();
        for rule_id in 1..=501 {
            engine.record_events(vec![event(rule_id)]);
            forwarded.extend(cursor.take_batch(&engine));
        }
        assert_eq!(forwarded.len(), 501);
        assert_eq!(forwarded.last().map(|e| e.rule_id), Some(501));
    }

    #[test]
    fn events_the_ring_dropped_between_two_ticks_are_counted_as_lost() {
        let engine = WafEngine::new();
        let mut cursor = WafForwardCursor::new();
        engine.record_events((1..=1200).map(event).collect());

        let forwarded = cursor.take_batch(&engine);
        assert_eq!(forwarded.len() as u64 + cursor.lost(), 1200);
        assert_eq!(forwarded.last().map(|e| e.rule_id), Some(1200));

        engine.record_events(vec![event(1201)]);
        let forwarded = cursor.take_batch(&engine);
        assert_eq!(
            forwarded.iter().map(|e| e.rule_id).collect::<Vec<_>>(),
            vec![1201]
        );
        assert_eq!(cursor.lost(), 1200 - 500);
    }

    #[test]
    fn the_supervisor_counts_every_forwarded_event_in_its_windows() {
        let worker = WafEngine::new();
        let supervisor = WafEngine::new();
        let mut cursor = WafForwardCursor::new();
        let total = 1300;
        for rule_id in 1..=total {
            worker.record_events(vec![event(rule_id)]);
            for forwarded in cursor.take_batch(&worker) {
                let line = encode_forwarded_event(&forwarded).expect("event encodes");
                let received = record_forwarded_event(&supervisor, &line).expect("line decodes");
                assert_eq!(received.rule_id, forwarded.rule_id);
            }
        }
        let hour = supervisor.event_counts_within(HOUR);
        assert_eq!(hour.total, u64::from(total));
        assert_eq!(
            hour.by_category,
            vec![("xss".to_string(), u64::from(total))]
        );
        assert_eq!(supervisor.recent_events(1)[0].rule_id, total);
    }

    #[test]
    fn a_line_that_is_not_an_event_is_not_recorded() {
        let supervisor = WafEngine::new();
        assert!(record_forwarded_event(&supervisor, "not json\n").is_none());
        assert_eq!(supervisor.event_count(), 0);
        assert_eq!(supervisor.event_counts_within(HOUR).total, 0);
    }
}
