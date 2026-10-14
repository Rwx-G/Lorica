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

//! WAF engine module: `WafEngine` and its public types.
//!
//! Organized as a module directory rather than a single file because
//! the engine grew past ~1100 LOC with the v1.3.0 prefilter work. The
//! crate's public API is unchanged: [`WafEngine`], [`WafEvent`],
//! [`WafVerdict`], [`WafMode`], [`RuleSummary`], and [`CustomRule`]
//! remain reachable at `lorica_waf::engine::*`.
//!
//! Submodules:
//! - [`types`] - public data types ([`WafEvent`], [`WafVerdict`],
//!   [`WafMode`], [`RuleSummary`], [`CustomRule`]).
//! - [`eval`] - hot-path [`WafEngine::evaluate`] /
//!   [`WafEngine::evaluate_body`] + the private `scan_field` helper.
//! - [`custom_rules`] - admin-facing CRUD for user-defined rules and
//!   the associated pattern/size caps.
//! - [`url_decode`] - recursive URL decoding helpers used by the hot
//!   path.
//! - [`window`] - per-minute event counts over the last day, beside
//!   the bounded recent-event ring.
//! - [`forward`] - the outbox a worker drains to forward its events.

mod custom_rules;
mod eval;
mod forward;
mod types;
mod url_decode;
mod window;

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, OnceLock};

use parking_lot::{Mutex, RwLock};

use crate::ip_blocklist::IpBlocklist;
use crate::rules::{RuleCategory, RuleSet};

pub use forward::{LostEvents, FORWARD_OUTBOX_CAPACITY, LOST_SOURCES_CAPACITY};
pub use types::{CustomRule, RuleSummary, WafEvent, WafMode, WafVerdict};
pub use window::{WindowCounts, LONGEST_EVENT_WINDOW};

/// What [`WafEngine::events_after`] answers for a sequence cursor.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EventsAfter {
    /// Events recorded after the cursor that the outbox still held,
    /// oldest first.
    pub events: Vec<WafEvent>,
    /// The cursor to pass next time: the sequence number of the last
    /// event recorded so far.
    pub next: u64,
    /// Events recorded after the cursor that the outbox dropped before
    /// they were asked for.
    pub lost: u64,
    /// The sources of those dropped events, as far as the outbox could
    /// count them (see [`LOST_SOURCES_CAPACITY`]).
    pub lost_by_source: Vec<LostEvents>,
}

/// WAF engine with precompiled rules, IP blocklist, and event ring buffer.
///
/// Cheap to share across worker threads behind an `Arc`: all mutable
/// state (disabled rule set, custom rules, event buffer, blocklist) is
/// behind interior locks. The recent-event buffer is bounded
/// (`max_events`); older events are dropped FIFO. Every recorded event is
/// also counted per minute, so [`Self::event_counts_within`] is exact
/// over its window however many events the ring has dropped. An engine
/// whose events are forwarded elsewhere also numbers them in an outbox,
/// see [`Self::enable_forwarding`].
pub struct WafEngine {
    pub(super) ruleset: RuleSet,
    pub(super) disabled_rules: RwLock<HashSet<u32>>,
    pub(super) custom_rules: RwLock<Vec<(CustomRule, regex::Regex)>>,
    pub(super) event_buffer: Arc<Mutex<VecDeque<WafEvent>>>,
    pub(super) max_events: usize,
    forward_outbox: OnceLock<Mutex<forward::ForwardOutbox>>,
    event_window: Mutex<window::EventWindow>,
    /// IP address blocklist (e.g. Data-Shield IPv4 Blocklist).
    pub(super) ip_blocklist: IpBlocklist,
    /// Two-phase prefilter (PERF-9): an Aho-Corasick automaton over a
    /// curated list of attack literals that covers every default rule.
    /// Per-field, if the prefilter does not match, the regex pass is
    /// skipped (clean traffic short-circuits to Pass without ever
    /// touching the regex engine). Custom user rules always run -
    /// they're outside the prefilter's coverage contract. See
    /// `prefilter.rs` for the literal list and the
    /// `prefilter_covers_*` regression tests.
    pub(super) prefilter: crate::prefilter::Prefilter,
}

impl WafEngine {
    /// Create a new WAF engine with the default CRS ruleset.
    pub fn new() -> Self {
        Self {
            ruleset: RuleSet::default_crs(),
            disabled_rules: RwLock::new(HashSet::new()),
            custom_rules: RwLock::new(Vec::new()),
            event_buffer: Arc::new(Mutex::new(VecDeque::with_capacity(500))),
            max_events: 500,
            forward_outbox: OnceLock::new(),
            event_window: Mutex::new(window::EventWindow::new()),
            ip_blocklist: IpBlocklist::new(),
            prefilter: crate::prefilter::Prefilter::build(),
        }
    }

    /// Return a reference to the IP blocklist.
    pub fn ip_blocklist(&self) -> &IpBlocklist {
        &self.ip_blocklist
    }

    /// Record an IP blocklist block as a WAF event.
    ///
    /// Synthesizes a pseudo-event with `rule_id = 0` and category
    /// [`crate::RuleCategory::IpBlocklist`] so blocklist hits show up
    /// in the same dashboard timeline as regex matches. `host` and
    /// `path` are accepted for symmetry with [`Self::evaluate`] but
    /// currently only the IP is stored.
    pub fn record_blocklist_event(&self, ip: &str, _host: &str, _path: &str) {
        let now = chrono::Utc::now();
        let event = WafEvent {
            rule_id: 0,
            description: format!("IP {ip} blocked by IP blocklist"),
            category: crate::RuleCategory::IpBlocklist,
            severity: 5,
            matched_field: "client_ip".to_string(),
            matched_value: ip.to_string(),
            timestamp: now.to_rfc3339(),
            client_ip: ip.to_string(),
            route_hostname: String::new(),
            action: String::new(),
        };
        // Stamped now, so the minute is known without parsing it back.
        self.record_at_minutes(vec![event], vec![Some(window::minute_of(now))]);
    }

    /// Record `events`: count each in the per-minute window, hand a copy
    /// to the forwarding outbox when there is one, then append them to
    /// the recent-event ring, dropping its oldest entries past capacity.
    ///
    /// Every event the engine produces goes through here. A process
    /// that receives events another engine produced (the supervisor,
    /// from its workers) records them here too, so its windowed counts
    /// cover them.
    pub fn record_events(&self, events: Vec<WafEvent>) {
        let now = chrono::Utc::now();
        let minutes = events
            .iter()
            .map(|event| window::minute_for(&event.timestamp, now))
            .collect();
        self.record_at_minutes(events, minutes);
    }

    /// [`Self::record_events`] with each event's minute already placed,
    /// so the locks below cover counter and pointer work only: parsing
    /// and cloning happen before each is taken.
    fn record_at_minutes(&self, events: Vec<WafEvent>, minutes: Vec<Option<i64>>) {
        {
            let mut window = self.event_window.lock();
            for (event, minute) in events.iter().zip(minutes) {
                if let Some(minute) = minute {
                    window.count_at(minute, event.category.as_str(), 1);
                }
            }
        }
        if let Some(outbox) = self.forward_outbox.get() {
            let copies = events.clone();
            outbox.lock().push(copies);
        }
        let mut buf = self.event_buffer.lock();
        for event in events {
            if buf.len() >= self.max_events {
                buf.pop_front();
            }
            buf.push_back(event);
        }
    }

    /// Number every event recorded from now on in an outbox that
    /// [`Self::events_after`] drains, for a process whose events must
    /// all reach another one (a worker forwarding to its supervisor).
    /// Idempotent.
    ///
    /// Off by default because each recorded event then costs one more
    /// copy, which a process nobody reads the outbox of should not pay.
    pub fn enable_forwarding(&self) {
        self.forward_outbox.get_or_init(|| {
            Mutex::new(forward::ForwardOutbox::new(
                FORWARD_OUTBOX_CAPACITY,
                LOST_SOURCES_CAPACITY,
            ))
        });
    }

    /// Events recorded after the sequence number `cursor`, for the one
    /// reader that must see every event once, such as a worker
    /// forwarding its events to the supervisor. Start from `0` and pass
    /// back [`EventsAfter::next`]. Empty until
    /// [`Self::enable_forwarding`] has run.
    ///
    /// The events are moved out of the outbox, so a second reader would
    /// find them gone. Events recorded after the cursor but already
    /// dropped by the outbox are reported in [`EventsAfter::lost`], with
    /// their sources in [`EventsAfter::lost_by_source`]; events forgotten
    /// by [`Self::clear_events`] are not, since nobody lost them. The
    /// numbering assumes events enter only through
    /// [`Self::record_events`].
    pub fn events_after(&self, cursor: u64) -> EventsAfter {
        let Some(outbox) = self.forward_outbox.get() else {
            return EventsAfter::default();
        };
        let taken = outbox.lock().take_after(cursor);
        taken.into()
    }

    /// Count `count` events of `category` that happened in the last
    /// moments but were never recorded here one by one: events a worker
    /// had to drop before it could forward them. They join the windowed
    /// counts, not the recent-event ring.
    pub fn record_lost_events(&self, category: &RuleCategory, count: u64) {
        let minute = window::minute_of(chrono::Utc::now());
        self.event_window
            .lock()
            .count_at(minute, category.as_str(), count);
    }

    /// Events recorded over the last `window` (at most
    /// [`LONGEST_EVENT_WINDOW`]), in total and per category, at minute
    /// resolution and unbounded by the recent-event ring.
    pub fn event_counts_within(&self, window: std::time::Duration) -> WindowCounts {
        self.event_window
            .lock()
            .counts_within(window, chrono::Utc::now())
    }

    /// Forget every recorded event: the recent-event ring, the
    /// forwarding outbox and the windowed counts alike.
    pub fn clear_events(&self) {
        self.event_window.lock().clear();
        if let Some(outbox) = self.forward_outbox.get() {
            outbox.lock().clear();
        }
        self.event_buffer.lock().clear();
    }

    /// Return a reference to the event buffer for dashboard consumption.
    pub fn event_buffer(&self) -> Arc<Mutex<VecDeque<WafEvent>>> {
        Arc::clone(&self.event_buffer)
    }

    /// Return the total number of rules in the ruleset.
    pub fn rule_count(&self) -> usize {
        self.ruleset.len()
    }

    /// Return the number of currently enabled rules.
    pub fn enabled_rule_count(&self) -> usize {
        let disabled = self.disabled_rules.read();
        self.ruleset.len() - disabled.len()
    }

    /// List all rules with their enabled/disabled status.
    ///
    /// Includes both general rules and header-scoped rules (v1.5.1
    /// audit H-3) so the dashboard listing reflects the full
    /// ruleset that an operator can disable.
    pub fn list_rules(&self) -> Vec<RuleSummary> {
        let disabled = self.disabled_rules.read();
        let general = self.ruleset.rules().iter().map(|r| RuleSummary {
            id: r.id,
            description: r.description.to_string(),
            category: r.category.clone(),
            severity: r.severity,
            enabled: !disabled.contains(&r.id),
        });
        let scoped = self.ruleset.header_scoped().iter().map(|r| RuleSummary {
            id: r.id,
            description: r.description.to_string(),
            category: r.category.clone(),
            severity: r.severity,
            enabled: !disabled.contains(&r.id),
        });
        general.chain(scoped).collect()
    }

    /// Disable a specific rule by ID. Returns false if rule ID not found.
    pub fn disable_rule(&self, rule_id: u32) -> bool {
        let known = self.ruleset.rules().iter().any(|r| r.id == rule_id)
            || self.ruleset.header_scoped().iter().any(|r| r.id == rule_id);
        if known {
            self.disabled_rules.write().insert(rule_id);
            true
        } else {
            false
        }
    }

    /// Enable a previously disabled rule by ID. Returns false if rule ID not found.
    pub fn enable_rule(&self, rule_id: u32) -> bool {
        let known = self.ruleset.rules().iter().any(|r| r.id == rule_id)
            || self.ruleset.header_scoped().iter().any(|r| r.id == rule_id);
        if known {
            self.disabled_rules.write().remove(&rule_id);
            true
        } else {
            false
        }
    }

    /// Return the IDs of currently disabled rules.
    pub fn disabled_rule_ids(&self) -> Vec<u32> {
        self.disabled_rules.read().iter().copied().collect()
    }

    /// Bulk-set which rules are disabled.
    ///
    /// Replaces the entire disabled set with `rule_ids`. IDs that do
    /// not match any loaded rule are silently ignored so stale config
    /// from disk does not poison the runtime state.
    pub fn set_disabled_rules(&self, rule_ids: &[u32]) {
        let mut disabled = self.disabled_rules.write();
        disabled.clear();
        for &id in rule_ids {
            if self.ruleset.rules().iter().any(|r| r.id == id) {
                disabled.insert(id);
            }
        }
    }

    /// Return recent WAF events from the ring buffer.
    ///
    /// Returns at most `limit` events, newest first.
    pub fn recent_events(&self, limit: usize) -> Vec<WafEvent> {
        let buf = self.event_buffer.lock();
        buf.iter().rev().take(limit).cloned().collect()
    }

    /// Return the total number of events in the ring buffer.
    pub fn event_count(&self) -> usize {
        self.event_buffer.lock().len()
    }
}

impl Default for WafEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
