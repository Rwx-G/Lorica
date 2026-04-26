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

mod custom_rules;
mod eval;
mod types;
mod url_decode;

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};

use crate::ip_blocklist::IpBlocklist;
use crate::rules::RuleSet;

pub use types::{CustomRule, RuleSummary, WafEvent, WafMode, WafVerdict};

/// WAF engine with precompiled rules, IP blocklist, and event ring buffer.
///
/// Cheap to share across worker threads behind an `Arc`: all mutable
/// state (disabled rule set, custom rules, event buffer, blocklist) is
/// behind interior locks. The recent-event buffer is bounded to 500
/// entries; older events are dropped FIFO.
pub struct WafEngine {
    pub(super) ruleset: RuleSet,
    pub(super) disabled_rules: RwLock<HashSet<u32>>,
    pub(super) custom_rules: RwLock<Vec<(CustomRule, regex::Regex)>>,
    pub(super) event_buffer: Arc<Mutex<VecDeque<WafEvent>>>,
    pub(super) max_events: usize,
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
        let event = WafEvent {
            rule_id: 0,
            description: format!("IP {ip} blocked by IP blocklist"),
            category: crate::RuleCategory::IpBlocklist,
            severity: 5,
            matched_field: "client_ip".to_string(),
            matched_value: ip.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            client_ip: ip.to_string(),
            route_hostname: String::new(),
            action: String::new(),
        };
        let mut buf = self.event_buffer.lock();
        if buf.len() >= self.max_events {
            buf.pop_front();
        }
        buf.push_back(event);
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
            || self
                .ruleset
                .header_scoped()
                .iter()
                .any(|r| r.id == rule_id);
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
            || self
                .ruleset
                .header_scoped()
                .iter()
                .any(|r| r.id == rule_id);
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
