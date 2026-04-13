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

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::{Mutex, RwLock};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::ip_blocklist::IpBlocklist;
use crate::rules::{RuleCategory, RuleSet};

/// WAF evaluation verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WafVerdict {
    /// Request is clean - no rules matched.
    Pass,
    /// One or more rules matched (detection mode - request proceeds).
    Detected(Vec<WafEvent>),
    /// One or more rules matched (blocking mode - request should be rejected).
    Blocked(Vec<WafEvent>),
}

/// A single WAF event recording a rule match.
///
/// One event is produced per rule that fires on a given field
/// (path, query, header, or body). Events are stored in the engine's
/// bounded ring buffer and surfaced to the dashboard / API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WafEvent {
    pub rule_id: u32,
    pub description: String,
    pub category: RuleCategory,
    pub severity: u8,
    pub matched_field: String,
    pub matched_value: String,
    pub timestamp: String,
    /// Client IP that triggered the event (set by the proxy layer).
    #[serde(default)]
    pub client_ip: String,
    /// Route hostname that was matched (set by the proxy layer).
    #[serde(default)]
    pub route_hostname: String,
    /// Whether the request was blocked or just detected.
    #[serde(default)]
    pub action: String,
}

/// WAF operating mode for a specific evaluation.
///
/// `Detection` records matches but lets the request through (used for
/// tuning new rules without breaking traffic). `Blocking` returns 403
/// to the client when any rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafMode {
    /// Log matches but allow the request to proceed.
    Detection,
    /// Reject the request with a 403 on any rule match.
    Blocking,
}

/// Summary of a WAF rule for API exposure.
///
/// Mirrors a [`crate::rules::WafRule`] but drops the compiled regex
/// so it can be safely serialized over the admin API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSummary {
    pub id: u32,
    pub description: String,
    pub category: RuleCategory,
    pub severity: u8,
    pub enabled: bool,
}

/// A user-defined custom WAF rule.
///
/// Custom rules are evaluated alongside the default ruleset on every
/// scanned field. Their regex is compiled with a size cap (see
/// [`WafEngine::MAX_CUSTOM_REGEX_SIZE`]) to bound admin attack surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    pub id: u32,
    pub description: String,
    pub category: RuleCategory,
    pub pattern: String,
    pub severity: u8,
    pub enabled: bool,
}

/// WAF engine with precompiled rules, IP blocklist, and event ring buffer.
///
/// Cheap to share across worker threads behind an `Arc`: all mutable
/// state (disabled rule set, custom rules, event buffer, blocklist) is
/// behind interior locks. The recent-event buffer is bounded to 500
/// entries; older events are dropped FIFO.
pub struct WafEngine {
    ruleset: RuleSet,
    disabled_rules: RwLock<HashSet<u32>>,
    custom_rules: RwLock<Vec<(CustomRule, regex::Regex)>>,
    event_buffer: Arc<Mutex<VecDeque<WafEvent>>>,
    max_events: usize,
    /// IP address blocklist (e.g. Data-Shield IPv4 Blocklist).
    ip_blocklist: IpBlocklist,
    /// Two-phase prefilter (PERF-9): an Aho-Corasick automaton over a
    /// curated list of attack literals that covers every default rule.
    /// Per-field, if the prefilter does not match, the regex pass is
    /// skipped (clean traffic short-circuits to Pass without ever
    /// touching the regex engine). Custom user rules always run -
    /// they're outside the prefilter's coverage contract. See
    /// `prefilter.rs` for the literal list and the
    /// `prefilter_covers_*` regression tests.
    prefilter: crate::prefilter::Prefilter,
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
    /// [`RuleCategory::IpBlocklist`] so blocklist hits show up in the
    /// same dashboard timeline as regex matches. `host` and `path` are
    /// accepted for symmetry with [`Self::evaluate`] but currently
    /// only the IP is stored.
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
    pub fn list_rules(&self) -> Vec<RuleSummary> {
        let disabled = self.disabled_rules.read();
        self.ruleset
            .rules()
            .iter()
            .map(|r| RuleSummary {
                id: r.id,
                description: r.description.to_string(),
                category: r.category.clone(),
                severity: r.severity,
                enabled: !disabled.contains(&r.id),
            })
            .collect()
    }

    /// Disable a specific rule by ID. Returns false if rule ID not found.
    pub fn disable_rule(&self, rule_id: u32) -> bool {
        if self.ruleset.rules().iter().any(|r| r.id == rule_id) {
            self.disabled_rules.write().insert(rule_id);
            true
        } else {
            false
        }
    }

    /// Enable a previously disabled rule by ID. Returns false if rule ID not found.
    pub fn enable_rule(&self, rule_id: u32) -> bool {
        if self.ruleset.rules().iter().any(|r| r.id == rule_id) {
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

    /// Maximum raw pattern length accepted for a custom WAF rule.
    /// Caps the admin-only attack surface on `RegexBuilder::build`:
    /// the `regex` crate has linear-time matching but pathological
    /// alternations or nested repetitions can still burn seconds and
    /// megabytes at *compile* time. 4 KiB is enough for any realistic
    /// operator-written pattern and short-circuits adversarial input.
    pub const MAX_CUSTOM_PATTERN_LEN: usize = 4 * 1024;

    /// Upper bound on the compiled NFA / DFA size (in bytes) for a
    /// custom rule. Matches what `RegexBuilder::size_limit` gates.
    pub const MAX_CUSTOM_REGEX_SIZE: usize = 512 * 1024;

    /// Add a custom user-defined WAF rule.
    ///
    /// Returns `Err` with a human-readable message if the pattern
    /// exceeds [`Self::MAX_CUSTOM_PATTERN_LEN`], if the compiled regex
    /// would exceed [`Self::MAX_CUSTOM_REGEX_SIZE`], or if the pattern
    /// is not a valid regex. On success the rule starts enabled.
    pub fn add_custom_rule(
        &self,
        id: u32,
        description: String,
        category: RuleCategory,
        pattern: &str,
        severity: u8,
    ) -> Result<(), String> {
        if pattern.len() > Self::MAX_CUSTOM_PATTERN_LEN {
            return Err(format!(
                "pattern exceeds {} bytes",
                Self::MAX_CUSTOM_PATTERN_LEN
            ));
        }
        let regex = regex::RegexBuilder::new(pattern)
            .size_limit(Self::MAX_CUSTOM_REGEX_SIZE)
            .build()
            .map_err(|e| format!("invalid regex: {e}"))?;
        let rule = CustomRule {
            id,
            description,
            category,
            pattern: pattern.to_string(),
            severity,
            enabled: true,
        };
        self.custom_rules.write().push((rule, regex));
        Ok(())
    }

    /// Remove a custom rule by ID. Returns `true` if a rule was removed.
    pub fn remove_custom_rule(&self, id: u32) -> bool {
        let mut rules = self.custom_rules.write();
        let before = rules.len();
        rules.retain(|(r, _)| r.id != id);
        rules.len() < before
    }

    /// Remove all custom rules.
    pub fn clear_custom_rules(&self) {
        self.custom_rules.write().clear();
    }

    /// List all custom rules.
    pub fn list_custom_rules(&self) -> Vec<CustomRule> {
        self.custom_rules
            .read()
            .iter()
            .map(|(r, _)| r.clone())
            .collect()
    }

    /// Evaluate a request against the WAF ruleset.
    ///
    /// Checks the URI path, query string, and the supplied header
    /// values. Each field is URL-decoded (recursively, up to 3 passes)
    /// before being scanned to defeat percent-encoded bypass attempts.
    /// Matching events are appended to the engine's ring buffer and a
    /// `latency_us` field is logged via tracing on every call - it
    /// measures the regex scan only, not request wall-clock.
    pub fn evaluate(
        &self,
        mode: WafMode,
        path: &str,
        query: Option<&str>,
        headers: &[(&str, &str)],
        host: &str,
        client_ip: &str,
    ) -> WafVerdict {
        let start = Instant::now();
        let mut events = Vec::new();
        let now = chrono::Utc::now().to_rfc3339();

        // PERF-9: two-phase eval. Per-field, run the cheap
        // Aho-Corasick prefilter first; only fall through to the
        // regex pass when the prefilter hits. Custom user rules are
        // outside the prefilter contract so we still scan them
        // regardless. Full-scan semantics (all events collected)
        // are preserved for observability.
        let has_custom_rules = !self.custom_rules.read().is_empty();

        // Check path (URL-decode to catch encoded traversal attacks)
        let decoded_path = Self::url_decode(path);
        if has_custom_rules || self.prefilter.matches(&decoded_path) {
            self.scan_field("path", &decoded_path, &now, &mut events);
        }

        // Check query string
        if let Some(q) = query {
            // URL-decode the query for better detection
            let decoded = Self::url_decode(q);
            if has_custom_rules || self.prefilter.matches(&decoded) {
                self.scan_field("query", &decoded, &now, &mut events);
            }
        }

        // Check relevant headers
        for (name, value) in headers {
            let decoded = Self::url_decode(value);
            if has_custom_rules || self.prefilter.matches(&decoded) {
                self.scan_field(&format!("header:{name}"), &decoded, &now, &mut events);
            }
        }

        let elapsed = start.elapsed();

        if !events.is_empty() {
            // Stamp each event with the client IP
            for ev in &mut events {
                ev.client_ip = client_ip.to_string();
            }
            // Store events in the ring buffer
            let mut buf = self.event_buffer.lock();
            for event in &events {
                if buf.len() >= self.max_events {
                    buf.pop_front();
                }
                buf.push_back(event.clone());
            }

            let rule_ids: Vec<u32> = events.iter().map(|e| e.rule_id).collect();
            let categories: Vec<&str> = events.iter().map(|e| e.category.as_str()).collect();

            match mode {
                WafMode::Detection => {
                    warn!(
                        host = host,
                        path = path,
                        rules = ?rule_ids,
                        categories = ?categories,
                        mode = "detection",
                        latency_us = elapsed.as_micros() as u64,
                        "WAF rules matched - request allowed (detection mode)"
                    );
                    WafVerdict::Detected(events)
                }
                WafMode::Blocking => {
                    warn!(
                        host = host,
                        path = path,
                        rules = ?rule_ids,
                        categories = ?categories,
                        mode = "blocking",
                        latency_us = elapsed.as_micros() as u64,
                        "WAF rules matched - request blocked"
                    );
                    WafVerdict::Blocked(events)
                }
            }
        } else {
            info!(
                host = host,
                latency_us = elapsed.as_micros() as u64,
                "WAF evaluation passed"
            );
            WafVerdict::Pass
        }
    }

    /// Evaluate a request body against the WAF ruleset.
    ///
    /// Scans the body content using the same rules as
    /// [`Self::evaluate`], but skips rules whose category does not
    /// apply to bodies (path traversal, protocol violations) to avoid
    /// false positives on CMS articles or JSON payloads. Non-UTF-8
    /// bodies (binary uploads) short-circuit to [`WafVerdict::Pass`].
    /// Intended to be called from `request_body_filter` once the full
    /// body is buffered.
    pub fn evaluate_body(
        &self,
        mode: WafMode,
        body: &[u8],
        host: &str,
        client_ip: &str,
    ) -> WafVerdict {
        // Only scan bodies that look like text (UTF-8 decodable).
        // Binary uploads (images, protobuf, etc.) are skipped to avoid
        // false positives and wasted CPU.
        let text = match std::str::from_utf8(body) {
            Ok(t) => t,
            Err(_) => return WafVerdict::Pass,
        };

        let start = Instant::now();
        let mut events = Vec::new();
        let now = chrono::Utc::now().to_rfc3339();

        // URL-decode the body to catch encoded payloads. PERF-9:
        // skip the regex pass entirely when neither the prefilter
        // nor any custom user rule applies.
        let decoded = Self::url_decode(text);
        let has_custom_rules = !self.custom_rules.read().is_empty();
        if has_custom_rules || self.prefilter.matches(&decoded) {
            self.scan_field("body", &decoded, &now, &mut events);
        }

        let elapsed = start.elapsed();

        if events.is_empty() {
            info!(
                host = host,
                latency_us = elapsed.as_micros() as u64,
                "WAF body evaluation passed"
            );
            return WafVerdict::Pass;
        }

        // Stamp each event with the client IP
        for ev in &mut events {
            ev.client_ip = client_ip.to_string();
        }

        // Store events in the ring buffer
        let mut buf = self.event_buffer.lock();
        for event in &events {
            if buf.len() >= self.max_events {
                buf.pop_front();
            }
            buf.push_back(event.clone());
        }
        drop(buf);

        let rule_ids: Vec<u32> = events.iter().map(|e| e.rule_id).collect();
        let categories: Vec<&str> = events.iter().map(|e| e.category.as_str()).collect();

        match mode {
            WafMode::Detection => {
                warn!(
                    host = host,
                    rules = ?rule_ids,
                    categories = ?categories,
                    mode = "detection",
                    latency_us = elapsed.as_micros() as u64,
                    "WAF body rules matched - request allowed (detection mode)"
                );
                WafVerdict::Detected(events)
            }
            WafMode::Blocking => {
                warn!(
                    host = host,
                    rules = ?rule_ids,
                    categories = ?categories,
                    mode = "blocking",
                    latency_us = elapsed.as_micros() as u64,
                    "WAF body rules matched - request blocked"
                );
                WafVerdict::Blocked(events)
            }
        }
    }

    /// Scan a single field against all enabled rules.
    /// When `field` is "body", rules that don't apply to body content
    /// (e.g. path traversal, protocol violations) are skipped.
    fn scan_field(&self, field: &str, value: &str, timestamp: &str, events: &mut Vec<WafEvent>) {
        let is_body = field == "body";
        let disabled = self.disabled_rules.read();
        for rule in self.ruleset.rules() {
            if disabled.contains(&rule.id) {
                continue;
            }
            if is_body && !rule.applies_to_body() {
                continue;
            }
            if let Some(m) = rule.pattern.find(value) {
                let matched_value = m.as_str().to_string();

                events.push(WafEvent {
                    rule_id: rule.id,
                    description: rule.description.to_string(),
                    category: rule.category.clone(),
                    severity: rule.severity,
                    matched_field: field.to_string(),
                    matched_value,
                    timestamp: timestamp.to_string(),
                    client_ip: String::new(),
                    route_hostname: String::new(),
                    action: String::new(),
                });
            }
        }

        // Also check custom rules
        let custom = self.custom_rules.read();
        for (rule, regex) in custom.iter() {
            if !rule.enabled {
                continue;
            }
            if let Some(m) = regex.find(value) {
                let matched_value = m.as_str().to_string();
                events.push(WafEvent {
                    rule_id: rule.id,
                    description: rule.description.clone(),
                    category: rule.category.clone(),
                    severity: rule.severity,
                    matched_field: field.to_string(),
                    matched_value,
                    timestamp: timestamp.to_string(),
                    client_ip: String::new(),
                    route_hostname: String::new(),
                    action: String::new(),
                });
            }
        }
    }

    /// Recursive URL decoding for encoded attack payloads.
    ///
    /// Decodes until stable or max 3 iterations to prevent double-encoding bypass.
    fn url_decode(input: &str) -> String {
        // Fast path: no percent-encoding or plus signs -> skip decode entirely
        if !input.contains('%') && !input.contains('+') {
            return input.to_string();
        }
        let mut current = input.to_string();
        for _ in 0..3 {
            let decoded = Self::url_decode_once(&current);
            if decoded == current {
                break;
            }
            current = decoded;
        }
        current
    }

    /// Single-pass URL decoding helper.
    fn url_decode_once(input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        let mut chars = input.chars();

        while let Some(c) = chars.next() {
            if c == '%' {
                let hex: String = chars.by_ref().take(2).collect();
                if hex.len() == 2 {
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        result.push(byte as char);
                        continue;
                    }
                }
                result.push('%');
                result.push_str(&hex);
            } else if c == '+' {
                result.push(' ');
            } else {
                result.push(c);
            }
        }
        result
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
mod tests {
    use super::*;

    fn engine() -> WafEngine {
        WafEngine::new()
    }

    // --- Pass verdicts ---

    #[test]
    fn test_clean_request_passes() {
        let e = engine();
        let verdict = e.evaluate(
            WafMode::Blocking,
            "/api/v1/users",
            Some("page=1&limit=20"),
            &[("user-agent", "Mozilla/5.0")],
            "example.com",
            "10.0.0.1",
        );
        assert_eq!(verdict, WafVerdict::Pass);
    }

    #[test]
    fn test_clean_request_with_normal_headers() {
        let e = engine();
        let verdict = e.evaluate(
            WafMode::Detection,
            "/index.html",
            None,
            &[("accept", "text/html"), ("cookie", "session=abc123")],
            "example.com",
            "10.0.0.1",
        );
        assert_eq!(verdict, WafVerdict::Pass);
    }

    // --- SQL Injection detection ---

    #[test]
    fn test_sqli_in_query_detected() {
        let e = engine();
        let verdict = e.evaluate(
            WafMode::Detection,
            "/search",
            Some("q=1%20UNION%20SELECT%20*%20FROM%20users"),
            &[],
            "example.com",
            "10.0.0.1",
        );
        match verdict {
            WafVerdict::Detected(events) => {
                assert!(!events.is_empty());
                assert!(events
                    .iter()
                    .any(|e| e.category == RuleCategory::SqlInjection));
            }
            other => panic!("expected Detected, got {other:?}"),
        }
    }

    #[test]
    fn test_sqli_in_query_blocked() {
        let e = engine();
        let verdict = e.evaluate(
            WafMode::Blocking,
            "/search",
            Some("q=1'+OR+1=1--"),
            &[],
            "example.com",
            "10.0.0.1",
        );
        match verdict {
            WafVerdict::Blocked(events) => {
                assert!(!events.is_empty());
                assert!(events
                    .iter()
                    .any(|e| e.category == RuleCategory::SqlInjection));
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    #[test]
    fn test_sqli_in_header() {
        let e = engine();
        let verdict = e.evaluate(
            WafMode::Blocking,
            "/api",
            None,
            &[("x-custom", "'; DROP TABLE users--")],
            "example.com",
            "10.0.0.1",
        );
        match verdict {
            WafVerdict::Blocked(events) => {
                assert!(events
                    .iter()
                    .any(|ev| ev.matched_field.starts_with("header:")));
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    // --- XSS detection ---

    #[test]
    fn test_xss_script_tag_blocked() {
        let e = engine();
        let verdict = e.evaluate(
            WafMode::Blocking,
            "/comment",
            Some("body=%3Cscript%3Ealert(1)%3C/script%3E"),
            &[],
            "example.com",
            "10.0.0.1",
        );
        match verdict {
            WafVerdict::Blocked(events) => {
                assert!(events.iter().any(|e| e.category == RuleCategory::Xss));
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    #[test]
    fn test_xss_event_handler_detected() {
        let e = engine();
        let verdict = e.evaluate(
            WafMode::Detection,
            "/page",
            Some("input=<img+onerror=alert(1)+src=x>"),
            &[],
            "example.com",
            "10.0.0.1",
        );
        match verdict {
            WafVerdict::Detected(events) => {
                assert!(events.iter().any(|e| e.category == RuleCategory::Xss));
            }
            other => panic!("expected Detected, got {other:?}"),
        }
    }

    // --- Path Traversal detection ---

    #[test]
    fn test_path_traversal_in_path() {
        let e = engine();
        let verdict = e.evaluate(
            WafMode::Blocking,
            "/files/../../../etc/passwd",
            None,
            &[],
            "example.com",
            "10.0.0.1",
        );
        match verdict {
            WafVerdict::Blocked(events) => {
                assert!(events
                    .iter()
                    .any(|e| e.category == RuleCategory::PathTraversal));
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    #[test]
    fn test_path_traversal_encoded() {
        let e = engine();
        let verdict = e.evaluate(
            WafMode::Blocking,
            "/files",
            Some("path=%2e%2e/%2e%2e/etc/passwd"),
            &[],
            "example.com",
            "10.0.0.1",
        );
        match verdict {
            WafVerdict::Blocked(events) => {
                assert!(events
                    .iter()
                    .any(|e| e.category == RuleCategory::PathTraversal));
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    // --- Command Injection detection ---

    #[test]
    fn test_cmdi_blocked() {
        let e = engine();
        let verdict = e.evaluate(
            WafMode::Blocking,
            "/api",
            Some("cmd=;+cat+/etc/passwd"),
            &[],
            "example.com",
            "10.0.0.1",
        );
        match verdict {
            WafVerdict::Blocked(events) => {
                assert!(events
                    .iter()
                    .any(|e| e.category == RuleCategory::CommandInjection));
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    // --- Event buffer ---

    #[test]
    fn test_events_stored_in_buffer() {
        let e = engine();
        assert_eq!(e.event_count(), 0);

        e.evaluate(
            WafMode::Detection,
            "/search",
            Some("q=1'+OR+1=1--"),
            &[],
            "example.com",
            "10.0.0.1",
        );

        assert!(e.event_count() > 0);
        let recent = e.recent_events(10);
        assert!(!recent.is_empty());
    }

    #[test]
    fn test_clean_request_no_events() {
        let e = engine();
        e.evaluate(
            WafMode::Blocking,
            "/healthy/path",
            Some("key=value"),
            &[],
            "example.com",
            "10.0.0.1",
        );
        assert_eq!(e.event_count(), 0);
    }

    // --- URL decoding ---

    #[test]
    fn test_url_decode_basic() {
        assert_eq!(WafEngine::url_decode("%3Cscript%3E"), "<script>");
        assert_eq!(WafEngine::url_decode("hello+world"), "hello world");
        assert_eq!(WafEngine::url_decode("no_encoding"), "no_encoding");
    }

    #[test]
    fn test_url_decode_double_encoded() {
        // %252e = %2e after first decode = . after second (recursive decoding)
        let decoded = WafEngine::url_decode("%252e%252e");
        assert_eq!(decoded, "..");
    }

    #[test]
    fn test_url_decode_triple_encoded() {
        // %25252e -> %252e -> %2e -> . (three iterations needed)
        let decoded = WafEngine::url_decode("%25252e");
        assert_eq!(decoded, ".");
    }

    #[test]
    fn test_url_decode_stable_input() {
        // Already decoded input should remain unchanged
        assert_eq!(WafEngine::url_decode("hello world"), "hello world");
    }

    // --- Mode behavior ---

    #[test]
    fn test_detection_mode_returns_detected() {
        let e = engine();
        let verdict = e.evaluate(
            WafMode::Detection,
            "/",
            Some("q=<script>alert(1)</script>"),
            &[],
            "example.com",
            "10.0.0.1",
        );
        assert!(matches!(verdict, WafVerdict::Detected(_)));
    }

    #[test]
    fn test_blocking_mode_returns_blocked() {
        let e = engine();
        let verdict = e.evaluate(
            WafMode::Blocking,
            "/",
            Some("q=<script>alert(1)</script>"),
            &[],
            "example.com",
            "10.0.0.1",
        );
        assert!(matches!(verdict, WafVerdict::Blocked(_)));
    }

    // --- Performance ---

    #[test]
    fn test_evaluation_is_fast() {
        let e = engine();
        let start = Instant::now();
        for _ in 0..1000 {
            e.evaluate(
                WafMode::Blocking,
                "/api/v1/users/123/profile",
                Some("page=1&limit=20&sort=name&order=asc"),
                &[
                    (
                        "user-agent",
                        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                    ),
                    ("accept", "application/json"),
                    ("cookie", "session=abcdef123456"),
                ],
                "example.com",
                "10.0.0.1",
            );
        }
        let elapsed = start.elapsed();
        let per_request_us = elapsed.as_micros() / 1000;
        // Must be under 1000us per request (recursive URL decoding adds overhead,
        // CI runners are slower than production hardware)
        assert!(
            per_request_us < 1000,
            "WAF evaluation too slow: {per_request_us}us per request"
        );
    }

    // --- Rule configuration ---

    #[test]
    fn test_list_rules() {
        let e = engine();
        let rules = e.list_rules();
        assert!(rules.len() >= 15);
        assert!(rules.iter().all(|r| r.enabled));
    }

    #[test]
    fn test_disable_rule() {
        let e = engine();
        assert!(e.disable_rule(942100));
        let rules = e.list_rules();
        let sqli_union = rules
            .iter()
            .find(|r| r.id == 942100)
            .expect("test setup: rule 942100 must exist in CRS ruleset");
        assert!(!sqli_union.enabled);
        assert_eq!(e.enabled_rule_count(), e.rule_count() - 1);
    }

    #[test]
    fn test_disable_unknown_rule_returns_false() {
        let e = engine();
        assert!(!e.disable_rule(999999));
    }

    #[test]
    fn test_enable_rule() {
        let e = engine();
        e.disable_rule(942100);
        assert!(e.enable_rule(942100));
        let rules = e.list_rules();
        let sqli_union = rules
            .iter()
            .find(|r| r.id == 942100)
            .expect("test setup: rule 942100 must exist in CRS ruleset");
        assert!(sqli_union.enabled);
    }

    #[test]
    fn test_disabled_rule_skipped_during_evaluation() {
        let e = engine();
        // Disable the UNION SELECT rule (942100)
        e.disable_rule(942100);

        let verdict = e.evaluate(
            WafMode::Blocking,
            "/search",
            Some("q=1 UNION SELECT * FROM users"),
            &[],
            "example.com",
            "10.0.0.1",
        );

        // Should still be blocked by the stacked queries rule (942150)
        // or pass if only 942100 matches this payload
        match &verdict {
            WafVerdict::Pass => {} // Rule was disabled, no other match
            WafVerdict::Blocked(events) => {
                // If it matched, it should NOT be via rule 942100
                assert!(!events.iter().any(|e| e.rule_id == 942100));
            }
            WafVerdict::Detected(_) => panic!("unexpected detection mode"),
        }
    }

    #[test]
    fn test_set_disabled_rules_bulk() {
        let e = engine();
        e.set_disabled_rules(&[942100, 941100, 930100]);
        let rules = e.list_rules();
        assert!(
            !rules
                .iter()
                .find(|r| r.id == 942100)
                .expect("test setup: rule 942100 must exist in CRS ruleset")
                .enabled
        );
        assert!(
            !rules
                .iter()
                .find(|r| r.id == 941100)
                .expect("test setup: rule 941100 must exist in CRS ruleset")
                .enabled
        );
        assert!(
            !rules
                .iter()
                .find(|r| r.id == 930100)
                .expect("test setup: rule 930100 must exist in CRS ruleset")
                .enabled
        );
        assert_eq!(e.enabled_rule_count(), e.rule_count() - 3);

        // Re-enable all
        e.set_disabled_rules(&[]);
        assert_eq!(e.enabled_rule_count(), e.rule_count());
    }

    // --- Client IP propagation ---

    #[test]
    fn test_client_ip_set_on_events() {
        let e = engine();
        let verdict = e.evaluate(
            WafMode::Blocking,
            "/search",
            Some("q=1'+OR+1=1--"),
            &[],
            "example.com",
            "10.20.30.40",
        );
        match verdict {
            WafVerdict::Blocked(events) => {
                assert!(!events.is_empty());
                for ev in &events {
                    assert_eq!(ev.client_ip, "10.20.30.40");
                }
            }
            other => panic!("expected Blocked, got {other:?}"),
        }

        // Also check the events in the ring buffer have client_ip set
        let recent = e.recent_events(10);
        for ev in &recent {
            assert_eq!(ev.client_ip, "10.20.30.40");
        }
    }

    // --- Body scanning ---

    #[test]
    fn test_body_sqli_blocked() {
        let e = engine();
        let body = b"username=admin&password=1' OR 1=1--";
        let verdict = e.evaluate_body(WafMode::Blocking, body, "example.com", "10.0.0.1");
        match verdict {
            WafVerdict::Blocked(events) => {
                assert!(!events.is_empty());
                assert!(events
                    .iter()
                    .any(|ev| ev.category == RuleCategory::SqlInjection));
                assert!(events.iter().all(|ev| ev.matched_field == "body"));
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    #[test]
    fn test_body_xss_detected() {
        let e = engine();
        let body = b"comment=<script>alert(document.cookie)</script>";
        let verdict = e.evaluate_body(WafMode::Detection, body, "example.com", "10.0.0.1");
        match verdict {
            WafVerdict::Detected(events) => {
                assert!(!events.is_empty());
                assert!(events.iter().any(|ev| ev.category == RuleCategory::Xss));
            }
            other => panic!("expected Detected, got {other:?}"),
        }
    }

    #[test]
    fn test_body_cmdi_blocked() {
        let e = engine();
        let body = b"input=; cat /etc/passwd";
        let verdict = e.evaluate_body(WafMode::Blocking, body, "example.com", "10.0.0.1");
        match verdict {
            WafVerdict::Blocked(events) => {
                assert!(!events.is_empty());
                assert!(events
                    .iter()
                    .any(|ev| ev.category == RuleCategory::CommandInjection));
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    #[test]
    fn test_body_clean_passes() {
        let e = engine();
        let body = b"username=admin&password=securePassword123";
        let verdict = e.evaluate_body(WafMode::Blocking, body, "example.com", "10.0.0.1");
        assert_eq!(verdict, WafVerdict::Pass);
    }

    #[test]
    fn test_body_path_traversal_not_scanned() {
        // Path traversal patterns in body content (e.g. CMS articles) should
        // NOT trigger WAF rules - these rules only apply to path/query/headers.
        let e = engine();
        let body = br#"{"content": "Navigate to ..\ or ../ to go back"}"#;
        let verdict = e.evaluate_body(WafMode::Blocking, body, "example.com", "10.0.0.1");
        assert_eq!(verdict, WafVerdict::Pass);
    }

    #[test]
    fn test_body_sqli_still_caught() {
        // SQLi in body should still be caught (applies_to_body = true)
        let e = engine();
        let body = b"search=1 UNION SELECT * FROM users";
        let verdict = e.evaluate_body(WafMode::Blocking, body, "example.com", "10.0.0.1");
        assert!(matches!(verdict, WafVerdict::Blocked(_)));
    }

    #[test]
    fn test_body_binary_skipped() {
        let e = engine();
        // Invalid UTF-8 body (binary data) should be skipped
        let body: &[u8] = &[0xff, 0xfe, 0x00, 0x01, 0x80, 0x90];
        let verdict = e.evaluate_body(WafMode::Blocking, body, "example.com", "10.0.0.1");
        assert_eq!(verdict, WafVerdict::Pass);
    }

    #[test]
    fn test_body_events_stored_in_buffer() {
        let e = engine();
        assert_eq!(e.event_count(), 0);
        e.evaluate_body(
            WafMode::Blocking,
            b"data=1' UNION SELECT * FROM users",
            "example.com",
            "10.0.0.1",
        );
        assert!(e.event_count() > 0);
    }

    #[test]
    fn test_body_client_ip_set() {
        let e = engine();
        let verdict = e.evaluate_body(
            WafMode::Blocking,
            b"q=<script>alert(1)</script>",
            "example.com",
            "192.168.1.100",
        );
        match verdict {
            WafVerdict::Blocked(events) => {
                for ev in &events {
                    assert_eq!(ev.client_ip, "192.168.1.100");
                }
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    #[test]
    fn test_waf_event_serde_default_client_ip() {
        // Verify backward compatibility: deserializing old JSON without client_ip
        let json = r#"{
            "rule_id": 942100,
            "description": "test",
            "category": "sql_injection",
            "severity": 5,
            "matched_field": "query",
            "matched_value": "test",
            "timestamp": "2026-01-01T00:00:00Z"
        }"#;
        let event: WafEvent = serde_json::from_str(json).expect("deserialization failed");
        assert_eq!(event.client_ip, "");
    }
}
