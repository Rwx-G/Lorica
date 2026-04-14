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

//! Request and body evaluation - the WAF's hot path.
//!
//! Keeps [`WafEngine::evaluate`] and [`WafEngine::evaluate_body`]
//! together with the private [`WafEngine::scan_field`] helper so the
//! two-phase prefilter + regex scan logic (PERF-9) lives in one place.

use std::time::Instant;

use tracing::{info, warn};

use super::{WafEngine, WafEvent, WafMode, WafVerdict};

impl WafEngine {
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
}
