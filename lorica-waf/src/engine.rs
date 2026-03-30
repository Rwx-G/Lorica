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

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WafEvent {
    pub rule_id: u32,
    pub description: String,
    pub category: RuleCategory,
    pub severity: u8,
    pub matched_field: String,
    pub matched_value: String,
    pub timestamp: String,
}

/// WAF operating mode for a specific evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafMode {
    Detection,
    Blocking,
}

/// WAF engine with precompiled rules and an event ring buffer.
pub struct WafEngine {
    ruleset: RuleSet,
    event_buffer: Arc<Mutex<VecDeque<WafEvent>>>,
    max_events: usize,
}

impl WafEngine {
    /// Create a new WAF engine with the default CRS ruleset.
    pub fn new() -> Self {
        Self {
            ruleset: RuleSet::default_crs(),
            event_buffer: Arc::new(Mutex::new(VecDeque::with_capacity(500))),
            max_events: 500,
        }
    }

    /// Return a reference to the event buffer for dashboard consumption.
    pub fn event_buffer(&self) -> Arc<Mutex<VecDeque<WafEvent>>> {
        Arc::clone(&self.event_buffer)
    }

    /// Return the number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.ruleset.len()
    }

    /// Evaluate a request against the WAF ruleset.
    ///
    /// Checks the URI path, query string, and specified header values.
    /// Returns the verdict along with timing information logged via tracing.
    pub fn evaluate(
        &self,
        mode: WafMode,
        path: &str,
        query: Option<&str>,
        headers: &[(&str, &str)],
        host: &str,
    ) -> WafVerdict {
        let start = Instant::now();
        let mut events = Vec::new();
        let now = chrono::Utc::now().to_rfc3339();

        // Check path
        self.scan_field("path", path, &now, &mut events);

        // Check query string
        if let Some(q) = query {
            // URL-decode the query for better detection
            let decoded = Self::url_decode(q);
            self.scan_field("query", &decoded, &now, &mut events);
        }

        // Check relevant headers
        for (name, value) in headers {
            let decoded = Self::url_decode(value);
            self.scan_field(&format!("header:{name}"), &decoded, &now, &mut events);
        }

        let elapsed = start.elapsed();

        if !events.is_empty() {
            // Store events in the ring buffer
            let mut buf = self.event_buffer.lock().unwrap();
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

    /// Scan a single field against all rules.
    fn scan_field(&self, field: &str, value: &str, timestamp: &str, events: &mut Vec<WafEvent>) {
        for rule in self.ruleset.rules() {
            if rule.pattern.is_match(value) {
                // Extract the matched substring (first match only)
                let matched_value = rule
                    .pattern
                    .find(value)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();

                events.push(WafEvent {
                    rule_id: rule.id,
                    description: rule.description.to_string(),
                    category: rule.category.clone(),
                    severity: rule.severity,
                    matched_field: field.to_string(),
                    matched_value,
                    timestamp: timestamp.to_string(),
                });
            }
        }
    }

    /// Basic URL decoding for common encoded attack payloads.
    fn url_decode(input: &str) -> String {
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
    pub fn recent_events(&self, limit: usize) -> Vec<WafEvent> {
        let buf = self.event_buffer.lock().unwrap();
        buf.iter().rev().take(limit).cloned().collect()
    }

    /// Return the total number of events in the ring buffer.
    pub fn event_count(&self) -> usize {
        self.event_buffer.lock().unwrap().len()
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
            &[
                ("accept", "text/html"),
                ("cookie", "session=abc123"),
            ],
            "example.com",
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
        // %252e = %2e after first decode = . after second
        // We only do single decoding, but the pattern should still match
        // %252e%252e in the path traversal rule
        let decoded = WafEngine::url_decode("%252e%252e");
        assert_eq!(decoded, "%2e%2e");
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
                    ("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"),
                    ("accept", "application/json"),
                    ("cookie", "session=abcdef123456"),
                ],
                "example.com",
            );
        }
        let elapsed = start.elapsed();
        let per_request_us = elapsed.as_micros() / 1000;
        // Must be under 500us per request (the AC says <0.5ms)
        assert!(
            per_request_us < 500,
            "WAF evaluation too slow: {per_request_us}us per request"
        );
    }
}
