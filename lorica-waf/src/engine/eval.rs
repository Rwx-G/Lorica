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
        // v1.5.2 audit L-20 : defer the `chrono::Utc::now().to_rfc3339()`
        // call (~200 ns per request) until at least one event fires.
        // Empty `now` is stamped on every WafEvent during the scan ;
        // the post-scan loop fills the real timestamp only when
        // events end up non-empty.
        let now = "";

        // PERF-9 + v1.5.1 audit M-4 : two-phase eval. Per-field,
        // run the cheap Aho-Corasick prefilter first ; only fall
        // through to the built-in regex pass when the prefilter
        // hits. Custom user rules are outside the prefilter
        // coverage contract (their patterns are unknown at build
        // time) so they run unconditionally when any custom rule
        // is loaded. Pre-fix, the presence of a single custom rule
        // bypassed the prefilter for the 49 built-in rules on
        // every field, turning every clean request into an
        // O(rules x fields) regex scan and amplifying admin
        // misconfiguration into a DoS vector.
        let has_custom_rules = !self.custom_rules.read().is_empty();

        // Check path (URI percent-decoding ; `+` is a literal in
        // paths per RFC 3986, do not rewrite to space). Decoding
        // is recursive to defeat double / triple-encoded traversal
        // attacks.
        let decoded_path = Self::url_decode_uri(path);
        if self.prefilter.matches(&decoded_path) {
            self.scan_builtin_rules("path", &decoded_path, now, &mut events);
        }
        if has_custom_rules {
            self.scan_custom_rules("path", &decoded_path, now, &mut events);
        }

        // Check query string (form-style decoding ; `+` -> space).
        if let Some(q) = query {
            let decoded = Self::url_decode_form(q);
            if self.prefilter.matches(&decoded) {
                self.scan_builtin_rules("query", &decoded, now, &mut events);
            }
            if has_custom_rules {
                self.scan_custom_rules("query", &decoded, now, &mut events);
            }
        }

        // Check relevant headers (URI percent-decoding ; `+` is a
        // literal in header values - rewriting it to space inflated
        // the false-positive surface on the previous form-style
        // decode, e.g. a header value `attacker+payload` decoded
        // to `attacker payload` and tripped space-anchored rules
        // like ` or 1=`).
        for (name, value) in headers {
            let decoded = Self::url_decode_uri(value);
            let field = format!("header:{name}");
            if self.prefilter.matches(&decoded) {
                self.scan_builtin_rules(&field, &decoded, now, &mut events);
            }
            if has_custom_rules {
                self.scan_custom_rules(&field, &decoded, now, &mut events);
            }
        }

        // Header-scoped rules (v1.5.1 audit H-3). Dispatched on
        // header NAME and matched against the URL-decoded VALUE.
        // The CRS-derived patterns for these rules used to look for
        // the header name inside the value (`(?i)transfer-encoding\s*:.*chunked.*chunked`)
        // which never matched after Pingora's parser pre-split
        // headers into `(name, value)` tuples - they were inert.
        // Scoped rules bypass the prefilter (the prefilter is
        // content-shape based and adds no signal here) and are
        // still subject to the per-rule disable list.
        {
            let disabled = self.disabled_rules.read();
            for scoped in self.ruleset.header_scoped() {
                if disabled.contains(&scoped.id) {
                    continue;
                }
                for (name, value) in headers {
                    if !scoped
                        .target_headers
                        .iter()
                        .any(|target| name.eq_ignore_ascii_case(target))
                    {
                        continue;
                    }
                    let decoded = Self::url_decode_uri(value);
                    if let Some(m) = scoped.pattern.find(&decoded) {
                        events.push(WafEvent {
                            rule_id: scoped.id,
                            description: scoped.description.to_string(),
                            category: scoped.category.clone(),
                            severity: scoped.severity,
                            matched_field: format!("header:{name}"),
                            matched_value: m.as_str().to_string(),
                            // Stamped post-scan in the !events.is_empty()
                            // branch (audit L-20 - chrono call deferred).
                            timestamp: String::new(),
                            client_ip: String::new(),
                            route_hostname: String::new(),
                            action: String::new(),
                        });
                    }
                }
            }
        }

        let elapsed = start.elapsed();

        if !events.is_empty() {
            // Compute timestamp lazily : only when we know at least
            // one event fired (v1.5.2 audit L-20).
            let timestamp = chrono::Utc::now().to_rfc3339();
            // Stamp each event with the client IP + the timestamp
            for ev in &mut events {
                ev.client_ip = client_ip.to_string();
                ev.timestamp = timestamp.clone();
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
        // v1.5.2 audit L-20 : defer chrono::Utc::now until events
        // are non-empty (same fast path as `evaluate`).
        let now = "";

        // URL-decode the body to catch encoded payloads. Form-style
        // (`+` -> space) is the safe default for request bodies :
        // `application/x-www-form-urlencoded` is the most common
        // shape on the routes WAF is enabled for, and the rewrite
        // is harmless for JSON / XML / multipart bodies (regex
        // patterns rarely anchor on a literal `+`). PERF-9 + audit
        // M-4 : built-in body rules only run when the prefilter
        // hits ; custom rules run unconditionally when present.
        let decoded = Self::url_decode_form(text);
        if self.prefilter.matches(&decoded) {
            self.scan_builtin_rules("body", &decoded, now, &mut events);
        }
        if !self.custom_rules.read().is_empty() {
            self.scan_custom_rules("body", &decoded, now, &mut events);
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

        // Stamp each event with the client IP + the (deferred) timestamp
        let timestamp = chrono::Utc::now().to_rfc3339();
        for ev in &mut events {
            ev.client_ip = client_ip.to_string();
            ev.timestamp = timestamp.clone();
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

    /// Scan a single field against the built-in rules only.
    ///
    /// Call sites gate this on the Aho-Corasick prefilter so a clean
    /// field skips the regex pass entirely (PERF-9). Custom user
    /// rules are scanned separately by [`Self::scan_custom_rules`]
    /// because they are outside the prefilter coverage contract.
    /// When `field` is "body", rules that don't apply to body
    /// content (e.g. path traversal, protocol violations) are
    /// skipped.
    fn scan_builtin_rules(
        &self,
        field: &str,
        value: &str,
        timestamp: &str,
        events: &mut Vec<WafEvent>,
    ) {
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
    }

    /// Scan a single field against the operator-supplied custom
    /// rules.
    ///
    /// Custom rules are NOT covered by the Aho-Corasick prefilter
    /// (their patterns are unknown at build time), so call sites
    /// invoke this unconditionally whenever any custom rule is
    /// loaded. Disabled rules are skipped. v1.5.1 audit M-4 split
    /// this off from the previous monolithic `scan_field` so the
    /// presence of a single (possibly broad) custom rule no longer
    /// disables the prefilter shortcut for the 49 built-in rules
    /// on every field of every request.
    fn scan_custom_rules(
        &self,
        field: &str,
        value: &str,
        timestamp: &str,
        events: &mut Vec<WafEvent>,
    ) {
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
