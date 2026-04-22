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

//! Unit tests for the WAF engine. Kept in one file (mirroring the
//! pre-split `engine.rs`) so a full behavioral sweep lives together.

use std::time::Instant;

use super::*;
use crate::rules::RuleCategory;

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

// ---------------------------------------------------------------------------
// Header-scoped rules (v1.5.1 audit H-3)
//
// These rules used to live in the main `rules` vec with patterns that
// looked for `name: value` strings (e.g. `(?i)transfer-encoding\s*:.*chunked.*chunked`)
// but Pingora's parser pre-splits headers into (name, value) tuples,
// so the patterns were inert. The dispatch now matches the header
// NAME against `target_headers` and applies the value-only pattern
// to the value alone. End-to-end tests through `evaluate` cover the
// dispatch logic.
// ---------------------------------------------------------------------------

#[test]
fn test_te_chunked_chunked_smuggling_detected() {
    let e = engine();
    let verdict = e.evaluate(
        WafMode::Blocking,
        "/api/v1/upload",
        None,
        &[("transfer-encoding", "chunked, chunked")],
        "example.com",
        "10.0.0.1",
    );
    match verdict {
        WafVerdict::Blocked(events) => {
            assert!(events.iter().any(|ev| ev.rule_id == 920140));
        }
        other => panic!("expected Blocked on TE chunked-chunked smuggling, got {other:?}"),
    }
}

#[test]
fn test_te_legitimate_chunked_passes() {
    let e = engine();
    let verdict = e.evaluate(
        WafMode::Blocking,
        "/api/v1/upload",
        None,
        &[("transfer-encoding", "chunked")],
        "example.com",
        "10.0.0.1",
    );
    assert_eq!(verdict, WafVerdict::Pass);
}

#[test]
fn test_te_gzip_then_chunked_passes() {
    // Common compression+chunked combo - must not trip 920140.
    let e = engine();
    let verdict = e.evaluate(
        WafMode::Blocking,
        "/api/v1/upload",
        None,
        &[("transfer-encoding", "gzip, chunked")],
        "example.com",
        "10.0.0.1",
    );
    assert_eq!(verdict, WafVerdict::Pass);
}

#[test]
fn test_invalid_content_length_detected() {
    let e = engine();
    let verdict = e.evaluate(
        WafMode::Blocking,
        "/api/v1/login",
        None,
        &[("content-length", "abc")],
        "example.com",
        "10.0.0.1",
    );
    match verdict {
        WafVerdict::Blocked(events) => {
            assert!(events.iter().any(|ev| ev.rule_id == 920100));
        }
        other => panic!("expected Blocked on invalid CL, got {other:?}"),
    }
}

#[test]
fn test_valid_content_length_passes() {
    let e = engine();
    let verdict = e.evaluate(
        WafMode::Blocking,
        "/api/v1/login",
        None,
        &[("content-length", "1024")],
        "example.com",
        "10.0.0.1",
    );
    assert_eq!(verdict, WafVerdict::Pass);
}

#[test]
fn test_proxy_header_injection_detected() {
    let e = engine();
    let verdict = e.evaluate(
        WafMode::Blocking,
        "/api/v1/foo",
        None,
        &[("x-forwarded-host", "evil.com|whoami")],
        "example.com",
        "10.0.0.1",
    );
    match verdict {
        WafVerdict::Blocked(events) => {
            assert!(events.iter().any(|ev| ev.rule_id == 920120));
        }
        other => panic!("expected Blocked on proxy-header injection, got {other:?}"),
    }
}

#[test]
fn test_proxy_header_legitimate_value_passes() {
    let e = engine();
    let verdict = e.evaluate(
        WafMode::Blocking,
        "/api/v1/foo",
        None,
        &[("x-forwarded-host", "api.example.com")],
        "example.com",
        "10.0.0.1",
    );
    assert_eq!(verdict, WafVerdict::Pass);
}

#[test]
fn test_header_scoped_dispatch_skips_other_headers() {
    // The `chunked, chunked` value on a NON-`transfer-encoding`
    // header must not trip rule 920140 - the dispatch is
    // name-gated.
    let e = engine();
    let verdict = e.evaluate(
        WafMode::Blocking,
        "/",
        None,
        &[("user-agent", "chunked, chunked")],
        "example.com",
        "10.0.0.1",
    );
    assert_eq!(verdict, WafVerdict::Pass);
}

#[test]
fn test_header_scoped_dispatch_case_insensitive() {
    // RFC 9110 says header names are ASCII case-insensitive ;
    // verify the dispatch tolerates `Content-Length` upper-case.
    let e = engine();
    let verdict = e.evaluate(
        WafMode::Blocking,
        "/",
        None,
        &[("Content-Length", "abc")],
        "example.com",
        "10.0.0.1",
    );
    match verdict {
        WafVerdict::Blocked(events) => {
            assert!(events.iter().any(|ev| ev.rule_id == 920100));
        }
        other => panic!("expected Blocked on case-insensitive header dispatch, got {other:?}"),
    }
}

#[test]
fn test_header_scoped_disable_takes_effect() {
    let e = engine();
    assert!(e.disable_rule(920140), "disable_rule must accept scoped IDs");
    let verdict = e.evaluate(
        WafMode::Blocking,
        "/",
        None,
        &[("transfer-encoding", "chunked, chunked")],
        "example.com",
        "10.0.0.1",
    );
    assert_eq!(verdict, WafVerdict::Pass);
    assert!(e.enable_rule(920140), "enable_rule must accept scoped IDs");
    let verdict2 = e.evaluate(
        WafMode::Blocking,
        "/",
        None,
        &[("transfer-encoding", "chunked, chunked")],
        "example.com",
        "10.0.0.1",
    );
    assert!(matches!(verdict2, WafVerdict::Blocked(_)));
}

#[test]
fn test_list_rules_includes_header_scoped() {
    let e = engine();
    let summaries = e.list_rules();
    assert!(summaries.iter().any(|s| s.id == 920100));
    assert!(summaries.iter().any(|s| s.id == 920120));
    assert!(summaries.iter().any(|s| s.id == 920140));
}
