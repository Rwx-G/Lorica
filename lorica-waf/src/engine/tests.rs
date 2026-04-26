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
    assert_eq!(WafEngine::url_decode_form("%3Cscript%3E"), "<script>");
    assert_eq!(WafEngine::url_decode_form("hello+world"), "hello world");
    assert_eq!(WafEngine::url_decode_form("no_encoding"), "no_encoding");
}

#[test]
fn test_url_decode_double_encoded() {
    // %252e = %2e after first decode = . after second (recursive decoding)
    let decoded = WafEngine::url_decode_form("%252e%252e");
    assert_eq!(decoded, "..");
}

#[test]
fn test_url_decode_triple_encoded() {
    // %25252e -> %252e -> %2e -> . (three iterations needed)
    let decoded = WafEngine::url_decode_form("%25252e");
    assert_eq!(decoded, ".");
}

#[test]
fn test_url_decode_stable_input() {
    // Already decoded input should remain unchanged
    assert_eq!(WafEngine::url_decode_form("hello world"), "hello world");
}

// --- v1.5.1 audit H-4 : UTF-8 + URI / form variants ---

#[test]
fn test_url_decode_form_multibyte_utf8_roundtrips() {
    // %C3%A9 is UTF-8 for `é` (U+00E9). Pre-fix, the byte-as-char
    // cast decoded this to two codepoints `U+00C3 U+00A9`. The
    // byte-level decode + from_utf8_lossy reassembly now restores
    // the original codepoint so a regex anchored on `é` actually
    // matches.
    assert_eq!(WafEngine::url_decode_form("%C3%A9"), "\u{00E9}");
    assert_eq!(WafEngine::url_decode_form("%E2%9C%93"), "\u{2713}"); // ✓
    assert_eq!(WafEngine::url_decode_form("%E2%80%A8"), "\u{2028}"); // LINE SEPARATOR
}

#[test]
fn test_url_decode_form_preserves_null_byte() {
    // A real %00 must survive decoding so signatures looking for
    // a NUL byte (e.g. truncation attacks) still fire.
    let decoded = WafEngine::url_decode_form("admin%00.png");
    assert!(decoded.contains('\0'));
    assert_eq!(decoded, "admin\0.png");
}

#[test]
fn test_url_decode_form_overlong_utf8_neutralised() {
    // %C0%80 is an overlong UTF-8 encoding of NUL (U+0000) - a
    // classic CRS bypass shape that pre-fix decoded byte-by-byte
    // into the codepoints `U+00C0 U+0080` (one of which then
    // ASCII-aliased back to NUL through the regex). The
    // from_utf8_lossy pass now rejects the overlong sequence and
    // surfaces U+FFFD instead, so an attacker cannot smuggle a
    // NUL past `\0`-anchored signatures via overlong encoding.
    let decoded = WafEngine::url_decode_form("%C0%80");
    assert!(!decoded.contains('\0'), "overlong NUL must not decode to a real NUL");
    assert!(decoded.contains('\u{FFFD}'), "overlong NUL must surface as REPLACEMENT CHARACTER");

    // Same for `%C0%BC` (overlong `<`) - must NOT decode to `<`.
    let decoded = WafEngine::url_decode_form("%C0%BC");
    assert!(!decoded.contains('<'), "overlong `<` must not decode to a real `<`");
}

#[test]
fn test_url_decode_form_invalid_escape_left_literal() {
    // Malformed %XX (non-hex digits, missing trailing chars) is
    // kept literally rather than silently dropped.
    assert_eq!(WafEngine::url_decode_form("%G1"), "%G1");
    assert_eq!(WafEngine::url_decode_form("%2"), "%2");
    assert_eq!(WafEngine::url_decode_form("trailing%"), "trailing%");
}

#[test]
fn test_url_decode_uri_keeps_plus_literal() {
    // RFC 3986 says `+` in a URI path / header value is literal.
    // Form-style decoding (treating `+` as space) is wrong for
    // these fields - it inflates the false-positive surface
    // (e.g. a header value `attacker+payload` would decode to
    // `attacker payload` and trip space-anchored signatures).
    assert_eq!(WafEngine::url_decode_uri("hello+world"), "hello+world");
    assert_eq!(WafEngine::url_decode_uri("a+b+c"), "a+b+c");
    assert_eq!(WafEngine::url_decode_uri("%2B"), "+"); // %2B IS the literal `+`, decoded as such
}

#[test]
fn test_url_decode_form_keeps_plus_to_space_semantics() {
    // Form-encoded fields (query string, x-www-form-urlencoded
    // body) treat `+` as space - keep that behaviour.
    assert_eq!(WafEngine::url_decode_form("hello+world"), "hello world");
    assert_eq!(WafEngine::url_decode_form("a+b+c"), "a b c");
}

#[test]
fn test_url_decode_uri_decodes_percent_escapes() {
    // URI variant must still do %XX decoding ; only the `+`
    // semantics differ from the form variant.
    assert_eq!(WafEngine::url_decode_uri("%3Cscript%3E"), "<script>");
    assert_eq!(WafEngine::url_decode_uri("%252e%252e"), "..");
}

#[test]
fn test_url_decode_uri_multibyte_utf8_roundtrips() {
    // UTF-8 multi-byte handling is the same as form (only `+`
    // semantics differ).
    assert_eq!(WafEngine::url_decode_uri("%C3%A9"), "\u{00E9}");
    assert_eq!(WafEngine::url_decode_uri("%E2%9C%93"), "\u{2713}");
}

// --- v1.5.1 audit M-4 : custom rules + prefilter contract ---

#[test]
fn test_custom_rule_still_fires_with_builtins_loaded() {
    // Functional regression : a custom rule that matches its
    // pattern must still produce a `WafEvent`, even though built-in
    // rules are now scanned through a separate code path.
    let e = engine();
    e.add_custom_rule(
        90001,
        "internal-marker".to_string(),
        RuleCategory::ProtocolViolation,
        r"INTERNAL_MARKER_42",
        4,
    )
    .expect("custom rule must compile");

    let verdict = e.evaluate(
        WafMode::Blocking,
        "/api/v1/foo",
        Some("q=INTERNAL_MARKER_42"),
        &[("user-agent", "test")],
        "example.com",
        "10.0.0.1",
    );
    match verdict {
        WafVerdict::Blocked(events) => {
            assert!(events.iter().any(|ev| ev.rule_id == 90001));
        }
        other => panic!("expected Blocked on custom rule match, got {other:?}"),
    }
}

#[test]
fn test_builtin_still_fires_when_custom_rule_present() {
    // PERF-9 + M-4 invariant : loading a custom rule must not
    // break the built-in detection. Add a custom rule that does
    // NOT match the request, send a SQLi attack, verify the
    // built-in 942100 (UNION SELECT) still fires.
    let e = engine();
    e.add_custom_rule(
        90002,
        "irrelevant-marker".to_string(),
        RuleCategory::ProtocolViolation,
        r"this_string_will_not_appear_in_traffic",
        2,
    )
    .expect("custom rule must compile");

    let verdict = e.evaluate(
        WafMode::Blocking,
        "/search",
        Some("q=1%20UNION%20SELECT%20*%20FROM%20users"),
        &[],
        "example.com",
        "10.0.0.1",
    );
    match verdict {
        WafVerdict::Blocked(events) => {
            assert!(
                events
                    .iter()
                    .any(|ev| ev.category == RuleCategory::SqlInjection),
                "built-in SQLi rule must still fire when a custom rule is loaded"
            );
            // And the custom rule did NOT misfire.
            assert!(
                events.iter().all(|ev| ev.rule_id != 90002),
                "custom rule with non-matching pattern must not fire"
            );
        }
        other => panic!("expected Blocked on SQLi, got {other:?}"),
    }
}

#[test]
fn test_clean_request_passes_with_custom_rule_loaded() {
    // M-4 regression pin : a clean request with a custom rule
    // loaded must NOT produce events from either the built-in
    // pass (prefilter does not match -> built-in scan skipped)
    // or the custom pass (request does not match the custom
    // pattern). Pre-fix, the presence of any custom rule
    // disabled the prefilter shortcut and ran every built-in
    // rule on every field of every request.
    let e = engine();
    e.add_custom_rule(
        90003,
        "marker".to_string(),
        RuleCategory::ProtocolViolation,
        r"WILL_NEVER_APPEAR",
        2,
    )
    .expect("custom rule must compile");

    let verdict = e.evaluate(
        WafMode::Blocking,
        "/api/v1/users/42",
        Some("page=1&limit=20"),
        &[("user-agent", "Mozilla/5.0"), ("accept", "application/json")],
        "example.com",
        "10.0.0.1",
    );
    assert_eq!(verdict, WafVerdict::Pass);
}

#[test]
fn test_custom_and_builtin_can_both_fire() {
    // When a request matches BOTH a custom rule and a built-in
    // rule, both events surface (full-scan semantics preserved).
    let e = engine();
    e.add_custom_rule(
        90004,
        "marker-on-script".to_string(),
        RuleCategory::Xss,
        r"INTERNAL_XSS_TAG",
        4,
    )
    .expect("custom rule must compile");

    let verdict = e.evaluate(
        WafMode::Blocking,
        "/search",
        Some("q=%3Cscript%3Ealert(1)%3C/script%3EINTERNAL_XSS_TAG"),
        &[],
        "example.com",
        "10.0.0.1",
    );
    match verdict {
        WafVerdict::Blocked(events) => {
            assert!(
                events.iter().any(|ev| ev.rule_id == 90004),
                "custom rule must fire"
            );
            assert!(
                events.iter().any(|ev| ev.category == RuleCategory::Xss),
                "built-in XSS rule must also fire"
            );
        }
        other => panic!("expected Blocked, got {other:?}"),
    }
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

// Perf regression coverage lives in `benches/evaluate.rs` (criterion,
// 3 representative request shapes, statistically robust). The previous
// `test_evaluation_is_fast` unit test with a 1000us wall-clock threshold
// was flaky under contended CI runners and duplicated coverage already
// provided by the criterion bench. Run `cargo bench -p lorica-waf` to
// catch perf regressions.

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
