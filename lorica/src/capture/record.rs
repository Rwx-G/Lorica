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

//! The capture record (Story 10.2 AC #1): the one JSON document a
//! capture produces, built at `logging` from the buffers Story 10.1
//! filled and the same values the access-log row is built from.
//!
//! The record is a `serde::Serialize` struct with a fixed field order
//! and no map anywhere in it, so two records of the same exchange are
//! byte-identical and a header that repeats is kept as many times as
//! it was sent. It is built and redacted here; where it goes is the
//! sinks' business.
//!
//! # Joining the access log
//!
//! [`CaptureRecord::build`] takes the [`LogEntry`] the access-log row is
//! made of and copies `request_id`, `timestamp`, `client_ip`, `is_xff`,
//! `backend`, `latency_ms`, `status` and `error` from it. That is what
//! makes a capture joinable on `request_id` and guaranteed to agree with
//! the row on everything else: there is one source, not two readings.

use base64::Engine;
use http::HeaderValue;
use lorica_api::logs::LogEntry;
use lorica_config::models::CaptureRule;
use lorica_http::{RequestHeader, ResponseHeader};
use serde::Serialize;

use super::buffers::{CaptureBody, CaptureSkip, CaptureState};
use super::redact::{is_redacted_header, mask_query, redacted_marker};

/// The `kind` every capture record carries, so a consumer reading a
/// mixed stream can tell a capture from an access-log row.
pub const CAPTURE_RECORD_KIND: &str = "capture";

/// How a recorded body is encoded in the `body` field.
///
/// `utf8` only when BOTH hold: the content type is textual (see
/// [`is_textual_content_type`]) and the kept bytes are valid UTF-8.
/// A textual content type carrying bytes that are not UTF-8 is
/// `base64`, and so is a truncated text body whose cut fell inside a
/// multi-byte character: the record never repairs bytes to make them
/// readable, because a repaired body is not the body that was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BodyEncoding {
    /// The bytes, as they are.
    Utf8,
    /// Standard base64 with padding, of the bytes as they are.
    Base64,
}

/// Why a direction of the record holds no body.
///
/// The one vocabulary for `body_skipped`, serialised lowercase. The
/// first two come from the buffering ([`CaptureSkip`]); the third is a
/// rule that never asked for this direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BodySkip {
    /// Stream-by-design content type; never buffered.
    Streaming,
    /// The node-wide in-flight ceiling was reached.
    Budget,
    /// The rule's `capture.request_body` or `capture.response_body` is
    /// off.
    Disabled,
}

impl From<CaptureSkip> for BodySkip {
    fn from(skip: CaptureSkip) -> Self {
        match skip {
            CaptureSkip::Streaming => Self::Streaming,
            CaptureSkip::Budget => Self::Budget,
        }
    }
}

/// Media types whose body is text, compared against the type without
/// its parameters. `text/*` and the `+json` / `+xml` structured-syntax
/// suffixes are matched by shape rather than listed.
///
/// The list is short on purpose. "Textual" decides only whether the
/// record is readable as-is or needs a decode step; a type left out is
/// still recorded, as base64. Growing the list makes some records
/// easier to read, and nothing else, so it should grow only for a type
/// operators actually capture.
const TEXTUAL_CONTENT_TYPES: [&str; 3] = [
    "application/json",
    "application/xml",
    "application/x-www-form-urlencoded",
];

/// Whether `content_type` (a `Content-Type` header value, parameters
/// included) names a body the record may hold as text.
///
/// ```
/// use lorica::capture::is_textual_content_type;
/// assert!(is_textual_content_type("application/json; charset=utf-8"));
/// assert!(is_textual_content_type("text/html"));
/// assert!(is_textual_content_type("application/problem+json"));
/// assert!(!is_textual_content_type("application/octet-stream"));
/// assert!(!is_textual_content_type("image/png"));
/// ```
pub fn is_textual_content_type(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    media_type.starts_with("text/")
        || media_type.ends_with("+json")
        || media_type.ends_with("+xml")
        || TEXTUAL_CONTENT_TYPES.contains(&media_type.as_str())
}

/// The request half of a record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapturedRequest {
    /// HTTP method as received.
    pub method: String,
    /// Request target (path and query) as received, with the query
    /// parameters the rule names masked. See
    /// [`mask_query`](super::mask_query).
    pub uri: String,
    /// HTTP version, e.g. `HTTP/1.1`.
    pub version: String,
    /// Headers as `[name, value]` pairs, every occurrence kept, values
    /// redacted per the rule. Names keep the case they were sent with
    /// when the connection preserved it, and are lowercase otherwise
    /// (HTTP/2). Occurrences of one name are adjacent and in the order
    /// they were sent.
    pub headers: Vec<(String, String)>,
    /// The kept bytes, in `body_encoding`. `null` when `body_skipped`
    /// says why; an empty string is a body that was genuinely empty.
    pub body: Option<String>,
    /// How `body` is encoded. `null` exactly when `body` is.
    pub body_encoding: Option<BodyEncoding>,
    /// Bytes the request body carried on the wire. Exceeds the kept
    /// length when `truncated`, and is still counted when the body was
    /// skipped.
    pub body_bytes_total: u64,
    /// Whether `body` is a prefix of what was sent.
    pub truncated: bool,
    /// Why `body` is `null`, or `null` itself when it is not.
    pub body_skipped: Option<BodySkip>,
}

/// The response half of a record.
///
/// The body is the UPSTREAM's, as it arrived at this proxy and before
/// any `response_rewrite` rule edited it. Story 10.1 buffers it ahead
/// of the rewrite on purpose: a capture answers "what did the backend
/// send", and on a route that rewrites bodies that is not what the
/// client received. The status and headers, by contrast, are the ones
/// written downstream, which is also what the access-log row reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapturedResponse {
    /// Status written downstream; `0` when no response was written.
    pub status: u16,
    /// Headers written downstream, same shape as the request's.
    pub headers: Vec<(String, String)>,
    /// The kept upstream bytes, in `body_encoding`. See the type doc.
    pub body: Option<String>,
    /// How `body` is encoded. `null` exactly when `body` is.
    pub body_encoding: Option<BodyEncoding>,
    /// Bytes the upstream body carried. Exceeds the kept length when
    /// `truncated`.
    pub body_bytes_total: u64,
    /// Whether `body` is a prefix of what the upstream sent.
    pub truncated: bool,
    /// Why `body` is `null`, or `null` itself when it is not.
    pub body_skipped: Option<BodySkip>,
}

/// One captured exchange, for one rule.
///
/// Two rules admitting the same exchange produce two records that
/// differ in `rule_id`, `rule_name`, and whatever their caps and
/// redaction lists make of the shared buffers. Each record owns its own
/// copy of the bytes it keeps: the buffer it was cut from dies at the
/// end of the `logging` hook that built the record, so the copy is the
/// only one that outlives the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureRecord {
    /// Always [`CAPTURE_RECORD_KIND`].
    pub kind: &'static str,
    /// The rule that admitted this exchange.
    pub rule_id: String,
    /// Its operator-facing name at the time.
    pub rule_name: String,
    /// The route the rule records.
    pub route_id: String,
    /// The access-log row's `request_id`; the join key.
    pub request_id: String,
    /// The access-log row's timestamp, RFC 3339.
    pub timestamp: String,
    /// The access-log row's client address.
    pub client_ip: String,
    /// Whether `client_ip` came from `X-Forwarded-For`.
    pub is_xff: bool,
    /// The backend that served the request, or `-`.
    pub backend: String,
    /// Request-to-response latency in milliseconds.
    pub latency_ms: u64,
    /// The access-log row's error text, when it has one.
    pub error: Option<String>,
    /// The request half.
    pub request: CapturedRequest,
    /// The response half.
    pub response: CapturedResponse,
}

/// The body fields of one direction, before they are placed in the
/// request or response half. Private so the two halves stay explicit
/// structs with a fixed field order; this is only how they are filled.
struct RecordedBody {
    body: Option<String>,
    encoding: Option<BodyEncoding>,
    total: u64,
    truncated: bool,
    skipped: Option<BodySkip>,
}

impl RecordedBody {
    /// What `rule` gets of one buffered direction.
    ///
    /// The buffer is shared between every candidate rule and sized to
    /// the largest cap among them, so a rule with a smaller cap reads a
    /// prefix and reports `truncated` for it; that is exactly the body
    /// the rule asked for.
    fn for_rule(
        direction: &CaptureBody,
        received: u64,
        wanted: bool,
        cap: usize,
        content_type: Option<&str>,
    ) -> Self {
        let skipped = |reason: BodySkip| Self {
            body: None,
            encoding: None,
            total: received,
            truncated: false,
            skipped: Some(reason),
        };
        if !wanted {
            return skipped(BodySkip::Disabled);
        }
        match direction {
            // A rule that wants a direction the state never buffered
            // can only be one whose `capture` block changed between
            // `request_filter` and `logging`; the state was built under
            // the older block, so "off" is the truthful answer.
            CaptureBody::Off => skipped(BodySkip::Disabled),
            CaptureBody::Skipped(reason) => skipped(BodySkip::from(*reason)),
            CaptureBody::Buffered {
                bytes, truncated, ..
            } => {
                let kept = &bytes[..bytes.len().min(cap)];
                let (body, encoding) = encode_body(kept, content_type);
                Self {
                    body: Some(body),
                    encoding: Some(encoding),
                    total: received,
                    truncated: *truncated || bytes.len() > cap,
                    skipped: None,
                }
            }
        }
    }
}

/// The `body` text and its encoding for `bytes` under `content_type`.
fn encode_body(bytes: &[u8], content_type: Option<&str>) -> (String, BodyEncoding) {
    let textual = content_type.is_some_and(is_textual_content_type);
    match std::str::from_utf8(bytes) {
        Ok(text) if textual => (text.to_string(), BodyEncoding::Utf8),
        _ => (
            base64::engine::general_purpose::STANDARD.encode(bytes),
            BodyEncoding::Base64,
        ),
    }
}

/// One header as the record carries it: the name, and either the value
/// or the marker that replaced it.
///
/// A value that is not UTF-8 (RFC 9110 `obs-text`) is recorded lossily;
/// the marker, when one applies, still counts the bytes as sent.
fn recorded_pair(name: String, value: &HeaderValue, extra_redacted: &[String]) -> (String, String) {
    let recorded = if is_redacted_header(&name, extra_redacted) {
        redacted_marker(value.len())
    } else {
        String::from_utf8_lossy(value.as_bytes()).into_owned()
    };
    (name, recorded)
}

/// Every header of `pairs`, redacted.
fn recorded_headers<'a>(
    pairs: impl Iterator<Item = (String, &'a HeaderValue)>,
    extra_redacted: &[String],
) -> Vec<(String, String)> {
    pairs
        .map(|(name, value)| recorded_pair(name, value, extra_redacted))
        .collect()
}

/// The request headers, in the case they were sent with when the
/// connection kept it.
fn request_headers(req: &RequestHeader, extra_redacted: &[String]) -> Vec<(String, String)> {
    if req.has_case() {
        recorded_headers(
            req.case_header_iter().map(|(name, value)| {
                (String::from_utf8_lossy(name.as_slice()).into_owned(), value)
            }),
            extra_redacted,
        )
    } else {
        recorded_headers(
            req.headers
                .iter()
                .map(|(name, value)| (name.as_str().to_string(), value)),
            extra_redacted,
        )
    }
}

/// The response headers, same rule as [`request_headers`].
fn response_headers(resp: &ResponseHeader, extra_redacted: &[String]) -> Vec<(String, String)> {
    if resp.has_case() {
        recorded_headers(
            resp.case_header_iter().map(|(name, value)| {
                (String::from_utf8_lossy(name.as_slice()).into_owned(), value)
            }),
            extra_redacted,
        )
    } else {
        recorded_headers(
            resp.headers
                .iter()
                .map(|(name, value)| (name.as_str().to_string(), value)),
            extra_redacted,
        )
    }
}

fn content_type_of(headers: &http::HeaderMap) -> Option<&str> {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
}

impl CaptureRecord {
    /// Build the record `rule` gets for the exchange `state` buffered.
    ///
    /// `access` is the access-log row for the same request, built
    /// first and passed in rather than re-derived, so the two agree by
    /// construction. `response` is `None` when nothing was written
    /// downstream (an upstream failure before any header, a client that
    /// hung up); the response half then carries the row's status and
    /// no headers.
    pub fn build(
        rule: &CaptureRule,
        state: &CaptureState,
        access: &LogEntry,
        request: &RequestHeader,
        response: Option<&ResponseHeader>,
    ) -> CaptureRecord {
        let uri = request
            .uri
            .path_and_query()
            .map_or_else(|| request.uri.to_string(), |pq| pq.as_str().to_string());
        let request_body = RecordedBody::for_rule(
            &state.request,
            state.request_received,
            rule.capture.request_body,
            rule.capture.request_body_max_bytes as usize,
            content_type_of(&request.headers),
        );
        let response_body = RecordedBody::for_rule(
            &state.response,
            state.response_received,
            rule.capture.response_body,
            rule.capture.response_body_max_bytes as usize,
            response.and_then(|resp| content_type_of(&resp.headers)),
        );

        CaptureRecord {
            kind: CAPTURE_RECORD_KIND,
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            route_id: rule.route_id.clone(),
            request_id: access.request_id.clone(),
            timestamp: access.timestamp.clone(),
            client_ip: access.client_ip.clone(),
            is_xff: access.is_xff,
            backend: access.backend.clone(),
            latency_ms: access.latency_ms,
            error: access.error.clone(),
            request: CapturedRequest {
                method: request.method.as_str().to_string(),
                uri: mask_query(&uri, &rule.redact.query),
                version: format!("{:?}", request.version),
                headers: request_headers(request, &rule.redact.headers),
                body: request_body.body,
                body_encoding: request_body.encoding,
                body_bytes_total: request_body.total,
                truncated: request_body.truncated,
                body_skipped: request_body.skipped,
            },
            response: CapturedResponse {
                status: access.status,
                headers: response
                    .map(|resp| response_headers(resp, &rule.redact.headers))
                    .unwrap_or_default(),
                body: response_body.body,
                body_encoding: response_body.encoding,
                body_bytes_total: response_body.total,
                truncated: response_body.truncated,
                body_skipped: response_body.skipped,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{CaptureBudget, CompiledCaptureRules};
    use chrono::{DateTime, Duration, Utc};
    use lorica_config::models::{
        CaptureEmit, CaptureLimits, CaptureMatch, CaptureOutput, CaptureRedaction, CaptureScope,
        StatusMatch,
    };
    use std::sync::Arc;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("test setup: a literal RFC 3339 instant parses")
            .with_timezone(&Utc)
    }

    /// A rule on `route-1` that keeps both directions up to 64 bytes.
    fn rule(id: &str) -> CaptureRule {
        CaptureRule {
            id: id.to_string(),
            name: format!("rule {id}"),
            route_id: "route-1".to_string(),
            enabled: true,
            match_: CaptureMatch::default(),
            emit: CaptureEmit {
                always: false,
                status: vec![StatusMatch::ServerError],
                min_latency_ms: None,
                upstream_error: false,
            },
            capture: CaptureScope {
                request_body: true,
                response_body: true,
                request_body_max_bytes: 64,
                response_body_max_bytes: 64,
            },
            limits: CaptureLimits::default(),
            output: CaptureOutput::default(),
            redact: CaptureRedaction::default(),
            created_by: "admin".to_string(),
            created_at: now(),
            expires_at: now() + Duration::hours(1),
            captures_emitted: 0,
            captures_dropped: 0,
        }
    }

    /// The access-log row `logging` would build for the request.
    fn access_row() -> LogEntry {
        LogEntry {
            id: 0,
            timestamp: "2026-01-01T00:00:00.123456789+00:00".to_string(),
            method: "POST".to_string(),
            path: "/checkout".to_string(),
            host: "shop.example.com".to_string(),
            status: 503,
            latency_ms: 1_234,
            backend: "10.0.0.2:8080".to_string(),
            error: Some("upstream timed out".to_string()),
            client_ip: "10.0.0.7".to_string(),
            is_xff: true,
            xff_proxy_ip: "10.0.0.1".to_string(),
            source: String::new(),
            request_id: "req-0123456789abcdef".to_string(),
        }
    }

    /// The state a request on `route-1` carries under `rules`, through
    /// the same candidate gate the proxy uses, with both bodies pushed.
    fn state_with(rules: &[CaptureRule], request: &[u8], response: &[u8]) -> CaptureState {
        let budget: Arc<CaptureBudget> = CaptureBudget::new(1024 * 1024);
        let compiled = CompiledCaptureRules::compile(rules);
        let candidates = compiled.candidates_for_request(
            "route-1",
            "POST",
            "/checkout",
            &http::HeaderMap::new(),
            "10.0.0.7"
                .parse()
                .expect("test setup: a literal address parses"),
            now(),
        );
        let mut state =
            CaptureState::new(&budget, &candidates).expect("the rule matches this request");
        state.push_request(request);
        state.push_response(response);
        state
    }

    fn request(target: &str, headers: &[(&str, &str)]) -> RequestHeader {
        let mut req = RequestHeader::build("POST", target.as_bytes(), None)
            .expect("test setup: a literal target builds");
        for (name, value) in headers {
            req.append_header((*name).to_string(), *value)
                .expect("test setup: a literal header appends");
        }
        req
    }

    fn response(status: u16, headers: &[(&str, &str)]) -> ResponseHeader {
        let mut resp = ResponseHeader::build(status, None).expect("test setup: a status builds");
        for (name, value) in headers {
            resp.append_header((*name).to_string(), *value)
                .expect("test setup: a literal header appends");
        }
        resp
    }

    fn json_text() -> (&'static str, &'static str) {
        ("Content-Type", "application/json")
    }

    fn header_value<'a>(pairs: &'a [(String, String)], name: &str) -> Vec<&'a str> {
        pairs
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    #[test]
    fn a_duplicate_header_keeps_both_occurrences_in_order() {
        let rule = rule("cap-1");
        let state = state_with(std::slice::from_ref(&rule), b"{}", b"{}");
        let resp = response(
            503,
            &[
                ("X-Trace", "first"),
                ("Retry-After", "1"),
                ("X-Trace", "second"),
            ],
        );
        let record = CaptureRecord::build(
            &rule,
            &state,
            &access_row(),
            &request("/checkout", &[json_text()]),
            Some(&resp),
        );
        assert_eq!(
            header_value(&record.response.headers, "x-trace"),
            vec!["first", "second"]
        );
        assert_eq!(record.response.headers.len(), 3);
    }

    #[test]
    fn a_textual_body_of_valid_utf8_is_recorded_as_utf8() {
        let rule = rule("cap-1");
        let state = state_with(
            std::slice::from_ref(&rule),
            "{\"name\":\"é\"}".as_bytes(),
            b"ok",
        );
        let record = CaptureRecord::build(
            &rule,
            &state,
            &access_row(),
            &request("/checkout", &[json_text()]),
            Some(&response(503, &[("Content-Type", "text/plain")])),
        );
        assert_eq!(record.request.body_encoding, Some(BodyEncoding::Utf8));
        assert_eq!(record.request.body.as_deref(), Some("{\"name\":\"é\"}"));
        assert_eq!(record.response.body_encoding, Some(BodyEncoding::Utf8));
        assert_eq!(record.response.body.as_deref(), Some("ok"));
    }

    #[test]
    fn a_textual_body_of_invalid_utf8_is_recorded_as_base64() {
        let rule = rule("cap-1");
        let state = state_with(std::slice::from_ref(&rule), b"\xff\xfe{}", b"");
        let record = CaptureRecord::build(
            &rule,
            &state,
            &access_row(),
            &request("/checkout", &[json_text()]),
            None,
        );
        assert_eq!(record.request.body_encoding, Some(BodyEncoding::Base64));
        assert_eq!(record.request.body.as_deref(), Some("//57fQ=="));
    }

    #[test]
    fn a_binary_content_type_with_valid_utf8_bytes_is_recorded_as_base64() {
        let rule = rule("cap-1");
        let state = state_with(std::slice::from_ref(&rule), b"plain text bytes", b"");
        let record = CaptureRecord::build(
            &rule,
            &state,
            &access_row(),
            &request("/checkout", &[("Content-Type", "application/octet-stream")]),
            None,
        );
        assert_eq!(record.request.body_encoding, Some(BodyEncoding::Base64));
        assert_eq!(
            record.request.body.as_deref(),
            Some("cGxhaW4gdGV4dCBieXRlcw==")
        );
    }

    #[test]
    fn a_body_with_no_content_type_is_recorded_as_base64() {
        let rule = rule("cap-1");
        let state = state_with(std::slice::from_ref(&rule), b"untyped", b"");
        let record = CaptureRecord::build(
            &rule,
            &state,
            &access_row(),
            &request("/checkout", &[]),
            None,
        );
        assert_eq!(record.request.body_encoding, Some(BodyEncoding::Base64));
    }

    #[test]
    fn body_bytes_total_exceeds_the_kept_length_when_truncated() {
        let mut rule = rule("cap-1");
        rule.capture.request_body_max_bytes = 8;
        let state = state_with(std::slice::from_ref(&rule), b"0123456789abcdef", b"");
        let record = CaptureRecord::build(
            &rule,
            &state,
            &access_row(),
            &request("/checkout", &[("Content-Type", "text/plain")]),
            None,
        );
        assert!(record.request.truncated);
        assert_eq!(record.request.body.as_deref(), Some("01234567"));
        assert_eq!(record.request.body_bytes_total, 16);
        assert!(record.request.body_bytes_total > 8);
    }

    #[test]
    fn a_rule_with_the_smaller_cap_reads_a_prefix_of_the_shared_buffer() {
        // The buffer is sized to the larger cap; the smaller rule's
        // record is cut to its own cap and says so.
        let mut small = rule("cap-small");
        small.capture.request_body_max_bytes = 4;
        let large = rule("cap-large");
        let state = state_with(&[small.clone(), large.clone()], b"0123456789", b"");
        let req = request("/checkout", &[("Content-Type", "text/plain")]);
        let small_record = CaptureRecord::build(&small, &state, &access_row(), &req, None);
        assert_eq!(small_record.request.body.as_deref(), Some("0123"));
        assert!(small_record.request.truncated);
        assert_eq!(small_record.request.body_bytes_total, 10);
        let large_record = CaptureRecord::build(&large, &state, &access_row(), &req, None);
        assert_eq!(large_record.request.body.as_deref(), Some("0123456789"));
        assert!(!large_record.request.truncated);
    }

    #[test]
    fn each_body_skipped_value_round_trips() {
        for (skip, wire) in [
            (BodySkip::Streaming, "\"streaming\""),
            (BodySkip::Budget, "\"budget\""),
            (BodySkip::Disabled, "\"disabled\""),
        ] {
            assert_eq!(
                serde_json::to_string(&skip).expect("an enum serialises"),
                wire
            );
        }
        assert_eq!(
            serde_json::to_string(&Option::<BodySkip>::None).expect("None serialises"),
            "null"
        );
        assert_eq!(BodySkip::from(CaptureSkip::Streaming), BodySkip::Streaming);
        assert_eq!(BodySkip::from(CaptureSkip::Budget), BodySkip::Budget);
    }

    #[test]
    fn a_direction_the_rule_turned_off_is_disabled_with_no_body() {
        let mut rule = rule("cap-1");
        rule.capture.response_body = false;
        let state = state_with(
            std::slice::from_ref(&rule),
            b"{}",
            b"a response nobody asked for",
        );
        let record = CaptureRecord::build(
            &rule,
            &state,
            &access_row(),
            &request("/checkout", &[json_text()]),
            Some(&response(503, &[])),
        );
        assert_eq!(record.response.body, None);
        assert_eq!(record.response.body_encoding, None);
        assert_eq!(record.response.body_skipped, Some(BodySkip::Disabled));
        assert_eq!(record.response.body_bytes_total, 27);
        assert!(!record.response.truncated);
    }

    #[test]
    fn a_streaming_response_is_recorded_as_skipped_not_empty() {
        let rule = rule("cap-1");
        let mut state = state_with(std::slice::from_ref(&rule), b"{}", b"event: hello\n");
        state.skip_response(CaptureSkip::Streaming);
        let record = CaptureRecord::build(
            &rule,
            &state,
            &access_row(),
            &request("/checkout", &[json_text()]),
            Some(&response(200, &[("Content-Type", "text/event-stream")])),
        );
        assert_eq!(record.response.body, None);
        assert_eq!(record.response.body_skipped, Some(BodySkip::Streaming));
        assert_eq!(record.response.body_bytes_total, 13);
    }

    #[test]
    fn the_always_redacted_headers_are_redacted_by_a_rule_that_names_nothing() {
        let rule = rule("cap-1");
        assert!(rule.redact.headers.is_empty());
        let state = state_with(std::slice::from_ref(&rule), b"", b"");
        let record = CaptureRecord::build(
            &rule,
            &state,
            &access_row(),
            &request(
                "/checkout",
                &[
                    ("Authorization", "Bearer abc"),
                    ("Proxy-Authorization", "Basic xyz"),
                    ("Cookie", "session=1"),
                    ("Accept", "*/*"),
                ],
            ),
            Some(&response(503, &[("Set-Cookie", "session=2; HttpOnly")])),
        );
        assert_eq!(
            header_value(&record.request.headers, "authorization"),
            vec!["<redacted:10 bytes>"]
        );
        assert_eq!(
            header_value(&record.request.headers, "proxy-authorization"),
            vec!["<redacted:9 bytes>"]
        );
        assert_eq!(
            header_value(&record.request.headers, "cookie"),
            vec!["<redacted:9 bytes>"]
        );
        assert_eq!(header_value(&record.request.headers, "accept"), vec!["*/*"]);
        assert_eq!(
            header_value(&record.response.headers, "set-cookie"),
            vec!["<redacted:19 bytes>"]
        );
    }

    #[test]
    fn a_rule_naming_x_api_key_redacts_it_and_authorization_stays_redacted() {
        let mut rule = rule("cap-1");
        rule.redact.headers = vec!["X-Api-Key".to_string()];
        let state = state_with(std::slice::from_ref(&rule), b"", b"");
        let record = CaptureRecord::build(
            &rule,
            &state,
            &access_row(),
            &request(
                "/checkout",
                &[("x-api-key", "k-123"), ("Authorization", "Bearer abc")],
            ),
            None,
        );
        assert_eq!(
            header_value(&record.request.headers, "x-api-key"),
            vec!["<redacted:5 bytes>"]
        );
        assert_eq!(
            header_value(&record.request.headers, "authorization"),
            vec!["<redacted:10 bytes>"]
        );
    }

    #[test]
    fn a_rule_naming_authorization_does_not_un_redact_it() {
        let mut rule = rule("cap-1");
        rule.redact.headers = vec!["Authorization".to_string()];
        let state = state_with(std::slice::from_ref(&rule), b"", b"");
        let record = CaptureRecord::build(
            &rule,
            &state,
            &access_row(),
            &request("/checkout", &[("Authorization", "Bearer abc")]),
            None,
        );
        assert_eq!(
            header_value(&record.request.headers, "authorization"),
            vec!["<redacted:10 bytes>"]
        );
    }

    #[test]
    fn the_redaction_marker_carries_the_byte_length_of_the_removed_value() {
        let rule = rule("cap-1");
        let state = state_with(std::slice::from_ref(&rule), b"", b"");
        let record = CaptureRecord::build(
            &rule,
            &state,
            &access_row(),
            &request("/checkout", &[("Cookie", "")]),
            Some(&response(503, &[("Set-Cookie", "a=b")])),
        );
        assert_eq!(
            header_value(&record.request.headers, "cookie"),
            vec!["<redacted:0 bytes>"]
        );
        assert_eq!(
            header_value(&record.response.headers, "set-cookie"),
            vec!["<redacted:3 bytes>"]
        );
    }

    #[test]
    fn the_uri_has_its_named_query_parameters_masked() {
        let mut rule = rule("cap-1");
        rule.redact.query = vec!["token".to_string()];
        let state = state_with(std::slice::from_ref(&rule), b"", b"");
        let record = CaptureRecord::build(
            &rule,
            &state,
            &access_row(),
            &request("/checkout?token=abc&q=%2Fx&token=", &[]),
            None,
        );
        assert_eq!(
            record.request.uri,
            "/checkout?token=<redacted:3 bytes>&q=%2Fx&token=<redacted:0 bytes>"
        );
    }

    #[test]
    fn two_records_of_the_same_exchange_serialise_byte_identically() {
        let rule = rule("cap-1");
        let state = state_with(std::slice::from_ref(&rule), b"{\"a\":1}", b"{\"b\":2}");
        let req = request("/checkout?x=1", &[json_text(), ("X-Trace", "t")]);
        let resp = response(503, &[json_text(), ("X-Trace", "u")]);
        let first = CaptureRecord::build(&rule, &state, &access_row(), &req, Some(&resp));
        let second = CaptureRecord::build(&rule, &state, &access_row(), &req, Some(&resp));
        let first_json = serde_json::to_vec(&first).expect("a record serialises");
        let second_json = serde_json::to_vec(&second).expect("a record serialises");
        assert_eq!(first_json, second_json);
        let text = String::from_utf8(first_json).expect("JSON is UTF-8");
        assert!(
            text.starts_with("{\"kind\":\"capture\",\"rule_id\":\"cap-1\",\"rule_name\":"),
            "field order is fixed: {text}"
        );
        assert!(text
            .contains("\"headers\":[[\"Content-Type\",\"application/json\"],[\"X-Trace\",\"t\"]]"));
    }

    #[test]
    fn the_record_joins_the_access_log_row_and_agrees_with_it() {
        let rule = rule("cap-1");
        let state = state_with(std::slice::from_ref(&rule), b"", b"");
        let access = access_row();
        let record = CaptureRecord::build(
            &rule,
            &state,
            &access,
            &request("/checkout", &[]),
            Some(&response(503, &[])),
        );
        assert_eq!(record.kind, "capture");
        assert_eq!(record.request_id, access.request_id);
        assert_eq!(record.timestamp, access.timestamp);
        assert_eq!(record.client_ip, access.client_ip);
        assert_eq!(record.is_xff, access.is_xff);
        assert_eq!(record.backend, access.backend);
        assert_eq!(record.latency_ms, access.latency_ms);
        assert_eq!(record.error, access.error);
        assert_eq!(record.response.status, access.status);
        assert_eq!(record.route_id, "route-1");
        assert_eq!(record.request.method, "POST");
        assert_eq!(record.request.version, "HTTP/1.1");
    }

    #[test]
    fn no_response_written_yields_the_rows_status_and_no_headers() {
        let rule = rule("cap-1");
        let state = state_with(std::slice::from_ref(&rule), b"", b"");
        let mut access = access_row();
        access.status = 0;
        let record = CaptureRecord::build(&rule, &state, &access, &request("/checkout", &[]), None);
        assert_eq!(record.response.status, 0);
        assert!(record.response.headers.is_empty());
        assert_eq!(record.response.body.as_deref(), Some(""));
        assert_eq!(record.response.body_encoding, Some(BodyEncoding::Base64));
    }
}
