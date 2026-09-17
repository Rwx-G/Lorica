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

//! Per-request capture buffers: the bytes a matched rule keeps while
//! the exchange is still in flight.
//!
//! The state machine lives here rather than in the proxy hooks so it
//! can be exercised without a running proxy. The hooks own three calls
//! and nothing else: build the state once at `request_filter`, push the
//! chunks they already hold, and let the state drop at `logging`.
//!
//! Two invariants this file exists to keep:
//!
//! - **The request is never altered.** Every push takes the chunk by
//!   reference and copies at most what it keeps. A body being captured
//!   reaches the upstream byte for byte, and one that overflows its cap
//!   keeps the prefix and lets the rest through untouched, the same
//!   stance `mirror_rewrite` takes on an oversize response.
//! - **Nothing is held past the request.** Bytes are reserved from the
//!   node-wide [`CaptureBudget`] as they are kept and returned by the
//!   reservation's `Drop`, so no code path can leak them.

use std::sync::Arc;

use super::node_ceiling::{CaptureBudget, CaptureReservation};
use super::rules::{CompiledCaptureRule, CompiledCaptureRules};

/// Why a direction holds no bytes although a rule asked for it.
///
/// Recorded rather than left as an empty body so a later record can say
/// which of the two happened: an empty body and a body nobody was
/// allowed to read are different facts about the exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureSkip {
    /// The content type is stream-by-design (SSE, multipart push,
    /// gRPC). Buffering it would hold the client's bytes until the
    /// stream ends, which for these types is "never".
    Streaming,
    /// The node-wide in-flight ceiling was reached.
    Budget,
}

/// One direction of a captured exchange.
#[derive(Debug)]
pub enum CaptureBody {
    /// No candidate rule asked for this direction.
    Off,
    /// Bytes kept so far, and the cap they stop at.
    Buffered {
        /// The bytes kept, never more than `cap`.
        bytes: Vec<u8>,
        /// Ceiling for this direction, the largest among the candidate
        /// rules that asked for it.
        cap: usize,
        /// Whether at least one byte was dropped at `cap`.
        truncated: bool,
    },
    /// A rule asked for this direction but nothing was kept.
    Skipped(CaptureSkip),
}

impl CaptureBody {
    fn new(cap: Option<usize>) -> Self {
        match cap {
            Some(cap) => Self::Buffered {
                bytes: Vec::new(),
                cap,
                truncated: false,
            },
            None => Self::Off,
        }
    }

    /// The bytes kept, or `None` when this direction is off or skipped.
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Buffered { bytes, .. } => Some(bytes.as_slice()),
            Self::Off | Self::Skipped(_) => None,
        }
    }

    /// How many bytes are kept. Zero for an off or skipped direction.
    pub fn len(&self) -> usize {
        self.bytes().map_or(0, <[u8]>::len)
    }

    /// Whether this direction holds no bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the body was cut at its cap.
    pub fn truncated(&self) -> bool {
        matches!(
            self,
            Self::Buffered {
                truncated: true,
                ..
            }
        )
    }

    /// Why nothing was kept, when a rule asked for this direction.
    pub fn skip(&self) -> Option<CaptureSkip> {
        match self {
            Self::Skipped(reason) => Some(*reason),
            Self::Off | Self::Buffered { .. } => None,
        }
    }

    /// Keep as much of `chunk` as the cap and the budget allow.
    fn push(&mut self, chunk: &[u8], reservation: &mut CaptureReservation) {
        let Self::Buffered {
            bytes,
            cap,
            truncated,
        } = self
        else {
            return;
        };
        let room = cap.saturating_sub(bytes.len());
        if room == 0 {
            *truncated = true;
            return;
        }
        let keep = chunk.len().min(room);
        if !reservation.grow(keep) {
            // Over the node ceiling. Give back what this direction
            // already holds instead of freezing a partial body: the
            // point of the ceiling is to relieve memory pressure, and a
            // prefix nobody can complete is worth less than the bytes
            // it costs.
            let held = bytes.len();
            reservation.shrink(held);
            *self = Self::Skipped(CaptureSkip::Budget);
            return;
        }
        // Plain amortised growth, no manual reserve. Reserving `cap` on
        // the first chunk removed the repeated copying but made a rule
        // at the 4 MiB ceiling allocate 4 MiB per direction per
        // in-flight capture for a ten-byte body, and the node ceiling
        // counts bytes HELD rather than capacity, so that memory was
        // unaccounted. `Vec`'s doubling keeps capacity within 2x the
        // bytes held, which the ceiling therefore bounds to within a
        // factor of two, and the copying is amortised to O(n).
        bytes.extend_from_slice(&chunk[..keep]);
        if keep < chunk.len() {
            *truncated = true;
        }
    }

    /// Drop this direction with a reason, returning its bytes.
    fn skip_with(&mut self, reason: CaptureSkip, reservation: &mut CaptureReservation) {
        if let Self::Off = self {
            return;
        }
        reservation.shrink(self.len());
        *self = Self::Skipped(reason);
    }
}

/// Everything one request holds for capture.
///
/// Built only for a request at least one rule considers, so a request
/// on a route with no capture rule never allocates this and pays a
/// single `Option` check per hook.
#[derive(Debug)]
pub struct CaptureState {
    /// Ids of the rules that considered this request, in the order
    /// `candidates_for_request` returned them. Kept as ids rather than
    /// borrowed rules because the configuration snapshot they came from
    /// can be swapped while the request is in flight.
    pub rule_ids: Vec<String>,
    /// The route the request was admitted on.
    ///
    /// Recorded here because the proxy's own `route_id` is set in
    /// `upstream_peer`, which a refused request never reaches: every
    /// early return from `request_filter` (a WAF block, a rate limit, a
    /// 403 from an IP list, a redirect) would otherwise arrive at
    /// `logging` with no route to look rules up by, and the exchange the
    /// operator most wanted would be the one nothing recorded.
    route_id: String,
    /// The compiled set the admission was taken from.
    ///
    /// An `Arc` clone of the snapshot's own set, so `logging` reads the
    /// rules that considered this request rather than whatever a reload
    /// installed while it was in flight. Cheap: one refcount bump per
    /// captured request, and it keeps the generation alive only as long
    /// as the exchange it judged.
    rules: Arc<CompiledCaptureRules>,
    /// The request body, as far as the rules wanted it.
    pub request: CaptureBody,
    /// The response body, as far as the rules wanted it.
    pub response: CaptureBody,
    /// Bytes the request body carried, kept or not. Counted on every
    /// chunk regardless of the direction's state, so a record can say
    /// how large a body was even when it kept a prefix or nothing.
    pub request_received: u64,
    /// Bytes the response body carried, kept or not. Same reason.
    pub response_received: u64,
    /// Bytes this request holds against the node-wide budget. Private
    /// because its release must stay tied to dropping the state.
    reservation: CaptureReservation,
}

impl CaptureState {
    /// Build the state for a request `candidates` considered, or `None`
    /// when no rule did.
    ///
    /// A direction is buffered when at least one candidate asks for it,
    /// up to the LARGEST cap among the ones that do: the buffer is
    /// shared, so anything smaller would silently truncate the record of
    /// the rule with the wider cap, and every rule reading a prefix of
    /// the same bytes is exactly what it asked for.
    ///
    /// `rules` is the snapshot's compiled set and `route_id` the route
    /// that matched; both are kept so the emit side can find the same
    /// rules again without depending on a field a later hook sets.
    pub fn new(
        budget: &Arc<CaptureBudget>,
        rules: &Arc<CompiledCaptureRules>,
        route_id: &str,
        candidates: &[&CompiledCaptureRule],
    ) -> Option<CaptureState> {
        if candidates.is_empty() {
            return None;
        }
        let request_cap = candidates
            .iter()
            .filter(|c| c.rule.capture.request_body)
            .map(|c| c.rule.capture.request_body_max_bytes as usize)
            .max();
        let response_cap = candidates
            .iter()
            .filter(|c| c.rule.capture.response_body)
            .map(|c| c.rule.capture.response_body_max_bytes as usize)
            .max();
        Some(CaptureState {
            rule_ids: candidates.iter().map(|c| c.rule.id.clone()).collect(),
            route_id: route_id.to_string(),
            rules: Arc::clone(rules),
            request: CaptureBody::new(request_cap),
            response: CaptureBody::new(response_cap),
            request_received: 0,
            response_received: 0,
            reservation: budget.reservation(),
        })
    }

    /// Keep what the rules allow of one request-body chunk.
    pub fn push_request(&mut self, chunk: &[u8]) {
        self.request_received += chunk.len() as u64;
        self.request.push(chunk, &mut self.reservation);
    }

    /// Keep what the rules allow of one response-body chunk.
    pub fn push_response(&mut self, chunk: &[u8]) {
        self.response_received += chunk.len() as u64;
        self.response.push(chunk, &mut self.reservation);
    }

    /// Stop buffering the response and record why.
    pub fn skip_response(&mut self, reason: CaptureSkip) {
        self.response.skip_with(reason, &mut self.reservation);
    }

    /// The route this request was admitted on.
    pub fn route_id(&self) -> &str {
        &self.route_id
    }

    /// Every rule on the admitting route, from the snapshot that
    /// admitted the request.
    ///
    /// This is what the emit side measures `emit` against. Reading the
    /// route from here rather than from the proxy context is what lets a
    /// refused request (a WAF block, a 403, a 429) still be recorded:
    /// those never reach the hook that sets the context's route. Reading
    /// the rules from the snapshot kept here rather than from a fresh
    /// `load()` is what keeps a reload mid-request from judging the
    /// exchange against rules that did not admit it.
    pub fn admitted_rules(&self) -> &[CompiledCaptureRule] {
        self.rules.rules_for_route(&self.route_id)
    }

    /// Bytes this request currently holds against the node budget.
    pub fn held_bytes(&self) -> usize {
        self.reservation.held()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{CompiledCaptureRule, CompiledCaptureRules};
    use chrono::{DateTime, Duration, Utc};
    use lorica_config::models::{
        CaptureEmit, CaptureLimits, CaptureMatch, CaptureOutput, CaptureRedaction, CaptureRule,
        CaptureScope, StatusMatch,
    };

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("test setup: a literal RFC 3339 instant parses")
            .with_timezone(&Utc)
    }

    /// A rule matching everything on `route-1`, with both directions on
    /// and the caps the caller names.
    fn rule(id: &str, request_cap: u32, response_cap: u32) -> CaptureRule {
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
                request_body_max_bytes: request_cap,
                response_body_max_bytes: response_cap,
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

    /// The state a request on `route-1` would carry under `rules`,
    /// going through the same candidate gate the proxy uses.
    fn state_for(budget: &Arc<CaptureBudget>, rules: &[CaptureRule]) -> Option<CaptureState> {
        let compiled = Arc::new(CompiledCaptureRules::compile(rules));
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
        CaptureState::new(budget, &compiled, "route-1", &candidates)
    }

    /// Feed a body through the request path the way the proxy hook
    /// does, and report the bytes that reached the upstream.
    ///
    /// The hook holds an `Option<Bytes>` it may rewrite; capture only
    /// ever reads it, and this helper is what proves that.
    fn stream_request(state: &mut CaptureState, chunks: &[&[u8]]) -> Vec<u8> {
        let mut forwarded = Vec::new();
        for chunk in chunks {
            let mut body: Option<bytes::Bytes> = Some(bytes::Bytes::copy_from_slice(chunk));
            if let Some(ref held) = body {
                state.push_request(held);
            }
            let out = body.take().expect("the capture path never takes the body");
            forwarded.extend_from_slice(&out);
        }
        forwarded
    }

    #[test]
    fn a_rule_watching_4xx_emits_on_a_refusal_the_proxy_never_routed() {
        // The proxy's own `route_id` is set in `upstream_peer`, which a
        // request refused inside `request_filter` (a WAF block, a 403
        // from an IP list, a 429) never reaches. The state carries the
        // admitting route itself, so the emit side still finds the rule.
        let budget = CaptureBudget::new(1024 * 1024);
        let mut refusing = rule("cap-4xx", 64, 64);
        refusing.emit.status = vec![StatusMatch::ClientError];
        let state = state_for(&budget, &[refusing]).expect("the rule matches this request");

        assert_eq!(state.route_id(), "route-1");
        let emitting: Vec<&CompiledCaptureRule> = state
            .admitted_rules()
            .iter()
            .filter(|candidate| state.rule_ids.iter().any(|id| id == &candidate.rule.id))
            .filter(|candidate| candidate.should_emit(403, 0, false))
            .collect();
        assert_eq!(emitting.len(), 1, "the 403 is recorded");
        assert_eq!(emitting[0].rule.id, "cap-4xx");
    }

    #[test]
    fn a_reload_mid_request_does_not_change_the_rules_that_admitted_it() {
        let budget = CaptureBudget::new(1024 * 1024);
        let state =
            state_for(&budget, &[rule("cap-1", 64, 64)]).expect("the rule matches this request");
        // A reload installs a snapshot with the rule gone. The state
        // holds the generation that admitted, so the exchange is still
        // judged against the rule that asked for it.
        let after_reload = Arc::new(CompiledCaptureRules::compile(&[]));
        assert!(after_reload.rules_for_route("route-1").is_empty());
        assert_eq!(state.admitted_rules().len(), 1);
        assert_eq!(state.admitted_rules()[0].rule.id, "cap-1");
    }

    #[test]
    fn a_chunked_body_grows_amortised_and_reserves_exactly_the_bytes_kept() {
        // A rule at the 4 MiB ceiling must not allocate 4 MiB for a
        // body of a few hundred bytes: capacity follows the bytes held,
        // within the factor of two `Vec`'s doubling costs, so the node
        // ceiling (which counts bytes held) bounds the real memory too.
        let budget = CaptureBudget::new(1024 * 1024);
        let mut state = state_for(&budget, &[rule("cap-1", 4 * 1024 * 1024, 64)])
            .expect("the rule matches this request");
        for _ in 0..17 {
            state.push_request(&[b'x'; 16]);
        }
        match &state.request {
            CaptureBody::Buffered { bytes, .. } => {
                assert_eq!(bytes.len(), 16 * 17);
                assert!(
                    bytes.capacity() <= 2 * bytes.len(),
                    "capacity {} is more than twice the {} bytes held",
                    bytes.capacity(),
                    bytes.len()
                );
            }
            other => panic!("expected a buffered direction, got {other:?}"),
        }
        assert_eq!(
            state.held_bytes(),
            16 * 17,
            "the reservation is exactly the bytes kept"
        );
        assert_eq!(budget.in_flight(), 16 * 17);
    }

    #[test]
    fn a_route_with_no_capture_rule_builds_no_state() {
        let budget = CaptureBudget::new(1024 * 1024);
        let compiled = CompiledCaptureRules::compile(&[]);
        assert!(!compiled.has_rules_for_route("route-1"));
        assert!(state_for(&budget, &[]).is_none());
        assert_eq!(budget.in_flight(), 0);
    }

    #[test]
    fn a_rule_on_another_route_builds_no_state() {
        let budget = CaptureBudget::new(1024 * 1024);
        let mut other = rule("cap-1", 64, 64);
        other.route_id = "route-2".to_string();
        assert!(state_for(&budget, &[other]).is_none());
        assert_eq!(budget.in_flight(), 0);
    }

    #[test]
    fn a_body_under_the_cap_is_buffered_whole_and_forwarded_unchanged() {
        let budget = CaptureBudget::new(1024 * 1024);
        let mut state =
            state_for(&budget, &[rule("cap-1", 64, 64)]).expect("the rule matches this request");
        let forwarded = stream_request(&mut state, &[b"hello ", b"world"]);
        assert_eq!(forwarded, b"hello world");
        assert_eq!(state.request.bytes(), Some(&b"hello world"[..]));
        assert!(!state.request.truncated());
        assert_eq!(budget.in_flight(), 11);
    }

    #[test]
    fn a_body_over_the_cap_keeps_exactly_the_cap_and_forwards_every_byte() {
        let budget = CaptureBudget::new(1024 * 1024);
        let mut state =
            state_for(&budget, &[rule("cap-1", 8, 64)]).expect("the rule matches this request");
        let forwarded = stream_request(&mut state, &[b"12345", b"67890", b"abcde"]);
        assert_eq!(forwarded, b"1234567890abcde");
        assert_eq!(state.request.bytes(), Some(&b"12345678"[..]));
        assert!(state.request.truncated());
        assert_eq!(budget.in_flight(), 8);
    }

    #[test]
    fn a_body_landing_exactly_on_the_cap_is_not_truncated() {
        let budget = CaptureBudget::new(1024 * 1024);
        let mut state =
            state_for(&budget, &[rule("cap-1", 5, 64)]).expect("the rule matches this request");
        let forwarded = stream_request(&mut state, &[b"12345"]);
        assert_eq!(forwarded, b"12345");
        assert_eq!(state.request.bytes(), Some(&b"12345"[..]));
        assert!(!state.request.truncated());
    }

    #[test]
    fn two_candidate_rules_buffer_to_the_larger_cap() {
        let budget = CaptureBudget::new(1024 * 1024);
        let mut state = state_for(
            &budget,
            &[rule("cap-small", 4, 4), rule("cap-large", 16, 32)],
        )
        .expect("both rules match this request");
        assert_eq!(state.rule_ids.len(), 2);
        stream_request(&mut state, &[b"0123456789"]);
        assert_eq!(state.request.bytes(), Some(&b"0123456789"[..]));
        assert!(!state.request.truncated());
        state.push_response(b"0123456789");
        assert_eq!(state.response.len(), 10);
    }

    #[test]
    fn a_direction_no_rule_asks_for_is_off_and_never_allocates() {
        let budget = CaptureBudget::new(1024 * 1024);
        let mut only_request = rule("cap-1", 64, 64);
        only_request.capture.response_body = false;
        let mut state = state_for(&budget, &[only_request]).expect("the rule matches this request");
        state.push_response(b"a response nobody asked for");
        assert!(matches!(state.response, CaptureBody::Off));
        assert!(state.response.is_empty());
        assert_eq!(budget.in_flight(), 0);
    }

    #[test]
    fn a_streaming_response_is_skipped_rather_than_recorded_empty() {
        let budget = CaptureBudget::new(1024 * 1024);
        let mut state =
            state_for(&budget, &[rule("cap-1", 64, 64)]).expect("the rule matches this request");
        state.push_response(b"event: hello\n");
        assert_eq!(budget.in_flight(), 13);
        state.skip_response(CaptureSkip::Streaming);
        assert_eq!(state.response.skip(), Some(CaptureSkip::Streaming));
        assert_eq!(state.response.bytes(), None);
        // The bytes buffered before the content type was known go back.
        assert_eq!(budget.in_flight(), 0);
        state.push_response(b"event: more\n");
        assert_eq!(state.response.skip(), Some(CaptureSkip::Streaming));
        assert_eq!(budget.in_flight(), 0);
    }

    #[test]
    fn over_the_node_ceiling_nothing_is_buffered_and_the_skip_says_budget() {
        let budget = CaptureBudget::new(16);
        let mut hog = budget.reservation();
        assert!(hog.grow(16));
        let mut state =
            state_for(&budget, &[rule("cap-1", 64, 64)]).expect("the rule matches this request");
        let forwarded = stream_request(&mut state, &[b"12345"]);
        assert_eq!(forwarded, b"12345", "the request is forwarded regardless");
        assert_eq!(state.request.skip(), Some(CaptureSkip::Budget));
        assert_eq!(state.request.bytes(), None);
        assert_eq!(state.held_bytes(), 0);
        assert_eq!(budget.in_flight(), 16, "only the other holder's bytes");
    }

    #[test]
    fn a_request_over_the_ceiling_mid_body_gives_back_its_prefix() {
        let budget = CaptureBudget::new(8);
        let mut state =
            state_for(&budget, &[rule("cap-1", 64, 64)]).expect("the rule matches this request");
        let forwarded = stream_request(&mut state, &[b"1234", b"56789"]);
        assert_eq!(forwarded, b"123456789");
        assert_eq!(state.request.skip(), Some(CaptureSkip::Budget));
        assert_eq!(budget.in_flight(), 0);
    }

    #[test]
    fn the_ceiling_counter_returns_to_its_previous_value_after_each_request() {
        let budget = CaptureBudget::new(1024);
        let mut resident = budget.reservation();
        assert!(resident.grow(100));
        let baseline = budget.in_flight();

        // A request that fits.
        {
            let mut state = state_for(&budget, &[rule("cap-1", 64, 64)])
                .expect("the rule matches this request");
            stream_request(&mut state, &[b"small"]);
            state.push_response(b"also small");
            assert!(budget.in_flight() > baseline);
        }
        assert_eq!(budget.in_flight(), baseline);

        // A request that overflows its cap.
        {
            let mut state =
                state_for(&budget, &[rule("cap-1", 4, 4)]).expect("the rule matches this request");
            stream_request(&mut state, &[b"far more than four bytes"]);
            state.push_response(b"far more than four bytes");
            assert_eq!(budget.in_flight(), baseline + 8);
        }
        assert_eq!(budget.in_flight(), baseline);
    }
}
