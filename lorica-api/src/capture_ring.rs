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

//! The recent-captures ring (Story 10.2 AC #5): the last
//! [`CAPTURE_RING_CAPACITY`] capture records this process emitted, held
//! in memory so the dashboard can show them and hand one back whole.
//!
//! It lives in this crate rather than beside the capture record because
//! of the dependency direction: the record type is in the `lorica`
//! binary crate, which depends on this one, and the two handlers that
//! read the ring are here. So the ring is fed the way the log-export
//! lanes and the metrics registry are fed, by the proxy calling into a
//! process-global, and it stores what the lanes receive: the record as
//! a JSON document, not as the typed struct.
//!
//! # Process-local, and therefore per worker
//!
//! One ring per process, for the same reason the capture budgets are:
//! it has to outlive every configuration snapshot. Under `--workers`
//! each worker fills its own ring and the supervisor, which serves the
//! management API, emits nothing and holds an empty one. The handlers
//! refuse to serve that empty ring (a 503 naming the sink to read
//! instead), because a ring that is silently empty on a busy node reads
//! as a feature that does not work.
//!
//! # One shape stored, a second derived on demand
//!
//! An entry holds the full JSON text, byte for byte what the sinks
//! received, shared with the log line it was built for. The listing
//! view, whose bodies are cut at [`CAPTURE_RING_LIST_BODY_MAX`], is
//! parsed out of that text the first time someone lists the ring and
//! memoised per entry. Built at push time instead, it made every
//! capture pay a `serde_json::Value` for a dashboard nobody had open;
//! derived on read, a ring nobody lists costs the text and nothing
//! else. The listing view is what keeps `GET /recent` from shipping
//! fifty records of up to two 4 MiB bodies each; the full text is what
//! makes the download the same document the SIEM has.

use std::collections::VecDeque;
use std::sync::{Arc, OnceLock};

use parking_lot::Mutex;
use serde_json::Value;

/// Records the ring keeps. The fiftieth push evicts the oldest.
pub const CAPTURE_RING_CAPACITY: usize = 50;

/// Longest body, in bytes of its JSON string form, the listing view
/// carries whole. Past it the body is cut to this many bytes and marked
/// (`body_elided: true`, `body_elided_total: <bytes>`). 4 KiB shows the
/// start of an error page or a JSON document, which is what a
/// dashboard row is for; the download has the rest.
pub const CAPTURE_RING_LIST_BODY_MAX: usize = 4 * 1024;

/// One record as the ring holds it.
#[derive(Debug, Clone)]
pub struct RecentCapture {
    /// The rule that admitted the exchange.
    pub rule_id: String,
    /// The access-log row's `request_id`; the lookup key.
    pub request_id: String,
    /// The name the directory sink writes the record under, and the
    /// `Content-Disposition` file name of the download. Computed by
    /// the sink so the two agree.
    pub file_name: String,
    /// The record as one JSON document, exactly as emitted. Shared
    /// with the log line the emit path built it for, so keeping a
    /// record costs a refcount rather than a copy.
    pub document: Arc<str>,
    /// The listing view, parsed and elided on the first read of this
    /// entry. Private: [`RecentCapture::listed`] is the way in, and it
    /// is what makes the derivation happen at most once.
    listed: OnceLock<Value>,
}

impl RecentCapture {
    /// The record with its bodies cut at
    /// [`CAPTURE_RING_LIST_BODY_MAX`], derived from
    /// [`document`](Self::document) on the first call and memoised.
    pub fn listed(&self) -> &Value {
        self.listed.get_or_init(|| {
            // The text came out of `serde_json::to_string` on the
            // record, so it parses. The fallback is here because the
            // alternative on a read path is a panic in a handler, and
            // an entry that names itself is more useful than none.
            let mut document: Value = serde_json::from_str(&self.document).unwrap_or_else(|_| {
                serde_json::json!({
                    "rule_id": self.rule_id,
                    "request_id": self.request_id,
                    "unparseable": true,
                })
            });
            elide_bodies(&mut document, CAPTURE_RING_LIST_BODY_MAX);
            document
        })
    }
}

/// A bounded, newest-first ring of [`RecentCapture`].
#[derive(Debug)]
pub struct CaptureRing {
    entries: Mutex<VecDeque<Arc<RecentCapture>>>,
    capacity: usize,
}

/// The ring the proxy fills and the management API reads.
pub fn node_capture_ring() -> &'static CaptureRing {
    static RING: OnceLock<CaptureRing> = OnceLock::new();
    RING.get_or_init(|| CaptureRing::new(CAPTURE_RING_CAPACITY))
}

impl CaptureRing {
    /// A ring holding at most `capacity` records. Tests build their own
    /// so they neither observe nor disturb the process-wide one.
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    /// Keep one record, evicting the oldest when the ring is full.
    ///
    /// `text` is the record serialised, which the caller already holds
    /// for the log line; the ring shares it rather than copying it and
    /// never parses it. Never blocks on anything but this ring's own
    /// mutex, whose critical sections are a push and a pop.
    pub fn remember(&self, rule_id: &str, request_id: &str, file_name: &str, text: Arc<str>) {
        let entry = Arc::new(RecentCapture {
            rule_id: rule_id.to_string(),
            request_id: request_id.to_string(),
            file_name: file_name.to_string(),
            document: text,
            listed: OnceLock::new(),
        });
        let mut entries = self.entries.lock();
        if entries.len() >= self.capacity {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// Every record, newest first, in its listing view.
    ///
    /// The lock guards a handful of `Arc` clones; the parsing and the
    /// eliding happen outside it, once per entry across the ring's
    /// life however many times it is listed.
    pub fn list(&self) -> Vec<Value> {
        let snapshot: Vec<Arc<RecentCapture>> = self.entries.lock().iter().rev().cloned().collect();
        snapshot
            .iter()
            .map(|entry| entry.listed().clone())
            .collect()
    }

    /// The newest record for `request_id`, narrowed to `rule_id` when
    /// given. Two rules admitting one exchange produce two records with
    /// the same `request_id`, which is why the second key exists.
    pub fn get(&self, request_id: &str, rule_id: Option<&str>) -> Option<Arc<RecentCapture>> {
        self.entries
            .lock()
            .iter()
            .rev()
            .find(|entry| {
                entry.request_id == request_id
                    && rule_id.is_none_or(|wanted| entry.rule_id == wanted)
            })
            .cloned()
    }

    /// How many records the ring holds.
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// Whether the ring holds nothing.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Cut `request.body` and `response.body` to at most `max` bytes each,
/// marking the halves that lost something.
///
/// The cut lands on a character boundary, so the listed prefix is
/// still a valid JSON string. A base64 body cut at 4096 bytes (a
/// multiple of four) still decodes as a prefix of the original.
fn elide_bodies(document: &mut Value, max: usize) {
    for half in ["request", "response"] {
        let Some(fields) = document.get_mut(half).and_then(Value::as_object_mut) else {
            continue;
        };
        let total = match fields.get("body") {
            Some(Value::String(body)) => body.len(),
            _ => continue,
        };
        if total <= max {
            fields.insert("body_elided".to_string(), Value::Bool(false));
            continue;
        }
        if let Some(Value::String(body)) = fields.get_mut("body") {
            let mut cut = max;
            while !body.is_char_boundary(cut) {
                cut -= 1;
            }
            body.truncate(cut);
        }
        fields.insert("body_elided".to_string(), Value::Bool(true));
        fields.insert("body_elided_total".to_string(), Value::from(total as u64));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(request_id: &str, rule_id: &str, request_body: &str) -> Value {
        serde_json::json!({
            "kind": "capture",
            "rule_id": rule_id,
            "request_id": request_id,
            "request": { "method": "POST", "body": request_body, "body_encoding": "utf8" },
            "response": { "status": 503, "body": "", "body_encoding": "base64" },
        })
    }

    fn remember(ring: &CaptureRing, request_id: &str, rule_id: &str, request_body: &str) {
        let document = record(request_id, rule_id, request_body);
        let text: Arc<str> =
            Arc::from(serde_json::to_string(&document).expect("a document serialises"));
        ring.remember(
            rule_id,
            request_id,
            &format!("20260101T000000.000000000Z-{request_id}.json"),
            text,
        );
    }

    #[test]
    fn the_ring_keeps_its_capacity_and_lists_newest_first() {
        let ring = CaptureRing::new(3);
        for i in 0..5 {
            remember(&ring, &format!("req-{i}"), "cap-1", "{}");
        }
        assert_eq!(ring.len(), 3);
        let ids: Vec<String> = ring
            .list()
            .iter()
            .map(|v| v["request_id"].as_str().expect("id").to_string())
            .collect();
        assert_eq!(ids, vec!["req-4", "req-3", "req-2"]);
        assert!(ring.get("req-0", None).is_none(), "the oldest was evicted");
        assert!(ring.get("req-4", None).is_some());
    }

    #[test]
    fn a_body_past_the_listing_cap_is_cut_and_marked_and_the_download_is_whole() {
        let ring = CaptureRing::new(2);
        let long = "x".repeat(CAPTURE_RING_LIST_BODY_MAX + 100);
        remember(&ring, "req-long", "cap-1", &long);
        let listed = &ring.list()[0];
        let body = listed["request"]["body"].as_str().expect("body");
        assert_eq!(body.len(), CAPTURE_RING_LIST_BODY_MAX);
        assert_eq!(listed["request"]["body_elided"], true);
        assert_eq!(
            listed["request"]["body_elided_total"],
            (CAPTURE_RING_LIST_BODY_MAX + 100) as u64
        );
        assert_eq!(listed["response"]["body_elided"], false);
        assert!(listed["response"].get("body_elided_total").is_none());

        let full = ring.get("req-long", None).expect("still in the ring");
        let parsed: Value = serde_json::from_str(&full.document).expect("the download is JSON");
        assert_eq!(
            parsed["request"]["body"].as_str().expect("body").len(),
            long.len()
        );
        assert!(parsed["request"].get("body_elided").is_none());
        assert_eq!(full.file_name, "20260101T000000.000000000Z-req-long.json");
    }

    #[test]
    fn the_listing_view_is_derived_from_the_shared_text_and_built_once() {
        let ring = CaptureRing::new(2);
        let document = record("req-lazy", "cap-1", "{}");
        let text: Arc<str> =
            Arc::from(serde_json::to_string(&document).expect("a document serialises"));
        ring.remember("cap-1", "req-lazy", "f.json", Arc::clone(&text));

        let entry = ring
            .get("req-lazy", None)
            .expect("the record is in the ring");
        assert!(
            Arc::ptr_eq(&text, &entry.document),
            "the ring shares the log line's text rather than copying it"
        );
        let first: *const Value = entry.listed();
        assert_eq!(entry.listed()["request_id"], "req-lazy");
        assert!(
            std::ptr::eq(first, entry.listed()),
            "the listing view is memoised, so listing twice parses once"
        );
    }

    #[test]
    fn the_cut_never_splits_a_multibyte_character() {
        // `é` is two bytes; a body of them has no boundary at 4096
        // unless 4096 is even, so put a three-byte character in play.
        let mut body = "a".repeat(CAPTURE_RING_LIST_BODY_MAX - 1);
        body.push('€');
        body.push_str("tail");
        let mut document = record("req", "cap", &body);
        elide_bodies(&mut document, CAPTURE_RING_LIST_BODY_MAX);
        let cut = document["request"]["body"].as_str().expect("body");
        assert_eq!(cut.len(), CAPTURE_RING_LIST_BODY_MAX - 1);
        assert!(cut.chars().all(|c| c == 'a'));
    }

    #[test]
    fn a_skipped_body_is_null_and_left_alone() {
        let mut document = serde_json::json!({
            "request": { "body": null, "body_skipped": "streaming" },
            "response": { "body": "ok" },
        });
        elide_bodies(&mut document, 1);
        assert!(document["request"].get("body_elided").is_none());
        assert_eq!(document["request"]["body"], Value::Null);
        assert_eq!(document["response"]["body_elided"], true);
        assert_eq!(document["response"]["body"], "o");
    }

    #[test]
    fn two_rules_on_one_exchange_are_told_apart_by_rule_id() {
        let ring = CaptureRing::new(4);
        remember(&ring, "req-1", "cap-a", "first");
        remember(&ring, "req-1", "cap-b", "second");
        assert_eq!(
            ring.get("req-1", None).expect("newest").rule_id,
            "cap-b",
            "without a rule the newest wins"
        );
        assert_eq!(
            ring.get("req-1", Some("cap-a")).expect("a").rule_id,
            "cap-a"
        );
        assert!(ring.get("req-1", Some("cap-c")).is_none());
    }
}
