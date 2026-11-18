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

//! The stream SLA routes of the management API (Story 12.9 D-g): the
//! windows, the buckets, the target, the export and the clear, their
//! role floors and their audit rows.

use std::sync::Arc;

use axum::http::StatusCode;
use chrono::{Duration, Utc};
use lorica_config::models::{
    Role, Stream, StreamProtocol, StreamSlaBucket, StreamSlaConfig, StreamSlaSummary,
};
use serde_json::{json, Value};

use crate::middleware::auth::SessionStore;
use crate::middleware::rate_limit::RateLimiter;
use crate::server::AppState;
use crate::tests::{body_json, create_user_and_login, send, setup_admin_and_login, test_state};

/// A logged-in admin on an in-memory node holding one TCP stream, with a
/// real audit log and a stream SLA collector.
struct Node {
    state: AppState,
    sessions: SessionStore,
    limiter: RateLimiter,
    admin: String,
    stream_id: String,
    _data_dir: tempfile::TempDir,
}

impl Node {
    async fn with_a_stream() -> Self {
        let data_dir = tempfile::tempdir().expect("test setup: tempdir");
        let (mut state, sessions, limiter) = test_state().await;
        state.log_store = Some(Arc::new(
            crate::log_store::LogStore::open(data_dir.path()).expect("test setup: log store"),
        ));
        state.stream_sla_collector = Some(Arc::new(lorica_bench::StreamSlaCollector::new()));
        let admin = setup_admin_and_login(&state, &sessions, &limiter).await;
        let stream = Stream::new(
            uuid::Uuid::new_v4().to_string(),
            "pg".to_string(),
            StreamProtocol::Tcp,
            "0.0.0.0".parse().expect("an address"),
            15432,
            15432,
            Utc::now(),
        );
        state
            .store
            .lock()
            .await
            .create_stream(&stream)
            .expect("test setup: stream");
        Self {
            state,
            sessions,
            limiter,
            admin,
            stream_id: stream.id,
            _data_dir: data_dir,
        }
    }

    async fn call_as(
        &self,
        cookie: &str,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let response = send(
            &self.state,
            &self.sessions,
            &self.limiter,
            method,
            uri,
            cookie,
            body,
        )
        .await;
        let status = response.status();
        (status, body_json(response).await)
    }

    async fn call(&self, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
        self.call_as(&self.admin, method, uri, body).await
    }

    /// One passive minute of this node's stream, `minutes_ago` old:
    /// ten judged connections, nine of them connected within the bound.
    async fn seed_bucket(&self, minutes_ago: i64) {
        let config = StreamSlaConfig::default_for_stream(&self.stream_id);
        let mut bucket = StreamSlaBucket::empty(
            &config,
            Utc::now() - Duration::minutes(minutes_ago),
            "passive",
        );
        bucket.judged_count = 10;
        bucket.success_count = 9;
        bucket.failure_count = 1;
        bucket.connected_count = 9;
        bucket.connect_latency_sum_ms = Some(900);
        bucket.connect_latency_min_ms = Some(20);
        bucket.connect_latency_max_ms = Some(300);
        bucket.connect_latency_p50_ms = Some(80);
        bucket.connect_latency_p95_ms = Some(250);
        bucket.connect_latency_p99_ms = Some(300);
        self.state
            .store
            .lock()
            .await
            .merge_stream_sla_bucket(&bucket)
            .expect("test setup: bucket");
    }

    async fn sla_audit_rows(&self) -> Vec<crate::audit::AuditRecord> {
        let log_store = self.state.log_store.clone().expect("log store");
        log_store.flush_audit().await.expect("the audit drains");
        let (mut rows, _) = log_store
            .query_audit(&crate::audit::AuditQuery {
                operator: None,
                action_prefix: Some("sla.".to_string()),
                from: None,
                to: None,
                limit: 100,
                before_id: None,
                node_id: None,
            })
            .expect("audit query");
        rows.reverse();
        rows
    }
}

#[tokio::test]
async fn a_stream_answers_its_windows_and_its_buckets() {
    let node = Node::with_a_stream().await;
    node.seed_bucket(10).await;
    let id = &node.stream_id;

    let (status, json) = node
        .call("GET", &format!("/api/v1/sla/streams/{id}"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let windows: Vec<StreamSlaSummary> =
        serde_json::from_value(json["data"].clone()).expect("stream summaries");
    let labels: Vec<&str> = windows.iter().map(|w| w.window.as_str()).collect();
    let expected: Vec<&str> = lorica_bench::results::SlaWindow::ALL
        .iter()
        .map(lorica_bench::results::SlaWindow::label)
        .collect();
    assert_eq!(labels, expected);
    for window in &windows {
        assert_eq!(&window.stream_id, id);
        assert_eq!(window.judged_count, 10, "{}", window.window);
        assert_eq!(window.success_count, 9, "{}", window.window);
        assert_eq!(
            window.avg_connect_latency_ms,
            Some(100.0),
            "{}",
            window.window
        );
    }

    let (status, json) = node
        .call("GET", &format!("/api/v1/sla/streams/{id}/buckets"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let buckets = json["data"].as_array().expect("buckets");
    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0]["connect_latency_p99_ms"], 300);

    // `Z`, not `+00:00`: a bare `+` in a query string decodes as a space.
    let to = (Utc::now() - Duration::hours(2)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let (_, json) = node
        .call(
            "GET",
            &format!("/api/v1/sla/streams/{id}/buckets?to={to}"),
            None,
        )
        .await;
    assert_eq!(json["data"].as_array().expect("buckets").len(), 0);
}

#[tokio::test]
async fn every_stream_sla_path_answers_404_for_a_stream_this_node_does_not_hold() {
    let node = Node::with_a_stream().await;
    let unknown = "/api/v1/sla/streams/no-such-stream";
    for (method, path, body) in [
        ("GET", unknown.to_string(), None),
        ("GET", format!("{unknown}/buckets"), None),
        ("GET", format!("{unknown}/config"), None),
        ("GET", format!("{unknown}/export"), None),
        ("GET", format!("{unknown}/export?format=csv"), None),
        (
            "PUT",
            format!("{unknown}/config"),
            Some(json!({ "target_pct": 90.0 })),
        ),
        ("DELETE", format!("{unknown}/data"), None),
    ] {
        let (status, json) = node.call(method, &path, body).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {json}");
    }
}

#[tokio::test]
async fn a_stream_target_round_trips_refuses_what_it_cannot_store_and_is_audited() {
    let node = Node::with_a_stream().await;
    let path = format!("/api/v1/sla/streams/{}/config", node.stream_id);

    let (status, json) = node.call("GET", &path, None).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["data"]["stream_id"], node.stream_id);
    assert_eq!(
        json["data"]["target_pct"],
        StreamSlaConfig::DEFAULT_TARGET_PCT
    );
    assert_eq!(
        json["data"]["max_connect_latency_ms"],
        StreamSlaConfig::DEFAULT_MAX_CONNECT_LATENCY_MS
    );

    for bad in [
        json!({ "target_pct": 150.0 }),
        json!({ "target_pct": -1.0 }),
        json!({ "max_connect_latency_ms": 0 }),
    ] {
        let (status, json) = node.call("PUT", &path, Some(bad.clone())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {json}");
    }
    // A route's field is not a stream's: refused, never read as accepted.
    let (status, json) = node
        .call("PUT", &path, Some(json!({ "success_status_min": 200 })))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{json}");

    let (status, json) = node
        .call(
            "PUT",
            &path,
            Some(json!({ "target_pct": 95.5, "max_connect_latency_ms": 800 })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let (_, json) = node.call("GET", &path, None).await;
    assert_eq!(json["data"]["target_pct"], 95.5);
    assert_eq!(json["data"]["max_connect_latency_ms"], 800);

    // Only the fields sent change.
    let (status, json) = node
        .call("PUT", &path, Some(json!({ "target_pct": 99.0 })))
        .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["data"]["max_connect_latency_ms"], 800);

    let rows = node.sla_audit_rows().await;
    let shape: Vec<(&str, &str, &str)> = rows
        .iter()
        .map(|r| {
            (
                r.action.as_str(),
                r.target_type.as_str(),
                r.target_id.as_str(),
            )
        })
        .collect();
    assert_eq!(
        shape,
        vec![
            ("sla.config_update", "stream", node.stream_id.as_str()),
            ("sla.config_update", "stream", node.stream_id.as_str()),
        ]
    );
}

#[tokio::test]
async fn a_stream_export_serves_json_and_csv_and_the_clear_empties_it() {
    let node = Node::with_a_stream().await;
    node.seed_bucket(10).await;
    let id = &node.stream_id;

    let (status, json) = node
        .call("GET", &format!("/api/v1/sla/streams/{id}/export"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["data"]["stream_id"], id.as_str());
    assert_eq!(json["data"]["config"]["stream_id"], id.as_str());
    assert_eq!(
        json["data"]["buckets"].as_array().expect("buckets").len(),
        1
    );

    let response = send(
        &node.state,
        &node.sessions,
        &node.limiter,
        "GET",
        &format!("/api/v1/sla/streams/{id}/export?format=csv"),
        &node.admin,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"].to_str().expect("header"),
        "text/csv"
    );
    assert!(response.headers()["content-disposition"]
        .to_str()
        .expect("header")
        .contains(&format!("sla-stream-{id}.csv")));
    let csv = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body");
    let csv = String::from_utf8(csv.to_vec()).expect("utf-8");
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines.len(), 2, "{csv}");
    assert!(lines[0].starts_with("bucket_start,judged_count,success_count,failure_count"));
    assert!(
        lines[1].ends_with(",10,9,1,9,900,20,300,80,250,300"),
        "{csv}"
    );

    let (status, json) = node
        .call("DELETE", &format!("/api/v1/sla/streams/{id}/data"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["data"]["deleted_buckets"], 1);
    let (_, json) = node
        .call("GET", &format!("/api/v1/sla/streams/{id}/buckets"), None)
        .await;
    assert_eq!(json["data"].as_array().expect("buckets").len(), 0);

    let rows = node.sla_audit_rows().await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "sla.data_clear");
    assert_eq!(rows[0].target_type, "stream");
    assert_eq!(&rows[0].target_id, id);
}

#[test]
fn a_udp_bucket_exports_its_missing_latencies_as_empty_cells() {
    // Nothing connects on UDP: an absent sample must not read as 0 ms.
    let config = StreamSlaConfig::default_for_stream("s-udp");
    let mut bucket = StreamSlaBucket::empty(&config, Utc::now(), "passive");
    bucket.judged_count = 4;
    bucket.success_count = 4;
    let csv = super::stream_buckets_csv(&[bucket]);
    let row = csv.lines().nth(1).expect("one bucket line");
    assert!(row.ends_with(",4,4,0,0,,,,,,"), "{row}");
}

#[tokio::test]
async fn a_viewer_reads_a_stream_sla_and_changes_nothing() {
    // The route SLA floors, unchanged: reads are Viewer, writes Operator.
    let node = Node::with_a_stream().await;
    let viewer = create_user_and_login(
        &node.state,
        &node.sessions,
        &node.limiter,
        "viewer01",
        Role::Viewer,
    )
    .await;
    let id = &node.stream_id;
    for path in [
        "/api/v1/sla/streams".to_string(),
        format!("/api/v1/sla/streams/{id}"),
        format!("/api/v1/sla/streams/{id}/buckets"),
        format!("/api/v1/sla/streams/{id}/config"),
        format!("/api/v1/sla/streams/{id}/export"),
    ] {
        let (status, json) = node.call_as(&viewer, "GET", &path, None).await;
        assert_eq!(status, StatusCode::OK, "{path}: {json}");
    }
    for (method, path, body) in [
        (
            "PUT",
            format!("/api/v1/sla/streams/{id}/config"),
            Some(json!({ "target_pct": 90.0 })),
        ),
        ("DELETE", format!("/api/v1/sla/streams/{id}/data"), None),
    ] {
        let (status, json) = node.call_as(&viewer, method, &path, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {json}");
    }
}

/// A stored TCP stream named `name` on `port`; its id.
async fn another_stream(node: &Node, name: &str, port: u16) -> String {
    let stream = Stream::new(
        uuid::Uuid::new_v4().to_string(),
        name.to_string(),
        StreamProtocol::Tcp,
        "0.0.0.0".parse().expect("an address"),
        port,
        port,
        Utc::now(),
    );
    node.state
        .store
        .lock()
        .await
        .create_stream(&stream)
        .expect("test setup: stream");
    stream.id
}

#[tokio::test]
async fn the_stream_overview_lists_every_held_stream_with_a_target_or_data_and_no_other() {
    // Story 12.9 Lot C3, the maintainer's decision: a read of its own
    // beside the route overview, the overview's windows per stream.
    let node = Node::with_a_stream().await;
    let (status, json) = node.call("GET", "/api/v1/sla/streams", None).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["data"], json!([]), "no target and no data: no row");

    node.seed_bucket(10).await;
    let targeted = another_stream(&node, "targeted", 15433).await;
    let quiet = another_stream(&node, "quiet", 15434).await;
    let gone = another_stream(&node, "gone", 15435).await;
    {
        let store = node.state.store.lock().await;
        store
            .upsert_stream_sla_config(&StreamSlaConfig::default_for_stream(&targeted))
            .expect("test setup: a target and no data");
        let mut bucket = StreamSlaBucket::empty(
            &StreamSlaConfig::default_for_stream(&gone),
            Utc::now() - Duration::minutes(5),
            "passive",
        );
        bucket.judged_count = 1;
        bucket.success_count = 1;
        store
            .merge_stream_sla_bucket(&bucket)
            .expect("test setup: bucket");
        store
            .delete_stream(&gone)
            .expect("test setup: the stream goes, its bucket stays");
    }

    let (status, json) = node.call("GET", "/api/v1/sla/streams", None).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let rows: Vec<StreamSlaSummary> =
        serde_json::from_value(json["data"].clone()).expect("stream summaries");
    let listed: Vec<String> = node
        .state
        .store
        .lock()
        .await
        .list_streams()
        .expect("streams")
        .into_iter()
        .map(|stream| stream.id)
        .filter(|id| *id == node.stream_id || *id == targeted)
        .collect();
    let windows: Vec<&str> = super::STREAM_OVERVIEW_WINDOWS
        .iter()
        .map(lorica_bench::results::SlaWindow::label)
        .collect();
    let expected: Vec<(String, &str)> = listed
        .iter()
        .flat_map(|id| windows.iter().map(move |window| (id.clone(), *window)))
        .collect();
    let answered: Vec<(String, &str)> = rows
        .iter()
        .map(|row| (row.stream_id.clone(), row.window.as_str()))
        .collect();
    assert_eq!(answered, expected);
    assert!(!answered.iter().any(|(id, _)| *id == quiet || *id == gone));
    for row in &rows {
        let judged = if row.stream_id == node.stream_id {
            10
        } else {
            0
        };
        assert_eq!(row.judged_count, judged, "{} {}", row.stream_id, row.window);
    }
    assert!(
        json["data"][0].get("stream_name").is_none(),
        "a row names its stream by id only: {json}"
    );
}

#[tokio::test]
async fn a_follower_answers_a_stream_pull_with_what_its_local_reads_serve() {
    use lorica_cluster::messages::SlaPull;

    use crate::sla::{answer_sla_pull, stream_bucket_from_wire, stream_summary_from_wire};

    let node = Node::with_a_stream().await;
    node.seed_bucket(5).await;
    let id = node.stream_id.clone();
    let (_, local_windows) = node
        .call("GET", &format!("/api/v1/sla/streams/{id}"), None)
        .await;
    let (_, local_buckets) = node
        .call("GET", &format!("/api/v1/sla/streams/{id}/buckets"), None)
        .await;
    let (_, local_overview) = node.call("GET", "/api/v1/sla/streams", None).await;
    let stream_pull = |stream_id: &str, buckets: bool| SlaPull {
        source: "passive".to_string(),
        streams: true,
        stream_id: stream_id.to_string(),
        buckets,
        ..SlaPull::default()
    };
    let store = node.state.store.lock().await;

    let windows = answer_sla_pull(&store, &stream_pull(&id, false)).expect("windows");
    assert!(windows.streams, "the answer says it is a stream answer");
    assert!(windows.summaries.is_empty() && windows.buckets.is_empty());
    let windows: Vec<StreamSlaSummary> = windows
        .stream_summaries
        .into_iter()
        .map(stream_summary_from_wire)
        .collect();
    assert_eq!(
        serde_json::to_value(&windows).expect("json"),
        local_windows["data"],
        "the proxied windows are the follower's own read"
    );

    let buckets = answer_sla_pull(&store, &stream_pull(&id, true)).expect("buckets");
    let buckets: Vec<StreamSlaBucket> = buckets
        .stream_buckets
        .into_iter()
        .map(|row| stream_bucket_from_wire(row).expect("an RFC 3339 start"))
        .collect();
    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0].judged_count, 10);
    assert_eq!(buckets[0].connect_latency_p95_ms, Some(250));
    assert_eq!(
        local_buckets["data"].as_array().map(Vec::len),
        Some(1),
        "the local read holds the same minute"
    );

    let overview = answer_sla_pull(&store, &stream_pull("", false)).expect("overview");
    let overview: Vec<StreamSlaSummary> = overview
        .stream_summaries
        .into_iter()
        .map(stream_summary_from_wire)
        .collect();
    assert_eq!(
        serde_json::to_value(&overview).expect("json"),
        local_overview["data"]
    );

    let unknown = answer_sla_pull(&store, &stream_pull("no-such-stream", false));
    assert!(
        unknown.is_err(),
        "a stream this node does not hold is refused"
    );
}

#[test]
fn a_stream_bucket_crosses_the_wire_whole() {
    use crate::sla::{stream_bucket_from_wire, stream_bucket_to_wire};

    let config = StreamSlaConfig::default_for_stream("stream-1");
    let mut bucket = StreamSlaBucket::empty(&config, Utc::now(), "passive");
    bucket.judged_count = 3;
    bucket.connected_count = 3;
    bucket.connect_latency_p99_ms = Some(42);
    let back = stream_bucket_from_wire(stream_bucket_to_wire(&bucket)).expect("decodes");
    assert_eq!(back, bucket);

    let udp = StreamSlaBucket::empty(&config, Utc::now(), "passive");
    let back = stream_bucket_from_wire(stream_bucket_to_wire(&udp)).expect("decodes");
    assert_eq!(back, udp, "no latency stays no latency");
}

#[tokio::test]
async fn the_stream_reads_take_node_as_fleet_reads_do() {
    let node = Node::with_a_stream().await;
    let id = node.stream_id.clone();
    let viewer = create_user_and_login(
        &node.state,
        &node.sessions,
        &node.limiter,
        "viewer01",
        Role::Viewer,
    )
    .await;
    for uri in [
        "/api/v1/sla/streams?node=node-b".to_string(),
        format!("/api/v1/sla/streams/{id}?node=node-b"),
        format!("/api/v1/sla/streams/{id}/buckets?node=node-b"),
    ] {
        let (status, _) = node.call_as(&viewer, "GET", &uri, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "a fleet read: {uri}");
        let (status, _) = node.call("GET", &uri, None).await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "off a control plane a node read is a conflict: {uri}"
        );
    }
    // An empty node is this node, as on the route reads.
    let (status, _) = node
        .call_as(
            &viewer,
            "GET",
            &format!("/api/v1/sla/streams/{id}?node="),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[test]
fn an_answer_without_the_stream_marker_is_refused_not_served_empty() {
    use lorica_cluster::messages::{SlaPullAck, SlaSummaryRow};

    let old_follower = SlaPullAck {
        summaries: vec![SlaSummaryRow::default()],
        ..SlaPullAck::default()
    };
    assert!(matches!(
        crate::sla::stream_answer_of("node-b", old_follower),
        Err(crate::error::ApiError::Conflict(reason)) if reason.contains("node-b")
    ));
    let answered = SlaPullAck {
        streams: true,
        ..SlaPullAck::default()
    };
    assert!(crate::sla::stream_answer_of("node-b", answered).is_ok());
}
