//! The stream management API (Story 12.1 Lot 5): CRUD, validation,
//! audit, the role floors, the follower gate and the per-node port
//! conflict check, IV2 included; and its stream plane surfaces (Story
//! 12.2 Lot E3): the bind state on the reads, the fd budget check of
//! the writes and the budget view.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::http::StatusCode;
use chrono::Utc;
use lorica_config::listen_ports::ReservedPorts;
use lorica_config::models::{ClusterNode, NodeStatus, Role};
use serde_json::{json, Value};

use super::{StreamResponse, STREAM_PORT_CONFLICT_CODE, STREAM_WITHHELD_FIELDS};
use crate::server::AppState;
use crate::stream_budget::{StreamPlaneState, STREAM_FD_BUDGET_CODE};
use crate::tests::{
    body_json, create_user_and_login, send, setup_admin_and_login, test_control_plane,
    test_follower_runtime, test_state,
};

/// The ports of the node under test. Distinct from every port an
/// enrolled node of these tests reports, so a refusal names the node it
/// is about and no other.
const THIS_NODE: ReservedPorts = ReservedPorts {
    management: 9443,
    http: 80,
    https: 443,
    cluster: Some(7443),
    enrollment: Some(7444),
    automation: None,
};

/// What `edge-1` reports in its heartbeat (IV2).
const EDGE_1: ReservedPorts = ReservedPorts {
    management: 19443,
    http: 8080,
    https: 8443,
    cluster: None,
    enrollment: Some(9445),
    automation: Some(9600),
};

/// A logged-in admin on an in-memory node with a real audit log.
struct Node {
    state: AppState,
    sessions: crate::middleware::auth::SessionStore,
    limiter: crate::middleware::rate_limit::RateLimiter,
    cookie: String,
    _control_liveness: Option<tokio::sync::watch::Receiver<u32>>,
    _data_dir: tempfile::TempDir,
}

impl Node {
    async fn standalone() -> Self {
        Self::with_cluster(|_| None).await
    }

    async fn control_plane() -> Self {
        Self::with_cluster(|state| {
            let (runtime, liveness) = test_control_plane();
            state.cluster = crate::cluster::ClusterRuntime::ControlPlane(runtime);
            Some(liveness)
        })
        .await
    }

    async fn follower() -> Self {
        Self::with_cluster(|state| {
            state.cluster = crate::cluster::ClusterRuntime::Follower(test_follower_runtime());
            None
        })
        .await
    }

    async fn with_cluster(
        set: impl FnOnce(&mut AppState) -> Option<tokio::sync::watch::Receiver<u32>>,
    ) -> Self {
        let data_dir = tempfile::tempdir().expect("test setup: tempdir");
        let (mut state, sessions, limiter) = test_state().await;
        state.log_store = Some(Arc::new(
            crate::log_store::LogStore::open(data_dir.path()).expect("test setup: log store"),
        ));
        state.reserved_ports = THIS_NODE;
        let liveness = set(&mut state);
        let cookie = setup_admin_and_login(&state, &sessions, &limiter).await;
        Self {
            state,
            sessions,
            limiter,
            cookie,
            _control_liveness: liveness,
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
        self.call_as(&self.cookie, method, uri, body).await
    }

    async fn create(&self, body: Value) -> (StatusCode, Value) {
        self.call("POST", "/api/v1/streams", Some(body)).await
    }

    async fn update(&self, id: &str, body: Value) -> (StatusCode, Value) {
        self.call("PUT", &format!("/api/v1/streams/{id}"), Some(body))
            .await
    }

    /// Create, asserting the 201, and answer the view.
    async fn created(&self, body: Value) -> Value {
        let (status, answer) = self.create(body).await;
        assert_eq!(status, StatusCode::CREATED, "{answer}");
        answer["data"].clone()
    }

    async fn backend(&self, address: &str) -> String {
        let (status, answer) = self
            .call(
                "POST",
                "/api/v1/backends",
                Some(json!({ "address": address, "health_check_enabled": false })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{answer}");
        answer["data"]["id"].as_str().expect("an id").to_string()
    }

    async fn enrol(&self, name: &str, status: NodeStatus, reported: Option<ReservedPorts>) {
        let now = Utc::now();
        let row = ClusterNode {
            node_id: format!("id-{name}"),
            name: name.to_string(),
            cert_fingerprint: format!("fp-{name}"),
            cert_serial: "0a00".to_string(),
            prev_cert_fingerprint: None,
            prev_cert_serial: None,
            address: String::new(),
            version: String::new(),
            schema_version: 0,
            status,
            enrolled_at: now,
            last_seen_at: None,
            applied_config_generation: 0,
            applied_config_hash: String::new(),
            cert_not_after: now + chrono::Duration::days(30),
            revoked_at: None,
            reserved_ports: reported,
        };
        self.state
            .store
            .lock()
            .await
            .create_cluster_node(&row)
            .expect("test setup: node");
    }

    async fn audit_rows(&self) -> Vec<crate::audit::AuditRecord> {
        let log_store = self.state.log_store.clone().expect("log store");
        log_store.flush_audit().await.expect("the audit drains");
        let (mut rows, _) = log_store
            .query_audit(&crate::audit::AuditQuery {
                operator: None,
                action_prefix: Some("stream.".to_string()),
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

/// A body the API accepts on a standalone node with [`THIS_NODE`].
fn tcp(name: &str, port: u16) -> Value {
    json!({
        "name": name,
        "protocol": "tcp",
        "listen_address": "0.0.0.0",
        "port_first": port,
    })
}

/// A stream as a read answers it, less its `bind`, which only the reads
/// carry: what a write answered for the same row.
fn without_bind(read: &Value) -> Value {
    let mut view = read.clone();
    let object = view.as_object_mut().expect("an object");
    assert!(object.contains_key("bind"), "a read carries bind: {read}");
    object.remove("bind");
    view
}

/// The `409` of a port conflict, with its message.
fn port_conflict(status: StatusCode, answer: &Value) -> String {
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(
        answer["error"]["code"], STREAM_PORT_CONFLICT_CODE,
        "{answer}"
    );
    answer["error"]["message"]
        .as_str()
        .expect("a message")
        .to_string()
}

// ---- CRUD, validation, audit ----

#[tokio::test]
async fn a_stream_round_trips_through_every_operation_with_its_audit_rows() {
    let node = Node::standalone().await;
    let backend = node.backend("192.0.2.10:25").await;

    let mut body = tcp("smtp", 2525);
    body["group_name"] = json!(" mail ");
    body["backend_ids"] = json!([backend]);
    let created = node.created(body).await;
    let id = created["id"].as_str().expect("an id").to_string();
    assert!(
        lorica_config::models::is_canonical_stream_id(&id),
        "a minted id is canonical: {id}"
    );
    assert_eq!(created["group_name"], "mail");
    assert_eq!(created["enabled"], true);
    assert_eq!(created["port_last"], 2525, "a single port by default");
    assert_eq!(created["backend_ids"], json!([backend]));

    let (status, read) = node
        .call("GET", &format!("/api/v1/streams/{id}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(without_bind(&read["data"]), created);
    assert_eq!(read["data"]["bind"], Value::Null, "nothing bound it yet");
    let (status, listed) = node.call("GET", "/api/v1/streams", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(without_bind(&listed["data"]["streams"][0]), created);
    assert_eq!(listed["data"]["streams"].as_array().map(Vec::len), Some(1));

    let (status, disabled) = node.update(&id, json!({ "enabled": false })).await;
    assert_eq!(status, StatusCode::OK, "{disabled}");
    assert_eq!(disabled["data"]["enabled"], false);
    assert_eq!(disabled["data"]["backend_ids"], json!([backend]));
    let (status, enabled) = node
        .update(&id, json!({ "enabled": true, "backend_ids": [] }))
        .await;
    assert_eq!(status, StatusCode::OK, "{enabled}");
    assert_eq!(enabled["data"]["enabled"], true);
    assert_eq!(enabled["data"]["backend_ids"], json!([]));

    let (status, deleted) = node
        .call("DELETE", &format!("/api/v1/streams/{id}"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{deleted}");
    for (method, body) in [
        ("GET", None),
        ("PUT", Some(json!({ "enabled": false }))),
        ("DELETE", None),
    ] {
        let (status, answer) = node
            .call(method, &format!("/api/v1/streams/{id}"), body)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method}: {answer}");
    }
    let backend_kept = node
        .state
        .store
        .lock()
        .await
        .get_backend(&backend)
        .expect("read");
    assert!(backend_kept.is_some(), "a stream's backends outlive it");

    // One row per mutation, each with the response views it moved
    // between.
    let hash = |view: &Value| crate::audit::hash_payload(Some(view));
    let rows = node.audit_rows().await;
    let shape: Vec<(&str, &str, String, String)> = rows
        .iter()
        .map(|r| {
            assert_eq!(r.target_type, "stream");
            (
                r.action.as_str(),
                r.target_id.as_str(),
                r.before_payload_hash.clone(),
                r.after_payload_hash.clone(),
            )
        })
        .collect();
    assert_eq!(
        shape,
        vec![
            ("stream.create", id.as_str(), String::new(), hash(&created)),
            (
                "stream.update",
                id.as_str(),
                hash(&created),
                hash(&disabled["data"])
            ),
            (
                "stream.update",
                id.as_str(),
                hash(&disabled["data"]),
                hash(&enabled["data"])
            ),
            (
                "stream.delete",
                id.as_str(),
                hash(&enabled["data"]),
                String::new()
            ),
        ]
    );
}

#[tokio::test]
async fn every_validation_refuses_with_its_status_and_nothing_is_stored() {
    let node = Node::standalone().await;
    let udp_backend = node.backend("192.0.2.20:53").await;
    let route_backend = node.backend("192.0.2.21:53").await;
    let (status, answer) = node
        .call(
            "POST",
            "/api/v1/routes",
            Some(json!({
                "hostname": "app.example.com",
                "path_prefix": "/",
                "load_balancing": "round_robin",
                "backend_ids": [route_backend],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "test setup: route: {answer}");

    let with = |patch: Value| {
        let mut body = tcp("ok", 2000);
        for (key, value) in patch.as_object().expect("an object") {
            body[key] = value.clone();
        }
        body
    };
    for (what, body, expected) in [
        (
            "name alphabet",
            with(json!({ "name": "Not-A-Name" })),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "empty name",
            with(json!({ "name": "" })),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "group alphabet",
            with(json!({ "group_name": "Mail Servers" })),
            StatusCode::BAD_REQUEST,
        ),
        (
            "selector alphabet",
            with(json!({ "node_selector": ["Edge 1"] })),
            StatusCode::BAD_REQUEST,
        ),
        (
            "port zero",
            with(json!({ "port_first": 0 })),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "inverted range",
            with(json!({ "port_first": 3000, "port_last": 2999 })),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "range above the cap",
            with(json!({
                "port_first": 10000,
                "port_last": 10000 + lorica_config::models::STREAM_PORT_RANGE_MAX,
            })),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "IPv4-mapped address",
            with(json!({ "listen_address": "::ffff:192.0.2.10" })),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "a hostname is not an address",
            with(json!({ "listen_address": "listener.example.com" })),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "unknown protocol",
            with(json!({ "protocol": "sctp" })),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "a client-chosen id",
            with(json!({ "id": "00000000-0000-4000-8000-000000000000" })),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "unknown backend",
            with(json!({ "backend_ids": ["no-such-backend"] })),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "UDP backend shared with a route",
            with(json!({ "protocol": "udp", "backend_ids": [route_backend] })),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ] {
        let (status, answer) = node.create(body).await;
        assert_eq!(status, expected, "{what}: {answer}");
    }
    let shared = with(json!({ "name": "dns", "protocol": "udp", "backend_ids": [route_backend] }));
    let (_, answer) = node.create(shared).await;
    assert!(
        answer["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("`dns`")),
        "the attachment refusal names the stream: {answer}"
    );
    assert!(
        node.state
            .store
            .lock()
            .await
            .list_streams()
            .expect("list")
            .is_empty(),
        "no refused create left a row"
    );

    // A taken name is refused by the store, and an update is held to
    // the same rules.
    let first = node
        .created(with(
            json!({ "name": "dns", "protocol": "udp", "backend_ids": [udp_backend] }),
        ))
        .await;
    let (status, answer) = node.create(with(json!({ "name": "dns" }))).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    let id = first["id"].as_str().expect("an id");
    for (what, body, expected) in [
        (
            "name alphabet",
            json!({ "name": "DNS" }),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "unknown backend",
            json!({ "backend_ids": ["no-such-backend"] }),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "UDP backend shared with a route",
            json!({ "backend_ids": [udp_backend, route_backend] }),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "a ported backend on a range",
            json!({ "port_first": 2000, "port_last": 2010 }),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "an id in the body",
            json!({ "id": id }),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ] {
        let (status, answer) = node.update(id, body).await;
        assert_eq!(status, expected, "{what}: {answer}");
    }
    let (_, read) = node
        .call("GET", &format!("/api/v1/streams/{id}"), None)
        .await;
    assert_eq!(
        without_bind(&read["data"]),
        first,
        "no refused update moved the row"
    );
}

#[tokio::test]
async fn the_ports_of_an_update_move_together() {
    let node = Node::standalone().await;
    let created = node.created(tcp("smtp", 2525)).await;
    let id = created["id"].as_str().expect("an id");

    let (_, moved) = node.update(id, json!({ "port_first": 2600 })).await;
    assert_eq!(
        (&moved["data"]["port_first"], &moved["data"]["port_last"]),
        (&json!(2600), &json!(2600)),
        "a single port stays a single port: {moved}"
    );
    let (_, widened) = node.update(id, json!({ "port_last": 2610 })).await;
    assert_eq!(
        (
            &widened["data"]["port_first"],
            &widened["data"]["port_last"]
        ),
        (&json!(2600), &json!(2610)),
        "{widened}"
    );
    let (_, both) = node
        .update(id, json!({ "port_first": 3000, "port_last": 3005 }))
        .await;
    assert_eq!(
        (&both["data"]["port_first"], &both["data"]["port_last"]),
        (&json!(3000), &json!(3005)),
        "{both}"
    );
}

#[tokio::test]
async fn the_view_publishes_every_model_field_but_the_withheld_ones() {
    let node = Node::standalone().await;
    let created = node.created(tcp("smtp", 2525)).await;
    let stored = node
        .state
        .store
        .lock()
        .await
        .get_stream(created["id"].as_str().expect("an id"))
        .expect("read")
        .expect("stored");
    let model: BTreeSet<String> = serde_json::to_value(&stored)
        .expect("the model serialises")
        .as_object()
        .expect("an object")
        .keys()
        .filter(|k| !STREAM_WITHHELD_FIELDS.contains(&k.as_str()))
        // The Story 12.3 engine settings joined the model in its Lot B
        // and are published by its Lot E, which drops this filter.
        .filter(|k| {
            !lorica_config::models::TCP_ENGINE_FIELDS
                .iter()
                .any(|field| field.name == k.as_str())
        })
        .cloned()
        .chain(std::iter::once("backend_ids".to_string()))
        .collect();
    let view: BTreeSet<String> = created
        .as_object()
        .expect("an object")
        .keys()
        .cloned()
        .collect();
    assert_eq!(view, model);
    let typed: StreamResponse = super::stream_to_response(&stored, Vec::new());
    assert_eq!(
        serde_json::to_value(&typed).expect("serialises")["listen_address"],
        "0.0.0.0"
    );
}

// ---- Roles and the follower gate ----

#[tokio::test]
async fn viewers_read_and_operators_write() {
    let node = Node::standalone().await;
    let created = node.created(tcp("smtp", 2525)).await;
    let id = created["id"].as_str().expect("an id");
    let viewer = create_user_and_login(
        &node.state,
        &node.sessions,
        &node.limiter,
        "viewer-streams",
        Role::Viewer,
    )
    .await;
    let operator = create_user_and_login(
        &node.state,
        &node.sessions,
        &node.limiter,
        "operator-streams",
        Role::Operator,
    )
    .await;

    let item = format!("/api/v1/streams/{id}");
    for uri in ["/api/v1/streams", item.as_str()] {
        let (status, answer) = node.call_as(&viewer, "GET", uri, None).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {answer}");
    }
    for (method, uri, body) in [
        ("POST", "/api/v1/streams", Some(tcp("imap", 1143))),
        ("PUT", item.as_str(), Some(json!({ "enabled": false }))),
        ("DELETE", item.as_str(), None),
    ] {
        let (status, answer) = node.call_as(&viewer, method, uri, body.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "viewer {method}: {answer}");
        let (status, answer) = node.call_as(&operator, method, uri, body).await;
        assert!(status.is_success(), "operator {method}: {status} {answer}");
    }
}

#[tokio::test]
async fn a_follower_refuses_every_write_outside_break_glass() {
    let node = Node::follower().await;
    let (status, answer) = node.create(tcp("smtp", 2525)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["error"]["code"], "conflict", "{answer}");
    let (status, answer) = node.call("GET", "/api/v1/streams", None).await;
    assert_eq!(status, StatusCode::OK, "reads stay local: {answer}");
}

// ---- Port conflicts (D-5) ----

#[tokio::test]
async fn iv2_a_stream_on_a_followers_https_or_enrollment_port_names_the_follower() {
    let node = Node::control_plane().await;
    node.enrol("edge-1", NodeStatus::Active, Some(EDGE_1)).await;

    for (port, listener) in [(8443, "https"), (9445, "enrollment")] {
        let mut body = tcp("pinned", port);
        body["node_selector"] = json!(["edge-1"]);
        let (status, answer) = node.create(body).await;
        let message = port_conflict(status, &answer);
        assert!(message.contains("edge-1"), "{message}");
        assert!(message.contains(listener), "{message}");
        assert!(message.contains("`pinned`"), "{message}");
    }
}

#[tokio::test]
async fn a_control_plane_checks_its_own_ports_only_for_the_streams_it_binds() {
    let node = Node::control_plane().await;
    node.enrol("edge-1", NodeStatus::Active, Some(EDGE_1)).await;

    // Fleet-wide: the control plane binds it, on its management port.
    let (status, answer) = node.create(tcp("fleet", THIS_NODE.management)).await;
    let message = port_conflict(status, &answer);
    assert!(message.contains("this node"), "{message}");
    assert!(message.contains("management"), "{message}");

    // Pinned to edge-1, which does not hold that port: the control
    // plane holds the stream to replicate it and does not bind it.
    let mut pinned = tcp("pinned", THIS_NODE.management);
    pinned["node_selector"] = json!(["edge-1"]);
    node.created(pinned).await;
}

#[tokio::test]
async fn a_standalone_node_checks_every_stream_against_its_own_ports() {
    let node = Node::standalone().await;
    for protocol in ["tcp", "udp"] {
        let mut body = tcp("on-management", THIS_NODE.management);
        body["protocol"] = json!(protocol);
        let (status, answer) = node.create(body).await;
        let message = port_conflict(status, &answer);
        assert!(message.contains("this node"), "{message}");
    }
}

#[tokio::test]
async fn streams_conflict_by_protocol_ports_and_address() {
    let node = Node::standalone().await;
    let mut game = tcp("game", 6000);
    game["protocol"] = json!("udp");
    game["port_last"] = json!(6099);
    let game = node.created(game).await;

    let mut overlapping = tcp("overlap", 6050);
    overlapping["protocol"] = json!("udp");
    overlapping["port_last"] = json!(6150);
    let (status, answer) = node.create(overlapping).await;
    let message = port_conflict(status, &answer);
    assert!(message.contains("`game`"), "{message}");
    assert!(message.contains("6000-6099/udp"), "{message}");

    // The same range on the other protocol.
    let mut tcp_range = tcp("tcp-range", 6050);
    tcp_range["port_last"] = json!(6150);
    node.created(tcp_range).await;

    // `[::]` binds dual-stack, so it collides with `0.0.0.0`; a specific
    // IPv6 address binds IPv6 only and does not.
    let mut dual = tcp("dual", 6000);
    dual["protocol"] = json!("udp");
    dual["listen_address"] = json!("::");
    let (status, answer) = node.create(dual).await;
    port_conflict(status, &answer);
    let mut v6 = tcp("v6", 6000);
    v6["protocol"] = json!("udp");
    v6["listen_address"] = json!("2001:db8::1");
    node.created(v6).await;

    // A disabled stream keeps its ports.
    let id = game["id"].as_str().expect("an id");
    let (status, answer) = node.update(id, json!({ "enabled": false })).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let mut again = tcp("again", 6099);
    again["protocol"] = json!("udp");
    let (status, answer) = node.create(again).await;
    let message = port_conflict(status, &answer);
    assert!(message.contains("`game`"), "{message}");

    // An update is checked against the other streams, never itself.
    let (status, answer) = node.update(id, json!({ "port_last": 6100 })).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
}

#[tokio::test]
async fn an_active_node_that_never_reported_refuses_the_stream_by_name() {
    let node = Node::control_plane().await;
    node.enrol("edge-1", NodeStatus::Active, None).await;
    // A revoked node is never checked, reported or not.
    node.enrol("edge-old", NodeStatus::Revoked, None).await;

    let mut body = tcp("pinned", 5432);
    body["node_selector"] = json!(["edge-1"]);
    let (status, answer) = node.create(body).await;
    let message = port_conflict(status, &answer);
    assert!(message.contains("edge-1"), "{message}");
    assert!(message.contains("not reported"), "{message}");

    let mut elsewhere = tcp("elsewhere", 5432);
    elsewhere["node_selector"] = json!(["edge-old"]);
    node.created(elsewhere).await;
}

#[tokio::test]
async fn a_conflict_on_a_follower_is_judged_on_its_own_streams() {
    let node = Node::control_plane().await;
    node.enrol("edge-1", NodeStatus::Active, Some(EDGE_1)).await;
    node.enrol("edge-2", NodeStatus::Active, Some(EDGE_1)).await;

    let mut on_edge_1 = tcp("pg-1", 5432);
    on_edge_1["node_selector"] = json!(["edge-1"]);
    node.created(on_edge_1).await;
    let mut on_edge_2 = tcp("pg-2", 5432);
    on_edge_2["node_selector"] = json!(["edge-2"]);
    node.created(on_edge_2).await;

    // Fleet-wide, it would bind on both: refused, naming the first node
    // and the stream it collides with there.
    let (status, answer) = node.create(tcp("pg-all", 5432)).await;
    let message = port_conflict(status, &answer);
    assert!(
        (message.contains("edge-1") && message.contains("`pg-1`"))
            || (message.contains("edge-2") && message.contains("`pg-2`")),
        "{message}"
    );
}

// ---- Import (D-9) ----

#[tokio::test]
async fn an_import_with_a_stream_on_a_reserved_port_is_refused_before_the_store_is_cleared() {
    let node = Node::standalone().await;
    let kept = node.created(tcp("smtp", 2525)).await;

    let toml_content = {
        let source = lorica_config::ConfigStore::open_in_memory().expect("source");
        source
            .create_stream(&source_stream("on-https", THIS_NODE.https))
            .expect("test setup: stream");
        lorica_config::export::export_to_toml(&source).expect("export")
    };
    let (status, answer) = node
        .call(
            "POST",
            "/api/v1/config/import",
            Some(json!({ "toml_content": toml_content })),
        )
        .await;
    let message = port_conflict(status, &answer);
    assert!(
        message.contains("`on-https`") && message.contains("this node"),
        "{message}"
    );
    let (_, listed) = node.call("GET", "/api/v1/streams", None).await;
    let listed: Vec<Value> = listed["data"]["streams"]
        .as_array()
        .expect("a list")
        .iter()
        .map(without_bind)
        .collect();
    assert_eq!(listed, vec![kept], "nothing was cleared");

    // Two imported streams colliding with each other.
    let toml_content = {
        let source = lorica_config::ConfigStore::open_in_memory().expect("source");
        source
            .create_stream(&source_stream("first", 5000))
            .expect("test setup: stream");
        let mut second = source_stream("second", 5000);
        second.listen_address = "192.0.2.10".parse().expect("an address");
        // Stored past the check the API would run, as an older file
        // could carry it.
        source
            .create_stream(&second)
            .expect("test setup: the store checks no ports");
        lorica_config::export::export_to_toml(&source).expect("export")
    };
    let (status, answer) = node
        .call(
            "POST",
            "/api/v1/config/import",
            Some(json!({ "toml_content": toml_content })),
        )
        .await;
    let message = port_conflict(status, &answer);
    assert!(
        message.contains("`first`") && message.contains("`second`"),
        "{message}"
    );
}

/// The preview runs the import's port check, so a file the import
/// refuses with `409` is never previewed as clean.
#[tokio::test]
async fn an_import_preview_reports_the_port_conflict_the_import_refuses() {
    // The import and its preview share one write budget, so each case
    // runs on a node of its own.
    let fresh_node = || async {
        let node = Node::control_plane().await;
        node.enrol("edge-1", NodeStatus::Active, Some(EDGE_1)).await;
        node
    };
    let export_of = |streams: Vec<lorica_config::models::Stream>| {
        let source = lorica_config::ConfigStore::open_in_memory().expect("source");
        for stream in &streams {
            source.create_stream(stream).expect("test setup: stream");
        }
        lorica_config::export::export_to_toml(&source).expect("export")
    };

    // On this node's management port (the control plane binds a
    // fleet-wide stream), and on a follower's HTTPS port: the preview
    // answers the very refusal the import answers, node named.
    let mut on_edge_1 = source_stream("on-edge-https", EDGE_1.https);
    on_edge_1.node_selector = vec!["edge-1".to_string()];
    for (file, named) in [
        (
            export_of(vec![source_stream("on-management", THIS_NODE.management)]),
            "this node",
        ),
        (export_of(vec![on_edge_1]), "edge-1"),
    ] {
        let node = fresh_node().await;
        let body = json!({ "toml_content": file });
        let (preview_status, preview) = node
            .call("POST", "/api/v1/config/import/preview", Some(body.clone()))
            .await;
        let (import_status, import) = node.call("POST", "/api/v1/config/import", Some(body)).await;
        let previewed = port_conflict(preview_status, &preview);
        assert!(previewed.contains(named), "{previewed}");
        assert_eq!(
            previewed,
            port_conflict(import_status, &import),
            "the preview and the import refuse alike"
        );
    }

    // A clean file previews as a diff, as before.
    let (status, answer) = fresh_node()
        .await
        .call(
            "POST",
            "/api/v1/config/import/preview",
            Some(json!({ "toml_content": export_of(vec![source_stream("smtp", 2525)]) })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(
        answer["data"]["streams"]["added"].as_array().map(Vec::len),
        Some(1),
        "{answer}"
    );
}

/// A fleet-wide TCP stream on `0.0.0.0:port`, as a TOML file would
/// carry it.
fn source_stream(name: &str, port: u16) -> lorica_config::models::Stream {
    let now = Utc::now();
    lorica_config::models::Stream::new(
        uuid::Uuid::new_v4().to_string(),
        name.to_string(),
        lorica_config::models::StreamProtocol::Tcp,
        "0.0.0.0".parse().expect("an address"),
        port,
        port,
        now,
    )
}

// ---- The stream plane surfaces (Story 12.2 Lot E3) ----

/// The `422` of a write a node's fd budget cannot hold, with its
/// message.
fn budget_refusal(status: StatusCode, answer: &Value) -> String {
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    assert_eq!(answer["error"]["code"], STREAM_FD_BUDGET_CODE, "{answer}");
    answer["error"]["message"]
        .as_str()
        .expect("a message")
        .to_string()
}

#[tokio::test]
async fn the_reads_carry_this_nodes_bind_state_of_each_stream() {
    let mut node = Node::standalone().await;
    let states = lorica_stream::StreamBindStates::new();
    node.state.stream_plane = StreamPlaneState::new(states.clone(), 65_536, 2);
    let pg = node.created(tcp("pg", 5432)).await;
    let pg_id = pg["id"].as_str().expect("an id");
    let smtp = node.created(tcp("smtp", 2525)).await;
    let smtp_id = smtp["id"].as_str().expect("an id");
    assert!(
        pg.get("bind").is_none(),
        "a write answers the configuration only: {pg}"
    );

    states.set_bound(pg_id, 1, 2);
    states.set_failed(
        smtp_id,
        lorica_stream::BindFailureKind::AddressInUse,
        "Address already in use (os error 98)".into(),
        2525,
        Utc::now(),
    );

    let (status, read) = node
        .call("GET", &format!("/api/v1/streams/{pg_id}"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{read}");
    assert_eq!(
        read["data"]["bind"],
        json!({ "state": "bound", "workers_serving": 1, "workers": 2 })
    );
    let (_, listed) = node.call("GET", "/api/v1/streams", None).await;
    let failed = listed["data"]["streams"]
        .as_array()
        .expect("a list")
        .iter()
        .find(|s| s["id"] == smtp_id)
        .expect("smtp listed")
        .clone();
    assert_eq!(failed["bind"]["state"], "failed");
    assert_eq!(failed["bind"]["kind"], "address_in_use");
    assert_eq!(
        failed["bind"]["os_error"],
        "Address already in use (os error 98)"
    );
    assert_eq!(failed["bind"]["port"], 2525);
    assert!(failed["bind"]["since"].is_string(), "{failed}");
}

#[tokio::test]
async fn a_create_or_update_the_budget_cannot_hold_is_refused_naming_node_and_constraint() {
    // 4,096 fds leave a stream budget of 1,024; the supervisor holds a
    // socket per worker per UDP port.
    let mut node = Node::standalone().await;
    node.state.stream_plane =
        StreamPlaneState::new(lorica_stream::StreamBindStates::new(), 4096, 2);
    let mut range = tcp("dns", 20_000);
    range["protocol"] = json!("udp");
    range["port_last"] = json!(20_999);

    let (status, answer) = node.create(range.clone()).await;
    let message = budget_refusal(status, &answer);
    for part in [
        "`dns`",
        "this node",
        "supervisor_fds",
        "2000",
        "1024",
        "4096",
    ] {
        assert!(message.contains(part), "{part}: {message}");
    }
    assert!(
        node.state
            .store
            .lock()
            .await
            .list_streams()
            .expect("list")
            .is_empty(),
        "a refused create leaves no row"
    );

    // Half the range fits one worker's share; widening it again is
    // refused and leaves the row as it stood.
    range["port_last"] = json!(20_499);
    let created = node.created(range).await;
    let id = created["id"].as_str().expect("an id");
    let (status, answer) = node.update(id, json!({ "port_last": 20_999 })).await;
    budget_refusal(status, &answer);
    let (_, read) = node
        .call("GET", &format!("/api/v1/streams/{id}"), None)
        .await;
    assert_eq!(without_bind(&read["data"]), created);

    // The per-node listening-socket cap is the stored setting: the
    // range's 500 ports fill it.
    {
        let store = node.state.store.lock().await;
        let mut settings = store.get_global_settings().expect("settings");
        settings.stream_listen_socket_cap = 500;
        store
            .update_global_settings(&settings)
            .expect("test setup: cap");
    }
    let (status, answer) = node.create(tcp("pg", 5432)).await;
    assert!(budget_refusal(status, &answer).contains("listen_socket_cap"));
    // A write that adds nothing on the node is never refused for it.
    let (status, answer) = node.update(id, json!({ "name": "dns-renamed" })).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
}

#[tokio::test]
async fn a_control_plane_warns_for_each_targeted_node_whose_budget_it_cannot_see() {
    let node = Node::control_plane().await;
    node.enrol("edge-1", NodeStatus::Active, Some(EDGE_1)).await;

    let mut pinned = tcp("pinned", 5432);
    pinned["node_selector"] = json!(["edge-1"]);
    let created = node.created(pinned).await;
    let warnings = created["warnings"].as_array().expect("warnings");
    assert_eq!(warnings.len(), 1, "{created}");
    assert!(
        warnings[0]
            .as_str()
            .is_some_and(|w| w.contains("node `edge-1`") && w.contains("fd_budget")),
        "{created}"
    );

    let standalone = Node::standalone().await;
    let created = standalone.created(tcp("pg", 5432)).await;
    assert!(
        created.get("warnings").is_none(),
        "a node that checks every target warns of nothing: {created}"
    );
}

#[tokio::test]
async fn the_budget_view_answers_this_node_to_operators_and_above() {
    let mut node = Node::standalone().await;
    let states = lorica_stream::StreamBindStates::new();
    node.state.stream_plane = StreamPlaneState::new(states.clone(), 65_536, 4);
    let pg = node.created(tcp("pg", 5432)).await;
    states.set_bound(pg["id"].as_str().expect("an id"), 4, 4);
    let mut dns = tcp("dns", 53);
    dns["protocol"] = json!("udp");
    dns["port_last"] = json!(54);
    node.created(dns).await;
    let mut off = tcp("off", 6000);
    off["enabled"] = json!(false);
    node.created(off).await;

    let (status, answer) = node.call("GET", "/api/v1/streams/budget", None).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let view = &answer["data"]["nodes"][0];
    assert_eq!(answer["data"]["nodes"].as_array().map(Vec::len), Some(1));
    assert_eq!(view["node_id"], Value::Null);
    assert_eq!(view["node_name"], Value::Null);
    assert!(view["reported_at"].is_string(), "{view}");
    assert_eq!(view["fd_limit"], 65_536);
    assert_eq!(view["base_reserve"], 1024);
    assert_eq!(view["http_reserve"], 32_768);
    assert_eq!(view["stream_budget"], 31_744);
    assert_eq!(view["worker_count"], 4);
    assert_eq!(view["listen_socket_cap"], 2048);
    assert_eq!(view["worker_drain_timeout_s"], 30);
    assert_eq!(view["listen_sockets_used"], 3);
    assert_eq!(view["worker_fds_committed"], 3);
    assert_eq!(view["supervisor_fds_committed"], 1 + 2 * 4);
    let shares: Vec<(&str, &str)> = view["streams"]
        .as_array()
        .expect("streams")
        .iter()
        .map(|s| {
            assert_eq!(s["ceiling"], Value::Null, "no engine declares one yet");
            assert_eq!(s["fds_per_unit"], Value::Null);
            (
                s["name"].as_str().expect("a name"),
                s["bind_state"].as_str().expect("a state"),
            )
        })
        .collect();
    assert_eq!(
        shares,
        vec![("dns", "pending"), ("pg", "bound")],
        "a disabled stream holds no share"
    );

    let viewer = create_user_and_login(
        &node.state,
        &node.sessions,
        &node.limiter,
        "viewer-budget",
        Role::Viewer,
    )
    .await;
    let operator = create_user_and_login(
        &node.state,
        &node.sessions,
        &node.limiter,
        "operator-budget",
        Role::Operator,
    )
    .await;
    let (status, answer) = node
        .call_as(&viewer, "GET", "/api/v1/streams/budget", None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    let (status, answer) = node
        .call_as(&operator, "GET", "/api/v1/streams/budget", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
}

#[tokio::test]
async fn a_follower_answers_the_budget_view_for_its_own_node() {
    let node = Node::follower().await;
    let (status, answer) = node.call("GET", "/api/v1/streams/budget", None).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let follower = test_follower_runtime();
    let view = &answer["data"]["nodes"][0];
    assert_eq!(view["node_id"], follower.node_id.as_str());
    assert_eq!(view["node_name"], follower.node_name.as_str());
}

// ---- The import's fd budget check (Story 12.2 Lot E2, E3's follow-up) ----

/// A TOML export of a store holding `streams`, with
/// `stream_listen_socket_cap` set to `cap` when given.
fn export_with(streams: &[lorica_config::models::Stream], cap: Option<u32>) -> String {
    let source = lorica_config::ConfigStore::open_in_memory().expect("source");
    for stream in streams {
        source.create_stream(stream).expect("test setup: stream");
    }
    if let Some(cap) = cap {
        let mut settings = source.get_global_settings().expect("settings");
        settings.stream_listen_socket_cap = cap;
        source
            .update_global_settings(&settings)
            .expect("test setup: cap");
    }
    lorica_config::export::export_to_toml(&source).expect("export")
}

/// A fleet-wide UDP range on `0.0.0.0`, as a TOML file would carry it.
fn udp_range(name: &str, first: u16, last: u16) -> lorica_config::models::Stream {
    lorica_config::models::Stream {
        protocol: lorica_config::models::StreamProtocol::Udp,
        port_last: last,
        ..source_stream(name, first)
    }
}

/// The preview's answer and then the import's, for one file.
async fn preview_and_import(
    node: &Node,
    file: String,
) -> ((StatusCode, Value), (StatusCode, Value)) {
    let body = json!({ "toml_content": file });
    let preview = node
        .call("POST", "/api/v1/config/import/preview", Some(body.clone()))
        .await;
    let import = node.call("POST", "/api/v1/config/import", Some(body)).await;
    (preview, import)
}

/// The import and its preview run the budget check of a stream write,
/// through the same function: a file a node's fd budget cannot hold is
/// refused `422` by both, before anything is cleared.
#[tokio::test]
async fn an_import_and_its_preview_refuse_a_stream_the_budget_cannot_hold() {
    // The import and its preview share one write budget, so each case
    // runs on a node of its own. 4,096 fds leave a stream budget of
    // 1,024; the supervisor holds a socket per worker per UDP port, so
    // 1,000 ports on two workers need 2,000.
    let fresh_node = || async {
        let mut node = Node::standalone().await;
        node.state.stream_plane =
            StreamPlaneState::new(lorica_stream::StreamBindStates::new(), 4096, 2);
        let kept = node.created(tcp("smtp", 2525)).await;
        (node, kept)
    };

    let (node, kept) = fresh_node().await;
    let ((preview_status, preview), (import_status, import)) = preview_and_import(
        &node,
        export_with(&[udp_range("dns", 20_000, 20_999)], None),
    )
    .await;
    let previewed = budget_refusal(preview_status, &preview);
    for part in ["`dns`", "this node", "supervisor_fds", "2000"] {
        assert!(previewed.contains(part), "{part}: {previewed}");
    }
    assert_eq!(
        previewed,
        budget_refusal(import_status, &import),
        "the preview and the import refuse alike"
    );
    let (_, listed) = node.call("GET", "/api/v1/streams", None).await;
    let listed: Vec<Value> = listed["data"]["streams"]
        .as_array()
        .expect("a list")
        .iter()
        .map(without_bind)
        .collect();
    assert_eq!(listed, vec![kept], "nothing was cleared");

    // The file's own cap is the one the import writes, so it is the one
    // checked: 10 ports under a cap of 5.
    let (node, _) = fresh_node().await;
    let ((preview_status, preview), (import_status, import)) = preview_and_import(
        &node,
        export_with(&[udp_range("small", 30_000, 30_009)], Some(5)),
    )
    .await;
    assert!(budget_refusal(preview_status, &preview).contains("listen_socket_cap"));
    assert!(budget_refusal(import_status, &import).contains("listen_socket_cap"));

    // A file that fits imports.
    let (node, _) = fresh_node().await;
    let ((preview_status, preview), (import_status, import)) = preview_and_import(
        &node,
        export_with(&[udp_range("dns", 20_000, 20_099)], None),
    )
    .await;
    assert_eq!(preview_status, StatusCode::OK, "{preview}");
    assert!(preview["data"].get("warnings").is_none(), "{preview}");
    assert_eq!(import_status, StatusCode::OK, "{import}");
}

/// Re-importing what a node already holds is never refused for its
/// budget, even on a node a lowered cap left over it: a stream carried
/// under its stored id is judged as an update of that row.
#[tokio::test]
async fn re_importing_an_export_passes_on_a_node_already_over_its_budget() {
    let node = Node::standalone().await;
    let mut wide = tcp("wide", 1000);
    wide["port_last"] = json!(1009);
    let id = node.created(wide).await["id"]
        .as_str()
        .expect("an id")
        .to_string();
    // The stored row, as a file under a cap of 5 would carry it: the
    // node's own export would also carry its users, whose redacted
    // hashes no import takes.
    let stored = node
        .state
        .store
        .lock()
        .await
        .get_stream(&id)
        .expect("read")
        .expect("the row");
    let same = export_with(std::slice::from_ref(&stored), Some(5));
    let renamed_id = export_with(
        &[lorica_config::models::Stream {
            id: uuid::Uuid::new_v4().to_string(),
            ..stored
        }],
        Some(5),
    );

    let (status, answer) = node
        .call(
            "POST",
            "/api/v1/config/import/preview",
            Some(json!({ "toml_content": renamed_id })),
        )
        .await;
    assert!(
        budget_refusal(status, &answer).contains("listen_socket_cap"),
        "the same ports under a new id are a new demand"
    );
    let (status, answer) = node
        .call(
            "POST",
            "/api/v1/config/import",
            Some(json!({ "toml_content": same })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
}

/// On a control plane, a targeted node that has not reported its budget
/// is named in the import's warnings and in its preview's, once.
#[tokio::test]
async fn an_import_names_each_targeted_node_whose_budget_it_cannot_see() {
    let node = Node::control_plane().await;
    node.enrol("edge-1", NodeStatus::Active, Some(EDGE_1)).await;
    let pinned = |name: &str, port: u16| lorica_config::models::Stream {
        node_selector: vec!["edge-1".to_string()],
        ..source_stream(name, port)
    };
    let body = json!({
        "toml_content": export_with(&[pinned("pg", 5432), pinned("smtp", 2525)], None)
    });
    let (status, preview) = node
        .call("POST", "/api/v1/config/import/preview", Some(body.clone()))
        .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    let (status, import) = node.call("POST", "/api/v1/config/import", Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{import}");
    for answer in [&preview, &import] {
        let warnings: Vec<&str> = answer["data"]["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .filter_map(Value::as_str)
            .filter(|w| w.contains("fd_budget"))
            .collect();
        assert_eq!(warnings.len(), 1, "{answer}");
        assert!(warnings[0].contains("node `edge-1`"), "{answer}");
    }
}
