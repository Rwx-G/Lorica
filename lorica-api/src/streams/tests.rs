//! The stream management API (Story 12.1 Lot 5): CRUD, validation,
//! audit, the role floors, the follower gate and the per-node port
//! conflict check, IV2 included.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::http::StatusCode;
use chrono::Utc;
use lorica_config::listen_ports::ReservedPorts;
use lorica_config::models::{ClusterNode, NodeStatus, Role};
use serde_json::{json, Value};

use super::{StreamResponse, STREAM_PORT_CONFLICT_CODE, STREAM_WITHHELD_FIELDS};
use crate::server::AppState;
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
    assert_eq!(read["data"], created);
    let (status, listed) = node.call("GET", "/api/v1/streams", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["data"]["streams"], json!([created]));

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
    assert_eq!(read["data"], first, "no refused update moved the row");
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
    assert_eq!(
        listed["data"]["streams"],
        json!([kept]),
        "nothing was cleared"
    );

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

/// A fleet-wide TCP stream on `0.0.0.0:port`, as a TOML file would
/// carry it.
fn source_stream(name: &str, port: u16) -> lorica_config::models::Stream {
    let now = Utc::now();
    lorica_config::models::Stream {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.to_string(),
        group_name: String::new(),
        protocol: lorica_config::models::StreamProtocol::Tcp,
        enabled: true,
        listen_address: "0.0.0.0".parse().expect("an address"),
        port_first: port,
        port_last: port,
        node_selector: Vec::new(),
        created_at: now,
        updated_at: now,
    }
}
