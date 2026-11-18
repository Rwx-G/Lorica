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

use super::{
    StreamLinks, StreamResponse, STREAM_LOCAL_BACKEND_CODE, STREAM_PORT_CONFLICT_CODE,
    STREAM_WITHHELD_FIELDS,
};
use crate::server::AppState;
use crate::stream_budget::{StreamPlaneState, DEFAULT_RANGE_USABLE_PORTS, STREAM_FD_BUDGET_CODE};
use crate::tests::{
    body_json, create_user_and_login, send, setup_admin_and_login, test_control_plane,
    test_follower_runtime, test_state,
};

/// The view fields that are not model fields: the links, by role, and
/// their caps.
const LINK_FIELDS: &[&str] = &["backend_ids", "backup_backend_ids", "backend_max_active"];

/// The view fields a client never writes: the server mints the id and
/// stamps the times.
const SERVER_OWNED_FIELDS: &[&str] = &["id", "created_at", "updated_at"];

/// The view fields that are not model fields and that a client never
/// writes either: what the view derives from the model (Story 12.4
/// D-j).
const DERIVED_FIELDS: &[&str] = &["drains_on_upgrade"];

/// Every view field a create and an update refuse.
fn read_only(field: &str) -> bool {
    SERVER_OWNED_FIELDS.contains(&field) || DERIVED_FIELDS.contains(&field)
}

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
pub(super) struct Node {
    pub(super) state: AppState,
    sessions: crate::middleware::auth::SessionStore,
    limiter: crate::middleware::rate_limit::RateLimiter,
    cookie: String,
    _control_liveness: Option<tokio::sync::watch::Receiver<u32>>,
    _data_dir: tempfile::TempDir,
}

impl Node {
    pub(super) async fn standalone() -> Self {
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

    pub(super) async fn call(
        &self,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        self.call_as(&self.cookie, method, uri, body).await
    }

    async fn create(&self, body: Value) -> (StatusCode, Value) {
        self.call("POST", "/api/v1/streams", Some(body)).await
    }

    pub(super) async fn update(&self, id: &str, body: Value) -> (StatusCode, Value) {
        self.call("PUT", &format!("/api/v1/streams/{id}"), Some(body))
            .await
    }

    /// Create, asserting the 201, and answer the view.
    pub(super) async fn created(&self, body: Value) -> Value {
        let (status, answer) = self.create(body).await;
        assert_eq!(status, StatusCode::CREATED, "{answer}");
        answer["data"].clone()
    }

    pub(super) async fn backend(&self, address: &str) -> String {
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

    pub(super) async fn audit_rows(&self) -> Vec<crate::audit::AuditRecord> {
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
pub(super) fn tcp(name: &str, port: u16) -> Value {
    json!({
        "name": name,
        "protocol": "tcp",
        "listen_address": "0.0.0.0",
        "port_first": port,
    })
}

/// The `udp` object that lets a UDP stream listen on an exposed address
/// (Story 12.5 D-k): the highest explicit per-source cap the rule takes.
fn exposed_udp() -> Value {
    json!({ "source_session_cap": lorica_config::models::UDP_EXPOSED_SOURCE_SESSION_CAP_MAX })
}

/// [`tcp`] as a UDP stream, with [`exposed_udp`] since it listens on
/// `0.0.0.0`.
fn udp(name: &str, port: u16) -> Value {
    let mut body = tcp(name, port);
    body["protocol"] = json!("udp");
    body["udp"] = exposed_udp();
    body
}

/// A stream as a read answers it, less its `bind`, which only the reads
/// carry: what a write answered for the same row.
pub(super) fn without_bind(read: &Value) -> Value {
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
            with(json!({
                "protocol": "udp",
                "udp": exposed_udp(),
                "backend_ids": [route_backend],
            })),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ] {
        let (status, answer) = node.create(body).await;
        assert_eq!(status, expected, "{what}: {answer}");
    }
    let shared = with(json!({
        "name": "dns",
        "protocol": "udp",
        "udp": exposed_udp(),
        "backend_ids": [route_backend],
    }));
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
        .created(with(json!({
            "name": "dns",
            "protocol": "udp",
            "udp": exposed_udp(),
            "backend_ids": [udp_backend],
        })))
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

/// The keys of a JSON object.
fn keys(object: &Value) -> BTreeSet<String> {
    object
        .as_object()
        .expect("an object")
        .keys()
        .cloned()
        .collect()
}

#[tokio::test]
async fn the_view_publishes_every_model_field_but_the_withheld_ones() {
    let node = Node::standalone().await;
    let terminating = terminating_body(&node).await;
    let guarded = merged(tcp("smtp", 2525), &source_controls_off_default());
    for body in [guarded, udp("dns", 53), terminating] {
        let created = node.created(body).await;
        let stored = stored_stream(&node, created["id"].as_str().expect("an id")).await;
        let model_json = serde_json::to_value(&stored).expect("the model serialises");
        let model: BTreeSet<String> = keys(&model_json)
            .into_iter()
            .filter(|k| !STREAM_WITHHELD_FIELDS.contains(&k.as_str()))
            .chain(LINK_FIELDS.iter().map(|k| k.to_string()))
            .chain(DERIVED_FIELDS.iter().map(|k| k.to_string()))
            .collect();
        assert_eq!(keys(&created), model);
        assert_eq!(created["drains_on_upgrade"], stored.drains_on_upgrade());
        // The source controls are the stored values, the GeoIP object in
        // the model's own shape.
        for field in lorica_config::models::Stream::protection_field_names() {
            assert_eq!(created[field], model_json[field], "{field}");
        }
        // The TLS objects are built field by field too, each the stored
        // value; a rule is the model's plus the backends serving it.
        for field in ["tls_mode", "no_sni_acknowledged", "clienthello_timeout_ms"] {
            assert_eq!(created[field], model_json[field], "{field}");
        }
        for object in ["tls_terminate", "upstream_tls"] {
            assert_eq!(created[object], model_json[object], "{object}");
        }
        let rules = created["match_rules"].as_array().expect("a list");
        assert_eq!(rules.len(), stored.match_rules.len());
        for (view, model) in rules
            .iter()
            .zip(model_json["match_rules"].as_array().expect("a list"))
        {
            let mut view = view.clone();
            let object = view.as_object_mut().expect("an object");
            for link in LINK_FIELDS {
                assert!(object.remove(*link).is_some(), "{link} in {object:?}");
            }
            assert_eq!(&view, model);
        }
        // The `udp` object is built field by field too: every setting of
        // the model's, each the stored value.
        match stored.protocol {
            lorica_config::models::StreamProtocol::Tcp => {
                assert_eq!(created["udp"], Value::Null, "a TCP stream carries none")
            }
            lorica_config::models::StreamProtocol::Udp => {
                assert_eq!(keys(&created["udp"]), keys(&model_json["udp"]));
                assert_eq!(created["udp"], model_json["udp"]);
            }
        }
        let typed: StreamResponse = super::stream_to_response(&stored, StreamLinks::default());
        assert_eq!(
            serde_json::to_value(&typed).expect("serialises")["listen_address"],
            "0.0.0.0"
        );
    }
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
    for body in [
        tcp("on-management", THIS_NODE.management),
        udp("on-management", THIS_NODE.management),
    ] {
        let (status, answer) = node.create(body).await;
        let message = port_conflict(status, &answer);
        assert!(message.contains("this node"), "{message}");
    }
}

#[tokio::test]
async fn streams_conflict_by_protocol_ports_and_address() {
    let node = Node::standalone().await;
    let mut game = udp("game", 6000);
    game["port_last"] = json!(6099);
    let game = node.created(game).await;

    let mut overlapping = udp("overlap", 6050);
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
    let mut dual = udp("dual", 6000);
    dual["listen_address"] = json!("::");
    let (status, answer) = node.create(dual).await;
    port_conflict(status, &answer);
    let mut v6 = udp("v6", 6000);
    v6["listen_address"] = json!("2001:db8::1");
    node.created(v6).await;

    // A disabled stream keeps its ports.
    let id = game["id"].as_str().expect("an id");
    let (status, answer) = node.update(id, json!({ "enabled": false })).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let (status, answer) = node.create(udp("again", 6099)).await;
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

/// This node's stream plane at `fd_limit` with `workers` workers, its
/// usable UDP source ports those of the default port range rather than
/// whatever the test host's are.
fn plane_at(
    states: lorica_stream::StreamBindStates,
    fd_limit: u64,
    workers: u32,
) -> StreamPlaneState {
    StreamPlaneState::new(states, fd_limit, workers)
        .with_usable_source_ports(Some(DEFAULT_RANGE_USABLE_PORTS))
}

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
    node.state.stream_plane = plane_at(states.clone(), 65_536, 2);
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
    // 12,288 fds leave a stream budget of 5,120: one worker holds the
    // 1,000 ports and the 4,096 default sessions, but the supervisor
    // holds a socket per worker per UDP port, 6,000 on six workers, and
    // the stream's caps memfd.
    let mut node = Node::standalone().await;
    node.state.stream_plane = plane_at(lorica_stream::StreamBindStates::new(), 12_288, 6);
    let mut range = udp("dns", 20_000);
    range["port_last"] = json!(20_999);

    let (status, answer) = node.create(range.clone()).await;
    let message = budget_refusal(status, &answer);
    for part in [
        "`dns`",
        "this node",
        "supervisor_fds",
        "6001",
        "5120",
        "12288",
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
    node.state.stream_plane = plane_at(states.clone(), 65_536, 4);
    let pg = node.created(tcp("pg", 5432)).await;
    states.set_bound(pg["id"].as_str().expect("an id"), 4, 4);
    let mut dns = udp("dns", 53);
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
    let pg_held = {
        let stored = node
            .state
            .store
            .lock()
            .await
            .get_stream(pg["id"].as_str().expect("an id"))
            .expect("read")
            .expect("stored");
        lorica_stream::tcp::held_fds(&stored).expect("a TCP stream declares its connections")
    };
    let dns_sessions = u64::from(lorica_config::models::UdpSettings::DEFAULT_MAX_SESSIONS);
    assert_eq!(
        view["worker_fds_committed"],
        3 + pg_held.total() + dns_sessions * lorica_stream::budget::UDP_FDS_PER_SESSION
    );
    // The TCP port, the UDP ports per worker, the UDP caps memfd.
    assert_eq!(view["supervisor_fds_committed"], 1 + 2 * 4 + 1);
    // The UDP session ceiling: the default range's ports bind it, the
    // fds left after the other streams being more.
    assert_eq!(view["usable_source_ports"], DEFAULT_RANGE_USABLE_PORTS);
    assert_eq!(view["session_ceiling"], DEFAULT_RANGE_USABLE_PORTS);
    assert_eq!(view["session_ceiling_bound_by"], "source_ports");
    assert_eq!(view["udp_sessions_committed"], dns_sessions);
    assert_eq!(view["over_ceiling"], false);
    assert_eq!(
        view["source_pools"],
        json!([{
            "pool": "default",
            "committed": dns_sessions,
            "usable": DEFAULT_RANGE_USABLE_PORTS,
        }])
    );
    let shares: Vec<(&str, &str)> = view["streams"]
        .as_array()
        .expect("streams")
        .iter()
        .map(|s| {
            if s["protocol"] == "tcp" {
                assert_eq!(s["ceiling"], pg_held.ceiling, "{s}");
                assert_eq!(s["fds_per_unit"], pg_held.fds_per_unit, "{s}");
            } else {
                assert_eq!(s["ceiling"], dns_sessions, "the stream's share: {s}");
                assert_eq!(
                    s["fds_per_unit"],
                    lorica_stream::budget::UDP_FDS_PER_SESSION,
                    "{s}"
                );
            }
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
    // The published schemas name exactly what the view carries.
    for (schema, object) in [
        ("NodeStreamBudget", view),
        ("StreamBudgetShare", &view["streams"][0]),
        ("StreamSourcePool", &view["source_pools"][0]),
    ] {
        assert_eq!(schema_properties(schema), keys(object), "{schema}");
    }

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

/// A fleet-wide UDP range on `0.0.0.0`, as a TOML file would carry it,
/// with 16 sessions: few enough that what one worker holds stays within
/// the small budgets these tests run on, so the ports alone decide. Its
/// explicit per-source cap lets it listen on that exposed address.
fn udp_range(name: &str, first: u16, last: u16) -> lorica_config::models::Stream {
    let mut stream = lorica_config::models::Stream::new(
        uuid::Uuid::new_v4().to_string(),
        name.to_string(),
        lorica_config::models::StreamProtocol::Udp,
        "0.0.0.0".parse().expect("an address"),
        first,
        last,
        Utc::now(),
    );
    let udp = stream
        .udp
        .as_mut()
        .expect("a UDP stream carries its settings");
    udp.max_sessions = 16;
    udp.source_session_cap = Some(lorica_config::models::UDP_EXPOSED_SOURCE_SESSION_CAP_MAX);
    stream
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
    // 1,024; the supervisor holds a socket per worker per UDP port and
    // a caps memfd per UDP stream, so 1,000 ports on two workers need
    // 2,001.
    let fresh_node = || async {
        let mut node = Node::standalone().await;
        node.state.stream_plane = plane_at(lorica_stream::StreamBindStates::new(), 4096, 2);
        // Within the 1,024 fds: one port and 100 connections of two.
        let mut smtp = tcp("smtp", 2525);
        smtp["max_connections"] = json!(100);
        let kept = node.created(smtp).await;
        (node, kept)
    };

    let (node, kept) = fresh_node().await;
    let ((preview_status, preview), (import_status, import)) = preview_and_import(
        &node,
        export_with(&[udp_range("dns", 20_000, 20_999)], None),
    )
    .await;
    let previewed = budget_refusal(preview_status, &preview);
    for part in ["`dns`", "this node", "supervisor_fds", "2001"] {
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

// ---- The engine settings and their surfaces (Story 12.3 Lot E) ----

/// A body that moves every Story 12.3 setting off its default, valid on
/// a TCP stream.
fn engine_settings_off_default() -> Value {
    json!({
        "load_balancing": "least_conn",
        "connect_timeout_ms": 2500,
        "idle_timeout_s": 120,
        "total_timeout_s": 3600,
        "max_connect_attempts": 5,
        "backend_keepalive": false,
        "backend_keepalive_idle_s": 30,
        "close_on_backend_down": true,
        "proxy_protocol_send": "v2",
        "proxy_protocol_accept": true,
        "proxy_protocol_trusted_cidrs": ["192.0.2.0/24"],
        "source_addresses": ["192.0.2.50"],
        "allow_local_backend": true,
        "upload_rate_bps": 65536,
        "download_rate_bps": 131072,
        "max_connections": 200,
    })
}

/// A body that moves every Story 12.6 source control off its default,
/// valid on a TCP stream, its country list in a form the store
/// canonicalises (see [`STORED_COUNTRIES`]).
fn source_controls_off_default() -> Value {
    json!({
        "source_max_connections": 16,
        "max_pending_connections": 64,
        "source_allow_cidrs": ["192.0.2.0/24", "2001:db8::/32"],
        "source_deny_cidrs": ["192.0.2.66"],
        "geoip": { "mode": "denylist", "countries": ["us", " fr ", "US"] },
        "source_open_rate": 50,
        "open_rate": 500,
    })
}

/// The country list of [`source_controls_off_default`] as it is stored
/// and answered: uppercased, trimmed, deduplicated.
const STORED_COUNTRIES: [&str; 2] = ["US", "FR"];

#[test]
fn the_source_controls_fixture_moves_every_protection_field() {
    let fixture: BTreeSet<String> = keys(&source_controls_off_default());
    let fields: BTreeSet<String> = lorica_config::models::Stream::protection_field_names()
        .iter()
        .map(|f| f.to_string())
        .collect();
    assert_eq!(fixture, fields);
}

/// `body` with every key of `patch` set on it.
fn merged(mut body: Value, patch: &Value) -> Value {
    for (key, value) in patch.as_object().expect("an object") {
        body[key] = value.clone();
    }
    body
}

/// A stored stream as the model holds it.
async fn stored_stream(node: &Node, id: &str) -> lorica_config::models::Stream {
    node.state
        .store
        .lock()
        .await
        .get_stream(id)
        .expect("read")
        .expect("stored")
}

/// The `409` of a local backend on a node's port, with its message.
fn local_backend_conflict(status: StatusCode, answer: &Value) -> String {
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(
        answer["error"]["code"], STREAM_LOCAL_BACKEND_CODE,
        "{answer}"
    );
    answer["error"]["message"]
        .as_str()
        .expect("a message")
        .to_string()
}

#[tokio::test]
async fn every_engine_setting_and_the_backups_round_trip_through_create_update_and_read() {
    let node = Node::standalone().await;
    let primary = node.backend("192.0.2.30:5432").await;
    let backup = node.backend("192.0.2.31:5432").await;
    let settings = engine_settings_off_default();
    let mut body = merged(tcp("pg", 5432), &settings);
    body["backend_ids"] = json!([primary]);
    body["backup_backend_ids"] = json!([backup]);
    let created = node.created(body).await;
    for (key, value) in settings.as_object().expect("an object") {
        assert_eq!(&created[key], value, "{key}: {created}");
    }
    assert_eq!(created["backend_ids"], json!([primary]));
    assert_eq!(created["backup_backend_ids"], json!([backup]));
    let id = created["id"].as_str().expect("an id");
    let (_, read) = node
        .call("GET", &format!("/api/v1/streams/{id}"), None)
        .await;
    assert_eq!(without_bind(&read["data"]), created);

    // The view is the model: each published setting is the stored one.
    let stored = serde_json::to_value(stored_stream(&node, id).await).expect("serialises");
    for key in settings.as_object().expect("an object").keys() {
        assert_eq!(stored[key], created[key], "{key}");
    }

    // An absent field keeps its value, `null` lifts a limit, and each
    // list of links replaces its own half.
    let (status, patched) = node
        .update(
            id,
            json!({
                "total_timeout_s": null,
                "upload_rate_bps": null,
                "connect_timeout_ms": 4000,
                "backup_backend_ids": [],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    let patched = &patched["data"];
    assert_eq!(patched["total_timeout_s"], Value::Null);
    assert_eq!(patched["upload_rate_bps"], Value::Null);
    assert_eq!(patched["connect_timeout_ms"], 4000);
    assert_eq!(patched["download_rate_bps"], created["download_rate_bps"]);
    assert_eq!(patched["max_connections"], created["max_connections"]);
    assert_eq!(patched["backend_ids"], json!([primary]));
    assert_eq!(patched["backup_backend_ids"], json!([]));

    // A backup moved to primary in one write.
    let (status, swapped) = node
        .update(id, json!({ "backend_ids": [primary, backup] }))
        .await;
    assert_eq!(status, StatusCode::OK, "{swapped}");
    let mut both = vec![primary.clone(), backup.clone()];
    both.sort();
    assert_eq!(swapped["data"]["backend_ids"], json!(both));
}

#[tokio::test]
async fn a_create_without_engine_settings_answers_the_model_defaults() {
    let node = Node::standalone().await;
    let created = node.created(tcp("smtp", 2525)).await;
    let id = created["id"].as_str().expect("an id");
    let mut defaults = lorica_config::models::Stream::new(
        id.to_string(),
        "smtp".to_string(),
        lorica_config::models::StreamProtocol::Tcp,
        "0.0.0.0".parse().expect("an address"),
        2525,
        2525,
        Utc::now(),
    );
    let stored = stored_stream(&node, id).await;
    defaults.created_at = stored.created_at;
    defaults.updated_at = stored.updated_at;
    assert_eq!(stored, defaults, "an absent setting is Stream::new's");
    assert_eq!(created["backup_backend_ids"], json!([]));
}

/// Every field a write answers, less the ones the server owns, is a
/// field a create and an update accept back: both bodies refuse an
/// unknown field, so a view field neither takes would fail here.
#[tokio::test]
async fn every_written_view_field_is_accepted_back_on_create_and_update() {
    let node = Node::standalone().await;
    let primary = node.backend("192.0.2.32:5432").await;
    let mut body = merged(
        merged(tcp("pg", 5432), &engine_settings_off_default()),
        &source_controls_off_default(),
    );
    body["backend_ids"] = json!([primary]);
    body["backend_max_active"] = json!({ primary.as_str(): 3 });
    let created = node.created(body).await;
    let id = created["id"].as_str().expect("an id").to_string();

    let terminating = node.created(terminating_body(&node).await).await;
    let terminating_id = terminating["id"].as_str().expect("an id").to_string();

    for (id, created, copy_port) in [(id, created, 5433), (terminating_id, terminating, 8444)] {
        let mut echoed = created.clone();
        let object = echoed.as_object_mut().expect("an object");
        for key in SERVER_OWNED_FIELDS.iter().chain(DERIVED_FIELDS) {
            assert!(object.remove(*key).is_some(), "{key} is in the view");
        }
        let (status, answer) = node.update(&id, echoed.clone()).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        let mut answered = answer["data"].clone();
        answered["updated_at"] = created["updated_at"].clone();
        answered
            .as_object_mut()
            .expect("an object")
            .remove("warnings");
        assert_eq!(answered, created, "echoing the view changes nothing");
        echoed["name"] = json!(format!(
            "{}-copy",
            created["name"].as_str().expect("a name")
        ));
        echoed["port_first"] = json!(copy_port);
        echoed["port_last"] = json!(copy_port);
        let (status, answer) = node.create(echoed).await;
        assert_eq!(status, StatusCode::CREATED, "{answer}");
    }

    let (status, answer) = node
        .update(
            created_id_of(&node, "pg").await.as_str(),
            json!({ "drains_on_upgrade": true }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "read-only: {answer}"
    );
}

/// The id of the stream named `name`.
async fn created_id_of(node: &Node, name: &str) -> String {
    node.state
        .store
        .lock()
        .await
        .list_streams()
        .expect("list")
        .into_iter()
        .find(|s| s.name == name)
        .expect("the stream exists")
        .id
}

#[tokio::test]
async fn every_engine_and_link_refusal_answers_422_and_stores_nothing() {
    let node = Node::standalone().await;
    let first = node.backend("192.0.2.40:5432").await;
    let second = node.backend("192.0.2.41:5432").await;
    let v6 = node.backend("[2001:db8::40]:5432").await;
    let local = node.backend("127.0.0.1:5999").await;
    let on = |patch: Value| merged(tcp("pg", 5432), &patch);
    let below = |range: std::ops::RangeInclusive<u32>| range.start() - 1;
    let above = |range: std::ops::RangeInclusive<u32>| range.end() + 1;
    type S = lorica_config::models::Stream;
    for (what, body) in [
        (
            "connect timeout below its range",
            on(json!({ "connect_timeout_ms": below(S::CONNECT_TIMEOUT_MS_RANGE) })),
        ),
        (
            "connect timeout above its range",
            on(json!({ "connect_timeout_ms": above(S::CONNECT_TIMEOUT_MS_RANGE) })),
        ),
        (
            "max_connections zero",
            on(json!({ "max_connections": below(S::MAX_CONNECTIONS_RANGE) })),
        ),
        (
            "max_connections above its range",
            on(json!({ "max_connections": above(S::MAX_CONNECTIONS_RANGE) })),
        ),
        (
            "attempts above their range",
            on(json!({ "max_connect_attempts": S::MAX_CONNECT_ATTEMPTS_RANGE.end() + 1 })),
        ),
        (
            "a rate below its range",
            on(json!({ "upload_rate_bps": S::RATE_BPS_RANGE.start() - 1 })),
        ),
        (
            "PROXY accept with no trusted peer",
            on(json!({ "proxy_protocol_accept": true })),
        ),
        (
            "a trust list of everyone",
            on(json!({ "proxy_protocol_trusted_cidrs": ["0.0.0.0/0"] })),
        ),
        (
            "an unspecified source address",
            on(json!({ "source_addresses": ["0.0.0.0"] })),
        ),
        (
            "an unknown balancing algorithm",
            on(json!({ "load_balancing": "fastest" })),
        ),
        (
            "an engine setting on UDP",
            on(json!({ "protocol": "udp", "udp": exposed_udp(), "max_connections": 10 })),
        ),
        (
            "PROXY accept on UDP",
            on(json!({
                "protocol": "udp",
                "udp": exposed_udp(),
                "proxy_protocol_accept": true,
                "proxy_protocol_trusted_cidrs": ["192.0.2.0/24"],
            })),
        ),
        (
            "an unknown backup",
            on(json!({ "backend_ids": [first], "backup_backend_ids": ["no-such-backend"] })),
        ),
        (
            "a backend both primary and backup",
            on(json!({ "backend_ids": [first], "backup_backend_ids": [first] })),
        ),
        (
            "backups and no primary",
            on(json!({ "backup_backend_ids": [first, second] })),
        ),
        (
            "a source family no backend has",
            on(json!({ "source_addresses": ["192.0.2.50"], "backend_ids": [v6] })),
        ),
        (
            "a local backend without the flag",
            on(json!({ "backend_ids": [local] })),
        ),
    ] {
        let (status, answer) = node.create(body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{what}: {answer}");
    }
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
    let (_, answer) = node.create(on(json!({ "backend_ids": [local] }))).await;
    assert!(
        answer["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("allow_local_backend") && m.contains("`pg`")),
        "rule A names the flag and the stream: {answer}"
    );

    // The same rules on an update, and a refused update moves nothing.
    let created = node.created(on(json!({ "backend_ids": [first] }))).await;
    let id = created["id"].as_str().expect("an id");
    let read_back = || async {
        let (_, read) = node
            .call("GET", &format!("/api/v1/streams/{id}"), None)
            .await;
        without_bind(&read["data"])
    };
    for (what, body) in [
        ("a range broken", json!({ "idle_timeout_s": 0 })),
        ("a local backend linked", json!({ "backend_ids": [local] })),
    ] {
        let (status, answer) = node.update(id, body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{what}: {answer}");
        assert_eq!(read_back().await, created, "{what}");
    }

    // The flag and the backend it allows land in one write, and leave
    // in one; the flag alone cannot leave under the backend.
    let (status, answer) = node
        .update(
            id,
            json!({ "allow_local_backend": true, "backend_ids": [local] }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let flagged = read_back().await;
    let (status, answer) = node
        .update(id, json!({ "allow_local_backend": false }))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    assert_eq!(read_back().await, flagged);
    let (status, answer) = node
        .update(
            id,
            json!({ "allow_local_backend": false, "backend_ids": [first] }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
}

// ---- Source controls and link caps (Story 12.6 Lot E) ----

/// The `max_active` of each stored link of stream `id`, by backend id.
async fn stored_caps(node: &Node, id: &str) -> Vec<(String, Option<u32>)> {
    let mut caps: Vec<(String, Option<u32>)> = node
        .state
        .store
        .lock()
        .await
        .list_stream_backends()
        .expect("links")
        .into_iter()
        .filter(|link| link.stream_id == id)
        .map(|link| (link.backend_id, link.max_active))
        .collect();
    caps.sort();
    caps
}

#[tokio::test]
async fn every_source_control_and_link_cap_round_trips_through_create_update_and_read() {
    let node = Node::standalone().await;
    let primary = node.backend("192.0.2.80:5432").await;
    let backup = node.backend("192.0.2.81:5432").await;
    let controls = source_controls_off_default();
    let mut body = merged(tcp("pg", 5432), &controls);
    body["backend_ids"] = json!([primary]);
    body["backup_backend_ids"] = json!([backup]);
    body["backend_max_active"] = json!({ primary.as_str(): 8, backup.as_str(): 2 });
    let created = node.created(body).await;
    for (key, value) in controls.as_object().expect("an object") {
        if key != "geoip" {
            assert_eq!(&created[key], value, "{key}: {created}");
        }
    }
    assert_eq!(
        created["geoip"],
        json!({ "mode": "denylist", "countries": STORED_COUNTRIES }),
        "a country list is answered as it is stored"
    );
    assert_eq!(
        created["backend_max_active"],
        json!({ primary.as_str(): 8, backup.as_str(): 2 })
    );
    let id = created["id"].as_str().expect("an id").to_string();
    let mut expected = vec![(primary.clone(), Some(8)), (backup.clone(), Some(2))];
    expected.sort();
    assert_eq!(stored_caps(&node, &id).await, expected);
    let stored = serde_json::to_value(stored_stream(&node, &id).await).expect("serialises");
    for field in lorica_config::models::Stream::protection_field_names() {
        assert_eq!(stored[field], created[field], "{field}");
    }
    let (_, read) = node
        .call("GET", &format!("/api/v1/streams/{id}"), None)
        .await;
    assert_eq!(without_bind(&read["data"]), created);

    // `null` lifts a limit, a list replaces the stored one, and an
    // absent field keeps its value.
    let (status, patched) = node
        .update(
            &id,
            json!({
                "source_max_connections": null,
                "geoip": null,
                "source_open_rate": null,
                "open_rate": null,
                "source_allow_cidrs": [],
                "max_pending_connections": 32,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    let patched = &patched["data"];
    for field in [
        "source_max_connections",
        "geoip",
        "source_open_rate",
        "open_rate",
    ] {
        assert_eq!(patched[field], Value::Null, "{field}");
    }
    assert_eq!(patched["source_allow_cidrs"], json!([]));
    assert_eq!(patched["max_pending_connections"], 32);
    assert_eq!(patched["source_deny_cidrs"], created["source_deny_cidrs"]);
    assert_eq!(patched["backend_max_active"], created["backend_max_active"]);

    // A link removed takes its cap with it; the others keep theirs.
    let (status, unlinked) = node.update(&id, json!({ "backup_backend_ids": [] })).await;
    assert_eq!(status, StatusCode::OK, "{unlinked}");
    assert_eq!(
        unlinked["data"]["backend_max_active"],
        json!({ primary.as_str(): 8 })
    );
    assert_eq!(
        stored_caps(&node, &id).await,
        vec![(primary.clone(), Some(8))]
    );

    // The caps alone replace every cap and keep the links.
    let (status, recapped) = node
        .update(
            &id,
            json!({ "backend_max_active": { primary.as_str(): 4 } }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{recapped}");
    assert_eq!(recapped["data"]["backend_ids"], json!([primary]));
    assert_eq!(
        stored_caps(&node, &id).await,
        vec![(primary.clone(), Some(4))]
    );
    let (status, uncapped) = node.update(&id, json!({ "backend_max_active": {} })).await;
    assert_eq!(status, StatusCode::OK, "{uncapped}");
    assert_eq!(uncapped["data"]["backend_max_active"], json!({}));
    assert_eq!(stored_caps(&node, &id).await, vec![(primary.clone(), None)]);
}

#[tokio::test]
async fn every_source_control_and_link_cap_refusal_answers_422_and_stores_nothing() {
    let node = Node::standalone().await;
    let first = node.backend("192.0.2.82:5432").await;
    let second = node.backend("192.0.2.83:5432").await;
    let on = |patch: Value| merged(tcp("pg", 5432), &patch);
    type S = lorica_config::models::Stream;
    let below = |range: std::ops::RangeInclusive<u32>| range.start() - 1;
    let above = |range: std::ops::RangeInclusive<u32>| range.end() + 1;
    let capped = |caps: Value| on(json!({ "backend_ids": [first], "backend_max_active": caps }));
    for (what, body, word) in [
        (
            "an allowlist of everyone",
            on(json!({ "source_allow_cidrs": ["0.0.0.0/0"] })),
            "source_allow_cidrs",
        ),
        (
            "a denylist of everyone",
            on(json!({ "source_deny_cidrs": ["::/0"] })),
            "source_deny_cidrs",
        ),
        (
            "a CIDR that does not parse",
            on(json!({ "source_deny_cidrs": ["192.0.2.0/33"] })),
            "source_deny_cidrs",
        ),
        (
            "a per-source cap below its range",
            on(json!({ "source_max_connections": below(S::SOURCE_MAX_CONNECTIONS_RANGE) })),
            "source_max_connections",
        ),
        (
            "a pending cap above its range",
            on(json!({ "max_pending_connections": above(S::MAX_PENDING_CONNECTIONS_RANGE) })),
            "max_pending_connections",
        ),
        (
            "a stream open rate below its range",
            on(json!({ "open_rate": below(S::OPEN_RATE_RANGE) })),
            "open_rate",
        ),
        (
            "a source open rate above its range",
            on(json!({ "source_open_rate": above(S::OPEN_RATE_RANGE) })),
            "source_open_rate",
        ),
        (
            "a country code of three letters",
            on(json!({ "geoip": { "mode": "denylist", "countries": ["USA"] } })),
            "geoip.countries",
        ),
        (
            "an empty country allowlist",
            on(json!({ "geoip": { "mode": "allowlist", "countries": [] } })),
            "geoip.countries",
        ),
        (
            "a per-source cap on UDP",
            on(json!({ "protocol": "udp", "udp": exposed_udp(), "source_max_connections": 4 })),
            "source_max_connections",
        ),
        (
            "a cap naming a backend the stream does not link",
            capped(json!({ second.as_str(): 4 })),
            "backend_max_active",
        ),
        (
            "a cap below its range",
            capped(json!({ first.as_str(): below(S::MAX_ACTIVE_RANGE) })),
            "max_active",
        ),
        (
            "a cap above its range",
            capped(json!({ first.as_str(): above(S::MAX_ACTIVE_RANGE) })),
            "max_active",
        ),
    ] {
        let (status, answer) = node.create(body).await;
        let message = unprocessable(status, &answer);
        assert!(message.contains(word), "{what}: {word}: {message}");
    }
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

    // On an update, a cap must name a link the update leaves, and a
    // refused update moves nothing.
    let created = node.created(capped(json!({ first.as_str(): 4 }))).await;
    let id = created["id"].as_str().expect("an id");
    for (what, body) in [
        (
            "a cap on a backend the update unlinks",
            json!({ "backend_ids": [second], "backend_max_active": { first.as_str(): 3 } }),
        ),
        (
            "a cap out of range",
            json!({ "backend_max_active": { first.as_str(): 0 } }),
        ),
        ("an open rate out of range", json!({ "open_rate": 0 })),
    ] {
        let (status, answer) = node.update(id, body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{what}: {answer}");
        let (_, read) = node
            .call("GET", &format!("/api/v1/streams/{id}"), None)
            .await;
        assert_eq!(without_bind(&read["data"]), created, "{what}");
        assert_eq!(
            stored_caps(&node, id).await,
            vec![(first.clone(), Some(4))],
            "{what}"
        );
    }
}

/// A source allowlist is what lets a UDP stream listen on an exposed
/// address without an explicit per-source cap (Story 12.6 D-l), and the
/// API holds a stream relying on it to it.
#[tokio::test]
async fn an_allowlist_lets_an_exposed_udp_stream_go_without_an_explicit_source_cap() {
    let node = Node::standalone().await;
    let mut body = tcp("dns", 53);
    body["protocol"] = json!("udp");
    body["source_allow_cidrs"] = json!(["198.51.100.0/24"]);
    let created = node.created(body).await;
    assert_eq!(created["udp"]["source_session_cap"], Value::Null);
    let id = created["id"].as_str().expect("an id");
    let (status, answer) = node.update(id, json!({ "source_allow_cidrs": [] })).await;
    assert!(
        unprocessable(status, &answer).contains("source_allow_cidrs"),
        "{answer}"
    );
}

#[tokio::test]
async fn a_tls_streams_link_caps_travel_inside_its_rules() {
    let node = Node::standalone().await;
    let first = node.backend("192.0.2.84:443").await;
    let second = node.backend("192.0.2.85:443").await;
    let mut web = tls_rule("web", &["a.example.com"], &[&first]);
    web["backup_backend_ids"] = json!([second]);
    web["backend_max_active"] = json!({ first.as_str(): 5 });
    let created = node
        .created(tls_stream("sni", 8443, "passthrough", json!([web])))
        .await;
    assert_eq!(
        created["match_rules"][0]["backend_max_active"],
        json!({ first.as_str(): 5 })
    );
    assert_eq!(
        created["backend_max_active"],
        json!({}),
        "the caps are per rule"
    );
    let id = created["id"].as_str().expect("an id").to_string();
    let mut expected = vec![(first.clone(), Some(5)), (second.clone(), None)];
    expected.sort();
    assert_eq!(stored_caps(&node, &id).await, expected);

    for (what, body, words) in [
        (
            "a stream-level cap",
            json!({ "backend_max_active": { first.as_str(): 1 } }),
            vec!["backend_max_active", "passthrough"],
        ),
        (
            "a rule's cap on a backend the rule does not link",
            json!({ "match_rules": [{
                "name": "web",
                "matcher": { "kind": "tls", "server_names": ["a.example.com"] },
                "backend_ids": [first],
                "backend_max_active": { second.as_str(): 1 },
            }] }),
            vec!["backend_max_active", "`web`", second.as_str()],
        ),
    ] {
        let (status, answer) = node.update(&id, body).await;
        let message = unprocessable(status, &answer);
        for word in words {
            assert!(message.contains(word), "{what}: {word}: {message}");
        }
        assert_eq!(stored_caps(&node, &id).await, expected, "{what}");
    }
}

/// IV4, first half: a stream pointed at this node's management API
/// through loopback is refused at creation, flag or not.
#[tokio::test]
async fn iv4_a_stream_pointed_at_the_management_port_is_refused_at_creation() {
    let node = Node::standalone().await;
    let management = node
        .backend(&format!("127.0.0.1:{}", THIS_NODE.management))
        .await;
    for flag in [false, true] {
        let mut body = tcp("admin", 5000);
        body["allow_local_backend"] = json!(flag);
        body["backend_ids"] = json!([management]);
        let (status, answer) = node.create(body).await;
        let message = local_backend_conflict(status, &answer);
        for part in [
            "`admin`",
            "this node",
            &format!("127.0.0.1:{}", THIS_NODE.management),
            "management",
        ] {
            assert!(message.contains(part), "flag {flag}, {part}: {message}");
        }
    }
    // The same address as a backup, and in its other local spellings.
    let mut body = tcp("admin", 5000);
    body["allow_local_backend"] = json!(true);
    let primary = node.backend("192.0.2.60:5000").await;
    body["backend_ids"] = json!([primary]);
    body["backup_backend_ids"] = json!([management]);
    let (status, answer) = node.create(body).await;
    local_backend_conflict(status, &answer);
    for address in [
        format!("localhost:{}", THIS_NODE.management),
        format!("[::1]:{}", THIS_NODE.management),
        format!("127.0.0.1:{}", THIS_NODE.https),
    ] {
        let backend = node.backend(&address).await;
        let mut body = tcp("admin", 5000);
        body["allow_local_backend"] = json!(true);
        body["backend_ids"] = json!([backend]);
        let (status, answer) = node.create(body).await;
        local_backend_conflict(status, &answer);
    }
    assert!(
        node.state
            .store
            .lock()
            .await
            .list_streams()
            .expect("list")
            .is_empty(),
        "nothing was created"
    );

    // A local backend on a port nothing holds needs the flag, and only
    // the flag.
    let free = node.backend("127.0.0.1:5999").await;
    let mut body = tcp("local", 5001);
    body["backend_ids"] = json!([free]);
    let (status, answer) = node.create(body.clone()).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    body["allow_local_backend"] = json!(true);
    node.created(body).await;
}

#[tokio::test]
async fn a_local_backend_may_not_reach_a_stream_port_in_either_order() {
    let node = Node::standalone().await;
    let other = node.created(tcp("pg", 6000)).await;
    let onto_pg = node.backend("127.0.0.1:6000").await;
    let mut looping = tcp("loop", 6001);
    looping["allow_local_backend"] = json!(true);
    looping["backend_ids"] = json!([onto_pg]);
    let (status, answer) = node.create(looping).await;
    let message = local_backend_conflict(status, &answer);
    assert!(
        message.contains("`loop`") && message.contains("`pg`"),
        "{message}"
    );

    // Its own port: the stream would forward to itself.
    let onto_self = node.backend("127.0.0.1:6002").await;
    let mut to_itself = tcp("self", 6002);
    to_itself["allow_local_backend"] = json!(true);
    to_itself["backend_ids"] = json!([onto_self]);
    let (status, answer) = node.create(to_itself).await;
    assert!(local_backend_conflict(status, &answer).contains("`self`"));

    // The other way round: a stored stream's local backend on a port a
    // write would now take. The refusal names the stream whose backend
    // it is.
    let onto_7000 = node.backend("127.0.0.1:7000").await;
    let mut forwarder = tcp("forwarder", 6003);
    forwarder["allow_local_backend"] = json!(true);
    forwarder["backend_ids"] = json!([onto_7000]);
    node.created(forwarder).await;
    let (status, answer) = node.create(tcp("target", 7000)).await;
    let message = local_backend_conflict(status, &answer);
    assert!(
        message.contains("`forwarder`") && message.contains("`target`"),
        "{message}"
    );
    let id = other["id"].as_str().expect("an id");
    let (status, answer) = node.update(id, json!({ "port_first": 7000 })).await;
    let message = local_backend_conflict(status, &answer);
    assert!(
        message.contains("`forwarder`") && message.contains("`pg`"),
        "{message}"
    );
}

#[tokio::test]
async fn a_backend_update_moving_a_linked_backend_onto_a_node_port_is_refused() {
    let node = Node::standalone().await;
    node.created(tcp("pg", 6100)).await;
    let backend = node.backend("127.0.0.1:5999").await;
    let mut local = tcp("local", 6000);
    local["allow_local_backend"] = json!(true);
    local["backend_ids"] = json!([backend]);
    node.created(local).await;

    let uri = format!("/api/v1/backends/{backend}");
    for (address, holder) in [
        ("127.0.0.1:6100".to_string(), "`pg`"),
        ("127.0.0.1:6000".to_string(), "`local`"),
        (format!("127.0.0.1:{}", THIS_NODE.management), "management"),
    ] {
        let (status, answer) = node
            .call("PUT", &uri, Some(json!({ "address": address })))
            .await;
        let message = local_backend_conflict(status, &answer);
        assert!(
            message.contains("stream `local`") && message.contains(holder),
            "{address}: {message}"
        );
    }
    let (_, read) = node.call("GET", &uri, None).await;
    assert_eq!(read["data"]["address"], "127.0.0.1:5999", "nothing moved");

    // A port nothing holds is the backend's to take.
    let (status, answer) = node
        .call("PUT", &uri, Some(json!({ "address": "127.0.0.1:5998" })))
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
}

#[tokio::test]
async fn an_import_and_its_preview_refuse_a_local_backend_on_a_node_port() {
    let node = Node::standalone().await;
    // A backend row as the management API stores it, carried into the
    // file below.
    let backend_id = node
        .backend(&format!("127.0.0.1:{}", THIS_NODE.management))
        .await;
    let backend = node
        .state
        .store
        .lock()
        .await
        .get_backend(&backend_id)
        .expect("read")
        .expect("stored");
    let file = {
        let source = lorica_config::ConfigStore::open_in_memory().expect("source");
        source
            .create_backend(&backend)
            .expect("test setup: backend");
        let mut stream = source_stream("admin", 5000);
        stream.allow_local_backend = true;
        source.create_stream(&stream).expect("test setup: stream");
        source
            .set_stream_backends(&stream.id, std::slice::from_ref(&backend.id))
            .expect("test setup: the store checks no node ports");
        lorica_config::export::export_to_toml(&source).expect("export")
    };
    let ((preview_status, preview), (import_status, import)) =
        preview_and_import(&node, file).await;
    let previewed = local_backend_conflict(preview_status, &preview);
    assert!(
        previewed.contains("`admin`") && previewed.contains("this node"),
        "{previewed}"
    );
    assert_eq!(
        previewed,
        local_backend_conflict(import_status, &import),
        "the preview and the import refuse alike"
    );
}

#[tokio::test]
async fn a_tcp_streams_connections_count_against_the_fd_budget_as_the_node_counts_them() {
    // 4,096 fds leave a stream budget of 1,024: one port and 511
    // connections of two fds fit, 512 do not.
    let mut node = Node::standalone().await;
    node.state.stream_plane = plane_at(lorica_stream::StreamBindStates::new(), 4096, 2);
    let mut body = tcp("pg", 5432);
    body["max_connections"] = json!(512);
    let (status, answer) = node.create(body.clone()).await;
    let message = budget_refusal(status, &answer);
    for part in ["`pg`", "worker_fds", "1025", "1024"] {
        assert!(message.contains(part), "{part}: {message}");
    }
    body["max_connections"] = json!(511);
    let created = node.created(body).await;
    let id = created["id"].as_str().expect("an id");
    let (status, answer) = node.update(id, json!({ "max_connections": 512 })).await;
    budget_refusal(status, &answer);
    let (status, answer) = node.update(id, json!({ "max_connections": 100 })).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "lowering the cap is always allowed: {answer}"
    );
}

// ---- The UDP settings and the listen-address rule (Story 12.5 Lot G) ----

/// The message of a `422`.
fn unprocessable(status: StatusCode, answer: &Value) -> String {
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    answer["error"]["message"]
        .as_str()
        .expect("a message")
        .to_string()
}

#[tokio::test]
async fn a_udp_streams_settings_take_their_defaults_and_each_written_one() {
    let node = Node::standalone().await;
    let defaults =
        serde_json::to_value(lorica_config::models::UdpSettings::default()).expect("serialises");

    // On a private address a UDP stream needs no `udp` object at all.
    let mut body = tcp("dns", 53);
    body["protocol"] = json!("udp");
    body["listen_address"] = json!("10.0.0.10");
    let created = node.created(body).await;
    assert_eq!(created["udp"], defaults);
    assert_eq!(
        created["idle_timeout_s"],
        lorica_config::models::Stream::DEFAULT_UDP_IDLE_TIMEOUT_S
    );

    // Each written setting over the defaults, `null` included.
    let mut body = udp("syslog", 514);
    body["udp"] = json!({
        "source_session_cap": 8,
        "responses_per_request": 0,
        "requests_per_session": null,
    });
    let syslog = node.created(body).await;
    let mut expected = defaults.clone();
    expected["source_session_cap"] = json!(8);
    expected["responses_per_request"] = json!(0);
    expected["requests_per_session"] = Value::Null;
    assert_eq!(syslog["udp"], expected);

    // An update keeps what it leaves out, and a `null` object is no
    // change.
    let id = syslog["id"].as_str().expect("an id");
    let (status, answer) = node
        .update(
            id,
            json!({ "udp": { "unbounded_responses": true, "max_sessions": 128 } }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    expected["unbounded_responses"] = json!(true);
    expected["max_sessions"] = json!(128);
    assert_eq!(answer["data"]["udp"], expected);
    let (status, answer) = node.update(id, json!({ "udp": null })).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["data"]["udp"], expected);
    let stored = stored_stream(&node, id).await;
    assert_eq!(
        serde_json::to_value(stored.udp).expect("serialises"),
        expected
    );

    // A range is the model's, named in the refusal; an unknown setting
    // is refused.
    for (patch, field) in [
        (json!({ "max_sessions": 0 }), "udp.max_sessions"),
        (json!({ "source_byte_rate": 1024 }), "udp.source_byte_rate"),
    ] {
        let (status, answer) = node.update(id, json!({ "udp": patch })).await;
        assert!(unprocessable(status, &answer).contains(field), "{answer}");
    }
    let (status, answer) = node.update(id, json!({ "udp": { "max": 1 } })).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    assert_eq!(
        read_udp(&node, id).await,
        expected,
        "no refused update moved it"
    );

    // A TCP stream carries none and takes none, in the model's words.
    let pg = node.created(tcp("pg", 5432)).await;
    assert_eq!(pg["udp"], Value::Null);
    let pg_id = pg["id"].as_str().expect("an id");
    let refused_on_tcp = "udp settings are refused on a TCP stream";
    let mut body = tcp("pg-udp", 5433);
    body["udp"] = json!({ "max_sessions": 10 });
    let (status, answer) = node.create(body).await;
    assert!(unprocessable(status, &answer).contains(refused_on_tcp));
    let (status, answer) = node
        .update(pg_id, json!({ "udp": { "max_sessions": 10 } }))
        .await;
    assert!(unprocessable(status, &answer).contains(refused_on_tcp));

    // A switch takes the new protocol's settings: the defaults under
    // the object a switch to UDP carries, none on the way back.
    let (status, answer) = node
        .update(
            pg_id,
            json!({ "protocol": "udp", "udp": merged(exposed_udp(), &json!({ "max_sessions": 10 })) }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let mut switched = merged(defaults.clone(), &exposed_udp());
    switched["max_sessions"] = json!(10);
    assert_eq!(answer["data"]["udp"], switched);
    let (status, answer) = node.update(pg_id, json!({ "protocol": "tcp" })).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["data"]["udp"], Value::Null);
}

/// The `udp` object of stream `id` as a read answers it.
async fn read_udp(node: &Node, id: &str) -> Value {
    let (_, read) = node
        .call("GET", &format!("/api/v1/streams/{id}"), None)
        .await;
    read["data"]["udp"].clone()
}

#[tokio::test]
async fn an_exposed_udp_stream_needs_an_explicit_source_cap_at_most_the_maximum() {
    let node = Node::standalone().await;
    let max = lorica_config::models::UDP_EXPOSED_SOURCE_SESSION_CAP_MAX;
    let rule = |status: StatusCode, answer: &Value, address: &str| {
        let message = unprocessable(status, answer);
        for part in [
            address,
            "exposed",
            "source allowlist",
            "udp.source_session_cap",
        ] {
            assert!(message.contains(part), "{part}: {message}");
        }
    };
    for (n, address) in (0u16..).zip(["0.0.0.0", "::", "192.0.2.10", "2001:db8::1"]) {
        let port = 6000 + n;
        let mut body = tcp(&format!("exposed-{n}"), port);
        body["protocol"] = json!("udp");
        body["listen_address"] = json!(address);
        for refused in [
            None,
            Some(json!({ "source_session_cap": null })),
            Some(json!({ "source_session_cap": max + 1 })),
        ] {
            let mut attempt = body.clone();
            if let Some(udp) = refused {
                attempt["udp"] = udp;
            }
            let (status, answer) = node.create(attempt).await;
            rule(status, &answer, address);
        }
        body["udp"] = json!({ "source_session_cap": max });
        node.created(body).await;
    }

    // The rule follows a stream through its updates.
    let mut body = tcp("private", 7000);
    body["protocol"] = json!("udp");
    body["listen_address"] = json!("10.0.0.10");
    let id = node.created(body).await["id"]
        .as_str()
        .expect("an id")
        .to_string();
    let (status, answer) = node
        .update(&id, json!({ "listen_address": "0.0.0.0" }))
        .await;
    rule(status, &answer, "0.0.0.0");
    let (status, answer) = node
        .update(
            &id,
            json!({ "listen_address": "0.0.0.0", "udp": { "source_session_cap": max } }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    for cap in [json!(max + 1), Value::Null] {
        let (status, answer) = node
            .update(&id, json!({ "udp": { "source_session_cap": cap } }))
            .await;
        rule(status, &answer, "0.0.0.0");
    }
}

#[tokio::test]
async fn a_udp_write_past_the_source_ports_is_refused_and_one_raising_nothing_passes() {
    let mut node = Node::standalone().await;
    let narrowed_to = |usable: u64| {
        StreamPlaneState::new(lorica_stream::StreamBindStates::new(), 65_536, 1)
            .with_usable_source_ports(Some(usable))
    };
    node.state.stream_plane = narrowed_to(5_000);
    let dns = node.created(udp("dns", 53)).await;
    let id = dns["id"].as_str().expect("an id");
    let (status, answer) = node.create(udp("ntp", 123)).await;
    let message = budget_refusal(status, &answer);
    for part in ["`ntp`", "this node", "source_ports", "8192", "5000"] {
        assert!(message.contains(part), "{part}: {message}");
    }

    // The range narrows under the stream: 4,096 sessions on 3,000
    // ports. A move and a lower share pass; a raise is refused.
    node.state.stream_plane = narrowed_to(3_000);
    let (status, answer) = node
        .update(id, json!({ "listen_address": "10.0.0.10" }))
        .await;
    assert_eq!(status, StatusCode::OK, "a move raises nothing: {answer}");
    let (status, answer) = node
        .update(id, json!({ "udp": { "max_sessions": 2048 } }))
        .await;
    assert_eq!(status, StatusCode::OK, "a lower share passes: {answer}");
    let (status, answer) = node
        .update(id, json!({ "udp": { "max_sessions": 4096 } }))
        .await;
    assert!(budget_refusal(status, &answer).contains("source_ports"));
}

// ---- The published description (`lorica-api/openapi.yaml`) ----

const OPENAPI: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.yaml"));

/// The lines of the component schema `name`, its header excluded.
fn schema_block(name: &str) -> Vec<&'static str> {
    let header = format!("    {name}:");
    let mut lines = OPENAPI.lines().skip_while(|l| l.trim_end() != header);
    assert!(lines.next().is_some(), "openapi.yaml has no schema {name}");
    lines
        .take_while(|l| l.trim().is_empty() || l.starts_with("     "))
        .collect()
}

/// The property names of the component schema `name`.
fn schema_properties(name: &str) -> BTreeSet<String> {
    schema_block(name)
        .into_iter()
        .filter_map(|line| {
            let key = line.strip_prefix("        ")?.strip_suffix(':')?;
            key.chars()
                .all(|c| c.is_ascii_lowercase() || c == '_')
                .then(|| key.to_string())
        })
        .collect()
}

/// The lines describing `property` of the component schema `name`.
fn property_block(name: &str, property: &str) -> Vec<&'static str> {
    let header = format!("        {property}:");
    let mut lines = schema_block(name)
        .into_iter()
        .skip_while(|l| l.trim_end() != header);
    assert!(lines.next().is_some(), "{name} has no property {property}");
    lines
        .take_while(|l| l.trim().is_empty() || l.starts_with("         "))
        .collect()
}

/// The value of the `key: value` line in `block`, unquoted.
fn scalar<'a>(block: &[&'a str], key: &str) -> Option<&'a str> {
    let prefix = format!("{key}: ");
    block.iter().find_map(|line| {
        line.trim()
            .strip_prefix(prefix.as_str())
            .map(|value| value.trim_matches('"'))
    })
}

/// The words of the `enum: [a, b]` line in `block`, unquoted.
fn enum_words(block: &[&str]) -> Vec<String> {
    let list = scalar(block, "enum").expect("an enum line");
    list.trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(|word| word.trim().trim_matches('"').to_string())
        .collect()
}

#[tokio::test]
async fn the_published_stream_schemas_name_exactly_the_fields_the_api_reads_and_answers() {
    let node = Node::standalone().await;
    let created = node.created(tcp("smtp", 2525)).await;
    let view: BTreeSet<String> = created
        .as_object()
        .expect("an object")
        .keys()
        .filter(|k| k.as_str() != "warnings")
        .cloned()
        .collect();
    assert_eq!(schema_properties("StreamResponse"), view);
    let writable: BTreeSet<String> = view.iter().filter(|k| !read_only(k)).cloned().collect();
    assert_eq!(schema_properties("CreateStreamRequest"), writable);
    assert_eq!(schema_properties("UpdateStreamRequest"), writable);
    let required: BTreeSet<String> = schema_block("StreamResponse")
        .into_iter()
        .filter_map(|line| line.strip_prefix("        - "))
        .map(str::to_string)
        .collect();
    assert_eq!(required, view, "every view field is always present");
}

#[tokio::test]
async fn the_published_udp_schemas_name_exactly_the_udp_view() {
    let node = Node::standalone().await;
    let created = node.created(udp("dns", 53)).await;
    let udp_view = keys(&created["udp"]);
    assert_eq!(schema_properties("StreamUdpSettings"), udp_view);
    assert_eq!(schema_properties("StreamUdpSettingsInput"), udp_view);
    let required: BTreeSet<String> = schema_block("StreamUdpSettings")
        .into_iter()
        .filter_map(|line| line.strip_prefix("        - "))
        .map(str::to_string)
        .collect();
    assert_eq!(required, udp_view, "every udp field is always present");
}

/// The prose of `block`, its lines joined with single spaces, so a
/// phrase reads the same wherever the YAML wraps it.
fn prose(block: &[&str]) -> String {
    block
        .iter()
        .map(|line| line.trim())
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn the_published_udp_ranges_defaults_and_words_are_the_models() {
    use lorica_config::models::{
        DatagramDropReason, Stream, StreamRefusal, UdpSettings, UDP_EXPOSED_SOURCE_SESSION_CAP_MAX,
    };
    use strum::VariantArray as _;

    for (field, range) in [
        ("max_sessions", UdpSettings::MAX_SESSIONS_RANGE),
        ("source_session_cap", UdpSettings::SOURCE_SESSION_CAP_RANGE),
        (
            "requests_per_session",
            UdpSettings::REQUESTS_PER_SESSION_RANGE,
        ),
        (
            "responses_per_request",
            UdpSettings::RESPONSES_PER_REQUEST_RANGE,
        ),
        (
            "response_bytes_ratio",
            UdpSettings::RESPONSE_BYTES_RATIO_RANGE,
        ),
        (
            "source_datagram_rate",
            UdpSettings::SOURCE_DATAGRAM_RATE_RANGE,
        ),
        ("source_byte_rate", UdpSettings::SOURCE_BYTE_RATE_RANGE),
        ("max_datagram_bytes", UdpSettings::MAX_DATAGRAM_BYTES_RANGE),
    ] {
        let block = property_block("StreamUdpSettings", field);
        assert_eq!(
            scalar(&block, "minimum"),
            Some(range.start().to_string().as_str()),
            "{field}"
        );
        assert_eq!(
            scalar(&block, "maximum"),
            Some(range.end().to_string().as_str()),
            "{field}"
        );
    }
    let defaults = serde_json::to_value(UdpSettings::default()).expect("serialises");
    for property in schema_properties("StreamUdpSettings") {
        let block = property_block("StreamUdpSettings", &property);
        let published = scalar(&block, "default").expect("every udp setting publishes its default");
        assert_eq!(published, defaults[&property].to_string(), "{property}");
    }

    // The figures the prose states are the model's.
    let settings = prose(&schema_block("StreamUdpSettings"));
    assert!(
        settings.contains(&format!("at most {UDP_EXPOSED_SOURCE_SESSION_CAP_MAX}")),
        "{settings}"
    );
    let cap = prose(&property_block("StreamUdpSettings", "source_session_cap"));
    assert!(
        cap.contains(&format!(
            "default of {}",
            UdpSettings::DEFAULT_SOURCE_SESSION_CAP
        )),
        "{cap}"
    );
    let idle = prose(&property_block("StreamResponse", "idle_timeout_s"));
    for figure in [
        format!("defaults to {}", Stream::DEFAULT_UDP_IDLE_TIMEOUT_S),
        format!("stops at {}", Stream::UDP_IDLE_TIMEOUT_S_RANGE.end()),
    ] {
        assert!(idle.contains(&figure), "{figure}: {idle}");
    }

    // The words are the enums'.
    let refusals: Vec<String> = StreamRefusal::VARIANTS
        .iter()
        .map(|v| <&str>::from(v).to_string())
        .collect();
    assert_eq!(enum_words(&schema_block("StreamRefusal")), refusals);
    let drops: Vec<String> = DatagramDropReason::VARIANTS
        .iter()
        .map(|v| v.as_str().to_string())
        .collect();
    assert_eq!(enum_words(&schema_block("StreamDatagramDropReason")), drops);
    let kinds: Vec<String> = lorica_stream::BindFailureKind::ALL
        .iter()
        .map(|k| k.as_str().to_string())
        .collect();
    assert_eq!(enum_words(&schema_block("StreamBindFailureKind")), kinds);
    // `CeilingBound` lists no variants; this match fails to compile when
    // one is added, which is when this list must grow with it.
    use lorica_stream::budget::CeilingBound;
    let every_bound = |bound: &CeilingBound| match bound {
        CeilingBound::FdBudget | CeilingBound::SourcePorts => (),
    };
    let all_bounds = [CeilingBound::FdBudget, CeilingBound::SourcePorts];
    all_bounds.iter().for_each(every_bound);
    let bounds: Vec<String> = all_bounds
        .iter()
        .map(|b| {
            serde_json::to_value(b)
                .expect("serialises")
                .as_str()
                .expect("a word")
                .to_string()
        })
        .collect();
    assert_eq!(
        enum_words(&property_block(
            "NodeStreamBudget",
            "session_ceiling_bound_by"
        )),
        bounds
    );
}

#[test]
fn the_published_enums_and_ranges_are_the_models() {
    use lorica_config::models::{LoadBalancing, Stream, StreamProxyProtocol};
    use strum::VariantArray as _;

    let proxy: Vec<String> = enum_words(&schema_block("StreamProxyProtocol"));
    let model: Vec<String> = StreamProxyProtocol::VARIANTS
        .iter()
        .map(|v| v.as_str().to_string())
        .collect();
    assert_eq!(proxy, model);

    // `LoadBalancing` lists no variants; this match fails to compile
    // when one is added, which is when this list must grow with it.
    let every_algorithm = |lb: &LoadBalancing| match lb {
        LoadBalancing::RoundRobin
        | LoadBalancing::ConsistentHash
        | LoadBalancing::Random
        | LoadBalancing::PeakEwma
        | LoadBalancing::LeastConn => (),
    };
    let algorithms = [
        LoadBalancing::RoundRobin,
        LoadBalancing::ConsistentHash,
        LoadBalancing::Random,
        LoadBalancing::PeakEwma,
        LoadBalancing::LeastConn,
    ];
    algorithms.iter().for_each(every_algorithm);
    let published: BTreeSet<String> =
        enum_words(&property_block("StreamResponse", "load_balancing"))
            .into_iter()
            .collect();
    let model: BTreeSet<String> = algorithms.iter().map(|a| a.as_str().to_string()).collect();
    assert_eq!(published, model);

    for (field, start, end) in [
        (
            "connect_timeout_ms",
            u64::from(*Stream::CONNECT_TIMEOUT_MS_RANGE.start()),
            u64::from(*Stream::CONNECT_TIMEOUT_MS_RANGE.end()),
        ),
        (
            "idle_timeout_s",
            u64::from(*Stream::TCP_IDLE_TIMEOUT_S_RANGE.start()),
            u64::from(*Stream::TCP_IDLE_TIMEOUT_S_RANGE.end()),
        ),
        (
            "total_timeout_s",
            u64::from(*Stream::TOTAL_TIMEOUT_S_RANGE.start()),
            u64::from(*Stream::TOTAL_TIMEOUT_S_RANGE.end()),
        ),
        (
            "max_connect_attempts",
            u64::from(*Stream::MAX_CONNECT_ATTEMPTS_RANGE.start()),
            u64::from(*Stream::MAX_CONNECT_ATTEMPTS_RANGE.end()),
        ),
        (
            "backend_keepalive_idle_s",
            u64::from(*Stream::BACKEND_KEEPALIVE_IDLE_S_RANGE.start()),
            u64::from(*Stream::BACKEND_KEEPALIVE_IDLE_S_RANGE.end()),
        ),
        (
            "upload_rate_bps",
            *Stream::RATE_BPS_RANGE.start(),
            *Stream::RATE_BPS_RANGE.end(),
        ),
        (
            "download_rate_bps",
            *Stream::RATE_BPS_RANGE.start(),
            *Stream::RATE_BPS_RANGE.end(),
        ),
        (
            "max_connections",
            u64::from(*Stream::MAX_CONNECTIONS_RANGE.start()),
            u64::from(*Stream::MAX_CONNECTIONS_RANGE.end()),
        ),
        (
            "source_max_connections",
            u64::from(*Stream::SOURCE_MAX_CONNECTIONS_RANGE.start()),
            u64::from(*Stream::SOURCE_MAX_CONNECTIONS_RANGE.end()),
        ),
        (
            "max_pending_connections",
            u64::from(*Stream::MAX_PENDING_CONNECTIONS_RANGE.start()),
            u64::from(*Stream::MAX_PENDING_CONNECTIONS_RANGE.end()),
        ),
        (
            "source_open_rate",
            u64::from(*Stream::OPEN_RATE_RANGE.start()),
            u64::from(*Stream::OPEN_RATE_RANGE.end()),
        ),
        (
            "open_rate",
            u64::from(*Stream::OPEN_RATE_RANGE.start()),
            u64::from(*Stream::OPEN_RATE_RANGE.end()),
        ),
        (
            "backend_max_active",
            u64::from(*Stream::MAX_ACTIVE_RANGE.start()),
            u64::from(*Stream::MAX_ACTIVE_RANGE.end()),
        ),
    ] {
        let block = property_block("StreamResponse", field);
        assert_eq!(
            scalar(&block, "minimum"),
            Some(start.to_string().as_str()),
            "{field}"
        );
        assert_eq!(
            scalar(&block, "maximum"),
            Some(end.to_string().as_str()),
            "{field}"
        );
    }
    for (field, max) in [
        (
            "proxy_protocol_trusted_cidrs",
            Stream::PROXY_PROTOCOL_TRUSTED_CIDRS_MAX,
        ),
        ("source_addresses", Stream::SOURCE_ADDRESSES_MAX),
        ("source_allow_cidrs", Stream::SOURCE_CIDRS_MAX),
        ("source_deny_cidrs", Stream::SOURCE_CIDRS_MAX),
    ] {
        let block = property_block("StreamResponse", field);
        assert_eq!(
            scalar(&block, "maxItems"),
            Some(max.to_string().as_str()),
            "{field}"
        );
    }
}

#[test]
fn the_published_source_controls_are_the_models() {
    use lorica_config::models::{GeoIpConfig, GeoIpMode, Stream};

    // The pending share the prose states is the model's divisor.
    let pending = prose(&property_block("StreamResponse", "max_pending_connections"));
    assert!(
        pending.contains(&format!(
            "max(1, cap / {})",
            Stream::PENDING_SOURCE_SHARE_DIVISOR
        )),
        "{pending}"
    );

    // The GeoIP object publishes the model's fields, words and limit.
    // `GeoIpMode` lists no variants; this match fails to compile when
    // one is added, which is when this list must grow with it.
    let every_mode = |mode: &GeoIpMode| match mode {
        GeoIpMode::Allowlist | GeoIpMode::Denylist => (),
    };
    let modes = [GeoIpMode::Allowlist, GeoIpMode::Denylist];
    modes.iter().for_each(every_mode);
    let words: Vec<String> = modes
        .iter()
        .map(|mode| {
            serde_json::to_value(mode)
                .expect("serialises")
                .as_str()
                .expect("a word")
                .to_string()
        })
        .collect();
    assert_eq!(enum_words(&property_block("StreamGeoIp", "mode")), words);
    let geoip = serde_json::to_value(GeoIpConfig {
        mode: GeoIpMode::Denylist,
        countries: Vec::new(),
    })
    .expect("serialises");
    assert_eq!(schema_properties("StreamGeoIp"), keys(&geoip));
    assert_eq!(
        scalar(&property_block("StreamGeoIp", "countries"), "maxItems"),
        Some(GeoIpConfig::COUNTRIES_MAX.to_string().as_str())
    );
}

/// Every `default:` the description publishes for a stream setting is
/// what a stream created without it holds.
#[test]
fn the_published_defaults_are_the_models() {
    let stream = lorica_config::models::Stream::new(
        "00000000-0000-4000-8000-000000000000".to_string(),
        "defaults".to_string(),
        lorica_config::models::StreamProtocol::Tcp,
        "0.0.0.0".parse().expect("an address"),
        5432,
        5432,
        Utc::now(),
    );
    let view = serde_json::to_value(super::stream_to_response(&stream, StreamLinks::default()))
        .expect("serialises");
    let mut checked = 0;
    for property in schema_properties("StreamResponse") {
        let block = property_block("StreamResponse", &property);
        let Some(published) = scalar(&block, "default") else {
            continue;
        };
        let model = match &view[&property] {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        assert_eq!(published, model, "{property}");
        checked += 1;
    }
    assert!(checked > 0, "the scan found no default");
}

// ---- TLS at layer 4 (Story 12.4 Lot F) ----

/// A self-signed leaf for `names`, DNS names or IP literals, and its
/// key, as PEM.
fn certificate_pems(names: &[&str]) -> (String, String) {
    let names: Vec<String> = names.iter().map(|name| name.to_string()).collect();
    let params = rcgen::CertificateParams::new(names).expect("test setup: names");
    let key = rcgen::KeyPair::generate().expect("test setup: key");
    let certificate = params.self_signed(&key).expect("test setup: certificate");
    (certificate.pem(), key.serialize_pem())
}

/// The parameters of a CA named `name`.
fn ca_params(name: &str) -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("test setup");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
}

/// One self-signed CA, as PEM: a client CA bundle that trusts only
/// itself.
fn single_ca_pem() -> String {
    let key = rcgen::KeyPair::generate().expect("test setup: key");
    ca_params("Stream Client CA")
        .self_signed(&key)
        .expect("test setup: CA")
        .pem()
}

/// A root and the CA it issued, as one PEM bundle: the shape the 1.10.3
/// check warns about.
fn root_and_issuing_ca_pem() -> String {
    let root_key = rcgen::KeyPair::generate().expect("test setup: key");
    let root_params = ca_params("Stream Test Root");
    let root = root_params
        .self_signed(&root_key)
        .expect("test setup: root");
    let root_issuer = rcgen::Issuer::new(root_params, root_key);
    let issuing_key = rcgen::KeyPair::generate().expect("test setup: key");
    let issuing = ca_params("Stream Test Issuing")
        .signed_by(&issuing_key, &root_issuer)
        .expect("test setup: issuing CA");
    format!("{}{}", root.pem(), issuing.pem())
}

impl Node {
    /// Upload a certificate for `names`, its domain the first; answer
    /// its id.
    async fn certificate(&self, names: &[&str]) -> String {
        let (cert_pem, key_pem) = certificate_pems(names);
        let (status, answer) = self
            .call(
                "POST",
                "/api/v1/certificates",
                Some(json!({ "domain": names[0], "cert_pem": cert_pem, "key_pem": key_pem })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{answer}");
        answer["data"]["id"].as_str().expect("an id").to_string()
    }

    /// The links of stream `id` as stored, sorted.
    async fn stored_links(&self, id: &str) -> Vec<lorica_config::models::StreamBackend> {
        self.state
            .store
            .lock()
            .await
            .list_stream_backends()
            .expect("links")
            .into_iter()
            .filter(|link| link.stream_id == id)
            .collect()
    }
}

/// A TCP stream on `port` in `mode` routing by `rules`.
fn tls_stream(name: &str, port: u16, mode: &str, rules: Value) -> Value {
    let mut body = tcp(name, port);
    body["tls_mode"] = json!(mode);
    body["match_rules"] = rules;
    body
}

/// A `tls` rule named `name` for `server_names`, served by `backends`.
fn tls_rule(name: &str, server_names: &[&str], backends: &[&String]) -> Value {
    json!({
        "name": name,
        "matcher": { "kind": "tls", "server_names": server_names },
        "backend_ids": backends,
    })
}

/// A terminating stream that sets every TLS field: a rule spelled in a
/// form the store canonicalises, a client CA, and upstream TLS
/// presenting a stored client certificate.
async fn terminating_body(node: &Node) -> Value {
    let backend = node.backend("192.0.2.60:8443").await;
    let served = node.certificate(&["app.example.com"]).await;
    let client = node.certificate(&["client.example.com"]).await;
    let mut body = tls_stream(
        "tls-edge",
        8443,
        "terminate",
        json!([{
            "name": "app",
            "matcher": { "kind": "tls", "server_names": ["App.Example.com."], "alpn": ["h2"] },
            "backend_ids": [backend],
        }]),
    );
    body["clienthello_timeout_ms"] = json!(3000);
    body["tls_terminate"] = json!({
        "certificate_ids": [served],
        "client_auth": {
            "ca_cert_pem": single_ca_pem(),
            "required": true,
            "allowed_organizations": ["Example Corp"],
        },
    });
    body["upstream_tls"] = json!({
        "server_name": { "mode": "fixed", "name": "backend.example.com" },
        "client_certificate_id": client,
        "alpn": ["h2"],
    });
    body
}

#[tokio::test]
async fn a_terminating_stream_answers_its_tls_fields_and_never_a_key() {
    let node = Node::standalone().await;
    let created = node.created(terminating_body(&node).await).await;
    assert_eq!(created["tls_mode"], "terminate");
    assert_eq!(created["drains_on_upgrade"], true);
    assert_eq!(
        created["match_rules"][0]["matcher"]["server_names"],
        json!(["app.example.com"]),
        "a server name is answered as it is stored"
    );
    assert_eq!(created["backend_ids"], json!([]), "the links are per rule");
    assert_eq!(created["clienthello_timeout_ms"], 3000);
    assert!(
        created["upstream_tls"]["client_certificate_id"].is_string(),
        "a client certificate by id: {created}"
    );
    let text = created.to_string();
    assert!(!text.contains("PRIVATE KEY"), "no key in the view: {text}");

    // A stream that terminates nothing and opens no TLS does not drain
    // for its TLS; one that only originates does.
    let plain = node.created(tcp("plain", 2525)).await;
    assert_eq!(plain["drains_on_upgrade"], false);
    let id = plain["id"].as_str().expect("an id");
    let (status, originating) = node
        .update(id, json!({ "upstream_tls": { "skip_verify": true } }))
        .await;
    assert_eq!(status, StatusCode::OK, "{originating}");
    assert_eq!(originating["data"]["drains_on_upgrade"], true);
    assert_eq!(
        originating["data"]["upstream_tls"]["server_name"],
        json!({ "mode": "backend_address" }),
        "the default name"
    );
    let (status, cleared) = node.update(id, json!({ "upstream_tls": null })).await;
    assert_eq!(status, StatusCode::OK, "{cleared}");
    assert_eq!(cleared["data"]["upstream_tls"], Value::Null);
    assert_eq!(cleared["data"]["drains_on_upgrade"], false);
}

#[tokio::test]
async fn a_tls_streams_links_travel_inside_its_rules() {
    let node = Node::standalone().await;
    let first = node.backend("192.0.2.70:443").await;
    let second = node.backend("192.0.2.71:443").await;
    let third = node.backend("192.0.2.72:443").await;
    let mut web = tls_rule("web", &["a.example.com"], &[&first]);
    web["backup_backend_ids"] = json!([second]);
    // A rule with no backend is accepted, as a stream with none is.
    let legacy = tls_rule("legacy", &["*.example.com"], &[]);
    let created = node
        .created(tls_stream("sni", 8443, "passthrough", json!([web, legacy])))
        .await;
    let id = created["id"].as_str().expect("an id").to_string();
    assert_eq!(created["backend_ids"], json!([]));
    assert_eq!(created["backup_backend_ids"], json!([]));
    assert_eq!(
        created["drains_on_upgrade"], false,
        "passthrough holds no TLS state"
    );
    assert_eq!(created["match_rules"][0]["backend_ids"], json!([first]));
    assert_eq!(
        created["match_rules"][0]["backup_backend_ids"],
        json!([second])
    );
    assert_eq!(created["match_rules"][1]["backend_ids"], json!([]));
    let rules_of = |links: Vec<lorica_config::models::StreamBackend>| {
        let mut rules: Vec<(String, bool, Option<String>)> = links
            .into_iter()
            .map(|l| (l.backend_id, l.backup, l.rule))
            .collect();
        rules.sort();
        rules
    };
    let mut expected = vec![
        (first.clone(), false, Some("web".to_string())),
        (second.clone(), true, Some("web".to_string())),
    ];
    expected.sort();
    assert_eq!(rules_of(node.stored_links(&id).await), expected);

    // `match_rules` replaces the rules and every link; left out, both
    // stay.
    let (status, moved) = node
        .update(
            &id,
            json!({ "match_rules": [
                tls_rule("web", &["a.example.com"], &[&third]),
                tls_rule("legacy", &["*.example.com"], &[&first]),
            ] }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{moved}");
    let mut expected = vec![
        (third.clone(), false, Some("web".to_string())),
        (first.clone(), false, Some("legacy".to_string())),
    ];
    expected.sort();
    assert_eq!(rules_of(node.stored_links(&id).await), expected);
    let (status, kept) = node.update(&id, json!({ "enabled": false })).await;
    assert_eq!(status, StatusCode::OK, "{kept}");
    assert_eq!(kept["data"]["match_rules"], moved["data"]["match_rules"]);

    // Refused, and nothing moves: a stream-level list on a TLS stream, a
    // backend serving two rules, a rule served by backups alone.
    let backup_only = {
        let mut rule = tls_rule("web", &["a.example.com"], &[]);
        rule["backup_backend_ids"] = json!([third]);
        rule
    };
    for (what, body, words) in [
        (
            "a stream-level primary",
            json!({ "backend_ids": [first] }),
            vec!["backend_ids", "passthrough", "match_rules"],
        ),
        (
            "a stream-level backup",
            json!({ "backup_backend_ids": [first] }),
            vec!["backup_backend_ids", "passthrough"],
        ),
        (
            "one backend for two rules",
            json!({ "match_rules": [
                tls_rule("web", &["a.example.com"], &[&first]),
                tls_rule("legacy", &["*.example.com"], &[&first]),
            ] }),
            vec![first.as_str()],
        ),
        (
            "a rule with backups alone",
            json!({ "match_rules": [backup_only] }),
            vec!["backup", "primary"],
        ),
        (
            "a backend both primary and backup of a rule",
            json!({ "match_rules": [{
                "name": "web",
                "matcher": { "kind": "tls", "server_names": ["a.example.com"] },
                "backend_ids": [first],
                "backup_backend_ids": [first],
            }] }),
            vec!["web", first.as_str()],
        ),
        (
            "leaving TLS with the rules' links",
            json!({ "tls_mode": "none", "match_rules": [] }),
            vec!["reads no ClientHello"],
        ),
    ] {
        let (status, answer) = node.update(&id, body).await;
        let message = unprocessable(status, &answer);
        for word in words {
            assert!(message.contains(word), "{what}: {word}: {message}");
        }
        assert_eq!(
            rules_of(node.stored_links(&id).await),
            expected,
            "{what}: nothing moved"
        );
    }
    let (status, answer) = node
        .create(merged(
            tls_stream(
                "sni-2",
                8444,
                "passthrough",
                json!([tls_rule("web", &["b.example.com"], &[])]),
            ),
            &json!({ "backend_ids": [second] }),
        ))
        .await;
    assert!(
        unprocessable(status, &answer).contains("backend_ids"),
        "{answer}"
    );

    // Leaving TLS: the rules go, and the links with them, in one write.
    let (status, plain) = node
        .update(
            &id,
            json!({ "tls_mode": "none", "match_rules": [], "backend_ids": [second] }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{plain}");
    assert_eq!(
        rules_of(node.stored_links(&id).await),
        vec![(second.clone(), false, None)]
    );
    assert_eq!(plain["data"]["match_rules"], json!([]));
}

#[tokio::test]
async fn every_tls_field_a_mode_does_not_take_is_refused_naming_field_and_mode() {
    let node = Node::standalone().await;
    let certificate = node.certificate(&["app.example.com"]).await;
    let rules = json!([tls_rule("app", &["app.example.com"], &[])]);
    let no_sni = json!([{ "name": "any", "matcher": { "kind": "no_sni" } }]);
    let terminate = json!({ "certificate_ids": [certificate] });
    let on = |base: Value, patch: Value| merged(base, &patch);
    let none = || tcp("plain", 2600);
    let passthrough = || tls_stream("sni", 2601, "passthrough", rules.clone());
    let udp_stream = || udp("dns", 2602);
    for (what, body, words) in [
        (
            "rules on none",
            on(none(), json!({ "match_rules": rules })),
            vec!["match_rules", "none"],
        ),
        (
            "a ClientHello deadline on none",
            on(none(), json!({ "clienthello_timeout_ms": 5000 })),
            vec!["clienthello_timeout_ms", "none"],
        ),
        (
            "termination on none",
            on(none(), json!({ "tls_terminate": terminate })),
            vec!["tls_terminate", "none"],
        ),
        (
            "the client's name upstream on none",
            on(
                none(),
                json!({ "upstream_tls": { "server_name": { "mode": "client" } } }),
            ),
            vec!["upstream_tls.server_name client", "none"],
        ),
        (
            "an acknowledgement without a no_sni rule",
            on(none(), json!({ "no_sni_acknowledged": true })),
            vec!["no_sni_acknowledged"],
        ),
        (
            "passthrough without rules",
            on(none(), json!({ "tls_mode": "passthrough" })),
            vec!["match_rules", "passthrough"],
        ),
        (
            "termination on passthrough",
            on(passthrough(), json!({ "tls_terminate": terminate })),
            vec!["tls_terminate", "passthrough"],
        ),
        (
            "upstream TLS on passthrough",
            on(passthrough(), json!({ "upstream_tls": {} })),
            vec!["upstream_tls", "passthrough"],
        ),
        (
            "terminate without its certificates",
            tls_stream("tls", 2603, "terminate", rules.clone()),
            vec!["tls_terminate", "terminate"],
        ),
        (
            "a no_sni rule unacknowledged",
            tls_stream("tls", 2603, "passthrough", no_sni.clone()),
            vec!["no_sni_acknowledged", "source allowlist"],
        ),
        (
            "a ClientHello deadline below its range",
            on(
                passthrough(),
                json!({
                    "clienthello_timeout_ms":
                        lorica_config::models::Stream::CLIENTHELLO_TIMEOUT_MS_RANGE.start() - 1
                }),
            ),
            vec!["clienthello_timeout_ms"],
        ),
        (
            "skip_verify with a client certificate",
            on(
                none(),
                json!({ "upstream_tls": {
                    "skip_verify": true, "client_certificate_id": certificate,
                } }),
            ),
            vec!["skip_verify", "client_certificate_id"],
        ),
        (
            "TLS on UDP",
            on(
                udp_stream(),
                json!({ "tls_mode": "passthrough", "match_rules": rules }),
            ),
            vec!["tls_mode", "UDP"],
        ),
        (
            "upstream TLS on UDP",
            on(udp_stream(), json!({ "upstream_tls": {} })),
            vec!["upstream_tls", "UDP"],
        ),
    ] {
        let (status, answer) = node.create(body).await;
        let message = unprocessable(status, &answer);
        for word in words {
            assert!(message.contains(word), "{what}: {word}: {message}");
        }
    }
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
}

#[tokio::test]
async fn certificate_coverage_follows_the_lookup_the_handshake_runs() {
    let node = Node::standalone().await;
    let exact = node.certificate(&["app.example.com"]).await;
    let wildcard = node.certificate(&["*.example.com"]).await;
    let terminating = |name: &str, server_name: &str, certificate: &str| {
        let mut body = tls_stream(
            name,
            9000,
            "terminate",
            json!([tls_rule("site", &[server_name], &[])]),
        );
        body["tls_terminate"] = json!({ "certificate_ids": [certificate] });
        body
    };
    let mut port = 9000;
    let mut write = |name: &str, server_name: &str, certificate: &str| {
        port += 1;
        let mut body = terminating(name, server_name, certificate);
        body["port_first"] = json!(port);
        body
    };

    // Served: the exact name, a name one label under a wildcard
    // certificate, and a wildcard rule by that wildcard itself, which
    // warns that the rule routes deeper names than it serves.
    for (what, body) in [
        ("exact", write("exact", "app.example.com", &exact)),
        (
            "one label",
            write("one-label", "api.example.com", &wildcard),
        ),
    ] {
        let (status, answer) = node.create(body).await;
        assert_eq!(status, StatusCode::CREATED, "{what}: {answer}");
        assert!(answer["data"].get("warnings").is_none(), "{what}: {answer}");
    }
    let (status, answer) = node
        .create(write("wildcard", "*.example.com", &wildcard))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{answer}");
    let warnings = answer["data"]["warnings"].to_string();
    for word in [
        "`site`",
        "*.example.com",
        "every depth",
        "a.b.example.com",
        "no_certificate",
    ] {
        assert!(warnings.contains(word), "{word}: {warnings}");
    }

    // Not served: another exact name, two labels under a wildcard
    // certificate, a wildcard rule over an exact certificate, and a
    // deeper wildcard rule over a wildcard certificate.
    for (what, body, name, certificate) in [
        (
            "another name",
            write("miss-exact", "www.example.org", &exact),
            "www.example.org",
            &exact,
        ),
        (
            "two labels",
            write("miss-depth", "a.b.example.com", &wildcard),
            "a.b.example.com",
            &wildcard,
        ),
        (
            "a wildcard over an exact certificate",
            write("miss-wild", "*.example.com", &exact),
            "*.example.com",
            &exact,
        ),
        (
            "a deeper wildcard",
            write("miss-deep", "*.b.example.com", &wildcard),
            "*.b.example.com",
            &wildcard,
        ),
    ] {
        let (status, answer) = node.create(body).await;
        let message = unprocessable(status, &answer);
        for word in ["`site`", name, certificate.as_str()] {
            assert!(message.contains(word), "{what}: {word}: {message}");
        }
    }

    // A certificate that does not exist, on either field.
    let (status, answer) = node
        .create(write("missing", "app.example.com", "no-such-certificate"))
        .await;
    let message = unprocessable(status, &answer);
    assert!(
        message.contains("tls_terminate.certificate_ids"),
        "{message}"
    );
    assert!(message.contains("no-such-certificate"), "{message}");
    let mut body = tcp("origin", 9100);
    body["upstream_tls"] = json!({ "client_certificate_id": "no-such-certificate" });
    let (status, answer) = node.create(body).await;
    assert!(
        unprocessable(status, &answer).contains("upstream_tls.client_certificate_id"),
        "{answer}"
    );

    // An update is checked as a create is.
    let id = created_id_of(&node, "exact").await;
    let (status, answer) = node
        .update(
            &id,
            json!({ "match_rules": [tls_rule("site", &["www.example.org"], &[])] }),
        )
        .await;
    assert!(
        unprocessable(status, &answer).contains("www.example.org"),
        "{answer}"
    );
}

#[tokio::test]
async fn a_no_sni_rule_on_a_terminating_stream_needs_an_address_certificate() {
    let node = Node::standalone().await;
    let named = node.certificate(&["app.example.com"]).await;
    let addressed = node.certificate(&["192.0.2.10"]).await;
    let body = |listen: &str, port: u16, certificate: &str| {
        let mut body = tls_stream(
            "bare",
            port,
            "terminate",
            json!([{ "name": "any", "matcher": { "kind": "no_sni" } }]),
        );
        body["listen_address"] = json!(listen);
        body["no_sni_acknowledged"] = json!(true);
        body["tls_terminate"] = json!({ "certificate_ids": [certificate] });
        body
    };
    let (status, answer) = node.create(body("0.0.0.0", 9200, &named)).await;
    let message = unprocessable(status, &answer);
    for word in ["`any`", "IP address SAN", named.as_str()] {
        assert!(message.contains(word), "{word}: {message}");
    }
    let (status, answer) = node.create(body("192.0.2.20", 9200, &addressed)).await;
    assert!(
        unprocessable(status, &answer).contains("192.0.2.20"),
        "the listen address is named: {answer}"
    );
    for (listen, port) in [("0.0.0.0", 9201), ("192.0.2.10", 9202)] {
        let mut accepted = body(listen, port, &addressed);
        accepted["name"] = json!(format!("bare-{port}"));
        let (status, answer) = node.create(accepted).await;
        assert_eq!(status, StatusCode::CREATED, "{listen}: {answer}");
    }
}

#[tokio::test]
async fn the_pem_bundles_are_checked_as_a_routes_and_a_widening_bundle_is_warned() {
    let node = Node::standalone().await;
    let certificate = node.certificate(&["app.example.com"]).await;
    let with_client_ca = |name: &str, port: u16, ca: &str| {
        let mut body = tls_stream(
            name,
            port,
            "terminate",
            json!([tls_rule("app", &["app.example.com"], &[])]),
        );
        body["tls_terminate"] = json!({
            "certificate_ids": [certificate],
            "client_auth": { "ca_cert_pem": ca, "allowed_organizations": [" Example Corp ", "Example Corp"] },
        });
        body
    };

    // A root next to the CA it issued saves, and the write says what it
    // trusts beyond the bundle, speaking of the stream.
    let bundle = root_and_issuing_ca_pem();
    let (status, answer) = node
        .create(with_client_ca("wide", 9300, &format!("\n{bundle}\n")))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{answer}");
    let warnings = answer["data"]["warnings"].to_string();
    for word in [
        "`wide`",
        "tls_terminate.client_auth.ca_cert_pem",
        "Stream Test Root",
        "self-signed root",
        "this stream",
    ] {
        assert!(warnings.contains(word), "{word}: {warnings}");
    }
    assert!(!warnings.contains("route"), "{warnings}");
    let client_auth = &answer["data"]["tls_terminate"]["client_auth"];
    assert_eq!(
        client_auth["ca_cert_pem"],
        bundle.trim(),
        "stored as the route validator leaves it"
    );
    assert_eq!(
        client_auth["allowed_organizations"],
        json!(["Example Corp"])
    );

    // One CA trusts only itself: no warning.
    let (status, answer) = node
        .create(with_client_ca("narrow", 9301, &single_ca_pem()))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{answer}");
    assert!(answer["data"].get("warnings").is_none(), "{answer}");

    // A block that is no X.509 certificate passes the model's shape check
    // and is refused here, naming the stream's own field.
    let junk = "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n";
    let (status, answer) = node.create(with_client_ca("junk", 9302, junk)).await;
    let message = unprocessable(status, &answer);
    assert!(
        message.contains("tls_terminate.client_auth.ca_cert_pem") && !message.contains("mtls."),
        "{message}"
    );
    let mut body = tcp("origin", 9303);
    body["upstream_tls"] = json!({ "ca_cert_pem": junk });
    let (status, answer) = node.create(body).await;
    let message = unprocessable(status, &answer);
    assert!(message.contains("upstream_tls.ca_cert_pem"), "{message}");

    // A server CA bundle may hold a root: trusting one is its purpose.
    let mut body = tcp("origin", 9303);
    body["upstream_tls"] = json!({ "ca_cert_pem": bundle });
    let (status, answer) = node.create(body).await;
    assert_eq!(status, StatusCode::CREATED, "{answer}");
    assert!(answer["data"].get("warnings").is_none(), "{answer}");
}

#[tokio::test]
async fn a_certificate_a_stream_names_cannot_be_deleted() {
    let node = Node::standalone().await;
    let created = node.created(terminating_body(&node).await).await;
    let served = created["tls_terminate"]["certificate_ids"][0]
        .as_str()
        .expect("an id")
        .to_string();
    let client = created["upstream_tls"]["client_certificate_id"]
        .as_str()
        .expect("an id")
        .to_string();
    for certificate in [&served, &client] {
        let (status, answer) = node
            .call(
                "DELETE",
                &format!("/api/v1/certificates/{certificate}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{answer}");
        let message = answer["error"]["message"].as_str().expect("a message");
        assert!(
            message.contains("tls-edge"),
            "the stream is named: {message}"
        );
    }
    let id = created["id"].as_str().expect("an id");
    let (status, _) = node
        .call("DELETE", &format!("/api/v1/streams/{id}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    for certificate in [&served, &client] {
        let (status, answer) = node
            .call(
                "DELETE",
                &format!("/api/v1/certificates/{certificate}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{answer}");
    }
}

#[tokio::test]
async fn an_import_and_its_preview_run_the_tls_checks() {
    let node = Node::standalone().await;
    let terminating = |certificate: &str| {
        let mut stream = lorica_config::models::Stream::new(
            uuid::Uuid::new_v4().to_string(),
            "imported".to_string(),
            lorica_config::models::StreamProtocol::Tcp,
            "0.0.0.0".parse().expect("an address"),
            9400,
            9400,
            Utc::now(),
        );
        stream.tls_mode = lorica_config::models::StreamTlsMode::Terminate;
        stream.match_rules = vec![lorica_config::models::StreamMatchRule {
            name: "site".to_string(),
            matcher: lorica_config::models::StreamMatcher::Tls {
                server_names: vec!["*.example.com".to_string()],
                alpn: Vec::new(),
            },
        }];
        stream.tls_terminate = Some(lorica_config::models::StreamTlsTerminate {
            certificate_ids: vec![certificate.to_string()],
            client_auth: None,
        });
        stream
    };

    // The file names a certificate it does not carry: both refuse.
    let ((preview_status, preview), (import_status, import)) = preview_and_import(
        &node,
        export_with(&[terminating("absent-certificate")], None),
    )
    .await;
    for (status, answer) in [(preview_status, &preview), (import_status, &import)] {
        let message = unprocessable(status, answer);
        assert!(message.contains("absent-certificate"), "{message}");
    }

    // The file carries it: the preview passes, with the wildcard
    // warning a write answers. A node of its own: the import and its
    // preview share one rate budget.
    let node = Node::standalone().await;
    let source = lorica_config::ConfigStore::open_in_memory().expect("source");
    let (cert_pem, key_pem) = certificate_pems(&["*.example.com"]);
    let now = Utc::now();
    let mut certificate = lorica_config::models::Certificate {
        id: uuid::Uuid::new_v4().to_string(),
        domain: "*.example.com".to_string(),
        san_domains: vec!["*.example.com".to_string()],
        fingerprint: "fp".to_string(),
        cert_pem,
        key_pem,
        issuer: "test".to_string(),
        not_before: now,
        not_after: now + chrono::Duration::days(30),
        is_acme: false,
        acme_auto_renew: false,
        created_at: now,
        acme_method: None,
        acme_dns_provider_id: None,
        adcs_authority_id: None,
        adcs_template: None,
        adcs_template_oid: None,
        adcs_request_id: None,
    };
    source
        .create_certificate(&certificate)
        .expect("test setup: certificate");
    source
        .create_stream(&terminating(&certificate.id))
        .expect("test setup: stream");
    let file = lorica_config::export::export_to_toml(&source).expect("export");
    let (status, preview) = node
        .call(
            "POST",
            "/api/v1/config/import/preview",
            Some(json!({ "toml_content": file })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert!(
        preview["data"]["warnings"]
            .to_string()
            .contains("every depth"),
        "{preview}"
    );

    // A file whose certificate no longer covers the rule is refused.
    certificate.domain = "www.example.org".to_string();
    certificate.san_domains = vec!["www.example.org".to_string()];
    let source = lorica_config::ConfigStore::open_in_memory().expect("source");
    source
        .create_certificate(&certificate)
        .expect("test setup: certificate");
    source
        .create_stream(&terminating(&certificate.id))
        .expect("test setup: stream");
    let file = lorica_config::export::export_to_toml(&source).expect("export");
    let (status, preview) = node
        .call(
            "POST",
            "/api/v1/config/import/preview",
            Some(json!({ "toml_content": file })),
        )
        .await;
    assert!(
        unprocessable(status, &preview).contains("*.example.com"),
        "{preview}"
    );
}

#[test]
fn the_published_tls_words_and_limits_are_the_models() {
    use lorica_config::models::{Stream, StreamMatcher, StreamTlsMode, UpstreamServerName};
    use strum::VariantArray as _;

    let modes: Vec<String> = StreamTlsMode::VARIANTS
        .iter()
        .map(|mode| mode.as_str().to_string())
        .collect();
    assert_eq!(enum_words(&schema_block("StreamTlsMode")), modes);

    // `StreamMatcher` and `UpstreamServerName` carry data, so they list
    // no variants; these matches fail to compile when one is added,
    // which is when the lists must grow with it.
    let every_matcher = |matcher: &StreamMatcher| match matcher {
        StreamMatcher::Tls { .. } | StreamMatcher::NoSni { .. } => matcher.kind(),
    };
    let matchers = [
        StreamMatcher::Tls {
            server_names: Vec::new(),
            alpn: Vec::new(),
        },
        StreamMatcher::NoSni { alpn: Vec::new() },
    ];
    assert_eq!(
        enum_words(&property_block("StreamTlsMatcher", "kind")),
        vec![every_matcher(&matchers[0]).to_string()]
    );
    assert_eq!(
        enum_words(&property_block("StreamNoSniMatcher", "kind")),
        vec![every_matcher(&matchers[1]).to_string()]
    );
    let every_name = |name: &UpstreamServerName| match name {
        UpstreamServerName::BackendAddress {}
        | UpstreamServerName::Client {}
        | UpstreamServerName::Fixed { .. } => name.mode().to_string(),
    };
    let names: Vec<String> = [
        UpstreamServerName::BackendAddress {},
        UpstreamServerName::Client {},
        UpstreamServerName::Fixed {
            name: String::new(),
        },
    ]
    .iter()
    .map(every_name)
    .collect();
    assert_eq!(
        enum_words(&property_block("StreamUpstreamServerName", "mode")),
        names
    );
    assert_eq!(
        serde_json::to_value(UpstreamServerName::default()).expect("serialises")["mode"],
        names[0],
        "the first mode published is the default"
    );

    let deadline = property_block("StreamResponse", "clienthello_timeout_ms");
    let range = Stream::CLIENTHELLO_TIMEOUT_MS_RANGE;
    assert_eq!(
        scalar(&deadline, "minimum"),
        Some(range.start().to_string().as_str())
    );
    assert_eq!(
        scalar(&deadline, "maximum"),
        Some(range.end().to_string().as_str())
    );
    let deadline_prose = prose(&deadline);
    assert!(
        deadline_prose.contains(&format!(
            "`null` is {}",
            Stream::DEFAULT_CLIENTHELLO_TIMEOUT_MS
        )),
        "{deadline_prose}"
    );
    for (schema, property, key, limit) in [
        (
            "StreamResponse",
            "match_rules",
            "maxItems",
            Stream::MATCH_RULES_MAX,
        ),
        (
            "StreamMatchRule",
            "name",
            "maxLength",
            Stream::MATCH_RULE_NAME_MAX_LEN,
        ),
        (
            "StreamTlsMatcher",
            "server_names",
            "maxItems",
            Stream::RULE_SERVER_NAMES_MAX,
        ),
        ("StreamTlsMatcher", "alpn", "maxItems", Stream::ALPN_MAX),
        ("StreamUpstreamTls", "alpn", "maxItems", Stream::ALPN_MAX),
        (
            "StreamTlsTerminate",
            "certificate_ids",
            "maxItems",
            Stream::TERMINATE_CERTIFICATES_MAX,
        ),
        (
            "StreamClientAuth",
            "allowed_organizations",
            "maxItems",
            Stream::ALLOWED_ORGANIZATIONS_MAX,
        ),
    ] {
        assert_eq!(
            scalar(&property_block(schema, property), key),
            Some(limit.to_string().as_str()),
            "{schema}.{property}"
        );
    }
    let rules = prose(&property_block("StreamResponse", "match_rules"));
    assert!(
        rules.contains(&format!(
            "at most {} server names",
            Stream::SERVER_NAMES_MAX
        )),
        "{rules}"
    );
    let alpn = prose(&property_block("StreamTlsMatcher", "alpn"));
    assert!(
        alpn.contains(&format!("1 to {} bytes", Stream::ALPN_PROTOCOL_MAX_LEN)),
        "{alpn}"
    );

    // Every nested TLS object publishes exactly the fields the view
    // answers, the model's own.
    let terminate = serde_json::to_value(lorica_config::models::StreamTlsTerminate {
        certificate_ids: Vec::new(),
        client_auth: None,
    })
    .expect("serialises");
    assert_eq!(schema_properties("StreamTlsTerminate"), keys(&terminate));
    let client_auth = serde_json::to_value(lorica_config::models::MtlsConfig {
        ca_cert_pem: String::new(),
        required: false,
        allowed_organizations: Vec::new(),
    })
    .expect("serialises");
    assert_eq!(schema_properties("StreamClientAuth"), keys(&client_auth));
    let upstream = serde_json::to_value(lorica_config::models::StreamUpstreamTls::default())
        .expect("serialises");
    assert_eq!(schema_properties("StreamUpstreamTls"), keys(&upstream));
    let rule: BTreeSet<String> = ["name", "matcher"]
        .iter()
        .chain(LINK_FIELDS)
        .map(|k| k.to_string())
        .collect();
    assert_eq!(schema_properties("StreamMatchRule"), rule);
}

// ---- The stream status (Story 12.10 Lot A) ----

/// Store `stream` directly, past the write checks the status does not
/// concern.
async fn stored(node: &Node, stream: &lorica_config::models::Stream) {
    node.state
        .store
        .lock()
        .await
        .create_stream(stream)
        .expect("test setup: stream");
}

/// The status entry of `id` in an answer of `GET /api/v1/streams/status`.
fn status_entry(answer: &Value, id: &str) -> Value {
    answer["data"]["streams"]
        .as_array()
        .expect("a list")
        .iter()
        .find(|s| s["id"] == id)
        .unwrap_or_else(|| panic!("{id} has no status: {answer}"))
        .clone()
}

/// A Viewer's cookie on `node`.
async fn viewer(node: &Node) -> String {
    create_user_and_login(
        &node.state,
        &node.sessions,
        &node.limiter,
        "viewer01",
        Role::Viewer,
    )
    .await
}

#[tokio::test]
async fn a_viewer_reads_the_status_of_a_standalone_node_without_nodes() {
    let mut node = Node::standalone().await;
    let states = lorica_stream::StreamBindStates::new();
    node.state.stream_plane = plane_at(states.clone(), 65_536, 2);
    let pg = source_stream("pg", 5432);
    let off = source_stream("off", 5433);
    stored(&node, &pg).await;
    stored(&node, &off).await;
    states.set_bound(&pg.id, 2, 2);

    let cookie = viewer(&node).await;
    let (status, answer) = node
        .call_as(&cookie, "GET", "/api/v1/streams/status", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let entry = status_entry(&answer, &pg.id);
    assert_eq!(entry["name"], "pg");
    assert_eq!(entry["protocol"], "tcp");
    assert_eq!(
        entry["bind"],
        serde_json::to_value(states.get(&pg.id)).expect("serialises"),
        "the value the stream reads carry"
    );
    assert_eq!(entry["nodes"], Value::Null, "no fleet to list");
    assert_eq!(entry["counters"], Value::Null, "nothing counted it yet");
    assert_eq!(status_entry(&answer, &off.id)["bind"], Value::Null);
}

#[tokio::test]
async fn a_follower_answers_its_own_counters_labelled_with_its_name_and_no_nodes() {
    let node = Node::follower().await;
    let pg = source_stream("pg", 5432);
    stored(&node, &pg).await;
    let counters = lorica_stream::StreamCounters::new();
    drop(counters.stream(&pg.id).accept());
    let collector = crate::stream_metrics::StreamMetricsCollector::new();
    collector.apply_worker(1, &counters.snapshot());

    let statuses = super::status::stream_statuses(&node.state, &collector)
        .await
        .expect("statuses");
    let entry = serde_json::to_value(&statuses[0]).expect("serialises");
    let crate::cluster::ClusterRuntime::Follower(follower) = &node.state.cluster else {
        panic!("a follower");
    };
    assert_eq!(entry["nodes"], Value::Null);
    assert_eq!(entry["counters"]["node_name"], follower.node_name.as_str());
    assert_eq!(entry["counters"]["accepted_total"], 1);
}

#[tokio::test]
async fn a_control_plane_lists_each_active_node_that_binds_the_stream() {
    let node = Node::control_plane().await;
    node.enrol("edge-2", NodeStatus::Active, None).await;
    node.enrol("edge-1", NodeStatus::Active, None).await;
    node.enrol("edge-3", NodeStatus::Pending, None).await;
    let fleet_wide = source_stream("dns", 5353);
    let mut pinned = source_stream("pg", 5432);
    pinned.node_selector = vec!["edge-2".to_string()];
    let mut nowhere = source_stream("smtp", 2525);
    nowhere.node_selector = vec!["edge-9".to_string()];
    for s in [&fleet_wide, &pinned, &nowhere] {
        stored(&node, s).await;
    }

    let cookie = viewer(&node).await;
    let (status, answer) = node
        .call_as(&cookie, "GET", "/api/v1/streams/status", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let on = |id: &str| -> Vec<(String, String)> {
        status_entry(&answer, id)["nodes"]
            .as_array()
            .expect("nodes on a control plane")
            .iter()
            .map(|n| {
                (
                    n["node_name"].as_str().expect("a name").to_string(),
                    n["state"].as_str().expect("a state").to_string(),
                )
            })
            .collect()
    };
    let unknown = |name: &str| (name.to_string(), "unknown".to_string());
    assert_eq!(
        on(&fleet_wide.id),
        vec![unknown("edge-1"), unknown("edge-2")],
        "every active node by name, unknown before a report; the pending node binds nothing"
    );
    assert_eq!(on(&pinned.id), vec![unknown("edge-2")]);
    assert!(on(&nowhere.id).is_empty(), "a stream no node binds");
    assert_eq!(
        status_entry(&answer, &fleet_wide.id)["nodes"][0]["node_id"],
        "id-edge-1"
    );
}

/// Every rendered series of `family` for `stream_id`: its other labels
/// and its value, as a scrape shows them.
fn rendered(
    collector: &crate::stream_metrics::StreamMetricsCollector,
    family: crate::stream_metrics::StreamFamily,
    stream_id: &str,
) -> Vec<(BTreeSet<(String, String)>, u64)> {
    use lorica_metrics::prometheus::core::Collector;
    collector
        .collect()
        .into_iter()
        .filter(|mf| mf.name() == family.qualified_name())
        .flat_map(|mf| mf.get_metric().to_vec())
        .filter(|m| {
            m.get_label()
                .iter()
                .any(|l| l.name() == "stream_id" && l.value() == stream_id)
        })
        .map(|m| {
            let labels = m
                .get_label()
                .iter()
                .filter(|l| l.name() != "stream_id")
                .map(|l| (l.name().to_string(), l.value().to_string()))
                .collect();
            let value = match family.family_type() {
                crate::stream_metrics::FamilyType::Counter => m.get_counter().value(),
                crate::stream_metrics::FamilyType::Gauge => m.get_gauge().value(),
                crate::stream_metrics::FamilyType::Histogram => {
                    panic!("the status answers no histogram")
                }
            };
            (labels, value as u64)
        })
        .collect()
}

/// The rendered value of the series of `family` for `stream_id` whose
/// other labels are exactly `labels`.
fn rendered_value(
    collector: &crate::stream_metrics::StreamMetricsCollector,
    family: crate::stream_metrics::StreamFamily,
    stream_id: &str,
    labels: &[(&str, &str)],
) -> u64 {
    let wanted: BTreeSet<(String, String)> = labels
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    rendered(collector, family, stream_id)
        .into_iter()
        .find(|(have, _)| *have == wanted)
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("{} renders no {labels:?}", family.qualified_name()))
}

/// The non-zero rendered reasons of `family` for `stream_id`.
fn rendered_reasons(
    collector: &crate::stream_metrics::StreamMetricsCollector,
    family: crate::stream_metrics::StreamFamily,
    stream_id: &str,
) -> BTreeSet<(String, u64)> {
    rendered(collector, family, stream_id)
        .into_iter()
        .filter(|(_, value)| *value > 0)
        .map(|(labels, value)| {
            let (_, reason) = labels
                .into_iter()
                .find(|(name, _)| name == "reason")
                .expect("a reason label");
            (reason, value)
        })
        .collect()
}

fn reasons_of(counters: &Value, key: &str) -> BTreeSet<(String, u64)> {
    counters[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} is an array: {counters}"))
        .iter()
        .map(|entry| {
            (
                entry["reason"].as_str().expect("a reason").to_string(),
                entry["count"].as_u64().expect("a count"),
            )
        })
        .collect()
}

#[tokio::test]
async fn the_counters_are_what_the_collector_renders_for_the_stream() {
    use crate::stream_metrics::{Direction, StreamFamily};
    use lorica_config::models::{DatagramDropReason, StreamEndKind, StreamRefusal};
    use strum::VariantArray;

    let node = Node::standalone().await;
    let dns = source_stream("dns", 5353);
    stored(&node, &dns).await;
    let counters = lorica_stream::StreamCounters::new();
    let stats = counters.stream(&dns.id);
    let _open = stats.accept();
    let _reading = stats.pending();
    drop(stats.accept());
    stats.add_upload(40);
    stats.add_download(400);
    for (n, &kind) in StreamEndKind::VARIANTS.iter().enumerate().skip(1) {
        for _ in 0..n {
            stats.ended(kind);
        }
    }
    for &refusal in StreamRefusal::VARIANTS {
        stats.refused(refusal);
    }
    stats.dropped(DatagramDropReason::VARIANTS[0]);
    let mut snapshot = counters.snapshot();
    let unseen = StreamEndKind::VARIANTS[0];
    snapshot
        .streams
        .get_mut(&dns.id)
        .expect("the stream's counters")
        .ended
        .insert(unseen, 0);
    let collector = crate::stream_metrics::StreamMetricsCollector::new();
    collector.apply_worker(7, &snapshot);

    let statuses = super::status::stream_statuses(&node.state, &collector)
        .await
        .expect("statuses");
    let entry = serde_json::to_value(&statuses[0]).expect("serialises");
    let live = &entry["counters"];
    assert_eq!(live["node_name"], Value::Null, "a standalone node");

    let single = |family: StreamFamily, labels: &[(&str, &str)]| {
        rendered_value(&collector, family, &dns.id, labels)
    };
    assert_eq!(live["active"], single(StreamFamily::Active, &[]));
    assert_eq!(live["pending"], single(StreamFamily::Pending, &[]));
    assert_eq!(live["accepted_total"], single(StreamFamily::Accepted, &[]));
    assert_eq!(
        live["bytes_upload_total"],
        single(
            StreamFamily::Bytes,
            &[("direction", Direction::Upload.as_str())]
        )
    );
    assert_eq!(
        live["bytes_download_total"],
        single(
            StreamFamily::Bytes,
            &[("direction", Direction::Download.as_str())]
        )
    );
    for (key, family) in [
        ("refused", StreamFamily::Refused),
        ("ended", StreamFamily::Ended),
        ("datagrams_dropped", StreamFamily::DatagramsDropped),
    ] {
        let answered = reasons_of(live, key);
        assert!(!answered.is_empty(), "{key} counted something");
        assert_eq!(
            answered,
            rendered_reasons(&collector, family, &dns.id),
            "{key}"
        );
    }
    assert!(
        !reasons_of(live, "ended")
            .iter()
            .any(|(reason, _)| reason == unseen.as_str()),
        "a zero count is not answered"
    );
}

#[tokio::test]
async fn the_published_status_schemas_name_exactly_the_fields_the_status_answers() {
    let node = Node::control_plane().await;
    node.enrol("edge-1", NodeStatus::Active, None).await;
    let pg = source_stream("pg", 5432);
    stored(&node, &pg).await;
    let counters = lorica_stream::StreamCounters::new();
    drop(counters.stream(&pg.id).accept());
    let collector = crate::stream_metrics::StreamMetricsCollector::new();
    collector.apply_worker(1, &counters.snapshot());
    let statuses = super::status::stream_statuses(&node.state, &collector)
        .await
        .expect("statuses");
    let entry = serde_json::to_value(&statuses[0]).expect("serialises");
    assert_eq!(schema_properties("StreamStatus"), keys(&entry));
    assert_eq!(
        schema_properties("StreamLiveCounters"),
        keys(&entry["counters"])
    );

    let failed = lorica_cluster::StreamBindingReport {
        stream_id: pg.id.clone(),
        state: lorica_cluster::StreamBindingState::Failed as i32,
        kind: "address_in_use".to_string(),
        os_error: "Address already in use (os error 98)".to_string(),
        port: 5432,
        failed_since_ms: 1_763_100_000_000,
    };
    let report = lorica_cluster::StreamPlaneReport {
        bindings: vec![failed],
        ..Default::default()
    };
    let row = node
        .state
        .store
        .lock()
        .await
        .get_cluster_node("id-edge-1")
        .expect("read")
        .expect("the enrolled node");
    let states = crate::cluster::stream_node_states(
        &[crate::cluster::NodeStreamSight {
            node: &row,
            report: Some(&report),
            drifted: false,
        }],
        std::slice::from_ref(&pg),
    );
    let node_state = serde_json::to_value(&states[&pg.id][0]).expect("serialises");
    assert_eq!(schema_properties("StreamNodeState"), keys(&node_state));
    let names = std::collections::HashMap::from([(pg.id.as_str(), pg.name.as_str())]);
    let plane = crate::cluster::stream_plane_view(&report, &[], &names, false, Role::Viewer);
    let binding = serde_json::to_value(&plane.bindings[0]).expect("serialises");
    assert_eq!(schema_properties("NodeStreamBinding"), keys(&binding));

    let reason = serde_json::to_value(crate::stream_metrics::ReasonCount {
        reason: String::new(),
        count: 0,
    })
    .expect("serialises");
    assert_eq!(schema_properties("StreamReasonCount"), keys(&reason));
}
