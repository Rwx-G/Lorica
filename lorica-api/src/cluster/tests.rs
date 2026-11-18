//! The cluster mutation handlers under cancellation: a handler dropped
//! after its commit (a client that disconnected) still leaves the audit
//! row and the journal line that commit is owed. And the stream plane on
//! the fleet view (Story 12.2 Lot E2): the enrollment preview's
//! `stream_ports`, each node's bind states, and the activation row.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use axum::extract::{Extension, Path};
use chrono::Utc;
use lorica_cluster::NodeState;
use lorica_config::models::{ClusterNode, NodeStatus, Role};
use lorica_stream::BindStateKind;

use crate::cluster::{ClusterRuntime, ControlPlaneRuntime};
use crate::middleware::auth::Session;
use crate::server::AppState;

/// A control plane with a real audit log, the shape the handlers run
/// against in production.
struct Fixture {
    state: AppState,
    runtime: Arc<ControlPlaneRuntime>,
    _liveness: tokio::sync::watch::Receiver<u32>,
    _data_dir: tempfile::TempDir,
}

impl Fixture {
    async fn new() -> Self {
        let data_dir = tempfile::tempdir().expect("test setup: tempdir");
        let (mut state, _sessions, _limiter) = crate::tests::test_state().await;
        state.log_store = Some(Arc::new(
            crate::log_store::LogStore::open(data_dir.path()).expect("test setup: log store"),
        ));
        let (runtime, liveness) = crate::tests::test_control_plane();
        state.cluster = ClusterRuntime::ControlPlane(Arc::clone(&runtime));
        Self {
            state,
            runtime,
            _liveness: liveness,
            _data_dir: data_dir,
        }
    }

    async fn seed(&self, id: &str, status: NodeStatus) {
        let now = Utc::now();
        let row = ClusterNode {
            node_id: id.to_string(),
            name: id.to_string(),
            cert_fingerprint: format!("fp-{id}"),
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
            reserved_ports: None,
        };
        self.state
            .store
            .lock()
            .await
            .create_cluster_node(&row)
            .expect("test setup: node");
        self.runtime
            .refresh(&self.state.store)
            .await
            .expect("test setup: initial refresh");
    }

    fn status_of(&self, id: &str) -> Option<NodeStatus> {
        let store = self.state.store.try_lock().ok()?;
        store
            .get_cluster_node(id)
            .expect("read")
            .map(|node| node.status)
    }

    async fn audited(&self, action: &str) -> bool {
        let log_store = self.state.log_store.clone().expect("log store");
        log_store
            .flush_audit()
            .await
            .expect("the audit writer drains");
        let (rows, _total) = log_store
            .query_audit(&crate::audit::AuditQuery {
                operator: None,
                action_prefix: Some(action.to_string()),
                from: None,
                to: None,
                limit: 10,
                before_id: None,
                node_id: None,
            })
            .expect("audit query");
        rows.iter().any(|row| row.action == action)
    }
}

fn super_admin() -> Session {
    Session {
        user_id: "user01".to_string(),
        username: "admin".to_string(),
        role: Role::SuperAdmin,
        created_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::hours(1),
    }
}

async fn eventually(what: &str, mut holds: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !holds() {
        assert!(Instant::now() < deadline, "never happened: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn eventually_audited(fixture: &Fixture, action: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !fixture.audited(action).await {
        assert!(Instant::now() < deadline, "no `{action}` audit row");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Every WARN message logged while installed. Installed with
/// `set_default` on a current-thread runtime, so the detached tasks the
/// handlers spawn log on the thread it is installed on.
#[derive(Default)]
struct Journal(StdMutex<Vec<String>>);

struct Message(String);

impl tracing::field::Visit for Message {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

struct Recording(Arc<Journal>);

impl tracing::Subscriber for Recording {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() <= tracing::Level::WARN
    }

    fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::Id {
        tracing::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::Id, _follows: &tracing::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut message = Message(String::new());
        event.record(&mut message);
        self.0 .0.lock().expect("journal").push(message.0);
    }

    fn enter(&self, _span: &tracing::Id) {}

    fn exit(&self, _span: &tracing::Id) {}
}

#[tokio::test(flavor = "current_thread")]
async fn a_revoke_whose_client_is_dropped_after_the_commit_is_still_audited_and_journalled() {
    let fixture = Fixture::new().await;
    fixture.seed("n0", NodeStatus::Active).await;
    let journal = Arc::new(Journal::default());
    let _installed = tracing::subscriber::set_default(Recording(Arc::clone(&journal)));

    // Held so the handler is parked between the commit and the rest.
    let guard = fixture.runtime.control.refresh_guard().await;
    let dropped = tokio::time::timeout(
        Duration::from_millis(50),
        super::revoke_node(
            crate::audit::ClientConnectInfo(None),
            http::HeaderMap::new(),
            Extension(fixture.state.clone()),
            Extension(super_admin()),
            Path("n0".to_string()),
        ),
    );
    assert!(dropped.await.is_err(), "the revoke could not finish yet");
    eventually("the row flip commits", || {
        fixture.status_of("n0") == Some(NodeStatus::Revoked)
    })
    .await;
    assert!(
        !fixture.audited("cluster.node.revoke").await,
        "audited before the enforcement it records"
    );
    drop(guard);

    eventually_audited(&fixture, "cluster.node.revoke").await;
    assert!(
        journal
            .0
            .lock()
            .expect("journal")
            .iter()
            .any(|m| m == "cluster node revoked"),
        "the revocation journal line was lost with the client"
    );
    assert_eq!(
        fixture
            .runtime
            .control
            .roster
            .lookup("fp-n0")
            .expect("entry")
            .state,
        NodeState::Revoked
    );
}

#[tokio::test(flavor = "current_thread")]
async fn an_activation_whose_client_is_dropped_after_the_commit_is_still_audited_and_enforced() {
    let fixture = Fixture::new().await;
    fixture.seed("n0", NodeStatus::Pending).await;

    let guard = fixture.runtime.control.refresh_guard().await;
    let dropped = tokio::time::timeout(
        Duration::from_millis(50),
        super::activate_node(
            crate::audit::ClientConnectInfo(None),
            http::HeaderMap::new(),
            Extension(fixture.state.clone()),
            Extension(super_admin()),
            Path("n0".to_string()),
        ),
    );
    assert!(
        dropped.await.is_err(),
        "the activation could not finish yet"
    );
    eventually("the activation commits", || {
        fixture.status_of("n0") == Some(NodeStatus::Active)
    })
    .await;
    drop(guard);

    eventually_audited(&fixture, "cluster.node.activate").await;
    eventually("the roster admits the activated node", || {
        fixture
            .runtime
            .control
            .roster
            .lookup("fp-n0")
            .is_some_and(|n| n.state == NodeState::Active)
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn an_activation_dropped_before_its_write_still_writes_and_refreshes() {
    // The write itself is part of the detached unit: a client gone
    // while the store lock is contended does not skip the refresh.
    let fixture = Fixture::new().await;
    fixture.seed("n0", NodeStatus::Pending).await;

    let held = Arc::clone(&fixture.state.store).lock_owned().await;
    let dropped = tokio::time::timeout(
        Duration::from_millis(50),
        super::activate_node(
            crate::audit::ClientConnectInfo(None),
            http::HeaderMap::new(),
            Extension(fixture.state.clone()),
            Extension(super_admin()),
            Path("n0".to_string()),
        ),
    );
    assert!(dropped.await.is_err(), "the store write could not run yet");
    drop(held);

    eventually("the roster admits the activated node", || {
        fixture
            .runtime
            .control
            .roster
            .lookup("fp-n0")
            .is_some_and(|n| n.state == NodeState::Active)
    })
    .await;
    eventually_audited(&fixture, "cluster.node.activate").await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_panicking_unit_is_logged_and_its_owed_audit_row_is_written_as_incomplete() {
    let fixture = Fixture::new().await;
    let journal = Arc::new(Journal::default());
    let _installed = tracing::subscriber::set_default(Recording(Arc::clone(&journal)));
    const ACTION: &str = "cluster.test.probe";

    let owed = crate::cluster::boundary::OwedAudit {
        log_store: fixture.state.log_store.clone(),
        ctx: crate::audit::AuditContext::node("cluster"),
        action: ACTION,
        target: ("cluster_node", "n0".to_string()),
    };
    let outcome = crate::cluster::boundary::detached_audited("probe", owed, async {
        panic!("injected after the commit");
    })
    .await;

    assert!(
        matches!(
            outcome,
            Err(lorica_fleet::ClusterRuntimeError::EnforcementTask(_))
        ),
        "the caller is told the unit failed"
    );
    eventually_audited(&fixture, &format!("{ACTION}.incomplete")).await;
    assert!(
        journal
            .0
            .lock()
            .expect("journal")
            .iter()
            .any(|m| m.starts_with("a cluster unit panicked")),
        "the panic reached the journal"
    );
}

/// A follower whose `lorica.db` is a file, so a second connection can
/// install a trigger that fails one write.
async fn follower_fixture() -> (
    crate::server::AppState,
    Arc<crate::cluster::FollowerRuntime>,
    tempfile::TempDir,
) {
    let data_dir = tempfile::tempdir().expect("test setup: tempdir");
    let (mut state, _sessions, _limiter) = crate::tests::test_state().await;
    state.store = Arc::new(tokio::sync::Mutex::new(
        lorica_config::ConfigStore::open(&data_dir.path().join("lorica.db"), None)
            .expect("test setup: config store"),
    ));
    state.log_store = Some(Arc::new(
        crate::log_store::LogStore::open(data_dir.path()).expect("test setup: log store"),
    ));
    let follower = Arc::new(crate::cluster::FollowerRuntime {
        node_id: "node-01".to_string(),
        node_name: "edge-01".to_string(),
        control_plane: "cp.example.com:7443".to_string(),
        connection: lorica_cluster::ClusterConnection::disconnected(),
        left: tokio::sync::watch::channel(false).0,
        applied: Arc::new(StdMutex::new(lorica_cluster::AppliedConfig {
            generation: 5,
            hash: "abc".to_string(),
            break_glass: false,
        })),
        break_glass: tokio::sync::watch::channel(None).0,
    });
    state.cluster = ClusterRuntime::Follower(Arc::clone(&follower));
    state
        .store
        .lock()
        .await
        .set_cluster_applied_config(5, "abc")
        .expect("test setup: applied marker");
    (state, follower, data_dir)
}

async fn open_window(state: &crate::server::AppState) -> bool {
    super::open_break_glass(
        crate::audit::ClientConnectInfo(None),
        http::HeaderMap::new(),
        Extension(state.clone()),
        Extension(super_admin()),
        axum::Json(super::BreakGlassRequest { duration_s: 600 }),
    )
    .await
    .is_ok()
}

async fn break_glass_audited(state: &crate::server::AppState) -> bool {
    let log_store = state.log_store.clone().expect("log store");
    log_store
        .flush_audit()
        .await
        .expect("the audit writer drains");
    let (rows, _total) = log_store
        .query_audit(&crate::audit::AuditQuery {
            action_prefix: Some(super::BREAK_GLASS_OPEN_ACTION.to_string()),
            limit: 10,
            ..Default::default()
        })
        .expect("audit query");
    !rows.is_empty()
}

#[tokio::test(flavor = "current_thread")]
async fn a_break_glass_window_that_fails_to_persist_opens_nothing_and_leaves_the_node_behind() {
    let (state, follower, data_dir) = follower_fixture().await;
    let saboteur =
        rusqlite::Connection::open(data_dir.path().join("lorica.db")).expect("second connection");
    saboteur
        .execute_batch(
            "CREATE TRIGGER refuse_window_update BEFORE UPDATE ON cluster_replica
                 WHEN NEW.key = 'break_glass_until'
                 BEGIN SELECT RAISE(ABORT, 'injected failure'); END;
             CREATE TRIGGER refuse_window_insert BEFORE INSERT ON cluster_replica
                 WHEN NEW.key = 'break_glass_until'
                 BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        )
        .expect("test setup: triggers");

    assert!(!open_window(&state).await, "the window write failed");
    {
        let store = state.store.lock().await;
        assert_eq!(
            store.cluster_break_glass_until().expect("window"),
            None,
            "no window persisted for a restart to reload"
        );
        assert_eq!(
            store.cluster_applied_config().expect("marker"),
            (0, String::new()),
            "the marker is cleared, so the node is behind and re-pulls"
        );
    }
    assert!(
        follower.break_glass_until().is_none(),
        "no window in memory"
    );
    assert_eq!(
        follower.applied().generation,
        0,
        "memory agrees with the store"
    );
    assert!(
        !break_glass_audited(&state).await,
        "no row for a window that never opened"
    );

    saboteur
        .execute_batch("DROP TRIGGER refuse_window_update; DROP TRIGGER refuse_window_insert;")
        .expect("test teardown: triggers");
    assert!(open_window(&state).await, "the retry opens the window");
    assert!(state
        .store
        .lock()
        .await
        .cluster_break_glass_until()
        .expect("window")
        .is_some());
    assert!(follower.break_glass_until().is_some());
    assert!(break_glass_audited(&state).await);
}

// ---- The stream plane on the fleet view (Story 12.2 Lot E2) ----

fn stream(name: &str, port: u16, selector: &[&str]) -> lorica_config::models::Stream {
    let mut stream = lorica_config::models::Stream::new(
        uuid::Uuid::new_v4().to_string(),
        name.to_string(),
        lorica_config::models::StreamProtocol::Tcp,
        "0.0.0.0".parse().expect("an address"),
        port,
        port,
        Utc::now(),
    );
    stream.node_selector = selector.iter().map(|s| s.to_string()).collect();
    stream
}

fn node_row(name: &str, status: NodeStatus) -> ClusterNode {
    let now = Utc::now();
    ClusterNode {
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
        reserved_ports: None,
    }
}

#[test]
fn stream_ports_lists_the_selected_and_the_fleet_wide_streams_a_node_will_bind() {
    let selected = stream("pg", 5432, &["edge-1"]);
    let fleet_wide = stream("dns", 53, &[]);
    let elsewhere = stream("smtp", 2525, &["edge-2"]);
    let disabled = lorica_config::models::Stream {
        enabled: false,
        ..stream("off", 6000, &["edge-1"])
    };
    let mut range = stream("range", 20_000, &[]);
    range.port_last = 20_009;
    let streams = [
        selected.clone(),
        fleet_wide.clone(),
        elsewhere,
        disabled,
        range.clone(),
    ];

    let pending = node_row("edge-1", NodeStatus::Pending);
    let ports = super::stream_ports(&pending, &streams);
    let named: Vec<(&str, u16, u16)> = ports
        .iter()
        .map(|p| (p.name.as_str(), p.port_first, p.port_last))
        .collect();
    assert_eq!(
        named,
        vec![
            ("pg", 5432, 5432),
            ("dns", 53, 53),
            ("range", 20_000, 20_009)
        ],
        "the selected and the fleet-wide streams, enabled ones only"
    );
    assert_eq!(ports[0].id, selected.id);
    assert_eq!(
        serde_json::to_value(&ports[2]).expect("serialises"),
        serde_json::json!({
            "id": range.id,
            "name": "range",
            "protocol": "tcp",
            "listen_address": "0.0.0.0",
            "port_first": 20_000,
            "port_last": 20_009,
        }),
        "the shape `openapi.yaml` documents as `StreamPortsEntry`"
    );
    assert_eq!(
        super::stream_ports(&node_row("edge-1", NodeStatus::Active), &streams),
        ports,
        "the same list once active"
    );
    assert!(super::stream_ports(&node_row("edge-1", NodeStatus::Revoked), &streams).is_empty());
    assert_eq!(
        super::stream_ports(&node_row("edge-3", NodeStatus::Pending), &streams).len(),
        2,
        "a node no selector names still opens every fleet-wide port"
    );
}

fn report(bindings: Vec<lorica_cluster::StreamBindingReport>) -> lorica_cluster::StreamPlaneReport {
    lorica_cluster::StreamPlaneReport {
        fd_limit: 65_536,
        worker_count: 4,
        listen_sockets_used: 3,
        worker_fds_committed: 3,
        supervisor_fds_committed: 5,
        bound_count: 1,
        bindings,
        truncated: false,
        usable_source_ports: Some(27_208),
    }
}

fn failed_binding(stream_id: &str, kind: &str) -> lorica_cluster::StreamBindingReport {
    lorica_cluster::StreamBindingReport {
        stream_id: stream_id.to_string(),
        state: lorica_cluster::StreamBindingState::Failed as i32,
        kind: kind.to_string(),
        os_error: "Address already in use (os error 98)".to_string(),
        port: 6000,
        failed_since_ms: 1_763_100_000_000,
    }
}

#[test]
fn the_fleet_view_renders_a_nodes_bindings_and_withholds_its_figures_from_viewers() {
    let pg = stream("pg", 5432, &[]);
    let dns = stream("dns", 6000, &[]);
    let targeted = super::stream_ports(
        &node_row("edge-1", NodeStatus::Active),
        &[pg.clone(), dns.clone()],
    );
    let reported = report(vec![failed_binding(&dns.id, "address_in_use")]);

    let operator = super::stream_plane_view(
        &reported,
        &targeted,
        &names_of(&[&pg, &dns]),
        false,
        Role::Operator,
    );
    assert_eq!(
        serde_json::to_value(&operator).expect("serialises"),
        serde_json::json!({
            "bound_count": 1,
            "listen_sockets_used": 3,
            "bindings": [{
                "stream_id": dns.id,
                "stream_name": "dns",
                "state": "failed",
                "kind": "address_in_use",
                "os_error": "Address already in use (os error 98)",
                "port": 6000,
                "since": chrono::DateTime::<Utc>::from_timestamp_millis(1_763_100_000_000)
                    .expect("a time"),
            }],
            "truncated": false,
            "fd_limit": 65_536,
            "worker_count": 4,
        }),
        "pg is not listed and the node is in sync: bound"
    );

    let viewer = super::stream_plane_view(
        &reported,
        &targeted,
        &names_of(&[&pg, &dns]),
        false,
        Role::Viewer,
    );
    let viewer = serde_json::to_value(&viewer).expect("serialises");
    assert!(viewer.get("fd_limit").is_none(), "{viewer}");
    assert!(viewer.get("worker_count").is_none(), "{viewer}");
    assert_eq!(
        viewer["bindings"][0]["state"], "failed",
        "bind states are not withheld"
    );
}

#[test]
fn under_drift_a_targeted_stream_the_node_does_not_list_is_unknown() {
    let pg = stream("pg", 5432, &[]);
    let dns = stream("dns", 6000, &[]);
    let targeted = super::stream_ports(
        &node_row("edge-1", NodeStatus::Active),
        &[pg.clone(), dns.clone()],
    );
    let reported = report(vec![failed_binding(&dns.id, "fd_budget")]);
    let view = super::stream_plane_view(
        &reported,
        &targeted,
        &names_of(&[&pg, &dns]),
        true,
        Role::Operator,
    );
    let states: Vec<(&str, BindStateKind)> = view
        .bindings
        .iter()
        .map(|b| (b.stream_id.as_str(), b.bind.state))
        .collect();
    assert_eq!(
        states,
        vec![
            (dns.id.as_str(), BindStateKind::Failed),
            (pg.id.as_str(), BindStateKind::Unknown),
        ]
    );
    assert_eq!(view.bindings[1].bind.kind, None);
}

#[test]
fn a_kind_or_a_state_only_a_newer_node_knows_reads_as_other_and_unknown() {
    let newer = report(vec![
        failed_binding("a", "quantum_entanglement"),
        lorica_cluster::StreamBindingReport {
            stream_id: "b".to_string(),
            state: 9,
            ..lorica_cluster::StreamBindingReport::default()
        },
    ]);
    let view = super::stream_plane_view(&newer, &[], &HashMap::new(), false, Role::Operator);
    assert_eq!(view.bindings[0].bind.kind, Some("other"));
    assert_eq!(view.bindings[1].bind.state, BindStateKind::Unknown);
}

#[test]
fn unknown_entries_past_the_bound_cut_the_list_and_say_so() {
    let streams: Vec<lorica_config::models::Stream> = (0
        ..=lorica_cluster::MAX_STREAM_PLANE_BINDINGS)
        .map(|n| {
            stream(
                &format!("s{n}"),
                1000 + u16::try_from(n).expect("port"),
                &[],
            )
        })
        .collect();
    let targeted = super::stream_ports(&node_row("edge-1", NodeStatus::Active), &streams);
    let view = super::stream_plane_view(
        &report(vec![]),
        &targeted,
        &HashMap::new(),
        true,
        Role::Operator,
    );
    assert_eq!(
        view.bindings.len(),
        lorica_cluster::MAX_STREAM_PLANE_BINDINGS
    );
    assert!(view.truncated);
}

/// Story 12.2 AC #9: a node that matches a stream's selector at
/// enrollment starts binding it at activation, and the control plane's
/// own chain records which ports that approval opened.
#[tokio::test(flavor = "current_thread")]
async fn an_activation_records_the_stream_ports_the_node_starts_binding() {
    let fixture = Fixture::new().await;
    fixture.seed("n0", NodeStatus::Pending).await;
    let selected = stream("pg", 5432, &["n0"]);
    let fleet_wide = stream("dns", 53, &[]);
    let elsewhere = stream("smtp", 2525, &["n1"]);
    {
        let store = fixture.state.store.lock().await;
        for s in [&selected, &fleet_wide, &elsewhere] {
            store.create_stream(s).expect("test setup: stream");
        }
    }

    let response = super::activate_node(
        crate::audit::ClientConnectInfo(None),
        http::HeaderMap::new(),
        Extension(fixture.state.clone()),
        Extension(super_admin()),
        Path("n0".to_string()),
    )
    .await
    .expect("activated");
    let body = crate::tests::body_json(axum::response::IntoResponse::into_response(response)).await;
    let ports: Vec<&str> = body["data"]["stream_ports"]
        .as_array()
        .expect("stream_ports")
        .iter()
        .map(|p| p["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(ports, vec!["dns", "pg"], "by name, as the store lists them");

    eventually_audited(&fixture, "cluster.node.activate").await;
    let log_store = fixture.state.log_store.clone().expect("log store");
    let (rows, _) = log_store
        .query_audit(&crate::audit::AuditQuery {
            action_prefix: Some("cluster.node.activate".to_string()),
            limit: 10,
            ..Default::default()
        })
        .expect("audit query");
    let row = rows.first().expect("the activation row");
    let entry = |s: &lorica_config::models::Stream| {
        serde_json::json!({
            "id": s.id,
            "name": s.name,
            "protocol": "tcp",
            "listen_address": "0.0.0.0",
            "port_first": s.port_first,
            "port_last": s.port_last,
        })
    };
    let expected = serde_json::json!({
        "status": "active",
        "name": "n0",
        "stream_ports": [entry(&fleet_wide), entry(&selected)],
    });
    assert_eq!(
        row.after_payload_hash,
        crate::audit::hash_payload(Some(&expected)),
        "the row's hashed payload names every port the activation opened"
    );
}

// ---- Stream names and per-node states (Story 12.10 Lot A) ----

/// The name lookup the roster builds from the stored streams.
fn names_of<'a>(streams: &[&'a lorica_config::models::Stream]) -> HashMap<&'a str, &'a str> {
    streams
        .iter()
        .map(|s| (s.id.as_str(), s.name.as_str()))
        .collect()
}

#[test]
fn every_binding_names_its_stream_and_one_no_longer_held_is_null() {
    let pg = stream("pg", 5432, &["edge-1"]);
    let elsewhere = stream("smtp", 2525, &["edge-2"]);
    let targeted = super::stream_ports(
        &node_row("edge-1", NodeStatus::Active),
        &[pg.clone(), elsewhere.clone()],
    );
    let deleted = uuid::Uuid::new_v4().to_string();
    let reported = report(vec![
        failed_binding(&elsewhere.id, "address_in_use"),
        failed_binding(&deleted, "address_in_use"),
    ]);
    let view = super::stream_plane_view(
        &reported,
        &targeted,
        &names_of(&[&pg, &elsewhere]),
        true,
        Role::Viewer,
    );
    let named: Vec<(&str, Option<&str>)> = view
        .bindings
        .iter()
        .map(|b| (b.stream_id.as_str(), b.stream_name.as_deref()))
        .collect();
    assert_eq!(
        named,
        vec![
            (elsewhere.id.as_str(), Some("smtp")),
            (deleted.as_str(), None),
            (pg.id.as_str(), Some("pg")),
        ],
        "a stream outside `stream_ports` is named, a deleted one is null, \
         and the drift entry is named too"
    );
    let rendered = serde_json::to_value(&view).expect("serialises");
    assert_eq!(
        rendered["bindings"][1]["stream_name"],
        serde_json::Value::Null
    );
}

fn sight<'a>(
    node: &'a ClusterNode,
    report: Option<&'a lorica_cluster::StreamPlaneReport>,
    drifted: bool,
) -> super::NodeStreamSight<'a> {
    super::NodeStreamSight {
        node,
        report,
        drifted,
    }
}

fn state_on(
    states: &HashMap<String, Vec<super::StreamNodeState>>,
    stream: &lorica_config::models::Stream,
) -> Vec<(String, BindStateKind)> {
    states
        .get(&stream.id)
        .map(|nodes| {
            nodes
                .iter()
                .map(|n| (n.node_name.clone(), n.bind.state))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_streams_state_per_node_follows_the_fleet_views_rule() {
    let pg = stream("pg", 5432, &[]);
    let dns = stream("dns", 6000, &[]);
    let streams = [pg.clone(), dns.clone()];
    let in_sync = node_row("edge-c", NodeStatus::Active);
    let drifting = node_row("edge-b", NodeStatus::Active);
    let silent = node_row("edge-a", NodeStatus::Active);
    let pending = node_row("edge-d", NodeStatus::Pending);
    let revoked = node_row("edge-e", NodeStatus::Revoked);
    let failing = report(vec![failed_binding(&dns.id, "address_in_use")]);

    let states = super::stream_node_states(
        &[
            sight(&in_sync, Some(&failing), false),
            sight(&drifting, Some(&failing), true),
            sight(&silent, None, false),
            sight(&pending, Some(&failing), false),
            sight(&revoked, Some(&failing), false),
        ],
        &streams,
    );

    assert_eq!(
        state_on(&states, &pg),
        vec![
            ("edge-a".to_string(), BindStateKind::Unknown),
            ("edge-b".to_string(), BindStateKind::Unknown),
            ("edge-c".to_string(), BindStateKind::Bound),
        ],
        "by node name: no report yet, unlisted under drift, unlisted in sync; \
         a pending or revoked node binds nothing"
    );
    assert_eq!(
        state_on(&states, &dns),
        vec![
            ("edge-a".to_string(), BindStateKind::Unknown),
            ("edge-b".to_string(), BindStateKind::Failed),
            ("edge-c".to_string(), BindStateKind::Failed),
        ],
        "a listed failure is read as listed, drift or not"
    );
    let failed = &states[&dns.id][2];
    assert_eq!(failed.node_id, in_sync.node_id);
    assert_eq!(
        failed.bind,
        super::node_bind_state(Some(&failing), false, &dns.id),
        "the same rule the fleet view's bindings use"
    );
    assert_eq!(failed.bind.port, Some(6000));
}

#[test]
fn a_node_a_stream_does_not_target_is_not_listed_for_it() {
    let pinned = stream("pg", 5432, &["edge-1"]);
    let one = node_row("edge-1", NodeStatus::Active);
    let two = node_row("edge-2", NodeStatus::Active);
    let states = super::stream_node_states(
        &[sight(&one, None, false), sight(&two, None, false)],
        std::slice::from_ref(&pinned),
    );
    assert_eq!(
        state_on(&states, &pinned),
        vec![("edge-1".to_string(), BindStateKind::Unknown)]
    );
}

#[test]
fn a_cut_list_vouches_for_no_unlisted_stream() {
    let pg = stream("pg", 5432, &[]);
    let node = node_row("edge-1", NodeStatus::Active);
    let mut cut = report(vec![]);
    cut.truncated = true;
    let states = super::stream_node_states(
        &[sight(&node, Some(&cut), false)],
        std::slice::from_ref(&pg),
    );
    assert_eq!(
        state_on(&states, &pg),
        vec![("edge-1".to_string(), BindStateKind::Unknown)]
    );
}
