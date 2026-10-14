//! The cluster mutation handlers under cancellation: a handler dropped
//! after its commit (a client that disconnected) still leaves the audit
//! row and the journal line that commit is owed.

use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use axum::extract::{Extension, Path};
use chrono::Utc;
use lorica_cluster::NodeState;
use lorica_config::models::{ClusterNode, NodeStatus, Role};

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

    let owed = crate::cluster::runtime::OwedAudit {
        log_store: fixture.state.log_store.clone(),
        ctx: crate::audit::AuditContext::node("cluster"),
        action: ACTION,
        target: ("cluster_node", "n0".to_string()),
    };
    let outcome = crate::cluster::runtime::detached_audited("probe", owed, async {
        panic!("injected after the commit");
    })
    .await;

    assert!(
        matches!(
            outcome,
            Err(crate::cluster::runtime::ClusterRuntimeError::EnforcementTask(_))
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

#[tokio::test(flavor = "current_thread")]
async fn a_unit_nested_in_another_runs_and_the_drain_waits_for_units_in_flight() {
    let (started, running) = tokio::sync::oneshot::channel::<()>();
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    let unit = tokio::spawn(crate::cluster::runtime::detached("outer", async move {
        // Nested: takes no slot of its own, so it can never wait on the
        // one its parent holds.
        let inner = crate::cluster::runtime::detached("inner", async { 7 }).await;
        let _ = started.send(());
        let _ = released.await;
        inner
    }));
    running.await.expect("the unit started");

    assert!(
        !crate::cluster::runtime::drain_detached(Duration::from_millis(50)).await,
        "a unit still in flight is not drained"
    );
    release.send(()).expect("the unit is waiting");
    assert!(crate::cluster::runtime::drain_detached(Duration::from_secs(5)).await);
    let inner = unit
        .await
        .expect("the caller task")
        .expect("the outer unit");
    assert_eq!(inner.expect("the inner unit"), 7);
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
