//! Upgrade of an `access-log.db` written by every released schema.
//!
//! The DDL below is copied from `LogStore::open` at each release tag and
//! is a frozen historical artefact: it must never be edited to follow
//! the live schema, which is what it exists to be compared with. Each
//! fixture is what that release's `open` left on a fresh file, which is
//! also what an upgrade through it left, since every release up to
//! v1.9.1 created its new tables whole and added columns only to tables
//! that existed.
//!
//! Distinct schemas, by the tags whose `open` produced them:
//!
//! - v1.0.0: access logs without `request_id`, WAF events, notifications.
//! - v1.1.0 and v1.2.0: plus `access_logs.request_id`.
//! - v1.3.0 to v1.5.13: plus two access-log indexes.
//! - v1.6.0: plus the audit chain, without the fan-in columns.
//! - v1.7.0 to v1.9.1: the audit chain with `node_id`, `origin_id` and
//!   `received_at`.
//!
//! The audit rows are chained with a copy of the hash v1.6.0 shipped
//! (`compute_chain_hash` is byte-identical from v1.6.0 to v1.9.1), not
//! with the current crate's, so a change to the live formula that broke
//! the chains already on disk fails here.

use std::path::Path;

use lorica_api::audit::{AuditQuery, NewAuditEntry, GENESIS_HASH};
use lorica_api::log_store::LogStore;
use lorica_api::logs::{LogEntry, LogsQuery};
use rusqlite::{params, Connection};

/// `access_logs` as v1.0.0 to v1.2.0 created it.
const ACCESS_LOGS_V1_0_0: &str = "
    CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        host TEXT NOT NULL,
        status INTEGER NOT NULL,
        latency_ms INTEGER NOT NULL,
        backend TEXT NOT NULL,
        error TEXT,
        client_ip TEXT NOT NULL DEFAULT '',
        is_xff INTEGER NOT NULL DEFAULT 0,
        xff_proxy_ip TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_access_logs_timestamp ON access_logs(timestamp);
    CREATE INDEX IF NOT EXISTS idx_access_logs_host ON access_logs(host);";

/// The two indexes v1.3.0 added to `access_logs`.
const ACCESS_LOGS_V1_3_0_INDEXES: &str = "
    CREATE INDEX IF NOT EXISTS idx_access_logs_status ON access_logs(status);
    CREATE INDEX IF NOT EXISTS idx_access_logs_host_timestamp ON access_logs(host, timestamp);";

/// The column v1.1.0 added to `access_logs`.
const ACCESS_LOGS_V1_1_0_REQUEST_ID: &str =
    "ALTER TABLE access_logs ADD COLUMN request_id TEXT NOT NULL DEFAULT '';";

/// `waf_events` and `notification_history`, unchanged from v1.0.0 to
/// v1.9.1.
const WAF_AND_NOTIFICATIONS_V1_0_0: &str = "
    CREATE TABLE IF NOT EXISTS waf_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_id INTEGER NOT NULL,
        description TEXT NOT NULL,
        category TEXT NOT NULL,
        severity INTEGER NOT NULL,
        matched_field TEXT NOT NULL,
        matched_value TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        client_ip TEXT NOT NULL DEFAULT '',
        route_hostname TEXT NOT NULL DEFAULT '',
        action TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_waf_events_timestamp ON waf_events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_waf_events_category ON waf_events(category);
    CREATE TABLE IF NOT EXISTS notification_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_type TEXT NOT NULL,
        summary TEXT NOT NULL,
        details TEXT NOT NULL DEFAULT '{}',
        timestamp TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_notif_history_timestamp ON notification_history(timestamp);";

/// The audit schema v1.6.0 created: no fan-in columns.
const AUDIT_V1_6_0: &str = "
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        operator_username TEXT NOT NULL,
        operator_role TEXT NOT NULL,
        action TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        before_payload_hash TEXT NOT NULL DEFAULT '',
        after_payload_hash TEXT NOT NULL DEFAULT '',
        ip TEXT NOT NULL DEFAULT '',
        user_agent TEXT NOT NULL DEFAULT '',
        prev_chain_hash TEXT NOT NULL,
        chain_hash TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
    CREATE INDEX IF NOT EXISTS idx_audit_log_operator ON audit_log(operator_username);
    CREATE TABLE IF NOT EXISTS audit_log_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );";

/// The first audit batch of `LogStore::open` from v1.7.0 to v1.9.1,
/// verbatim. Its two `node_id` indexes run before the `ALTER TABLE`
/// that adds the column, which is the production failure on a v1.6.0
/// file.
const AUDIT_V1_7_0_FIRST_BATCH: &str = "
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        node_id TEXT NOT NULL DEFAULT '',
        origin_id INTEGER NOT NULL DEFAULT 0,
        timestamp TEXT NOT NULL,
        operator_username TEXT NOT NULL,
        operator_role TEXT NOT NULL,
        action TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        before_payload_hash TEXT NOT NULL DEFAULT '',
        after_payload_hash TEXT NOT NULL DEFAULT '',
        ip TEXT NOT NULL DEFAULT '',
        user_agent TEXT NOT NULL DEFAULT '',
        prev_chain_hash TEXT NOT NULL,
        chain_hash TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
    CREATE INDEX IF NOT EXISTS idx_audit_log_operator ON audit_log(operator_username);
    CREATE INDEX IF NOT EXISTS idx_audit_log_node ON audit_log(node_id, origin_id);
    CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_log_origin
        ON audit_log(node_id, origin_id) WHERE node_id != '';
    CREATE TABLE IF NOT EXISTS audit_log_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );";

/// The column v1.7.0 added after its first batch; the other two fan-in
/// columns were in that batch's `CREATE TABLE`.
const AUDIT_V1_7_0_RECEIVED_AT: &str =
    "ALTER TABLE audit_log ADD COLUMN received_at TEXT NOT NULL DEFAULT '';";

/// One released schema, and what it can hold.
struct Released {
    tag: &'static str,
    ddl: Vec<&'static str>,
    has_request_id: bool,
    audit: AuditEra,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AuditEra {
    None,
    PreFanIn,
    FanIn,
}

fn released_schemas() -> Vec<Released> {
    let v1_0_0 = vec![ACCESS_LOGS_V1_0_0, WAF_AND_NOTIFICATIONS_V1_0_0];
    let v1_1_0 = vec![
        ACCESS_LOGS_V1_0_0,
        ACCESS_LOGS_V1_1_0_REQUEST_ID,
        WAF_AND_NOTIFICATIONS_V1_0_0,
    ];
    let v1_3_0 = vec![
        ACCESS_LOGS_V1_0_0,
        ACCESS_LOGS_V1_3_0_INDEXES,
        ACCESS_LOGS_V1_1_0_REQUEST_ID,
        WAF_AND_NOTIFICATIONS_V1_0_0,
    ];
    let v1_6_0 = [v1_3_0.clone(), vec![AUDIT_V1_6_0]].concat();
    let v1_7_0 = [
        v1_3_0.clone(),
        vec![AUDIT_V1_7_0_FIRST_BATCH, AUDIT_V1_7_0_RECEIVED_AT],
    ]
    .concat();
    vec![
        Released {
            tag: "v1.0.0",
            ddl: v1_0_0,
            has_request_id: false,
            audit: AuditEra::None,
        },
        Released {
            tag: "v1.2.0",
            ddl: v1_1_0,
            has_request_id: true,
            audit: AuditEra::None,
        },
        Released {
            tag: "v1.5.13",
            ddl: v1_3_0,
            has_request_id: true,
            audit: AuditEra::None,
        },
        Released {
            tag: "v1.6.0",
            ddl: v1_6_0,
            has_request_id: true,
            audit: AuditEra::PreFanIn,
        },
        Released {
            tag: "v1.9.1",
            ddl: v1_7_0,
            has_request_id: true,
            audit: AuditEra::FanIn,
        },
    ]
}

/// `compute_chain_hash` as v1.6.0 shipped it, kept here as the formula
/// the rows on disk were written with.
fn released_chain_hash(prev: &str, fields: &[&str; 10]) -> String {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    for field in std::iter::once(&prev).chain(fields.iter()) {
        ctx.update(&(field.len() as u64).to_le_bytes());
        ctx.update(field.as_bytes());
    }
    ctx.finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The ten chained fields of the n-th fixture row, in chain order.
fn audit_fields(n: usize) -> [String; 10] {
    [
        format!("2026-01-0{n}T10:00:00+00:00"),
        "admin".into(),
        "super_admin".into(),
        "route.update".into(),
        "route".into(),
        format!("route-{n}"),
        format!("{:064x}", n),
        format!("{:064x}", n + 100),
        "192.0.2.10".into(),
        "Mozilla/5.0".into(),
    ]
}

/// Insert a chain of `rows` local audit rows anchored on `anchor`, the
/// way v1.6.0 to v1.9.1 wrote them, and return the tail hash.
fn write_released_local_chain(conn: &Connection, anchor: &str, rows: usize) -> String {
    let mut prev = anchor.to_string();
    for n in 1..=rows {
        let f = audit_fields(n);
        let refs: [&str; 10] = std::array::from_fn(|i| f[i].as_str());
        let hash = released_chain_hash(&prev, &refs);
        conn.execute(
            "INSERT INTO audit_log (timestamp, operator_username, operator_role, action,
                target_type, target_id, before_payload_hash, after_payload_hash,
                ip, user_agent, prev_chain_hash, chain_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9], prev, hash],
        )
        .expect("test setup: released audit row");
        prev = hash;
    }
    prev
}

/// What a fixture file holds beyond its schema, for the assertions.
struct Written {
    local_tail: Option<String>,
    local_rows: u64,
    fanned_in_rows: u64,
}

const FANNED_IN_NODE: &str = "node-b";

fn write_released_file(dir: &Path, release: &Released) -> Written {
    let conn = Connection::open(dir.join("access-log.db")).expect("test setup: raw open");
    for ddl in &release.ddl {
        conn.execute_batch(ddl).expect("test setup: released DDL");
    }
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;",
    )
    .expect("test setup: released pragmas");

    for n in 1..=3u32 {
        let timestamp = format!("2026-01-0{n}T09:00:00+00:00");
        if release.has_request_id {
            conn.execute(
                "INSERT INTO access_logs (timestamp, method, path, host, status, latency_ms,
                    backend, error, client_ip, is_xff, xff_proxy_ip, source, request_id)
                 VALUES (?1, 'GET', ?2, 'app.example.com', 200, 12, '192.0.2.20:8080', NULL,
                    '192.0.2.10', 0, '', '', ?3)",
                params![timestamp, format!("/page/{n}"), format!("req-{n}")],
            )
        } else {
            conn.execute(
                "INSERT INTO access_logs (timestamp, method, path, host, status, latency_ms,
                    backend, error, client_ip, is_xff, xff_proxy_ip, source)
                 VALUES (?1, 'GET', ?2, 'app.example.com', 200, 12, '192.0.2.20:8080', NULL,
                    '192.0.2.10', 0, '', '')",
                params![timestamp, format!("/page/{n}")],
            )
        }
        .expect("test setup: released access row");
    }
    conn.execute(
        "INSERT INTO waf_events (rule_id, description, category, severity, matched_field,
            matched_value, timestamp, client_ip, route_hostname, action)
         VALUES (942100, 'SQL injection', 'sql_injection', 5, 'query', 'id=1 OR 1=1',
            '2026-01-01T09:30:00+00:00', '192.0.2.10', 'app.example.com', 'blocked')",
        [],
    )
    .expect("test setup: released WAF event");
    conn.execute(
        "INSERT INTO notification_history (alert_type, summary, details, timestamp)
         VALUES ('backend_down', 'backend 192.0.2.20:8080 is down', '{\"backend\":\"192.0.2.20:8080\"}',
            '2026-01-01T09:45:00+00:00')",
        [],
    )
    .expect("test setup: released notification");

    match release.audit {
        AuditEra::None => Written {
            local_tail: None,
            local_rows: 0,
            fanned_in_rows: 0,
        },
        AuditEra::PreFanIn => {
            // Retention already ran on this node: the seal stands in for
            // the rows it removed, and the chain anchors on it.
            let seal = format!("{:064x}", 0xdead_beef_u64);
            conn.execute(
                "INSERT INTO audit_log_meta (key, value) VALUES ('retention_seal', ?1)",
                params![seal],
            )
            .expect("test setup: released seal");
            Written {
                local_tail: Some(write_released_local_chain(&conn, &seal, 3)),
                local_rows: 3,
                fanned_in_rows: 0,
            }
        }
        AuditEra::FanIn => {
            let tail = write_released_local_chain(&conn, GENESIS_HASH, 2);
            // A follower's chain as the control plane stored it: hashes
            // verbatim, ordered by the origin's ids, anchored on the
            // arrival seal its first batch wrote.
            let arrival = format!("{:064x}", 0x0b_u64);
            conn.execute(
                "INSERT INTO audit_log_meta (key, value) VALUES (?1, ?2)",
                params![format!("retention_seal:{FANNED_IN_NODE}"), arrival],
            )
            .expect("test setup: released arrival seal");
            let mut prev = arrival;
            for (n, origin_id) in [(5usize, 41i64), (6, 42)] {
                let f = audit_fields(n);
                let refs: [&str; 10] = std::array::from_fn(|i| f[i].as_str());
                let hash = released_chain_hash(&prev, &refs);
                conn.execute(
                    "INSERT INTO audit_log (timestamp, operator_username, operator_role,
                        action, target_type, target_id, before_payload_hash,
                        after_payload_hash, ip, user_agent, prev_chain_hash, chain_hash,
                        node_id, origin_id, received_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                        '2026-01-07T00:00:00+00:00')",
                    params![
                        f[0],
                        f[1],
                        f[2],
                        f[3],
                        f[4],
                        f[5],
                        f[6],
                        f[7],
                        f[8],
                        f[9],
                        prev,
                        hash,
                        FANNED_IN_NODE,
                        origin_id
                    ],
                )
                .expect("test setup: released fanned-in row");
                prev = hash;
            }
            Written {
                local_tail: Some(tail),
                local_rows: 2,
                fanned_in_rows: 2,
            }
        }
    }
}

fn all_access_logs() -> LogsQuery {
    LogsQuery {
        route: None,
        status: None,
        status_min: None,
        status_max: None,
        time_from: None,
        time_to: None,
        client_ip: None,
        search: None,
        limit: Some(100),
        after_id: None,
        before_id: None,
    }
}

fn new_audit_entry() -> NewAuditEntry {
    NewAuditEntry {
        timestamp: "2026-02-01T00:00:00+00:00".into(),
        operator_username: "admin".into(),
        operator_role: "super_admin".into(),
        action: "route.delete".into(),
        target_type: "route".into(),
        target_id: "route-9".into(),
        before_payload_hash: String::new(),
        after_payload_hash: String::new(),
        ip: "192.0.2.10".into(),
        user_agent: "Mozilla/5.0".into(),
    }
}

fn assert_upgrades(release: &Released) {
    let tag = release.tag;
    let dir = tempfile::tempdir().expect("test setup: tempdir");
    let written = write_released_file(dir.path(), release);

    let store = LogStore::open(dir.path())
        .unwrap_or_else(|e| panic!("{tag}: a released access-log.db must open: {e}"));

    // Rows already on disk, read through the current API.
    let (entries, total) = store.query(&all_access_logs()).expect("access logs read");
    assert_eq!(total, 3, "{tag}: access logs kept");
    let mut paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    paths.sort_unstable();
    assert_eq!(paths, ["/page/1", "/page/2", "/page/3"], "{tag}");
    let expected_ids: Vec<String> = if release.has_request_id {
        vec!["req-3".into(), "req-2".into(), "req-1".into()]
    } else {
        vec![String::new(); 3]
    };
    let mut newest_first = entries.clone();
    newest_first.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    let ids: Vec<String> = newest_first.iter().map(|e| e.request_id.clone()).collect();
    assert_eq!(ids, expected_ids, "{tag}: request ids");

    let waf = store.list_waf_events(10, None).expect("WAF events read");
    assert_eq!(waf.len(), 1, "{tag}: WAF events kept");
    assert_eq!(waf[0].rule_id, 942100);
    assert_eq!(waf[0].category, lorica_waf::RuleCategory::SqlInjection);
    assert_eq!(waf[0].action, "blocked");

    let notifications = store
        .list_notification_history(10)
        .expect("notifications read");
    assert_eq!(notifications.len(), 1, "{tag}: notifications kept");
    assert_eq!(
        notifications[0].alert_type,
        lorica_notify::events::AlertType::BackendDown
    );
    assert_eq!(
        notifications[0].details.get("backend").map(String::as_str),
        Some("192.0.2.20:8080")
    );

    // The chain written by the release verifies with the current code.
    let local = store.verify_audit_chain().expect("verify");
    assert!(
        local.verified,
        "{tag}: released local chain must verify: {local:?}"
    );
    assert_eq!(local.total_rows, written.local_rows, "{tag}");
    if written.fanned_in_rows > 0 {
        let peer = store
            .verify_audit_chain_for(FANNED_IN_NODE)
            .expect("verify");
        assert!(
            peer.verified,
            "{tag}: released fanned-in chain must verify: {peer:?}"
        );
        assert_eq!(peer.total_rows, written.fanned_in_rows, "{tag}");
    }
    let (rows, audit_total) = store
        .query_audit(&AuditQuery {
            node_id: Some(String::new()),
            limit: 100,
            ..AuditQuery::default()
        })
        .expect("audit read");
    assert_eq!(
        audit_total, written.local_rows,
        "{tag}: local audit rows kept"
    );
    assert!(rows
        .iter()
        .all(|r| r.node_id.is_empty() && r.origin_id == 0));

    // New writes land, and the next audit row chains onto the old tail.
    store
        .insert(&LogEntry {
            id: 0,
            timestamp: "2026-02-01T00:00:00+00:00".into(),
            method: "POST".into(),
            path: "/after-upgrade".into(),
            host: "app.example.com".into(),
            status: 201,
            latency_ms: 5,
            backend: "192.0.2.20:8080".into(),
            error: None,
            client_ip: "192.0.2.10".into(),
            is_xff: false,
            xff_proxy_ip: String::new(),
            source: String::new(),
            request_id: "req-new".into(),
        })
        .expect("access log insert");
    let (_, total) = store.query(&all_access_logs()).expect("access logs read");
    assert_eq!(total, 4, "{tag}");
    store
        .insert_waf_event(&lorica_waf::WafEvent {
            rule_id: 941100,
            description: "XSS".into(),
            category: lorica_waf::RuleCategory::Xss,
            severity: 4,
            matched_field: "query".into(),
            matched_value: "<script>".into(),
            timestamp: "2026-02-01T00:00:00+00:00".into(),
            client_ip: "192.0.2.10".into(),
            route_hostname: "app.example.com".into(),
            action: "detected".into(),
        })
        .expect("WAF insert");
    assert_eq!(store.list_waf_events(10, None).expect("WAF read").len(), 2);
    store
        .insert_notification_event(&lorica_notify::AlertEvent::new(
            lorica_notify::events::AlertType::ConfigChanged,
            "config changed",
        ))
        .expect("notification insert");
    assert_eq!(store.notification_history_count().expect("count"), 2);

    let (_, new_hash) = store
        .insert_audit(&new_audit_entry())
        .expect("audit insert");
    let (newest, _) = store
        .query_audit(&AuditQuery {
            node_id: Some(String::new()),
            limit: 1,
            ..AuditQuery::default()
        })
        .expect("audit read");
    assert_eq!(newest[0].chain_hash, new_hash);
    let anchor = written
        .local_tail
        .clone()
        .unwrap_or_else(|| GENESIS_HASH.to_string());
    assert_eq!(
        newest[0].prev_chain_hash, anchor,
        "{tag}: the first new row chains onto the released tail"
    );
    let local = store.verify_audit_chain().expect("verify");
    assert!(local.verified, "{tag}: chain after the new row: {local:?}");
    assert_eq!(local.total_rows, written.local_rows + 1, "{tag}");

    // A second open of the upgraded file is a no-op.
    drop(store);
    let reopened = LogStore::open(dir.path()).expect("an upgraded file reopens");
    assert!(reopened.verify_audit_chain().expect("verify").verified);
}

#[test]
fn every_released_access_log_schema_upgrades_with_its_rows() {
    for release in released_schemas() {
        assert_upgrades(&release);
    }
}

/// The production failure, reproduced and then opened by the fix.
///
/// A v1.6.0 file, run through the first audit batch v1.7.0 to v1.9.1
/// shipped, fails exactly as the journal of an affected node shows it
/// on every start, and leaves the file as it found it. The current
/// `LogStore::open` then opens that same file with every v1.6.0 row
/// intact.
#[test]
fn a_v1_6_0_file_that_v1_7_0_to_v1_9_1_refused_now_opens() {
    let release = released_schemas()
        .into_iter()
        .find(|r| r.tag == "v1.6.0")
        .expect("the v1.6.0 schema");
    let dir = tempfile::tempdir().expect("test setup: tempdir");
    let written = write_released_file(dir.path(), &release);

    {
        let conn = Connection::open(dir.path().join("access-log.db")).expect("raw open");
        let err = conn
            .execute_batch(AUDIT_V1_7_0_FIRST_BATCH)
            .expect_err("the v1.7.0 to v1.9.1 ordering must fail on a v1.6.0 file");
        let logged = format!("failed to initialize audit log schema: {err}");
        assert!(
            logged.contains("no such column: node_id"),
            "not the production error: {logged}"
        );
        let has_node_id: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('audit_log') WHERE name = 'node_id'",
                [],
                |row| row.get(0),
            )
            .expect("table info");
        assert_eq!(has_node_id, 0);
    }

    let store = LogStore::open(dir.path()).expect("the fix opens the file 1.7.0 refused");
    let local = store.verify_audit_chain().expect("verify");
    assert!(local.verified, "{local:?}");
    assert_eq!(local.total_rows, written.local_rows);
    let (_, total) = store.query(&all_access_logs()).expect("access logs read");
    assert_eq!(total, 3);
}
