//! Upgrade of a `cluster-telemetry.db` written by a released version.
//!
//! The file first shipped in v1.7.0 and its schema was the same through
//! v1.9.1; since then only indexes on existing columns were added, which
//! `CREATE INDEX IF NOT EXISTS` applies to an old file on its next open.
//! The DDL below is copied from `ClusterTelemetryStore::open` at v1.7.0
//! and is a frozen historical artefact: never edit it to follow the live
//! schema, which is what it exists to be compared with.

use lorica_api::cluster_telemetry_store::{ClusterTelemetryStore, FleetQuery, TelemetryTable};
use rusqlite::Connection;

const CLUSTER_TELEMETRY_V1_7_0: &str = "
    CREATE TABLE IF NOT EXISTS fleet_access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        node_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        host TEXT NOT NULL,
        status INTEGER NOT NULL,
        latency_ms INTEGER NOT NULL,
        backend TEXT NOT NULL,
        error TEXT NOT NULL DEFAULT '',
        client_ip TEXT NOT NULL DEFAULT '',
        is_xff INTEGER NOT NULL DEFAULT 0,
        xff_proxy_ip TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL DEFAULT '',
        request_id TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_fleet_access_node_id
        ON fleet_access_logs(node_id, id);
    CREATE INDEX IF NOT EXISTS idx_fleet_access_node_ts
        ON fleet_access_logs(node_id, timestamp);
    CREATE INDEX IF NOT EXISTS idx_fleet_access_ts
        ON fleet_access_logs(timestamp);

    CREATE TABLE IF NOT EXISTS fleet_waf_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        node_id TEXT NOT NULL,
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
    CREATE INDEX IF NOT EXISTS idx_fleet_waf_node_id
        ON fleet_waf_events(node_id, id);
    CREATE INDEX IF NOT EXISTS idx_fleet_waf_node_ts
        ON fleet_waf_events(node_id, timestamp);
    CREATE INDEX IF NOT EXISTS idx_fleet_waf_ts
        ON fleet_waf_events(timestamp);

    CREATE TABLE IF NOT EXISTS fleet_bans (
        node_id TEXT NOT NULL,
        client_ip TEXT NOT NULL,
        remaining_s INTEGER NOT NULL,
        reason TEXT NOT NULL,
        observed_at TEXT NOT NULL,
        PRIMARY KEY (node_id, client_ip)
    );";

#[test]
fn cluster_telemetry_db_from_v1_7_0_upgrades_with_its_rows() {
    let dir = tempfile::tempdir().expect("test setup: tempdir");
    {
        let conn =
            Connection::open(dir.path().join("cluster-telemetry.db")).expect("test setup: open");
        conn.execute_batch(CLUSTER_TELEMETRY_V1_7_0)
            .expect("test setup: released schema");
        conn.execute_batch(
            "INSERT INTO fleet_access_logs (node_id, timestamp, method, path, host, status,
                latency_ms, backend, client_ip, request_id)
             VALUES ('node-b', '2026-01-01T09:00:00+00:00', 'GET', '/', 'app.example.com',
                200, 12, '192.0.2.20:8080', '192.0.2.10', 'req-1');
             INSERT INTO fleet_waf_events (node_id, rule_id, description, category, severity,
                matched_field, matched_value, timestamp, client_ip, route_hostname, action)
             VALUES ('node-b', 942100, 'SQL injection', 'sql_injection', 5, 'query',
                'id=1 OR 1=1', '2026-01-01T09:30:00+00:00', '192.0.2.10',
                'app.example.com', 'blocked');
             INSERT INTO fleet_bans (node_id, client_ip, remaining_s, reason, observed_at)
             VALUES ('node-b', '192.0.2.10', 600, 'waf', '2026-01-01T09:31:00+00:00');",
        )
        .expect("test setup: released rows");
    }

    let store = ClusterTelemetryStore::open(dir.path()).expect("a released file must open");

    let access = store
        .query_access(&FleetQuery {
            limit: 10,
            ..FleetQuery::default()
        })
        .expect("access read");
    assert_eq!(access.len(), 1);
    assert_eq!(access[0].node_id, "node-b");

    // Through the category indexes the release did not have.
    let waf = store
        .query_waf(&FleetQuery {
            node_id: Some("node-b".into()),
            category: Some("sql_injection".into()),
            limit: 10,
            ..FleetQuery::default()
        })
        .expect("WAF read");
    assert_eq!(waf.len(), 1);
    assert_eq!(waf[0].rule_id, 942100);
    assert_eq!(
        store
            .count_for_node(TelemetryTable::Waf, "node-b")
            .expect("count"),
        1
    );

    assert_eq!(store.query_bans(None).expect("bans read").len(), 1);
    assert_eq!(
        store
            .prune_stale_bans("2026-02-01T00:00:00+00:00")
            .expect("ban prune writes"),
        1
    );

    drop(store);
    ClusterTelemetryStore::open(dir.path()).expect("an upgraded file reopens");
}
