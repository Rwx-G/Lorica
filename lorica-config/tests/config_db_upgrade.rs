//! Upgrade of a `lorica.db` written by a released version.
//!
//! Each fixture under `tests/fixtures/` is the file a released
//! `ConfigStore::open` left, dumped from that tag's own code: v1.0.0, the
//! oldest release, and v1.5.13, the last one before the tracked runner,
//! whose unconditional `ALTER TABLE`s left many columns on disk under a
//! recorded version of 21. Rows are written into it the way that release
//! wrote them, then the current code opens the file and reads them back.

use std::path::Path;

use chrono::{TimeZone, Utc};
use lorica_config::models::Role;
use lorica_config::ConfigStore;
use rusqlite::Connection;

const LORICA_DB_V1_0_0: &str = include_str!("fixtures/lorica_db_v1_0_0.sql");
const LORICA_DB_V1_5_13: &str = include_str!("fixtures/lorica_db_v1_5_13.sql");

/// Rows a node of that era held, written with the columns both fixtures
/// share and the RFC 3339 timestamps those releases stored.
const RELEASED_ROWS: &str = "
    INSERT INTO certificates (id, domain, fingerprint, cert_pem, key_pem, issuer,
        not_before, not_after, created_at)
    VALUES ('cert-1', 'app.example.com', 'ab:cd', 'CERT', CAST('KEY' AS BLOB), 'Example CA', '2026-01-01T00:00:00+00:00',
        '2027-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00');
    INSERT INTO routes (id, hostname, certificate_id, created_at, updated_at)
    VALUES ('route-1', 'app.example.com', 'cert-1', '2026-01-01T00:00:00+00:00',
        '2026-01-01T00:00:00+00:00');
    INSERT INTO backends (id, address, created_at, updated_at)
    VALUES ('backend-1', '192.0.2.10:8080', '2026-01-01T00:00:00+00:00',
        '2026-01-01T00:00:00+00:00');
    INSERT INTO route_backends (route_id, backend_id) VALUES ('route-1', 'backend-1');
    INSERT INTO sla_buckets (route_id, bucket_start, request_count, success_count)
    VALUES ('route-1', '2026-01-01T00:00:00+00:00', 10, 9);
    INSERT INTO admin_users (id, username, password_hash, must_change_password, created_at)
    VALUES ('admin-1', 'admin', 'hash', 0, '2026-01-01T00:00:00+00:00');
    UPDATE global_settings SET value = '9444' WHERE key = 'management_port';
";

fn write_released_file(path: &Path, fixture: &str) {
    let conn = Connection::open(path).expect("test setup: raw open");
    conn.execute_batch(fixture)
        .expect("test setup: released schema");
    conn.execute_batch(RELEASED_ROWS)
        .expect("test setup: released rows");
}

fn assert_upgrades(fixture: &str) {
    let dir = tempfile::tempdir().expect("test setup: tempdir");
    let path = dir.path().join("lorica.db");
    write_released_file(&path, fixture);

    let store = ConfigStore::open(&path, None).expect("a released lorica.db must open");

    let head = ConfigStore::open_in_memory()
        .expect("fresh store")
        .schema_version()
        .expect("fresh version");
    assert_eq!(store.schema_version().expect("version"), head);

    let route = store
        .get_route("route-1")
        .expect("route reads")
        .expect("route kept");
    assert_eq!(route.hostname, "app.example.com");
    assert_eq!(route.certificate_id.as_deref(), Some("cert-1"));
    assert_eq!(
        store.list_backends_for_route("route-1").expect("links"),
        vec!["backend-1".to_string()]
    );
    let backends = store.list_backends().expect("backends read");
    assert_eq!(backends.len(), 1);
    assert_eq!(backends[0].address, "192.0.2.10:8080");

    let cert = store
        .get_certificate("cert-1")
        .expect("certificate reads")
        .expect("certificate kept");
    assert_eq!(cert.domain, "app.example.com");
    assert_eq!(cert.key_pem, "KEY");

    // Migration 22 moved the pre-RBAC admin into `users` as the one
    // super admin, and migration 55 rebuilt `sla_buckets` with its rows.
    let admin = store
        .get_user("admin-1")
        .expect("user reads")
        .expect("admin migrated");
    assert_eq!(admin.username, "admin");
    assert_eq!(admin.role, Role::SuperAdmin);
    let from = Utc.with_ymd_and_hms(2025, 12, 31, 0, 0, 0).unwrap();
    let to = Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap();
    let buckets = store
        .query_sla_buckets("route-1", &from, &to, "passive")
        .expect("buckets read");
    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0].request_count, 10);

    assert_eq!(
        store
            .get_global_settings()
            .expect("settings read")
            .management_port,
        9444
    );

    drop(store);
    let reopened = ConfigStore::open(&path, None).expect("an upgraded file reopens");
    assert_eq!(reopened.schema_version().expect("version"), head);
}

#[test]
fn lorica_db_from_v1_0_0_upgrades_with_its_rows() {
    assert_upgrades(LORICA_DB_V1_0_0);
}

#[test]
fn lorica_db_from_v1_5_13_upgrades_with_its_rows() {
    assert_upgrades(LORICA_DB_V1_5_13);
}

/// A migration whose body fails partway leaves nothing behind: neither
/// the statements before the failure nor its version. Migration 12 adds
/// two columns; with the second already present the first is added and
/// the second fails, and the first must be rolled back with it.
/// Committed statement by statement, the first column stayed and the
/// next open replayed it into a duplicate-column error, on every start.
#[test]
fn a_migration_that_fails_midway_leaves_no_partial_schema() {
    let dir = tempfile::tempdir().expect("test setup: tempdir");
    let path = dir.path().join("lorica.db");
    {
        let conn = Connection::open(&path).expect("test setup: raw open");
        conn.execute_batch(
            "CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            INSERT INTO schema_migrations (version) VALUES (11);
            CREATE TABLE routes (
                id TEXT PRIMARY KEY,
                path_rewrite_replacement TEXT
            );",
        )
        .expect("test setup: schema at version 11");
    }

    let err = ConfigStore::open(&path, None)
        .err()
        .expect("migration 12 must fail on the duplicate column");
    assert!(
        err.to_string().contains("duplicate column name"),
        "unexpected error: {err}"
    );

    let conn = Connection::open(&path).expect("raw reopen");
    let pattern_columns: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('routes') WHERE name = 'path_rewrite_pattern'",
            [],
            |row| row.get(0),
        )
        .expect("table info");
    assert_eq!(pattern_columns, 0, "the half-applied migration was kept");
    let version: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .expect("version");
    assert_eq!(version, 11);
}

/// Channels as 1.9.1 saved them: one with an explicit list, one with an
/// empty list (every type), one with the wildcard, one that already
/// ticked one of the log-store types.
const RELEASED_CHANNELS: &str = r#"
    INSERT INTO notification_configs (id, channel, enabled, config, alert_types)
    VALUES ('explicit', 'webhook', 1, '{"url":"https://hooks.example.com/a"}',
            '["backend_down","waf_alert"]');
    INSERT INTO notification_configs (id, channel, enabled, config, alert_types)
    VALUES ('everything', 'webhook', 1, '{"url":"https://hooks.example.com/b"}', '[]');
    INSERT INTO notification_configs (id, channel, enabled, config, alert_types)
    VALUES ('wildcard', 'slack', 1, '{"url":"https://hooks.example.com/c"}', '["*"]');
    INSERT INTO notification_configs (id, channel, enabled, config, alert_types)
    VALUES ('partial', 'webhook', 0, '{"url":"https://hooks.example.com/d"}',
            '["log_store_recovered"]');
"#;

fn alert_types_of(store: &ConfigStore, id: &str) -> Vec<String> {
    store
        .get_notification_config(id)
        .expect("channel reads")
        .expect("channel kept")
        .alert_types
}

/// A channel saved before 1.9.2 with an explicit alert-type list had no
/// box to tick for the log-store alerts; the upgrade subscribes it, and
/// leaves alone the channels that already receive every type.
#[test]
fn an_upgrade_subscribes_explicit_channels_to_the_log_store_alerts() {
    let dir = tempfile::tempdir().expect("test setup: tempdir");
    let path = dir.path().join("lorica.db");
    write_released_file(&path, LORICA_DB_V1_5_13);
    Connection::open(&path)
        .expect("test setup: raw open")
        .execute_batch(RELEASED_CHANNELS)
        .expect("test setup: released channels");

    let store = ConfigStore::open(&path, None).expect("a released lorica.db must open");
    assert_eq!(
        alert_types_of(&store, "explicit"),
        [
            "backend_down",
            "waf_alert",
            "log_store_unavailable",
            "log_store_recovered",
            "adcs_authority_failed",
            "cert_issuance_failed"
        ]
    );
    assert!(alert_types_of(&store, "everything").is_empty());
    assert_eq!(alert_types_of(&store, "wildcard"), ["*"]);
    assert_eq!(
        alert_types_of(&store, "partial"),
        [
            "log_store_recovered",
            "log_store_unavailable",
            "adcs_authority_failed",
            "cert_issuance_failed"
        ],
        "a type already ticked is not added twice"
    );

    // An operator who unticks them afterwards is not overridden.
    let mut explicit = store
        .get_notification_config("explicit")
        .expect("channel reads")
        .expect("channel kept");
    explicit.alert_types = vec!["backend_down".to_string()];
    store
        .update_notification_config(&explicit)
        .expect("operator edit");
    drop(store);
    let reopened = ConfigStore::open(&path, None).expect("an upgraded file reopens");
    assert_eq!(alert_types_of(&reopened, "explicit"), ["backend_down"]);
}

/// Migration 65 does for the AD CS alerts what migration 63 did for the
/// log-store ones. The file is rewound to version 64 so the channels are
/// written as a 1.9.x node would have them, then reopened.
#[test]
fn an_upgrade_subscribes_explicit_channels_to_the_adcs_alerts() {
    let dir = tempfile::tempdir().expect("test setup: tempdir");
    let path = dir.path().join("lorica.db");
    drop(ConfigStore::open(&path, None).expect("test setup: fresh store"));
    Connection::open(&path)
        .expect("test setup: raw open")
        .execute_batch(
            r#"
            DELETE FROM schema_migrations WHERE version >= 65;
            INSERT INTO notification_configs (id, channel, enabled, config, alert_types)
            VALUES ('explicit', 'webhook', 1, '{"url":"https://hooks.example.com/a"}',
                    '["backend_down","log_store_unavailable"]');
            INSERT INTO notification_configs (id, channel, enabled, config, alert_types)
            VALUES ('everything', 'webhook', 1, '{"url":"https://hooks.example.com/b"}', '[]');
            INSERT INTO notification_configs (id, channel, enabled, config, alert_types)
            VALUES ('wildcard', 'slack', 1, '{"url":"https://hooks.example.com/c"}', '["*"]');
            INSERT INTO notification_configs (id, channel, enabled, config, alert_types)
            VALUES ('partial', 'webhook', 0, '{"url":"https://hooks.example.com/d"}',
                    '["cert_issuance_failed"]');
            "#,
        )
        .expect("test setup: channels saved at version 64");

    let store = ConfigStore::open(&path, None).expect("a version 64 lorica.db must open");
    assert_eq!(
        alert_types_of(&store, "explicit"),
        [
            "backend_down",
            "log_store_unavailable",
            "adcs_authority_failed",
            "cert_issuance_failed"
        ]
    );
    assert!(alert_types_of(&store, "everything").is_empty());
    assert_eq!(alert_types_of(&store, "wildcard"), ["*"]);
    assert_eq!(
        alert_types_of(&store, "partial"),
        ["cert_issuance_failed", "adcs_authority_failed"],
        "a type already ticked is not added twice"
    );

    let mut explicit = store
        .get_notification_config("explicit")
        .expect("channel reads")
        .expect("channel kept");
    explicit.alert_types = vec!["backend_down".to_string()];
    store
        .update_notification_config(&explicit)
        .expect("operator edit");
    drop(store);
    let reopened = ConfigStore::open(&path, None).expect("an upgraded file reopens");
    assert_eq!(alert_types_of(&reopened, "explicit"), ["backend_down"]);
}
