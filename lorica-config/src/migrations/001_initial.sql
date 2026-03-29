-- Initial schema for Lorica configuration database

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS global_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO global_settings (key, value) VALUES ('management_port', '9443');
INSERT OR IGNORE INTO global_settings (key, value) VALUES ('log_level', 'info');
INSERT OR IGNORE INTO global_settings (key, value) VALUES ('default_health_check_interval_s', '10');

CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    san_domains TEXT NOT NULL DEFAULT '[]',
    fingerprint TEXT NOT NULL,
    cert_pem BLOB NOT NULL,
    key_pem BLOB NOT NULL,
    issuer TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    is_acme INTEGER NOT NULL DEFAULT 0,
    acme_auto_renew INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_certificates_domain ON certificates(domain);
CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates(not_after);

CREATE TABLE IF NOT EXISTS routes (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    path_prefix TEXT NOT NULL DEFAULT '/',
    certificate_id TEXT,
    load_balancing TEXT NOT NULL DEFAULT 'round_robin',
    waf_enabled INTEGER NOT NULL DEFAULT 0,
    waf_mode TEXT NOT NULL DEFAULT 'detection',
    topology_type TEXT NOT NULL DEFAULT 'single_vm',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_routes_hostname ON routes(hostname);

CREATE TABLE IF NOT EXISTS backends (
    id TEXT PRIMARY KEY,
    address TEXT NOT NULL,
    weight INTEGER NOT NULL DEFAULT 100,
    health_status TEXT NOT NULL DEFAULT 'healthy',
    health_check_enabled INTEGER NOT NULL DEFAULT 1,
    health_check_interval_s INTEGER NOT NULL DEFAULT 10,
    lifecycle_state TEXT NOT NULL DEFAULT 'normal',
    active_connections INTEGER NOT NULL DEFAULT 0,
    tls_upstream INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_backends_health_status ON backends(health_status);

CREATE TABLE IF NOT EXISTS route_backends (
    route_id TEXT NOT NULL,
    backend_id TEXT NOT NULL,
    PRIMARY KEY (route_id, backend_id),
    FOREIGN KEY (route_id) REFERENCES routes(id) ON DELETE CASCADE,
    FOREIGN KEY (backend_id) REFERENCES backends(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notification_configs (
    id TEXT PRIMARY KEY,
    channel TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    config TEXT NOT NULL DEFAULT '{}',
    alert_types TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS user_preferences (
    id TEXT PRIMARY KEY,
    preference_key TEXT NOT NULL UNIQUE,
    value TEXT NOT NULL DEFAULT 'never',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS admin_users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_login TEXT
);
