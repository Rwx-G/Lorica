-- lorica.db exactly as Lorica v1.0.0 left a fresh file: the sqlite_master
-- DDL and every seeded row, dumped by running that tag's own
-- ConfigStore::open. A frozen historical artefact: never edit it to
-- follow the live schema, which is what it exists to be compared with.
-- applied_at is normalised; it is the only value the dump run chose.
CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
CREATE TABLE global_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE certificates (
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
, acme_method TEXT DEFAULT NULL, acme_dns_provider_id TEXT DEFAULT NULL);
CREATE INDEX idx_certificates_domain ON certificates(domain);
CREATE INDEX idx_certificates_not_after ON certificates(not_after);
CREATE TABLE routes (
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
    updated_at TEXT NOT NULL DEFAULT (datetime('now')), force_https INTEGER NOT NULL DEFAULT 0, redirect_hostname TEXT DEFAULT NULL, hostname_aliases TEXT NOT NULL DEFAULT '[]', proxy_headers TEXT NOT NULL DEFAULT '{}', response_headers TEXT NOT NULL DEFAULT '{}', security_headers TEXT NOT NULL DEFAULT 'moderate', connect_timeout_s INTEGER NOT NULL DEFAULT 5, read_timeout_s INTEGER NOT NULL DEFAULT 60, send_timeout_s INTEGER NOT NULL DEFAULT 60, strip_path_prefix TEXT DEFAULT NULL, add_path_prefix TEXT DEFAULT NULL, access_log_enabled INTEGER NOT NULL DEFAULT 1, proxy_headers_remove TEXT NOT NULL DEFAULT '[]', response_headers_remove TEXT NOT NULL DEFAULT '[]', max_request_body_bytes INTEGER DEFAULT NULL, websocket_enabled INTEGER NOT NULL DEFAULT 1, rate_limit_rps INTEGER DEFAULT NULL, rate_limit_burst INTEGER DEFAULT NULL, ip_allowlist TEXT NOT NULL DEFAULT '[]', ip_denylist TEXT NOT NULL DEFAULT '[]', cors_allowed_origins TEXT NOT NULL DEFAULT '[]', cors_allowed_methods TEXT NOT NULL DEFAULT '[]', cors_max_age_s INTEGER DEFAULT NULL, compression_enabled INTEGER NOT NULL DEFAULT 0, retry_attempts INTEGER DEFAULT NULL, cache_enabled INTEGER NOT NULL DEFAULT 0, cache_ttl_s INTEGER NOT NULL DEFAULT 300, cache_max_bytes INTEGER NOT NULL DEFAULT 52428800, max_connections INTEGER DEFAULT NULL, slowloris_threshold_ms INTEGER NOT NULL DEFAULT 5000, auto_ban_threshold INTEGER DEFAULT NULL, auto_ban_duration_s INTEGER NOT NULL DEFAULT 3600, path_rewrite_pattern TEXT, path_rewrite_replacement TEXT, redirect_to TEXT DEFAULT NULL, path_rules TEXT DEFAULT '[]', return_status INTEGER DEFAULT NULL,
    FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE SET NULL
);
CREATE INDEX idx_routes_hostname ON routes(hostname);
CREATE TABLE backends (
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
, health_check_path TEXT DEFAULT NULL, name TEXT NOT NULL DEFAULT '', group_name TEXT NOT NULL DEFAULT '', h2_upstream INTEGER NOT NULL DEFAULT 0, tls_sni TEXT NOT NULL DEFAULT '', tls_skip_verify INTEGER NOT NULL DEFAULT 0);
CREATE INDEX idx_backends_health_status ON backends(health_status);
CREATE TABLE route_backends (
    route_id TEXT NOT NULL,
    backend_id TEXT NOT NULL,
    PRIMARY KEY (route_id, backend_id),
    FOREIGN KEY (route_id) REFERENCES routes(id) ON DELETE CASCADE,
    FOREIGN KEY (backend_id) REFERENCES backends(id) ON DELETE CASCADE
);
CREATE TABLE notification_configs (
    id TEXT PRIMARY KEY,
    channel TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    config TEXT NOT NULL DEFAULT '{}',
    alert_types TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE user_preferences (
    id TEXT PRIMARY KEY,
    preference_key TEXT NOT NULL UNIQUE,
    value TEXT NOT NULL DEFAULT 'never',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE admin_users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_login TEXT
);
CREATE TABLE sla_configs (
    route_id TEXT PRIMARY KEY REFERENCES routes(id) ON DELETE CASCADE,
    target_pct REAL NOT NULL DEFAULT 99.9,
    max_latency_ms INTEGER NOT NULL DEFAULT 500,
    success_status_min INTEGER NOT NULL DEFAULT 200,
    success_status_max INTEGER NOT NULL DEFAULT 399,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE sla_buckets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    route_id TEXT NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
    bucket_start TEXT NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,
    latency_sum_ms INTEGER NOT NULL DEFAULT 0,
    latency_min_ms INTEGER NOT NULL DEFAULT 0,
    latency_max_ms INTEGER NOT NULL DEFAULT 0,
    latency_p50_ms INTEGER NOT NULL DEFAULT 0,
    latency_p95_ms INTEGER NOT NULL DEFAULT 0,
    latency_p99_ms INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL DEFAULT 'passive', cfg_max_latency_ms INTEGER NOT NULL DEFAULT 500, cfg_status_min INTEGER NOT NULL DEFAULT 200, cfg_status_max INTEGER NOT NULL DEFAULT 399, cfg_target_pct REAL NOT NULL DEFAULT 99.9,
    UNIQUE(route_id, bucket_start, source)
);
CREATE INDEX idx_sla_buckets_route_time
    ON sla_buckets(route_id, bucket_start);
CREATE INDEX idx_sla_buckets_time
    ON sla_buckets(bucket_start);
CREATE TABLE probe_configs (
    id TEXT PRIMARY KEY,
    route_id TEXT NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
    method TEXT NOT NULL DEFAULT 'GET',
    path TEXT NOT NULL DEFAULT '/',
    expected_status INTEGER NOT NULL DEFAULT 200,
    interval_s INTEGER NOT NULL DEFAULT 30,
    timeout_ms INTEGER NOT NULL DEFAULT 5000,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_probe_configs_route
    ON probe_configs(route_id);
CREATE TABLE load_test_configs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    target_url TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    headers TEXT NOT NULL DEFAULT '{}',
    body TEXT,
    concurrency INTEGER NOT NULL DEFAULT 10,
    requests_per_second INTEGER NOT NULL DEFAULT 100,
    duration_s INTEGER NOT NULL DEFAULT 30,
    error_threshold_pct REAL NOT NULL DEFAULT 10.0,
    schedule_cron TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE load_test_results (
    id TEXT PRIMARY KEY,
    config_id TEXT NOT NULL REFERENCES load_test_configs(id) ON DELETE CASCADE,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    total_requests INTEGER NOT NULL DEFAULT 0,
    successful_requests INTEGER NOT NULL DEFAULT 0,
    failed_requests INTEGER NOT NULL DEFAULT 0,
    avg_latency_ms REAL NOT NULL DEFAULT 0,
    p50_latency_ms INTEGER NOT NULL DEFAULT 0,
    p95_latency_ms INTEGER NOT NULL DEFAULT 0,
    p99_latency_ms INTEGER NOT NULL DEFAULT 0,
    min_latency_ms INTEGER NOT NULL DEFAULT 0,
    max_latency_ms INTEGER NOT NULL DEFAULT 0,
    throughput_rps REAL NOT NULL DEFAULT 0,
    aborted INTEGER NOT NULL DEFAULT 0,
    abort_reason TEXT
);
CREATE INDEX idx_load_test_results_config
    ON load_test_results(config_id, started_at);
CREATE TABLE waf_custom_rules (
    id INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'custom',
    pattern TEXT NOT NULL,
    severity INTEGER NOT NULL DEFAULT 5,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE probe_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    probe_id TEXT NOT NULL,
    route_id TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    latency_ms INTEGER NOT NULL,
    success INTEGER NOT NULL,
    error TEXT,
    executed_at TEXT NOT NULL
);
CREATE INDEX idx_probe_results_probe_id ON probe_results(probe_id);
CREATE INDEX idx_probe_results_executed_at ON probe_results(executed_at);
CREATE TABLE dns_providers (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    provider_type TEXT NOT NULL,
                    config TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    username TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
INSERT INTO schema_migrations (version, applied_at) VALUES (1, '2026-01-01 00:00:00');
INSERT INTO schema_migrations (version, applied_at) VALUES (2, '2026-01-01 00:00:00');
INSERT INTO schema_migrations (version, applied_at) VALUES (3, '2026-01-01 00:00:00');
INSERT INTO schema_migrations (version, applied_at) VALUES (4, '2026-01-01 00:00:00');
INSERT INTO schema_migrations (version, applied_at) VALUES (5, '2026-01-01 00:00:00');
INSERT INTO schema_migrations (version, applied_at) VALUES (6, '2026-01-01 00:00:00');
INSERT INTO schema_migrations (version, applied_at) VALUES (7, '2026-01-01 00:00:00');
INSERT INTO schema_migrations (version, applied_at) VALUES (8, '2026-01-01 00:00:00');
INSERT INTO schema_migrations (version, applied_at) VALUES (9, '2026-01-01 00:00:00');
INSERT INTO schema_migrations (version, applied_at) VALUES (10, '2026-01-01 00:00:00');
INSERT INTO schema_migrations (version, applied_at) VALUES (11, '2026-01-01 00:00:00');
INSERT INTO schema_migrations (version, applied_at) VALUES (12, '2026-01-01 00:00:00');
INSERT INTO schema_migrations (version, applied_at) VALUES (13, '2026-01-01 00:00:00');
INSERT INTO schema_migrations (version, applied_at) VALUES (14, '2026-01-01 00:00:00');
INSERT INTO schema_migrations (version, applied_at) VALUES (15, '2026-01-01 00:00:00');
INSERT INTO schema_migrations (version, applied_at) VALUES (16, '2026-01-01 00:00:00');
INSERT INTO schema_migrations (version, applied_at) VALUES (17, '2026-01-01 00:00:00');
INSERT INTO schema_migrations (version, applied_at) VALUES (18, '2026-01-01 00:00:00');
INSERT INTO schema_migrations (version, applied_at) VALUES (19, '2026-01-01 00:00:00');
INSERT INTO schema_migrations (version, applied_at) VALUES (20, '2026-01-01 00:00:00');
INSERT INTO schema_migrations (version, applied_at) VALUES (21, '2026-01-01 00:00:00');
INSERT INTO global_settings (key, value) VALUES ('management_port', '9443');
INSERT INTO global_settings (key, value) VALUES ('log_level', 'info');
INSERT INTO global_settings (key, value) VALUES ('default_health_check_interval_s', '10');
