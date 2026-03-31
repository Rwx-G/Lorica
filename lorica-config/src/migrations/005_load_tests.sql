-- Load test configurations
CREATE TABLE IF NOT EXISTS load_test_configs (
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

-- Load test results (one row per completed test run)
CREATE TABLE IF NOT EXISTS load_test_results (
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

CREATE INDEX IF NOT EXISTS idx_load_test_results_config
    ON load_test_results(config_id, started_at);
