-- Active SLA probe configuration per route
CREATE TABLE IF NOT EXISTS probe_configs (
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

CREATE INDEX IF NOT EXISTS idx_probe_configs_route
    ON probe_configs(route_id);
