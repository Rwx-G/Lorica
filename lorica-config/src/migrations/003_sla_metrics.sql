-- SLA configuration per route
CREATE TABLE IF NOT EXISTS sla_configs (
    route_id TEXT PRIMARY KEY REFERENCES routes(id) ON DELETE CASCADE,
    target_pct REAL NOT NULL DEFAULT 99.9,
    max_latency_ms INTEGER NOT NULL DEFAULT 500,
    success_status_min INTEGER NOT NULL DEFAULT 200,
    success_status_max INTEGER NOT NULL DEFAULT 399,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Time-bucketed SLA metrics (1-minute resolution)
CREATE TABLE IF NOT EXISTS sla_buckets (
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
    source TEXT NOT NULL DEFAULT 'passive',
    UNIQUE(route_id, bucket_start, source)
);

CREATE INDEX IF NOT EXISTS idx_sla_buckets_route_time
    ON sla_buckets(route_id, bucket_start);

CREATE INDEX IF NOT EXISTS idx_sla_buckets_time
    ON sla_buckets(bucket_start);
