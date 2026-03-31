-- Snapshot the SLA success criteria active when each bucket was recorded.
-- This ensures historical reporting remains consistent even if the SLA
-- configuration is changed after the fact.
ALTER TABLE sla_buckets ADD COLUMN cfg_max_latency_ms INTEGER NOT NULL DEFAULT 500;
ALTER TABLE sla_buckets ADD COLUMN cfg_status_min INTEGER NOT NULL DEFAULT 200;
ALTER TABLE sla_buckets ADD COLUMN cfg_status_max INTEGER NOT NULL DEFAULT 399;
ALTER TABLE sla_buckets ADD COLUMN cfg_target_pct REAL NOT NULL DEFAULT 99.9;
