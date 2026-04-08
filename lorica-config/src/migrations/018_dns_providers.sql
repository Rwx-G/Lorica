-- Migration 018: Add global DNS providers table and reference column on certificates.
-- DNS credentials are stored once in dns_providers and referenced by ID,
-- instead of duplicating encrypted credentials on every certificate.

CREATE TABLE IF NOT EXISTS dns_providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    provider_type TEXT NOT NULL,
    config TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

ALTER TABLE certificates ADD COLUMN acme_dns_provider_id TEXT DEFAULT NULL;
