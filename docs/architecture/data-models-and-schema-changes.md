# Data Models and Schema Changes

> **Status: HISTORICAL (v1.0 schema baseline) — partially out of date
> as of v1.5.2.**
>
> This document was written against the v1.0 schema (7 tables, 4
> indexes). The current schema as of v1.5.2 is substantially larger
> (16+ tables, multiple migrations adding columns to existing rows) ;
> the per-table column lists below reflect what was in v1.0, not what
> the running database carries today. Audit M-24 (v1.5.2).
>
> For the **canonical current schema**, the source of truth lives in :
>
> - `lorica-config/src/migrations/` — every migration applied since
>   v1.0 (001 through 019 as of v1.5.2). Read in numeric order, this
>   tells you the current shape of every column, index, and table.
> - `lorica-config/src/store/mod.rs` — the inline `ALTER TABLE` /
>   `CREATE INDEX IF NOT EXISTS` calls that live alongside the
>   migrations (some indexes are only added at runtime, e.g. session
>   indexes per audit L-1 / sessions.rs).
> - `lorica-config/src/store/{routes,backends,certs,...}.rs` — one
>   module per table, each holding the SELECT / INSERT / UPDATE
>   queries against the current column set.
> - `lorica-config/src/models/` — the Rust struct shape that round-
>   trips through serde for the API. Field names match the column
>   names ; field doc-comments explain when each was added.
>
> Notable additions since v1.0 not described in this document :
> `sessions`, `bot_pending_challenges`, `cert_export_acls`,
> `dns_providers`, `probe_configs`, `probe_results`, `sla_buckets`,
> `load_test_configs`, `load_test_results`. The `Route` table grew
> from 9 columns to 30+ (basic-auth, stale-while-revalidate,
> rate-limit struct, geoip, mTLS, forward-auth, mirror, response-
> rewrite, header-rules, traffic-splits, bot-protection,
> group-name, ...). The `NotificationChannel` enum gained `Slack`
> (v1.4.0) ; `UserPreference.value` gained additional variants.
>
> A full rewrite is `feat`-shaped and tracked in `docs/backlog.md` ;
> for now, treat this file as the v1.0 reference baseline.

## New Data Models

### Route

**Purpose:** Defines a proxy route mapping incoming requests to backend servers.
**Integration:** Read by the `ProxyHttp` implementation to make routing decisions. Stored in SQLite, loaded into memory at startup and updated via command channel.

**Key Attributes:**
- `id`: TEXT (UUID) - Primary key
- `hostname`: TEXT - Incoming hostname to match (e.g., `example.com`)
- `path_prefix`: TEXT - Path prefix to match (default: `/`)
- `certificate_id`: TEXT (nullable, FK) - Associated TLS certificate
- `load_balancing`: TEXT - Algorithm: `round_robin`, `consistent_hash`, `random`, `peak_ewma`
- `waf_enabled`: BOOLEAN - Whether WAF is active for this route
- `waf_mode`: TEXT - `detection` or `blocking` (when WAF enabled)
- `enabled`: BOOLEAN - Whether the route is active
- `created_at`: TIMESTAMP
- `updated_at`: TIMESTAMP

**Relationships:**
- Has many Backends (via route_backends join)
- Belongs to one Certificate (optional)

### Backend

**Purpose:** Represents an upstream server that receives proxied traffic.
**Integration:** Mapped to Pingora's `HttpPeer` for connection establishment. Health status tracked and reflected in load balancing decisions.

**Key Attributes:**
- `id`: TEXT (UUID) - Primary key
- `address`: TEXT - Backend address (e.g., `192.168.1.10:8080`)
- `weight`: INTEGER - Load balancing weight (default: 100)
- `health_status`: TEXT - `healthy`, `degraded`, `down`
- `health_check_enabled`: BOOLEAN - Whether active health checks run
- `health_check_interval_s`: INTEGER - Seconds between checks (default: 10)
- `lifecycle_state`: TEXT - `normal`, `closing`, `closed`
- `active_connections`: INTEGER - Current connection count
- `tls_upstream`: BOOLEAN - Whether to use TLS to connect to backend
- `created_at`: TIMESTAMP
- `updated_at`: TIMESTAMP

**Relationships:**
- Belongs to many Routes (via route_backends join)

### Certificate

**Purpose:** Stores TLS certificates for termination.
**Integration:** Loaded into rustls `CertifiedKey` structures. Indexed by SNI trie for fast lookup during TLS handshake.

**Key Attributes:**
- `id`: TEXT (UUID) - Primary key
- `domain`: TEXT - Primary domain (e.g., `example.com`)
- `san_domains`: TEXT (JSON array) - Subject Alternative Names
- `fingerprint`: TEXT - SHA256 fingerprint
- `cert_pem`: BLOB - Certificate chain PEM
- `key_pem`: BLOB (encrypted at rest) - Private key PEM
- `issuer`: TEXT - Certificate issuer
- `not_before`: TIMESTAMP - Validity start
- `not_after`: TIMESTAMP - Validity end
- `is_acme`: BOOLEAN - Whether managed by ACME
- `acme_auto_renew`: BOOLEAN - Whether to auto-renew
- `created_at`: TIMESTAMP

**Relationships:**
- Has many Routes

### NotificationConfig

**Purpose:** Configures notification channels and alert preferences.
**Integration:** Checked by the notification system when events occur.

**Key Attributes:**
- `id`: TEXT (UUID) - Primary key
- `channel`: TEXT - `email` or `webhook`
- `enabled`: BOOLEAN
- `config`: TEXT (JSON) - Channel-specific config (SMTP settings, webhook URL)
- `alert_types`: TEXT (JSON array) - Which event types trigger this channel

### UserPreference

**Purpose:** Stores consent-driven preferences (never/always/once decisions).
**Integration:** Checked before any automated action to determine if consent is needed.

**Key Attributes:**
- `id`: TEXT (UUID) - Primary key
- `preference_key`: TEXT - Unique identifier (e.g., `self_signed_cert`, `acme_renewal`)
- `value`: TEXT - `never`, `always`, `once`
- `created_at`: TIMESTAMP
- `updated_at`: TIMESTAMP

### AdminUser

**Purpose:** Dashboard admin account.
**Integration:** Used by API authentication middleware.

**Key Attributes:**
- `id`: TEXT (UUID) - Primary key
- `username`: TEXT - Admin username (default: `admin`)
- `password_hash`: TEXT - Argon2 hash
- `must_change_password`: BOOLEAN - True on first run
- `created_at`: TIMESTAMP
- `last_login`: TIMESTAMP

## Schema Integration Strategy

**Database Changes Required:**
- **New Tables:** `routes`, `backends`, `route_backends` (join), `certificates`, `notification_configs`, `user_preferences`, `admin_users`, `schema_migrations`
- **Modified Tables:** None (new database)
- **New Indexes:** `idx_routes_hostname`, `idx_backends_health_status`, `idx_certificates_domain`, `idx_certificates_not_after`
- **Migration Strategy:** Embedded migrations using a simple version table (`schema_migrations`). Migrations run automatically on startup. Each migration is a SQL file compiled into the binary.

**Backward Compatibility:**
- TOML export format is versioned (field `version` in export file)
- Lorica can import any prior TOML format version (forward-compatible reader)
- Database schema changes between versions are handled by auto-migrations
