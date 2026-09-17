# Data Models and Schema Changes

> **Status: the per-table sections below are HISTORICAL. They are the
> v1.0 design round (7 tables, 4 indexes) and are not maintained.**
>
> Read them for the reasoning behind the original shape. Do not read
> them as a description of the running database: the column lists are
> v1.0 columns. Audit M-24 (v1.5.2) prepended the first version of this
> banner ; it was refreshed during the v1.8.0 cycle.
>
> **What is true today.** The configuration database holds 34 tables
> and its schema version is 60. Captured traffic is not one of them: a
> capture rule is a row, the captured bodies are files on disk.
>
> ## Where the migrations actually live
>
> The authoritative list is the `MIGRATIONS` constant in
> `lorica-config/src/store/mod.rs`: a slice of `(version, fn)` pairs,
> 1 through 60 in ascending order, applied by
> `ConfigStore::run_migrations`. Start there. It is the only place that
> enumerates the whole history.
>
> **`lorica-config/src/migrations/` is not that list.** The directory
> holds 18 `.sql` batch files and they cover schema versions 1-16, 19
> and 21 only. Every other version (17, 18, 20, and 22 through 60) is a
> Rust function in `store/mod.rs` carrying its DDL inline. A reader who
> follows the directory alone sees 18 of the 60 migrations and misses
> every table added since v1.6.0. The filenames also drift from the
> version numbers past 16: `017_acme_method.sql` is version 19 and
> `019_sessions.sql` is version 21, and no `018_*.sql` exists.
>
> ## The rest of the current sources
>
> - `lorica-config/src/store/mod.rs` - besides `MIGRATIONS`, the
>   `column_exists` / `add_column_if_absent` helpers that make the
>   post-22 migrations idempotent for databases upgraded from the
>   pre-tracked runner, which already carry those columns.
> - `lorica-config/src/store/*.rs` - roughly one module per table
>   (`routes.rs`, `backends.rs`, `certs.rs`, `capture.rs`,
>   `automation_token.rs`, `oidc_issuer.rs`, `cluster_*.rs`, ...), each
>   holding the SELECT / INSERT / UPDATE queries against the current
>   column set.
> - `lorica-config/src/models/` - the Rust struct shape that round-
>   trips through serde for the API. Field names match the column
>   names ; field doc-comments explain when each was added.
> - `lorica-config/src/canonical.rs` - the cluster replication blob.
>   `CANONICAL_FORMAT_VERSION` is `2`; it moved from 1 to 2 during the
>   v1.8.0 cycle and the whole of that release rides the same number,
>   guarded by a shape digest rather than by the integer alone.
>
> Two further SQLite databases exist outside `lorica-config` and are
> not migrated by `MIGRATIONS`. They create their tables with
> `CREATE TABLE IF NOT EXISTS` at open time:
>
> - `access-log.db` via `lorica-api/src/log_store.rs`: `access_logs`,
>   `waf_events`, `notification_history`, `audit_log`, `audit_log_meta`.
> - `cluster-telemetry.db` via `lorica-api/src/cluster_telemetry_store.rs`
>   on a control-plane node: `fleet_access_logs`, `fleet_waf_events`,
>   `fleet_bans`.
>
> ## Notable additions since v1.0, by cycle
>
> - Through v1.5.x: `sessions`, `bot_pending_challenges`,
>   `cert_export_acls`, `dns_providers`, `probe_configs`,
>   `probe_results`, `sla_buckets`, `sla_configs`, `load_test_configs`,
>   `load_test_results`, `waf_custom_rules`, `ai_crawlers_custom`.
> - v1.6.0 (migrations up to 46): `users` replaced `admin_users`
>   (migration 22, RBAC backfill, `admin_users` dropped), and sessions
>   gained a role column.
> - v1.7.0 (migrations 47-54, cluster): `acme_challenges`,
>   `cluster_state`, `cluster_ca`, `cluster_nodes`,
>   `cluster_join_tokens`, `cluster_revoked_serials`,
>   `cluster_identity`, `cluster_secrets`, `cluster_replica`.
> - v1.8.0 (migrations 56-60, capture and CI automation):
>   `capture_rules`, `api_tokens`, `automation_environments`,
>   `oidc_issuers` (plus its `ca_pem` column at 60). Routes and
>   backends gained `managed_by`, and `CANONICAL_FORMAT_VERSION`
>   became 2.
>
> The `Route` table grew from 9 columns to 30+ (basic-auth,
> stale-while-revalidate, rate-limit struct, geoip, mTLS, forward-auth,
> mirror, response-rewrite, header-rules, traffic-splits,
> bot-protection, group-name, `managed_by`, ...). The
> `NotificationChannel` enum gained `Slack` (v1.4.0) ;
> `UserPreference.value` gained additional variants.
>
> A full rewrite is `feat`-shaped and tracked in `docs/backlog.md` ;
> for now, treat the sections below as the v1.0 reference baseline and
> the pointers above as current.

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

### User

**Purpose:** Dashboard / API user account with RBAC role (Story 8.3, v1.6.0; replaced the single-admin `AdminUser` / `admin_users` table via schema migration 22).
**Integration:** Used by API authentication middleware and per-route authorization; the session carries the role.

**Key Attributes:**
- `id`: TEXT (UUID) - Primary key
- `username`: TEXT - Unique username (bootstrap account: `admin`)
- `password_hash`: TEXT - Argon2id hash
- `role`: TEXT - `super_admin`, `operator`, or `viewer`
- `must_change_password`: BOOLEAN - True on first run / after admin reset
- `created_at`: TIMESTAMP
- `last_login_at`: TIMESTAMP (nullable)
- `disabled_at`: TIMESTAMP (nullable) - Set when the account is disabled; login rejected
- `created_by`: TEXT (nullable) - `users.id` of the creating account

## Schema Integration Strategy

**Database Changes Required:**
- **New Tables:** `routes`, `backends`, `route_backends` (join), `certificates`, `notification_configs`, `user_preferences`, `users`, `schema_migrations`
- **Modified Tables:** None (new database)
- **New Indexes:** `idx_routes_hostname`, `idx_backends_health_status`, `idx_certificates_domain`, `idx_certificates_not_after`
- **Migration Strategy:** Embedded migrations using a simple version table (`schema_migrations`). Migrations run automatically on startup. Each migration was a SQL file compiled into the binary at v1.0; today only versions 1-16, 19 and 21 still are, and every other version is a Rust function in the `MIGRATIONS` slice (see the banner).

**Backward Compatibility:**
- TOML export format is versioned (field `version` in export file)
- Lorica can import any prior TOML format version (forward-compatible reader)
- Database schema changes between versions are handled by auto-migrations
