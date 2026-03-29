# Story 1.3: Configuration State and Persistence

**Epic:** [Epic 1 - Foundation](../prd/epic-1-foundation.md)
**Status:** Review
**Priority:** P0
**Depends on:** Story 1.2

---

As an infrastructure engineer,
I want Lorica to persist its configuration in an embedded database,
so that my routes, backends, and certificates survive restarts.

## Acceptance Criteria

1. `lorica-config` crate created
2. Data model defined: Route, Backend, Certificate, GlobalSettings
3. Embedded SQLite database with WAL mode for crash safety
4. CRUD operations for all data model entities
5. Database file created automatically on first launch in data directory
6. Database migrations system for future schema changes
7. TOML export: serialize full state to a TOML file
8. TOML import: deserialize and load a TOML file into the database
9. Unit tests for all CRUD operations and export/import round-trip

## Integration Verification

- IV1: Database survives unclean shutdown (kill -9) without corruption
- IV2: Export -> wipe -> import produces identical state
- IV3: Schema migration runs automatically on binary upgrade

## Tasks

- [x] Create `lorica-config` crate in workspace
- [x] Define Rust structs for Route, Backend, Certificate, GlobalSettings, AdminUser, UserPreference, NotificationConfig
- [x] Add rusqlite dependency with WAL mode
- [x] Create initial SQL migration (`001_initial.sql`)
- [x] Implement migration runner (version table + auto-run on startup)
- [x] Implement ConfigStore with CRUD for all entities
- [x] Implement TOML export (serde + toml crate)
- [x] Implement TOML import with validation
- [x] Write unit tests for all CRUD operations
- [x] Write test for export/import round-trip
- [x] Write test for crash safety (WAL mode verification)

## Dev Notes

- See `docs/architecture/data-models-and-schema-changes.md` for full schema
- Use UUID for all primary keys (uuid crate)
- Private key PEM should be encrypted at rest in the database
- TOML export format must include a `version` field for forward compatibility
- Keep ConfigStore as the sole database access point - no raw SQL elsewhere

## Dev Agent Record

### Agent Model Used
Claude Opus 4.6

### File List
- `Cargo.toml` (modified - added lorica-config to workspace members)
- `lorica-config/Cargo.toml` (new)
- `lorica-config/src/lib.rs` (new)
- `lorica-config/src/error.rs` (new - ConfigError with thiserror)
- `lorica-config/src/models.rs` (new - Route, Backend, Certificate, GlobalSettings, AdminUser, UserPreference, NotificationConfig, RouteBackend + enums)
- `lorica-config/src/store.rs` (new - ConfigStore with CRUD, migrations, WAL mode)
- `lorica-config/src/export.rs` (new - TOML export with version field)
- `lorica-config/src/import.rs` (new - TOML import with validation)
- `lorica-config/src/migrations/001_initial.sql` (new - initial schema)
- `lorica-config/src/tests.rs` (new - 17 unit tests)

### Change Log
- feat(config): add lorica-config crate with SQLite persistence

### Completion Notes
- All 17 tests pass (CRUD for all 7 entities + route-backend links + global settings + migration + export/import round-trip + WAL crash safety + import validation + file export/import + clear all)
- Clippy clean with `-D clippy::all`
- Formatted with `cargo fmt`
- All enums implement `std::str::FromStr` trait
- serde_json used for JSON array columns (san_domains, alert_types)
- ConfigStore is the sole database access point as required
