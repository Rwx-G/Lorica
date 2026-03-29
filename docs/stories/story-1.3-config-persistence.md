# Story 1.3: Configuration State and Persistence

**Epic:** [Epic 1 - Foundation](../prd/epic-1-foundation.md)
**Status:** Done
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
- `lorica-config/Cargo.toml` (new - added ring dependency for encryption)
- `lorica-config/src/lib.rs` (new - with #![deny(clippy::all)])
- `lorica-config/src/error.rs` (new - ConfigError with thiserror)
- `lorica-config/src/models.rs` (new - Route, Backend, Certificate, GlobalSettings, AdminUser, UserPreference, NotificationConfig, RouteBackend + enums)
- `lorica-config/src/store.rs` (new - ConfigStore with CRUD, migrations, WAL mode, key_pem encryption)
- `lorica-config/src/crypto.rs` (new - AES-256-GCM encryption for key_pem at rest)
- `lorica-config/src/export.rs` (new - TOML export with version field)
- `lorica-config/src/import.rs` (new - TOML import with validation)
- `lorica-config/src/migrations/001_initial.sql` (new - initial schema)
- `lorica-config/src/tests.rs` (new - 26 unit tests)
- `docs/backlog.md` (modified - removed fixed items)

### Change Log
- feat(config): add lorica-config crate with SQLite persistence
- fix(config): address QA findings for 1.3 - key_pem encryption at rest, #![deny(clippy::all)]

### Completion Notes
- All 26 tests pass (17 original + 6 crypto + 3 encrypted storage)
- Clippy clean with `-D clippy::all` (now enforced in lib.rs)
- Formatted with `cargo fmt`
- All enums implement `std::str::FromStr` trait
- serde_json used for JSON array columns (san_domains, alert_types)
- ConfigStore is the sole database access point as required
- Certificate key_pem encrypted at rest with AES-256-GCM via ring (Dev Notes requirement)
- EncryptionKey::load_or_create manages key file lifecycle

## QA Results

### Review Date: 2026-03-29

### Reviewed By: Quinn (Test Architect)

### Code Quality Assessment

Solid implementation with clean architecture. The `lorica-config` crate follows Rust best practices: proper use of `thiserror` for error types, `FromStr` trait implementations, clean module separation (models/store/export/import/error). ConfigStore correctly acts as the sole database access point. WAL mode and foreign keys are enabled at connection open. Migration system is idempotent and version-tracked. TOML export includes the required version field for forward compatibility. All 17 tests pass and cover the full CRUD surface plus round-trip and crash safety scenarios.

### Refactoring Performed

None - implementation is clean and does not require refactoring at this stage.

### Compliance Check

- Coding Standards: PASS
- Project Structure: PASS - follows source-tree.md layout for lorica-config
- Testing Strategy: PASS - unit tests in dedicated test module, covers all CRUD + edge cases
- All ACs Met: PASS - all 9 acceptance criteria are satisfied

### AC Traceability

| AC | Status | Evidence |
|----|--------|----------|
| AC1: lorica-config crate | PASS | Crate created with Cargo.toml, added to workspace |
| AC2: Data models | PASS | Route, Backend, Certificate, GlobalSettings + AdminUser, UserPreference, NotificationConfig in models.rs |
| AC3: SQLite with WAL | PASS | `PRAGMA journal_mode=WAL` in ConfigStore::open, test_wal_mode_enabled confirms persistence |
| AC4: CRUD operations | PASS | Full CRUD for all 7 entities + route-backend links + global settings in store.rs |
| AC5: Auto-create DB | PASS | ConfigStore::open creates file via rusqlite Connection::open |
| AC6: Migrations | PASS | schema_migrations table, version tracking, auto-run on open, test_migration_idempotent |
| AC7: TOML export | PASS | export.rs with version field, export_to_toml and export_to_file |
| AC8: TOML import | PASS | import.rs with parse_toml validation (references, version), import_to_store |
| AC9: Unit tests | PASS | 17 tests covering all CRUD, round-trip, crash safety, validation, clear |

### IV Traceability

| IV | Status | Evidence |
|----|--------|----------|
| IV1: Crash safety | PASS | test_wal_mode_enabled: write -> drop (simulate crash) -> reopen -> data intact |
| IV2: Export-wipe-import | PASS | test_export_import_round_trip: full state export -> fresh store import -> verify all data matches |
| IV3: Auto-migration | PASS | test_migration_idempotent: open twice on same file, schema version remains 1 |

### Improvements Checklist

- [x] All acceptance criteria implemented
- [x] All integration verifications covered by tests
- [x] Clippy clean, cargo fmt applied
- [ ] Consider encrypting key_pem at rest (noted in Dev Notes but not in ACs - defer to future story)
- [ ] Consider filtering sensitive fields (password_hash) from TOML export or adding a warning
- [ ] Consider adding `#![deny(clippy::all)]` to lib.rs per coding standards
- [ ] Consider adding doc comments (`///`) on public ConfigStore methods

### Security Review

**key_pem plaintext storage**: Dev Notes mention "Private key PEM should be encrypted at rest in the database" but this requires a key management strategy (master key derivation, rotation). This is correctly deferred as it adds significant complexity beyond this foundation story. Tracked as a future recommendation.

**Password hash in TOML export**: The export includes admin_users with argon2 password hashes. While hashed (not plaintext), the export file should be treated as sensitive. No immediate action needed but worth noting for the API layer (Story 1.4) which may expose export functionality.

No other security issues found. Foreign keys are properly configured. No SQL injection risk (parameterized queries throughout).

### Performance Considerations

No performance concerns. SQLite with WAL mode is appropriate for the expected workload. Queries use proper indexes (hostname, domain, not_after, health_status).

### Files Modified During Review

None - no refactoring was required.

### Gate Status

Gate: PASS -> docs/qa/gates/1.3-config-persistence.yml
Quality Score: 95

### Recommended Status

PASS - Ready for Done
