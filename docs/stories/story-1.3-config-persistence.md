# Story 1.3: Configuration State and Persistence

**Epic:** [Epic 1 - Foundation](../prd/epic-1-foundation.md)
**Status:** Draft
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

- [ ] Create `lorica-config` crate in workspace
- [ ] Define Rust structs for Route, Backend, Certificate, GlobalSettings, AdminUser, UserPreference, NotificationConfig
- [ ] Add rusqlite dependency with WAL mode
- [ ] Create initial SQL migration (`001_initial.sql`)
- [ ] Implement migration runner (version table + auto-run on startup)
- [ ] Implement ConfigStore with CRUD for all entities
- [ ] Implement TOML export (serde + toml crate)
- [ ] Implement TOML import with validation
- [ ] Write unit tests for all CRUD operations
- [ ] Write test for export/import round-trip
- [ ] Write test for crash safety (WAL mode verification)

## Dev Notes

- See `docs/architecture/data-models-and-schema-changes.md` for full schema
- Use UUID for all primary keys (uuid crate)
- Private key PEM should be encrypted at rest in the database
- TOML export format must include a `version` field for forward compatibility
- Keep ConfigStore as the sole database access point - no raw SQL elsewhere
