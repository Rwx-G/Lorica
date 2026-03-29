# Story 1.10: Configuration Export/Import and Settings

**Epic:** [Epic 1 - Foundation](../prd/epic-1-foundation.md)
**Status:** Done
**Priority:** P1
**Depends on:** Stories 1.5, 1.3

---

As an infrastructure engineer,
I want to export my full configuration and adjust global settings from the dashboard,
so that I can backup, share, and restore my proxy setup.

## Acceptance Criteria

1. Settings screen: global configuration (management port display, log level, default health check interval)
2. Export button: downloads current state as a TOML file
3. Import function: upload a TOML file, preview changes, apply with confirmation
4. Import shows diff: what will be added, modified, or removed
5. Settings for notification preferences (stdout always on, email/webhook configuration)
6. Preference memory UI: manage stored preferences (never/always/once decisions)

## Integration Verification

- IV1: Exported TOML can be imported on a fresh Lorica instance and produce identical configuration
- IV2: Import preview accurately reflects the changes that will be applied
- IV3: Settings changes take effect immediately without restart

## Tasks

- [x] Build settings screen with global config display
- [x] Implement export button (calls `POST /api/v1/config/export`, downloads file)
- [x] Implement import UI (file upload, calls `POST /api/v1/config/import`)
- [x] Build import diff preview screen (added/modified/removed)
- [x] Implement import confirmation flow (`POST /api/v1/config/import/confirm`)
- [x] Build notification preferences section (email SMTP config, webhook URL)
- [x] Build preference memory management UI
- [x] Test round-trip: export from instance A, import to instance B
- [x] Test import diff preview accuracy

## Dev Notes

- Export TOML format must include a `version` field for forward compatibility
- Import preview uses ConfigDiff from lorica-config to compute changes
- Settings that require restart should display a warning (though most should be hot-reloadable)
- Notification preferences stored in NotificationConfig table
- User preferences stored in UserPreference table

## Dev Agent Record

- ConfigDiff module added to lorica-config for computing import diffs
- Import preview endpoint added: POST /api/v1/config/import/preview
- Settings CRUD endpoints: GET/PUT /api/v1/settings
- Notification config CRUD: GET/POST/PUT/DELETE /api/v1/notifications
- Preference management: GET/PUT/DELETE /api/v1/preferences
- Settings.svelte page with 4 sections: Global Config, Notifications, Preferences, Export/Import
- Management port shown as read-only (requires restart)
- Import flow: upload file -> preview diff -> confirm/cancel

## File List

- `lorica-config/src/diff.rs` - ConfigDiff computation (new)
- `lorica-config/src/lib.rs` - Module registration
- `lorica-config/src/tests.rs` - 5 new diff tests
- `lorica-api/src/settings.rs` - Settings, notifications, preferences endpoints (new)
- `lorica-api/src/config.rs` - Import preview endpoint added
- `lorica-api/src/lib.rs` - Module registration
- `lorica-api/src/server.rs` - Route registration
- `lorica-api/src/tests.rs` - 8 new integration tests
- `lorica-dashboard/frontend/src/lib/api.ts` - 12 new API client methods and interfaces
- `lorica-dashboard/frontend/src/lib/api.test.ts` - 12 new tests
- `lorica-dashboard/frontend/src/routes/Settings.svelte` - Settings page (new)
- `lorica-dashboard/frontend/src/routes/Dashboard.svelte` - Settings route wiring

## Change Log

- 2026-03-30: Implementation complete - all tasks done, all tests passing

## QA Results

### Review Date: 2026-03-30

### Reviewed By: Quinn (Test Architect)

### Code Quality Assessment

Strong implementation quality. Backend follows established patterns (ConfigStore CRUD, axum handlers, JSON envelope responses). The ConfigDiff module is well-designed with a generic `diff_by_id` helper that avoids repetition across entity types. The Settings.svelte component handles four distinct concerns (settings, notifications, preferences, export/import) cleanly with proper state management and error handling. All code passes Svelte type checking and Rust compilation with no warnings in new code.

### Refactoring Performed

No refactoring needed - code quality is high.

### Compliance Check

- Coding Standards: Pass - `#![deny(clippy::all)]` enforced, proper doc comments on public APIs, consistent error handling
- Project Structure: Pass - new files match source-tree.md (diff.rs, settings.rs), frontend follows established page/component conventions
- Testing Strategy: Pass - unit tests in `#[cfg(test)]` modules, integration tests via tower::ServiceExt, frontend tests via Vitest with mock fetch
- All ACs Met: Pass - all 6 acceptance criteria fully implemented and testable

### Improvements Checklist

- [x] All acceptance criteria implemented
- [x] Backend endpoints follow existing REST conventions
- [x] Frontend follows Svelte 5 patterns (runes, $state, $props)
- [x] Tests cover happy paths and error cases
- [x] Import preview diff is computed server-side (not in browser)
- [x] Management port displayed as read-only with restart warning
- [ ] Future: Validate notification config JSON format on backend (currently free-text string)
- [ ] Future: Add file size limit on import TOML upload to prevent memory exhaustion
- [ ] Future: Add notification config connection test (verify SMTP/webhook reachability)

### Security Review

No security concerns. All new endpoints are behind the existing `require_auth` middleware. Settings changes are scoped to the management interface (localhost-only). Import replaces all data which is appropriate for admin-only access. No secrets or credentials exposed in API responses.

### Performance Considerations

No concerns. ConfigDiff computation is O(n) per entity type using HashSet lookups. All database operations use existing indexed queries. Frontend loads all settings data in a single parallel Promise.all call.

### Files Modified During Review

No files modified during review.

### Gate Status

Gate: PASS - docs/qa/gates/1.10-export-import-settings.yml
Quality Score: 95

### Recommended Status

Ready for Done - all acceptance criteria met, comprehensive test coverage, clean code quality
