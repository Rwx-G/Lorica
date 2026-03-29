# Story 1.10: Configuration Export/Import and Settings

**Epic:** [Epic 1 - Foundation](../prd/epic-1-foundation.md)
**Status:** Review
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
