# Story 1.10: Configuration Export/Import and Settings

**Epic:** [Epic 1 - Foundation](../prd/epic-1-foundation.md)
**Status:** Draft
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

- [ ] Build settings screen with global config display
- [ ] Implement export button (calls `POST /api/v1/config/export`, downloads file)
- [ ] Implement import UI (file upload, calls `POST /api/v1/config/import`)
- [ ] Build import diff preview screen (added/modified/removed)
- [ ] Implement import confirmation flow (`POST /api/v1/config/import/confirm`)
- [ ] Build notification preferences section (email SMTP config, webhook URL)
- [ ] Build preference memory management UI
- [ ] Test round-trip: export from instance A, import to instance B
- [ ] Test import diff preview accuracy

## Dev Notes

- Export TOML format must include a `version` field for forward compatibility
- Import preview uses ConfigDiff from lorica-config to compute changes
- Settings that require restart should display a warning (though most should be hot-reloadable)
- Notification preferences stored in NotificationConfig table
- User preferences stored in UserPreference table
