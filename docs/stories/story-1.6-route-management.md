# Story 1.6: Dashboard - Route Management

**Epic:** [Epic 1 - Foundation](../prd/epic-1-foundation.md)
**Status:** Done
**Priority:** P0
**Depends on:** Story 1.5

---

As an infrastructure engineer,
I want to view, create, edit, and delete routes from the dashboard,
so that I can manage my proxy configuration visually.

## Acceptance Criteria

1. Routes list screen: table with input URL, destination, TLS status, health status
2. Route creation form: hostname, path, backend selection, TLS certificate selection
3. Route edit: inline or modal editing of all route parameters
4. Route delete: confirmation dialog before deletion
5. Status indicators: green (healthy), orange (degraded), red (down)
6. All operations go through the REST API

## Integration Verification

- IV1: Route created in dashboard appears in API `GET /api/routes`
- IV2: Route deleted in dashboard is removed from proxy configuration
- IV3: Dashboard reflects current state after page refresh

## Tasks

- [x] Build routes list screen with data table
- [x] Implement status indicator components (green/orange/red)
- [x] Build route creation form (hostname, path, backend, cert selection)
- [x] Build route edit modal/inline editing
- [x] Build route delete with confirmation dialog
- [x] Wire all operations to REST API endpoints
- [x] Test CRUD operations end-to-end via dashboard

## Dev Notes

- All data fetching goes through the REST API - no direct database access from frontend
- Consider using a data table component library compatible with chosen framework
- Backend and certificate selectors should show available options from API
- Consent-driven: deletion always requires explicit confirmation

## Dev Agent Record

- Added route CRUD methods + backend/cert list methods to `src/lib/api.ts`
- Created `StatusBadge.svelte` component for health indicators (green/orange/red/unknown)
- Created `ConfirmDialog.svelte` component for delete confirmation
- Created `Routes.svelte` with full CRUD: list table, create/edit modal form, delete dialog
- Form includes backend multi-select, certificate dropdown, load balancing selector
- Health status derived from associated backends' health
- Wired Routes into Dashboard.svelte replacing Placeholder
- All type checks pass (0 errors, 0 warnings)
- Frontend build passes (64.73 KB JS, 12.66 KB CSS)
- All 5 existing Rust dashboard tests pass

## File List

- `lorica-dashboard/frontend/src/lib/api.ts` - Added route/backend/certificate interfaces and API methods
- `lorica-dashboard/frontend/src/components/StatusBadge.svelte` - NEW - Health status badge component
- `lorica-dashboard/frontend/src/components/ConfirmDialog.svelte` - NEW - Confirmation dialog component
- `lorica-dashboard/frontend/src/routes/Routes.svelte` - NEW - Route management page (list + CRUD)
- `lorica-dashboard/frontend/src/routes/Dashboard.svelte` - Updated to use Routes instead of Placeholder

## QA Results

- **Gate:** PASS (score: 97/100)
- **Reviewer:** Romain G.
- **AC Coverage:** All 6 ACs met, all 3 IVs verified
- **Issues Found:** 1 low-severity (dead code - `backendLabel` function) - fixed
- **NFR:** Security PASS, Performance PASS, Reliability PASS, Maintainability PASS
- **Future Recommendations:**
  - Add Vitest + @testing-library/svelte for frontend component tests
  - Consider keyboard navigation (Escape to close modal, Enter to submit)

## Change Log

- 2026-03-29: Implementation complete, all tasks checked off, status set to Review
- 2026-03-29: QA PASS (97/100), dead code fixed, status set to Done
