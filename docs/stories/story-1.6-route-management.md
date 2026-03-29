# Story 1.6: Dashboard - Route Management

**Epic:** [Epic 1 - Foundation](../prd/epic-1-foundation.md)
**Status:** Draft
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

- [ ] Build routes list screen with data table
- [ ] Implement status indicator components (green/orange/red)
- [ ] Build route creation form (hostname, path, backend, cert selection)
- [ ] Build route edit modal/inline editing
- [ ] Build route delete with confirmation dialog
- [ ] Wire all operations to REST API endpoints
- [ ] Test CRUD operations end-to-end via dashboard

## Dev Notes

- All data fetching goes through the REST API - no direct database access from frontend
- Consider using a data table component library compatible with chosen framework
- Backend and certificate selectors should show available options from API
- Consent-driven: deletion always requires explicit confirmation
