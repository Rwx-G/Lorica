# Story 6.3: Hostname Aliases and Redirects

**Epic:** [Epic 6 - Route Configuration](../prd/epic-6-route-config.md)
**Status:** Draft
**Priority:** P1
**Depends on:** Story 6.1

---

As an infrastructure engineer,
I want hostname aliases and hostname redirects per route,
so that I can serve multiple domains from one route and canonicalize hostnames.

## Acceptance Criteria

1. Route has optional redirect_to_hostname field (301 redirect before proxying)
2. Route has optional hostname_aliases list (additional hostnames that match this route)
3. Dashboard route form includes alias list and redirect hostname
4. Tests verify alias matching and redirect behavior

## Integration Verification

- IV1: Request to alias hostname is routed to correct backend
- IV2: Request to redirected hostname receives 301 to canonical hostname
- IV3: Alias and redirect settings persist across restart

## Tasks

- [ ] Add redirect_to_hostname optional field to route model
- [ ] Add hostname_aliases list field to route model (stored as JSON array or separate table)
- [ ] Write database migration for new route columns
- [ ] Implement hostname alias resolution in request routing (match aliases same as primary hostname)
- [ ] Implement hostname redirect middleware (301 with Location header to canonical hostname)
- [ ] Ensure redirect preserves scheme, path, query string, and fragment
- [ ] Add API endpoints for alias and redirect config CRUD
- [ ] Update dashboard route form with alias list editor and redirect hostname input
- [ ] Write tests for alias matching (request to alias routes to correct backend)
- [ ] Write tests for hostname redirect (301 response with correct Location header)
- [ ] Write tests for alias and redirect persistence across restart

## Dev Notes

- Hostname aliases are additional hostnames that resolve to the same route (no redirect, direct proxy)
- redirect_to_hostname triggers a 301 BEFORE any proxying - the client must re-request with the canonical hostname
- If both redirect_to_hostname and hostname_aliases are set, redirect takes precedence for matching hostnames
- Alias matching is case-insensitive (DNS is case-insensitive)
- Alias hostnames must be unique across all routes (no two routes can claim the same alias)
- Consider storing aliases in a separate table with a unique constraint for efficient lookup
- Redirect should use the same scheme as the incoming request unless force_https_redirect is also enabled (Story 6.1)
