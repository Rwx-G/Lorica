# Story 1.4: REST API Foundation

**Epic:** [Epic 1 - Foundation](../prd/epic-1-foundation.md)
**Status:** Draft
**Priority:** P0
**Depends on:** Story 1.3

---

As an infrastructure engineer,
I want a REST API for managing routes, backends, and certificates,
so that the dashboard (and any automation tool) can control Lorica programmatically.

## Acceptance Criteria

1. `lorica-api` crate created with axum
2. API served on management port (default: 9443), bound to localhost only
3. Authentication: session-based with username/password
4. First-run: generate random admin password, log to stdout once
5. Force password change on first API login
6. Endpoints implemented:
   - `POST /api/auth/login`, `POST /api/auth/logout`, `PUT /api/auth/password`
   - `GET/POST /api/routes`, `GET/PUT/DELETE /api/routes/:id`
   - `GET/POST /api/backends`, `GET/PUT/DELETE /api/backends/:id`
   - `GET/POST /api/certificates`, `GET/PUT/DELETE /api/certificates/:id`
   - `GET /api/status` (proxy state overview)
   - `POST /api/config/export`, `POST /api/config/import`
7. All endpoints return JSON with consistent error format
8. API documentation via OpenAPI/Swagger spec

## Integration Verification

- IV1: Management port refuses connections from non-localhost addresses
- IV2: All CRUD operations correctly persist to embedded database
- IV3: Unauthenticated requests receive 401
- IV4: API responses are valid JSON and follow the documented schema

## Tasks

- [ ] Create `lorica-api` crate in workspace
- [ ] Set up axum with tower middleware stack
- [ ] Implement localhost-only binding for management port
- [ ] Implement admin user creation on first run (random password, log once)
- [ ] Implement auth endpoints (login, logout, password change)
- [ ] Implement session middleware (HTTP-only secure cookies)
- [ ] Implement rate limiting on login endpoint
- [ ] Implement routes CRUD endpoints
- [ ] Implement backends CRUD endpoints
- [ ] Implement certificates CRUD endpoints (multipart upload for PEM)
- [ ] Implement status endpoint
- [ ] Implement config export/import endpoints
- [ ] Define consistent JSON error format
- [ ] Write integration tests for all endpoints
- [ ] Generate OpenAPI spec

## Dev Notes

- See `docs/architecture/api-design-and-integration.md` for full endpoint specs
- Use argon2 for password hashing
- Session timeout default: 30 minutes
- Rate limit on login: 5 attempts per minute
- JSON envelope: `{"data": ...}` for success, `{"error": {"code": "...", "message": "..."}}` for errors
- Use `thiserror` for typed API errors mapped to HTTP status codes
