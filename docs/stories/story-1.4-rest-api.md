# Story 1.4: REST API Foundation

**Epic:** [Epic 1 - Foundation](../prd/epic-1-foundation.md)
**Status:** Review
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

- [x] Create `lorica-api` crate in workspace
- [x] Set up axum with tower middleware stack
- [x] Implement localhost-only binding for management port
- [x] Implement admin user creation on first run (random password, log once)
- [x] Implement auth endpoints (login, logout, password change)
- [x] Implement session middleware (HTTP-only secure cookies)
- [x] Implement rate limiting on login endpoint
- [x] Implement routes CRUD endpoints
- [x] Implement backends CRUD endpoints
- [x] Implement certificates CRUD endpoints (multipart upload for PEM)
- [x] Implement status endpoint
- [x] Implement config export/import endpoints
- [x] Define consistent JSON error format
- [x] Write integration tests for all endpoints
- [x] Generate OpenAPI spec

## Dev Notes

- See `docs/architecture/api-design-and-integration.md` for full endpoint specs
- Use argon2 for password hashing
- Session timeout default: 30 minutes
- Rate limit on login: 5 attempts per minute
- JSON envelope: `{"data": ...}` for success, `{"error": {"code": "...", "message": "..."}}` for errors
- Use `thiserror` for typed API errors mapped to HTTP status codes

## Dev Agent Record

### Agent Model Used
Claude Opus 4.6

### File List
- `Cargo.toml` (modified - added lorica-api to workspace members)
- `lorica-api/Cargo.toml` (new - axum, argon2, tower dependencies)
- `lorica-api/src/lib.rs` (new - with #![deny(clippy::all)])
- `lorica-api/src/error.rs` (new - ApiError with thiserror, JSON envelope helpers)
- `lorica-api/src/middleware/mod.rs` (new)
- `lorica-api/src/middleware/auth.rs` (new - SessionStore, session cookie, require_auth middleware)
- `lorica-api/src/middleware/rate_limit.rs` (new - RateLimiter 5 attempts/minute)
- `lorica-api/src/auth.rs` (new - login, logout, password change, first-run admin setup)
- `lorica-api/src/server.rs` (new - axum router, localhost-only binding, AppState)
- `lorica-api/src/routes.rs` (new - routes CRUD with backend associations)
- `lorica-api/src/backends.rs` (new - backends CRUD)
- `lorica-api/src/certificates.rs` (new - certificates CRUD with delete protection)
- `lorica-api/src/status.rs` (new - proxy status overview endpoint)
- `lorica-api/src/config.rs` (new - TOML export/import endpoints)
- `lorica-api/src/tests.rs` (new - 15 integration tests)
- `lorica-api/openapi.yaml` (new - OpenAPI 3.0 spec)

### Change Log
- feat(api): add lorica-api crate with axum server, auth, and session management
- feat(api): add routes, backends, and certificates CRUD endpoints
- feat(api): add status overview and config export/import endpoints
- test(api): add 15 integration tests for all API endpoints
- docs(api): add OpenAPI 3.0 spec for all REST endpoints

### Completion Notes
- All 15 tests pass
- Clippy clean with `-D clippy::all` (enforced in lib.rs)
- Formatted with `cargo fmt`
- Existing lorica-config tests still pass (26/26)
- Session-based auth with HTTP-only SameSite=Strict cookies
- Rate limiting: 5 login attempts per minute window
- First-run admin password: 24 chars, logged once to stdout
- JSON envelope: `{"data":...}` for success, `{"error":{"code":"...","message":"..."}}` for errors
- Certificate delete blocked when routes reference it (409 Conflict)
- Config export returns TOML, import replaces all state
