# Epic 1.5 QA Report - Dashboard Embedded Frontend Skeleton

**Date:** 2026-03-29
**Reviewer:** Quinn (Test Architect)

## Executive Summary

Story 1.5 (Dashboard - Embedded Frontend Skeleton) has been successfully implemented and passed quality gate review. The `lorica-dashboard` crate provides an embedded Svelte 5 frontend compiled into the binary via rust-embed, served alongside the REST API on the management port. All 10 acceptance criteria and 4 integration verifications are satisfied. One API field alignment issue was found and fixed during QA review.

## Test Coverage

| Stack | Tests | Status |
|-------|-------|--------|
| Rust (lorica-dashboard) | 5 | PASS |
| Rust (lorica-api) | 17 | PASS |
| Frontend (svelte-check) | 101 files | PASS (0 errors, 0 warnings) |

New tests added in Story 1.5:
- 1 index serving test (GET / returns HTML with correct content-type)
- 1 SPA fallback test (non-API paths serve index.html)
- 1 API passthrough test (/api/* returns 404, not intercepted by SPA)
- 1 missing asset test (nonexistent /assets/* returns 404)
- 1 cache header test (index.html uses no-cache)

## Story Status

| Story | Title | Gate | Score | QA Iterations |
|-------|-------|------|-------|---------------|
| 1.5 | Dashboard - Embedded Frontend Skeleton | PASS | 95 | 1 |

## PRD Acceptance Criteria Traceability

| AC | Requirement | Code | Tests |
|----|-------------|------|-------|
| AC1 | lorica-dashboard crate created | lorica-dashboard/Cargo.toml, Cargo.toml workspace | cargo check |
| AC2 | Frontend framework selected (Svelte 5) | lorica-dashboard/frontend/package.json | svelte-check |
| AC3 | Build integrated into Cargo pipeline | lorica-dashboard/build.rs | cargo build (auto npm build) |
| AC4 | Assets embedded via rust-embed | lib.rs: #[derive(Embed)] #[folder = "frontend/dist"] | test_index_returns_html |
| AC5 | Dashboard served on management port | lorica-api/src/server.rs: merge(dashboard_routes) | test_index_returns_html |
| AC6 | Login screen functional | Login.svelte -> api.login() -> /api/v1/auth/login | svelte-check, manual |
| AC7 | Password change screen functional | PasswordChange.svelte -> api.changePassword() | svelte-check, manual |
| AC8 | Navigation skeleton (7 items) | Nav.svelte: Overview, Routes, Backends, Certificates, Logs, System, Settings | svelte-check |
| AC9 | Overview with placeholder cards | Overview.svelte + Card.svelte (routes, backends, certs) | svelte-check |
| AC10 | Asset size < 5MB | dist/: 59KB total (index.html + CSS + JS + favicon) | vite build output |

## Architecture Decisions

- **Svelte 5** selected over Solid and htmx for best balance of bundle size (~59KB), TypeScript support, and reactivity model
- **Hash-based routing** (`#/path`) instead of history API to avoid server-side route configuration
- **No frontend routing library** - custom 15-line router using Svelte stores for zero dependencies
- **Dark theme only** for initial skeleton - matches infrastructure tool conventions
- **SPA fallback** in Rust: non-API paths serve index.html, API paths return 404 (passthrough)

## NFR Validation

### Security
- **Status: PASS**
- No XSS vectors (`{@html}` only renders hardcoded SVG icon map)
- Login form uses `autocomplete` attributes for password managers
- Password change enforces 12-char minimum (stricter than API's 8-char)
- Session cookie: HttpOnly, Secure, SameSite=Strict with Path=/api
- No secrets in committed code

### Performance
- **Status: PASS**
- Bundle: 59KB total, 19KB gzipped
- Immutable cache headers (1 year) on hashed assets, no-cache on index.html
- Zero disk I/O: rust-embed serves from compiled binary memory
- Build time: ~110ms for frontend, negligible impact on cargo build

### Reliability
- **Status: PASS**
- SPA fallback handles unknown client-side routes gracefully
- API routes not intercepted by dashboard (explicit /api/ prefix check)
- build.rs gracefully handles SKIP_FRONTEND_BUILD mode with placeholder
- Error states handled in all frontend screens (loading, error, success)

### Maintainability
- **Status: PASS**
- Clean component separation (routes/, components/, lib/)
- TypeScript throughout with strict mode
- Shared CSS custom properties for consistent theming
- API client centralized in single module with typed interfaces

## Risk Assessment

No risks identified. This is a UI skeleton with no data mutation capabilities beyond login/password change, which are already secured by the existing API auth layer.

## Recommendations

### Immediate
None - all critical items addressed.

### Future
- Add Vitest + @testing-library/svelte for frontend component tests (Story 1.6+)
- Extract shared SVG shield icon to a reusable Svelte component (3 duplications across Login, PasswordChange, Nav)
- Consider adding a light theme toggle in Settings screen (Story 1.10)

## Epic Gate Decision

**PASS** - Quality score 95/100. All acceptance criteria met, all tests passing, no security concerns, excellent bundle size. One API field alignment issue was identified and resolved during review.
