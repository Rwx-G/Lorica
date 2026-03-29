# Story 1.5: Dashboard - Embedded Frontend Skeleton

**Epic:** [Epic 1 - Foundation](../prd/epic-1-foundation.md)
**Status:** Review
**Priority:** P0
**Depends on:** Story 1.4

---

As an infrastructure engineer,
I want a web dashboard embedded in the Lorica binary,
so that I can manage my reverse proxy from a browser without any additional tool.

## Acceptance Criteria

1. `lorica-dashboard` crate created
2. Frontend framework selected and scaffolded (evaluation: Svelte vs Solid vs htmx)
3. Frontend build integrated into Cargo build pipeline (build.rs or pre-build script)
4. Static assets embedded in binary via `rust-embed`
5. Dashboard served on management port alongside the API
6. Login screen functional (consumes `/api/auth/login`)
7. First-run password change screen functional
8. Navigation skeleton: Overview, Routes, Backends, Certificates, Logs, System, Settings
9. Overview screen: placeholder cards for route count, backend health summary, cert status summary
10. Total embedded asset size < 5MB

## Integration Verification

- IV1: Dashboard loads in browser at `https://localhost:9443`
- IV2: Login flow works end-to-end (auth -> session -> dashboard)
- IV3: Binary size increase from dashboard embedding is < 5MB
- IV4: Dashboard is not accessible from non-localhost addresses

## Tasks

- [x] Evaluate frontend frameworks (Svelte vs Solid vs htmx) for bundle size
- [x] Create `lorica-dashboard` crate
- [x] Scaffold frontend project in `lorica-dashboard/frontend/`
- [x] Configure build.rs or pre-build script for frontend compilation
- [x] Set up rust-embed for static asset embedding
- [x] Implement asset serving routes in axum (GET /, GET /assets/*)
- [x] Build login screen consuming `/api/auth/login`
- [x] Build password change screen
- [x] Build navigation skeleton (sidebar or top nav)
- [x] Build overview screen with placeholder cards
- [x] Verify total embedded asset size < 5MB
- [x] Test end-to-end login flow in browser

## Dev Notes

- Framework evaluation criteria: bundle size (< 5MB), reactivity, TypeScript support, build speed
- htmx would produce the smallest bundle but limits interactivity
- Svelte compiles to vanilla JS with small runtime - likely best balance
- **Decision: Svelte 5** selected. Total dist output ~59KB (well under 5MB limit)
- rust-embed includes files at compile time via `#[derive(RustEmbed)]`
- SPA routing: dashboard handles client-side routes via hash router, API routes pass through to axum
- build.rs runs `npm install` + `npm run build` automatically during `cargo build`
- SKIP_FRONTEND_BUILD=1 env var skips frontend build for Rust-only development

## Dev Agent Record

- Framework evaluation: Svelte 5 chosen for minimal bundle size (~59KB total dist), TypeScript support, and compile-to-vanilla-JS approach
- Created `lorica-dashboard` crate with rust-embed for asset embedding and axum routes for serving
- Scaffolded Svelte 5 + Vite + TypeScript frontend with Login, PasswordChange, Navigation, Overview screens
- build.rs integrates frontend build into Cargo pipeline (auto npm install + build)
- Dashboard router merged into lorica-api server.rs alongside existing API routes
- All 5 dashboard tests pass, all 17 existing API tests pass (no regressions)
- Clippy clean, cargo fmt applied, svelte-check 0 errors

## File List

- `lorica-dashboard/Cargo.toml` - Crate manifest
- `lorica-dashboard/build.rs` - Frontend build integration
- `lorica-dashboard/src/lib.rs` - rust-embed setup, asset serving routes, SPA fallback
- `lorica-dashboard/src/tests.rs` - Asset serving and SPA fallback tests
- `lorica-dashboard/frontend/package.json` - Frontend dependencies (Svelte 5 + Vite)
- `lorica-dashboard/frontend/vite.config.ts` - Vite build configuration
- `lorica-dashboard/frontend/index.html` - HTML entry point
- `lorica-dashboard/frontend/src/main.ts` - Svelte mount point
- `lorica-dashboard/frontend/src/app.css` - Global styles (dark theme)
- `lorica-dashboard/frontend/src/App.svelte` - Root component with auth routing
- `lorica-dashboard/frontend/src/lib/api.ts` - API client (login, logout, changePassword, getStatus)
- `lorica-dashboard/frontend/src/lib/auth.ts` - Auth state store
- `lorica-dashboard/frontend/src/lib/router.ts` - Hash-based SPA router
- `lorica-dashboard/frontend/src/routes/Login.svelte` - Login screen
- `lorica-dashboard/frontend/src/routes/PasswordChange.svelte` - First-run password change
- `lorica-dashboard/frontend/src/routes/Dashboard.svelte` - Layout with sidebar nav + content area
- `lorica-dashboard/frontend/src/routes/Overview.svelte` - Overview with status cards
- `lorica-dashboard/frontend/src/routes/Placeholder.svelte` - Placeholder for unimplemented sections
- `lorica-dashboard/frontend/src/components/Nav.svelte` - Sidebar navigation
- `lorica-dashboard/frontend/src/components/Card.svelte` - Status card component
- `lorica-dashboard/frontend/src/assets/favicon.svg` - Shield favicon
- `lorica-dashboard/frontend/public/favicon.svg` - Public favicon copy

## Change Log

- Created `lorica-dashboard` crate with rust-embed asset embedding
- Selected Svelte 5 as frontend framework (59KB total bundle)
- Implemented login, password change, navigation skeleton, and overview screens
- Integrated dashboard into lorica-api router on management port
- Added build.rs for automatic frontend compilation during cargo build
