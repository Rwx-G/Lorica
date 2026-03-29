# Story 1.5: Dashboard - Embedded Frontend Skeleton

**Epic:** [Epic 1 - Foundation](../prd/epic-1-foundation.md)
**Status:** Draft
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

- [ ] Evaluate frontend frameworks (Svelte vs Solid vs htmx) for bundle size
- [ ] Create `lorica-dashboard` crate
- [ ] Scaffold frontend project in `lorica-dashboard/frontend/`
- [ ] Configure build.rs or pre-build script for frontend compilation
- [ ] Set up rust-embed for static asset embedding
- [ ] Implement asset serving routes in axum (GET /, GET /assets/*)
- [ ] Build login screen consuming `/api/auth/login`
- [ ] Build password change screen
- [ ] Build navigation skeleton (sidebar or top nav)
- [ ] Build overview screen with placeholder cards
- [ ] Verify total embedded asset size < 5MB
- [ ] Test end-to-end login flow in browser

## Dev Notes

- Framework evaluation criteria: bundle size (< 5MB), reactivity, TypeScript support, build speed
- htmx would produce the smallest bundle but limits interactivity
- Svelte compiles to vanilla JS with small runtime - likely best balance
- rust-embed includes files at compile time via `#[derive(RustEmbed)]`
- SPA routing: dashboard handles client-side routes, API routes pass through to axum
