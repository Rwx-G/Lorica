# Story 1.1: Fork and Strip Pingora

**Epic:** [Epic 1 - Foundation](../prd/epic-1-foundation.md)
**Status:** Done
**Priority:** P0
**Depends on:** None (first story)

---

As an infrastructure engineer,
I want a clean Lorica codebase forked from Pingora with unused components removed,
so that I have a minimal, focused foundation to build on.

## Acceptance Criteria

1. Pingora repository cloned, git history removed, fresh repository initialized
2. All crates renamed from `pingora-*` to `lorica-*`
3. All internal `use pingora_*` references updated to `lorica_*`
4. `pingora-openssl`, `pingora-boringssl`, `pingora-s2n` crates removed
5. `pingora-cache`, `pingora-memory-cache`, `pingora-lru`, `tinyufo` crates removed
6. Conditional compilation for non-rustls TLS backends removed
7. Cloudflare-specific code removed (sentry, cf-rustracing)
8. NOTICE file created crediting Cloudflare Pingora as upstream (Apache-2.0)
9. Deprecated dependencies updated (serde_yaml -> serde_yml, nix 0.24 -> 0.29+)
10. `cargo check` and `cargo test` pass on the stripped codebase

## Integration Verification

- IV1: Existing Pingora unit tests pass (adjusted for renames)
- IV2: rustls TLS backend compiles and links correctly as sole TLS provider
- IV3: No references to removed crates remain in the workspace

## Tasks

- [x] Clone Pingora repository
- [x] Remove git history, initialize fresh repo
- [x] Create NOTICE file with Cloudflare attribution
- [x] Rename all crate directories (`pingora-*` -> `lorica-*`)
- [x] Update all Cargo.toml package names and dependencies
- [x] Update all `use pingora_*` imports to `lorica_*`
- [x] Remove openssl, boringssl, s2n crates and their references
- [ ] Remove cache, memory-cache, lru, tinyufo crates (kept temporarily - proxy depends on cache)
- [x] Remove conditional TLS compilation (keep rustls only)
- [x] Remove Cloudflare-specific code (sentry features removed, examples removed)
- [x] Update deprecated deps (serde_yaml -> serde_yml)
- [x] Run `cargo check` - PASS (warnings only, no errors)
- [x] Run `cargo test` - PASS (558 tests, 0 failures, 1 skipped env-dependent)
- [x] Verify no references to removed crates remain (0 pingora mentions in code)

## Deferred Items

- nix 0.24 -> 0.29 migration deferred (API breaking changes require deeper refactoring)
- Cache crate kept temporarily (proxy has deep coupling with cache - needs dedicated story to decouple)
- cf-rustracing kept in cache crate only (Cloudflare tracing dependency, will be removed with cache decoupling)

## Dev Notes

- Pingora workspace root Cargo.toml lists all member crates - update this first
- The `pingora` facade crate re-exports others via features - replace with `lorica` facade
- rustls feature is currently behind a feature flag in pingora-core - make it the default/only path
- Some tests may reference OpenSSL-specific behavior - remove or adapt these
- Keep all original copyright headers, add Lorica copyright to modified files
