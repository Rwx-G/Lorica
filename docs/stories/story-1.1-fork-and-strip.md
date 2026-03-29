# Story 1.1: Fork and Strip Pingora

**Epic:** [Epic 1 - Foundation](../prd/epic-1-foundation.md)
**Status:** Draft
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

- [ ] Clone Pingora repository
- [ ] Remove git history, initialize fresh repo
- [ ] Create NOTICE file with Cloudflare attribution
- [ ] Rename all crate directories (`pingora-*` -> `lorica-*`)
- [ ] Update all Cargo.toml package names and dependencies
- [ ] Update all `use pingora_*` imports to `lorica_*`
- [ ] Remove openssl, boringssl, s2n crates and their references
- [ ] Remove cache, memory-cache, lru, tinyufo crates
- [ ] Remove conditional TLS compilation (keep rustls only)
- [ ] Remove Cloudflare-specific code (sentry, cf-rustracing)
- [ ] Update deprecated deps (serde_yaml -> serde_yml, nix 0.24 -> 0.29+)
- [ ] Run `cargo check` - fix all compilation errors
- [ ] Run `cargo test` - fix all test failures
- [ ] Verify no references to removed crates remain

## Dev Notes

- Pingora workspace root Cargo.toml lists all member crates - update this first
- The `pingora` facade crate re-exports others via features - replace with `lorica` facade
- rustls feature is currently behind a feature flag in pingora-core - make it the default/only path
- Some tests may reference OpenSSL-specific behavior - remove or adapt these
- Keep all original copyright headers, add Lorica copyright to modified files
