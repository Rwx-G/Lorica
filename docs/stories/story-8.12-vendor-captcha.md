# Story 8.12: Vendor `captcha 1.0` into `lorica-challenge`

**Epic:** 8 (v1.6.0)
**Status:** Review
**Author:** Romain G.

## Story

As a security-conscious maintainer,
I want the `captcha 1.0` external dependency (single-maintainer, ~13
months inactive, on a security-sensitive bot-challenge path) inlined
into `lorica-challenge`,
so that the supply-chain takeover surface collapses onto code we review
at vendor-time and so that the v1.6.0 audit row M-16 (supply chain)
closes.

## Acceptance Criteria

1. `lorica-challenge/src/captcha/` module created with the inlined
   captcha generation logic (pure Rust: PNG generation, embedded font,
   filter / distortion code).
2. The `captcha = "1.0"` workspace dependency is removed from
   `lorica-challenge/Cargo.toml`. `cargo audit` confirms the
   supply-chain row clears.
3. The vendoring follows the v1.3.0 `no_debug` precedent: original
   license header preserved in a `LICENSE` file; original author
   credited in the module-level doc comment; deltas vs upstream
   documented in `lorica-challenge/src/captcha/VENDORING.md`.
4. The existing `lorica-challenge::captcha` API surface is preserved
   byte-for-byte (drop-in); consumers in `lorica/src/bot.rs` see no
   change.
5. New unit tests cover: PNG output is a valid PNG (header + IDAT),
   output dimensions match the configured size, generated text matches
   what the API returns, two consecutive calls produce different images.
6. `cargo audit` is clean; the v1.6.0 release notes mention the
   vendoring.

## Tasks / Subtasks

- [x] AC #1: `captcha/` module with vendored engine under `vendored/`
      (mod, images, fonts, filters/{noise,wave,dots}, font_default.json).
- [x] AC #2: `captcha = "1.0"` removed; `image`/`lodepng`/`serde_json`
      promoted to direct deps at the versions already in `Cargo.lock`
      (net-neutral dependency tree; `hound` + `base64 0.13` orphaned
      out).
- [x] AC #3: `LICENSE` (upstream MIT verbatim), author credit in the
      module doc, `VENDORING.md` (source, font SHA-256, deltas 1-7).
- [x] AC #4: `lorica-challenge::captcha` public API unchanged; `bot.rs`
      and `bot_handlers.rs` untouched (verified via `git diff`).
- [x] AC #5: 4 behaviours covered by inline `#[cfg(test)]` tests (valid
      PNG + IDAT, dimensions via IHDR, text matches tuple accessor, two
      calls differ).
- [x] AC #6: `cargo audit` clean (no `captcha`, `captcha` absent from
      `Cargo.lock`); CHANGELOG updated.

## Dev Notes

Faithful vendoring, not a reimplementation: the engine is copied from
`captcha` 1.0.0 (MIT, Daniel Etzold) read out of the cargo registry
cache. The audio module, sample presets, `cow`/`grid` filters, and the
`save`/`as_base64`/`as_wav` methods were dropped as unused; the only
behavioural code change is adapting the font base64 decode from base64
0.13 (`base64::decode`) to the workspace's base64 0.22 `Engine` API
(`STANDARD.decode`) - the decoded bytes are identical. `font_default.json`
is byte-identical to upstream (SHA-256 recorded in `VENDORING.md`).

Deviation from AC #5 test location: tests live inline in
`captcha/mod.rs` rather than a separate `tests.rs`. AC #5 permits inline
tests; this keeps the existing wrapper test block in place.

Dependency note: `image`, `lodepng`, and `serde_json` become direct deps
of `lorica-challenge`, but each was already resolved in `Cargo.lock`
transitively via `captcha`, so the set of compiled crates does not grow
(it shrinks: `hound` and `base64 0.13` leave). No brand-new third-party
crate enters the build.

## Dev Agent Record

### Completion Notes

Implemented by a delegated agent, then independently re-verified by the
orchestrator in Docker (CI-matching recipe): `cargo test -p
lorica-challenge` green, `cargo build -p lorica` clean, `cargo clippy -p
lorica-challenge --all-targets -D warnings` clean, `captcha` absent from
`Cargo.lock`, `cargo audit` clear of any `captcha` advisory. `bot.rs`
and `bot_handlers.rs` confirmed unchanged.

## File List

- `lorica-challenge/src/captcha/mod.rs` (new; former `captcha.rs` wrapper
  + vendored engine backing + 4 tests)
- `lorica-challenge/src/captcha/vendored/{mod,images,fonts}.rs` (new)
- `lorica-challenge/src/captcha/vendored/filters/{mod,noise,wave,dots}.rs`
  (new)
- `lorica-challenge/src/captcha/vendored/font_default.json` (new,
  byte-identical to upstream)
- `lorica-challenge/src/captcha/LICENSE` (new, upstream MIT)
- `lorica-challenge/src/captcha/VENDORING.md` (new)
- `lorica-challenge/src/captcha.rs` (deleted, replaced by module)
- `lorica-challenge/Cargo.toml` (captcha removed; image/lodepng/serde_json
  promoted)
- `Cargo.lock` (captcha + hound + base64 0.13 removed)

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-08-12 | 1.0 | Story implemented (delegated + orchestrator-verified): captcha 1.0.0 vendored into lorica-challenge/src/captcha/vendored/, external dep removed, API preserved (bot.rs untouched), LICENSE + VENDORING.md, 4 behavioural tests. Gates: lorica-challenge tests green, lorica builds, clippy clean, cargo audit clear of captcha. Status -> Review. | Romain G. |
