# Vendored `captcha` engine

The image-rendering engine under `vendored/` is inlined from the
[`captcha`](https://crates.io/crates/captcha) crate, **version 1.0.0**,
authored by **Daniel Etzold** and licensed under the **MIT License**
(see `LICENSE` in this directory for the original text).

## Why it is vendored

Story 8.12 (v1.6.0 audit row **M-16**). The `captcha` crate is a
low-traffic leaf dependency that runs in-process on every captcha
challenge. A takeover of that crate (or any of its exclusive
transitive deps) would land arbitrary code inside Lorica's request
path. Inlining the ~800 lines we actually use collapses that
supply-chain surface to a reviewable, pinned snapshot while keeping
the `lorica-challenge::captcha` public API (`generate`, `verify`,
`validate_alphabet`, `DEFAULT_CODE_LEN`, ...) byte-for-byte identical,
so no caller changes.

## Upstream layout vs. here

| Upstream `src/`        | Here `vendored/`            | Status         |
| ---------------------- | --------------------------- | -------------- |
| `lib.rs`               | `mod.rs`                    | trimmed        |
| `images/mod.rs`        | `images.rs`                 | trimmed        |
| `fonts/mod.rs`         | `fonts.rs`                  | base64 delta   |
| `fonts/font_default.json` | `font_default.json`      | byte-identical |
| `filters/mod.rs`       | `filters/mod.rs`            | trimmed        |
| `filters/noise.rs`     | `filters/noise.rs`          | path rebadge   |
| `filters/wave.rs`      | `filters/wave.rs`           | path rebadge   |
| `filters/dots.rs`      | `filters/dots.rs`           | path rebadge   |
| `filters/cow.rs`       | (removed)                   | dropped        |
| `filters/grid.rs`      | (removed)                   | dropped        |
| `samples/mod.rs`       | (removed)                   | dropped        |
| `audio/mod.rs`         | (removed)                   | dropped        |

`font_default.json` is copied byte-for-byte from upstream
(sha256 `086beb3f43a8052cfc26bb313ee8c6610b9f3d01738bc55c841a2c4146f16e0c`).

## Deltas vs. upstream 1.0.0

1. **Module paths rebadged.** Upstream used 2018-style crate-root
   imports (`use images::Image`, `use filters::Filter`, `use Captcha`).
   These are rewritten as `super::`/relative paths so the code lives
   inside the private `vendored` submodule of `lorica-challenge`.

2. **`audio` module and the `hound` dependency removed.** Lorica never
   emits audio captchas. Dropping it removes the optional `hound`
   dependency entirely.

3. **`samples` module removed** (`generate`, `by_name`, `Difficulty`,
   `CaptchaName`). Lorica drives the builder API directly; the
   preset factories are unused.

4. **`cow` and `grid` filters removed.** They were only referenced by
   the deleted `samples` presets. The retained filters are exactly the
   three the Lorica wrapper applies: `Noise`, `Wave`, `Dots`.

5. **`save` / `as_base64` / `as_wav` methods removed** from `Image` and
   `RngCaptcha`. Lorica only needs the in-memory `as_png` / `as_tuple`
   path, so the filesystem (`std::path::Path`, `image::save`) and
   base64-encode surfaces are dropped.

6. **base64 decode adapted to base64 0.22.** Upstream targeted base64
   0.13 (`base64::decode(s)`). Lorica is on base64 0.22 workspace-wide,
   whose API routes through an `Engine`
   (`STANDARD.decode(s)`). This is the only behavioural code change;
   the decoded bytes are identical.

7. **`#![allow(dead_code)]` on the `vendored` module.** The vendored
   core keeps upstream's full builder surface (`set_font`,
   `add_text_area`, `extract`, `set_color`, `Geometry::new`, ...) even
   though the wrapper exercises only a subset. Keeping the methods
   intact makes a future re-sync with upstream a diff rather than a
   rewrite. The attribute is scoped to the vendored subtree only.

## Dependencies promoted to direct deps

Removing `captcha = "1.0"` from `Cargo.toml` orphaned the transitive
deps the vendored code links against, so they are now declared
directly on `lorica-challenge` at the versions already resolved in the
workspace `Cargo.lock`:

- `image` 0.24 (`png` feature only) - raster buffer + font PNG decode.
- `lodepng` 3 - PNG encoder for the finished image.
- `serde_json` 1 - parses `font_default.json`.

`base64` (0.22) and `rand` (0.9) were already direct dependencies.

## Re-syncing with a newer upstream

1. `cargo fetch` then read `captcha-<ver>/src/` from the registry cache.
2. Re-apply deltas 1-7 above.
3. Re-copy `font_default.json` verbatim and update the sha256 here if
   upstream changed the glyph table.
4. Re-run `cargo test -p lorica-challenge`.
