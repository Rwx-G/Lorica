// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Image-captcha generation + verification.
//!
//! Wraps the pure-Rust [`captcha`](https://docs.rs/captcha) crate
//! with an opinionated configuration: 6-character codes drawn from
//! a configurable alphabet that excludes visually-confusable glyphs
//! by default (0/O, 1/l/I). Distortion filters (Noise + Wave +
//! Dots) are tuned for "readable on a phone, expensive to OCR".
//!
//! The generator produces a `(text, png_bytes)` tuple. The caller
//! stashes `text` on the server side (keyed by a one-shot URL
//! nonce signed with the HMAC secret) and serves `png_bytes` at
//! the image URL. See `docs/architecture/bot-protection.md` § 3.3
//! for the flow.
//!
//! Verification is case-insensitive and uses a constant-time
//! comparator so an attacker with timing access cannot enumerate
//! the expected code one byte at a time.

use subtle::ConstantTimeEq;

use crate::{ChallengeError, Result};

/// Default alphabet: digits + mixed-case ASCII letters, minus the
/// visually-confusable glyphs (`0`, `O`, `1`, `l`, `I`) AND the
/// glyphs the `captcha` 1.0 crate's default font does not render
/// (`L` uppercase, `o` lowercase — the crate silently drops any
/// unknown glyph, which would produce short codes if left in).
/// Keeping the list hard-coded and visible makes it auditable:
/// future `captcha` upgrades that change the font character set
/// must be paired with a review of this string.
pub const DEFAULT_ALPHABET: &str =
    "23456789abcdefghijkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ";

/// Minimum alphabet length. Below 10 characters the brute-force
/// search space gets thin (6-char code with a 9-symbol alphabet =
/// ~530k possibilities, which a paid solver handles trivially).
pub const MIN_ALPHABET_LEN: usize = 10;

/// Default number of characters in the generated code. Six is a
/// sweet spot: short enough to type on mobile in one glance,
/// long enough that random guessing over the default alphabet is
/// ~55^6 ≈ 2.8 × 10^10 tries.
pub const DEFAULT_CODE_LEN: u32 = 6;

/// Captcha image dimensions. Matches the `captcha` crate default
/// and renders legibly on a phone without too much horizontal
/// wrap.
pub const IMAGE_WIDTH: u32 = 220;
pub const IMAGE_HEIGHT: u32 = 120;

/// Validate an alphabet string passed in from config. Enforces:
/// - length ≥ [`MIN_ALPHABET_LEN`]
/// - all characters in the ASCII printable range (0x20..=0x7e,
///   excluding space), so the image renderer has a glyph for each
/// - no duplicates (a duplicate in the alphabet just skews the
///   probability distribution without adding entropy; reject at
///   write time so the dashboard surfaces the mistake).
///
/// Returns the validated alphabet as a `Vec<char>` ready to pass
/// to [`generate`], or an `Err` describing the first issue found.
pub fn validate_alphabet(s: &str) -> Result<Vec<char>> {
    if s.chars().count() < MIN_ALPHABET_LEN {
        return Err(ChallengeError::Malformed(
            "captcha alphabet shorter than minimum of 10 characters",
        ));
    }
    let mut out: Vec<char> = Vec::new();
    for c in s.chars() {
        // ASCII printable, excluding space / control. Space would
        // render invisibly and trip users up.
        if !(c.is_ascii_graphic()) {
            return Err(ChallengeError::Malformed(
                "captcha alphabet contains non-ASCII-printable character",
            ));
        }
        if out.contains(&c) {
            return Err(ChallengeError::Malformed(
                "captcha alphabet contains a duplicate character",
            ));
        }
        out.push(c);
    }
    Ok(out)
}

/// Generate a captcha: random code + PNG-encoded distorted image.
/// Returns `(text, png_bytes)`.
///
/// - `alphabet`: pre-validated via [`validate_alphabet`]. A fresh
///   validation inside the generator is cheap, but punting it to
///   the caller means the dashboard gets a crisp "invalid
///   alphabet" error at save time rather than after the operator
///   triggers their first captcha.
/// - `code_len`: number of characters in the code. Must be in
///   `1..=12`. 12 characters is the widest the rendered image
///   still fits at [`IMAGE_WIDTH`] without glyph crowding.
pub fn generate(alphabet: &[char], code_len: u32) -> Result<(String, Vec<u8>)> {
    if !(1..=12).contains(&code_len) {
        return Err(ChallengeError::Internal("code_len outside 1..=12"));
    }
    if alphabet.len() < MIN_ALPHABET_LEN {
        return Err(ChallengeError::Malformed(
            "alphabet shorter than minimum of 10 characters",
        ));
    }

    use captcha::filters::{Dots, Noise, Wave};
    use captcha::Captcha;

    // Intersect the operator-supplied alphabet with the glyphs the
    // crate's default font actually renders. The `captcha` 1.0
    // crate silently skips an `add_char` call when the randomly-
    // chosen character has no glyph, which would produce a code
    // shorter than `code_len`. Filtering upfront guarantees every
    // `add_char` below lands.
    let supported = Captcha::new().supported_chars();
    let effective: Vec<char> = alphabet
        .iter()
        .copied()
        .filter(|c| supported.contains(c))
        .collect();
    if effective.len() < MIN_ALPHABET_LEN {
        return Err(ChallengeError::Malformed(
            "alphabet has fewer than 10 characters with a renderable glyph",
        ));
    }

    let mut c = Captcha::new();
    c.set_chars(&effective);
    c.add_chars(code_len);
    c.apply_filter(Noise::new(0.4));
    c.apply_filter(Wave::new(2.0, 20.0).horizontal());
    c.apply_filter(Wave::new(2.0, 20.0).vertical());
    c.view(IMAGE_WIDTH, IMAGE_HEIGHT);
    c.apply_filter(Dots::new(15));

    // Defence-in-depth: the filter above should guarantee the
    // full `code_len` chars land, but a future crate version or
    // font swap could still regress. Assert at the end and
    // surface a typed internal error rather than handing the
    // caller a short code.
    if c.chars().len() != code_len as usize {
        return Err(ChallengeError::Internal(
            "captcha crate produced fewer chars than requested",
        ));
    }

    // `as_tuple` returns (text, png_bytes). The crate returns
    // `Option<...>` because the PNG encoder can technically fail;
    // in practice it fails only on memory allocation errors, so
    // a None here is treated as a non-retryable internal fault.
    let (text, png) = c
        .as_tuple()
        .ok_or(ChallengeError::Internal("captcha PNG encode failed"))?;
    Ok((text, png))
}

/// Verify a user-submitted captcha answer against the expected
/// text. Case-insensitive (both sides lowercased before compare)
/// because the default alphabet mixes cases but a human typing on
/// mobile very often misses the shift-lock state.
///
/// Constant-time byte equality via
/// [`subtle::ConstantTimeEq::ct_eq`] so an attacker with timing
/// access cannot leak the expected text byte-by-byte. This matters
/// more for the captcha than the cookie because an attacker CAN
/// drive repeated verify calls with chosen input for a given
/// challenge (same URL, different form field), so the timing
/// channel is directly measurable.
pub fn verify(submitted: &str, expected: &str) -> Result<()> {
    let sub = submitted.trim().to_ascii_lowercase();
    let exp = expected.trim().to_ascii_lowercase();
    // Pre-filter on length: `ct_eq` returns false on different-
    // length inputs but only after comparing the min prefix.
    // Bailing early keeps the branch-free guarantee since the
    // length check is not secret-dependent (the expected length
    // is known to the attacker already — it is the captcha code
    // length they saw on the image).
    if sub.len() != exp.len() {
        return Err(ChallengeError::CaptchaMismatch);
    }
    if sub.as_bytes().ct_eq(exp.as_bytes()).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(ChallengeError::CaptchaMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_alphabet_validates() {
        let chars = validate_alphabet(DEFAULT_ALPHABET).unwrap();
        assert!(chars.len() >= MIN_ALPHABET_LEN);
        // Regression: the default explicitly excludes 0/O/1/l/I.
        assert!(!chars.contains(&'0'));
        assert!(!chars.contains(&'O'));
        assert!(!chars.contains(&'1'));
        assert!(!chars.contains(&'l'));
        assert!(!chars.contains(&'I'));
    }

    #[test]
    fn validate_alphabet_rejects_too_short() {
        let err = validate_alphabet("abc").unwrap_err();
        assert!(matches!(err, ChallengeError::Malformed(_)));
    }

    #[test]
    fn validate_alphabet_rejects_duplicates() {
        let err = validate_alphabet("aabcdefghij").unwrap_err();
        assert!(matches!(err, ChallengeError::Malformed(_)));
    }

    #[test]
    fn validate_alphabet_rejects_non_printable() {
        // Tab is ASCII but not `is_ascii_graphic`.
        let err = validate_alphabet("abcdefghij\t").unwrap_err();
        assert!(matches!(err, ChallengeError::Malformed(_)));
    }

    #[test]
    fn validate_alphabet_rejects_non_ascii() {
        // Emoji / unicode letters.
        let err = validate_alphabet("abcdefghij😀").unwrap_err();
        assert!(matches!(err, ChallengeError::Malformed(_)));
    }

    #[test]
    fn generate_produces_matching_text_and_png() {
        let alphabet = validate_alphabet(DEFAULT_ALPHABET).unwrap();
        let (text, png) = generate(&alphabet, DEFAULT_CODE_LEN).unwrap();

        // Length sanity.
        assert_eq!(
            text.chars().count(),
            DEFAULT_CODE_LEN as usize,
            "text='{text}' has the wrong length"
        );

        // Every char in the generated code came from the alphabet.
        for c in text.chars() {
            assert!(
                alphabet.contains(&c),
                "generated char '{c}' not in alphabet"
            );
        }

        // PNG magic bytes check (0x89 'P' 'N' 'G' 0x0d 0x0a 0x1a 0x0a).
        assert!(png.len() > 8);
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n", "not a PNG");
    }

    #[test]
    fn generate_rejects_bad_code_len() {
        let alphabet = validate_alphabet(DEFAULT_ALPHABET).unwrap();
        assert!(generate(&alphabet, 0).is_err());
        assert!(generate(&alphabet, 13).is_err());
    }

    #[test]
    fn generate_rejects_short_alphabet() {
        let short: Vec<char> = "abcde".chars().collect();
        let err = generate(&short, 6).unwrap_err();
        assert!(matches!(err, ChallengeError::Malformed(_)));
    }

    #[test]
    fn verify_accepts_exact_match() {
        assert!(verify("abc123", "abc123").is_ok());
    }

    #[test]
    fn verify_is_case_insensitive() {
        assert!(verify("ABC123", "abc123").is_ok());
        assert!(verify("AbC123", "aBc123").is_ok());
    }

    #[test]
    fn verify_trims_whitespace() {
        assert!(verify("  abc123  ", "abc123").is_ok());
    }

    #[test]
    fn verify_rejects_mismatch() {
        let err = verify("abc124", "abc123").unwrap_err();
        assert!(matches!(err, ChallengeError::CaptchaMismatch));
    }

    #[test]
    fn verify_rejects_length_mismatch() {
        let err = verify("abc12", "abc123").unwrap_err();
        assert!(matches!(err, ChallengeError::CaptchaMismatch));
        let err = verify("abc1234", "abc123").unwrap_err();
        assert!(matches!(err, ChallengeError::CaptchaMismatch));
    }

    #[test]
    fn verify_rejects_empty_vs_nonempty() {
        let err = verify("", "abc123").unwrap_err();
        assert!(matches!(err, ChallengeError::CaptchaMismatch));
    }

    #[test]
    fn generate_two_calls_yield_different_codes() {
        // The crate's internal RNG is reseeded on each new Captcha
        // instance, so two consecutive generates must differ with
        // extremely high probability. Pinning 2 iterations is
        // enough to catch a "RNG not seeded" regression.
        let alphabet = validate_alphabet(DEFAULT_ALPHABET).unwrap();
        let (t1, _) = generate(&alphabet, DEFAULT_CODE_LEN).unwrap();
        let (t2, _) = generate(&alphabet, DEFAULT_CODE_LEN).unwrap();
        assert_ne!(t1, t2, "two fresh captchas returned the same code");
    }
}
