// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Recursive URL decoding helpers used by the WAF to defeat
//! double- or triple-encoded bypass attempts.
//!
//! Two flavors are exposed :
//!
//! - [`WafEngine::url_decode_uri`] - generic URI percent-decoding.
//!   `+` is preserved literally. Used for fields where `+` carries
//!   no special meaning per RFC 3986 (the URI request-target path,
//!   header values).
//! - [`WafEngine::url_decode_form`] - `application/x-www-form-urlencoded`
//!   decoding. `+` is rewritten to a literal space. Used for the
//!   query string and request bodies.
//!
//! The legacy `url_decode` single-name helper was removed in v1.5.2
//! (backlog #25 cleanup pass). Callers always go through one of the
//! explicit `*_uri` / `*_form` variants - the old alias encouraged
//! form-style decoding on header values, which inflated the
//! false-positive surface (`attacker+payload` decoded to
//! `attacker payload` and could trip space-anchored signatures).
//!
//! v1.5.1 audit H-4 hardening :
//!
//! - Decoding works on raw bytes (`Vec<u8>`) rather than `char`s, so
//!   multi-byte UTF-8 escapes like `%C3%A9` (`é`) reassemble into
//!   the original codepoint instead of mojibaking into two
//!   `U+00C3 U+00A9` codepoints. SQLi / XSS regexes that look for
//!   specific UTF-8 byte sequences now see them post-decode.
//! - Overlong UTF-8 forms (`%C0%80` for NUL, `%C0%BC` for `<`) are
//!   rejected by `String::from_utf8_lossy` and surface as the
//!   Unicode replacement character `U+FFFD` instead of leaking the
//!   underlying ASCII codepoint to downstream regexes - closes the
//!   classic CRS overlong-bypass evasion path.

use std::borrow::Cow;

use super::WafEngine;

impl WafEngine {
    /// URI percent-decoding suitable for fields where `+` is a
    /// literal character (paths, header values).
    ///
    /// Decodes recursively (up to 3 passes, until stable) so that
    /// double / triple-encoded payloads (`%252e%252e` -> `%2e%2e`
    /// -> `..`) are caught. Returns `Cow::Borrowed(input)` on the
    /// no-decode fast path (clean traffic) so the WAF eval hot
    /// path doesn't allocate a String per (field, request) when
    /// nothing needed decoding (audit L-19).
    pub(super) fn url_decode_uri(input: &str) -> Cow<'_, str> {
        Self::url_decode_recursive(input, false)
    }

    /// Form-style percent-decoding (`application/x-www-form-urlencoded`)
    /// suitable for query strings and form-encoded request bodies.
    ///
    /// Identical to [`Self::url_decode_uri`] except that `+` is
    /// rewritten to a literal space. Returns `Cow::Borrowed` on
    /// the no-decode fast path (no `%` AND no `+`).
    pub(super) fn url_decode_form(input: &str) -> Cow<'_, str> {
        Self::url_decode_recursive(input, true)
    }

    fn url_decode_recursive(input: &str, plus_to_space: bool) -> Cow<'_, str> {
        // Fast path: no percent-encoding and (when applicable) no
        // `+` to rewrite -> nothing to decode, return borrowed.
        let needs_plus = plus_to_space && input.contains('+');
        if !input.contains('%') && !needs_plus {
            return Cow::Borrowed(input);
        }
        let mut current = input.to_string();
        for _ in 0..3 {
            let decoded = Self::url_decode_once(&current, plus_to_space);
            if decoded == current {
                break;
            }
            current = decoded;
        }
        Cow::Owned(current)
    }

    /// Single-pass byte-level percent decode, with optional
    /// form-style `+` -> space substitution.
    ///
    /// Operates on bytes (not chars) so that multi-byte UTF-8
    /// percent escapes reassemble correctly. The output is rebuilt
    /// from the raw byte buffer via [`String::from_utf8_lossy`] :
    /// invalid UTF-8 sequences (e.g. overlong forms) become
    /// `U+FFFD` rather than leaking through to downstream regexes
    /// as their ASCII alias.
    fn url_decode_once(input: &str, plus_to_space: bool) -> String {
        let bytes = input.as_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if b == b'%' && i + 2 < bytes.len() {
                if let (Some(d1), Some(d2)) =
                    (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2]))
                {
                    out.push((d1 << 4) | d2);
                    i += 3;
                    continue;
                }
                // Invalid escape (e.g. `%G1`, `%X` at end of input)
                // - keep the literal `%` and let the caller see the
                // raw garbage rather than silently dropping bytes.
                out.push(b);
                i += 1;
            } else if b == b'+' && plus_to_space {
                out.push(b' ');
                i += 1;
            } else {
                out.push(b);
                i += 1;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }
}

/// ASCII hex digit -> nibble. Returns `None` for non-hex bytes.
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
