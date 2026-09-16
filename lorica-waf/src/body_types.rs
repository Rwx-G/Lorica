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

//! Which request bodies the engine can parse, decided on the declared
//! `Content-Type`.
//!
//! [`crate::engine::WafEngine::evaluate_body`] returns
//! [`crate::WafVerdict::Pass`] on any body that does not decode as
//! UTF-8, so every byte buffered for a binary upload is wasted work,
//! and on a Blocking route the oversize rejection that follows is a
//! false positive with no rule behind it. This module moves that
//! decision in front of the buffer: the caller asks
//! [`body_is_inspectable`] once, with the request header still in
//! hand, and skips buffering entirely when the answer is no.
//!
//! The set describes what the engine can parse, not a policy
//! preference. An operator who wants less inspection has
//! `waf_enabled` per route.

/// Media types the engine scans, matched exactly.
///
/// Beyond this list, [`body_is_inspectable`] also accepts every
/// `text/` subtype and the RFC 6839 structured suffixes `+json` and
/// `+xml`, which is what covers `application/activity+json` and
/// `application/atom+xml`.
///
/// `multipart/form-data` is deliberately absent. Lorica has no
/// multipart parser, so scanning it means running SQL and XSS
/// signatures over the raw envelope: base64 and binary part payloads
/// included. That is high false-positive and low value. A parser with
/// a separate limit for the non-file parts (the ModSecurity
/// `SecRequestBodyNoFilesLimit` model) is the follow-up, tracked in
/// `docs/backlog.md`.
pub const INSPECTABLE_BODY_CONTENT_TYPES: &[&str] = &[
    "application/json",
    "application/x-www-form-urlencoded",
    "application/xml",
    "text/xml",
];

/// Whether a body declaring `content_type` is worth buffering and
/// scanning.
///
/// The media type is taken up to the first `;`, so parameters such as
/// `charset=utf-8` are ignored, then trimmed and compared
/// ASCII-case-insensitively. An absent header, a header that is not a
/// media type, and every type outside
/// [`INSPECTABLE_BODY_CONTENT_TYPES`] and the two rules above are not
/// inspectable.
///
/// A client that declares `application/octet-stream` therefore skips
/// inspection. That is the residual risk of trusting the declared
/// type, and it is documented in `docs/security.md` rather than
/// glossed over: the mitigating argument is that the upstream will
/// also treat the body as an opaque blob, and the argument does not
/// hold for an application that ignores the type it was sent.
///
/// ```rust
/// use lorica_waf::body_is_inspectable;
///
/// assert!(body_is_inspectable(Some("application/json; charset=utf-8")));
/// assert!(body_is_inspectable(Some("application/activity+json")));
/// assert!(!body_is_inspectable(Some("application/octet-stream")));
/// assert!(!body_is_inspectable(None));
/// ```
pub fn body_is_inspectable(content_type: Option<&str>) -> bool {
    let Some(raw) = content_type else {
        return false;
    };
    let media = raw.split(';').next().unwrap_or("").trim();
    // Every media type is `type/subtype`. Without the separator the
    // header is not one, and a bare `+json` must not match the suffix
    // rule below.
    if !media.contains('/') {
        return false;
    }
    if INSPECTABLE_BODY_CONTENT_TYPES
        .iter()
        .any(|known| media.eq_ignore_ascii_case(known))
    {
        return true;
    }
    // `str::get` returns None rather than panicking when the index
    // falls inside a multi-byte character.
    if media
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("text/"))
    {
        return true;
    }
    match media.rsplit_once('+') {
        Some((_, suffix)) => {
            suffix.eq_ignore_ascii_case("json") || suffix.eq_ignore_ascii_case("xml")
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_matches_are_inspectable() {
        for known in INSPECTABLE_BODY_CONTENT_TYPES {
            assert!(body_is_inspectable(Some(known)), "{known}");
        }
    }

    #[test]
    fn parameters_are_stripped() {
        assert!(body_is_inspectable(Some("application/json; charset=utf-8")));
        assert!(body_is_inspectable(Some(
            "application/x-www-form-urlencoded ; charset=iso-8859-1"
        )));
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert!(body_is_inspectable(Some("Application/JSON")));
        assert!(body_is_inspectable(Some("TEXT/Plain")));
        assert!(body_is_inspectable(Some("application/ATOM+XML")));
    }

    #[test]
    fn every_text_subtype_is_inspectable() {
        assert!(body_is_inspectable(Some("text/plain")));
        assert!(body_is_inspectable(Some("text/html")));
        assert!(body_is_inspectable(Some("text/csv")));
    }

    #[test]
    fn structured_suffixes_are_inspectable() {
        assert!(body_is_inspectable(Some("application/activity+json")));
        assert!(body_is_inspectable(Some("application/atom+xml")));
        assert!(body_is_inspectable(Some("application/vnd.api+json")));
    }

    #[test]
    fn binary_types_are_not_inspectable() {
        assert!(!body_is_inspectable(Some("application/octet-stream")));
        assert!(!body_is_inspectable(Some("image/png")));
        assert!(!body_is_inspectable(Some("video/mp4")));
        assert!(!body_is_inspectable(Some("application/pdf")));
        assert!(!body_is_inspectable(Some("application/gzip")));
    }

    #[test]
    fn multipart_is_not_inspectable() {
        assert!(!body_is_inspectable(Some(
            "multipart/form-data; boundary=----WebKitFormBoundary"
        )));
        assert!(!body_is_inspectable(Some("multipart/mixed")));
    }

    #[test]
    fn absent_or_unparseable_headers_are_not_inspectable() {
        assert!(!body_is_inspectable(None));
        assert!(!body_is_inspectable(Some("")));
        assert!(!body_is_inspectable(Some("   ")));
        assert!(!body_is_inspectable(Some("json")));
        assert!(!body_is_inspectable(Some("+json")));
        assert!(!body_is_inspectable(Some(";charset=utf-8")));
    }

    #[test]
    fn a_multibyte_media_type_does_not_panic() {
        assert!(!body_is_inspectable(Some("té/xt")));
        assert!(!body_is_inspectable(Some("日本語/text")));
    }
}
