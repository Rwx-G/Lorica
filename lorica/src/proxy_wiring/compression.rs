// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Which upstream responses a route's `compression_enabled` encodes.
//!
//! The forked compression context would encode any status and any
//! `application/` type once given a level. That is too wide for a proxy
//! in front of arbitrary backends: a `206` would keep a `Content-Range`
//! that no longer describes its body, a binary download would lose its
//! `Content-Length` and with it resuming, and a stream would stall: the
//! encoders emit nothing until they have filled a block or the body
//! ends, so an event stream, a long poll or a log tail would hold its
//! data. Only a body of declared length is compressed for that reason; an
//! open-ended one is sent chunked. The policy here is applied before the
//! level is handed to the context.

use lorica_http::ResponseHeader;

use super::mirror_rewrite::is_stream_content_type;

/// The level a route's compression encodes at, for every algorithm.
pub(crate) const RESPONSE_COMPRESSION_LEVEL: u32 = 6;

/// Statuses whose body is compressed, as nginx's gzip filter does.
const COMPRESSED_STATUSES: &[u16] = &[200, 403, 404];

/// Media types compressed besides `text/*` and the `+json` / `+xml`
/// structured suffixes: the textual `application/` types, and the
/// image and font formats that are not compressed already.
const COMPRESSED_MEDIA_TYPES: &[&str] = &[
    "application/json",
    "application/javascript",
    "application/x-javascript",
    "application/ecmascript",
    "application/xml",
    "application/wasm",
    "application/vnd.ms-fontobject",
    "image/x-icon",
    "image/vnd.microsoft.icon",
    "font/ttf",
    "font/otf",
];

/// Structured syntax suffixes (RFC 6839) that mark a textual type.
const COMPRESSED_SUFFIXES: &[&str] = &["+json", "+xml"];

/// Whether a route with `compression_enabled` compresses `upstream_response`.
///
/// The context still applies its own checks on top: the client must
/// accept an encoding, the backend must not have encoded the body, and a
/// declared `Content-Length` must be at least 20 bytes.
pub(crate) fn compresses_response(upstream_response: &ResponseHeader) -> bool {
    if !COMPRESSED_STATUSES.contains(&upstream_response.status.as_u16())
        || !upstream_response
            .headers
            .contains_key(http::header::CONTENT_LENGTH)
    {
        return false;
    }
    upstream_response
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(is_compressible_content_type)
}

fn is_compressible_content_type(content_type: &str) -> bool {
    if is_stream_content_type(content_type) {
        return false;
    }
    let media_type = content_type.split(';').next().unwrap_or("").trim();
    media_type
        .get(..5)
        .is_some_and(|p| p.eq_ignore_ascii_case("text/"))
        || COMPRESSED_MEDIA_TYPES
            .iter()
            .any(|t| media_type.eq_ignore_ascii_case(t))
        || COMPRESSED_SUFFIXES.iter().any(|s| {
            media_type.len() > s.len()
                && media_type
                    .get(media_type.len() - s.len()..)
                    .is_some_and(|tail| tail.eq_ignore_ascii_case(s))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A response of declared length, the only shape that is compressed.
    fn response(status: u16, content_type: Option<&str>) -> ResponseHeader {
        let mut resp = ResponseHeader::build(status, None).unwrap();
        resp.insert_header(http::header::CONTENT_LENGTH, "4096")
            .unwrap();
        if let Some(ct) = content_type {
            resp.insert_header(http::header::CONTENT_TYPE, ct).unwrap();
        }
        resp
    }

    #[test]
    fn a_body_without_declared_length_is_not_compressed() {
        let mut chunked = response(200, Some("application/json"));
        chunked.remove_header(&http::header::CONTENT_LENGTH);
        assert!(!compresses_response(&chunked));
    }

    #[test]
    fn every_listed_media_type_is_compressed_whatever_its_case_and_parameters() {
        for media_type in COMPRESSED_MEDIA_TYPES {
            for content_type in [
                media_type.to_string(),
                media_type.to_ascii_uppercase(),
                format!("{media_type}; charset=utf-8"),
            ] {
                assert!(
                    compresses_response(&response(200, Some(&content_type))),
                    "{content_type}"
                );
            }
        }
    }

    #[test]
    fn text_and_structured_suffix_types_are_compressed() {
        for content_type in [
            "text/html",
            "TEXT/CSS",
            "text/plain; charset=utf-8",
            "image/svg+xml",
            "application/ld+json",
            "application/rss+xml",
            "application/problem+json",
        ] {
            assert!(
                compresses_response(&response(200, Some(content_type))),
                "{content_type}"
            );
        }
    }

    #[test]
    fn stream_binary_and_already_compressed_types_are_not() {
        for content_type in [
            "text/event-stream",
            "text/event-stream; charset=utf-8",
            "application/grpc",
            "application/grpc-web+proto",
            "multipart/x-mixed-replace; boundary=frame",
            "application/octet-stream",
            "binary/octet-stream",
            "application/pdf",
            "application/zip",
            "application/x-7z-compressed",
            "image/png",
            "font/woff2",
            "video/mp4",
            "+json",
        ] {
            assert!(
                !compresses_response(&response(200, Some(content_type))),
                "{content_type}"
            );
        }
    }

    #[test]
    fn a_response_without_content_type_is_not_compressed() {
        assert!(!compresses_response(&response(200, None)));
    }

    #[test]
    fn only_the_listed_statuses_are_compressed() {
        for status in [
            100u16, 101, 200, 201, 204, 206, 301, 304, 403, 404, 416, 500, 503,
        ] {
            assert_eq!(
                compresses_response(&response(status, Some("text/html"))),
                COMPRESSED_STATUSES.contains(&status),
                "{status}"
            );
        }
    }
}
