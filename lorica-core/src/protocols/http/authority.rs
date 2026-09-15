// Copyright 2026 Cloudflare, Inc.
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

//! HTTP authority consistency checks shared by protocol versions.
//!
//! Ported from upstream Pingora `ffab8302`, reduced to the checks that
//! are reachable in this fork.
//!
//! # What was left upstream, and why
//!
//! The upstream commit also carries a raw request-target classifier
//! (`raw_target_authority`, `has_ambiguous_port_suffix`, the CONNECT
//! reconciliation) for absolute-form targets such as
//! `GET http://host/path HTTP/1.1`. Those shapes cannot reach this code
//! here: `RequestHeader::build` routes the target through
//! `Uri::builder().path_and_query()`, and the `http` version this
//! workspace pins rejects an absolute-form or scheme-prefixed target
//! outright, so `read_request` (`v1/server.rs`) fails the request at
//! parse time, before any of this runs. Verified by porting the
//! upstream tests: their inputs cannot be constructed here.
//!
//! Importing a parser that nothing can reach would mean carrying ~330
//! lines of untestable code in a security-critical path. If the pinned
//! `http` ever starts accepting those targets, or the H2 path starts
//! carrying a raw absolute-form `:path`, take the rest of `ffab8302`
//! then, and take it with its tests.
//!
//! What remains is the part that is reachable on both protocols and
//! that a proxy in front of another server must not get wrong: one
//! request, one unambiguous authority.

use http::header;
use lorica_error::{Error, ErrorType::InvalidHTTPHeader, Result};
use lorica_http::RequestHeader;

/// Validate that a request has one unambiguous authority.
///
/// Rejects duplicate `Host` ([RFC 9112 section 3.2]), userinfo in
/// `Host` or in the URI authority ([RFC 9110 section 4.2.4]), and a
/// `Host` that disagrees with the URI authority. This is stricter than
/// [RFC 9112 section 3.2.2], which replaces a conflicting `Host`.
///
/// Every one of these is a split between what this proxy routes on and
/// what the upstream will route on. Userinfo matters because
/// [`http::Uri::host`] strips it, so a validator and a router reading
/// the same bytes can disagree about the host.
///
/// HTTP/1 ingress calls this from `validate_request`; HTTP/2 ingress
/// calls it per stream during acceptance.
///
/// [RFC 9110 section 4.2.4]: https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.4
/// [RFC 9112 section 3.2]: https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2
/// [RFC 9112 section 3.2.2]: https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.2
pub fn validate_request_authority(req: &RequestHeader) -> Result<()> {
    validate_request_authority_fields(req)
}

/// Validate the authority fields shared by H1 and H2 ingress.
pub fn validate_request_authority_fields(req: &RequestHeader) -> Result<()> {
    let mut hosts = req.headers.get_all(header::HOST).iter();
    let (host, duplicate_host) = (hosts.next(), hosts.next());

    if duplicate_host.is_some() {
        return Error::e_explain(InvalidHTTPHeader, "multiple Host header fields");
    }

    if host.is_some_and(|host| host.as_bytes().contains(&b'@')) {
        return Error::e_explain(InvalidHTTPHeader, "userinfo in Host header");
    }

    let uri_authority = req.uri.authority().map(|authority| authority.as_str());
    if uri_authority.is_some_and(|authority| authority.contains('@')) {
        return Error::e_explain(InvalidHTTPHeader, "userinfo in URI authority");
    }

    if host
        .zip(uri_authority)
        .is_some_and(|(host, authority)| host.as_bytes() != authority.as_bytes())
    {
        return Error::e_explain(InvalidHTTPHeader, "Host header differs from URI authority");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn request(method: &str, target: &str, hosts: &[&str]) -> RequestHeader {
        let mut request = RequestHeader::build(method, target.as_bytes(), None).unwrap();
        for host in hosts {
            request.append_header(header::HOST, *host).unwrap();
        }
        request
    }

    #[test]
    fn validate_authority_sources() {
        assert!(validate_request_authority(&request("GET", "/test", &[])).is_ok());
        assert!(
            validate_request_authority(&request("GET", "/test", &["authority.example:8443"]))
                .is_ok()
        );
        assert!(validate_request_authority(&request(
            "GET",
            "/test",
            &["authority.example", "other.example"]
        ))
        .is_err());
        assert!(validate_request_authority(&request(
            "GET",
            "/test",
            &["authority.example", "authority.example"]
        ))
        .is_err());
        assert!(
            validate_request_authority(&request("GET", "/test", &["user@authority.example"]))
                .is_err()
        );
        assert!(validate_request_authority(&request(
            "GET",
            "/test",
            &["user:pass@authority.example"]
        ))
        .is_err());
        assert!(validate_request_authority(&request(
            "GET",
            "/test",
            &["user%40authority.example"]
        ))
        .is_ok());

        let uri_request = |uri: &str, host: Option<&str>| {
            let mut request = http::Request::builder().uri(uri).body(()).unwrap();
            if let Some(host) = host {
                request
                    .headers_mut()
                    .insert(header::HOST, HeaderValue::from_str(host).unwrap());
            }
            RequestHeader::from(request.into_parts().0)
        };
        assert!(validate_request_authority(&uri_request(
            "https://user@authority.example/test",
            None
        ))
        .is_err());
        assert!(validate_request_authority(&uri_request(
            "https://authority.example/test",
            Some("other.example")
        ))
        .is_err());
        // The H2 shape this exists for: `:authority` and `Host` agree.
        assert!(validate_request_authority(&uri_request(
            "https://authority.example/test",
            Some("authority.example")
        ))
        .is_ok());
    }

    #[test]
    fn absolute_form_targets_do_not_survive_header_parsing() {
        // The justification for the reduced port, asserted rather than
        // claimed: an absolute-form target is refused where `read_request`
        // builds the header, so the upstream classifier this module does
        // not carry would have nothing to classify.
        for target in [
            "http://authority.example/test",
            "http://user@authority.example/test",
            "http:443",
            "http:///path",
        ] {
            assert!(
                RequestHeader::build("GET", target.as_bytes(), None).is_err(),
                "{target} became a request header; revisit the rest of upstream ffab8302"
            );
        }
    }
}
