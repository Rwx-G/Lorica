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

//! Redaction applied to a capture record before it leaves the proxy
//! (Story 10.2 AC #2).
//!
//! Two things are redacted: header values, and the values of named
//! query-string parameters in the request target. In both cases the
//! NAME stays and the value is replaced by [`redacted_marker`], so an
//! operator reading the record can see the header or parameter was
//! present and how large its value was, without seeing the value.
//!
//! # What a rule cannot do
//!
//! [`ALWAYS_REDACTED_HEADERS`] is a `const`, and [`is_redacted_header`]
//! consults it before it consults the rule. The rule's `redact.headers`
//! list is the only configurable input, and it is ORed in: it can add
//! names, and no value it can hold subtracts one. There is no setting,
//! no automation scope and no dashboard field that reaches this list,
//! because a capture is a verbatim copy of production traffic and a
//! credential in one is a disclosure with a retention period.
//!
//! # What is not redacted
//!
//! The body. A capture rule exists so an operator can see the exact
//! bytes an exchange carried, and a body scrubber that guessed at
//! secrets would make the record lie in the one place it must not.
//! The rule's body caps, the retention TTL and the always-redacted
//! headers are the controls; a body is what the operator asked to see.

/// Header names redacted in every record, whatever the rule says.
///
/// Lowercase, because [`is_redacted_header`] compares without regard
/// to case and the `http` crate stores names lowercase anyway.
pub const ALWAYS_REDACTED_HEADERS: [&str; 4] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
];

/// Whether a header called `name` is redacted under a rule listing
/// `extra` names on top of [`ALWAYS_REDACTED_HEADERS`].
///
/// Case-insensitive on both lists: header names are, per RFC 9110.
///
/// ```
/// use lorica::capture::is_redacted_header;
/// assert!(is_redacted_header("Authorization", &[]));
/// assert!(is_redacted_header("X-Api-Key", &["x-api-key".to_string()]));
/// assert!(!is_redacted_header("Accept", &[]));
/// ```
pub fn is_redacted_header(name: &str, extra: &[String]) -> bool {
    ALWAYS_REDACTED_HEADERS
        .iter()
        .any(|always| always.eq_ignore_ascii_case(name))
        || extra.iter().any(|named| named.eq_ignore_ascii_case(name))
}

/// The text that stands in for a redacted value.
///
/// `removed_bytes` is the byte length of the value that was dropped,
/// so a reader can tell an empty `Authorization` header from a
/// 2 KiB one without seeing either.
///
/// ```
/// use lorica::capture::redacted_marker;
/// assert_eq!(redacted_marker(10), "<redacted:10 bytes>");
/// ```
pub fn redacted_marker(removed_bytes: usize) -> String {
    format!("<redacted:{removed_bytes} bytes>")
}

/// Mask the value of every query parameter in `uri` whose name is in
/// `names`, comparing names exactly.
///
/// The query is walked as raw text and never decoded: a percent-encoded
/// value is masked as the bytes it was sent as, and everything that is
/// not a masked value is copied byte for byte. Decoding and re-encoding
/// would alter the record for parameters the rule never named, and a
/// record that differs from the wire is worse than one that is harder
/// to read. Consequences of that stance, all deliberate:
///
/// - A parameter that repeats is masked at every occurrence, each with
///   its own byte count.
/// - `name=` (present, empty) becomes `name=<redacted:0 bytes>`.
///   `name` alone (no `=`) is left as it is: there is no value to
///   remove, and adding an `=` would put a byte on the record that was
///   not on the wire.
/// - A name that was sent percent-encoded does not match its decoded
///   spelling. The rule names what the wire carries.
///
/// ```
/// use lorica::capture::mask_query;
/// let masked = mask_query("/login?user=bob&token=s3cret", &["token".to_string()]);
/// assert_eq!(masked, "/login?user=bob&token=<redacted:6 bytes>");
/// ```
pub fn mask_query(uri: &str, names: &[String]) -> String {
    if names.is_empty() {
        return uri.to_string();
    }
    let Some((path, query)) = uri.split_once('?') else {
        return uri.to_string();
    };
    let masked = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) if names.iter().any(|named| named == name) => {
                format!("{name}={}", redacted_marker(value.len()))
            }
            _ => pair.to_string(),
        })
        .collect::<Vec<String>>()
        .join("&");
    format!("{path}?{masked}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|n| (*n).to_string()).collect()
    }

    #[test]
    fn the_four_always_redacted_headers_are_redacted_with_no_extra_names() {
        for name in [
            "Authorization",
            "Proxy-Authorization",
            "Cookie",
            "Set-Cookie",
        ] {
            assert!(is_redacted_header(name, &[]), "{name}");
        }
        assert!(!is_redacted_header("Content-Type", &[]));
    }

    #[test]
    fn header_names_compare_without_regard_to_case() {
        assert!(is_redacted_header("AUTHORIZATION", &[]));
        assert!(is_redacted_header("set-cookie", &[]));
        assert!(is_redacted_header("x-api-key", &names(&["X-API-KEY"])));
    }

    #[test]
    fn an_extra_name_extends_the_set_and_the_always_set_stays() {
        let extra = names(&["X-Api-Key"]);
        assert!(is_redacted_header("X-Api-Key", &extra));
        assert!(is_redacted_header("Authorization", &extra));
        assert!(is_redacted_header("Cookie", &extra));
    }

    #[test]
    fn a_rule_that_names_an_always_redacted_header_cannot_un_redact_it() {
        // There is no path by which a listed name subtracts; this test
        // is the statement of that fact, so a future "exclusions" list
        // has to delete it on purpose.
        let extra = names(&["Authorization", "Set-Cookie"]);
        assert!(is_redacted_header("Authorization", &extra));
        assert!(is_redacted_header("Set-Cookie", &extra));
        assert!(is_redacted_header("Cookie", &extra));
    }

    #[test]
    fn the_marker_carries_the_byte_length_of_what_was_removed() {
        assert_eq!(redacted_marker(0), "<redacted:0 bytes>");
        assert_eq!(redacted_marker("Bearer abc".len()), "<redacted:10 bytes>");
        assert_eq!(redacted_marker("é".len()), "<redacted:2 bytes>");
    }

    #[test]
    fn a_repeated_parameter_is_masked_at_every_occurrence() {
        let masked = mask_query("/p?token=abc&x=1&token=defgh", &names(&["token"]));
        assert_eq!(
            masked,
            "/p?token=<redacted:3 bytes>&x=1&token=<redacted:5 bytes>"
        );
    }

    #[test]
    fn a_parameter_with_no_value_is_masked_as_zero_bytes_or_left_alone() {
        let masked = mask_query("/p?token=&x=1", &names(&["token"]));
        assert_eq!(masked, "/p?token=<redacted:0 bytes>&x=1");
        let bare = mask_query("/p?token&x=1", &names(&["token"]));
        assert_eq!(bare, "/p?token&x=1", "no `=` means no value to remove");
    }

    #[test]
    fn a_percent_encoded_value_is_masked_by_its_wire_length_without_decoding() {
        // `%2Fa%2Fb` is 8 bytes on the wire and 4 decoded. The record
        // reports the wire.
        let masked = mask_query("/p?next=%2Fa%2Fb&keep=%2Fc", &names(&["next"]));
        assert_eq!(masked, "/p?next=<redacted:8 bytes>&keep=%2Fc");
    }

    #[test]
    fn an_unrelated_parameter_is_untouched_and_names_compare_exactly() {
        let masked = mask_query("/p?Token=abc&token=def&tokens=ghi", &names(&["token"]));
        assert_eq!(masked, "/p?Token=abc&token=<redacted:3 bytes>&tokens=ghi");
    }

    #[test]
    fn a_target_without_a_query_and_an_empty_name_list_are_copied_verbatim() {
        assert_eq!(mask_query("/p", &names(&["token"])), "/p");
        assert_eq!(mask_query("/p?token=abc", &[]), "/p?token=abc");
    }
}
