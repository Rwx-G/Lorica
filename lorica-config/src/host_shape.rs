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

//! Whether a host name is an IP address, the one rule every surface
//! asks.
//!
//! A browser does not send a host as it was typed. Its URL parser (the
//! WHATWG URL Standard, section 3.5 "host parsing") reads a name whose
//! last label is a number (decimal, octal with a leading `0`, or hex
//! with `0x`) as an IPv4 address in any of the spellings `inet_aton`
//! accepts, and sends it as four decimal numbers: `010.0.0.1` goes out
//! as `8.0.0.1`, `0xc0.0.2.10` and `3221225994` as `192.0.2.10`, and
//! `1.2.3.256` is refused outright. A route, an alias, a grant or an AD
//! CS suffix stored under such a spelling names a host no browser ever
//! sends, and a wildcard over such a tail would cover an address, which
//! only an `iPAddress` SAN does. [`host_shape`] tells the cases apart,
//! and every caller deciding "is this an address?" asks it.
//!
//! The dashboard implements the same rule in TypeScript
//! (`lorica-dashboard/frontend/src/lib/cert-san-match.ts`). The two
//! share a vector set, `ip-literal.generated.ts`, which
//! `lorica-api/tests/ip_literal_fixture.rs` renders from this module and
//! pins byte for byte; the dashboard's suite replays it and holds each
//! vector against the browser's own URL parser.

use std::net::{Ipv4Addr, Ipv6Addr};

/// What a host name is to a browser's URL parser. See the module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostShape {
    /// An IPv4 address in the one spelling a browser sends: four
    /// decimal numbers from 0 to 255, none with a leading zero.
    Ipv4(Ipv4Addr),
    /// An IPv6 address, with or without the brackets a `Host` header
    /// carries it in. A zone id (`fe80::1%eth0`) is not part of one.
    Ipv6(Ipv6Addr),
    /// A name the URL parser reads as an IPv4 address written another
    /// way, or refuses as a malformed one: its last label is a number,
    /// yet it is not the dotted form [`HostShape::Ipv4`] holds. No
    /// browser sends it as it is written.
    NonCanonicalIpv4,
    /// Anything else: a DNS name, or text that is not a host at all.
    /// Whether it is a valid name is another check's business.
    NotAnAddress,
}

impl HostShape {
    /// The name of this shape in the vector set the dashboard replays.
    pub fn kind(self) -> &'static str {
        match self {
            HostShape::Ipv4(_) => "ipv4",
            HostShape::Ipv6(_) => "ipv6",
            HostShape::NonCanonicalIpv4 => "non_canonical_ipv4",
            HostShape::NotAnAddress => "not_an_address",
        }
    }

    /// The address as a route stores it and a request names it, the
    /// form `route_selection::canonical_hostname` writes: dotted
    /// decimal, or an IPv6 literal in brackets as [`Ipv6Addr`] displays
    /// it (RFC 5952). `None` when the name is no address.
    ///
    /// ```
    /// use lorica_config::host_shape::host_shape;
    /// assert_eq!(host_shape("2001:DB8::0001").canonical().as_deref(), Some("[2001:db8::1]"));
    /// assert_eq!(host_shape("010.0.0.1").canonical(), None);
    /// ```
    pub fn canonical(self) -> Option<String> {
        match self {
            HostShape::Ipv4(address) => Some(address.to_string()),
            HostShape::Ipv6(address) => Some(format!("[{address}]")),
            HostShape::NonCanonicalIpv4 | HostShape::NotAnAddress => None,
        }
    }
}

/// What `name` is to a browser's URL parser.
///
/// One root dot is ignored, as `route_selection::canonical_hostname`
/// drops it, and ASCII case makes no difference. A bracketed name is an
/// IPv6 literal or nothing; an unbracketed name holding a `:` is an
/// IPv6 address or nothing (a port is not part of a host). Otherwise
/// the URL Standard's "ends in a number" test decides whether the name
/// is read as an IPv4 address, and only the canonical dotted spelling
/// is [`HostShape::Ipv4`].
///
/// Allocates nothing.
///
/// ```
/// use lorica_config::host_shape::{host_shape, HostShape};
/// assert!(matches!(host_shape("192.0.2.10"), HostShape::Ipv4(_)));
/// assert!(matches!(host_shape("[2001:db8::1]"), HostShape::Ipv6(_)));
/// assert_eq!(host_shape("010.0.0.1"), HostShape::NonCanonicalIpv4);
/// assert_eq!(host_shape("0xc0.0.2.10"), HostShape::NonCanonicalIpv4);
/// assert_eq!(host_shape("app.example.com"), HostShape::NotAnAddress);
/// ```
pub fn host_shape(name: &str) -> HostShape {
    let without_root = name.strip_suffix('.').unwrap_or(name);
    if let Some(inner) = without_root
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return inner
            .parse::<Ipv6Addr>()
            .map_or(HostShape::NotAnAddress, HostShape::Ipv6);
    }
    if without_root.contains(':') {
        return without_root
            .parse::<Ipv6Addr>()
            .map_or(HostShape::NotAnAddress, HostShape::Ipv6);
    }
    // The test runs on the name as sent, root dot included: the URL
    // Standard drops one empty last label itself, and a second one
    // makes the name a domain.
    if !ends_in_a_number(name) {
        return HostShape::NotAnAddress;
    }
    without_root
        .parse::<Ipv4Addr>()
        .map_or(HostShape::NonCanonicalIpv4, HostShape::Ipv4)
}

/// Whether `name` is an address of any spelling, [`host_shape`] being
/// anything but [`HostShape::NotAnAddress`]: no DNS name, and so never
/// covered by a wildcard or a DNS SAN, and never requested from AD CS.
///
/// ```
/// use lorica_config::host_shape::names_an_address;
/// assert!(names_an_address("192.0.2.10"));
/// assert!(names_an_address("0.2.10"));
/// assert!(names_an_address("[::1]"));
/// assert!(!names_an_address("app.example.com"));
/// assert!(!names_an_address("192.0.2.10.example.org"));
/// ```
pub fn names_an_address(name: &str) -> bool {
    host_shape(name) != HostShape::NotAnAddress
}

/// The URL Standard's "ends in a number checker": whether the last
/// label of `name`, one empty last label aside, is all decimal digits
/// or parses as an IPv4 number (`0x` hex, `0` octal).
fn ends_in_a_number(name: &str) -> bool {
    let mut labels = name.rsplit('.');
    let mut last = labels.next().unwrap_or_default();
    if last.is_empty() {
        match labels.next() {
            Some(before) => last = before,
            None => return false,
        }
    }
    (!last.is_empty() && last.bytes().all(|b: u8| b.is_ascii_digit()))
        || parses_as_an_ipv4_number(last)
}

/// The URL Standard's "IPv4 number parser", answering only whether it
/// succeeds: `0x` (any case) then hex digits, possibly none; a leading
/// `0` then octal digits; or decimal digits. The value is never needed:
/// what matters is that the parser takes the label for a number.
fn parses_as_an_ipv4_number(label: &str) -> bool {
    if label.is_empty() {
        return false;
    }
    let (digits, radix): (&str, u32) = match label
        .strip_prefix("0x")
        .or_else(|| label.strip_prefix("0X"))
    {
        Some(hex) => (hex, 16),
        None if label.len() >= 2 && label.starts_with('0') => (&label[1..], 8),
        None => (label, 10),
    };
    digits.chars().all(|c: char| c.is_digit(radix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_label_decides_whether_a_name_is_read_as_a_number() {
        for name in [
            "1",
            "0x",
            "0X1F",
            "07",
            "08",
            "a.10",
            "a.0x0",
            "a.10.",
            "0xc0.0.2.10",
        ] {
            assert!(ends_in_a_number(name), "{name}");
        }
        for name in [
            "", ".", "a", "a.b", "a.0xg", "a.10..", "10.a", "a.1a", "a.-1", "a.+1",
        ] {
            assert!(!ends_in_a_number(name), "{name}");
        }
    }

    #[test]
    fn only_the_dotted_decimal_spelling_is_an_ipv4_address() {
        assert_eq!(
            host_shape("192.0.2.10"),
            HostShape::Ipv4(Ipv4Addr::new(192, 0, 2, 10))
        );
        assert_eq!(
            host_shape("192.0.2.10."),
            HostShape::Ipv4(Ipv4Addr::new(192, 0, 2, 10))
        );
        for spelled_otherwise in [
            "010.0.0.1",
            "192.0.2.010",
            "0xc0.0.2.10",
            "3221225994",
            "192.0.10",
            "1.2.3.256",
            "1.2.3.4.5",
            "example.123",
            "*.0.2.10",
        ] {
            assert_eq!(
                host_shape(spelled_otherwise),
                HostShape::NonCanonicalIpv4,
                "{spelled_otherwise}"
            );
        }
    }

    #[test]
    fn an_ipv6_address_is_one_with_or_without_brackets_and_never_with_a_zone_or_port() {
        let address: Ipv6Addr = "2001:db8::1".parse().expect("test setup: address");
        for name in [
            "2001:db8::1",
            "[2001:db8::1]",
            "[2001:DB8::1].",
            "2001:db8::1.",
        ] {
            assert_eq!(host_shape(name), HostShape::Ipv6(address), "{name}");
        }
        for name in [
            "[fe80::1%25eth0]",
            "fe80::1%eth0",
            "[2001:db8::1]:443",
            "192.0.2.10:443",
            "[not-an-address]",
            "[192.0.2.10]",
        ] {
            assert_eq!(host_shape(name), HostShape::NotAnAddress, "{name}");
        }
    }

    #[test]
    fn every_shape_names_its_canonical_form_as_canonical_hostname_writes_it() {
        for name in ["192.0.2.10", "[2001:DB8:0:0::0001]", "[::FFFF:C000:20A]"] {
            let canonical = host_shape(name).canonical().expect(name);
            assert_eq!(
                crate::route_selection::canonical_hostname(name),
                canonical,
                "{name}"
            );
            assert_eq!(host_shape(&canonical), host_shape(name), "{name}");
        }
    }
}
