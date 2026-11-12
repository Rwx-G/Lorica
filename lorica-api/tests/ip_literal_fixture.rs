//! The guard on the Rust-to-TypeScript edge of the IP-literal rule.
//!
//! `lorica_config::host_shape` decides whether a host name is an IP
//! address, the way a browser's URL parser reads it. The dashboard
//! decides the same thing in `cert-san-match.ts` (the route editor's
//! certificate coverage check, and the AD CS hints in
//! `adcs-issuance.ts`). Two implementations of one rule share a vector
//! set: this test renders `ip-literal.generated.ts` from the Rust rule
//! and compares it with the committed bytes, and the dashboard's suite
//! replays every vector through its own implementation and against the
//! browser's URL parser. A rule changed on either side alone turns one
//! of the two suites red.
//!
//! Nothing is auto-written: when the file is stale the failure prints
//! it as it must read.
//!
//! The vector set also holds the last-line copy of the rule in
//! `lorica-adcs` (`build_csr` refuses an address as a dNSName), which
//! cannot link `lorica-config`: every vector is replayed through it.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use lorica_adcs::{build_csr, KeyType, SubjectFields};
use lorica_config::host_shape::{host_shape, HostShape};
use lorica_config::route_selection::{validate_hostname_syntax, HostnameShape};

/// The generated file, relative to this crate's manifest.
const GENERATED_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../lorica-dashboard/frontend/src/lib/ip-literal.generated.ts"
));

/// Where the fixture lives, for the failure message.
const FIXTURE_PATH: &str = "lorica-dashboard/frontend/src/lib/ip-literal.generated.ts";

/// The names the vector set classifies: each family the rule tells
/// apart, and the edges between them. The expected answers are not
/// listed here; they are what `host_shape` says.
const INPUTS: &[&str] = &[
    // IPv4 in the dotted spelling a browser sends.
    "192.0.2.10",
    "0.0.0.0",
    "255.255.255.255",
    "192.0.2.10.",
    // The other spellings a browser reads as an IPv4 address, and the
    // ones it refuses as a malformed one.
    "010.0.0.1",
    "192.0.2.010",
    "00.0.0.0",
    "0xC0.0.2.10",
    "0XC0.0.2.10",
    "0xc0.0x0.0x2.0xa",
    "3221225994",
    "0xc000020a",
    "030000001012",
    "192.0.10",
    "192.10",
    "1",
    "0x",
    "256.0.0.1",
    "1.2.3.256",
    "1.2.3.4.5",
    "example.123",
    "example.0x1f",
    "example.010",
    "*.0.2.10",
    "*.10",
    // DNS names, numeric labels anywhere but last included.
    "app.example.com",
    "App.Example.COM",
    "app.example.com.",
    "localhost",
    "_",
    "*.example.com",
    "192.0.2.10.example.org",
    "10.example",
    "v10",
    "example.0xg",
    "0x.example",
    "192.0.2.10..",
    "",
    ".",
    "bücher.example",
    // IPv6, bracketed or not, under several spellings.
    "[2001:db8::1]",
    "[2001:DB8:0:0:0:0:0:1]",
    "2001:db8::1",
    "2001:0db8:0000:0000:0000:0000:0000:0001",
    "[2001:db8::1].",
    "[::1]",
    "::",
    "[::]",
    "[2001:db8:0:1:0:0:0:1]",
    "[1:0:0:2:0:0:0:3]",
    "[0:0:1:0:0:0:0:0]",
    // IPv4-mapped and IPv4-compatible.
    "[::ffff:192.0.2.10]",
    "::ffff:c000:20a",
    "[::FFFF:C000:20A]",
    "[::192.0.2.10]",
    // Not an address: zone ids, ports, bracketed text, malformed.
    "[fe80::1%25eth0]",
    "fe80::1%eth0",
    "192.0.2.10:443",
    "[2001:db8::1]:443",
    "app.example.com:8443",
    "[not-an-address]",
    "[192.0.2.10]",
    "[2001:db8::1",
    "2001:db8::1]",
    "2001:db8::1::2",
    "12345::1",
    "[::ffff:01.2.3.4]",
];

/// `text` as a single-quoted TypeScript string literal.
fn typescript_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for c in text.chars() {
        match c {
            '\'' => out.push_str("\\'"),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

/// The kind names the vectors use, sorted, each once.
fn kinds_in_use() -> BTreeSet<&'static str> {
    INPUTS
        .iter()
        .map(|input| host_shape(input).kind())
        .collect()
}

/// The fixture as it must read, rendered from `host_shape`.
fn rendered_fixture() -> String {
    let mut out = String::new();
    out.push_str(
        "// Rendered from lorica-config's `host_shape` by\n\
         // lorica-api/tests/ip_literal_fixture.rs, which prints the file as it must\n\
         // read when the committed one differs. Replace the file with that; never\n\
         // edit it by hand.\n\n",
    );
    let kinds: Vec<String> = kinds_in_use().into_iter().map(typescript_string).collect();
    out.push_str("/** What a host name is to a browser's URL parser (`HostShape::kind`). */\n");
    out.push_str(&format!(
        "export type HostKind = {};\n\n",
        kinds.join(" | ")
    ));
    out.push_str(
        "/**\n * One name, what it is, and the address as a route stores it and a request\n \
         * names it (`HostShape::canonical`, `null` for no address).\n */\n\
         export interface HostShapeVector {\n  readonly input: string;\n  \
         readonly kind: HostKind;\n  readonly canonical: string | null;\n}\n\n",
    );
    out.push_str("export const HOST_SHAPE_VECTORS: readonly HostShapeVector[] = [\n");
    for input in INPUTS {
        let shape = host_shape(input);
        out.push_str(&format!(
            "  {{ input: {}, kind: {}, canonical: {} }},\n",
            typescript_string(input),
            typescript_string(shape.kind()),
            shape
                .canonical()
                .map_or("null".to_string(), |canonical| typescript_string(
                    &canonical
                )),
        ));
    }
    out.push_str("];\n");
    out
}

#[test]
fn the_dashboard_fixture_is_the_vector_set_rendered_from_the_rule() {
    let rendered = rendered_fixture();
    assert!(
        GENERATED_FIXTURE == rendered,
        "\n{FIXTURE_PATH} is not what lorica-config's `host_shape` renders. Replace the \
         whole file with what follows, byte for byte (LF line endings), between the \
         markers:\n\n-----BEGIN {FIXTURE_PATH}-----\n{rendered}-----END {FIXTURE_PATH}-----\n"
    );
}

#[test]
fn the_vectors_cover_every_shape_and_every_input_once() {
    // A vector set that stopped exercising a shape would still compare
    // equal to its own rendering; this keeps it wide. The match is
    // exhaustive, so a new shape fails to compile here until it is
    // given an input.
    let every_shape = [
        HostShape::Ipv4(Ipv4Addr::UNSPECIFIED),
        HostShape::Ipv6(Ipv6Addr::UNSPECIFIED),
        HostShape::NonCanonicalIpv4,
        HostShape::NotAnAddress,
    ];
    for shape in every_shape {
        let kind: &str = match shape {
            HostShape::Ipv4(_)
            | HostShape::Ipv6(_)
            | HostShape::NonCanonicalIpv4
            | HostShape::NotAnAddress => shape.kind(),
        };
        assert!(kinds_in_use().contains(kind), "no vector is {kind}");
    }
    let unique: BTreeSet<&&str> = INPUTS.iter().collect();
    assert_eq!(unique.len(), INPUTS.len(), "an input is listed twice");
}

/// `lorica-adcs` refuses, as a dNSName, every vector that names an
/// address, and builds a request for every one that is a host name a
/// route could carry.
#[test]
fn the_csr_builder_refuses_every_address_the_rule_names() {
    let dns_name = HostnameShape {
        allow_wildcard: false,
        allow_empty: false,
        allow_catch_all: false,
        allow_ipv6_literal: false,
        field_label: "san",
    };
    let mut built = 0;
    for input in INPUTS {
        let csr = build_csr(
            &[input.to_string()],
            &SubjectFields::default(),
            "LoricaWebServer",
            KeyType::EcdsaP256,
        );
        if host_shape(input) != HostShape::NotAnAddress {
            assert!(csr.is_err(), "{input:?} names an address and was requested");
        } else if validate_hostname_syntax(input, dns_name).is_ok() {
            assert!(csr.is_ok(), "{input:?} is a host name and was refused");
            built += 1;
        }
    }
    assert!(built > 0, "no vector is a host name: the replay went blind");
}
