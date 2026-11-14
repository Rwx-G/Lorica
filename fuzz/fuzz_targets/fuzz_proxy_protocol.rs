// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Fuzz target for the PROXY protocol header parser
//! (`lorica_core::protocols::proxy_protocol`), v1.11.0 Story 12.8.
//!
//! The parser reads bytes a trusted load balancer sends ahead of the
//! client's, and `classify_prefix` reads the first bytes of every direct
//! client on a listener with PROXY accept on. Both run on input the
//! network controls, so this harness pins, on arbitrary bytes:
//!
//! - neither function panics;
//! - a complete header never claims more bytes than it was given, nor
//!   more than `MAX_HEADER_LEN`, and its TLVs iterate within it;
//! - the answer does not depend on how the header was split across
//!   reads: every prefix shorter than a complete header, and every prefix
//!   of an incomplete one, is `Incomplete`, so a refusal is final;
//! - `parse` and `classify_prefix` agree on what is not a header;
//! - (Story 12.3) every header the encoder writes, for addresses taken
//!   from the input, parses back whole to the same canonical addresses.
//!
//! Run with:
//!
//! ```sh
//! cargo +nightly fuzz run fuzz_proxy_protocol
//! ```

#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use libfuzzer_sys::fuzz_target;
use lorica_core::protocols::proxy_protocol::{
    classify_prefix, encode_v1, encode_v2, encode_v2_dgram, parse, Addresses, Parsed, Prefix,
    MAX_HEADER_LEN, V1_MAX_LEN,
};

/// A source and a destination read from the first bytes of `data`: one
/// byte picks each address's family, then the addresses and ports
/// follow. `None` when `data` is too short.
fn addresses_from(data: &[u8]) -> Option<(SocketAddr, SocketAddr)> {
    let (&families, mut rest) = data.split_first()?;
    let mut read = |v6: bool| -> Option<SocketAddr> {
        let len = if v6 { 16 } else { 4 };
        let (octets, tail) = (rest.get(..len)?, rest.get(len..)?);
        let (port, tail) = (tail.get(..2)?, &tail[2..]);
        rest = tail;
        let ip = if v6 {
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(octets).ok()?))
        } else {
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(octets).ok()?))
        };
        Some(SocketAddr::new(ip, u16::from_be_bytes([port[0], port[1]])))
    };
    let source = read(families & 1 == 1)?;
    let destination = read(families & 2 == 2)?;
    Some((source, destination))
}

fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

/// Encode, parse, compare: the whole header is consumed and carries the
/// canonical addresses, or none when their families differ.
fn round_trip(source: SocketAddr, destination: SocketAddr) {
    let (source_c, destination_c) = (canonical(source), canonical(destination));
    let same_family = source_c.is_ipv4() == destination_c.is_ipv4();
    for (wire, udp) in [
        (encode_v1(source, destination), false),
        (encode_v2(source, destination), false),
        (encode_v2_dgram(source, destination), true),
    ] {
        let Ok(Parsed::Complete { header, consumed }) = parse(&wire) else {
            panic!("an encoded header does not parse: {wire:?}");
        };
        assert_eq!(consumed, wire.len());
        assert!(wire.len() <= MAX_HEADER_LEN);
        if wire.starts_with(b"PROXY ") {
            assert!(wire.len() <= V1_MAX_LEN);
        }
        let expected = match (same_family, udp) {
            (false, _) => Addresses::Unspecified,
            (true, false) => Addresses::Tcp {
                source: source_c,
                destination: destination_c,
            },
            (true, true) => Addresses::Udp {
                source: source_c,
                destination: destination_c,
            },
        };
        assert_eq!(header.addresses, expected);
    }
}

fuzz_target!(|data: &[u8]| {
    if let Some((source, destination)) = addresses_from(data) {
        round_trip(source, destination);
    }

    let prefix = classify_prefix(data);
    let parsed = parse(data);

    if prefix == Prefix::NotProxy {
        assert!(parsed.is_err(), "a buffer with no signature parsed");
    }

    match parsed {
        Ok(Parsed::Complete { header, consumed }) => {
            assert!(consumed <= data.len());
            assert!(consumed <= MAX_HEADER_LEN);
            let tlv_bytes: usize = header.tlvs.map(|(_, value)| 3 + value.len()).sum();
            assert!(tlv_bytes <= consumed);
            for cut in 0..consumed {
                assert_eq!(parse(&data[..cut]), Ok(Parsed::Incomplete), "cut at {cut}");
            }
            let header_alone = parse(&data[..consumed]).expect("the header alone parses");
            assert_eq!(header_alone, parse(data).expect("parsed above"));
        }
        Ok(Parsed::Incomplete) => {
            for cut in 0..data.len() {
                assert_eq!(parse(&data[..cut]), Ok(Parsed::Incomplete), "cut at {cut}");
            }
        }
        Err(_) => {}
    }
});
