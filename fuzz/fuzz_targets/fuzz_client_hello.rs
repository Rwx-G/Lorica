// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Fuzz target for the ClientHello reader of TLS streams
//! (`lorica_stream::tls::client_hello`), v1.11.0 Story 12.4.
//!
//! The reader runs on the first bytes of every client of a TLS stream,
//! before any rule admits it, so this harness pins, on arbitrary bytes:
//!
//! - `parse` never panics;
//! - an accepted hello never claims more bytes than it was given, nor
//!   more than `CLIENTHELLO_BUFFER`;
//! - the answer does not depend on how the bytes arrived: every prefix of
//!   an accepted hello asks for more, and a refusal stays the same refusal
//!   whatever follows, so the engine can refuse at the first bad byte;
//! - a hello rustls writes, for a server name and an ALPN list taken from
//!   the input and cut into records at sizes taken from the input, parses
//!   to that name in canonical form and that list; and a hello
//!   re-serialised from what was parsed parses to the same fields.
//!
//! Run with:
//!
//! ```sh
//! cargo +nightly fuzz run fuzz_client_hello
//! ```

#![no_main]

use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use lorica_stream::tls::client_hello::{
    parse, ClientHelloError, Parsed, CLIENTHELLO_BUFFER, EXTENSION_ALPN,
    EXTENSION_ENCRYPTED_CLIENT_HELLO, EXTENSION_SERVER_NAME, MAX_RECORD_LEN, RECORD_HEADER_LEN,
};

/// A rustls client config per protocol version, built once.
fn base_config(tls13: bool) -> rustls::ClientConfig {
    static CONFIGS: OnceLock<[rustls::ClientConfig; 2]> = OnceLock::new();
    let configs = CONFIGS.get_or_init(|| {
        let build = |version: &'static rustls::SupportedProtocolVersion| {
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[version])
            .expect("ring supports both versions")
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth()
        };
        [
            build(&rustls::version::TLS12),
            build(&rustls::version::TLS13),
        ]
    });
    configs[usize::from(tls13)].clone()
}

/// A DNS name rustls accepts, from `data`: up to four labels of up to 12
/// letters and digits, each starting with a letter (so the name never
/// reads as an IP address), in mixed case.
fn dns_name(data: &mut &[u8]) -> Option<String> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let (&shape, rest) = data.split_first()?;
    *data = rest;
    let labels = 1 + usize::from(shape & 3);
    let mut name = String::new();
    for index in 0..labels {
        let (&len, rest) = data.split_first()?;
        let len = 1 + usize::from(len % 12);
        let bytes = rest.get(..len)?;
        *data = &rest[len..];
        if index > 0 {
            name.push('.');
        }
        for (position, &b) in bytes.iter().enumerate() {
            let alphabet = if position == 0 { &ALPHABET[..52] } else { ALPHABET };
            name.push(char::from(alphabet[usize::from(b) % alphabet.len()]));
        }
    }
    Some(name)
}

/// Up to four ALPN protocols of 1 to 16 arbitrary bytes, from `data`.
fn alpn_list(data: &mut &[u8]) -> Option<Vec<Vec<u8>>> {
    let (&count, rest) = data.split_first()?;
    *data = rest;
    let mut protocols = Vec::new();
    for _ in 0..(count & 3) {
        let (&len, rest) = data.split_first()?;
        let len = 1 + usize::from(len % 16);
        protocols.push(rest.get(..len)?.to_vec());
        *data = &rest[len..];
    }
    Some(protocols)
}

/// The handshake messages of `wire`'s records, joined.
fn messages_of(wire: &[u8]) -> Vec<u8> {
    let mut message = Vec::new();
    let mut rest = wire;
    while rest.len() >= RECORD_HEADER_LEN {
        let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        message.extend_from_slice(&rest[RECORD_HEADER_LEN..RECORD_HEADER_LEN + len]);
        rest = &rest[RECORD_HEADER_LEN + len..];
    }
    message
}

/// `message` cut into handshake records whose payload sizes cycle
/// through `sizes` (each at least 1), at most 64 of them.
fn records(message: &[u8], sizes: &[u8]) -> Vec<u8> {
    let floor = message.len().div_ceil(64);
    let mut wire = Vec::new();
    let mut rest = message;
    let mut index = 0;
    while !rest.is_empty() {
        let size = sizes
            .get(index % sizes.len().max(1))
            .map_or(rest.len(), |&s| usize::from(s).max(1))
            .max(floor)
            .min(rest.len())
            .min(MAX_RECORD_LEN);
        let (fragment, tail) = rest.split_at(size);
        wire.extend_from_slice(&[22, 3, 1]);
        wire.extend_from_slice(&u16::try_from(size).expect("at most 16 KiB").to_be_bytes());
        wire.extend_from_slice(fragment);
        rest = tail;
        index += 1;
    }
    wire
}

fn push16(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&u16::try_from(data.len()).expect("small").to_be_bytes());
    out.extend_from_slice(data);
}

/// A minimal hello carrying what `parsed` says, in one record.
fn reserialise(parsed: &Parsed) -> Vec<u8> {
    let mut extensions = Vec::new();
    if let Some(name) = &parsed.server_name {
        let mut entry = vec![0];
        push16(&mut entry, name.as_bytes());
        let mut data = Vec::new();
        push16(&mut data, &entry);
        extensions.extend_from_slice(&EXTENSION_SERVER_NAME.to_be_bytes());
        push16(&mut extensions, &data);
    }
    if !parsed.alpn.is_empty() {
        let mut names = Vec::new();
        for protocol in &parsed.alpn {
            names.push(u8::try_from(protocol.len()).expect("at most 255"));
            names.extend_from_slice(protocol);
        }
        let mut data = Vec::new();
        push16(&mut data, &names);
        extensions.extend_from_slice(&EXTENSION_ALPN.to_be_bytes());
        push16(&mut extensions, &data);
    }
    if parsed.ech_offered {
        extensions.extend_from_slice(&EXTENSION_ENCRYPTED_CLIENT_HELLO.to_be_bytes());
        push16(&mut extensions, &[]);
    }
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0; 32]);
    body.push(0);
    push16(&mut body, &[0x13, 0x01]);
    body.extend_from_slice(&[1, 0]);
    push16(&mut body, &extensions);
    let len = u32::try_from(body.len()).expect("small").to_be_bytes();
    let mut message = vec![1, len[1], len[2], len[3]];
    message.extend_from_slice(&body);
    records(&message, &[])
}

fn same_fields(a: &Parsed, b: &Parsed) -> bool {
    a.server_name == b.server_name && a.alpn == b.alpn && a.ech_offered == b.ech_offered
}

fuzz_target!(|data: &[u8]| {
    // Arbitrary bytes.
    match parse(data) {
        Ok(hello) => {
            assert!(hello.consumed <= data.len());
            assert!(hello.consumed <= CLIENTHELLO_BUFFER);
            for end in [0, hello.consumed / 2, hello.consumed - 1] {
                assert_eq!(parse(&data[..end]), Err(ClientHelloError::NeedMore));
            }
            assert_eq!(parse(&data[..hello.consumed]).as_ref(), Ok(&hello));
        }
        Err(ClientHelloError::Invalid(kind)) => {
            let mut longer = data.to_vec();
            longer.push(0);
            assert_eq!(parse(&longer), Err(ClientHelloError::Invalid(kind)));
        }
        Err(ClientHelloError::NeedMore) => {}
    }

    // rustls' own hello, for a name and protocols the input picks.
    let Some((&flags, mut rest)) = data.split_first() else {
        return;
    };
    let Some(name) = dns_name(&mut rest) else {
        return;
    };
    let Some(alpn) = alpn_list(&mut rest) else {
        return;
    };
    let mut config = base_config(flags & 1 == 1);
    config.enable_sni = flags & 2 == 0;
    config.alpn_protocols = alpn.clone();
    let Ok(server_name) = rustls::pki_types::ServerName::try_from(name.clone()) else {
        return;
    };
    let mut client =
        rustls::ClientConnection::new(Arc::new(config.clone()), server_name).expect("a client");
    let mut wire = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut wire).expect("in memory");
    }
    let wire = records(&messages_of(&wire), rest);
    let hello = parse(&wire).expect("rustls' hello is accepted");
    assert_eq!(hello.consumed, wire.len());
    let expected_name = config.enable_sni.then(|| name.to_ascii_lowercase());
    assert_eq!(hello.server_name, expected_name);
    assert_eq!(hello.alpn, alpn);

    let again = parse(&reserialise(&hello)).expect("a re-serialised hello is accepted");
    assert!(same_fields(&again, &hello), "{again:?} != {hello:?}");
});
