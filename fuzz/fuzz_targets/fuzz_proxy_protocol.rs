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
//! - `parse` and `classify_prefix` agree on what is not a header.
//!
//! Run with:
//!
//! ```sh
//! cargo +nightly fuzz run fuzz_proxy_protocol
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use lorica_core::protocols::proxy_protocol::{
    classify_prefix, parse, Parsed, Prefix, MAX_HEADER_LEN,
};

fuzz_target!(|data: &[u8]| {
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
