// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Fuzz target for the hand-rolled OCSP response DER parser
//! (`lorica_tls::ocsp::validate_ocsp_response_bytes`). v1.5.1
//! audit L-4.
//!
//! The parser hand-decodes the SEQUENCE length encoding (short
//! form / long form 0x81 / long form 0x82) and reaches into the
//! ENUMERATED responseStatus field at a computed offset. The
//! audit flagged that the `bytes.len() <= status_offset + 2`
//! bound check on the long-form 0x82 path can pass for inputs
//! whose DER-declared content length overshoots the actual
//! buffer ; the worst case is `try_fetch_ocsp` returning `Err`
//! and the proxy serving the request without a stapled OCSP
//! response (best-effort behaviour, no security regression).
//!
//! This harness pins the no-panic invariant on arbitrary input
//! - the function MUST return `Ok(())` or `Err(String)` and
//! MUST NEVER panic regardless of the byte sequence supplied.
//! Run with :
//!
//! ```sh
//! cargo +nightly fuzz run fuzz_ocsp_response
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use lorica_tls::ocsp::validate_ocsp_response_bytes;

fuzz_target!(|data: &[u8]| {
    // We deliberately discard the result. The contract pinned
    // here is "must not panic", not "must reach a specific
    // verdict". `Ok` and `Err` outcomes are both well-formed.
    let _ = validate_ocsp_response_bytes(data);
});
