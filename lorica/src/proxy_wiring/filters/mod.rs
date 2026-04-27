// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Per-stage `request_filter` rejection helpers.
//!
//! Story 8.1 AC #4 - the `check_<name>` methods extracted from
//! `request_filter` (AC #5) live in dedicated submodules so the
//! cross-cutting decomposition stays organised by concern (IP-based
//! checks, route-config checks, rate limits, mTLS, GeoIP, etc.). The
//! AC originally listed `filters/{cache, waf, rate_limit,
//! forward_auth, bot}.rs` ; the practical mapping landed as a single
//! `checks.rs` file because most helpers cross those concern lines
//! (e.g. `check_ip_blocked` is both an IP check and a WAF check) and
//! splitting the inherent `impl LoricaProxy` block across many files
//! was buying organisation at the cost of import noise. A future
//! per-concern split is a simple `mv` of the corresponding `fn` body
//! between files.

pub mod checks;
