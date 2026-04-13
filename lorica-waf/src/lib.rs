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

#![deny(unsafe_code)]

//! WAF engine for Lorica with OWASP CRS-inspired rules.
//!
//! Provides SQL injection, XSS, path traversal, command injection, SSRF,
//! XXE, SSTI, prototype pollution, and protocol-violation detection using
//! precompiled regex patterns. Supports detection-only and blocking modes.
//!
//! The crate exposes three main building blocks:
//! - [`engine::WafEngine`] - holds the active ruleset, custom rules,
//!   IP blocklist, and a bounded ring buffer of recent events.
//! - [`rules::RuleSet`] / [`rules::WafRule`] - the default CRS-inspired
//!   ruleset and the per-rule shape consumed by the engine.
//! - [`ip_blocklist::IpBlocklist`] - a separate O(1) IP blocklist that
//!   pulls from an external feed and short-circuits requests before
//!   the regex pipeline runs.

pub mod engine;
pub mod ip_blocklist;
pub mod prefilter;
pub mod rules;

pub use engine::{RuleSummary, WafEngine, WafEvent, WafMode, WafVerdict};
pub use ip_blocklist::IpBlocklist;
pub use rules::{RuleCategory, RuleSet, WafRule};
