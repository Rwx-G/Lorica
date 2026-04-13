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

//! Public data types exposed by the WAF engine.
//!
//! Kept in a dedicated module so the core engine file stays focused on
//! behavior and orchestration. Re-exported through `engine::mod` so the
//! crate's public paths (`lorica_waf::engine::WafEvent`, etc.) are
//! unchanged.

use serde::{Deserialize, Serialize};

use crate::rules::RuleCategory;

/// WAF evaluation verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WafVerdict {
    /// Request is clean - no rules matched.
    Pass,
    /// One or more rules matched (detection mode - request proceeds).
    Detected(Vec<WafEvent>),
    /// One or more rules matched (blocking mode - request should be rejected).
    Blocked(Vec<WafEvent>),
}

/// A single WAF event recording a rule match.
///
/// One event is produced per rule that fires on a given field
/// (path, query, header, or body). Events are stored in the engine's
/// bounded ring buffer and surfaced to the dashboard / API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WafEvent {
    pub rule_id: u32,
    pub description: String,
    pub category: RuleCategory,
    pub severity: u8,
    pub matched_field: String,
    pub matched_value: String,
    pub timestamp: String,
    /// Client IP that triggered the event (set by the proxy layer).
    #[serde(default)]
    pub client_ip: String,
    /// Route hostname that was matched (set by the proxy layer).
    #[serde(default)]
    pub route_hostname: String,
    /// Whether the request was blocked or just detected.
    #[serde(default)]
    pub action: String,
}

/// WAF operating mode for a specific evaluation.
///
/// `Detection` records matches but lets the request through (used for
/// tuning new rules without breaking traffic). `Blocking` returns 403
/// to the client when any rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafMode {
    /// Log matches but allow the request to proceed.
    Detection,
    /// Reject the request with a 403 on any rule match.
    Blocking,
}

/// Summary of a WAF rule for API exposure.
///
/// Mirrors a [`crate::rules::WafRule`] but drops the compiled regex
/// so it can be safely serialized over the admin API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSummary {
    pub id: u32,
    pub description: String,
    pub category: RuleCategory,
    pub severity: u8,
    pub enabled: bool,
}

/// A user-defined custom WAF rule.
///
/// Custom rules are evaluated alongside the default ruleset on every
/// scanned field. Their regex is compiled with a size cap (see
/// [`super::WafEngine::MAX_CUSTOM_REGEX_SIZE`]) to bound admin attack
/// surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    pub id: u32,
    pub description: String,
    pub category: RuleCategory,
    pub pattern: String,
    pub severity: u8,
    pub enabled: bool,
}
