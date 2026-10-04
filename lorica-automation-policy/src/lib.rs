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

#![deny(clippy::all)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

//! The automation plane's policy, as data and pure functions.
//!
//! # Why a crate of its own
//!
//! The policy has four readers that cannot all see each other.
//! `lorica-config` owns the token model, `lorica-api` enforces the
//! plane, `lorica-mcp` describes it to a model, and `lorica` mints the
//! tokens. `lorica-mcp`'s stdio binary must not link SQLite, so it
//! could depend on neither of the first two, and until this crate it
//! restated the scope spellings, the settings allowlist and its bounds
//! in its own source under tests that pinned each copy. Every one of
//! them now reads the one statement here, and a copy that remains (the
//! dashboard's fixture, the OpenAPI documents, `docs/mcp.md`) is pinned
//! against it or rendered from it.
//!
//! # What is here, and what is deliberately not
//!
//! Here: the scope vocabulary ([`scope`]), the MCP tier partition and
//! the rule that resolves a scope set to one tier ([`tier`]), the admin
//! tier's settings allowlist ([`settings`]), and the config tier's
//! withheld route fields and one-way protection rules
//! ([`protections`]).
//!
//! Not here: anything that reads a row, a request or a clock. The
//! predicates that weigh a patched route against the stored one need
//! `lorica-config`'s types and stay in `lorica-api`; token validation
//! stays in `lorica-config`. No I/O and no dependency beyond `serde`,
//! so this crate adds nothing to the stdio binary's graph.

pub mod protections;
pub mod scope;
pub mod settings;
pub mod tier;

pub use protections::{
    ProtectionRule, BACKEND_PROTECTION_RULES, ROUTE_PROTECTION_RULES, WITHHELD_ROUTE_FIELDS,
};
pub use scope::{AutomationScope, AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS};
pub use settings::{
    admin_setting, AdminSetting, Direction, Reach, TakesEffect, RETENTION_TIER_CEILING_ROWS,
    SETTINGS_ALLOWLIST, SETTINGS_ALLOWLIST_NAMES,
};
pub use tier::{resolve, Tier, TierDefinition, TierError, UnknownTier, TIERS};
