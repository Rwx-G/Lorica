// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Operator-defined AI / LLM crawler entry stored in the
//! `ai_crawlers_custom` SQLite table. Story 8.2 AC #6.
//!
//! Built-in crawlers ship hardcoded in `lorica/src/ai_bot.rs` ;
//! this struct is the operator-overridable / supplemental layer
//! merged at request-evaluation time. Custom-wins-on-conflict
//! semantics let operators ship a fresh CIDR list mid-cycle when
//! a vendor's published JSON changes between Lorica patch releases.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Per-vendor verification mechanism for a custom crawler.
///
/// Mirrors the runtime `lorica::ai_bot::Verification` enum but
/// uses owned types so the row can round-trip through SQLite +
/// JSON. Stored as :
/// - `verification_kind = 'rdns'`, `verification_data =
///   '{"suffixes": [".x.com", ...]}'`
/// - `verification_kind = 'ip_ranges'`, `verification_data =
///   '{"cidrs": ["1.2.3.0/24", ...]}'`
/// - `verification_kind = 'ua_only'`, `verification_data = NULL`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CustomVerification {
    /// Forward-confirmed reverse-DNS suffix list. At least one
    /// entry. Each suffix must start with a leading dot
    /// (validated at the API boundary).
    Rdns {
        /// Suffix list ; each entry like `.crawl.commoncrawl.org`.
        suffixes: Vec<String>,
    },
    /// Vendor-published IP-list. Each CIDR validated via
    /// `ipnet::IpNet::from_str` at the API boundary. Length-
    /// capped at 64 (AC #6 server-side DoS defense).
    IpRanges {
        /// CIDR list ; each entry like `203.0.113.0/24`. Capped
        /// at [`CUSTOM_CRAWLER_MAX_CIDRS`] entries.
        cidrs: Vec<String>,
    },
    /// User-Agent string match alone. Trivially spoofable ;
    /// surfaces via the `ua_only_match` Prometheus label for
    /// operator visibility.
    UaOnly,
}

/// Operator-defined AI crawler entry. Merged with the built-in
/// registry at request-evaluation time.
///
/// On conflict by `name` the custom entry wins (lets operators
/// override a stale built-in vendor IP list with a fresh CIDR
/// list mid-cycle, before the next Lorica patch release).
// `CustomVerification` above cannot take `deny_unknown_fields`:
// serde does not support it on internally-tagged enums (the tag
// buffering deserializer ignores unknown keys by design). The struct
// fields around it are still strict.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomCrawler {
    /// Auto-incremented row id (DB-assigned).
    pub id: i64,
    /// Stable label used in Prometheus counters, dashboard
    /// widgets, and the `/api/v1/ai-crawlers/test` endpoint.
    /// MUST be unique. Same name as a built-in -> custom wins.
    pub name: String,
    /// Regex source. Compiled with `RegexBuilder` size + dfa
    /// caps at the API boundary, validated against
    /// `BASELINE_UAS` to reject patterns that match legitimate
    /// browser UAs (closes the admin-`(?i).*` privilege
    /// escalation path - AC #6 baseline-UA smoke test).
    pub user_agent_pattern: String,
    /// Verification mechanism (see [`CustomVerification`]).
    pub verification: CustomVerification,
    /// Disabled rows are skipped at merge time but stay in the
    /// table for dashboard editing.
    pub enabled: bool,
    /// First-insert timestamp (DB-assigned).
    pub created_at: DateTime<Utc>,
    /// Last-write timestamp (refreshed on every update).
    pub updated_at: DateTime<Utc>,
}

/// Hard cap on `IpRanges::cidrs` length (AC #6 server-side DoS
/// defense). Matches the realistic vendor maximum (Anthropic ~30,
/// OpenAI ~10, Meta AS32934 ~50). Operators wanting more split
/// across multiple custom crawlers.
pub const CUSTOM_CRAWLER_MAX_CIDRS: usize = 64;

/// Hard cap on the `ai_crawlers_custom` table row count (AC #6
/// cardinality + RPC-payload defense). Bounds Prometheus
/// cardinality (256 + 12 builtin = 268 crawler labels) and the
/// `PreparedReload` RPC payload size.
pub const CUSTOM_CRAWLER_MAX_COUNT: usize = 256;
