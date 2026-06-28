// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Process-wide merged AI-crawler registry (Story 8.2 AC #6 / #8).
//!
//! At request-evaluation the proxy must consult both the compiled-in
//! [`BUILTIN_CRAWLERS`](crate::ai_bot::BUILTIN_CRAWLERS) registry AND
//! the operator-defined custom rows stored in the
//! `ai_crawlers_custom` SQLite table. Recompiling the custom regexes
//! per request would be wasteful, so this module owns a single
//! arc-swappable snapshot ([`MergedCrawlersHandle`]) rebuilt once at
//! worker startup and once on every config-reload commit.
//!
//! Merge rules ([`build_merged`]):
//! - The built-in registry seeds the snapshot, each entry converted
//!   to owned types ([`MergedCrawler`]).
//! - Each ENABLED custom row is layered on top. A custom row whose
//!   `name` collides with an existing entry REPLACES it in place
//!   (custom-wins-on-conflict, lets an operator ship a fresh vendor
//!   CIDR list mid-cycle). A new name is appended.
//! - Disabled custom rows are excluded entirely.
//!
//! The build NEVER panics on bad operator data : a custom row whose
//! pattern fails to compile, or whose CIDR list contains an
//! unparseable entry, is skipped with a `tracing::warn!` plus a
//! `lorica_ai_bot_skipped_custom_total{reason}` tick. The built-in
//! registry and every other valid row stay live. This is the AC #8
//! row-level tolerance guarantee : one corrupt row can never blank
//! the live registry on hot-reload.

use std::str::FromStr;
use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwap;
use ipnet::IpNet;
use lorica_config::models::{CustomCrawler, CustomVerification};
use regex::{Regex, RegexBuilder};

use crate::ai_bot::{Verification, BUILTIN_CRAWLERS, VENDOR_IP_RANGES};

/// Owned, request-ready verification mechanism. Mirrors
/// [`crate::ai_bot::Verification`] but holds owned data so built-in
/// and custom entries share one representation in the merged
/// snapshot.
#[derive(Debug, Clone)]
pub enum MergedVerification {
    /// Forward-confirmed reverse-DNS suffix list (with leading dot).
    Rdns(Vec<String>),
    /// Resolved vendor IP-list. Built-in entries inline the bundled
    /// [`VENDOR_IP_RANGES`] set ; custom entries parse their stored
    /// CIDR strings at build time.
    IpRanges(Vec<IpNet>),
    /// User-Agent match alone. No verification possible.
    UaOnly,
}

impl MergedVerification {
    /// Stable string label for Prometheus / dashboard display.
    /// Matches [`crate::ai_bot::Verification::kind_str`].
    pub fn kind_str(&self) -> &'static str {
        match self {
            MergedVerification::Rdns(_) => "rdns",
            MergedVerification::IpRanges(_) => "ip_ranges",
            MergedVerification::UaOnly => "ua_only",
        }
    }
}

/// Single entry in the merged registry. The regex is compiled once
/// at build time and matched read-only on the hot path.
#[derive(Debug, Clone)]
pub struct MergedCrawler {
    /// Stable label used in counters and the injected
    /// `X-Lorica-Verified-Bot` header.
    pub name: String,
    /// Precompiled User-Agent regex.
    pub pattern: Regex,
    /// Per-crawler verification dispatch.
    pub verification: MergedVerification,
}

impl MergedCrawler {
    /// Return the first crawler whose pattern matches `ua`, scanning
    /// `registry` in order (built-in first, custom overrides applied
    /// in place). `None` when no entry matches.
    pub fn match_first<'a>(registry: &'a [MergedCrawler], ua: &str) -> Option<&'a MergedCrawler> {
        registry.iter().find(|crawler| crawler.pattern.is_match(ua))
    }
}

/// Arc-swappable holder for the process-wide merged registry. Reads
/// (`load` / `load_full`) are lock-free ; [`store`](Self::store)
/// publishes a freshly built snapshot atomically on reload.
pub struct MergedCrawlersHandle {
    inner: ArcSwap<Vec<MergedCrawler>>,
}

impl MergedCrawlersHandle {
    fn new(initial: Vec<MergedCrawler>) -> Self {
        MergedCrawlersHandle {
            inner: ArcSwap::from_pointee(initial),
        }
    }

    /// Lock-free read guard over the current snapshot. Cheap, but do
    /// not hold across an `.await` ; use [`load_full`](Self::load_full)
    /// on the request path where the snapshot is kept past an await.
    pub fn load(&self) -> arc_swap::Guard<Arc<Vec<MergedCrawler>>> {
        self.inner.load()
    }

    /// Full `Arc` clone of the current snapshot. `Send`, safe to hold
    /// across `.await` points on the async filter path.
    pub fn load_full(&self) -> Arc<Vec<MergedCrawler>> {
        self.inner.load_full()
    }

    /// Atomically publish a newly built registry. Subsequent reads
    /// observe the new snapshot ; in-flight readers keep the old one.
    pub fn store(&self, registry: Vec<MergedCrawler>) {
        self.inner.store(Arc::new(registry));
    }
}

static HANDLE: OnceLock<MergedCrawlersHandle> = OnceLock::new();

/// Process-wide merged-registry handle. Initialised on first use with
/// the built-in registry only, so a request that arrives before the
/// startup rebuild still evaluates against the built-in crawlers.
pub fn handle() -> &'static MergedCrawlersHandle {
    HANDLE.get_or_init(|| MergedCrawlersHandle::new(build_merged(&[])))
}

fn merged_from_builtin(verification: &Verification) -> MergedVerification {
    match verification {
        Verification::Rdns(suffixes) => {
            MergedVerification::Rdns(suffixes.iter().map(|s| s.to_string()).collect())
        }
        Verification::IpRanges(key) => {
            MergedVerification::IpRanges(VENDOR_IP_RANGES.get(*key).cloned().unwrap_or_default())
        }
        Verification::UaOnly => MergedVerification::UaOnly,
    }
}

/// Resolve a custom row's verification into the owned merged form.
/// `None` means the row must be skipped (an invalid CIDR was found) ;
/// the skip is already logged and counted here.
fn merged_from_custom(row_id: i64, verification: &CustomVerification) -> Option<MergedVerification> {
    match verification {
        CustomVerification::Rdns { suffixes } => Some(MergedVerification::Rdns(suffixes.clone())),
        CustomVerification::UaOnly => Some(MergedVerification::UaOnly),
        CustomVerification::IpRanges { cidrs } => {
            let mut nets: Vec<IpNet> = Vec::with_capacity(cidrs.len());
            for cidr in cidrs {
                match IpNet::from_str(cidr) {
                    Ok(net) => nets.push(net),
                    Err(e) => {
                        lorica_api::metrics::record_ai_bot_skipped_custom("json_parse");
                        tracing::warn!(
                            target: "lorica::ai_bot",
                            row_id,
                            cidr = %cidr,
                            error = %e,
                            "skipping custom crawler with invalid CIDR ; remaining registry intact"
                        );
                        return None;
                    }
                }
            }
            Some(MergedVerification::IpRanges(nets))
        }
    }
}

/// Build the merged registry from the built-in set plus the supplied
/// enabled custom rows. See the module docs for the merge + tolerance
/// rules. Pure (no global state touched) so it is unit-testable in
/// isolation ; [`rebuild_from_store`] wraps it with the store load and
/// the global publish.
pub fn build_merged(custom: &[CustomCrawler]) -> Vec<MergedCrawler> {
    let mut registry: Vec<MergedCrawler> =
        Vec::with_capacity(BUILTIN_CRAWLERS.len() + custom.len());

    for builtin in BUILTIN_CRAWLERS {
        match Regex::new(builtin.user_agent_pattern) {
            Ok(pattern) => registry.push(MergedCrawler {
                name: builtin.name.to_string(),
                pattern,
                verification: merged_from_builtin(&builtin.verification),
            }),
            Err(e) => {
                tracing::error!(
                    target: "lorica::ai_bot",
                    crawler = builtin.name,
                    error = %e,
                    "built-in AI crawler pattern failed to compile ; skipping entry"
                );
            }
        }
    }

    for row in custom {
        if !row.enabled {
            continue;
        }
        let pattern = match RegexBuilder::new(&row.user_agent_pattern)
            .case_insensitive(true)
            .size_limit(1 << 20)
            .dfa_size_limit(1 << 21)
            .build()
        {
            Ok(pattern) => pattern,
            Err(e) => {
                lorica_api::metrics::record_ai_bot_skipped_custom("regex_compile");
                tracing::warn!(
                    target: "lorica::ai_bot",
                    row_id = row.id,
                    error = %e,
                    "skipping malformed custom crawler ; remaining registry intact"
                );
                continue;
            }
        };
        let verification = match merged_from_custom(row.id, &row.verification) {
            Some(verification) => verification,
            None => continue,
        };
        let entry = MergedCrawler {
            name: row.name.clone(),
            pattern,
            verification,
        };
        match registry.iter().position(|c| c.name == entry.name) {
            Some(idx) => registry[idx] = entry,
            None => registry.push(entry),
        }
    }

    registry
}

/// Rebuild the merged registry from the current store state and swap
/// it into the global [`handle`]. Single entry point for both worker
/// startup and every config-reload commit. Uses the lenient loader so
/// an unreadable custom row is dropped (logged + counted) instead of
/// aborting the rebuild.
pub fn rebuild_from_store(store: &lorica_config::ConfigStore) {
    let (good, skipped) = store.list_custom_crawlers_lenient();
    for (row_id, reason) in &skipped {
        lorica_api::metrics::record_ai_bot_skipped_custom("json_parse");
        tracing::warn!(
            target: "lorica::ai_bot",
            row_id = *row_id,
            reason = %reason,
            "skipping unreadable custom crawler row ; remaining registry intact"
        );
    }
    handle().store(build_merged(&good));
}
