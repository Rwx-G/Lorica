// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! AI / LLM crawler deny-list registry and verification dispatch.
//!
//! Story 8.2 module. Curated registry of AI training crawlers
//! (GPTBot, ClaudeBot, CCBot, Bytespider, ...) with three
//! per-crawler verification kinds:
//!
//! - [`Verification::Rdns`] - forward-confirmed reverse-DNS via the
//!   existing `bot_rdns` resolver. Hardest to spoof. Available for
//!   the 2 vendors that publish a stable PTR suffix
//!   (CCBot / Common Crawl, Applebot).
//! - [`Verification::IpRanges`] - CIDR-membership lookup against a
//!   compile-time bundled vendor JSON file. Fast, no async work.
//!   Available for OpenAI, Anthropic, Perplexity, Amazon, Meta.
//! - [`Verification::UaOnly`] - User-Agent string match alone,
//!   trivially spoofable. Surfaces hits via the `ua_only_match`
//!   counter for operator visibility. Available for Bytespider,
//!   Diffbot, and the Google-Extended robots.txt-only token.
//!
//! Vendor IP-list JSONs ship at `lorica/src/ai_bot/vendor_ips/`,
//! one file per vendor key, each paired with a `.sha256` sidecar
//! and a `.source` provenance file. Integrity is verified at
//! startup inside the [`VENDOR_IP_RANGES`] `Lazy` initializer ;
//! mismatch or parse failure degrades that vendor's range set to
//! an empty `Vec`, which falls through the spoofed-fallback flow
//! - the worker never panics on a stale or tampered bundle.
//!
//! UA-pattern starting points come from the community-curated
//! `ai-robots-txt/ai.robots.txt` registry (snapshot 2026-05-03).
//! Patterns are word-boundary-anchored (`\b...\b`) and
//! case-insensitive (`(?i)`) to avoid substring false-positives
//! while tolerating UA-string casing drift.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use once_cell::sync::Lazy;
use regex::Regex;
use sha2::{Digest, Sha256};
use tracing::error;

/// Per-crawler verification mechanism. Stored as `&'static` data
/// so the registry is fully `const`-friendly and zero-allocation
/// at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    /// Forward-confirmed reverse-DNS via `bot_rdns`. Suffix list
    /// is checked against the PTR's confirmed name (with leading
    /// dot, e.g. `.crawl.commoncrawl.org`).
    Rdns(&'static [&'static str]),
    /// Vendor-published IP-list bundled at compile time. The
    /// `&'static str` is a key into [`VENDOR_IP_RANGES`].
    IpRanges(&'static str),
    /// User-Agent match alone. No verification possible. Surfaces
    /// via the `ua_only_match` counter for operator visibility.
    UaOnly,
}

impl Verification {
    /// Stable string label for Prometheus / dashboard display.
    pub fn kind_str(&self) -> &'static str {
        match self {
            Verification::Rdns(_) => "rdns",
            Verification::IpRanges(_) => "ip_ranges",
            Verification::UaOnly => "ua_only",
        }
    }
}

/// Single curated AI crawler entry. Pattern is a regex string
/// compiled once at startup into [`COMPILED_PATTERNS`] ; never
/// recompiled per-request.
#[derive(Debug, Clone, Copy)]
pub struct AiCrawler {
    /// Stable label used in counters, dashboard widgets, and the
    /// `/api/v1/ai-crawlers/test` endpoint. MUST be unique.
    pub name: &'static str,
    /// Regex source. Word-boundary-anchored, case-insensitive.
    pub user_agent_pattern: &'static str,
    /// Per-crawler verification dispatch.
    pub verification: Verification,
}

/// Built-in registry. Sourced from the `ai-robots-txt/ai.robots.txt`
/// community list (snapshot 2026-05-03), verified per-vendor against
/// the vendor's own crawler doc page (cf. Story 8.2 Dev Notes
/// "Vendor verification matrix" section).
///
/// Order matters : [`match_user_agent`] iterates top-down and
/// returns the first match, so vendors with overlapping UA
/// patterns (e.g. ClaudeBot + Claude-User + Claude-SearchBot)
/// are listed in the order operators expect to see counter
/// increments under.
pub static BUILTIN_CRAWLERS: &[AiCrawler] = &[
    AiCrawler {
        name: "GPTBot",
        user_agent_pattern: r"(?i)\bGPTBot\b",
        verification: Verification::IpRanges("openai_gptbot"),
    },
    AiCrawler {
        name: "ChatGPT-User",
        user_agent_pattern: r"(?i)\bChatGPT-User\b",
        verification: Verification::IpRanges("openai_chatgpt-user"),
    },
    AiCrawler {
        name: "OAI-SearchBot",
        user_agent_pattern: r"(?i)\bOAI-SearchBot\b",
        verification: Verification::IpRanges("openai_oai-searchbot"),
    },
    AiCrawler {
        name: "ClaudeBot",
        user_agent_pattern: r"(?i)\bClaudeBot\b",
        verification: Verification::IpRanges("anthropic"),
    },
    AiCrawler {
        name: "Claude-User",
        user_agent_pattern: r"(?i)\bClaude-User\b",
        verification: Verification::IpRanges("anthropic"),
    },
    AiCrawler {
        name: "Claude-SearchBot",
        user_agent_pattern: r"(?i)\bClaude-SearchBot\b",
        verification: Verification::IpRanges("anthropic"),
    },
    AiCrawler {
        name: "anthropic-ai",
        user_agent_pattern: r"(?i)\banthropic-ai\b",
        verification: Verification::IpRanges("anthropic"),
    },
    AiCrawler {
        name: "CCBot",
        user_agent_pattern: r"(?i)\bCCBot/\d",
        verification: Verification::Rdns(&[".crawl.commoncrawl.org"]),
    },
    AiCrawler {
        name: "PerplexityBot",
        user_agent_pattern: r"(?i)\bPerplexityBot/\d",
        verification: Verification::IpRanges("perplexity_perplexitybot"),
    },
    AiCrawler {
        name: "Perplexity-User",
        user_agent_pattern: r"(?i)\bPerplexity-User/\d",
        verification: Verification::IpRanges("perplexity_perplexity-user"),
    },
    AiCrawler {
        name: "Bytespider",
        user_agent_pattern: r"(?i)\bBytespider\b",
        verification: Verification::UaOnly,
    },
    AiCrawler {
        name: "Google-Extended",
        user_agent_pattern: r"(?i)\bGoogle-Extended\b",
        verification: Verification::UaOnly,
    },
    AiCrawler {
        name: "Applebot",
        user_agent_pattern: r"(?i)\bApplebot(?:-Extended)?\b",
        verification: Verification::Rdns(&[".applebot.apple.com"]),
    },
    AiCrawler {
        name: "Amazonbot",
        user_agent_pattern: r"(?i)\b(?:Amazonbot|Amzn-SearchBot|Amzn-User)\b",
        verification: Verification::IpRanges("amazon"),
    },
    AiCrawler {
        name: "FacebookBot",
        user_agent_pattern: r"(?i)\b(?:FacebookBot|facebookexternalhit|meta-externalagent)\b",
        verification: Verification::IpRanges("meta_as32934"),
    },
    AiCrawler {
        name: "Diffbot",
        user_agent_pattern: r"(?i)\bDiffbot\b",
        verification: Verification::UaOnly,
    },
];

/// Baseline browser / utility / search-bot User-Agent corpus used
/// by the AC #6 server-side baseline-UA smoke test. Single source
/// of truth lives in
/// [`lorica_config::ai_crawler_registry::BASELINE_UAS`] so the live
/// proxy filter and the `lorica-api` validation endpoint share one
/// canonical copy ; re-exported here for the in-crate round-trip
/// test and any registry-only caller.
pub use lorica_config::ai_crawler_registry::BASELINE_UAS;

/// Lazy-compiled regexes paired with the matching [`AiCrawler`].
/// Compiled exactly once at first access, never per-request. Hot
/// path is a precompiled-regex sweep, microsecond-class for the
/// typical 16-entry registry.
pub static COMPILED_PATTERNS: Lazy<Vec<(Regex, &'static AiCrawler)>> = Lazy::new(|| {
    BUILTIN_CRAWLERS
        .iter()
        .filter_map(|crawler| match Regex::new(crawler.user_agent_pattern) {
            Ok(re) => Some((re, crawler)),
            Err(e) => {
                error!(
                    target: "lorica::ai_bot",
                    crawler = crawler.name,
                    pattern = crawler.user_agent_pattern,
                    error = %e,
                    "built-in AI crawler pattern failed to compile ; skipping entry"
                );
                None
            }
        })
        .collect()
});

/// Vendor-published IP-list ranges, keyed by vendor identifier
/// matching the `Verification::IpRanges(key)` value of the
/// corresponding [`BUILTIN_CRAWLERS`] entry. Loaded from
/// compile-time-bundled JSON at first access, with SHA-256
/// integrity verification against the sibling `.sha256` sidecar
/// and graceful empty-vec fallback on integrity / parse failure.
///
/// Bundled vendor data lives at `lorica/src/ai_bot/vendor_ips/`,
/// one `<vendor_key>.json` per entry. Refresh cadence : alongside
/// each Lorica patch release. Operators wanting mid-cycle refresh
/// override via Custom Crawler CRUD (Story 8.2 AC #6).
pub static VENDOR_IP_RANGES: Lazy<HashMap<&'static str, Vec<IpNet>>> = Lazy::new(|| {
    let mut m: HashMap<&'static str, Vec<IpNet>> = HashMap::new();
    let entries: [(&'static str, Vec<IpNet>); 8] = [
        load_vendor_json(
            "openai_gptbot",
            include_bytes!("ai_bot/vendor_ips/openai_gptbot.json"),
            include_str!("ai_bot/vendor_ips/openai_gptbot.json.sha256"),
        ),
        load_vendor_json(
            "openai_chatgpt-user",
            include_bytes!("ai_bot/vendor_ips/openai_chatgpt-user.json"),
            include_str!("ai_bot/vendor_ips/openai_chatgpt-user.json.sha256"),
        ),
        load_vendor_json(
            "openai_oai-searchbot",
            include_bytes!("ai_bot/vendor_ips/openai_oai-searchbot.json"),
            include_str!("ai_bot/vendor_ips/openai_oai-searchbot.json.sha256"),
        ),
        load_vendor_json(
            "anthropic",
            include_bytes!("ai_bot/vendor_ips/anthropic.json"),
            include_str!("ai_bot/vendor_ips/anthropic.json.sha256"),
        ),
        load_vendor_json(
            "perplexity_perplexitybot",
            include_bytes!("ai_bot/vendor_ips/perplexity_perplexitybot.json"),
            include_str!("ai_bot/vendor_ips/perplexity_perplexitybot.json.sha256"),
        ),
        load_vendor_json(
            "perplexity_perplexity-user",
            include_bytes!("ai_bot/vendor_ips/perplexity_perplexity-user.json"),
            include_str!("ai_bot/vendor_ips/perplexity_perplexity-user.json.sha256"),
        ),
        load_vendor_json(
            "amazon",
            include_bytes!("ai_bot/vendor_ips/amazon.json"),
            include_str!("ai_bot/vendor_ips/amazon.json.sha256"),
        ),
        load_vendor_json(
            "meta_as32934",
            include_bytes!("ai_bot/vendor_ips/meta_as32934.json"),
            include_str!("ai_bot/vendor_ips/meta_as32934.json.sha256"),
        ),
    ];
    for (key, ranges) in entries {
        m.insert(key, ranges);
    }
    m
});

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut hex = String::with_capacity(64);
    for byte in digest.iter() {
        // write! to String never fails ; sha2's digest is always
        // 32 bytes so the loop bound is fixed.
        let _ = write!(hex, "{:02x}", byte);
    }
    hex
}

/// Single-vendor loader used by the [`VENDOR_IP_RANGES`]
/// initializer. Verifies SHA-256 against the sidecar pin, parses
/// the JSON as a flat `Vec<String>` of CIDR strings, and walks
/// each into an [`IpNet`].
///
/// On any failure (sidecar mismatch, JSON parse error, CIDR
/// parse error), logs a structured `tracing::error!` and returns
/// `(key, Vec::new())` so the worker never panics on stale or
/// tampered bundled data. The empty range set falls through the
/// existing `Verification::IpRanges` flow naturally : no IP
/// matches, the spoofed-fallback path applies.
fn load_vendor_json(
    key: &'static str,
    json_bytes: &'static [u8],
    expected_sha: &'static str,
) -> (&'static str, Vec<IpNet>) {
    let actual = sha256_hex(json_bytes);
    let expected = expected_sha.trim();
    if actual != expected {
        error!(
            target: "lorica::ai_bot",
            vendor = key,
            expected = expected,
            got = %actual,
            "vendor IP-list integrity FAIL ; degrading to empty range set"
        );
        return (key, Vec::new());
    }
    let list: Vec<String> = match serde_json::from_slice(json_bytes) {
        Ok(v) => v,
        Err(e) => {
            error!(
                target: "lorica::ai_bot",
                vendor = key,
                error = %e,
                "vendor IP-list JSON parse FAIL ; degrading to empty range set"
            );
            return (key, Vec::new());
        }
    };
    let parsed: Result<Vec<IpNet>, _> = list.iter().map(|s| IpNet::from_str(s)).collect();
    match parsed {
        Ok(nets) => (key, nets),
        Err(e) => {
            error!(
                target: "lorica::ai_bot",
                vendor = key,
                error = %e,
                "vendor IP-list CIDR parse FAIL ; degrading to empty range set"
            );
            (key, Vec::new())
        }
    }
}

/// Match a User-Agent string against the built-in registry.
/// Returns the first matching [`AiCrawler`] in
/// [`BUILTIN_CRAWLERS`] order, or `None` if no built-in pattern
/// matches.
///
/// Pure read of the lazy-compiled patterns ; no allocation, no
/// regex recompilation. Hot-path safe.
///
/// For the merged registry (built-in + custom), use the
/// [`MergedCrawlersHandle`](crate::proxy_wiring::ai_bot_merged::MergedCrawlersHandle)
/// flow plumbed through the worker's reload commit ; this helper
/// covers the built-in-only path (used by tests and by the
/// registry-only stats endpoint).
pub fn match_user_agent(ua: &str) -> Option<&'static AiCrawler> {
    COMPILED_PATTERNS
        .iter()
        .find(|(re, _)| re.is_match(ua))
        .map(|(_, crawler)| *crawler)
}

/// Membership test for the bundled vendor IP-list. `vendor_key`
/// MUST match a `Verification::IpRanges(key)` value of the
/// crawler entry being evaluated. Returns `false` when the
/// vendor key is missing from the bundle (treated as "no match
/// possible" - falls through to the spoofed-fallback flow).
///
/// Implementation : linear scan of `Vec<IpNet>` calling
/// `IpNet::contains`. Acceptable up to ~500 ranges per vendor at
/// the cost of a few microseconds per matched-UA request. The
/// caller MUST pass the post-trust-boundary peer IP (e.g.
/// `RequestCtx.client_ip`) ; reading the raw `X-Forwarded-For`
/// header here would let a malicious client claim to be in any
/// vendor's CIDR by spoofing the XFF.
pub fn ip_in_vendor_ranges(ip: IpAddr, vendor_key: &str) -> bool {
    match VENDOR_IP_RANGES.get(vendor_key) {
        Some(ranges) => ranges.iter().any(|net| net.contains(&ip)),
        None => false,
    }
}

/// Build the body of an auto-served `/robots.txt` (Story 8.2
/// AC #10). Output conforms to RFC 9309 : LF line endings, no
/// trailing whitespace, one `User-agent: <name>\nDisallow: /\n\n`
/// block per active crawler in `active_crawlers`. When the slice
/// is empty, falls back to the generic `User-agent: *\nAllow: /\n`
/// signal (no crawlers active = nothing to opt out of).
///
/// The header carries the Lorica package version + the registry
/// pin so operators can tell from a `curl` exactly which Lorica
/// release generated the body and which `ai-robots-txt` snapshot
/// it tracks.
pub fn build_robots_txt(active_crawlers: &[&AiCrawler]) -> String {
    let names: Vec<&str> = active_crawlers.iter().map(|c| c.name).collect();
    build_robots_txt_from_names(&names)
}

/// Names-only variant of [`build_robots_txt`] used by the merged
/// registry path (built-in + custom crawlers, Story 8.2 AC #8). The
/// merged registry stores owned crawler names rather than
/// `&'static AiCrawler`, so the `/robots.txt` stage hands this helper
/// a flat slice of active crawler names. Output is byte-for-byte the
/// same shape as [`build_robots_txt`].
///
/// Delegates to the shared
/// [`lorica_config::ai_crawler_registry::build_robots_txt_from_names`]
/// builder, passing this crate's package version so the header carries
/// the product release. `lorica-api`'s `robots-preview` endpoint calls
/// the same shared builder, so both bodies stay byte-for-byte identical.
pub fn build_robots_txt_from_names(active_names: &[&str]) -> String {
    lorica_config::ai_crawler_registry::build_robots_txt_from_names(
        active_names,
        env!("CARGO_PKG_VERSION"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_at_least_twelve_entries() {
        // AC #1 "ships with at minimum 12 entries".
        assert!(
            BUILTIN_CRAWLERS.len() >= 12,
            "registry too small: {}",
            BUILTIN_CRAWLERS.len()
        );
    }

    #[test]
    fn registry_names_unique() {
        // Same name twice would corrupt counter labels and merge
        // logic in MergedCrawlersHandle (custom-wins-on-conflict).
        let mut names: Vec<&str> = BUILTIN_CRAWLERS.iter().map(|c| c.name).collect();
        names.sort_unstable();
        let unique_count = names.iter().collect::<std::collections::HashSet<_>>().len();
        assert_eq!(unique_count, names.len(), "duplicate crawler names: {names:?}");
    }

    #[test]
    fn every_pattern_compiles() {
        for crawler in BUILTIN_CRAWLERS {
            Regex::new(crawler.user_agent_pattern)
                .unwrap_or_else(|e| panic!("{}: pattern {:?} -> {e}", crawler.name, crawler.user_agent_pattern));
        }
    }

    #[test]
    fn gptbot_matches_real_world_ua() {
        let ua = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.0; +https://openai.com/gptbot";
        let m = match_user_agent(ua).expect("GPTBot should match");
        assert_eq!(m.name, "GPTBot");
    }

    #[test]
    fn ccbot_matches_with_version_suffix() {
        let m = match_user_agent("CCBot/2.0 (https://commoncrawl.org/faq/)").expect("CCBot should match");
        assert_eq!(m.name, "CCBot");
        assert!(matches!(m.verification, Verification::Rdns(_)));
    }

    #[test]
    fn applebot_extended_alias_matches() {
        // Same regex covers both Applebot and Applebot-Extended.
        let m1 = match_user_agent("Mozilla/5.0 (Applebot/0.1; +http://www.apple.com/go/applebot)").expect("Applebot should match");
        let m2 = match_user_agent("Mozilla/5.0 (compatible; Applebot-Extended; +http://www.apple.com/go/applebot)").expect("Applebot-Extended should match");
        assert_eq!(m1.name, "Applebot");
        assert_eq!(m2.name, "Applebot");
    }

    #[test]
    fn case_insensitive_match() {
        // Lowercased UA still matches.
        let m = match_user_agent("mozilla/5.0 gptbot/1.0").expect("lowercase gptbot should match");
        assert_eq!(m.name, "GPTBot");
    }

    #[test]
    fn baseline_browser_uas_dont_match_any_crawler() {
        // Every BASELINE_UAS entry MUST be rejected by every
        // built-in pattern - otherwise the AC #6 baseline-UA
        // smoke test would reject legitimate Custom Crawlers
        // sourced from these patterns. NOTE: the
        // facebookexternalhit baseline is intentionally omitted
        // from this round-trip - the FacebookBot built-in DOES
        // match facebookexternalhit by design (it IS a Meta bot,
        // just not strictly an AI training one) ; AC #9 docs
        // discusses this nuance.
        for &ua in BASELINE_UAS {
            if ua.contains("facebookexternalhit") {
                continue;
            }
            let hit = match_user_agent(ua);
            assert!(
                hit.is_none(),
                "baseline UA {ua:?} false-positive matched crawler {hit:?}"
            );
        }
    }

    #[test]
    fn substring_with_word_boundary_rejects_glued() {
        // "MyGPTBotProxy" has no boundary before/after GPTBot
        // because of the surrounding letters - \b should reject.
        assert!(match_user_agent("MyGPTBotProxy/1.0").is_none());
        // "GPTBotic" same story.
        assert!(match_user_agent("Mozilla/5.0 (compatible; GPTBotic/1.0)").is_none());
    }

    #[test]
    fn vendor_ip_ranges_loaded_for_all_keys() {
        // Cold-start integrity gate : every IpRanges crawler
        // MUST resolve to a non-empty range set after VENDOR_IP_RANGES
        // initialization. An empty Vec at this point means a
        // SHA-256 mismatch or a malformed bundled JSON, both of
        // which are degraded-not-crashed but should be flagged
        // by tests.
        for crawler in BUILTIN_CRAWLERS {
            if let Verification::IpRanges(key) = crawler.verification {
                let ranges = VENDOR_IP_RANGES
                    .get(key)
                    .unwrap_or_else(|| panic!("vendor key {key} missing from VENDOR_IP_RANGES"));
                assert!(
                    !ranges.is_empty(),
                    "vendor key {key} resolved to empty Vec - SHA-256 mismatch or parse error?"
                );
            }
        }
    }

    #[test]
    fn ip_in_vendor_ranges_happy_path() {
        // Pick a known-good GPTBot IP from the bundled file.
        let in_range: IpAddr = "132.196.86.5".parse().unwrap();
        assert!(ip_in_vendor_ranges(in_range, "openai_gptbot"));
        // 8.8.8.8 is Google DNS, not OpenAI.
        let out_of_range: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!ip_in_vendor_ranges(out_of_range, "openai_gptbot"));
    }

    #[test]
    fn ip_in_vendor_ranges_unknown_vendor_returns_false() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(!ip_in_vendor_ranges(ip, "this_vendor_does_not_exist"));
    }

    #[test]
    fn anthropic_ip_range_matches_supernet() {
        // 216.73.216.0/22 is the wide Anthropic range. Pick a
        // sample inside it.
        let ip: IpAddr = "216.73.217.42".parse().unwrap();
        assert!(ip_in_vendor_ranges(ip, "anthropic"));
    }

    #[test]
    fn meta_ip_range_matches_supernet() {
        // 31.13.64.0/18 covers Facebook's main block.
        let ip: IpAddr = "31.13.65.1".parse().unwrap();
        assert!(ip_in_vendor_ranges(ip, "meta_as32934"));
    }

    #[test]
    fn build_robots_txt_empty_returns_allow_all() {
        let body = build_robots_txt(&[]);
        assert!(body.contains("User-agent: *"));
        assert!(body.contains("Allow: /"));
        assert!(body.starts_with("# Generated by Lorica v"));
    }

    #[test]
    fn build_robots_txt_three_crawlers_emits_three_blocks() {
        let active: Vec<&AiCrawler> = BUILTIN_CRAWLERS.iter().take(3).collect();
        let body = build_robots_txt(&active);
        let disallow_count = body.matches("Disallow: /").count();
        assert_eq!(disallow_count, 3);
        for crawler in &active {
            let block = format!("User-agent: {}", crawler.name);
            assert!(body.contains(&block), "missing block for {}", crawler.name);
        }
    }

    #[test]
    fn build_robots_txt_ends_with_single_newline() {
        let active: Vec<&AiCrawler> = BUILTIN_CRAWLERS.iter().take(1).collect();
        let body = build_robots_txt(&active);
        assert!(body.ends_with('\n'));
        assert!(!body.ends_with("\n\n"), "trailing blank line not RFC 9309");
    }

    #[test]
    fn verification_kind_str() {
        assert_eq!(Verification::Rdns(&[".x.com"]).kind_str(), "rdns");
        assert_eq!(Verification::IpRanges("openai_gptbot").kind_str(), "ip_ranges");
        assert_eq!(Verification::UaOnly.kind_str(), "ua_only");
    }

    #[test]
    fn baseline_uas_count_meets_ac6_floor() {
        // AC #6 task : "20 baseline browser UAs". Floor enforced
        // here so a future commit cannot silently shrink the
        // smoke-test corpus. The corpus was later expanded past 20
        // to defeat version-wildcard evasions ; the authoritative
        // expanded-size lock lives in lorica-config's
        // `ai_crawler_registry` tests.
        assert!(BASELINE_UAS.len() >= 20, "BASELINE_UAS too small: {}", BASELINE_UAS.len());
    }

    #[test]
    fn builtin_registry_matches_shared_descriptors() {
        // Drift tripwire (Story 8.2 medium finding). The flat,
        // cross-crate `BUILTIN_CRAWLER_DESCRIPTORS` in lorica-config
        // is the single source of truth the dashboard /builtin and
        // /test endpoints read ; this richer `BUILTIN_CRAWLERS`
        // registry drives the live proxy filter. They MUST agree
        // entry-for-entry on (name, user_agent_pattern,
        // verification_kind), in the same order, or the endpoints
        // disagree with the filter. A content edit to EITHER table
        // (pattern tweak, kind change, reorder) that desyncs the two
        // fails here - the count-only check it replaces could not
        // catch that.
        use lorica_config::ai_crawler_registry::BUILTIN_CRAWLER_DESCRIPTORS;

        assert_eq!(
            BUILTIN_CRAWLERS.len(),
            BUILTIN_CRAWLER_DESCRIPTORS.len(),
            "registry length drift: {} crawlers vs {} descriptors",
            BUILTIN_CRAWLERS.len(),
            BUILTIN_CRAWLER_DESCRIPTORS.len()
        );
        for (crawler, descriptor) in BUILTIN_CRAWLERS.iter().zip(BUILTIN_CRAWLER_DESCRIPTORS.iter())
        {
            assert_eq!(
                crawler.name, descriptor.name,
                "name drift / order drift: {:?} vs {:?}",
                crawler.name, descriptor.name
            );
            assert_eq!(
                crawler.user_agent_pattern, descriptor.user_agent_pattern,
                "pattern drift for {}: {:?} vs {:?}",
                crawler.name, crawler.user_agent_pattern, descriptor.user_agent_pattern
            );
            assert_eq!(
                crawler.verification.kind_str(),
                descriptor.verification_kind,
                "verification kind drift for {}: {} vs {}",
                crawler.name,
                crawler.verification.kind_str(),
                descriptor.verification_kind
            );
        }
    }
}
