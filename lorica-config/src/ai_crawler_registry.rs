// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Single source of truth for the AI / LLM crawler built-in registry
//! data shared across crates (Story 8.2).
//!
//! The binary crate `lorica` and the API crate `lorica-api` both need
//! the same built-in crawler descriptors and the same baseline-UA
//! corpus, but `lorica` depends on `lorica-api` (not the reverse), so
//! neither can import the other's tables. Both depend on
//! `lorica-config`, so the canonical data lives here and each crate
//! reads it:
//!
//! - [`BUILTIN_CRAWLER_DESCRIPTORS`] - the 16 built-in crawler
//!   descriptors (name + UA pattern + verification kind + vendor),
//!   consumed by the `lorica-api` read endpoints (`/builtin`, `/test`,
//!   `/robots-preview`) and pinned against the richer
//!   `lorica::ai_bot::BUILTIN_CRAWLERS` registry by a parity test.
//! - [`BASELINE_UAS`] - the baseline browser / utility / search-bot
//!   User-Agent corpus used by the AC #6 baseline-UA smoke test and by
//!   the false-positive round-trip test.
//! - [`build_robots_txt_from_names`] - the RFC 9309 `/robots.txt` body
//!   builder shared by the live proxy filter and the preview endpoint.

use std::fmt::Write as _;

/// One built-in AI-crawler descriptor. The canonical, verification-rich
/// registry (`lorica::ai_bot::BUILTIN_CRAWLERS`) binds each entry to a
/// `Verification` variant carrying vendor IP-range keys and rDNS suffix
/// slices ; that data stays in the binary crate because it references
/// compile-time-bundled vendor JSON. This descriptor is the flat,
/// cross-crate-shareable projection of the same entry: the
/// verification mechanism is reduced to its stable string label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltinCrawlerDescriptor {
    /// Stable crawler label. Matches the registry `name` ; MUST be
    /// unique across the table.
    pub name: &'static str,
    /// Word-boundary-anchored, case-insensitive regex source.
    pub user_agent_pattern: &'static str,
    /// Verification kind label: one of `rdns`, `ip_ranges`, `ua_only`.
    pub verification_kind: &'static str,
    /// Short human-facing vendor label.
    pub source: &'static str,
}

/// Built-in AI-crawler descriptor table (snapshot 2026-05-03). Order
/// matches `lorica::ai_bot::BUILTIN_CRAWLERS` entry-for-entry ; a
/// parity test in that crate fails if name, pattern, or verification
/// kind drift between the two tables.
pub static BUILTIN_CRAWLER_DESCRIPTORS: &[BuiltinCrawlerDescriptor] = &[
    BuiltinCrawlerDescriptor {
        name: "GPTBot",
        user_agent_pattern: r"(?i)\bGPTBot\b",
        verification_kind: "ip_ranges",
        source: "OpenAI",
    },
    BuiltinCrawlerDescriptor {
        name: "ChatGPT-User",
        user_agent_pattern: r"(?i)\bChatGPT-User\b",
        verification_kind: "ip_ranges",
        source: "OpenAI",
    },
    BuiltinCrawlerDescriptor {
        name: "OAI-SearchBot",
        user_agent_pattern: r"(?i)\bOAI-SearchBot\b",
        verification_kind: "ip_ranges",
        source: "OpenAI",
    },
    BuiltinCrawlerDescriptor {
        name: "ClaudeBot",
        user_agent_pattern: r"(?i)\bClaudeBot\b",
        verification_kind: "ip_ranges",
        source: "Anthropic",
    },
    BuiltinCrawlerDescriptor {
        name: "Claude-User",
        user_agent_pattern: r"(?i)\bClaude-User\b",
        verification_kind: "ip_ranges",
        source: "Anthropic",
    },
    BuiltinCrawlerDescriptor {
        name: "Claude-SearchBot",
        user_agent_pattern: r"(?i)\bClaude-SearchBot\b",
        verification_kind: "ip_ranges",
        source: "Anthropic",
    },
    BuiltinCrawlerDescriptor {
        name: "anthropic-ai",
        user_agent_pattern: r"(?i)\banthropic-ai\b",
        verification_kind: "ip_ranges",
        source: "Anthropic",
    },
    BuiltinCrawlerDescriptor {
        name: "CCBot",
        user_agent_pattern: r"(?i)\bCCBot/\d",
        verification_kind: "rdns",
        source: "Common Crawl",
    },
    BuiltinCrawlerDescriptor {
        name: "PerplexityBot",
        user_agent_pattern: r"(?i)\bPerplexityBot/\d",
        verification_kind: "ip_ranges",
        source: "Perplexity",
    },
    BuiltinCrawlerDescriptor {
        name: "Perplexity-User",
        user_agent_pattern: r"(?i)\bPerplexity-User/\d",
        verification_kind: "ip_ranges",
        source: "Perplexity",
    },
    BuiltinCrawlerDescriptor {
        name: "Bytespider",
        user_agent_pattern: r"(?i)\bBytespider\b",
        verification_kind: "ua_only",
        source: "ByteDance",
    },
    BuiltinCrawlerDescriptor {
        name: "Google-Extended",
        user_agent_pattern: r"(?i)\bGoogle-Extended\b",
        verification_kind: "ua_only",
        source: "Google",
    },
    BuiltinCrawlerDescriptor {
        name: "Applebot",
        user_agent_pattern: r"(?i)\bApplebot(?:-Extended)?\b",
        verification_kind: "rdns",
        source: "Apple",
    },
    BuiltinCrawlerDescriptor {
        name: "Amazonbot",
        user_agent_pattern: r"(?i)\b(?:Amazonbot|Amzn-SearchBot|Amzn-User)\b",
        verification_kind: "ip_ranges",
        source: "Amazon",
    },
    BuiltinCrawlerDescriptor {
        name: "FacebookBot",
        user_agent_pattern: r"(?i)\b(?:FacebookBot|facebookexternalhit|meta-externalagent)\b",
        verification_kind: "ip_ranges",
        source: "Meta",
    },
    BuiltinCrawlerDescriptor {
        name: "Diffbot",
        user_agent_pattern: r"(?i)\bDiffbot\b",
        verification_kind: "ua_only",
        source: "Diffbot",
    },
];

/// Baseline browser / utility / search-bot User-Agent corpus used by
/// the AC #6 server-side baseline-UA smoke test: when an admin posts a
/// custom AI-crawler regex, the server compiles it and runs
/// `Regex::is_match` against each entry here. If any baseline UA
/// matches, the POST is rejected with HTTP 400. This is a best-effort
/// heuristic against the most common over-broad patterns (e.g. an
/// admin registering `(?i).*` or a bare `Mozilla`) ; it is NOT a
/// complete guarantee that a custom regex never matches a legitimate
/// browser.
///
/// The corpus pins several real browsers at multiple major versions
/// AND keeps version-diverse entries (Chrome 120 through 142, Firefox
/// 120 and 131, Edge 120 and 138) so a version-wildcarded evasion such
/// as `(?i)Chrome/1[3-9]\d` is caught rather than slipping past a
/// corpus frozen at a single major. Vendor-forked Chromium browsers
/// that expose a distinct token (Vivaldi, Samsung Internet, Yandex
/// Browser, Brave) are included too.
pub static BASELINE_UAS: &[&str] = &[
    // Chrome desktop / mobile
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    // Firefox desktop / mobile
    "Mozilla/5.0 (Windows NT 10.0; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Android 13; Mobile; rv:120.0) Gecko/120.0 Firefox/120.0",
    // Safari desktop / iOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    // Edge / Opera
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    // CLI tools (operators sometimes run health checks)
    "curl/8.4.0",
    "Wget/1.21.4",
    "PostmanRuntime/7.36.0",
    // Search-index bots (intentionally NOT AI-training; blocking
    // these by accident is a real operator risk - see
    // docs/ai-crawlers.md "False-positive policy")
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Mozilla/5.0 (compatible; DuckDuckBot/1.1; +http://duckduckgo.com/duckduckbot.html)",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    "Mozilla/5.0 (compatible; Twitterbot/1.0)",
    "Mozilla/5.0 (compatible; LinkedInBot/1.0; +http://www.linkedin.com)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
    // Higher / version-wildcard-defeating browser majors: a pattern
    // like (?i)Chrome/1[3-9]\d that misses the Chrome/120 corpus is
    // caught by these.
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; rv:131.0) Gecko/20100101 Firefox/131.0",
    // Chromium forks that expose a distinct vendor token.
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Vivaldi/7.0.3495.27",
    "Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/130.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 YaBrowser/24.10.0.0 Safari/537.36",
    // Brave ships a Chromium UA with no distinct token by design ;
    // included as a current-major Chrome baseline.
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
];

/// Build the body of an auto-served `/robots.txt` (Story 8.2 AC #10).
///
/// Output conforms to RFC 9309: LF line endings, no trailing
/// whitespace, one `User-agent: <name>\nDisallow: /\n\n` block per
/// name in `active_names`. When the slice is empty, falls back to the
/// generic `User-agent: *\nAllow: /\n` signal (no crawlers active =
/// nothing to opt out of).
///
/// `version` is the calling crate's package version
/// (`env!("CARGO_PKG_VERSION")`), written into the header comment so a
/// `curl` reveals exactly which Lorica release generated the body. It
/// is passed in rather than read here so the body carries the product
/// version, not this config crate's version.
///
/// ```
/// use lorica_config::ai_crawler_registry::build_robots_txt_from_names;
/// let body = build_robots_txt_from_names(&["GPTBot"], "1.0.0");
/// assert!(body.contains("# Generated by Lorica v1.0.0"));
/// assert!(body.contains("User-agent: GPTBot"));
/// assert!(body.ends_with('\n') && !body.ends_with("\n\n"));
/// ```
pub fn build_robots_txt_from_names(active_names: &[&str], version: &str) -> String {
    let mut out: String = String::with_capacity(64 + active_names.len() * 48);
    let _ = writeln!(out, "# Generated by Lorica v{version}");
    let _ = writeln!(
        out,
        "# Source: ai-robots-txt/ai.robots.txt @ snapshot 2026-05-03"
    );
    out.push('\n');
    if active_names.is_empty() {
        out.push_str("User-agent: *\nAllow: /\n");
        return out;
    }
    for name in active_names {
        let _ = writeln!(out, "User-agent: {name}");
        out.push_str("Disallow: /\n\n");
    }
    // Strip the trailing blank line so the body ends on a single
    // `\n` per RFC 9309 trailing-whitespace guidance.
    while out.ends_with("\n\n") {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_table_has_sixteen_unique_named_entries() {
        assert_eq!(BUILTIN_CRAWLER_DESCRIPTORS.len(), 16);
        let mut names: Vec<&str> = BUILTIN_CRAWLER_DESCRIPTORS.iter().map(|d| d.name).collect();
        names.sort_unstable();
        let unique: std::collections::HashSet<&&str> = names.iter().collect();
        assert_eq!(unique.len(), names.len(), "duplicate names: {names:?}");
    }

    #[test]
    fn descriptor_kinds_are_valid_labels() {
        for d in BUILTIN_CRAWLER_DESCRIPTORS {
            assert!(
                matches!(d.verification_kind, "rdns" | "ip_ranges" | "ua_only"),
                "{} has invalid kind {}",
                d.name,
                d.verification_kind
            );
        }
    }

    #[test]
    fn baseline_uas_count_meets_expanded_floor() {
        // AC #6 floor is 20 ; the corpus was expanded past that to
        // defeat version-wildcarded evasions. Lock the expanded size
        // so a future commit cannot silently shrink it back. The
        // pattern-vs-baseline false-positive round-trip lives in the
        // consuming crates (lorica::ai_bot, lorica-api) which have a
        // regex dependency.
        assert!(
            BASELINE_UAS.len() >= 29,
            "BASELINE_UAS shrank below the expanded corpus: {}",
            BASELINE_UAS.len()
        );
    }

    #[test]
    fn robots_body_empty_is_allow_all() {
        let body: String = build_robots_txt_from_names(&[], "9.9.9");
        assert!(body.contains("# Generated by Lorica v9.9.9"));
        assert!(body.contains("User-agent: *"));
        assert!(body.contains("Allow: /"));
        assert!(body.ends_with('\n'));
        assert!(!body.ends_with("\n\n"));
    }

    #[test]
    fn robots_body_one_block_per_name() {
        let body: String = build_robots_txt_from_names(&["GPTBot", "CCBot", "Applebot"], "1.2.3");
        assert_eq!(body.matches("Disallow: /").count(), 3);
        assert!(body.contains("User-agent: GPTBot"));
        assert!(body.ends_with('\n'));
        assert!(!body.ends_with("\n\n"));
    }
}
