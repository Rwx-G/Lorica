//! Hostname pattern matching. This module holds MORE THAN ONE rule on
//! purpose, and every rule lives here so a reader meets its sibling
//! before picking one.
//!
//! * [`matches_any_depth`]: a `*.` wildcard covers its parent suffix at
//!   any depth, so `*.example.com` covers both `a.example.com` and
//!   `a.b.example.com`, and a bare `*` covers everything. Used by the
//!   certificate export ACL ([`super::CertExportAcl`]).
//! * [`matches_one_label`]: TLS wildcard semantics, where `*.` stands
//!   for exactly one label, so `*.example.com` covers `a.example.com`
//!   and nothing deeper, and a bare `*` covers nothing. Used by an
//!   automation token's hostname grant
//!   ([`super::AutomationToken::allows_hostname`]).
//!
//! They differ because the two callers answer different questions. The
//! ACL decides which uid and gid own an exported certificate file; an
//! operator who writes `*.prod.example.com` there is naming a zone of
//! their filesystem, over-matching costs precision, and a miss falls
//! back to the global default, which still works. A token grant decides
//! whether a caller may claim a name at all; over-matching hands out
//! authority nobody wrote down, so the wildcard means what it means in
//! a certificate, one label.
//!
//! [`specificity`] ranks patterns for a caller that must pick one
//! winner among several matches. It reads a pattern's shape only, so it
//! serves either rule.
//!
//! A third matcher, `host_pattern_matches` in
//! `crate::store::cluster_nodes`, is deliberately NOT one of these: it
//! mirrors `ProxyConfig::find_route` byte for byte, case-sensitivity
//! included, and its own doc carries that reason.

/// Does `pattern` match `hostname`, with a wildcard covering any depth?
///
/// Rules:
/// * `*` matches every hostname.
/// * A pattern starting with `*.` matches any hostname whose suffix
///   is `pattern[2..]`, but only on a full label boundary. So
///   `*.example.com` matches `grafana.example.com` but NOT
///   `somethingelse.com` or `example.com` itself.
/// * Everything else matches as an exact string (case-insensitive).
///
/// See [`matches_one_label`] for the stricter sibling that stops at one
/// label; a caller granting authority over a name wants that one.
///
/// ```
/// use lorica_config::models::matches_any_depth;
/// assert!(matches_any_depth("*.example.com", "a.b.example.com"));
/// assert!(!matches_any_depth("*.example.com", "example.com"));
/// ```
pub fn matches_any_depth(pattern: &str, hostname: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let host_lc = hostname.to_ascii_lowercase();
    let pat_lc = pattern.to_ascii_lowercase();
    if let Some(suffix) = pat_lc.strip_prefix("*.") {
        // `host_lc` must end with `.suffix` AND have at least one
        // label before it. `*.example.com` matches `a.example.com`
        // but not `example.com`.
        let needle = format!(".{suffix}");
        return host_lc.ends_with(&needle) && host_lc.len() > needle.len();
    }
    pat_lc == host_lc
}

/// Does `pattern` match `hostname` under TLS wildcard semantics, where
/// `*.` stands for exactly one label?
///
/// Rules:
/// * `*` alone matches nothing. A bare catch-all is not a grant anyone
///   should receive implicitly; a caller that wants one has to say so.
/// * A pattern starting with `*.` matches a hostname whose suffix is
///   `pattern[2..]` preceded by exactly ONE more label. So
///   `*.example.com` matches `a.example.com` and refuses
///   `a.b.example.com`, `example.com` and `.example.com`.
/// * Everything else matches as an exact string (case-insensitive).
///
/// One trailing dot is stripped from both arguments first, because
/// `a.example.com.` and `a.example.com` name the same host and a grant
/// that behaves differently depending on an invisible character is a
/// trap. An empty pattern or an empty hostname matches nothing.
///
/// See [`matches_any_depth`] for the looser sibling the certificate
/// export ACL uses, and the module doc for why both exist.
///
/// ```
/// use lorica_config::models::matches_one_label;
/// assert!(matches_one_label("*.example.com", "a.example.com"));
/// assert!(!matches_one_label("*.example.com", "a.b.example.com"));
/// assert!(!matches_one_label("*", "anything.example.com"));
/// ```
pub fn matches_one_label(pattern: &str, hostname: &str) -> bool {
    let pat_lc = strip_root_label(&pattern.to_ascii_lowercase());
    let host_lc = strip_root_label(&hostname.to_ascii_lowercase());
    if pat_lc.is_empty() || host_lc.is_empty() || pat_lc == "*" {
        return false;
    }
    if let Some(parent) = pat_lc.strip_prefix("*.") {
        if parent.is_empty() {
            return false;
        }
        let needle = format!(".{parent}");
        let Some(label) = host_lc.strip_suffix(&needle) else {
            return false;
        };
        // What the wildcard stands for must be exactly one non-empty
        // label: no `.` inside it, and not the empty string that
        // `.example.com` would leave behind.
        return !label.is_empty() && !label.contains('.');
    }
    pat_lc == host_lc
}

/// Drop the root label a fully qualified name may carry, so
/// `a.example.com.` and `a.example.com` compare equal.
fn strip_root_label(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_string()
}

/// Rank a pattern by specificity so the most specific match wins.
/// Exact match > longer wildcard suffix > shorter wildcard suffix >
/// catch-all (`*`). The numeric output is only meaningful inside
/// `sort_by_key(|acl| -specificity(...))`.
pub fn specificity(pattern: &str) -> u32 {
    if pattern == "*" {
        return 0;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Wildcard: rank by suffix length so `*.prod.mibu.fr` beats
        // `*.mibu.fr`.
        return 10_000 + suffix.len() as u32;
    }
    // Exact: always wins over wildcards, rank by length as tiebreaker.
    100_000 + pattern.len() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- matches_any_depth: the certificate export ACL rule ----

    #[test]
    fn matches_any_depth_accepts_an_exact_hostname_whatever_its_case() {
        assert!(matches_any_depth("grafana.mibu.fr", "grafana.mibu.fr"));
        assert!(matches_any_depth("grafana.mibu.fr", "GRAFANA.mibu.FR"));
        assert!(!matches_any_depth("grafana.mibu.fr", "other.mibu.fr"));
    }

    #[test]
    fn matches_any_depth_accepts_one_label_but_never_the_bare_parent() {
        assert!(matches_any_depth("*.mibu.fr", "grafana.mibu.fr"));
        assert!(matches_any_depth("*.mibu.fr", "a-b_c.mibu.fr"));
        assert!(!matches_any_depth("*.mibu.fr", "mibu.fr")); // no bare parent
        assert!(!matches_any_depth("*.mibu.fr", "grafana.example.com"));
    }

    #[test]
    fn matches_any_depth_accepts_a_deep_subdomain() {
        // `*.mibu.fr` also matches `a.b.mibu.fr` - this rule does not
        // enforce a strict "one label" boundary, which is exactly what
        // separates it from `matches_one_label`.
        assert!(matches_any_depth("*.mibu.fr", "a.b.mibu.fr"));
    }

    #[test]
    fn matches_any_depth_accepts_every_hostname_for_the_catch_all() {
        assert!(matches_any_depth("*", "whatever.com"));
        assert!(matches_any_depth("*", "localhost"));
    }

    // ---- matches_one_label: the TLS wildcard rule ----

    #[test]
    fn matches_one_label_accepts_exactly_one_label_and_refuses_two() {
        assert!(matches_one_label(
            "*.review.example.com",
            "mr-42.review.example.com"
        ));
        assert!(!matches_one_label(
            "*.review.example.com",
            "a.b.review.example.com"
        ));
    }

    #[test]
    fn matches_one_label_refuses_the_bare_parent_domain() {
        assert!(!matches_one_label("*.example.com", "example.com"));
    }

    #[test]
    fn matches_one_label_refuses_a_bare_wildcard() {
        assert!(!matches_one_label("*", "anything.example.com"));
        assert!(!matches_one_label("*", "localhost"));
    }

    #[test]
    fn matches_one_label_refuses_an_empty_label_or_an_empty_name() {
        assert!(!matches_one_label("*.example.com", ".example.com"));
        assert!(!matches_one_label("*.example.com", "a..example.com"));
        assert!(!matches_one_label("*.", "a.example.com"));
        assert!(!matches_one_label("", ""));
        assert!(!matches_one_label("example.com", ""));
        assert!(!matches_one_label("", "example.com"));
    }

    #[test]
    fn matches_one_label_reads_a_trailing_dot_as_the_same_name() {
        assert!(matches_one_label("*.example.com", "a.example.com."));
        assert!(matches_one_label("*.example.com.", "a.example.com"));
        assert!(matches_one_label("api.example.com.", "api.example.com"));
        assert!(!matches_one_label("*.example.com", "a.b.example.com."));
        // Only the root label goes; a name with two trailing dots is
        // malformed and stays refused.
        assert!(!matches_one_label("*.example.com", "a.example.com.."));
    }

    #[test]
    fn both_rules_agree_on_an_exact_hostname() {
        for hostname in ["api.example.com", "API.Example.COM"] {
            assert!(matches_any_depth("api.example.com", hostname));
            assert!(matches_one_label("api.example.com", hostname));
        }
        assert!(!matches_any_depth("api.example.com", "other.example.com"));
        assert!(!matches_one_label("api.example.com", "other.example.com"));
    }

    #[test]
    fn the_two_rules_diverge_on_a_deep_subdomain_and_that_is_the_point() {
        // Same pattern, same hostname, opposite answers. The ACL rule
        // covers a whole zone whatever its depth; the grant rule hands
        // out one label and nothing below it.
        let pattern = "*.example.com";
        let deep = "a.b.example.com";
        assert!(matches_any_depth(pattern, deep));
        assert!(!matches_one_label(pattern, deep));
    }

    // ---- specificity ----

    #[test]
    fn specificity_puts_exact_above_wildcard_above_catchall() {
        assert!(specificity("grafana.mibu.fr") > specificity("*.mibu.fr"));
        assert!(specificity("*.mibu.fr") > specificity("*.fr"));
        assert!(specificity("*.fr") > specificity("*"));
    }
}
