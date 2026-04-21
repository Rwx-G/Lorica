//! Per-hostname-pattern ACL for the certificate export zone (v1.4.1).
//!
//! Default ownership of exported cert files is driven by
//! `GlobalSettings.cert_export_owner_uid` / `cert_export_group_gid`.
//! That is fine when every reader of the zone is the same Unix user,
//! but a homelab / multi-tenant setup often wants "Ansible reads
//! `*.prod.example.com`, but a backup tool reads `*.internal` and
//! an ops user reads `grafana.mibu.fr`" - each with a different
//! group gid so POSIX permissions actually isolate readers.
//!
//! One `CertExportAcl` row = one rule. The writer walks the ACLs
//! in longest-pattern-first order and applies the first match's
//! uid / gid instead of the global default.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One ACL row.
///
/// `hostname_pattern` supports a single optional `*` prefix so the
/// most common case (cover every subdomain of a parent) fits in
/// one rule. Full regex was rejected on purpose: the exporter runs
/// on every cert issue and operator input here becomes filesystem
/// behavior - a regex typo would be much harder to debug than a
/// "does this glob match" check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertExportAcl {
    /// Stable UUID; primary key.
    pub id: String,
    /// Hostname pattern. Exact (`grafana.mibu.fr`), leading wildcard
    /// (`*.prod.example.com`), or `*` for "match every hostname".
    pub hostname_pattern: String,
    /// Optional override for the uid Lorica applies to files
    /// exported for matching certs. `None` = inherit the global
    /// default.
    pub allowed_uid: Option<u32>,
    /// Optional override for the gid. `None` = inherit the global
    /// default.
    pub allowed_gid: Option<u32>,
    /// Insert timestamp.
    pub created_at: DateTime<Utc>,
}

/// Does `pattern` match `hostname`? Rules:
/// * `*` matches every hostname.
/// * A pattern starting with `*.` matches any hostname whose suffix
///   is `pattern[2..]`, but only on a full label boundary. So
///   `*.example.com` matches `grafana.example.com` but NOT
///   `somethingelse.com` or `example.com` itself.
/// * Everything else matches as an exact string (case-insensitive).
pub fn pattern_matches(pattern: &str, hostname: &str) -> bool {
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

/// Return the single ACL with the highest specificity that matches,
/// or `None` if no ACL applies.
pub fn resolve<'a>(acls: &'a [CertExportAcl], hostname: &str) -> Option<&'a CertExportAcl> {
    acls.iter()
        .filter(|a| pattern_matches(&a.hostname_pattern, hostname))
        .max_by_key(|a| specificity(&a.hostname_pattern))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_pattern_matches_hostname() {
        assert!(pattern_matches("grafana.mibu.fr", "grafana.mibu.fr"));
        assert!(pattern_matches("grafana.mibu.fr", "GRAFANA.mibu.FR"));
        assert!(!pattern_matches("grafana.mibu.fr", "other.mibu.fr"));
    }

    #[test]
    fn wildcard_matches_one_label_deep() {
        assert!(pattern_matches("*.mibu.fr", "grafana.mibu.fr"));
        assert!(pattern_matches("*.mibu.fr", "a-b_c.mibu.fr"));
        assert!(!pattern_matches("*.mibu.fr", "mibu.fr")); // no bare parent
        assert!(!pattern_matches("*.mibu.fr", "grafana.example.com"));
    }

    #[test]
    fn wildcard_can_match_deep_subdomain() {
        // `*.mibu.fr` also matches `a.b.mibu.fr` - we do not enforce
        // a strict "one label" rule because X.509 wildcards are
        // typically understood that way in cert subject CN.
        assert!(pattern_matches("*.mibu.fr", "a.b.mibu.fr"));
    }

    #[test]
    fn catchall_matches_every_hostname() {
        assert!(pattern_matches("*", "whatever.com"));
        assert!(pattern_matches("*", "localhost"));
    }

    #[test]
    fn specificity_puts_exact_above_wildcard_above_catchall() {
        assert!(specificity("grafana.mibu.fr") > specificity("*.mibu.fr"));
        assert!(specificity("*.mibu.fr") > specificity("*.fr"));
        assert!(specificity("*.fr") > specificity("*"));
    }

    fn acl(id: &str, pattern: &str, gid: Option<u32>) -> CertExportAcl {
        CertExportAcl {
            id: id.into(),
            hostname_pattern: pattern.into(),
            allowed_uid: None,
            allowed_gid: gid,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn resolve_picks_most_specific_match() {
        let acls = vec![
            acl("1", "*", Some(100)),
            acl("2", "*.mibu.fr", Some(200)),
            acl("3", "grafana.mibu.fr", Some(300)),
        ];
        let got = resolve(&acls, "grafana.mibu.fr").expect("test setup");
        assert_eq!(got.id, "3");
        let got = resolve(&acls, "other.mibu.fr").expect("test setup");
        assert_eq!(got.id, "2");
        let got = resolve(&acls, "example.com").expect("test setup");
        assert_eq!(got.id, "1");
    }

    #[test]
    fn resolve_returns_none_when_no_acl_matches() {
        let acls = vec![acl("1", "only.example.com", Some(100))];
        assert!(resolve(&acls, "other.example.com").is_none());
    }
}
