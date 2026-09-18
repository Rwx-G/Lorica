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

use super::hostname_pattern::{matches_any_depth, specificity};

/// One ACL row.
///
/// `hostname_pattern` supports a single optional `*` prefix so the
/// most common case (cover every subdomain of a parent) fits in
/// one rule. Full regex was rejected on purpose: the exporter runs
/// on every cert issue and operator input here becomes filesystem
/// behavior - a regex typo would be much harder to debug than a
/// "does this glob match" check.
///
/// The matcher is [`super::matches_any_depth`], the looser of the two
/// hostname rules the crate carries: here a wildcard covers its parent
/// at any depth. Its sibling [`super::matches_one_label`] stops at one
/// label, and their module doc says why both exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Return the single ACL with the highest specificity that matches,
/// or `None` if no ACL applies.
pub fn resolve<'a>(acls: &'a [CertExportAcl], hostname: &str) -> Option<&'a CertExportAcl> {
    acls.iter()
        .filter(|a| matches_any_depth(&a.hostname_pattern, hostname))
        .max_by_key(|a| specificity(&a.hostname_pattern))
}

#[cfg(test)]
mod tests {
    use super::*;

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
