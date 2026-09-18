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

//! One definition of what an operator-supplied address entry is, and
//! the pure CIDR policy built on it.
//!
//! Everything that reads an address list in this workspace answers to
//! [`parse_cidr`]: the TCP pre-filter, the capture-rule and
//! automation-token validators, the management API, the automation
//! listener. Three separate answers to "is this a CIDR" used to exist,
//! and the distance between them is how a list could be refused at one
//! door and silently dropped at the next (backlog #88).
//!
//! # One parser, two dispositions
//!
//! Agreeing on what a BAD entry is does not mean agreeing on what to do
//! about one, and the two stances here are deliberate:
//!
//! - A validator ([`validate_cidr`], [`validate_cidr_list`]) REFUSES
//!   the write. It runs at a boundary where an operator is waiting for
//!   an answer, so a typo comes back as an error instead of becoming a
//!   policy nobody asked for.
//! - The runtime ([`ConnectionFilterPolicy::from_cidrs`]) SKIPS the
//!   entry with a warning and keeps the rest. It runs on a
//!   configuration that is already stored, where failing closed on a
//!   typo would refuse every connection to the node: a silent widening
//!   is a bug, a self-inflicted outage is worse. It is defence in depth
//!   behind the validators, not where the rule is enforced.
//!
//! [`ConnectionFilterPolicy`] is the rule, not the runtime. The
//! `ArcSwap`, the per-IP connection counters and the pingora
//! `ConnectionFilter` implementation stay in the binary that owns the
//! accept loop.

use std::net::IpAddr;

use ipnet::IpNet;
use tracing::warn;

/// Parse one address entry into a network.
///
/// Accepts a CIDR (`10.0.0.0/8`, `2001:db8::/32`) and a bare address,
/// which is promoted to its single-host network: `203.0.113.7` means
/// `203.0.113.7/32`. Surrounding whitespace is ignored. An entry that
/// is empty after trimming is not an address and is refused here; the
/// list-level helpers decide whether a blank is worth refusing a whole
/// write over.
///
/// # Errors
///
/// Returns the operator-facing reason, quoting the entry as supplied.
///
/// ```rust
/// use lorica_config::connection_filter::parse_cidr;
///
/// assert!(parse_cidr(" 10.0.0.0/8 ").is_ok());
/// assert!(parse_cidr("203.0.113.7").is_ok());
/// assert!(parse_cidr("10.0.0.0/33").is_err());
/// ```
pub fn parse_cidr(entry: &str) -> std::result::Result<IpNet, String> {
    let trimmed: &str = entry.trim();
    if let Ok(net) = trimmed.parse::<IpNet>() {
        return Ok(net);
    }
    trimmed
        .parse::<IpAddr>()
        .map(IpNet::from)
        .map_err(|_| format!("`{entry}` is not a valid IP or CIDR"))
}

/// Refuse one entry [`parse_cidr`] cannot read, naming the setting it
/// came from.
///
/// # Errors
///
/// Returns the operator-facing reason.
pub fn validate_cidr(entry: &str, field: &str) -> std::result::Result<(), String> {
    // The per-entry reason plus the field, as one sentence: an operator
    // fixes a list, not a parser.
    parse_cidr(entry)
        .map(|_| ())
        .map_err(|_| format!("`{entry}` is not a valid IP or CIDR in {field}"))
}

/// Refuse the first entry of a list [`parse_cidr`] cannot read.
///
/// Entries that are empty after trimming are skipped rather than
/// refused: they come from a textarea that ended on a newline, they
/// carry no policy, and the runtime drops them too. A blank can neither
/// widen nor narrow anything, so refusing a whole settings write over
/// one is friction with no security to show for it.
///
/// # Errors
///
/// Returns the operator-facing reason for the first bad entry.
pub fn validate_cidr_list(entries: &[String], field: &str) -> std::result::Result<(), String> {
    for entry in entries {
        if entry.trim().is_empty() {
            continue;
        }
        validate_cidr(entry, field)?;
    }
    Ok(())
}

/// Parsed CIDR policy: a deny list and an allow list, evaluated by
/// [`accepts`](ConnectionFilterPolicy::accepts).
#[derive(Debug, Default, Clone)]
pub struct ConnectionFilterPolicy {
    /// CIDR ranges always rejected. Evaluated first, so a deny entry
    /// always wins.
    pub deny: Vec<IpNet>,
    /// CIDR ranges allowed when non-empty. When empty, the policy is
    /// default-allow: only `deny` can reject. When non-empty, it is
    /// default-deny: an address is accepted only if it matches at least
    /// one entry here and none in `deny`.
    pub allow: Vec<IpNet>,
}

impl ConnectionFilterPolicy {
    /// Parse two address lists, skipping malformed entries with a
    /// warning.
    ///
    /// Skipping is the runtime disposition the module doc describes. A
    /// stored list only reaches this function after a validator
    /// accepted it, so a skip here means the store predates that
    /// validator; the WARN is what points at it.
    pub fn from_cidrs(allow: &[String], deny: &[String]) -> Self {
        Self {
            allow: parse_skipping(allow, "connection_allow_cidrs"),
            deny: parse_skipping(deny, "connection_deny_cidrs"),
        }
    }

    /// Build a policy from already-parsed networks, for the callers
    /// that refused their bad entries instead of skipping them.
    pub fn from_nets(allow: Vec<IpNet>, deny: Vec<IpNet>) -> Self {
        Self { deny, allow }
    }

    /// Whether the given address is accepted under this policy.
    #[inline]
    pub fn accepts(&self, ip: IpAddr) -> bool {
        if self.deny.iter().any(|net| net.contains(&ip)) {
            return false;
        }
        if self.allow.is_empty() {
            return true;
        }
        self.allow.iter().any(|net| net.contains(&ip))
    }

    /// `true` when the policy decides nothing (both lists empty), so a
    /// caller can skip evaluating it when the feature is unused.
    #[inline]
    pub fn is_noop(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }
}

fn parse_skipping(entries: &[String], field: &str) -> Vec<IpNet> {
    entries
        .iter()
        .filter_map(|entry| match parse_cidr(entry) {
            Ok(net) => Some(net),
            // A blank is whitespace, not a rule somebody lost.
            Err(_) if entry.trim().is_empty() => None,
            Err(reason) => {
                warn!(field, %reason, "ignoring invalid CIDR entry");
                None
            }
        })
        .collect()
}

/// Strings every door in the crate must read the same way. `true`
/// means "a CIDR or an address", `false` means "an entry a validator
/// refuses and the runtime drops".
///
/// Lives outside the test module so the other validators built on this
/// parser (capture rules, automation tokens, global settings) assert
/// against the SAME corpus instead of each keeping a shorter list of
/// strings it happens to think about.
#[cfg(test)]
pub(crate) const CIDR_CORPUS: &[(&str, bool)] = &[
    ("10.0.0.0/8", true),
    ("10.0.0.0/32", true),
    ("0.0.0.0/0", true),
    ("203.0.113.7", true),
    ("  203.0.113.7  ", true),
    ("2001:db8::/32", true),
    ("::1", true),
    ("::/0", true),
    ("10.0.0.1/8", true),
    ("10.0.0.0/33", false),
    ("2001:db8::/129", false),
    ("10.0.0.256", false),
    ("10.0.0.0/", false),
    ("10.0.0.0/-1", false),
    ("10.0.0.0/8/8", false),
    ("bogus", false),
    ("", false),
    ("   ", false),
    ("10.0.0.0 /8", false),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::CIDR_CORPUS as CORPUS;

    #[test]
    fn parser_corpus() {
        for (entry, valid) in CORPUS {
            assert_eq!(
                parse_cidr(entry).is_ok(),
                *valid,
                "parse_cidr disagrees on {entry:?}"
            );
        }
    }

    #[test]
    fn validate_cidr_names_the_field() {
        let err: String = validate_cidr("10.0.0.0/33", "connection_allow_cidrs")
            .expect_err("a /33 is not a v4 network");
        assert!(err.contains("connection_allow_cidrs"), "{err}");
        assert!(err.contains("10.0.0.0/33"), "{err}");
    }

    #[test]
    fn validate_cidr_list_tolerates_blanks_and_refuses_the_rest() {
        let entries: Vec<String> = vec![String::new(), "  ".to_string(), "10.0.0.0/8".to_string()];
        assert!(validate_cidr_list(&entries, "waf_whitelist_ips").is_ok());

        let bad: Vec<String> = vec!["10.0.0.0/8".to_string(), "10.0.0.0/33".to_string()];
        assert!(validate_cidr_list(&bad, "waf_whitelist_ips").is_err());
    }

    #[test]
    fn empty_policy_is_noop() {
        let p = ConnectionFilterPolicy::from_cidrs(&[], &[]);
        assert!(p.is_noop());
        assert!(p.accepts(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn deny_only_default_allow() {
        let p = ConnectionFilterPolicy::from_cidrs(
            &[],
            &["10.0.0.0/8".to_string(), "203.0.113.7".to_string()],
        );
        assert!(p.accepts(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!p.accepts(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!p.accepts(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))));
        assert!(p.accepts(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8))));
    }

    #[test]
    fn allow_nonempty_is_default_deny() {
        let p = ConnectionFilterPolicy::from_cidrs(&["192.168.0.0/16".to_string()], &[]);
        assert!(p.accepts(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!p.accepts(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn deny_wins_over_allow() {
        let p = ConnectionFilterPolicy::from_cidrs(
            &["10.0.0.0/8".to_string()],
            &["10.0.0.5".to_string()],
        );
        assert!(p.accepts(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!p.accepts(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
        assert!(!p.accepts(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn ipv6_cidrs() {
        let p = ConnectionFilterPolicy::from_cidrs(&[], &["2001:db8::/32".to_string()]);
        let inside: IpAddr = IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().expect("literal v6"));
        let outside: IpAddr = IpAddr::V6("2001:db9::1".parse::<Ipv6Addr>().expect("literal v6"));
        assert!(!p.accepts(inside));
        assert!(p.accepts(outside));
    }

    #[test]
    fn bare_ip_is_promoted_to_a_single_host_net() {
        let p = ConnectionFilterPolicy::from_cidrs(&["203.0.113.7".to_string()], &[]);
        assert!(p.accepts(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))));
        assert!(!p.accepts(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8))));
    }

    #[test]
    fn invalid_entries_are_skipped_at_runtime() {
        let p = ConnectionFilterPolicy::from_cidrs(
            &[
                "bogus".to_string(),
                "   ".to_string(),
                "10.0.0.0/8".to_string(),
            ],
            &[],
        );
        assert_eq!(p.allow.len(), 1);
        // The surviving entry still filters: one skipped entry does not
        // turn the list into the empty, default-allow one.
        assert!(!p.accepts(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn runtime_skip_and_validator_refusal_agree_on_what_is_bad() {
        for (entry, valid) in CORPUS {
            let list: Vec<String> = vec![(*entry).to_string()];
            let parsed = ConnectionFilterPolicy::from_cidrs(&list, &[]);
            assert_eq!(
                parsed.allow.len() == 1,
                *valid,
                "the runtime keeps {entry:?} but the parser does not"
            );
            assert_eq!(
                validate_cidr(entry, "field").is_ok(),
                *valid,
                "the validator disagrees on {entry:?}"
            );
        }
    }
}
