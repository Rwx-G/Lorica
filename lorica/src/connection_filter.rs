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

//! TCP-level connection pre-filter.
//!
//! Evaluated once per TCP accept, before the TLS handshake. Allows the
//! operator to drop connections from known-hostile networks without spending
//! CPU on TLS negotiation, WAF evaluation, or routing.
//!
//! The filter holds its CIDR lists inside an [`ArcSwap`], so hot-reloads
//! triggered by a `GlobalSettings` update take effect on the next accepted
//! connection without rebuilding listeners. This keeps the feature coherent
//! in both single-process and worker modes: each worker holds its own
//! `GlobalConnectionFilter` instance, updated through the same
//! `reload_proxy_config` path the supervisor broadcasts via the command
//! channel.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use ipnet::IpNet;
use lorica_core::listeners::ConnectionFilter;
use tracing::warn;

/// Parsed CIDR policy used by [`GlobalConnectionFilter`].
#[derive(Debug, Default, Clone)]
pub struct ConnectionFilterPolicy {
    /// CIDR ranges always rejected. Evaluated last so a deny entry always wins.
    pub deny: Vec<IpNet>,
    /// CIDR ranges allowed when non-empty. When empty, the filter operates in
    /// default-allow mode: only the `deny` list can reject connections.
    /// When non-empty, the filter operates in default-deny mode: a connection
    /// is accepted only if its IP matches at least one entry here (and does
    /// not match `deny`).
    pub allow: Vec<IpNet>,
}

impl ConnectionFilterPolicy {
    /// Parse two CIDR string lists, skipping malformed entries with a warning.
    /// Bare IPs are promoted to single-host nets (same contract as
    /// `trusted_proxies`/`waf_whitelist_ips`).
    pub fn from_cidrs(allow: &[String], deny: &[String]) -> Self {
        Self {
            allow: parse_cidrs(allow, "connection_allow_cidrs"),
            deny: parse_cidrs(deny, "connection_deny_cidrs"),
        }
    }

    /// Return `true` if the given IP should be accepted under this policy.
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

    /// `true` when the policy is a pure no-op (both lists empty), so the
    /// runtime can skip even calling the filter when the feature is unused.
    #[inline]
    pub fn is_noop(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }
}

fn parse_cidrs(entries: &[String], field_name: &str) -> Vec<IpNet> {
    entries
        .iter()
        .filter_map(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return None;
            }
            if let Ok(net) = trimmed.parse::<IpNet>() {
                Some(net)
            } else if let Ok(ip) = trimmed.parse::<IpAddr>() {
                Some(IpNet::from(ip))
            } else {
                warn!(field = field_name, entry = %trimmed, "ignoring invalid CIDR entry");
                None
            }
        })
        .collect()
}

/// Concrete [`ConnectionFilter`] backed by an [`ArcSwap`] policy.
///
/// Cloning the inner `Arc<GlobalConnectionFilter>` hands out handles that
/// observe every [`reload`](Self::reload); listeners hold one such clone, the
/// reload task holds another, and both see the same atomic snapshot without
/// locks.
#[derive(Debug)]
pub struct GlobalConnectionFilter {
    policy: ArcSwap<ConnectionFilterPolicy>,
}

impl GlobalConnectionFilter {
    /// Build a filter with an initial policy (defaults to allow-all when both
    /// lists are empty).
    pub fn new(policy: ConnectionFilterPolicy) -> Self {
        Self {
            policy: ArcSwap::from_pointee(policy),
        }
    }

    /// Convenience: build an empty (allow-all) filter. Used at startup before
    /// the first `reload_proxy_config` pass seeds real CIDR lists.
    pub fn empty() -> Self {
        Self::new(ConnectionFilterPolicy::default())
    }

    /// Atomically replace the policy. Takes effect on the next accepted TCP
    /// connection; existing connections are not affected.
    pub fn reload(&self, policy: ConnectionFilterPolicy) {
        self.policy.store(Arc::new(policy));
    }

    /// Read a snapshot of the current policy. Useful for tests and metrics.
    pub fn snapshot(&self) -> Arc<ConnectionFilterPolicy> {
        self.policy.load_full()
    }
}

#[async_trait]
impl ConnectionFilter for GlobalConnectionFilter {
    async fn should_accept(&self, addr: Option<&SocketAddr>) -> bool {
        let Some(addr) = addr else {
            return true;
        };
        let policy = self.policy.load();
        if policy.is_noop() {
            return true;
        }
        policy.accepts(addr.ip())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), 0)
    }

    fn v6(ip: Ipv6Addr) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(ip), 0)
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
        let p = ConnectionFilterPolicy::from_cidrs(
            &["192.168.0.0/16".to_string()],
            &[],
        );
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
        let p = ConnectionFilterPolicy::from_cidrs(
            &[],
            &["2001:db8::/32".to_string()],
        );
        assert!(!p.accepts(
            "2001:db8::1".parse().unwrap()
        ));
        assert!(p.accepts("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn invalid_entries_are_skipped() {
        let p = ConnectionFilterPolicy::from_cidrs(
            &[
                "bogus".to_string(),
                "   ".to_string(),
                "10.0.0.0/8".to_string(),
            ],
            &[],
        );
        assert_eq!(p.allow.len(), 1);
    }

    #[tokio::test]
    async fn filter_accepts_missing_addr() {
        let f = GlobalConnectionFilter::new(
            ConnectionFilterPolicy::from_cidrs(&[], &["0.0.0.0/0".to_string()]),
        );
        // Missing peer addr (e.g. Unix socket accept): be permissive since
        // the deny policy cannot be evaluated against an IP.
        assert!(f.should_accept(None).await);
    }

    #[tokio::test]
    async fn filter_hot_reloads() {
        let f = GlobalConnectionFilter::empty();
        let addr = v4(203, 0, 113, 9);
        assert!(f.should_accept(Some(&addr)).await);

        f.reload(ConnectionFilterPolicy::from_cidrs(
            &[],
            &["203.0.113.0/24".to_string()],
        ));
        assert!(!f.should_accept(Some(&addr)).await);

        f.reload(ConnectionFilterPolicy::from_cidrs(&[], &[]));
        assert!(f.should_accept(Some(&addr)).await);
    }

    #[tokio::test]
    async fn filter_ipv6_hot_reload() {
        let f = GlobalConnectionFilter::empty();
        let addr = v6("2001:db8::1".parse().unwrap());
        assert!(f.should_accept(Some(&addr)).await);
        f.reload(ConnectionFilterPolicy::from_cidrs(
            &["::1/128".to_string()],
            &[],
        ));
        assert!(!f.should_accept(Some(&addr)).await);
    }
}
