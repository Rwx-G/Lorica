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
//! The RULE is not here: `ConnectionFilterPolicy` lives in
//! `lorica-config`, next to the settings it reads and the validators
//! that refuse a malformed entry at the boundary (backlog #88). What
//! stays here is the RUNTIME around it: the hot-swappable snapshot,
//! the per-source-IP connection counters, and the pingora trait
//! implementation the accept loop calls.
//!
//! The filter holds its CIDR lists inside an [`ArcSwap`], so hot-reloads
//! triggered by a `GlobalSettings` update take effect on the next accepted
//! connection without rebuilding listeners. This keeps the feature coherent
//! in both single-process and worker modes: each worker holds its own
//! `GlobalConnectionFilter` instance, updated through the same
//! `reload_proxy_config` path the supervisor broadcasts via the command
//! channel.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use dashmap::DashMap;
use lorica_core::listeners::{AcceptPermit, AcceptVerdict, ConnectionFilter};

/// The policy this filter evaluates. Re-exported so the accept-loop
/// wiring names one path for the rule and the runtime it runs in.
pub use lorica_config::connection_filter::ConnectionFilterPolicy;

/// RAII token decrementing one IP's live-connection count when the
/// accepted stream drops (Story 8.9 AC #5). The listener attaches it
/// to the stream, so the decrement happens exactly at connection
/// close.
#[derive(Debug)]
struct PerIpPermit {
    ip: IpAddr,
    counter: Arc<AtomicU32>,
    map: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
}

impl Drop for PerIpPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
        // Best-effort map hygiene: drop the entry once its count is
        // back to zero so an IP scan cannot grow the map unboundedly.
        // The remove_if re-check makes a concurrent increment safe.
        self.map
            .remove_if(&self.ip, |_, counter| counter.load(Ordering::Acquire) == 0);
    }
}

impl AcceptPermit for PerIpPermit {}

/// Concrete [`ConnectionFilter`] backed by an [`ArcSwap`] policy, plus
/// an optional per-source-IP live-connection cap (Story 8.9 AC #5).
///
/// Cloning the inner `Arc<GlobalConnectionFilter>` hands out handles that
/// observe every [`reload`](Self::reload); listeners hold one such clone, the
/// reload task holds another, and both see the same atomic snapshot without
/// locks.
///
/// The per-IP cap is per PROCESS: each worker owns its own filter
/// instance, so the effective ceiling in multi-worker mode is
/// `connection_limits_per_ip x workers`. Documented in the setting's
/// operator docs; a shmem-backed global count is a backlog candidate.
#[derive(Debug)]
pub struct GlobalConnectionFilter {
    policy: ArcSwap<ConnectionFilterPolicy>,
    /// 0 = cap disabled.
    per_ip_limit: AtomicU32,
    per_ip_counts: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
}

impl GlobalConnectionFilter {
    /// Build a filter with an initial policy (defaults to allow-all when both
    /// lists are empty).
    pub fn new(policy: ConnectionFilterPolicy) -> Self {
        Self {
            policy: ArcSwap::from_pointee(policy),
            per_ip_limit: AtomicU32::new(0),
            per_ip_counts: Arc::new(DashMap::new()),
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

    /// Set the per-source-IP live-connection cap (`None` / `Some(0)`
    /// disables it). Takes effect on the next accept; connections
    /// already established keep their permits.
    pub fn set_per_ip_limit(&self, limit: Option<u32>) {
        self.per_ip_limit
            .store(limit.unwrap_or(0), Ordering::Release);
    }

    /// Current per-IP cap (0 = disabled). For tests and diagnostics.
    pub fn per_ip_limit(&self) -> u32 {
        self.per_ip_limit.load(Ordering::Acquire)
    }

    /// Read a snapshot of the current policy. Useful for tests and metrics.
    pub fn snapshot(&self) -> Arc<ConnectionFilterPolicy> {
        self.policy.load_full()
    }

    /// Atomically reserve one connection slot for `ip`. Returns the
    /// RAII permit, or `None` when the IP is at its cap.
    fn try_reserve(&self, ip: IpAddr, limit: u32) -> Option<PerIpPermit> {
        let counter = self
            .per_ip_counts
            .entry(ip)
            .or_insert_with(|| Arc::new(AtomicU32::new(0)))
            .clone();
        // fetch_add-then-check keeps the reserve atomic without a CAS
        // loop: an over-increment is immediately undone before Reject.
        let previous = counter.fetch_add(1, Ordering::AcqRel);
        if previous >= limit {
            counter.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(PerIpPermit {
            ip,
            counter,
            map: Arc::clone(&self.per_ip_counts),
        })
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

    async fn try_accept(&self, addr: Option<&SocketAddr>) -> AcceptVerdict {
        // CIDR policy first (deny wins, no permit needed to refuse).
        if !self.should_accept(addr).await {
            return AcceptVerdict::Reject;
        }
        let limit = self.per_ip_limit.load(Ordering::Acquire);
        if limit == 0 {
            return AcceptVerdict::Accept(None);
        }
        let Some(addr) = addr else {
            // No peer address (unix sockets): the cap cannot apply.
            return AcceptVerdict::Accept(None);
        };
        match self.try_reserve(addr.ip(), limit) {
            Some(permit) => AcceptVerdict::Accept(Some(Box::new(permit))),
            None => {
                lorica_api::metrics::inc_per_ip_connection_refused();
                AcceptVerdict::Reject
            }
        }
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

    // The policy's own behaviour (deny wins, empty allow = default
    // allow, a bare IP is promoted, a malformed entry is skipped) is
    // tested where the policy lives, in
    // `lorica_config::connection_filter`. What follows exercises the
    // runtime this module owns: the hot swap, the per-IP cap, and the
    // pingora accept verdicts.

    #[tokio::test]
    async fn filter_accepts_missing_addr() {
        let f = GlobalConnectionFilter::new(ConnectionFilterPolicy::from_cidrs(
            &[],
            &["0.0.0.0/0".to_string()],
        ));
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

    fn permit_of(verdict: AcceptVerdict) -> Option<Box<dyn AcceptPermit>> {
        match verdict {
            AcceptVerdict::Accept(permit) => permit,
            AcceptVerdict::Reject => panic!("expected Accept"),
        }
    }

    #[tokio::test]
    async fn per_ip_cap_disabled_hands_out_no_permit() {
        let f = GlobalConnectionFilter::empty();
        let addr = v4(203, 0, 113, 9);
        assert!(permit_of(f.try_accept(Some(&addr)).await).is_none());
    }

    #[tokio::test]
    async fn per_ip_cap_refuses_over_limit_and_recovers_on_drop() {
        let f = GlobalConnectionFilter::empty();
        f.set_per_ip_limit(Some(2));
        let addr = v4(203, 0, 113, 9);

        let p1 = permit_of(f.try_accept(Some(&addr)).await).expect("permit 1");
        let p2 = permit_of(f.try_accept(Some(&addr)).await).expect("permit 2");
        assert!(matches!(
            f.try_accept(Some(&addr)).await,
            AcceptVerdict::Reject
        ));

        // A different IP is unaffected by the saturated one.
        let other = v4(203, 0, 113, 10);
        assert!(permit_of(f.try_accept(Some(&other)).await).is_some());

        // Dropping one permit frees one slot for the capped IP.
        drop(p1);
        let p3 = permit_of(f.try_accept(Some(&addr)).await).expect("slot freed by drop");
        drop(p2);
        drop(p3);
    }

    #[tokio::test]
    async fn per_ip_cap_zero_or_none_disables() {
        let f = GlobalConnectionFilter::empty();
        f.set_per_ip_limit(Some(1));
        assert_eq!(f.per_ip_limit(), 1);
        f.set_per_ip_limit(None);
        assert_eq!(f.per_ip_limit(), 0);
        let addr = v4(203, 0, 113, 9);
        assert!(permit_of(f.try_accept(Some(&addr)).await).is_none());
    }

    #[tokio::test]
    async fn per_ip_cap_respects_cidr_deny_first() {
        let f = GlobalConnectionFilter::new(ConnectionFilterPolicy::from_cidrs(
            &[],
            &["203.0.113.0/24".to_string()],
        ));
        f.set_per_ip_limit(Some(10));
        let denied = v4(203, 0, 113, 9);
        assert!(matches!(
            f.try_accept(Some(&denied)).await,
            AcceptVerdict::Reject
        ));
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
