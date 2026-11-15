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

//! TCP-level connection pre-filter, and the PROXY protocol policy of the
//! HTTP listeners.
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
//!
//! The filter also carries the node's [`ProxyProtocolGate`] (Story 12.8):
//! the PROXY protocol settings behind their own `ArcSwap`, reloaded in the
//! same commit, and one [`ProxyProtocolPolicy`] view of them per HTTP
//! listener. On a listener whose mode is not off, the accept path of
//! `lorica-core` reads a header from the peers the gate trusts and then
//! runs this filter on the client address the header carried, so the
//! allow and deny lists and the per-IP cap judge the real client.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use dashmap::DashMap;
use ipnet::IpNet;
use lorica_config::models::ProxyProtocolMode as StoredProxyProtocolMode;
use lorica_core::listeners::{
    AcceptPermit, AcceptVerdict, ConnectionFilter, ProxyHeaderOutcome, ProxyProtocolMode,
    ProxyProtocolPolicy,
};
use tracing::warn;

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
    proxy_protocol: Arc<ProxyProtocolGate>,
}

impl GlobalConnectionFilter {
    /// Build a filter with an initial policy (defaults to allow-all when both
    /// lists are empty). PROXY protocol accept starts off on both listeners.
    pub fn new(policy: ConnectionFilterPolicy) -> Self {
        Self {
            policy: ArcSwap::from_pointee(policy),
            per_ip_limit: AtomicU32::new(0),
            per_ip_counts: Arc::new(DashMap::new()),
            proxy_protocol: Arc::new(ProxyProtocolGate::new()),
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

    /// The PROXY protocol gate of this process's HTTP listeners, reloaded
    /// with the filter. Each listener registers with
    /// [`ProxyProtocolGate::policy`]; Story 12.15 reads
    /// [`ProxyProtocolGate::trusts`].
    pub fn proxy_protocol(&self) -> &Arc<ProxyProtocolGate> {
        &self.proxy_protocol
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

/// One of the two HTTP listeners a PROXY protocol policy serves, and the
/// `listener` label of its counters and refusal lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpListener {
    /// The plaintext HTTP listener.
    Http,
    /// The HTTPS listener.
    Https,
}

impl HttpListener {
    /// The stable label of the listener, for metrics and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            HttpListener::Http => "http",
            HttpListener::Https => "https",
        }
    }
}

/// The three node-local PROXY protocol settings (Story 12.8), as a reload
/// carries them from the store to the [`ProxyProtocolGate`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyProtocolSettings {
    /// `proxy_protocol_http`.
    pub http: StoredProxyProtocolMode,
    /// `proxy_protocol_https`.
    pub https: StoredProxyProtocolMode,
    /// `proxy_protocol_trusted_cidrs`.
    pub trusted_cidrs: Vec<String>,
}

impl ProxyProtocolSettings {
    /// The PROXY protocol part of a stored settings document.
    pub fn from_global(settings: &lorica_config::models::GlobalSettings) -> Self {
        Self {
            http: settings.proxy_protocol_http,
            https: settings.proxy_protocol_https,
            trusted_cidrs: settings.proxy_protocol_trusted_cidrs.clone(),
        }
    }
}

/// The parsed settings one reload installs.
#[derive(Debug, Default)]
struct GatePolicy {
    http: ProxyProtocolMode,
    https: ProxyProtocolMode,
    trusted: Vec<IpNet>,
}

impl GatePolicy {
    fn from_settings(settings: &ProxyProtocolSettings) -> Self {
        Self {
            http: listener_mode(settings.http),
            https: listener_mode(settings.https),
            trusted: parse_trust_list(&settings.trusted_cidrs),
        }
    }

    fn mode(&self, listener: HttpListener) -> ProxyProtocolMode {
        match listener {
            HttpListener::Http => self.http,
            HttpListener::Https => self.https,
        }
    }

    fn trusts_peer(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.trusted.iter().any(|net| net.contains(&ip))
    }
}

fn listener_mode(stored: StoredProxyProtocolMode) -> ProxyProtocolMode {
    match stored {
        StoredProxyProtocolMode::Off => ProxyProtocolMode::Off,
        StoredProxyProtocolMode::Required => ProxyProtocolMode::Required,
        StoredProxyProtocolMode::Optional => ProxyProtocolMode::Optional,
    }
}

/// The trust list as the runtime reads it: a malformed entry is skipped
/// with a warning, as every stored address list is, and so is a `/0`.
/// The validators refuse both at the write boundary; a `/0` reaching
/// here would let any peer name its own client and defeat every address
/// control the node has, so the runtime does not widen to it either.
fn parse_trust_list(entries: &[String]) -> Vec<IpNet> {
    const FIELD: &str = "proxy_protocol_trusted_cidrs";
    entries
        .iter()
        .filter_map(
            |entry| match lorica_config::connection_filter::parse_cidr(entry) {
                Ok(net) if net.prefix_len() == 0 => {
                    warn!(
                        field = FIELD,
                        entry = %entry,
                        "ignoring a trust entry that would trust every address"
                    );
                    None
                }
                Ok(net) => Some(net),
                Err(_) if entry.trim().is_empty() => None,
                Err(reason) => {
                    warn!(field = FIELD, %reason, "ignoring invalid address entry");
                    None
                }
            },
        )
        .collect()
}

/// How long one refusal line per listener and reason holds back the
/// next ones (Story 12.8 D-j).
pub const REFUSAL_LOG_WINDOW: Duration = Duration::from_secs(10);

/// What the refusal log does with one refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalLogDecision {
    /// Write the refusal line, after a line reporting `suppressed`
    /// refusals of the same listener and reason that the window just
    /// closed held back and nobody has reported yet.
    Write {
        /// Refusals held back and not yet reported, 0 for none.
        suppressed: u64,
    },
    /// Hold the line back. `first` is true for the first refusal held back
    /// in this window: its caller arranges the report due at `window_ends`.
    Suppress {
        /// Whether this is the window's first held-back refusal.
        first: bool,
        /// When the window closes.
        window_ends: Instant,
    },
}

#[derive(Debug, Clone, Copy)]
struct RefusalWindow {
    opened: Instant,
    suppressed: u64,
}

/// At most one refusal line per listener and reason per
/// [`REFUSAL_LOG_WINDOW`], then one line counting what the window held
/// back. Refusals from an untrusted peer are attacker-driven, so an
/// unthrottled line per refusal would let anyone write the log at will;
/// the counters still count every refusal.
#[derive(Debug, Default)]
pub struct RefusalLogLimiter {
    windows: parking_lot::Mutex<HashMap<(HttpListener, ProxyHeaderOutcome), RefusalWindow>>,
}

impl RefusalLogLimiter {
    /// Decides on one refusal of `reason` on `listener` at `now`.
    pub fn admit(
        &self,
        listener: HttpListener,
        reason: ProxyHeaderOutcome,
        now: Instant,
    ) -> RefusalLogDecision {
        let mut windows = self.windows.lock();
        let fresh = RefusalWindow {
            opened: now,
            suppressed: 0,
        };
        match windows.get_mut(&(listener, reason)) {
            Some(window) if now < window.opened + REFUSAL_LOG_WINDOW => {
                window.suppressed += 1;
                RefusalLogDecision::Suppress {
                    first: window.suppressed == 1,
                    window_ends: window.opened + REFUSAL_LOG_WINDOW,
                }
            }
            Some(window) => {
                let suppressed = window.suppressed;
                *window = fresh;
                RefusalLogDecision::Write { suppressed }
            }
            None => {
                windows.insert((listener, reason), fresh);
                RefusalLogDecision::Write { suppressed: 0 }
            }
        }
    }

    /// Takes the count the window ending at `window_ends` held back, once:
    /// 0 when it was already taken, or when a later refusal opened a new
    /// window and reported it with its own line.
    pub fn close(
        &self,
        listener: HttpListener,
        reason: ProxyHeaderOutcome,
        window_ends: Instant,
    ) -> u64 {
        let mut windows = self.windows.lock();
        match windows.get_mut(&(listener, reason)) {
            Some(window) if window.opened + REFUSAL_LOG_WINDOW == window_ends => {
                std::mem::take(&mut window.suppressed)
            }
            _ => 0,
        }
    }
}

/// The node's PROXY protocol policy for its HTTP and HTTPS listeners
/// (Story 12.8): the two listener modes and the trust list behind an
/// [`ArcSwap`], reloaded with the connection filter, so a settings change
/// applies to the connections accepted after it without a restart.
#[derive(Debug)]
pub struct ProxyProtocolGate {
    policy: ArcSwap<GatePolicy>,
    refusal_log: RefusalLogLimiter,
}

impl Default for ProxyProtocolGate {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyProtocolGate {
    /// A gate with both listeners off and nobody trusted.
    pub fn new() -> Self {
        Self {
            policy: ArcSwap::from_pointee(GatePolicy::default()),
            refusal_log: RefusalLogLimiter::default(),
        }
    }

    /// Installs `settings`. Connections already accepted keep the policy
    /// they were accepted under.
    pub fn reload(&self, settings: &ProxyProtocolSettings) {
        self.policy
            .store(Arc::new(GatePolicy::from_settings(settings)));
    }

    /// The live mode of `listener`.
    pub fn mode(&self, listener: HttpListener) -> ProxyProtocolMode {
        self.policy.load().mode(listener)
    }

    /// Whether `listener` reads a PROXY header from the socket peer
    /// `addr`: its mode is not off and `addr` is in the trust list. An
    /// IPv4-mapped IPv6 address is matched as the IPv4 address it maps.
    pub fn trusts(&self, listener: HttpListener, addr: &SocketAddr) -> bool {
        let policy = self.policy.load();
        policy.mode(listener) != ProxyProtocolMode::Off && policy.trusts_peer(addr.ip())
    }

    /// The policy `listener`'s endpoint is registered with.
    pub fn policy(self: &Arc<Self>, listener: HttpListener) -> Arc<dyn ProxyProtocolPolicy> {
        Arc::new(ListenerPolicy {
            gate: Arc::clone(self),
            listener,
        })
    }

    /// Counts one outcome, and writes a refusal's line unless the
    /// refusal log holds it back.
    fn record(
        self: &Arc<Self>,
        listener: HttpListener,
        outcome: ProxyHeaderOutcome,
        peer: Option<&SocketAddr>,
        detail: Option<&'static str>,
    ) {
        if outcome.is_accepted() {
            lorica_api::metrics::inc_proxy_protocol_accepted(listener.as_str(), outcome.as_str());
            return;
        }
        lorica_api::metrics::inc_proxy_protocol_refused(listener.as_str(), outcome.as_str());
        match self.refusal_log.admit(listener, outcome, Instant::now()) {
            RefusalLogDecision::Write { suppressed } => {
                if suppressed > 0 {
                    log_suppressed(listener, outcome, suppressed);
                }
                warn!(
                    listener = listener.as_str(),
                    reason = outcome.as_str(),
                    peer = ?peer,
                    detail = detail.unwrap_or(""),
                    "PROXY protocol: connection refused"
                );
            }
            RefusalLogDecision::Suppress {
                first: true,
                window_ends,
            } => self.report_suppressed_at(listener, outcome, window_ends),
            RefusalLogDecision::Suppress { first: false, .. } => {}
        }
    }

    /// Writes the held-back count when the window closes. Without a
    /// runtime to wait on (a unit test), the next refusal after the window
    /// reports it instead.
    fn report_suppressed_at(
        self: &Arc<Self>,
        listener: HttpListener,
        outcome: ProxyHeaderOutcome,
        window_ends: Instant,
    ) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let gate = Arc::clone(self);
        runtime.spawn(async move {
            tokio::time::sleep_until(tokio::time::Instant::from_std(window_ends)).await;
            let suppressed = gate.refusal_log.close(listener, outcome, window_ends);
            if suppressed > 0 {
                log_suppressed(listener, outcome, suppressed);
            }
        });
    }
}

fn log_suppressed(listener: HttpListener, outcome: ProxyHeaderOutcome, suppressed: u64) {
    warn!(
        listener = listener.as_str(),
        reason = outcome.as_str(),
        suppressed,
        window_s = REFUSAL_LOG_WINDOW.as_secs(),
        "PROXY protocol: refusals suppressed"
    );
}

/// One listener's view of the gate, the [`ProxyProtocolPolicy`] its
/// endpoint asks on every accept.
#[derive(Debug)]
struct ListenerPolicy {
    gate: Arc<ProxyProtocolGate>,
    listener: HttpListener,
}

impl ProxyProtocolPolicy for ListenerPolicy {
    fn mode(&self) -> ProxyProtocolMode {
        self.gate.mode(self.listener)
    }

    fn is_trusted(&self, peer: &SocketAddr) -> bool {
        self.gate.trusts(self.listener, peer)
    }

    fn record(
        &self,
        outcome: ProxyHeaderOutcome,
        peer: Option<&SocketAddr>,
        detail: Option<&'static str>,
    ) {
        self.gate.record(self.listener, outcome, peer, detail);
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

    // ---- Story 12.8: the PROXY protocol gate ----

    fn settings(
        http: StoredProxyProtocolMode,
        https: StoredProxyProtocolMode,
        trusted: &[&str],
    ) -> ProxyProtocolSettings {
        ProxyProtocolSettings {
            http,
            https,
            trusted_cidrs: trusted.iter().map(|e| (*e).to_string()).collect(),
        }
    }

    #[test]
    fn the_gate_starts_off_and_follows_every_reload_through_views_taken_before_it() {
        // Live apply: the endpoints register their view once, at
        // startup, and each reload is what they read on the next accept.
        let filter = GlobalConnectionFilter::empty();
        let gate = Arc::clone(filter.proxy_protocol());
        let http = gate.policy(HttpListener::Http);
        let https = gate.policy(HttpListener::Https);
        let balancer = v4(192, 0, 2, 10);
        assert_eq!(http.mode(), ProxyProtocolMode::Off);
        assert_eq!(https.mode(), ProxyProtocolMode::Off);
        assert!(!gate.trusts(HttpListener::Http, &balancer));

        filter.proxy_protocol().reload(&settings(
            StoredProxyProtocolMode::Off,
            StoredProxyProtocolMode::Required,
            &["192.0.2.0/24"],
        ));
        assert_eq!(http.mode(), ProxyProtocolMode::Off);
        assert_eq!(https.mode(), ProxyProtocolMode::Required);
        // A listener that is off trusts nobody, whatever the list holds.
        assert!(!gate.trusts(HttpListener::Http, &balancer));
        assert!(!http.is_trusted(&balancer));
        assert!(gate.trusts(HttpListener::Https, &balancer));
        assert!(https.is_trusted(&balancer));
        assert!(!https.is_trusted(&v4(198, 51, 100, 1)));
        // An IPv4-mapped IPv6 peer is matched as the address it maps.
        let mapped = v6("::ffff:192.0.2.10".parse().unwrap());
        assert!(https.is_trusted(&mapped));

        filter.proxy_protocol().reload(&settings(
            StoredProxyProtocolMode::Optional,
            StoredProxyProtocolMode::Off,
            &["127.0.0.1/32", "::1/128"],
        ));
        assert_eq!(http.mode(), ProxyProtocolMode::Optional);
        assert_eq!(https.mode(), ProxyProtocolMode::Off);
        assert!(http.is_trusted(&v4(127, 0, 0, 1)));
        assert!(http.is_trusted(&v6(Ipv6Addr::LOCALHOST)));
        assert!(!http.is_trusted(&balancer));

        filter
            .proxy_protocol()
            .reload(&ProxyProtocolSettings::default());
        assert_eq!(http.mode(), ProxyProtocolMode::Off);
        assert!(!gate.trusts(HttpListener::Http, &v4(127, 0, 0, 1)));
    }

    #[test]
    fn the_runtime_skips_a_slash_zero_and_a_malformed_trust_entry() {
        // The validators refuse both; a stored list that predates them
        // must not widen the trust to every address.
        let gate = Arc::new(ProxyProtocolGate::new());
        gate.reload(&settings(
            StoredProxyProtocolMode::Required,
            StoredProxyProtocolMode::Required,
            &["0.0.0.0/0", "::/0", "bogus", " ", "192.0.2.10"],
        ));
        assert!(!gate.trusts(HttpListener::Http, &v4(203, 0, 113, 9)));
        assert!(!gate.trusts(HttpListener::Http, &v6("2001:db8::1".parse().unwrap())));
        assert!(gate.trusts(HttpListener::Http, &v4(192, 0, 2, 10)));
        assert!(!gate.trusts(HttpListener::Http, &v4(192, 0, 2, 11)));
    }

    #[test]
    fn the_settings_are_read_from_the_stored_document() {
        let mut stored = lorica_config::models::GlobalSettings::default();
        assert_eq!(
            ProxyProtocolSettings::from_global(&stored),
            ProxyProtocolSettings::default()
        );
        stored.proxy_protocol_https = StoredProxyProtocolMode::Optional;
        stored.proxy_protocol_trusted_cidrs = vec!["10.0.0.0/24".to_string()];
        assert_eq!(
            ProxyProtocolSettings::from_global(&stored),
            settings(
                StoredProxyProtocolMode::Off,
                StoredProxyProtocolMode::Optional,
                &["10.0.0.0/24"]
            )
        );
    }

    #[test]
    fn the_refusal_log_writes_one_line_per_window_and_reports_what_it_held_back_once() {
        let log = RefusalLogLimiter::default();
        let (http, https) = (HttpListener::Http, HttpListener::Https);
        let untrusted = ProxyHeaderOutcome::UntrustedPeer;
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let first_window_ends = t0 + REFUSAL_LOG_WINDOW;

        assert_eq!(
            log.admit(http, untrusted, t0),
            RefusalLogDecision::Write { suppressed: 0 }
        );
        assert_eq!(
            log.admit(http, untrusted, at(1)),
            RefusalLogDecision::Suppress {
                first: true,
                window_ends: first_window_ends
            }
        );
        assert_eq!(
            log.admit(http, untrusted, at(2)),
            RefusalLogDecision::Suppress {
                first: false,
                window_ends: first_window_ends
            }
        );
        // Each listener and each reason has its own window.
        assert_eq!(
            log.admit(https, untrusted, at(2)),
            RefusalLogDecision::Write { suppressed: 0 }
        );
        assert_eq!(
            log.admit(http, ProxyHeaderOutcome::Timeout, at(2)),
            RefusalLogDecision::Write { suppressed: 0 }
        );

        // The window's end reports its two held-back refusals, once.
        assert_eq!(log.close(http, untrusted, first_window_ends), 2);
        assert_eq!(log.close(http, untrusted, first_window_ends), 0);
        // Already reported: the next window opens with nothing owed.
        assert_eq!(
            log.admit(http, untrusted, first_window_ends),
            RefusalLogDecision::Write { suppressed: 0 }
        );

        // A refusal after the window, before its report ran, carries the
        // count itself, and the late report then finds nothing to say.
        let second_window_ends = first_window_ends + REFUSAL_LOG_WINDOW;
        assert!(matches!(
            log.admit(http, untrusted, first_window_ends + Duration::from_secs(1)),
            RefusalLogDecision::Suppress { first: true, .. }
        ));
        assert_eq!(
            log.admit(http, untrusted, second_window_ends + Duration::from_secs(1)),
            RefusalLogDecision::Write { suppressed: 1 }
        );
        assert_eq!(log.close(http, untrusted, second_window_ends), 0);
    }

    #[test]
    fn every_outcome_lands_on_one_counter_under_its_listener_and_its_own_label() {
        // D-j: accepted outcomes count as `kind`, refused ones as
        // `reason`, each under the listener that saw it. Walked over the
        // enum, so a new outcome is counted somewhere or this fails. The
        // counters are process-wide and other tests may record too, so
        // each step checks the one series it moved.
        let gate = Arc::new(ProxyProtocolGate::new());
        for listener in [HttpListener::Http, HttpListener::Https] {
            let view = gate.policy(listener);
            let other = match listener {
                HttpListener::Http => HttpListener::Https,
                HttpListener::Https => HttpListener::Http,
            };
            for outcome in ProxyHeaderOutcome::all() {
                let label = outcome.as_str();
                let read = |l: HttpListener| {
                    (
                        lorica_api::metrics::proxy_protocol_accepted_value(l.as_str(), label),
                        lorica_api::metrics::proxy_protocol_refused_value(l.as_str(), label),
                    )
                };
                let (accepted, refused) = read(listener);
                let elsewhere = read(other);
                view.record(
                    outcome,
                    Some(&v4(192, 0, 2, 10)),
                    (!outcome.is_accepted()).then_some("test"),
                );
                let (accepted_after, refused_after) = read(listener);
                if outcome.is_accepted() {
                    assert!(accepted_after > accepted, "{label} not counted as accepted");
                    assert_eq!(refused_after, refused, "{label} counted as refused");
                } else {
                    assert!(refused_after > refused, "{label} not counted as refused");
                    assert_eq!(accepted_after, accepted, "{label} counted as accepted");
                }
                assert_eq!(
                    read(other),
                    elsewhere,
                    "{label} counted on the other listener"
                );
            }
        }
    }
}
