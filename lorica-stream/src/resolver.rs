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

//! The per-process cache of backend host names (Story 12.3 D-n), shared
//! by the TCP and UDP engines (Story 12.5 Interface edit E3), and the
//! node's interface addresses the local check reads (D-m).
//!
//! - A name is resolved through the [`Resolve`] seam and re-resolved at
//!   its record TTL clamped to [`DNS_MIN_INTERVAL`, `DNS_MAX_INTERVAL`].
//! - A failed or empty resolution keeps the last good list and retries
//!   at the floor; the first failure after a success and the first
//!   success after failures each log one warn line per backend naming
//!   the host, and every failure counts `dns_failures` per backend: the
//!   health event of AC #13. No notification is raised (Resolved 3).
//! - A name never resolved has no address. One used before the schedule
//!   reached it is resolved on demand, within the connect timeout of the
//!   attempt that needs it.
//! - Names leave the cache when no stream of the table uses them. IP
//!   literals are never resolved.
//! - The interface addresses are read at construction and every
//!   [`INTERFACE_REFRESH_INTERVAL`] by the same schedule.
//!
//! The schedule runs as one task on the runtime that first calls
//! [`ResolverCache::track`]: the stream runtime's thread, which nothing
//! here blocks. Resolutions run one at a time, each bounded by
//! [`DNS_RESOLVE_TIMEOUT`].

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use lorica_config::models::backend_address_host;
use tokio::sync::Notify;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::counters::StreamCounters;
use crate::seams::{Resolve, ResolveError, Resolved};
use crate::table::StreamTable;

/// The shortest interval between two resolutions of a name, also the
/// retry interval after a failure: a TTL of 0 does not hammer the
/// resolver.
pub const DNS_MIN_INTERVAL: Duration = Duration::from_secs(5);

/// The longest interval between two resolutions of a name: it bounds
/// how stale an address is after a failover.
pub const DNS_MAX_INTERVAL: Duration = Duration::from_secs(60);

/// How long a scheduled resolution may take before it counts as a
/// failure.
pub const DNS_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the node's interface addresses are read again.
pub const INTERFACE_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// When a name resolved with `ttl` is resolved again: the TTL clamped to
/// [`DNS_MIN_INTERVAL`, `DNS_MAX_INTERVAL`].
pub fn refresh_interval(ttl: Duration) -> Duration {
    ttl.clamp(DNS_MIN_INTERVAL, DNS_MAX_INTERVAL)
}

/// A backend naming a host, for the warn line and the counters.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BackendLabel {
    id: String,
    name: String,
}

#[derive(Debug)]
struct HostEntry {
    addresses: Option<Arc<[IpAddr]>>,
    due: Instant,
    failing: bool,
    backends: Vec<BackendLabel>,
}

impl HostEntry {
    fn new(now: Instant) -> Self {
        HostEntry {
            addresses: None,
            due: now,
            failing: false,
            backends: Vec::new(),
        }
    }
}

/// The host-name cache and interface set of one process.
pub struct ResolverCache {
    resolver: Arc<dyn Resolve>,
    counters: Arc<StreamCounters>,
    hosts: Mutex<HashMap<String, HostEntry>>,
    interfaces: RwLock<Arc<HashSet<IpAddr>>>,
    wake: Notify,
    scheduled: AtomicBool,
}

impl std::fmt::Debug for ResolverCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolverCache")
            .field("hosts", &self.lock().len())
            .finish()
    }
}

/// The IP literal a backend address names, if it names one.
pub fn literal_host(address: &str) -> Option<IpAddr> {
    backend_address_host(address).parse().ok()
}

impl ResolverCache {
    /// A cache resolving through `resolver`, counting failures in
    /// `counters`, with the interface addresses read now.
    pub fn new(resolver: Arc<dyn Resolve>, counters: Arc<StreamCounters>) -> Arc<Self> {
        let cache = Arc::new(ResolverCache {
            resolver,
            counters,
            hosts: Mutex::new(HashMap::new()),
            interfaces: RwLock::new(Arc::new(HashSet::new())),
            wake: Notify::new(),
            scheduled: AtomicBool::new(false),
        });
        cache.refresh_interfaces();
        cache
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, HostEntry>> {
        self.hosts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The node's interface addresses, canonical, as last read.
    pub fn interfaces(&self) -> Arc<HashSet<IpAddr>> {
        Arc::clone(
            &self
                .interfaces
                .read()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }

    /// Read the interface addresses again; a failure keeps the last set.
    pub fn refresh_interfaces(&self) {
        match lorica_worker::stream_sockets::interface_addresses() {
            Ok(addresses) => {
                *self
                    .interfaces
                    .write()
                    .unwrap_or_else(PoisonError::into_inner) =
                    Arc::new(addresses.into_iter().collect());
            }
            Err(e) => warn!(error = %e,
                            "interface addresses not read; keeping the last set"),
        }
    }

    /// Track the host names of every backend `table` links to a stream,
    /// and forget the others. Starts the schedule on the current tokio
    /// runtime the first time.
    pub fn track(self: &Arc<Self>, table: &StreamTable) {
        let mut wanted: HashMap<String, Vec<BackendLabel>> = HashMap::new();
        for backend in table.backends() {
            if literal_host(&backend.address).is_some() {
                continue;
            }
            wanted
                .entry(backend_address_host(&backend.address).to_ascii_lowercase())
                .or_default()
                .push(BackendLabel {
                    id: backend.id.clone(),
                    name: backend.name.clone(),
                });
        }
        let now = Instant::now();
        {
            let mut hosts = self.lock();
            hosts.retain(|host, _| wanted.contains_key(host));
            for (host, mut labels) in wanted {
                labels.sort_by(|a, b| a.id.cmp(&b.id));
                hosts
                    .entry(host)
                    .or_insert_with(|| HostEntry::new(now))
                    .backends = labels;
            }
        }
        self.wake.notify_one();
        if !self.scheduled.swap(true, Ordering::AcqRel) {
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => {
                    handle.spawn(Arc::clone(self).schedule());
                }
                Err(_) => self.scheduled.store(false, Ordering::Release),
            }
        }
    }

    /// The addresses of `host` known now: the literal itself, or the
    /// last good resolution. `None` for a name never resolved.
    pub fn cached(&self, host: &str) -> Option<Arc<[IpAddr]>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Some(Arc::from([ip.to_canonical()]));
        }
        self.lock()
            .get(&host.to_ascii_lowercase())
            .and_then(|e| e.addresses.clone())
    }

    /// The addresses of `host`, resolving it now, within `timeout`, if no
    /// resolution of it was ever tried. A name whose resolutions so far
    /// all failed is not resolved on demand: the schedule retries it at
    /// the floor, so a dead name never holds every new connection for
    /// its connect timeout.
    pub async fn addresses(&self, host: &str, timeout: Duration) -> Option<Arc<[IpAddr]>> {
        if let Some(known) = self.cached(host) {
            return Some(known);
        }
        let failed_before = self
            .lock()
            .get(&host.to_ascii_lowercase())
            .is_some_and(|e| e.failing);
        if failed_before {
            return None;
        }
        self.resolve(host, timeout).await;
        self.cached(host)
    }

    /// When `host` is resolved next, if the cache holds it.
    pub fn due(&self, host: &str) -> Option<Instant> {
        self.lock().get(&host.to_ascii_lowercase()).map(|e| e.due)
    }

    /// Resolve `host` now, within `timeout`, and record the outcome.
    pub async fn resolve(&self, host: &str, timeout: Duration) {
        let host = host.to_ascii_lowercase();
        let outcome = match tokio::time::timeout(timeout, self.resolver.lookup(&host)).await {
            Ok(result) => result,
            Err(_) => Err(ResolveError(format!(
                "no answer within {} ms",
                timeout.as_millis()
            ))),
        };
        self.record(&host, outcome);
    }

    fn record(&self, host: &str, outcome: Result<Resolved, ResolveError>) {
        let now = Instant::now();
        let mut hosts = self.lock();
        let entry = hosts
            .entry(host.to_string())
            .or_insert_with(|| HostEntry::new(now));
        let resolved = outcome.and_then(|r| {
            let mut addresses: Vec<IpAddr> = r.addresses.iter().map(IpAddr::to_canonical).collect();
            addresses.sort_unstable();
            addresses.dedup();
            if addresses.is_empty() {
                Err(ResolveError("no address in the answer".into()))
            } else {
                Ok((addresses, r.ttl))
            }
        });
        match resolved {
            Ok((addresses, ttl)) => {
                entry.due = now + refresh_interval(ttl);
                if entry.failing {
                    for b in &entry.backends {
                        warn!(backend_id = %b.id, backend = %b.name, %host,
                              addresses = ?addresses,
                              "stream backend name resolves again");
                    }
                }
                entry.failing = false;
                entry.addresses = Some(addresses.into());
            }
            Err(e) => {
                entry.due = now + DNS_MIN_INTERVAL;
                for b in &entry.backends {
                    self.counters.backend(&b.id).dns_failure();
                    if !entry.failing {
                        warn!(backend_id = %b.id, backend = %b.name, %host, error = %e,
                              kept = ?entry.addresses,
                              "stream backend name not resolved; keeping the last addresses");
                    }
                }
                entry.failing = true;
            }
        }
    }

    async fn schedule(self: Arc<Self>) {
        let mut interfaces_due = Instant::now() + INTERFACE_REFRESH_INTERVAL;
        loop {
            let next = self
                .lock()
                .values()
                .map(|e| e.due)
                .min()
                .map_or(interfaces_due, |d| d.min(interfaces_due));
            tokio::select! {
                _ = tokio::time::sleep_until(next) => {}
                _ = self.wake.notified() => {}
            }
            let now = Instant::now();
            let due: Vec<String> = self
                .lock()
                .iter()
                .filter(|(_, e)| e.due <= now)
                .map(|(host, _)| host.clone())
                .collect();
            for host in due {
                if self.lock().contains_key(&host) {
                    self.resolve(&host, DNS_RESOLVE_TIMEOUT).await;
                }
            }
            if Instant::now() >= interfaces_due {
                self.refresh_interfaces();
                interfaces_due = Instant::now() + INTERFACE_REFRESH_INTERVAL;
            }
        }
    }
}

/// Log the transition of a backend into or out of "every address is
/// refused as local" for a stream, once per transition (D-m, IV4).
#[derive(Debug, Default)]
pub struct LocalExclusions(Mutex<HashSet<(String, String)>>);

impl LocalExclusions {
    /// Record whether `backend_id` is excluded from `stream_id` as local
    /// now. Returns true on a transition into exclusion.
    pub fn set(&self, stream_id: &str, backend_id: &str, excluded: bool) -> bool {
        let mut set = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let key = (stream_id.to_string(), backend_id.to_string());
        if excluded {
            set.insert(key)
        } else {
            if set.remove(&key) {
                info!(%stream_id, %backend_id,
                      "stream backend no longer resolves to a refused local address");
            }
            false
        }
    }

    /// Forget the pairs `table` no longer links.
    pub fn retain(&self, table: &StreamTable) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(stream, backend)| table.holds(stream, Some(backend)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seams::SeamFuture;

    struct Scripted(Mutex<Vec<Result<Resolved, ResolveError>>>);

    impl Resolve for Scripted {
        fn lookup<'a>(&'a self, _host: &'a str) -> SeamFuture<'a, Result<Resolved, ResolveError>> {
            let next = self
                .0
                .lock()
                .unwrap()
                .pop()
                .unwrap_or_else(|| Err(ResolveError("script exhausted".into())));
            Box::pin(async move { next })
        }
    }

    fn answer(ips: &[&str], ttl_s: u64) -> Result<Resolved, ResolveError> {
        Ok(Resolved {
            addresses: ips.iter().map(|ip| ip.parse().unwrap()).collect(),
            ttl: Duration::from_secs(ttl_s),
        })
    }

    #[test]
    fn the_interval_is_the_ttl_clamped_both_ways() {
        assert_eq!(refresh_interval(Duration::ZERO), DNS_MIN_INTERVAL);
        assert_eq!(
            refresh_interval(Duration::from_secs(30)),
            Duration::from_secs(30)
        );
        assert_eq!(
            refresh_interval(Duration::from_secs(86_400)),
            DNS_MAX_INTERVAL
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_failure_keeps_the_last_list_and_retries_at_the_floor() {
        // Popped from the end: a TTL of 0, a TTL of a day, a failure, an
        // empty answer, then a recovery.
        let script = vec![
            answer(&["192.0.2.12"], 10),
            answer(&[], 10),
            Err(ResolveError("SERVFAIL".into())),
            answer(&["192.0.2.11", "::ffff:192.0.2.10"], 86_400),
            answer(&["192.0.2.10"], 0),
        ];
        let counters = Arc::new(StreamCounters::new());
        let cache = ResolverCache::new(
            Arc::new(Scripted(Mutex::new(script))),
            Arc::clone(&counters),
        );
        let t = Duration::from_secs(1);

        let start = Instant::now();
        cache.resolve("db.example.com", t).await;
        assert_eq!(cache.due("db.example.com"), Some(start + DNS_MIN_INTERVAL));
        cache.resolve("db.example.com", t).await;
        assert_eq!(cache.due("db.example.com"), Some(start + DNS_MAX_INTERVAL));
        let two: Arc<[IpAddr]> =
            Arc::from(["192.0.2.10".parse().unwrap(), "192.0.2.11".parse().unwrap()].as_slice());
        assert_eq!(cache.cached("DB.example.com"), Some(Arc::clone(&two)));

        cache.resolve("db.example.com", t).await;
        assert_eq!(cache.cached("db.example.com"), Some(Arc::clone(&two)));
        assert_eq!(cache.due("db.example.com"), Some(start + DNS_MIN_INTERVAL));
        cache.resolve("db.example.com", t).await;
        assert_eq!(cache.cached("db.example.com"), Some(Arc::clone(&two)));

        cache.resolve("db.example.com", t).await;
        assert_eq!(
            cache.cached("db.example.com").as_deref(),
            Some(["192.0.2.12".parse::<IpAddr>().unwrap()].as_slice())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_literal_is_never_resolved_and_a_new_name_is_resolved_on_demand() {
        let cache = ResolverCache::new(
            Arc::new(Scripted(Mutex::new(vec![answer(&["192.0.2.20"], 30)]))),
            Arc::new(StreamCounters::new()),
        );
        assert_eq!(
            cache.cached("::ffff:192.0.2.1").as_deref(),
            Some(["192.0.2.1".parse::<IpAddr>().unwrap()].as_slice())
        );
        assert_eq!(cache.cached("new.example.com"), None);
        let got = cache
            .addresses("new.example.com", Duration::from_secs(1))
            .await;
        assert_eq!(
            got.as_deref(),
            Some(["192.0.2.20".parse::<IpAddr>().unwrap()].as_slice())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_name_that_failed_is_left_to_the_schedule() {
        // Popped from the end: a failure, then an answer only the
        // schedule may fetch.
        let cache = ResolverCache::new(
            Arc::new(Scripted(Mutex::new(vec![
                answer(&["192.0.2.30"], 30),
                Err(ResolveError("NXDOMAIN".into())),
            ]))),
            Arc::new(StreamCounters::new()),
        );
        let t = Duration::from_secs(1);
        assert_eq!(cache.addresses("dead.example.com", t).await, None);
        assert_eq!(cache.addresses("dead.example.com", t).await, None);
        cache.resolve("dead.example.com", t).await;
        assert_eq!(
            cache.addresses("dead.example.com", t).await.as_deref(),
            Some(["192.0.2.30".parse::<IpAddr>().unwrap()].as_slice())
        );
    }

    #[test]
    fn exclusions_report_the_transition_once() {
        let exclusions = LocalExclusions::default();
        assert!(exclusions.set("s", "b", true));
        assert!(!exclusions.set("s", "b", true));
        assert!(!exclusions.set("s", "b", false));
        assert!(exclusions.set("s", "b", true));
    }
}
