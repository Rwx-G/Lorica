// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Reverse-DNS lookup with mandatory forward confirmation.
//!
//! Bot-protection's `bypass.rdns` category lets an operator write
//! `googlebot.com` and grant a bypass to every client whose PTR
//! matches (and whose forward A/AAAA resolves back to the same IP).
//! The forward-confirm step is the design-doc-mandated guard (§
//! 10.3): without it, any hostile resolver could point a PTR at
//! `crawl.google.com` and trivially bypass.
//!
//! Architecture:
//! - Process-wide `RdnsResolver` initialised once at startup with
//!   the system `/etc/resolv.conf` (via hickory-resolver's
//!   `from_system_conf`). Arc-shared across the proxy.
//! - A 16 k-entry LRU cache keyed by client IP. Value is
//!   `RdnsCacheEntry { confirmed_name, expires_at }`. Cache TTL
//!   1 h; `expires_at < now` means the entry is treated as absent.
//! - Lookup is `async`. Callers on the proxy hot path dispatch via
//!   a synchronous cache-only helper that never blocks; cache
//!   misses fail closed (the bot-protection evaluator skips the
//!   rDNS category on miss rather than stalling the hot path). A
//!   background task (spawned inside request_filter via
//!   `tokio::spawn`) populates the cache asynchronously so the
//!   NEXT request from the same IP gets a hit.
//! - Zero cost when no route uses `bypass.rdns` — the populate
//!   call site only runs when the config has at least one suffix.

use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashSet;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use lru::LruCache;
use parking_lot::Mutex;
use tokio::sync::Semaphore;

/// How long a successful rDNS result stays cached. One hour matches
/// typical operator rDNS deployments AND caps the window where a
/// stale PTR entry is trusted. Lower values increase resolver
/// traffic under sustained crawler volume; higher values delay
/// rotation when a crawler's IP range changes hands.
const CACHE_TTL_S: i64 = 3600;

/// LRU capacity. 16 384 entries × ~128 bytes per slot = ~2 MiB
/// worst-case memory. Bounded, deterministic.
const CACHE_CAPACITY: usize = 16_384;

/// Hard cap on concurrent background `resolve_and_cache` tasks
/// (v1.5.1 audit L-10). Bounds the in-flight async work even
/// under a flood of unique IPs that bypass the dedup. Mirrors
/// the `MIRROR_SEMAPHORE` precedent in `proxy_wiring/mirror_rewrite.rs`.
/// Each resolve task holds a hickory query future + the connection
/// state for at most ~6 s (timeout+attempts), so 256 in-flight ≈
/// a few MiB of pending state - well within budget.
const MAX_INFLIGHT_RESOLVES: usize = 256;

/// What the cache stores per client IP. `None` confirmed name =
/// "we looked up, no PTR or forward-confirm failed" — still a
/// cache entry so we do NOT re-resolve on every request from a
/// non-matching IP. `Some(name)` = forward-confirmed PTR.
#[derive(Debug, Clone)]
pub struct RdnsCacheEntry {
    pub confirmed_name: Option<String>,
    pub expires_at: i64,
}

/// Process-wide rDNS resolver + cache. Held via [`handle`] the same
/// way `lorica::geoip::handle()` and `lorica::geoip::asn_handle()`
/// work so the reload path and the request filter access a single
/// initialised state without plumbing a resolver through every
/// call.
pub struct RdnsResolver {
    inner: TokioAsyncResolver,
    cache: Mutex<LruCache<IpAddr, RdnsCacheEntry>>,
    /// IPs currently being resolved by a background populate task.
    /// `try_spawn_resolve` consults this set before spawning a
    /// new task : a concurrent miss for the same fresh IP is a
    /// no-op rather than a duplicate spawn. Entries are removed
    /// when the task completes (success or fail). v1.5.1 audit
    /// L-10 (was : every cache miss spawned an unbounded
    /// `tokio::spawn`, so a flood of N concurrent requests for
    /// the same fresh IP allocated N redundant resolve futures).
    inflight: DashSet<IpAddr>,
    /// Bounded permits for concurrent background resolve tasks.
    /// `try_spawn_resolve` drops the spawn silently when the cap
    /// is reached - the next request from the same IP retries
    /// once a slot frees up. Bounds total in-flight async work
    /// even under a botnet flood of unique IPs.
    permits: Arc<Semaphore>,
}

impl RdnsResolver {
    /// Build a resolver from the system `/etc/resolv.conf`. Returns
    /// an `io::Error` when the resolv.conf is absent or malformed
    /// — which in practice only happens on bare containers without
    /// a DNS configuration. Caller logs and skips registration.
    pub fn from_system_conf() -> std::io::Result<Self> {
        let (config, mut opts) = hickory_resolver::system_conf::read_system_conf()?;
        // Short timeouts — a stuck DNS server must not wedge the
        // background populate task. Two retries + 2 s each = ≤ 6 s
        // end-to-end per lookup, well inside the tokio spawn's
        // natural lifetime.
        opts.timeout = Duration::from_secs(2);
        opts.attempts = 2;
        Ok(Self::build(config, opts))
    }

    /// Build with a custom resolver config. Reserved for tests.
    pub fn with_config(config: ResolverConfig, opts: ResolverOpts) -> Self {
        Self::build(config, opts)
    }

    fn build(config: ResolverConfig, opts: ResolverOpts) -> Self {
        let inner = TokioAsyncResolver::tokio(config, opts);
        let capacity = NonZeroUsize::new(CACHE_CAPACITY).expect("non-zero cache cap");
        Self {
            inner,
            cache: Mutex::new(LruCache::new(capacity)),
            inflight: DashSet::new(),
            permits: Arc::new(Semaphore::new(MAX_INFLIGHT_RESOLVES)),
        }
    }

    /// Spawn a background resolve for `ip` if no other task is
    /// already in flight for the same IP and the in-flight cap
    /// has not been reached. Idempotent and lock-free on the
    /// happy path - intended to be called from the proxy
    /// `request_filter` on every cache miss for the rDNS
    /// bypass category.
    ///
    /// Behaviour matrix :
    ///
    /// - `ip` already in flight -> no-op (dedup, the previous
    ///   spawn will populate the cache).
    /// - At permit cap -> no-op (drop, the next request for
    ///   this IP will retry once a slot frees up). The cache
    ///   stays unpopulated for this IP and the bot evaluator
    ///   keeps treating "rDNS bypass does not fire" - same
    ///   semantic as a fresh boot.
    /// - Otherwise spawn a task that calls `resolve_and_cache`
    ///   then removes the IP from `inflight`.
    ///
    /// v1.5.1 audit L-10 : pre-fix, the proxy spawned an
    /// unbounded `tokio::spawn(resolve_and_cache)` per cache
    /// miss. A flood of N concurrent requests for the same
    /// fresh IP allocated N redundant resolve futures ; a
    /// botnet flood of unique IPs allocated unbounded async
    /// work proportional to attack volume.
    pub fn try_spawn_resolve(self: &Arc<Self>, ip: IpAddr) {
        // Dedup : DashSet::insert returns false if the IP was
        // already present. A second concurrent miss for the
        // same fresh IP is a no-op.
        if !self.inflight.insert(ip) {
            return;
        }
        // Hard cap : try_acquire_owned is non-blocking. When
        // the semaphore is exhausted we drop the spawn and
        // remove the IP from inflight so a later attempt can
        // retry once a slot frees up.
        let permit = match Arc::clone(&self.permits).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                self.inflight.remove(&ip);
                return;
            }
        };
        let resolver = Arc::clone(self);
        tokio::spawn(async move {
            // Hold the permit for the lifetime of the resolve so
            // the cap reflects real in-flight work.
            let _permit = permit;
            let _ = resolver.resolve_and_cache(ip).await;
            resolver.inflight.remove(&ip);
        });
    }

    /// Number of resolve tasks currently in flight. Test-only
    /// accessor used by `try_spawn_resolve` regression tests.
    #[cfg(test)]
    pub(crate) fn inflight_count(&self) -> usize {
        self.inflight.len()
    }

    /// Synchronous cache-only lookup. Returns `Some(Some(name))`
    /// on a fresh forward-confirmed hit, `Some(None)` on a fresh
    /// "looked up, no match" entry, and `None` when the cache
    /// does not know about this IP yet (request-filter treats
    /// this as "rDNS bypass does not fire on this request; the
    /// next request from the same IP will, once the background
    /// populate lands").
    pub fn cache_check(&self, ip: IpAddr, now: i64) -> Option<Option<String>> {
        let mut cache = self.cache.lock();
        match cache.get(&ip) {
            Some(entry) if entry.expires_at > now => Some(entry.confirmed_name.clone()),
            _ => None,
        }
    }

    /// Async lookup. Resolves the PTR for `ip`, then for each
    /// returned name resolves the A/AAAA and checks whether ANY
    /// resolved address equals `ip`. Returns the first
    /// forward-confirmed name, or `None` when nothing confirms.
    /// Updates the cache either way so the result is reusable.
    pub async fn resolve_and_cache(&self, ip: IpAddr) -> Option<String> {
        let confirmed = self.lookup_with_forward_confirm(ip).await;
        let now = unix_now();
        let entry = RdnsCacheEntry {
            confirmed_name: confirmed.clone(),
            expires_at: now + CACHE_TTL_S,
        };
        self.cache.lock().put(ip, entry);
        confirmed
    }

    async fn lookup_with_forward_confirm(&self, ip: IpAddr) -> Option<String> {
        // PTR lookup. hickory returns a list of names; iterate and
        // take the first that forward-confirms. In practice the
        // list is length 1 for every real-world rDNS deployment.
        let reverse = self.inner.reverse_lookup(ip).await.ok()?;
        for name in reverse.iter() {
            let name_str = name.to_ascii();
            // Forward lookup. Hickory's `lookup_ip` handles both
            // A and AAAA; we scan every returned IpAddr for an
            // equality match with the client.
            let forward = match self.inner.lookup_ip(name_str.as_str()).await {
                Ok(f) => f,
                Err(_) => continue,
            };
            if forward.iter().any(|resolved| resolved == ip) {
                // Strip the trailing dot that hickory preserves in
                // canonical form (`googlebot.com.` → `googlebot.com`).
                let cleaned = name_str.trim_end_matches('.').to_ascii_lowercase();
                return Some(cleaned);
            }
        }
        None
    }
}

/// Check whether `confirmed_name` matches any suffix in the
/// operator's bypass list. Suffix comparison is anchored at the
/// end AND respects DNS label boundaries, so `googlebot.com`
/// matches `crawl.googlebot.com` but NOT
/// `fakegooglebot.com`. Case-insensitive.
pub fn suffix_matches(confirmed_name: &str, suffixes: &[String]) -> bool {
    let host = confirmed_name.trim_end_matches('.').to_ascii_lowercase();
    suffixes.iter().any(|suffix| {
        let suffix = suffix.trim_end_matches('.').to_ascii_lowercase();
        if host == suffix {
            return true;
        }
        // Strict suffix match: the host must end with `.{suffix}`
        // so `fakegooglebot.com` does not match `googlebot.com`.
        host.ends_with(&format!(".{suffix}"))
    })
}

static RDNS_HANDLE: OnceLock<Arc<RdnsResolver>> = OnceLock::new();

/// Register the process-wide rDNS resolver. Called once at
/// startup after the tokio runtime is up (the resolver needs
/// `TokioAsyncResolver::tokio` which expects a runtime). Second
/// call is a silent no-op.
pub fn set_handle(resolver: Arc<RdnsResolver>) {
    let _ = RDNS_HANDLE.set(resolver);
}

/// Read the process-wide rDNS resolver handle. `None` before
/// [`set_handle`] or when the startup path failed to build one
/// (e.g. missing `/etc/resolv.conf`) — the bot evaluator treats
/// that as "rDNS bypass category is a silent no-op".
pub fn handle() -> Option<Arc<RdnsResolver>> {
    RDNS_HANDLE.get().cloned()
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_matches_exact() {
        let suffixes = vec!["googlebot.com".to_string()];
        assert!(suffix_matches("googlebot.com", &suffixes));
        assert!(suffix_matches("crawl.googlebot.com", &suffixes));
        assert!(suffix_matches("Crawl.GoogleBot.Com", &suffixes));
    }

    #[test]
    fn suffix_matches_rejects_sibling_host() {
        // Documented threat: `fakegooglebot.com` is NOT a subdomain
        // of `googlebot.com` and MUST NOT bypass.
        let suffixes = vec!["googlebot.com".to_string()];
        assert!(!suffix_matches("fakegooglebot.com", &suffixes));
        assert!(!suffix_matches("googlebot.com.attacker.example", &suffixes));
    }

    #[test]
    fn suffix_matches_handles_trailing_dot() {
        let suffixes = vec!["googlebot.com.".to_string()];
        assert!(suffix_matches("crawl.googlebot.com.", &suffixes));
        assert!(suffix_matches("crawl.googlebot.com", &suffixes));
    }

    #[test]
    fn suffix_matches_empty_list_matches_nothing() {
        assert!(!suffix_matches("googlebot.com", &[]));
    }

    #[test]
    fn suffix_matches_multiple_patterns() {
        let suffixes = vec!["googlebot.com".to_string(), "search.msn.com".to_string()];
        assert!(suffix_matches("msnbot.search.msn.com", &suffixes));
        // `google.com` is not in the suffix list — must not match
        // even though it looks like it could belong to Google.
        assert!(!suffix_matches(
            "rate-limited-proxy-66-249-64-1.google.com.",
            &suffixes
        ));
    }

    #[test]
    fn cache_expires_past_ttl() {
        // Resolver requires a tokio runtime to actually dispatch
        // queries. We only exercise the cache surface here — the
        // hickory inner is unused.
        let config = ResolverConfig::default();
        let opts = ResolverOpts::default();
        let resolver = RdnsResolver::with_config(config, opts);
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        // Seed the cache with an expired entry.
        resolver.cache.lock().put(
            ip,
            RdnsCacheEntry {
                confirmed_name: Some("googlebot.com".into()),
                expires_at: 1_000,
            },
        );
        assert!(resolver.cache_check(ip, 2_000).is_none());
        // Fresh entry — same IP, new timestamp.
        resolver.cache.lock().put(
            ip,
            RdnsCacheEntry {
                confirmed_name: Some("googlebot.com".into()),
                expires_at: 3_000,
            },
        );
        assert_eq!(
            resolver.cache_check(ip, 2_000),
            Some(Some("googlebot.com".to_string()))
        );
    }

    /// v1.5.1 audit L-10 : `try_spawn_resolve` must dedup
    /// concurrent calls for the same fresh IP - exactly one
    /// background task should be in flight regardless of how many
    /// times the request_filter fires for that IP. Uses the same
    /// black-hole resolver from the test below to keep the spawned
    /// task pending while we inspect `inflight_count`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn try_spawn_resolve_dedups_concurrent_calls_for_same_ip() {
        use hickory_resolver::config::{NameServerConfig, Protocol};
        use std::net::SocketAddr;

        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig {
            socket_addr: addr,
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: false,
            bind_addr: None,
        });
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_millis(200);
        opts.attempts = 1;
        opts.cache_size = 0;

        let resolver = Arc::new(RdnsResolver::with_config(config, opts));
        let ip: IpAddr = "192.0.2.7".parse().unwrap();

        assert_eq!(resolver.inflight_count(), 0);

        // Five concurrent spawn calls for the same IP : the
        // first inserts into `inflight` and spawns ; the next
        // four short-circuit on the dedup check.
        for _ in 0..5 {
            resolver.try_spawn_resolve(ip);
        }
        assert_eq!(
            resolver.inflight_count(),
            1,
            "five concurrent spawns for the same IP must collapse to one in-flight task"
        );

        // Wait for the single task to time out + complete. The
        // black-hole resolver gives up after 200 ms ; budget 1 s
        // for the spawn scheduling + cache write + inflight remove.
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(
            resolver.inflight_count(),
            0,
            "inflight set must drain after the resolve task completes"
        );
    }

    /// `try_spawn_resolve` for two different IPs must run two
    /// concurrent tasks (no false dedup across IPs).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn try_spawn_resolve_does_not_dedup_across_ips() {
        use hickory_resolver::config::{NameServerConfig, Protocol};
        use std::net::SocketAddr;

        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig {
            socket_addr: addr,
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: false,
            bind_addr: None,
        });
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_millis(200);
        opts.attempts = 1;
        opts.cache_size = 0;

        let resolver = Arc::new(RdnsResolver::with_config(config, opts));
        let ip1: IpAddr = "192.0.2.10".parse().unwrap();
        let ip2: IpAddr = "192.0.2.11".parse().unwrap();
        let ip3: IpAddr = "192.0.2.12".parse().unwrap();

        resolver.try_spawn_resolve(ip1);
        resolver.try_spawn_resolve(ip2);
        resolver.try_spawn_resolve(ip3);

        assert_eq!(resolver.inflight_count(), 3);

        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(resolver.inflight_count(), 0);
    }

    /// `resolve_and_cache` must populate the cache even when the PTR
    /// lookup fails or forward-confirm does not match (the negative
    /// entry prevents a hot-path from re-resolving the same IP every
    /// request). Pointing the resolver at a black-hole nameserver
    /// exercises the failure path without needing a real DNS server
    /// in the test — the PTR lookup times out and `resolve_and_cache`
    /// returns None, but the cache entry still lands.
    ///
    /// This covers the implicit "fail-closed with cached negative"
    /// contract that the request_filter relies on for the rDNS
    /// bypass category.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resolve_and_cache_writes_negative_entry_on_resolver_failure() {
        use hickory_resolver::config::{NameServerConfig, Protocol};
        use std::net::SocketAddr;

        // 127.0.0.1:1 is deliberately a port nothing listens on —
        // UDP sends will drop / time out. The short opts below cap
        // the test at ≤ 1 s wall-clock.
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig {
            socket_addr: addr,
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: false,
            bind_addr: None,
        });
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_millis(200);
        opts.attempts = 1;
        // Disable caching INSIDE hickory so our 200 ms budget is not
        // eaten by retry warm-up.
        opts.cache_size = 0;

        let resolver = RdnsResolver::with_config(config, opts);
        let ip: IpAddr = "192.0.2.42".parse().unwrap();

        // Pre-flight: cache is empty.
        let now = unix_now();
        assert!(resolver.cache_check(ip, now).is_none());

        // Resolve: PTR times out, returns None.
        let got = resolver.resolve_and_cache(ip).await;
        assert!(got.is_none(), "black-hole nameserver must not resolve");

        // Post-condition: the cache now has a negative entry, so
        // cache_check returns `Some(None)` — the request filter uses
        // this to skip re-resolving the same IP on the hot path.
        match resolver.cache_check(ip, now) {
            Some(None) => {}
            other => panic!("expected Some(None) negative cache entry, got {other:?}"),
        }
    }
}
