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

//! Token-bucket identity, and the worker-mode sync both ends of the
//! `RateLimitDelta` RPC share (design § 6).
//!
//! A bucket key reads `<route_id>|<rule>|<capacity>:<refill_per_sec>|<scope_key>`:
//!
//! - `<rule>` is `-` for the route-level limit, or the position in
//!   `Route::path_rules` of the matched rule when that rule sets a rate
//!   limit of its own, so a path rule never shares tokens with its route.
//! - `<capacity>:<refill_per_sec>` is the limit the bucket was sized for.
//!   A reload that changes a limit, or reorders rules so that a position
//!   now carries another limit, yields a new key and a fresh bucket; the
//!   old one goes idle and is evicted. Nothing is reset on reload, so a
//!   reload of an unrelated route never hands a throttled client a full
//!   bucket, and no bucket outlives the limit it was built for.
//! - `<scope_key>` is the client IP for `per_ip`, or
//!   [`PER_ROUTE_SCOPE_KEY`] for `per_route`.
//!
//! The supervisor never takes the limit from the key on trust: it
//! re-derives it from the route in its store and answers `untracked`
//! when the two disagree, as it does for a route that is gone or carries
//! no limit. A worker drops a bucket the supervisor does not track
//! instead of reading the reply as "0 tokens left" (issue #45).

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use lorica_command::{RateLimitEntry, RateLimitSnapshot};
use lorica_config::models::{RateLimit, RateLimitScope, Route};
use lorica_config::ConfigStore;
use lorica_limits::token_bucket::{AuthoritativeBucket, LocalBucket};

/// Scope key of a `per_route` bucket. Never a valid IP literal, so it
/// cannot collide with a `per_ip` bucket of the same route.
pub const PER_ROUTE_SCOPE_KEY: &str = "__route__";

/// Scope key of a `per_ip` bucket whose client address is unknown or is
/// not an IP literal (an `X-Forwarded-For` entry is client-supplied text
/// behind a trusted proxy). Sharing one bucket keeps a client from
/// minting a fresh bucket per request, and keeps the scope key free of
/// the `|` separator.
pub const UNKNOWN_CLIENT_SCOPE_KEY: &str = "unknown";

/// `<rule>` segment of a route-level bucket.
const ROUTE_LEVEL_RULE: &str = "-";

/// How often idle buckets are evicted, on workers, in single-process
/// mode and on the supervisor alike.
pub const BUCKET_PRUNE_INTERVAL: Duration = Duration::from_secs(60);

/// A bucket untouched for this long is evicted. A later request rebuilds
/// it full, which the client has earned by staying away that long.
pub const BUCKET_IDLE_TTL: Duration = Duration::from_secs(5 * 60);

/// Upper bound on the entries of one `RateLimitDelta` push. A scan from
/// many addresses leaves one non-full bucket per address, and the RPC
/// frame is capped at 1 MiB: an unbounded batch would fail as a whole
/// and leave every bucket stale. At about 120 bytes per entry (UUID
/// route id, IPv6 client), 2048 entries stay well under the frame cap in
/// both directions, and still refresh 20 480 buckets per second per
/// worker; the rest wait their turn through [`collect_sync_batch`]'s
/// rotating cursor.
pub const SYNC_BATCH_MAX_ENTRIES: usize = 2048;

/// The bucket a request on `route` for `request_path` draws from: the
/// matched path rule's own limit when that rule sets one, the route's
/// otherwise. Returns the rule position (`None` for route level) and the
/// limit, or `None` when the request is not rate-limited.
pub fn resolve_request_limit(
    route: &Route,
    request_path: &str,
) -> Option<(Option<usize>, RateLimit)> {
    match route.matching_path_rule(request_path) {
        Some((index, rule)) if rule.overrides_rate_limit() => route
            .effective_rate_limit_with(rule)
            .map(|limit| (Some(index), limit)),
        _ => route.effective_rate_limit().map(|limit| (None, limit)),
    }
}

/// The limit of the bucket that [`resolve_request_limit`] attributes to
/// `rule` on `route`. The supervisor's side of the same resolution.
pub fn limit_for_rule(route: &Route, rule: Option<usize>) -> Option<RateLimit> {
    match rule {
        None => route.effective_rate_limit(),
        Some(index) => route
            .path_rules
            .get(index)
            .filter(|rule| rule.overrides_rate_limit())
            .and_then(|rule| route.effective_rate_limit_with(rule)),
    }
}

/// Scope key of the bucket `limit` assigns to a client. `client_ip` is
/// the resolved client address when it parsed as an IP literal.
pub fn scope_key<'a>(limit: &RateLimit, client_ip: Option<&'a str>) -> &'a str {
    match limit.scope {
        RateLimitScope::PerIp => client_ip.unwrap_or(UNKNOWN_CLIENT_SCOPE_KEY),
        RateLimitScope::PerRoute => PER_ROUTE_SCOPE_KEY,
    }
}

/// Build the bucket key described in the module documentation. One
/// allocation: this runs once per rate-limited request.
pub fn bucket_key(
    route_id: &str,
    rule: Option<usize>,
    limit: &RateLimit,
    scope_key: &str,
) -> String {
    let mut rule_buf = itoa::Buffer::new();
    let rule_part = match rule {
        Some(index) => rule_buf.format(index),
        None => ROUTE_LEVEL_RULE,
    };
    let mut capacity_buf = itoa::Buffer::new();
    let capacity = capacity_buf.format(limit.capacity);
    let mut refill_buf = itoa::Buffer::new();
    let refill = refill_buf.format(limit.refill_per_sec);
    let mut key = String::with_capacity(
        route_id.len() + rule_part.len() + capacity.len() + refill.len() + scope_key.len() + 4,
    );
    key.push_str(route_id);
    key.push('|');
    key.push_str(rule_part);
    key.push('|');
    key.push_str(capacity);
    key.push(':');
    key.push_str(refill);
    key.push('|');
    key.push_str(scope_key);
    key
}

/// A bucket key taken apart. See the module documentation for the shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketKey<'a> {
    /// Route the bucket belongs to.
    pub route_id: &'a str,
    /// Path-rule position, `None` for the route-level bucket.
    pub rule: Option<usize>,
    /// Burst size the bucket was built for.
    pub capacity: u32,
    /// Refill rate the bucket was built for.
    pub refill_per_sec: u32,
    /// Client IP, [`UNKNOWN_CLIENT_SCOPE_KEY`] or [`PER_ROUTE_SCOPE_KEY`].
    pub scope_key: &'a str,
}

impl<'a> BucketKey<'a> {
    /// Parse a key built by [`bucket_key`]. Split from the right: the
    /// scope key never contains `|` and the route id is the one segment
    /// whose content this module does not control.
    pub fn parse(key: &'a str) -> Option<Self> {
        let mut parts = key.rsplitn(4, '|');
        let scope_key = parts.next()?;
        let (capacity, refill_per_sec) = parts.next()?.split_once(':')?;
        let rule = match parts.next()? {
            ROUTE_LEVEL_RULE => None,
            index => Some(index.parse().ok()?),
        };
        let route_id = parts.next()?;
        Some(Self {
            route_id,
            rule,
            capacity: capacity.parse().ok()?,
            refill_per_sec: refill_per_sec.parse().ok()?,
            scope_key,
        })
    }

    /// Whether this key is the one [`bucket_key`] builds for `limit`,
    /// scope included.
    pub fn was_built_for(&self, limit: &RateLimit) -> bool {
        let scope_matches = match limit.scope {
            RateLimitScope::PerRoute => self.scope_key == PER_ROUTE_SCOPE_KEY,
            RateLimitScope::PerIp => self.scope_key != PER_ROUTE_SCOPE_KEY,
        };
        scope_matches
            && self.capacity == limit.capacity
            && self.refill_per_sec == limit.refill_per_sec
    }
}

/// Drain up to `max_entries` buckets that [`LocalBucket::needs_sync`]
/// into one `RateLimitDelta` batch. A depleted bucket goes in with
/// `consumed = 0`: refused requests consume nothing, and only the
/// supervisor's reply can tell it how much has refilled.
///
/// When more buckets need a sync than one batch holds, `cursor` carries
/// the position to resume from on the next tick, so every bucket is
/// served within `ceil(n / max_entries)` ticks instead of the first
/// `max_entries` starving the rest. Positions are counted in map
/// iteration order, which an insert or a removal shifts; the cursor only
/// has to be fair over time, not exact.
pub fn collect_sync_batch(
    buckets: &DashMap<String, Arc<LocalBucket>>,
    cursor: &mut usize,
    max_entries: usize,
) -> Vec<RateLimitEntry> {
    fn drain(
        item: dashmap::mapref::multiple::RefMulti<'_, String, Arc<LocalBucket>>,
    ) -> RateLimitEntry {
        RateLimitEntry {
            key: item.key().clone(),
            consumed: item.value().take_delta(),
        }
    }
    let start = *cursor;
    let mut batch: Vec<RateLimitEntry> = buckets
        .iter()
        .filter(|item| item.value().needs_sync())
        .skip(start)
        .take(max_entries)
        .map(drain)
        .collect();
    if batch.len() == max_entries {
        *cursor = start + max_entries;
        return batch;
    }
    let before_len = batch.len();
    batch.extend(
        buckets
            .iter()
            .filter(|item| item.value().needs_sync())
            .take(start.min(max_entries - before_len))
            .map(drain),
    );
    *cursor = batch.len() - before_len;
    batch
}

/// Apply the supervisor's reply to a [`collect_sync_batch`] push.
pub fn apply_sync_reply(
    buckets: &DashMap<String, Arc<LocalBucket>>,
    snapshots: Vec<RateLimitSnapshot>,
) {
    for snapshot in snapshots {
        if snapshot.untracked {
            // The next request rebuilds the bucket from this worker's
            // own, possibly newer, config.
            buckets.remove(&snapshot.key);
        } else if let Some(bucket) = buckets.get(&snapshot.key) {
            bucket.value().refresh(snapshot.remaining);
        }
    }
}

/// Limits of one route, resolved once from the store per route and
/// reused for every key of that route until the next reload.
#[derive(Debug)]
struct RoutePolicy {
    route: Option<RateLimit>,
    rules: Vec<Option<RateLimit>>,
}

impl RoutePolicy {
    fn of(route: &Route) -> Self {
        Self {
            route: limit_for_rule(route, None),
            rules: (0..route.path_rules.len())
                .map(|index| limit_for_rule(route, Some(index)))
                .collect(),
        }
    }

    fn limit(&self, rule: Option<usize>) -> Option<&RateLimit> {
        match rule {
            None => self.route.as_ref(),
            Some(index) => self.rules.get(index).and_then(Option::as_ref),
        }
    }
}

/// Supervisor-side authority for worker-mode rate limits: one
/// [`AuthoritativeBucket`] per key across every worker, plus the
/// per-route policy cache that sizes them (audit M-4: without it, N
/// workers pushing a first-seen key at once serialise N SQLite reads on
/// the store mutex).
#[derive(Debug, Default)]
pub struct SupervisorRateLimits {
    buckets: DashMap<String, Arc<AuthoritativeBucket>>,
    /// `None` caches "no such route", so a stale key costs one store
    /// read per reload rather than one per tick.
    policies: DashMap<String, Option<Arc<RoutePolicy>>>,
}

impl SupervisorRateLimits {
    /// Empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget every cached route policy. Called after each config
    /// change, so the next push re-reads the routes from the store.
    /// Buckets survive: their key pins the limit they were built for.
    pub fn invalidate_policies(&self) {
        self.policies.clear();
    }

    /// Number of authoritative buckets held.
    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    /// Evict buckets no worker has synced for `idle_ttl`. A worker syncs
    /// a bucket while it has consumption to push or is below capacity,
    /// so an evicted bucket was full or abandoned.
    pub fn prune_idle(&self, now_ns: u64, idle_ttl: Duration) {
        let idle_ttl_ns = u64::try_from(idle_ttl.as_nanos()).unwrap_or(u64::MAX);
        self.buckets
            .retain(|_, bucket| now_ns.saturating_sub(bucket.last_activity_ns()) < idle_ttl_ns);
    }

    /// Apply one worker's batched consumption and return the
    /// authoritative token count per key, `untracked` for a key this
    /// registry does not hold a bucket for and will not create one.
    pub async fn apply_deltas(
        &self,
        entries: &[RateLimitEntry],
        store: &tokio::sync::Mutex<ConfigStore>,
        now_ns: u64,
    ) -> Vec<RateLimitSnapshot> {
        let mut snapshots = Vec::with_capacity(entries.len());
        for entry in entries {
            let snapshot = match self.bucket_for(&entry.key, store, now_ns).await {
                Some(bucket) => RateLimitSnapshot {
                    key: entry.key.clone(),
                    remaining: bucket.apply_delta(entry.consumed, now_ns),
                    untracked: false,
                },
                None => RateLimitSnapshot {
                    key: entry.key.clone(),
                    remaining: 0,
                    untracked: true,
                },
            };
            snapshots.push(snapshot);
        }
        snapshots
    }

    async fn bucket_for(
        &self,
        key: &str,
        store: &tokio::sync::Mutex<ConfigStore>,
        now_ns: u64,
    ) -> Option<Arc<AuthoritativeBucket>> {
        if let Some(bucket) = self.buckets.get(key) {
            return Some(Arc::clone(bucket.value()));
        }
        let parsed = BucketKey::parse(key)?;
        let policy = self.policy(parsed.route_id, store).await?;
        let limit = policy.limit(parsed.rule)?;
        if !parsed.was_built_for(limit) {
            tracing::debug!(
                key,
                capacity = limit.capacity,
                refill_per_sec = limit.refill_per_sec,
                "rate-limit key built for another limit than the stored route; untracked"
            );
            return None;
        }
        let bucket = self
            .buckets
            .entry(key.to_string())
            .or_insert_with(|| {
                Arc::new(AuthoritativeBucket::new(
                    limit.capacity,
                    limit.refill_per_sec,
                    now_ns,
                ))
            })
            .clone();
        Some(bucket)
    }

    async fn policy(
        &self,
        route_id: &str,
        store: &tokio::sync::Mutex<ConfigStore>,
    ) -> Option<Arc<RoutePolicy>> {
        if let Some(cached) = self.policies.get(route_id) {
            return cached.value().clone();
        }
        let fetched = store.lock().await.get_route(route_id);
        match fetched {
            Ok(route) => {
                let policy = route.map(|route| Arc::new(RoutePolicy::of(&route)));
                self.policies.insert(route_id.to_string(), policy.clone());
                policy
            }
            Err(e) => {
                // Not cached: a transient store error must not pin the
                // route as unlimited until the next reload.
                tracing::warn!(
                    route_id,
                    error = %e,
                    "rate-limit policy lookup failed; key untracked for this push"
                );
                None
            }
        }
    }
}

/// Serve one `RateLimitDelta` RPC on the supervisor.
pub async fn handle_rate_limit_delta(
    inc: lorica_command::IncomingCommand,
    limits: &SupervisorRateLimits,
    store: &tokio::sync::Mutex<ConfigStore>,
) {
    use lorica_command::{command, response, RateLimitDeltaResult, Response};

    let entries = match inc.command().payload.clone() {
        Some(command::Payload::RateLimitDelta(delta)) => delta.entries,
        _ => {
            let _ = inc.reply_error("malformed RateLimitDelta payload").await;
            return;
        }
    };
    let snapshots = limits
        .apply_deltas(&entries, store, lorica_shmem::now_ns())
        .await;
    let _ = inc
        .reply(Response::ok_with(
            0,
            response::Payload::RateLimitDeltaResult(RateLimitDeltaResult { snapshots }),
        ))
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy_wiring::tests::make_route;
    use lorica_config::models::{PathMatchType, PathRule};

    fn legacy_route(id: &str, rps: u32, burst: u32) -> Route {
        let mut route = make_route(id, &format!("{id}.example.com"), "/", true);
        route.rate_limit_rps = Some(rps);
        route.rate_limit_burst = Some(burst);
        route
    }

    fn login_rule(rps: u32, burst: u32) -> PathRule {
        PathRule {
            path: "/login".to_string(),
            match_type: PathMatchType::Prefix,
            rate_limit_rps: Some(rps),
            rate_limit_burst: Some(burst),
            ..Default::default()
        }
    }

    fn store_with(routes: &[Route]) -> tokio::sync::Mutex<ConfigStore> {
        let store = ConfigStore::open_in_memory().expect("in-memory store");
        for route in routes {
            store.create_route(route).expect("create route");
        }
        tokio::sync::Mutex::new(store)
    }

    fn entry(key: &str, consumed: u32) -> RateLimitEntry {
        RateLimitEntry {
            key: key.to_string(),
            consumed,
        }
    }

    fn key_for(route: &Route, path: &str, client: &str) -> String {
        let (rule, limit) = resolve_request_limit(route, path).expect("route is rate-limited");
        bucket_key(&route.id, rule, &limit, scope_key(&limit, Some(client)))
    }

    #[test]
    fn bucket_key_round_trips() {
        let limit = RateLimit {
            capacity: 5,
            refill_per_sec: 20,
            scope: RateLimitScope::PerIp,
        };
        let key = bucket_key("r-1", None, &limit, "2001:db8::1");
        assert_eq!(key, "r-1|-|5:20|2001:db8::1");
        assert_eq!(
            BucketKey::parse(&key),
            Some(BucketKey {
                route_id: "r-1",
                rule: None,
                capacity: 5,
                refill_per_sec: 20,
                scope_key: "2001:db8::1",
            })
        );

        let per_route = RateLimit {
            scope: RateLimitScope::PerRoute,
            ..limit.clone()
        };
        let key = bucket_key("odd|route", Some(3), &per_route, PER_ROUTE_SCOPE_KEY);
        let parsed = BucketKey::parse(&key).expect("parses");
        assert_eq!(
            parsed.route_id, "odd|route",
            "route id may carry the separator"
        );
        assert_eq!(parsed.rule, Some(3));
        assert!(parsed.was_built_for(&per_route));
        assert!(
            !parsed.was_built_for(&limit),
            "scope is part of the identity"
        );
    }

    #[test]
    fn bucket_key_rejects_malformed_keys() {
        for key in [
            "",
            "r|ip",
            "r|-|5|ip",
            "r|x|5:20|ip",
            "r|-|5:x|ip",
            "|-|5:-1|ip",
        ] {
            assert_eq!(BucketKey::parse(key), None, "{key:?}");
        }
    }

    #[test]
    fn was_built_for_compares_the_limit() {
        let limit = RateLimit {
            capacity: 5,
            refill_per_sec: 20,
            scope: RateLimitScope::PerIp,
        };
        let key = bucket_key("r", None, &limit, "10.0.0.1");
        let parsed = BucketKey::parse(&key).expect("parses");
        assert!(parsed.was_built_for(&limit));
        assert!(!parsed.was_built_for(&RateLimit {
            capacity: 6,
            ..limit.clone()
        }));
        assert!(!parsed.was_built_for(&RateLimit {
            refill_per_sec: 21,
            ..limit
        }));
    }

    #[test]
    fn legacy_route_resolves_to_its_synthesised_limit() {
        let route = legacy_route("r", 20, 5);
        assert_eq!(
            resolve_request_limit(&route, "/anything"),
            Some((
                None,
                RateLimit {
                    capacity: 5,
                    refill_per_sec: 20,
                    scope: RateLimitScope::PerIp,
                }
            ))
        );
        assert_eq!(key_for(&route, "/", "10.0.0.1"), "r|-|5:20|10.0.0.1");
    }

    #[test]
    fn path_rule_override_gets_its_own_bucket() {
        let mut route = legacy_route("r", 20, 5);
        route.path_rules = vec![
            PathRule {
                path: "/static".to_string(),
                backend_ids: Some(vec!["b".to_string()]),
                ..Default::default()
            },
            login_rule(1, 2),
        ];
        let (rule, limit) = resolve_request_limit(&route, "/login/form").expect("limited");
        assert_eq!(rule, Some(1));
        assert_eq!(limit.capacity, 2);
        assert_eq!(limit.refill_per_sec, 1);
        assert_eq!(key_for(&route, "/login", "10.0.0.1"), "r|1|2:1|10.0.0.1");
        // A matched rule that does not touch the rate limit keeps the
        // route-level bucket.
        assert_eq!(
            key_for(&route, "/static/a.css", "10.0.0.1"),
            "r|-|5:20|10.0.0.1"
        );
        assert_eq!(key_for(&route, "/", "10.0.0.1"), "r|-|5:20|10.0.0.1");
        // `rate_limit_rps = 0` on a rule lifts the limit for its paths.
        route.path_rules[1].rate_limit_rps = Some(0);
        assert_eq!(resolve_request_limit(&route, "/login"), None);
    }

    #[test]
    fn supervisor_side_resolution_inverts_the_request_side() {
        let mut route = legacy_route("r", 20, 5);
        route.rate_limit = Some(RateLimit {
            capacity: 9,
            refill_per_sec: 3,
            scope: RateLimitScope::PerRoute,
        });
        route.path_rules = vec![
            login_rule(1, 2),
            PathRule {
                path: "/api".to_string(),
                rate_limit_burst: Some(50),
                ..Default::default()
            },
            PathRule {
                path: "/static".to_string(),
                cache_enabled: Some(true),
                ..Default::default()
            },
        ];
        for path in ["/", "/login", "/api/x", "/static/y"] {
            let (rule, limit) = resolve_request_limit(&route, path).expect("limited");
            assert_eq!(limit_for_rule(&route, rule), Some(limit), "{path}");
        }
        assert_eq!(
            limit_for_rule(&route, Some(2)),
            None,
            "a rule without a rate-limit override owns no bucket"
        );
        assert_eq!(limit_for_rule(&route, Some(7)), None);
    }

    #[test]
    fn scope_key_falls_back_for_an_unknown_client() {
        let per_ip = RateLimit {
            capacity: 1,
            refill_per_sec: 1,
            scope: RateLimitScope::PerIp,
        };
        assert_eq!(scope_key(&per_ip, Some("10.0.0.1")), "10.0.0.1");
        assert_eq!(scope_key(&per_ip, None), UNKNOWN_CLIENT_SCOPE_KEY);
        let per_route = RateLimit {
            scope: RateLimitScope::PerRoute,
            ..per_ip
        };
        assert_eq!(scope_key(&per_route, Some("10.0.0.1")), PER_ROUTE_SCOPE_KEY);
    }

    #[tokio::test]
    async fn supervisor_seeds_a_legacy_route_from_its_effective_limit() {
        // Issue #45: the supervisor used to read only the structured
        // `rate_limit`, found nothing on a legacy route and answered 0.
        let route = legacy_route("r-legacy", 20, 5);
        let store = store_with(std::slice::from_ref(&route));
        let limits = SupervisorRateLimits::new();
        let key = key_for(&route, "/", "10.0.0.1");

        let snapshots = limits.apply_deltas(&[entry(&key, 1)], &store, 0).await;
        assert_eq!(snapshots.len(), 1);
        assert!(!snapshots[0].untracked);
        assert_eq!(snapshots[0].remaining, 4, "burst 5 minus the one consumed");

        // A zero-delta refresh one second later sees the 20/s refill,
        // clamped at the burst.
        let snapshots = limits
            .apply_deltas(&[entry(&key, 0)], &store, 1_000_000_000)
            .await;
        assert_eq!(snapshots[0].remaining, 5);
        assert!(!snapshots[0].untracked);
    }

    #[tokio::test]
    async fn supervisor_never_answers_zero_tokens_for_an_unlimited_or_unknown_key() {
        let unlimited = make_route("r-free", "free.example.com", "/", true);
        let limited = legacy_route("r-limited", 20, 5);
        let store = store_with(&[unlimited, limited.clone()]);
        let limits = SupervisorRateLimits::new();
        let stale_limit = RateLimit {
            capacity: 99,
            refill_per_sec: 1,
            scope: RateLimitScope::PerIp,
        };
        let keys = [
            "r-free|-|5:20|10.0.0.1".to_string(),
            "r-gone|-|5:20|10.0.0.1".to_string(),
            bucket_key(&limited.id, None, &stale_limit, "10.0.0.1"),
            bucket_key(&limited.id, Some(0), &stale_limit, "10.0.0.1"),
            "not a key".to_string(),
        ];
        let entries: Vec<RateLimitEntry> = keys.iter().map(|k| entry(k, 1)).collect();
        let snapshots = limits.apply_deltas(&entries, &store, 0).await;
        assert_eq!(snapshots.len(), keys.len());
        for snapshot in &snapshots {
            assert!(snapshot.untracked, "{} must be untracked", snapshot.key);
        }
        assert_eq!(limits.bucket_count(), 0, "no bucket for an untracked key");
    }

    #[tokio::test]
    async fn supervisor_sizes_a_path_rule_bucket_from_the_rule() {
        let mut route = legacy_route("r-rule", 20, 5);
        route.path_rules = vec![login_rule(1, 2)];
        let store = store_with(std::slice::from_ref(&route));
        let limits = SupervisorRateLimits::new();
        let rule_key = key_for(&route, "/login", "10.0.0.1");
        let route_key = key_for(&route, "/", "10.0.0.1");
        assert_ne!(rule_key, route_key);

        let snapshots = limits
            .apply_deltas(&[entry(&rule_key, 2), entry(&route_key, 2)], &store, 0)
            .await;
        assert_eq!(snapshots[0].remaining, 0, "rule bucket holds 2");
        assert_eq!(snapshots[1].remaining, 3, "route bucket holds 5");
    }

    #[tokio::test]
    async fn supervisor_reload_invalidation_rereads_the_route() {
        let mut route = legacy_route("r-reload", 20, 5);
        let store = store_with(std::slice::from_ref(&route));
        let limits = SupervisorRateLimits::new();
        let old_key = key_for(&route, "/", "10.0.0.1");
        let snapshots = limits.apply_deltas(&[entry(&old_key, 0)], &store, 0).await;
        assert!(!snapshots[0].untracked);

        route.rate_limit_burst = Some(8);
        store
            .lock()
            .await
            .update_route(&route)
            .expect("update route");
        let new_key = key_for(&route, "/", "10.0.0.1");
        let before = limits.apply_deltas(&[entry(&new_key, 0)], &store, 0).await;
        assert!(
            before[0].untracked,
            "cached policy still describes the old limit"
        );

        limits.invalidate_policies();
        let after = limits.apply_deltas(&[entry(&new_key, 0)], &store, 0).await;
        assert!(!after[0].untracked);
        assert_eq!(after[0].remaining, 8);
    }

    #[tokio::test]
    async fn supervisor_prunes_idle_buckets() {
        let route = legacy_route("r-prune", 20, 5);
        let store = store_with(std::slice::from_ref(&route));
        let limits = SupervisorRateLimits::new();
        let idle = key_for(&route, "/", "10.0.0.1");
        let busy = key_for(&route, "/", "10.0.0.2");
        let ttl = Duration::from_secs(300);
        let ttl_ns = 300_000_000_000;
        limits.apply_deltas(&[entry(&idle, 1)], &store, 0).await;
        limits
            .apply_deltas(&[entry(&busy, 1)], &store, ttl_ns)
            .await;
        limits.prune_idle(ttl_ns + 1, ttl);
        assert_eq!(limits.bucket_count(), 1);
        let snapshots = limits
            .apply_deltas(&[entry(&busy, 0)], &store, ttl_ns + 2)
            .await;
        assert!(!snapshots[0].untracked);
        assert_eq!(
            snapshots[0].remaining, 4,
            "the survivor kept its state; a rebuilt bucket would hold 5"
        );
    }

    fn local_map(entries: &[(&str, u32)]) -> DashMap<String, Arc<LocalBucket>> {
        let map = DashMap::new();
        for (key, capacity) in entries {
            map.insert((*key).to_string(), Arc::new(LocalBucket::new(*capacity, 0)));
        }
        map
    }

    #[test]
    fn sync_batch_carries_depleted_buckets_without_consumption() {
        let buckets = local_map(&[("full", 5), ("drained", 5), ("busy", 5)]);
        let drained = Arc::clone(buckets.get("drained").expect("present").value());
        for _ in 0..5 {
            assert!(drained.try_consume(1, 0));
        }
        assert!(!drained.try_consume(1, 0));
        assert_eq!(drained.take_delta(), 5, "already pushed on an earlier tick");
        drained.refresh(0);
        assert!(buckets.get("busy").expect("present").try_consume(1, 0));

        let mut cursor = 0;
        let mut batch = collect_sync_batch(&buckets, &mut cursor, SYNC_BATCH_MAX_ENTRIES);
        batch.sort_by(|a, b| a.key.cmp(&b.key));
        assert_eq!(
            batch,
            vec![entry("busy", 1), entry("drained", 0)],
            "a full idle bucket stays out, a drained one goes in with nothing consumed"
        );
    }

    #[test]
    fn sync_batch_is_capped_and_rotates_over_every_bucket() {
        let keys: Vec<String> = (0..10).map(|i| format!("k{i}")).collect();
        let buckets = DashMap::new();
        for key in &keys {
            let bucket = Arc::new(LocalBucket::new(3, 0));
            assert!(bucket.try_consume(3, 0));
            bucket.take_delta();
            bucket.refresh(0);
            buckets.insert(key.clone(), bucket);
        }
        let mut cursor = 0;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..3 {
            let batch = collect_sync_batch(&buckets, &mut cursor, 4);
            assert!(batch.len() <= 4);
            seen.extend(batch.into_iter().map(|e| e.key));
        }
        assert_eq!(
            seen.len(),
            keys.len(),
            "three ticks of four cover ten buckets"
        );
    }

    #[test]
    fn sync_reply_refreshes_tracked_and_drops_untracked_buckets() {
        let buckets = local_map(&[("tracked", 5), ("untracked", 5)]);
        for key in ["tracked", "untracked"] {
            let bucket = Arc::clone(buckets.get(key).expect("present").value());
            for _ in 0..5 {
                assert!(bucket.try_consume(1, 0));
            }
            bucket.refresh(0);
        }
        apply_sync_reply(
            &buckets,
            vec![
                RateLimitSnapshot {
                    key: "tracked".to_string(),
                    remaining: 3,
                    untracked: false,
                },
                RateLimitSnapshot {
                    key: "untracked".to_string(),
                    remaining: 0,
                    untracked: true,
                },
            ],
        );
        assert_eq!(buckets.get("tracked").expect("kept").tokens(), 3);
        assert!(
            buckets.get("untracked").is_none(),
            "an untracked key must not stay drained at 0"
        );
    }
}
