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

//! Prometheus metrics endpoint and registry for Lorica.
//!
//! All metrics use bounded label cardinality: route_id (not hostname/path)
//! to prevent OOM from malicious Host headers.

use axum::extract::Extension;
use axum::http::header;
use axum::response::IntoResponse;
use once_cell::sync::Lazy;
use prometheus::{
    Encoder, GaugeVec, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Registry,
    TextEncoder,
};

use crate::server::AppState;

/// Global metrics registry.
static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

/// HTTP request counter. Labels: route_id, status_code.
static HTTP_REQUESTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        prometheus::opts!("http_requests_total", "Total HTTP requests proxied").namespace("lorica"),
        &["route_id", "status_code"],
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// HTTP request latency histogram in seconds. Labels: route_id.
static HTTP_REQUEST_DURATION_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    let histogram = HistogramVec::new(
        HistogramOpts::new(
            "http_request_duration_seconds",
            "HTTP request latency in seconds",
        )
        .namespace("lorica")
        .buckets(vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0,
        ]),
        &["route_id"],
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(histogram.clone())).ok();
    histogram
});

/// Active proxy connections gauge.
static ACTIVE_CONNECTIONS: Lazy<IntGauge> = Lazy::new(|| {
    let gauge = IntGauge::with_opts(
        prometheus::Opts::new(
            "active_connections",
            "Current number of active proxy connections",
        )
        .namespace("lorica"),
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(gauge.clone())).ok();
    gauge
});

/// Backend health status gauge. Labels: backend_id, address. Value: 1=healthy, 0.5=degraded, 0=down.
static BACKEND_HEALTH: Lazy<GaugeVec> = Lazy::new(|| {
    let gauge = GaugeVec::new(
        prometheus::opts!(
            "backend_health",
            "Backend health status (1=healthy, 0.5=degraded, 0=down)"
        )
        .namespace("lorica"),
        &["backend_id", "address"],
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(gauge.clone())).ok();
    gauge
});

/// Certificate days to expiry gauge. Labels: domain.
static CERT_EXPIRY_DAYS: Lazy<GaugeVec> = Lazy::new(|| {
    let gauge = GaugeVec::new(
        prometheus::opts!(
            "certificate_expiry_days",
            "Days until certificate expiration"
        )
        .namespace("lorica"),
        &["domain"],
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(gauge.clone())).ok();
    gauge
});

/// WAF events counter. Labels: category, action (detected/blocked).
static WAF_EVENTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        prometheus::opts!("waf_events_total", "Total WAF events").namespace("lorica"),
        &["category", "action"],
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// AI-bot evaluation counter (Story 8.2 AC #4). Labels: crawler,
/// route_id, action. `action` is one of `deny | log | spoofed |
/// ua_only_match`. Cardinality bound: crawler_count *
/// route_count * 4. The 12+ built-in BUILTIN_CRAWLERS plus the
/// AC #6 server-side cap of 256 custom crawlers gives a worst-case
/// crawler-label dimension of ~268 ; multiplied by routes and 4
/// actions, this stays comfortably below the per-process metric
/// budget. Operator visibility for AI-crawler hits surfaces here.
///
/// `ua_only_match` is an ADDITIONAL signal, not a mutually-exclusive
/// action: for a `UaOnly` crawler it is emitted alongside the policy
/// action, so a single UaOnly request increments BOTH `ua_only_match`
/// AND the policy bucket (`deny` or `log`). The double-count is
/// intentional - it lets an operator see how much of the deny/log
/// volume rests on the unverifiable UA-only signal. Do not sum the
/// four actions expecting the request total.
static AI_BOT_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        prometheus::opts!(
            "ai_bot_total",
            "Total AI / LLM crawler evaluations (deny / log / spoofed / ua_only_match)"
        )
        .namespace("lorica"),
        &["crawler", "route_id", "action"],
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// AI-bot rDNS resolver fail-open counter (Story 8.2 AC #4). No
/// labels: surfaces operator visibility for the path where
/// `bot_rdns::handle()` returns `None` (rDNS disabled at startup,
/// e.g. missing /etc/resolv.conf), so the rDNS verification flow
/// degrades to Allow. Hit count tells the operator how many
/// requests landed on the no-rDNS-substrate path.
static AI_BOT_RDNS_UNAVAILABLE_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let counter = IntCounter::with_opts(
        prometheus::Opts::new(
            "ai_bot_rdns_unavailable_total",
            "AI-bot evaluations that hit the rDNS-resolver-unavailable fail-open path",
        )
        .namespace("lorica"),
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// Counter for custom crawlers skipped on reload (Story 8.2 AC #8
/// tampered-row defense). Labels: reason, one of a small fixed set
/// of buckets: `"regex_compile"` (UA pattern failed to compile),
/// `"cidr_parse"` (a CIDR string in an ip_ranges row was malformed),
/// `"row_decode"` (the lenient store loader could not decode the
/// row: DB/column error, unknown verification_kind, or datetime
/// parse). Surfaces operator visibility for the skip-with-warn path
/// so a corrupt SQLite row never silently disappears from the merged
/// registry.
static AI_BOT_SKIPPED_CUSTOM_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        prometheus::opts!(
            "ai_bot_skipped_custom_total",
            "Custom AI crawlers skipped on reload due to malformed regex or verification_data"
        )
        .namespace("lorica"),
        &["reason"],
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// Increment the `lorica_ai_bot_total{crawler, route_id, action}`
/// counter. Called from the request-filter helpers in
/// `lorica/src/proxy_wiring/filters/ai_bot.rs` at the decision
/// point. `action` MUST be one of the four documented strings
/// (`deny | log | spoofed | ua_only_match`) ; the counter API
/// itself does not constrain that, so the call site enforces.
pub fn record_ai_bot(crawler: &str, route_id: &str, action: &str) {
    AI_BOT_TOTAL
        .with_label_values(&[crawler, route_id, action])
        .inc();
    push_ai_bot_stat(route_id, crawler, action);
}

/// Sliding-window length for the in-process AI-bot stats ring
/// buffer backing `GET /api/v1/ai-crawlers/stats?window=5m`.
const AI_BOT_STATS_WINDOW: std::time::Duration = std::time::Duration::from_secs(300);

/// Per-route hard cap on retained ring-buffer events. Oldest
/// entries are dropped first when a single route exceeds this
/// under a sustained AI-crawler burst, bounding memory regardless
/// of traffic.
const AI_BOT_STATS_MAX_PER_ROUTE: usize = 4096;

/// One AI-bot evaluation recorded in the in-process ring buffer.
struct AiBotStatEvent {
    /// Monotonic insertion instant ; used for 5-minute pruning.
    at: std::time::Instant,
    /// Matched crawler name (built-in or custom).
    crawler: String,
    /// Decision action: `deny | log | spoofed | ua_only_match`.
    action: String,
}

/// In-process 5-minute sliding ring buffer of AI-bot evaluations,
/// keyed by `route_id`. Populated from [`record_ai_bot`] (the same
/// call site the proxy's `check_ai_bot` filter already drives), read
/// by the `/api/v1/ai-crawlers/stats` endpoint.
///
/// WORKERS-MODE LIMITATION : this buffer is per-process. In
/// multi-worker mode `check_ai_bot` runs inside the worker
/// processes while the stats endpoint is served by the supervisor,
/// so the supervisor's buffer reflects ONLY same-process
/// evaluations (e.g. requests the supervisor itself handled, which
/// in a pure worker deployment is none). The authoritative
/// cross-process source is the Prometheus `lorica_ai_bot_total`
/// counter exposed via `/metrics` : the AI-bot counters are shipped
/// from each worker to the supervisor's registry via
/// [`snapshot_per_worker_counters`] / [`apply_worker_generic_counters`]
/// (they are listed in [`PER_WORKER_COUNTERS`]), so `/metrics` is a
/// true cross-process aggregate. The 5-minute buffer here is only an
/// in-process convenience for the top-5 endpoint per Story 8.2 AC #7.
static AI_BOT_STATS_BUFFER: Lazy<
    parking_lot::Mutex<std::collections::HashMap<String, std::collections::VecDeque<AiBotStatEvent>>>,
> = Lazy::new(|| parking_lot::Mutex::new(std::collections::HashMap::new()));

/// Push one AI-bot evaluation into the ring buffer and prune the
/// route's queue (drop entries older than the window, then enforce
/// the per-route cap).
fn push_ai_bot_stat(route_id: &str, crawler: &str, action: &str) {
    let now = std::time::Instant::now();
    let mut map = AI_BOT_STATS_BUFFER.lock();
    let buf = map.entry(route_id.to_string()).or_default();
    buf.push_back(AiBotStatEvent {
        at: now,
        crawler: crawler.to_string(),
        action: action.to_string(),
    });
    prune_ai_bot_buffer(buf, now);
    while buf.len() > AI_BOT_STATS_MAX_PER_ROUTE {
        buf.pop_front();
    }
}

/// Drop ring-buffer entries older than [`AI_BOT_STATS_WINDOW`].
/// Entries are appended in time order so a front-to-back scan stops
/// at the first in-window entry.
fn prune_ai_bot_buffer(
    buf: &mut std::collections::VecDeque<AiBotStatEvent>,
    now: std::time::Instant,
) {
    while let Some(front) = buf.front() {
        if now.duration_since(front.at) > AI_BOT_STATS_WINDOW {
            buf.pop_front();
        } else {
            break;
        }
    }
}

/// Return the `(crawler, action)` pairs recorded for `route_id`
/// within the last 5 minutes, pruning expired entries on the way.
/// Returns an empty vec when the route has no in-window events
/// (including the workers-mode case described on
/// [`AI_BOT_STATS_BUFFER`]).
pub fn ai_bot_window_events(route_id: &str) -> Vec<(String, String)> {
    let now = std::time::Instant::now();
    let mut map = AI_BOT_STATS_BUFFER.lock();
    let Some(buf) = map.get_mut(route_id) else {
        return Vec::new();
    };
    prune_ai_bot_buffer(buf, now);
    buf.iter()
        .map(|e| (e.crawler.clone(), e.action.clone()))
        .collect()
}

/// Test-only helper that clears the AI-bot stats ring buffer so a
/// fresh test starts from an empty window.
#[cfg(test)]
pub fn reset_ai_bot_stats_for_test() {
    AI_BOT_STATS_BUFFER.lock().clear();
}

/// Increment the `lorica_ai_bot_rdns_unavailable_total` counter.
/// Called when `bot_rdns::handle()` returns `None` on a request
/// that would otherwise have walked the Rdns verification path.
pub fn record_ai_bot_rdns_unavailable() {
    AI_BOT_RDNS_UNAVAILABLE_TOTAL.inc();
}

/// Increment the `lorica_ai_bot_skipped_custom_total{reason}`
/// counter. Called inside the merged-registry rebuild whenever a
/// custom-crawler row's pattern fails to compile or its
/// `verification_data` blob fails to parse - the row is dropped
/// and the counter ticks ; valid rows + the entire built-in
/// registry stay operational.
pub fn record_ai_bot_skipped_custom(reason: &str) {
    AI_BOT_SKIPPED_CUSTOM_TOTAL
        .with_label_values(&[reason])
        .inc();
}

/// EWMA latency score per backend (microseconds). Labels: backend_address.
static EWMA_SCORE: Lazy<GaugeVec> = Lazy::new(|| {
    let gauge = GaugeVec::new(
        prometheus::opts!(
            "ewma_score_us",
            "Peak EWMA latency score per backend in microseconds"
        )
        .namespace("lorica"),
        &["backend_address"],
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(gauge.clone())).ok();
    gauge
});

/// Update EWMA score metric for a backend.
pub fn set_ewma_score(address: &str, score_us: f64) {
    EWMA_SCORE.with_label_values(&[address]).set(score_us);
}

/// System CPU usage gauge (0-100).
static SYSTEM_CPU_PERCENT: Lazy<prometheus::Gauge> = Lazy::new(|| {
    let gauge = prometheus::Gauge::with_opts(
        prometheus::Opts::new("system_cpu_percent", "System CPU usage percentage")
            .namespace("lorica"),
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(gauge.clone())).ok();
    gauge
});

/// System memory usage gauge (bytes).
static SYSTEM_MEMORY_USED_BYTES: Lazy<IntGauge> = Lazy::new(|| {
    let gauge = IntGauge::with_opts(
        prometheus::Opts::new("system_memory_used_bytes", "System memory used in bytes")
            .namespace("lorica"),
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(gauge.clone())).ok();
    gauge
});

/// Record an HTTP request in the metrics.
///
/// Uses `itoa::Buffer` instead of `status_code.to_string()` so the
/// per-request hot path doesn't allocate a 3-char `String` for a
/// label that's always `100..=599`. Mirrors the existing itoa usage
/// in `proxy_wiring.rs` for header rule indices (audit M-15).
pub fn record_request(route_id: &str, status_code: u16, latency_seconds: f64) {
    let mut status_buf = itoa::Buffer::new();
    let status_str = status_buf.format(status_code);
    HTTP_REQUESTS_TOTAL
        .with_label_values(&[route_id, status_str])
        .inc();
    HTTP_REQUEST_DURATION_SECONDS
        .with_label_values(&[route_id])
        .observe(latency_seconds);
}

/// Update the active connections gauge.
pub fn set_active_connections(count: i64) {
    ACTIVE_CONNECTIONS.set(count);
}

/// Update backend health metric.
pub fn set_backend_health(backend_id: &str, address: &str, health: f64) {
    BACKEND_HEALTH
        .with_label_values(&[backend_id, address])
        .set(health);
}

/// Update certificate expiry metric.
pub fn set_cert_expiry_days(domain: &str, days: f64) {
    CERT_EXPIRY_DAYS.with_label_values(&[domain]).set(days);
}

/// Record a WAF event.
pub fn record_waf_event(category: &str, action: &str) {
    WAF_EVENTS_TOTAL
        .with_label_values(&[category, action])
        .inc();
}

/// Update system resource metrics.
pub fn set_system_metrics(cpu_percent: f64, memory_used_bytes: i64) {
    SYSTEM_CPU_PERCENT.set(cpu_percent);
    SYSTEM_MEMORY_USED_BYTES.set(memory_used_bytes);
}

// ---- v1.3.0 feature counters ---------------------------------------------
//
// All four counters share a small design rule: label cardinality must
// stay bounded so a Prometheus scrape doesn't explode under hostile
// or accidental traffic. Route ids are stable, operator-controlled
// strings. No user-input-derived label is added.

/// Cache predictor bypass counter. Increments each time the predictor
/// short-circuits the cache state machine because a prior origin
/// response marked the key as uncacheable.
/// Labels: `route_id` (bounded by the number of configured routes).
static CACHE_PREDICTOR_BYPASS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        prometheus::opts!(
            "cache_predictor_bypass_total",
            "Times the cache predictor short-circuited a request as uncacheable"
        )
        .namespace("lorica"),
        &["route_id"],
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// Record a cache-predictor bypass for a route.
pub fn inc_cache_predictor_bypass(route_id: &str) {
    CACHE_PREDICTOR_BYPASS_TOTAL
        .with_label_values(&[route_id])
        .inc();
}

/// Header-routing rule match counter. Increments each time a header
/// rule selected a backend override. A separate label "fallthrough"
/// is recorded when no rule matched, so operators can compare
/// matched vs. default traffic without a second metric.
/// Labels: `route_id`, `rule_index` (or `"default"` for fallthrough).
static HEADER_RULE_MATCH_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        prometheus::opts!(
            "header_rule_match_total",
            "Header-based routing rule matches (rule_index=\"default\" when no rule matched)"
        )
        .namespace("lorica"),
        &["route_id", "rule_index"],
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// Record a header-routing rule match. Pass `"default"` as rule_index
/// when no rule matched.
pub fn inc_header_rule_match(route_id: &str, rule_index: &str) {
    HEADER_RULE_MATCH_TOTAL
        .with_label_values(&[route_id, rule_index])
        .inc();
}

/// Canary traffic-split selection counter. `split_name` is the name
/// the operator gave the split (or `""` for unnamed; `"default"` for
/// the "didn't hit any split" bucket).
/// Labels: `route_id`, `split_name`.
static CANARY_SPLIT_SELECTED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        prometheus::opts!(
            "canary_split_selected_total",
            "Canary traffic split selections (split_name=\"default\" when no split matched)"
        )
        .namespace("lorica"),
        &["route_id", "split_name"],
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// Record a canary-split selection. Pass `"default"` as split_name
/// when no split matched.
pub fn inc_canary_split_selected(route_id: &str, split_name: &str) {
    CANARY_SPLIT_SELECTED_TOTAL
        .with_label_values(&[route_id, split_name])
        .inc();
}

/// Request-mirroring outcome counter. Three outcomes:
/// - `"spawned"`: mirror sub-request was launched
/// - `"dropped_saturated"`: dropped because the 256-slot semaphore
///   was exhausted (shadow fleet overloaded)
/// - `"dropped_oversize_body"`: dropped because request body
///   exceeded `max_body_bytes`
///
/// Labels: `route_id`, `outcome`.
static MIRROR_OUTCOME_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        prometheus::opts!(
            "mirror_outcome_total",
            "Request-mirroring sub-request outcomes per route"
        )
        .namespace("lorica"),
        &["route_id", "outcome"],
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// Record a mirror outcome.
pub fn inc_mirror_outcome(route_id: &str, outcome: &str) {
    MIRROR_OUTCOME_TOTAL
        .with_label_values(&[route_id, outcome])
        .inc();
}

/// Forward-auth verdict-cache hit/miss counter. `"hit"` means we
/// served a cached Allow verdict without calling the auth service;
/// `"miss"` means we made the sub-request. Labels: `route_id`,
/// `outcome` ("hit" | "miss").
static FORWARD_AUTH_CACHE_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        prometheus::opts!(
            "forward_auth_cache_total",
            "Forward-auth verdict cache lookups (outcome=hit|miss)"
        )
        .namespace("lorica"),
        &["route_id", "outcome"],
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// Record a forward-auth verdict cache lookup outcome.
pub fn inc_forward_auth_cache(route_id: &str, outcome: &str) {
    FORWARD_AUTH_CACHE_TOTAL
        .with_label_values(&[route_id, outcome])
        .inc();
}

/// Counter: GeoIP-filter rejections per route. Labels:
/// - `route_id`: bounded by number of configured routes.
/// - `country`: ISO 3166-1 alpha-2 (bounded ~240).
/// - `mode`: "allowlist" | "denylist".
///
/// Cardinality bound: routes * countries * 2, well within Prometheus
/// comfort envelope on any sensible deployment. A route with no
/// GeoIP config never increments this counter.
static GEOIP_BLOCK_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        prometheus::opts!(
            "geoip_block_total",
            "GeoIP-filter blocks (country=ISO3166 alpha-2, mode=allowlist|denylist)"
        )
        .namespace("lorica"),
        &["route_id", "country", "mode"],
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// Record a GeoIP filter rejection. Called from the proxy request
/// filter when a country mismatches the per-route
/// `Allowlist` / `Denylist` rule and Lorica returns 403.
pub fn inc_geoip_block(route_id: &str, country: &str, mode: &str) {
    GEOIP_BLOCK_TOTAL
        .with_label_values(&[route_id, country, mode])
        .inc();
}

/// Counter: bot-protection challenge outcomes per route (v1.4.0
/// Epic 3 story 3.7). Labels:
/// - `route_id`: bounded by the number of configured routes.
/// - `mode`: `"cookie"` / `"javascript"` / `"captcha"` (the mode
///   the route was configured with at the time of the event).
/// - `outcome`: `"shown"` (challenge page served), `"passed"`
///   (verdict cookie verified OR solve succeeded), `"failed"`
///   (wrong PoW / captcha answer, or cookie scope mismatch), or
///   `"bypassed"` (one of the five bypass categories matched —
///   detail carried on the OTel span, not the metric).
///
/// Cardinality bound: routes × 3 modes × 4 outcomes, well inside
/// Prometheus comfort on any plausible deployment. Routes without
/// `bot_protection` configured never touch this counter.
static BOT_CHALLENGE_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        prometheus::opts!(
            "bot_challenge_total",
            "Bot-protection challenge outcomes (outcome=shown|passed|failed|bypassed)"
        )
        .namespace("lorica"),
        &["route_id", "mode", "outcome"],
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// Record one bot-protection challenge outcome. Called from the
/// proxy request filter on every bot-protection decision that
/// reaches a terminal state: pass, challenge render, or verify
/// result.
pub fn inc_bot_challenge(route_id: &str, mode: &str, outcome: &str) {
    BOT_CHALLENGE_TOTAL
        .with_label_values(&[route_id, mode, outcome])
        .inc();
}

// ---------------------------------------------------------------------------
// Cross-worker counter aggregation (v1.4.0 follow-up).
//
// In worker mode, each of the `IntCounterVec` statics above lives
// in the worker process that incremented it. The supervisor's
// `/metrics` handler scrapes the supervisor's own registry — which
// does NOT see worker-side increments for these counters because
// the existing `MetricsReport` wire format only carries the typed
// fields (cache_hits, active_connections, per-route request counts,
// WAF counts).
//
// The helpers below let a worker serialise a snapshot of the
// per-worker counters into `Vec<GenericCounterEntry>` (cheap: iter
// the `IntCounterVec::get_metric_with_label_values`-style family
// readback via `prometheus::core::Collector::collect()`), and let
// the supervisor apply that snapshot to its OWN registry — keyed
// per-worker so successive scrapes replace instead of double-count.
//
// The supervisor's apply path does not just `inc_by` — that would
// double-count on the second scrape. Instead it tracks per-worker
// snapshots (worker_id -> metric_name -> label_tuple -> value) and
// on every apply it computes the delta to reach the new value; if
// a worker resets or drops out, the delta goes negative and the
// counter stays where it is (prometheus counters cannot decrement).
// ---------------------------------------------------------------------------

/// Names of the per-worker counter vecs whose deltas ship on the
/// wire. Kept as a const array so worker snapshot and supervisor
/// apply look at the same list — a counter added here without
/// being added to both snapshot + apply logic will simply not
/// aggregate.
pub const PER_WORKER_COUNTERS: &[&str] = &[
    "lorica_cache_predictor_bypass_total",
    "lorica_header_rule_match_total",
    "lorica_canary_split_selected_total",
    "lorica_mirror_outcome_total",
    "lorica_forward_auth_cache_total",
    "lorica_geoip_block_total",
    "lorica_bot_challenge_total",
    // AI-bot counters (Story 8.2). In worker mode check_ai_bot /
    // rebuild run in the workers, so without shipping these the
    // supervisor's /metrics never sees worker-side AI-bot activity -
    // which the stats doc claims is the cross-process source of truth.
    "lorica_ai_bot_total",
    "lorica_ai_bot_skipped_custom_total",
    "lorica_ai_bot_rdns_unavailable_total",
];

/// One generic counter entry at the lorica-api boundary.
/// `(metric_name, label_NAME_value_pairs, value)`. The lorica
/// binary translates between this tuple and the
/// `lorica_command::GenericCounterEntry` wire type — this crate
/// stays free of the lorica-command dep.
///
/// Labels are name=value pairs (not positional values) because
/// `prometheus::Metric::get_label()` returns them in ALPHABETICAL
/// order, not registration order. At apply time the supervisor
/// looks up each metric's registered label-name list and builds
/// the positional `with_label_values` slice from there.
pub type GenericCounterTuple = (String, Vec<(String, String)>, u64);

/// Snapshot every per-worker counter. Called on every
/// metrics-report tick by the worker. Returns an empty vec when no
/// counter has ever incremented on this worker (all vecs are lazy
/// — they only allocate label sets on first `inc`).
pub fn snapshot_per_worker_counters() -> Vec<GenericCounterTuple> {
    use prometheus::core::Collector;

    let vecs: [(&str, &IntCounterVec); 9] = [
        (
            "lorica_cache_predictor_bypass_total",
            &CACHE_PREDICTOR_BYPASS_TOTAL,
        ),
        ("lorica_header_rule_match_total", &HEADER_RULE_MATCH_TOTAL),
        (
            "lorica_canary_split_selected_total",
            &CANARY_SPLIT_SELECTED_TOTAL,
        ),
        ("lorica_mirror_outcome_total", &MIRROR_OUTCOME_TOTAL),
        ("lorica_forward_auth_cache_total", &FORWARD_AUTH_CACHE_TOTAL),
        ("lorica_geoip_block_total", &GEOIP_BLOCK_TOTAL),
        ("lorica_bot_challenge_total", &BOT_CHALLENGE_TOTAL),
        ("lorica_ai_bot_total", &AI_BOT_TOTAL),
        (
            "lorica_ai_bot_skipped_custom_total",
            &AI_BOT_SKIPPED_CUSTOM_TOTAL,
        ),
    ];

    let mut out = Vec::new();
    for (name, vec) in vecs {
        // `Collector::collect()` returns an owned one-element
        // `Vec<MetricFamily>` by API contract (prometheus 0.14
        // `vec![self.v.collect()]`); the vec internals are
        // pub(crate), so there is no buffer-reuse readback path.
        // The small Vec allocations per tick live inside the
        // prometheus crate and cannot be hoisted out (backlog #41g).
        let families = vec.collect();
        for mf in families {
            for m in mf.get_metric() {
                // Carry label name=value pairs on the wire so the
                // supervisor can rebuild positional ordering using
                // the target vec's registered label names.
                // `get_label` returns pairs in alphabetical order,
                // which is NOT the registration order.
                let labels: Vec<(String, String)> = m
                    .get_label()
                    .iter()
                    .map(|l| (l.name().to_string(), l.value().to_string()))
                    .collect();
                let value = m.get_counter().value() as u64;
                if value > 0 {
                    out.push((name.to_string(), labels, value));
                }
            }
        }
    }

    // The rDNS-unavailable counter is a label-less `IntCounter`, not
    // an `IntCounterVec`, so it cannot live in the `vecs` array. Snap
    // it on its own with an empty label set ; the supervisor apply
    // path resolves it to a scalar target.
    let rdns_unavailable = AI_BOT_RDNS_UNAVAILABLE_TOTAL.get();
    if rdns_unavailable > 0 {
        out.push((
            "lorica_ai_bot_rdns_unavailable_total".to_string(),
            Vec::new(),
            rdns_unavailable,
        ));
    }
    out
}

/// Supervisor-side snapshot: worker_id -> metric_name ->
/// label_key -> last-known-value. Stored alongside the typed
/// per-worker fields in `AggregatedMetrics`.
type PerWorkerCounterSnapshot =
    std::collections::HashMap<String, std::collections::HashMap<String, u64>>;

static SUPERVISOR_GENERIC_SNAPSHOT: Lazy<
    parking_lot::RwLock<std::collections::HashMap<u32, PerWorkerCounterSnapshot>>,
> = Lazy::new(|| parking_lot::RwLock::new(std::collections::HashMap::new()));

/// Apply a worker's generic-counter snapshot to the supervisor's
/// own metrics registry. Called from the supervisor's
/// `MetricsReport` ingress. The supervisor's vec (same
/// `IntCounterVec` statics declared above — the `lorica-api`
/// crate is linked into both worker and supervisor binaries)
/// receives a POSITIVE delta only: a dropped worker's state stays
/// in the last scrape until another `MetricsReport` arrives or a
/// `forget_worker` call removes it.
pub fn apply_worker_generic_counters(worker_id: u32, entries: &[GenericCounterTuple]) {
    // Registered label order for each per-worker counter vec.
    // MUST match the `&[...]` passed to `IntCounterVec::new` at
    // the corresponding `Lazy::new` above. The apply path walks
    // this list to reorder name=value pairs from the wire into
    // positional arguments for `with_label_values`.
    fn label_names(metric: &str) -> Option<&'static [&'static str]> {
        match metric {
            "lorica_cache_predictor_bypass_total" => Some(&["route_id"]),
            "lorica_header_rule_match_total" => Some(&["route_id", "rule_index"]),
            "lorica_canary_split_selected_total" => Some(&["route_id", "split_name"]),
            "lorica_mirror_outcome_total" => Some(&["route_id", "outcome"]),
            "lorica_forward_auth_cache_total" => Some(&["route_id", "outcome"]),
            "lorica_geoip_block_total" => Some(&["route_id", "country", "mode"]),
            "lorica_bot_challenge_total" => Some(&["route_id", "mode", "outcome"]),
            "lorica_ai_bot_total" => Some(&["crawler", "route_id", "action"]),
            "lorica_ai_bot_skipped_custom_total" => Some(&["reason"]),
            // Label-less scalar : empty registered-order list.
            "lorica_ai_bot_rdns_unavailable_total" => Some(&[]),
            _ => None,
        }
    }

    fn key_from_positional(values: &[String]) -> String {
        values.join("\0")
    }

    /// Where a resolved wire entry applies on the supervisor side:
    /// a labelled `IntCounterVec` or a label-less scalar `IntCounter`
    /// (the rDNS-unavailable counter). References are `Copy`.
    #[derive(Clone, Copy)]
    enum CounterTarget {
        Vec(&'static IntCounterVec),
        Scalar(&'static IntCounter),
    }

    /// One wire entry fully resolved before the snapshot lock is
    /// taken: owned key strings plus the target supervisor-side
    /// counter.
    struct PreparedEntry {
        metric_name: String,
        label_key: String,
        positional: Vec<String>,
        value: u64,
        target: CounterTarget,
    }

    // Phase 1 - no lock held. Resolve the label order, build the
    // positional values and the snapshot key, and bind the target
    // vec for every wire entry. All string allocation happens here
    // so the write lock below covers hashmap delta math only,
    // instead of the whole apply loop. Holding the global lock
    // across the full loop serialized every apply, and /metrics
    // scrapes funnel through apply via the pull-on-scrape
    // refresher, so they stalled behind it too (backlog #41g).
    let mut prepared: Vec<PreparedEntry> = Vec::with_capacity(entries.len());
    for (name, label_pairs, value) in entries {
        let Some(order) = label_names(name) else {
            continue;
        };
        let target: CounterTarget = match name.as_str() {
            "lorica_cache_predictor_bypass_total" => {
                CounterTarget::Vec(&CACHE_PREDICTOR_BYPASS_TOTAL)
            }
            "lorica_header_rule_match_total" => CounterTarget::Vec(&HEADER_RULE_MATCH_TOTAL),
            "lorica_canary_split_selected_total" => {
                CounterTarget::Vec(&CANARY_SPLIT_SELECTED_TOTAL)
            }
            "lorica_mirror_outcome_total" => CounterTarget::Vec(&MIRROR_OUTCOME_TOTAL),
            "lorica_forward_auth_cache_total" => CounterTarget::Vec(&FORWARD_AUTH_CACHE_TOTAL),
            "lorica_geoip_block_total" => CounterTarget::Vec(&GEOIP_BLOCK_TOTAL),
            "lorica_bot_challenge_total" => CounterTarget::Vec(&BOT_CHALLENGE_TOTAL),
            "lorica_ai_bot_total" => CounterTarget::Vec(&AI_BOT_TOTAL),
            "lorica_ai_bot_skipped_custom_total" => {
                CounterTarget::Vec(&AI_BOT_SKIPPED_CUSTOM_TOTAL)
            }
            "lorica_ai_bot_rdns_unavailable_total" => {
                CounterTarget::Scalar(&AI_BOT_RDNS_UNAVAILABLE_TOTAL)
            }
            _ => continue,
        };
        // Reorder name=value pairs into positional values matching
        // the registered order. Missing names get an empty string
        // (the registered vec never accepts empty labels, so this
        // will fail the `get_metric_with_label_values` check in
        // phase 3 and be skipped - safe default).
        let mut positional: Vec<String> = Vec::with_capacity(order.len());
        for expected in order {
            let v = label_pairs
                .iter()
                .find(|(n, _)| n.as_str() == *expected)
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            positional.push(v);
        }
        let label_key = key_from_positional(&positional);
        prepared.push(PreparedEntry {
            metric_name: name.clone(),
            label_key,
            positional,
            value: *value,
            target,
        });
    }

    // Phase 2 - tight critical section. Compute per-label deltas
    // against the worker's last-known snapshot and record the new
    // values: HashMap moves and u64 math only, no string building
    // and no prometheus calls under the lock. Note this MERGES
    // into the existing worker state rather than swapping it out
    // wholesale - a label combo absent from this report keeps its
    // previous value, otherwise the next report carrying it again
    // would re-apply the full count as a fresh delta.
    let mut to_apply: Vec<(CounterTarget, Vec<String>, u64)> = Vec::with_capacity(prepared.len());
    {
        let mut map = SUPERVISOR_GENERIC_SNAPSHOT.write();
        let worker_state = map.entry(worker_id).or_default();
        for entry in prepared {
            let metric_state = worker_state.entry(entry.metric_name).or_default();
            let prev = metric_state.get(&entry.label_key).copied().unwrap_or(0);
            if entry.value <= prev {
                continue;
            }
            let delta = entry.value - prev;
            metric_state.insert(entry.label_key, entry.value);
            to_apply.push((entry.target, entry.positional, delta));
        }
    }

    // Phase 3 - no lock held. Counter increments are atomic and the
    // deltas were computed atomically in phase 2, so interleaving
    // with a concurrent apply still converges to the same sums.
    for (target, positional, delta) in to_apply {
        match target {
            CounterTarget::Vec(vec) => {
                let label_refs: Vec<&str> = positional.iter().map(|s| s.as_str()).collect();
                if vec.get_metric_with_label_values(&label_refs).is_ok() {
                    vec.with_label_values(&label_refs).inc_by(delta);
                }
            }
            // Label-less scalar : no label-arity guard needed.
            CounterTarget::Scalar(counter) => counter.inc_by(delta),
        }
    }
}

/// Drop a worker's snapshot on the supervisor side. Called when
/// the supervisor detects a dead worker (RPC channel gone, crash
/// signalled). Without this, the supervisor would keep the last-
/// known counter values forever, skewing the aggregate.
pub fn forget_worker_generic_counters(worker_id: u32) {
    SUPERVISOR_GENERIC_SNAPSHOT.write().remove(&worker_id);
}

/// Test-only helper that wipes the supervisor's generic-counter
/// snapshot so a fresh test starts from zero.
#[cfg(test)]
pub fn reset_generic_counter_snapshot_for_test() {
    SUPERVISOR_GENERIC_SNAPSHOT.write().clear();
}

/// Counter: notification events dropped by the bounded broadcast
/// channel, labeled by drop reason (`lag` = subscriber fell behind,
/// `closed` = channel closed). Bounded-cardinality: only two labels.
static NOTIFIER_EVENTS_DROPPED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        prometheus::opts!(
            "notifier_events_dropped_total",
            "Alert events dropped by the notifier broadcast channel (reason=lag|closed)"
        )
        .namespace("lorica"),
        &["reason"],
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// Record one or more dropped notification events.
pub fn inc_notifier_events_dropped(reason: &str, count: u64) {
    NOTIFIER_EVENTS_DROPPED_TOTAL
        .with_label_values(&[reason])
        .inc_by(count);
}

/// Counter: log writes dropped because the background log writer
/// queue was full (backlog #24). Non-zero values mean the SQLite
/// writer cannot keep up with sustained request volume; the proxy
/// keeps serving and sheds forensics rows instead of latency.
static LOG_WRITE_DROPPED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        prometheus::opts!(
            "log_write_dropped_total",
            "Access-log entries and WAF events dropped on log-writer queue overflow (kind=access|waf)"
        )
        .namespace("lorica"),
        &["kind"],
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// Bump the dropped-log-write counter for `kind` (`"access"` or `"waf"`).
pub fn inc_log_write_dropped(kind: &str) {
    LOG_WRITE_DROPPED_TOTAL.with_label_values(&[kind]).inc();
}

/// Counter: log-stream WebSocket entries dropped because a
/// subscriber lagged the bounded broadcast channel (v1.5.0 audit
/// LOW-12 backpressure). Non-zero values signal a slow client (or
/// a client blocked at the kernel send buffer). The WebSocket
/// handler also closes the connection with WS close code 1008
/// (Policy Violation) once the per-connection drop count exceeds
/// `LOG_WS_CLOSE_ON_DROPS`, protecting Lorica from stuck-client
/// backpressure amplification.
static LOGS_WS_DROPPED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        prometheus::opts!(
            "logs_ws_dropped_total",
            "Log entries dropped by a WebSocket subscriber (reason=slow_client|closed)"
        )
        .namespace("lorica"),
        &["reason"],
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// Record one or more dropped log-stream WebSocket entries.
pub fn inc_logs_ws_dropped(reason: &str, count: u64) {
    LOGS_WS_DROPPED_TOTAL
        .with_label_values(&[reason])
        .inc_by(count);
}

/// Counter: WAF event persistence failures (v1.5.1 audit L-6).
///
/// Bumped each time the proxy hot path tries to persist a
/// `WafEvent` to the SQLite-backed `LogStore` and the call
/// returns `Err`. Pre-fix, every call site swallowed the result
/// with `let _ = ...` so a full disk / corrupted DB / schema
/// mismatch silently dropped events without an operator signal.
/// The companion log line at `tracing::warn!` carries the
/// underlying error string + the rule id / category so the
/// counter is "is the persistence working ?" and the log line
/// is "what failed". Non-zero values warrant investigation -
/// the proxy keeps running (events still flow through the
/// in-memory ring buffer + Prometheus categories), but the
/// persistent forensics trail is broken.
static WAF_EVENT_PERSIST_FAILED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let counter = IntCounter::with_opts(
        prometheus::opts!(
            "waf_event_persist_failed_total",
            "WAF events the proxy could not persist to the LogStore"
        )
        .namespace("lorica"),
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// Bump the WAF-event-persistence-failed counter by one.
///
/// Called from `LoricaProxy::persist_waf_event` whenever a
/// `LogStore::insert_waf_event` call returns `Err`.
pub fn inc_waf_event_persist_failed() {
    WAF_EVENT_PERSIST_FAILED_TOTAL.inc();
}

/// Counter: BanIp commands dropped by the supervisor -> worker
/// broadcast channel when a worker subscriber falls behind the
/// bounded queue. Non-zero values signal that the ban channel
/// capacity is too small for the ban burst rate or that a worker
/// is stuck long enough to lag the channel. The auto-ban logic
/// self-heals on subsequent WAF events + the next `ConfigReload`
/// picks up the persisted state, so this is observability, not a
/// correctness crisis.
static BAN_BROADCAST_LAGGED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        prometheus::opts!(
            "ban_broadcast_lagged_total",
            "BanIp commands missed by a worker subscriber due to broadcast channel lag"
        )
        .namespace("lorica"),
        &["worker_id"],
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// Counter: pipelined-RPC outcomes on the supervisor-to-worker
/// channel. Labels: `kind` (`metrics_pull` | `config_reload_abort` |
/// `config_reload_prepare` | `config_reload_commit`) and `outcome`
/// (`ok` | `timeout` | `error`). Use this to spot a worker that
/// consistently times out or errors on one RPC type while healthy
/// on others (e.g. a long-running config rebuild stalling Prepare
/// but leaving metrics pull responsive).
///
/// Non-zero `timeout` on `config_reload_prepare` usually means DB
/// contention or a pathological config payload; non-zero `timeout`
/// on `metrics_pull` means a worker is stuck past the 500 ms per-
/// worker budget.
static SUPERVISOR_RPC_OUTCOME_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        prometheus::opts!(
            "supervisor_rpc_outcome_total",
            "Outcome of supervisor -> worker pipelined RPCs, by kind and result"
        )
        .namespace("lorica"),
        &["kind", "outcome"],
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// Record the outcome of a supervisor-initiated RPC. `kind` is the
/// logical operation (`metrics_pull`, `config_reload_prepare`,
/// `config_reload_commit`, `config_reload_abort`) and `outcome` is
/// one of `ok`, `timeout`, `error`. Safe to call from any async
/// context (counter ops are lock-free).
pub fn inc_supervisor_rpc_outcome(kind: &str, outcome: &str) {
    SUPERVISOR_RPC_OUTCOME_TOTAL
        .with_label_values(&[kind, outcome])
        .inc();
}

/// Record one or more BanIp commands lagged on a given worker's
/// broadcast subscription. `count` is the number of missed messages
/// reported by `RecvError::Lagged(n)`.
pub fn inc_ban_broadcast_lagged(worker_id: &str, count: u64) {
    BAN_BROADCAST_LAGGED_TOTAL
        .with_label_values(&[worker_id])
        .inc_by(count);
}

/// Counter: ConfigReload broadcast messages missed by a worker
/// subscriber due to channel-capacity overflow. Same shape as
/// `ban_broadcast_lagged_total` ; non-zero means the legacy reload
/// broadcast (used as fallback when the two-phase RPC fails) lost
/// reload notifications faster than the worker could consume them.
/// The supervisor catches up by re-issuing a single ConfigReload on
/// the next iteration so the worker reaches the latest DB state, but
/// individual `seq` numbers are dropped on the floor (audit C-2).
static RELOAD_BROADCAST_LAGGED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        prometheus::opts!(
            "reload_broadcast_lagged_total",
            "ConfigReload broadcast messages missed by a worker subscriber due to channel lag"
        )
        .namespace("lorica"),
        &["worker_id"],
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// Record one or more ConfigReload broadcast messages lagged on a
/// given worker's subscription.
pub fn inc_reload_broadcast_lagged(worker_id: &str, count: u64) {
    RELOAD_BROADCAST_LAGGED_TOTAL
        .with_label_values(&[worker_id])
        .inc_by(count);
}

/// Counter: per-process resolver hooks (`apply_geoip` / `apply_asn`
/// / `apply_otel` / `apply_bot_secret`) that failed to apply because
/// the store fetch returned `Err`. Non-zero values pin the matching
/// resolver state at whatever was last applied successfully and are
/// only recoverable by the next successful settings read - so a
/// transient SQLite error during a `.mmdb` autoupdate cycle would
/// otherwise freeze the resolver for the lifetime of the process
/// without any operator-visible signal (audit M-19).
static RESOLVER_APPLY_FAILED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        prometheus::opts!(
            "resolver_apply_failed_total",
            "Per-process resolver hook failed to apply settings (store fetch error)"
        )
        .namespace("lorica"),
        &["kind"],
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// Record one resolver-apply failure. `kind` is one of `geoip`,
/// `asn`, `otel`, `bot_secret`.
pub fn inc_resolver_apply_failed(kind: &str) {
    RESOLVER_APPLY_FAILED_TOTAL.with_label_values(&[kind]).inc();
}

/// Counter: bot verdict cross-worker propagation RPCs (worker ->
/// supervisor verdict cache push) that failed. Bot cache propagation
/// is fire-and-forget (the local worker is already populated, so a
/// failure only delays cross-worker sharing) but a non-zero rate
/// flags a stuck supervisor RPC channel and was previously a silent
/// `let _ = endpoint.request_rpc(...).await` swallow (audit L-14).
static BOT_VERDICT_PUSH_FAILED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let counter = IntCounter::new(
        "lorica_bot_verdict_push_failed_total",
        "Bot verdict cross-worker propagation RPCs (worker -> supervisor) that failed",
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// Record one bot-verdict-push RPC failure.
pub fn inc_bot_verdict_push_failed() {
    BOT_VERDICT_PUSH_FAILED_TOTAL.inc();
}

/// Counter: certificate bundles rejected as invalid (v1.5.3).
///
/// Bumped when a cert+key bundle fails the `CertifiedKey::keys_match`
/// SPKI-consistency check or fails to parse altogether. Two label
/// values exposed so operators can alert on each independently :
///
/// - `source="upload"` : the API gate (`POST /certificates`,
///   `PUT /certificates/{id}`, `POST /config/import`) rejected an
///   incoming bundle. Steady-state 0 ; non-zero is informational
///   (someone tried a paste error and the API caught it - no fleet
///   impact, no row in the DB).
///
/// - `source="reload"` : the worker-side `cert_resolver::reload`
///   skipped a row that was already in the DB (legacy v1.5.2 row,
///   row written outside the API gate, or a row that stopped
///   loading after a future schema change). Non-zero is alertable :
///   that domain is currently NOT served by TLS termination on the
///   affected worker, the `journalctl` per-row WARN names the
///   specific domain.
///
/// Bounded cardinality : two label values, no operator-controlled
/// or user-controlled string in the label set.
static CERTIFICATES_INVALID_BUNDLE_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        prometheus::opts!(
            "certificates_invalid_bundle_total",
            "Certificate bundles rejected as invalid (source=upload|reload)"
        )
        .namespace("lorica"),
        &["source"],
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// Bump the invalid-bundle counter by one. `source` must be either
/// `"upload"` (API gate rejection) or `"reload"` (worker resolver
/// skipped a row). Other values are accepted but waste cardinality.
pub fn inc_certificates_invalid_bundle(source: &str) {
    CERTIFICATES_INVALID_BUNDLE_TOTAL
        .with_label_values(&[source])
        .inc();
}

/// Bump the invalid-bundle counter by `count` for a given source.
/// Used by the worker boot / reload path which reports the skipped
/// total for one batch in a single call rather than N inc's.
pub fn inc_certificates_invalid_bundle_by(source: &str, count: u64) {
    if count == 0 {
        return;
    }
    CERTIFICATES_INVALID_BUNDLE_TOTAL
        .with_label_values(&[source])
        .inc_by(count);
}

/// Counter: two-phase config reload rounds where the Commit phase
/// partially succeeded - some workers committed, others failed
/// (timeout / error). The supervisor coordinator falls back to the
/// legacy broadcast which makes the failed workers re-do the work
/// via the legacy ConfigReload handler ; in the interim the fleet
/// is split (different workers serving different generations of the
/// config). Audit M-17 ; non-zero values flag a real fleet-coherence
/// gap that operators need to know about even though the system
/// self-heals on the next reload.
static CONFIG_RELOAD_SPLIT_FLEET_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let counter = IntCounter::new(
        "lorica_config_reload_split_fleet_total",
        "Config reload commits where some workers committed and others failed (transient fleet split)",
    )
    .expect("prometheus metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// Record one config-reload split-fleet event.
pub fn inc_config_reload_split_fleet() {
    CONFIG_RELOAD_SPLIT_FLEET_TOTAL.inc();
}

/// GET /metrics - Prometheus scrape endpoint.
///
/// Refreshes dynamic gauges (active connections, backend health, cert expiry,
/// system resources) from AppState before encoding.
///
/// In worker mode, first invokes the pipelined `metrics_refresher`
/// (WPAR-7) so per-worker counters are pulled fresh over the RPC
/// channel before the scrape encodes them. The refresher dedups
/// concurrent scrapes internally and has a bounded per-worker
/// timeout, so an unresponsive worker cannot stall a Prometheus poll.
/// A conservative wall-clock timeout (~`refresher budget + margin`)
/// wraps the whole invocation in case the refresher hangs on a
/// supervisor-side lock - we never want /metrics to be the slowest
/// thing a Prometheus scrape waits on.
pub async fn get_metrics(Extension(state): Extension<AppState>) -> impl IntoResponse {
    // WPAR-7 pull-on-scrape: refresh aggregated counters before reading.
    // Wall-clock budget = per-worker timeout (500 ms) + generous margin
    // for scheduling overhead. On timeout we keep the cached state so
    // the scrape still returns something useful.
    if let Some(ref refresher) = state.metrics_refresher {
        let _ = tokio::time::timeout(std::time::Duration::from_millis(1_000), refresher()).await;
    }

    // Refresh active connections (aggregated from workers if available)
    let active_conns = if let Some(ref agg) = state.aggregated_metrics {
        agg.total_active_connections().await as i64
    } else {
        state
            .active_connections
            .load(std::sync::atomic::Ordering::Relaxed) as i64
    };
    set_active_connections(active_conns);

    // Refresh aggregated EWMA scores from workers
    if let Some(ref agg) = state.aggregated_metrics {
        for (addr, score) in agg.merged_ewma_scores().await {
            set_ewma_score(&addr, score);
        }
    }

    // Refresh backend health and cert expiry from the store
    if let Ok(store) = state.store.try_lock() {
        if let Ok(backends) = store.list_backends() {
            for b in &backends {
                let health_val = match b.health_status {
                    lorica_config::models::HealthStatus::Healthy => 1.0,
                    lorica_config::models::HealthStatus::Degraded => 0.5,
                    lorica_config::models::HealthStatus::Down => 0.0,
                    lorica_config::models::HealthStatus::Unknown => -1.0,
                };
                set_backend_health(&b.id, &b.address, health_val);
            }
        }
        if let Ok(certs) = store.list_certificates() {
            for c in &certs {
                let days = (c.not_after - chrono::Utc::now()).num_days() as f64;
                set_cert_expiry_days(&c.domain, days);
            }
        }
    }

    // Refresh system metrics. `sys_cache.refresh()` is sync I/O on
    // /proc (CPU, memory, process) that takes tens of milliseconds
    // on a busy box. Use `tokio::task::block_in_place` so the current
    // worker thread can host other tasks during the sync work instead
    // of stalling the entire reactor for the duration of every
    // /metrics scrape (audit L-8). Multi-threaded runtime required ;
    // Lorica's tokio runtime is multi-threaded by default. The lock
    // itself is brief (no .await crossing) so it stays a tokio Mutex.
    {
        let mut sys_cache = state.system_cache.lock().await;
        let (cpu, mem) = tokio::task::block_in_place(|| {
            sys_cache.refresh();
            (
                sys_cache.cpu_usage_percent() as f64,
                sys_cache.memory_used_bytes() as i64,
            )
        });
        set_system_metrics(cpu, mem);
    }

    // Encode and return
    let encoder = TextEncoder::new();
    let content_type = encoder.format_type().to_string();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        return (
            [(header::CONTENT_TYPE, "text/plain".to_string())],
            format!("metrics encoding failed: {e}").into_bytes(),
        );
    }

    // In supervisor mode, append aggregated worker request/WAF counters
    // (workers have their own Prometheus registries, so the supervisor's
    // counters are empty for these metrics)
    if let Some(ref agg) = state.aggregated_metrics {
        let req_counts = agg.merged_request_counts().await;
        if !req_counts.is_empty() {
            buffer.extend_from_slice(
                b"# HELP lorica_http_requests_total Total HTTP requests proxied\n\
                  # TYPE lorica_http_requests_total counter\n",
            );
            for ((route_id, status), count) in &req_counts {
                buffer.extend_from_slice(
                    format!(
                        "lorica_http_requests_total{{route_id=\"{route_id}\",status_code=\"{status}\"}} {count}\n"
                    )
                    .as_bytes(),
                );
            }
        }

        let waf_counts = agg.merged_waf_counts().await;
        if !waf_counts.is_empty() {
            buffer.extend_from_slice(
                b"# HELP lorica_waf_events_total Total WAF events\n\
                  # TYPE lorica_waf_events_total counter\n",
            );
            for ((category, action), count) in &waf_counts {
                buffer.extend_from_slice(
                    format!(
                        "lorica_waf_events_total{{category=\"{category}\",action=\"{action}\"}} {count}\n"
                    )
                    .as_bytes(),
                );
            }
        }
    }

    ([(header::CONTENT_TYPE, content_type)], buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_request() {
        record_request("route-1", 200, 0.05);
        record_request("route-1", 200, 0.1);
        record_request("route-1", 404, 0.01);
        // Should not panic, counters should increment
    }

    #[test]
    fn test_record_waf_event() {
        record_waf_event("sql_injection", "blocked");
        record_waf_event("xss", "detected");
    }

    #[test]
    fn test_set_backend_health() {
        set_backend_health("b1", "10.0.0.1:8080", 1.0);
        set_backend_health("b1", "10.0.0.1:8080", 0.0);
    }

    #[test]
    fn test_set_cert_expiry() {
        set_cert_expiry_days("example.com", 30.0);
        set_cert_expiry_days("example.com", 7.0);
    }

    #[test]
    fn test_set_system_metrics() {
        set_system_metrics(45.5, 1024 * 1024 * 512);
    }

    #[test]
    fn test_set_active_connections() {
        set_active_connections(42);
        set_active_connections(0);
    }

    #[test]
    fn test_metrics_encode() {
        record_request("test-encode", 200, 0.001);
        let encoder = TextEncoder::new();
        let families = REGISTRY.gather();
        let mut buf = Vec::new();
        encoder
            .encode(&families, &mut buf)
            .expect("test setup: encode metrics");
        let text = String::from_utf8(buf).expect("test setup: metrics output is UTF-8");
        assert!(text.contains("lorica_http_requests_total"));
        assert!(text.contains("test-encode"));
    }

    #[test]
    fn test_inc_geoip_block_increments_counter() {
        // Story 2.5 coverage: exercise the counter through its public
        // entry point and scrape the Prometheus text format to prove
        // the (route_id, country, mode) triple actually shows up.
        // Use unique-per-test label values so this case does not race
        // with other tests reading from the shared REGISTRY.
        inc_geoip_block("metrics-test-rt", "ZZ", "denylist");
        inc_geoip_block("metrics-test-rt", "ZZ", "denylist");
        inc_geoip_block("metrics-test-rt", "ZZ", "allowlist");

        let encoder = TextEncoder::new();
        let families = REGISTRY.gather();
        let mut buf = Vec::new();
        encoder
            .encode(&families, &mut buf)
            .expect("test setup: encode metrics");
        let text = String::from_utf8(buf).expect("test setup: metrics output is UTF-8");

        // Both label combos must be present, and the denylist count
        // must be 2 (two inc calls above).
        let deny_line = text
            .lines()
            .find(|l| {
                l.starts_with("lorica_geoip_block_total{")
                    && l.contains("route_id=\"metrics-test-rt\"")
                    && l.contains("country=\"ZZ\"")
                    && l.contains("mode=\"denylist\"")
            })
            .unwrap_or_else(|| panic!("denylist counter missing. text=\n{text}"));
        let allow_line = text
            .lines()
            .find(|l| {
                l.starts_with("lorica_geoip_block_total{")
                    && l.contains("route_id=\"metrics-test-rt\"")
                    && l.contains("country=\"ZZ\"")
                    && l.contains("mode=\"allowlist\"")
            })
            .unwrap_or_else(|| panic!("allowlist counter missing. text=\n{text}"));

        let deny_val: u64 = deny_line
            .split_whitespace()
            .next_back()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("denylist value unparseable: {deny_line}"));
        let allow_val: u64 = allow_line
            .split_whitespace()
            .next_back()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("allowlist value unparseable: {allow_line}"));
        assert_eq!(deny_val, 2, "expected 2 denylist increments");
        assert_eq!(allow_val, 1, "expected 1 allowlist increment");
    }

    #[test]
    fn test_snapshot_then_apply_aggregates_across_workers() {
        // Two workers both increment the same counter. The
        // supervisor's apply_worker_generic_counters should
        // eventually produce `a + b` at the supervisor label
        // combo. Uses unique-per-test label values so we do not
        // race other tests on the shared REGISTRY.
        reset_generic_counter_snapshot_for_test();

        // Worker 1 pretends to have incremented 3 times.
        apply_worker_generic_counters(
            1,
            &[(
                "lorica_bot_challenge_total".to_string(),
                vec![
                    ("route_id".to_string(), "agg-test-rt".to_string()),
                    ("mode".to_string(), "cookie".to_string()),
                    ("outcome".to_string(), "shown".to_string()),
                ],
                3,
            )],
        );
        // Worker 2 pretends to have incremented 5 times.
        apply_worker_generic_counters(
            2,
            &[(
                "lorica_bot_challenge_total".to_string(),
                vec![
                    ("route_id".to_string(), "agg-test-rt".to_string()),
                    ("mode".to_string(), "cookie".to_string()),
                    ("outcome".to_string(), "shown".to_string()),
                ],
                5,
            )],
        );

        // Supervisor's vec must now show 3 + 5 = 8 at that label.
        let v = BOT_CHALLENGE_TOTAL
            .with_label_values(&["agg-test-rt", "cookie", "shown"])
            .get();
        assert_eq!(v, 8, "supervisor should see aggregated count");

        // Worker 1 sends a new snapshot with a bigger value (4).
        // Only the DELTA (4 - 3 = 1) is applied, not the full 4.
        apply_worker_generic_counters(
            1,
            &[(
                "lorica_bot_challenge_total".to_string(),
                vec![
                    ("route_id".to_string(), "agg-test-rt".to_string()),
                    ("mode".to_string(), "cookie".to_string()),
                    ("outcome".to_string(), "shown".to_string()),
                ],
                4,
            )],
        );
        let v = BOT_CHALLENGE_TOTAL
            .with_label_values(&["agg-test-rt", "cookie", "shown"])
            .get();
        assert_eq!(v, 9, "apply should be delta-based, not replace");

        // A regressed worker snapshot (worker crashes + restarts
        // at 0) must NOT decrement the counter. Prometheus
        // counters can't go down; we just skip the delta.
        apply_worker_generic_counters(
            1,
            &[(
                "lorica_bot_challenge_total".to_string(),
                vec![
                    ("route_id".to_string(), "agg-test-rt".to_string()),
                    ("mode".to_string(), "cookie".to_string()),
                    ("outcome".to_string(), "shown".to_string()),
                ],
                0,
            )],
        );
        let v = BOT_CHALLENGE_TOTAL
            .with_label_values(&["agg-test-rt", "cookie", "shown"])
            .get();
        assert_eq!(
            v, 9,
            "regressed snapshot must not decrement supervisor counter"
        );

        // Forgetting worker 2 clears its snapshot — but the
        // supervisor counter stays where it is (Prometheus
        // counters can't decrement). A later worker 2 snapshot
        // will therefore push full value again as new delta.
        forget_worker_generic_counters(2);
        apply_worker_generic_counters(
            2,
            &[(
                "lorica_bot_challenge_total".to_string(),
                vec![
                    ("route_id".to_string(), "agg-test-rt".to_string()),
                    ("mode".to_string(), "cookie".to_string()),
                    ("outcome".to_string(), "shown".to_string()),
                ],
                7,
            )],
        );
        let v = BOT_CHALLENGE_TOTAL
            .with_label_values(&["agg-test-rt", "cookie", "shown"])
            .get();
        // Before forget: 4 (w1) + 5 (w2) = 9.
        // After forget + w2 resend 7: 4 + 5 + 7 = 16 (the
        // forget wiped w2's prev=5 so the full 7 reappears as
        // delta). This is the correct semantics — a crashed
        // worker's counts are NOT lost at the supervisor.
        assert_eq!(v, 16);
    }

    #[test]
    fn test_ai_bot_counters_aggregate_across_workers() {
        // Story 8.2 audit fix: the AI-bot counters must reach the
        // supervisor's registry in worker mode. Exercises both a
        // 3-label IntCounterVec (ai_bot_total) and the label-less
        // IntCounter scalar (ai_bot_rdns_unavailable_total).
        reset_generic_counter_snapshot_for_test();

        // ai_bot_total{crawler,route_id,action} from two workers.
        for (wid, val) in [(11u32, 2u64), (12u32, 3u64)] {
            apply_worker_generic_counters(
                wid,
                &[(
                    "lorica_ai_bot_total".to_string(),
                    vec![
                        ("crawler".to_string(), "CCBot".to_string()),
                        ("route_id".to_string(), "ai-agg-rt".to_string()),
                        ("action".to_string(), "deny".to_string()),
                    ],
                    val,
                )],
            );
        }
        let v = AI_BOT_TOTAL
            .with_label_values(&["CCBot", "ai-agg-rt", "deny"])
            .get();
        assert_eq!(v, 5, "ai_bot_total must aggregate across workers");

        // Label-less scalar: ai_bot_rdns_unavailable_total. Wire form
        // carries an empty label set.
        let before = AI_BOT_RDNS_UNAVAILABLE_TOTAL.get();
        apply_worker_generic_counters(
            11,
            &[(
                "lorica_ai_bot_rdns_unavailable_total".to_string(),
                Vec::new(),
                4,
            )],
        );
        apply_worker_generic_counters(
            12,
            &[(
                "lorica_ai_bot_rdns_unavailable_total".to_string(),
                Vec::new(),
                6,
            )],
        );
        assert_eq!(
            AI_BOT_RDNS_UNAVAILABLE_TOTAL.get(),
            before + 10,
            "label-less rdns-unavailable scalar must aggregate across workers"
        );
    }

    #[test]
    fn test_snapshot_emits_only_non_zero() {
        // Snapshot should skip counter entries that have never
        // been incremented — that keeps the RPC payload small
        // under steady state.
        inc_bot_challenge("snapshot-test", "javascript", "passed");
        let snap = snapshot_per_worker_counters();
        let hit = snap.iter().find(|(n, pairs, _)| {
            n == "lorica_bot_challenge_total" && pairs.iter().any(|(_, v)| v == "snapshot-test")
        });
        assert!(
            hit.is_some(),
            "incremented counter should appear in snapshot"
        );
        // None of the entries should have value 0 — that's the
        // skip-zero-entries guard.
        for (_, _, v) in &snap {
            assert!(*v > 0, "snapshot must not emit zero entries");
        }
    }

    #[test]
    fn test_bounded_labels() {
        // Simulate high-cardinality attack: many different route_ids
        // With route_id (not hostname), this is bounded by DB routes
        for i in 0..10 {
            record_request(&format!("route-{i}"), 200, 0.01);
        }
        // Should not OOM - labels are bounded by actual routes
        let encoder = TextEncoder::new();
        let families = REGISTRY.gather();
        let mut buf = Vec::new();
        encoder
            .encode(&families, &mut buf)
            .expect("test setup: encode metrics");
        assert!(!buf.is_empty());
    }
}
