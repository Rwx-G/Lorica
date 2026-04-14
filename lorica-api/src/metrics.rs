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
    Encoder, GaugeVec, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, Registry, TextEncoder,
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
pub fn record_request(route_id: &str, status_code: u16, latency_seconds: f64) {
    HTTP_REQUESTS_TOTAL
        .with_label_values(&[route_id, &status_code.to_string()])
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

    // Refresh system metrics
    {
        let mut sys_cache = state.system_cache.lock().await;
        sys_cache.refresh();
        let cpu = sys_cache.cpu_usage_percent() as f64;
        let mem = sys_cache.memory_used_bytes() as i64;
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
