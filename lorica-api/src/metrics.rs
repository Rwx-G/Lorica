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
        prometheus::opts!("http_requests_total", "Total HTTP requests proxied")
            .namespace("lorica"),
        &["route_id", "status_code"],
    )
    .unwrap();
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
    .unwrap();
    REGISTRY.register(Box::new(histogram.clone())).ok();
    histogram
});

/// Active proxy connections gauge.
static ACTIVE_CONNECTIONS: Lazy<IntGauge> = Lazy::new(|| {
    let gauge = IntGauge::with_opts(
        prometheus::Opts::new("active_connections", "Current number of active proxy connections")
            .namespace("lorica"),
    )
    .unwrap();
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
    .unwrap();
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
    .unwrap();
    REGISTRY.register(Box::new(gauge.clone())).ok();
    gauge
});

/// WAF events counter. Labels: category, action (detected/blocked).
static WAF_EVENTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        prometheus::opts!("waf_events_total", "Total WAF events").namespace("lorica"),
        &["category", "action"],
    )
    .unwrap();
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
    .unwrap();
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
    .unwrap();
    REGISTRY.register(Box::new(gauge.clone())).ok();
    gauge
});

/// System memory usage gauge (bytes).
static SYSTEM_MEMORY_USED_BYTES: Lazy<IntGauge> = Lazy::new(|| {
    let gauge = IntGauge::with_opts(
        prometheus::Opts::new("system_memory_used_bytes", "System memory used in bytes")
            .namespace("lorica"),
    )
    .unwrap();
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

/// GET /metrics - Prometheus scrape endpoint.
///
/// Refreshes dynamic gauges (active connections, backend health, cert expiry,
/// system resources) from AppState before encoding.
pub async fn get_metrics(Extension(state): Extension<AppState>) -> impl IntoResponse {
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
        encoder.encode(&families, &mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
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
        encoder.encode(&families, &mut buf).unwrap();
        assert!(!buf.is_empty());
    }
}
