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

use std::sync::atomic::Ordering;

use chrono::{Timelike, Utc};
use lorica_config::models::{SlaBucket, SlaConfig};
use lorica_config::ConfigStore;

use super::bucket::RouteBucket;
use super::helpers::{compute_percentiles, current_bucket_start};
use super::SlaCollector;

#[test]
fn test_compute_percentiles_empty() {
    let mut samples: Vec<u64> = vec![];
    assert_eq!(compute_percentiles(&mut samples), (0, 0, 0));
}

#[test]
fn test_compute_percentiles_single() {
    let mut samples = vec![42];
    assert_eq!(compute_percentiles(&mut samples), (42, 42, 42));
}

#[test]
fn test_compute_percentiles_distribution() {
    let mut samples: Vec<u64> = (1..=100).collect();
    let (p50, p95, p99) = compute_percentiles(&mut samples);
    assert_eq!(p50, 51); // index 50 in 0-based = value 51
    assert_eq!(p95, 96);
    assert_eq!(p99, 100);
}

#[test]
fn test_route_bucket_record_success() {
    let bucket = RouteBucket::new(Utc::now());
    bucket.record(100, true);
    bucket.record(200, true);
    bucket.record(150, false);

    assert_eq!(bucket.request_count.load(Ordering::Relaxed), 3);
    assert_eq!(bucket.success_count.load(Ordering::Relaxed), 2);
    assert_eq!(bucket.error_count.load(Ordering::Relaxed), 1);
    assert_eq!(bucket.latency_sum_ms.load(Ordering::Relaxed), 450);
    assert_eq!(bucket.latency_min_ms.load(Ordering::Relaxed), 100);
    assert_eq!(bucket.latency_max_ms.load(Ordering::Relaxed), 200);
}

#[test]
fn test_route_bucket_to_sla_bucket() {
    let bucket = RouteBucket::new(Utc::now());
    bucket.record(10, true);
    bucket.record(20, true);
    bucket.record(30, false);

    let sla = bucket.to_sla_bucket();
    assert_eq!(sla.request_count, 3);
    assert_eq!(sla.success_count, 2);
    assert_eq!(sla.error_count, 1);
    assert_eq!(sla.latency_sum_ms, 60);
    assert_eq!(sla.latency_min_ms, 10);
    assert_eq!(sla.latency_max_ms, 30);
    assert_eq!(sla.source, "passive");
}

#[test]
fn test_collector_record_and_flush() {
    let collector = SlaCollector::new();
    let store = ConfigStore::open_in_memory().expect("test setup: open in-memory store");

    // Record some metrics
    collector.record("route-1", 200, 50);
    collector.record("route-1", 200, 100);
    collector.record("route-1", 500, 200);
    collector.record("route-2", 200, 30);

    // Flush won't write current-minute buckets (they're not complete yet).
    // So we expect 0 flushed for the current minute.
    let flushed = collector.flush(&store);
    assert_eq!(flushed, 0, "current-minute buckets should not flush");
}

#[test]
fn test_collector_default_success_criteria() {
    let collector = SlaCollector::new();
    assert!(collector.is_success("any", 200, 100));
    assert!(collector.is_success("any", 301, 400));
    assert!(collector.is_success("any", 404, 100)); // 4xx client errors are not backend failures
    assert!(collector.is_success("any", 499, 100));
    assert!(!collector.is_success("any", 500, 100));
    assert!(!collector.is_success("any", 200, 600));
}

#[test]
fn test_collector_custom_success_criteria() {
    let collector = SlaCollector::new();
    let config = SlaConfig {
        route_id: "r1".to_string(),
        target_pct: 99.0,
        max_latency_ms: 200,
        success_status_min: 200,
        success_status_max: 299,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    collector.set_sla_config("r1", config);

    assert!(collector.is_success("r1", 200, 100));
    assert!(!collector.is_success("r1", 301, 100)); // 3xx not in range
    assert!(!collector.is_success("r1", 200, 300)); // too slow
}

#[test]
fn test_sla_config_is_success() {
    let config = SlaConfig::default_for_route("r1");
    assert!(config.is_success(200, 100));
    assert!(config.is_success(399, 500));
    assert!(config.is_success(404, 100)); // 4xx within 200-499 default
    assert!(config.is_success(499, 100));
    assert!(!config.is_success(500, 100)); // 5xx = real backend error
    assert!(!config.is_success(200, 501)); // exceeds max_latency_ms
}

#[test]
fn test_current_bucket_start_truncated() {
    let bs = current_bucket_start();
    assert_eq!(bs.second(), 0);
    assert_eq!(bs.nanosecond(), 0);
}

#[test]
fn test_store_sla_bucket_insert_and_query() {
    let store = ConfigStore::open_in_memory().expect("test setup: open in-memory store");

    // Create a route first (FK constraint)
    let route = lorica_config::models::Route {
        id: "r1".to_string(),
        hostname: "example.com".to_string(),
        path_prefix: "/".to_string(),
        certificate_id: None,
        load_balancing: lorica_config::models::LoadBalancing::RoundRobin,
        waf_enabled: false,
        waf_mode: lorica_config::models::WafMode::Detection,

        enabled: true,
        force_https: false,
        redirect_hostname: None,
        redirect_to: None,
        hostname_aliases: Vec::new(),
        proxy_headers: std::collections::HashMap::new(),
        response_headers: std::collections::HashMap::new(),
        security_headers: "moderate".to_string(),
        connect_timeout_s: 5,
        read_timeout_s: 60,
        send_timeout_s: 60,
        strip_path_prefix: None,
        add_path_prefix: None,
        path_rewrite_pattern: None,
        path_rewrite_replacement: None,
        access_log_enabled: true,
        proxy_headers_remove: Vec::new(),
        response_headers_remove: Vec::new(),
        max_request_body_bytes: None,
        websocket_enabled: true,
        rate_limit_rps: None,
        rate_limit_burst: None,
        ip_allowlist: Vec::new(),
        ip_denylist: Vec::new(),
        cors_allowed_origins: Vec::new(),
        cors_allowed_methods: Vec::new(),
        cors_max_age_s: None,
        compression_enabled: false,
        retry_attempts: None,
        cache_enabled: false,
        cache_ttl_s: 300,
        cache_max_bytes: 52428800,
        max_connections: None,
        slowloris_threshold_ms: 5000,
        auto_ban_threshold: None,
        auto_ban_duration_s: 3600,
        path_rules: vec![],
        return_status: None,
        sticky_session: false,
        basic_auth_username: None,
        basic_auth_password_hash: None,
        stale_while_revalidate_s: 10,
        stale_if_error_s: 60,
        retry_on_methods: vec![],
        maintenance_mode: false,
        error_page_html: None,
        cache_vary_headers: vec![],
        header_rules: vec![],
        traffic_splits: vec![],
        forward_auth: None,
        mirror: None,
        response_rewrite: None,
        mtls: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    store
        .create_route(&route)
        .expect("test setup: create route");

    let now = current_bucket_start();
    let bucket = SlaBucket {
        id: None,
        route_id: "r1".to_string(),
        bucket_start: now,
        request_count: 100,
        success_count: 95,
        error_count: 5,
        latency_sum_ms: 5000,
        latency_min_ms: 10,
        latency_max_ms: 200,
        latency_p50_ms: 40,
        latency_p95_ms: 150,
        latency_p99_ms: 190,
        source: "passive".to_string(),
        cfg_max_latency_ms: 500,
        cfg_status_min: 200,
        cfg_status_max: 399,
        cfg_target_pct: 99.9,
    };
    store
        .insert_sla_bucket(&bucket)
        .expect("test setup: insert sla bucket");

    let from = now - chrono::Duration::minutes(1);
    let to = now + chrono::Duration::minutes(1);
    let buckets = store
        .query_sla_buckets("r1", &from, &to, "passive")
        .expect("test setup: query sla buckets");
    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0].request_count, 100);
    assert_eq!(buckets[0].success_count, 95);
    assert_eq!(buckets[0].latency_p50_ms, 40);
}

#[test]
fn test_store_sla_summary() {
    let store = ConfigStore::open_in_memory().expect("test setup: open in-memory store");

    let route = lorica_config::models::Route {
        id: "r1".to_string(),
        hostname: "example.com".to_string(),
        path_prefix: "/".to_string(),
        certificate_id: None,
        load_balancing: lorica_config::models::LoadBalancing::RoundRobin,
        waf_enabled: false,
        waf_mode: lorica_config::models::WafMode::Detection,

        enabled: true,
        force_https: false,
        redirect_hostname: None,
        redirect_to: None,
        hostname_aliases: Vec::new(),
        proxy_headers: std::collections::HashMap::new(),
        response_headers: std::collections::HashMap::new(),
        security_headers: "moderate".to_string(),
        connect_timeout_s: 5,
        read_timeout_s: 60,
        send_timeout_s: 60,
        strip_path_prefix: None,
        add_path_prefix: None,
        path_rewrite_pattern: None,
        path_rewrite_replacement: None,
        access_log_enabled: true,
        proxy_headers_remove: Vec::new(),
        response_headers_remove: Vec::new(),
        max_request_body_bytes: None,
        websocket_enabled: true,
        rate_limit_rps: None,
        rate_limit_burst: None,
        ip_allowlist: Vec::new(),
        ip_denylist: Vec::new(),
        cors_allowed_origins: Vec::new(),
        cors_allowed_methods: Vec::new(),
        cors_max_age_s: None,
        compression_enabled: false,
        retry_attempts: None,
        cache_enabled: false,
        cache_ttl_s: 300,
        cache_max_bytes: 52428800,
        max_connections: None,
        slowloris_threshold_ms: 5000,
        auto_ban_threshold: None,
        auto_ban_duration_s: 3600,
        path_rules: vec![],
        return_status: None,
        sticky_session: false,
        basic_auth_username: None,
        basic_auth_password_hash: None,
        stale_while_revalidate_s: 10,
        stale_if_error_s: 60,
        retry_on_methods: vec![],
        maintenance_mode: false,
        error_page_html: None,
        cache_vary_headers: vec![],
        header_rules: vec![],
        traffic_splits: vec![],
        forward_auth: None,
        mirror: None,
        response_rewrite: None,
        mtls: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    store
        .create_route(&route)
        .expect("test setup: create route");

    let now = current_bucket_start();
    for i in 0..3 {
        let bucket = SlaBucket {
            id: None,
            route_id: "r1".to_string(),
            bucket_start: now - chrono::Duration::minutes(i),
            request_count: 100,
            success_count: 99,
            error_count: 1,
            latency_sum_ms: 5000,
            latency_min_ms: 10,
            latency_max_ms: 200,
            latency_p50_ms: 40,
            latency_p95_ms: 150,
            latency_p99_ms: 190,
            source: "passive".to_string(),
            cfg_max_latency_ms: 500,
            cfg_status_min: 200,
            cfg_status_max: 399,
            cfg_target_pct: 99.9,
        };
        store
            .insert_sla_bucket(&bucket)
            .expect("test setup: insert sla bucket");
    }

    let from = now - chrono::Duration::hours(1);
    let to = now + chrono::Duration::minutes(1);
    let summary = store
        .compute_sla_summary("r1", &from, &to, "1h", "passive")
        .expect("test setup: compute sla summary");
    assert_eq!(summary.total_requests, 300);
    assert_eq!(summary.successful_requests, 297);
    assert!((summary.sla_pct - 99.0).abs() < 0.01);
    assert!(!summary.meets_target); // 99.0% < 99.9% default target
}

#[test]
fn test_store_sla_summary_no_data() {
    let store = ConfigStore::open_in_memory().expect("test setup: open in-memory store");
    let now = Utc::now();
    let from = now - chrono::Duration::hours(1);
    let summary = store
        .compute_sla_summary("nonexistent", &from, &now, "1h", "passive")
        .expect("test setup: compute sla summary");
    assert_eq!(summary.total_requests, 0);
    assert_eq!(summary.sla_pct, 0.0);
    assert!(!summary.meets_target);
}

#[test]
fn test_store_prune_buckets() {
    let store = ConfigStore::open_in_memory().expect("test setup: open in-memory store");

    let route = lorica_config::models::Route {
        id: "r1".to_string(),
        hostname: "example.com".to_string(),
        path_prefix: "/".to_string(),
        certificate_id: None,
        load_balancing: lorica_config::models::LoadBalancing::RoundRobin,
        waf_enabled: false,
        waf_mode: lorica_config::models::WafMode::Detection,

        enabled: true,
        force_https: false,
        redirect_hostname: None,
        redirect_to: None,
        hostname_aliases: Vec::new(),
        proxy_headers: std::collections::HashMap::new(),
        response_headers: std::collections::HashMap::new(),
        security_headers: "moderate".to_string(),
        connect_timeout_s: 5,
        read_timeout_s: 60,
        send_timeout_s: 60,
        strip_path_prefix: None,
        add_path_prefix: None,
        path_rewrite_pattern: None,
        path_rewrite_replacement: None,
        access_log_enabled: true,
        proxy_headers_remove: Vec::new(),
        response_headers_remove: Vec::new(),
        max_request_body_bytes: None,
        websocket_enabled: true,
        rate_limit_rps: None,
        rate_limit_burst: None,
        ip_allowlist: Vec::new(),
        ip_denylist: Vec::new(),
        cors_allowed_origins: Vec::new(),
        cors_allowed_methods: Vec::new(),
        cors_max_age_s: None,
        compression_enabled: false,
        retry_attempts: None,
        cache_enabled: false,
        cache_ttl_s: 300,
        cache_max_bytes: 52428800,
        max_connections: None,
        slowloris_threshold_ms: 5000,
        auto_ban_threshold: None,
        auto_ban_duration_s: 3600,
        path_rules: vec![],
        return_status: None,
        sticky_session: false,
        basic_auth_username: None,
        basic_auth_password_hash: None,
        stale_while_revalidate_s: 10,
        stale_if_error_s: 60,
        retry_on_methods: vec![],
        maintenance_mode: false,
        error_page_html: None,
        cache_vary_headers: vec![],
        header_rules: vec![],
        traffic_splits: vec![],
        forward_auth: None,
        mirror: None,
        response_rewrite: None,
        mtls: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    store
        .create_route(&route)
        .expect("test setup: create route");

    let now = current_bucket_start();
    let old = now - chrono::Duration::days(31);
    let recent = now - chrono::Duration::hours(1);

    for (start, suffix) in [(old, "old"), (recent, "recent")] {
        let bucket = SlaBucket {
            id: None,
            route_id: "r1".to_string(),
            bucket_start: start,
            request_count: 10,
            success_count: 10,
            error_count: 0,
            latency_sum_ms: 100,
            latency_min_ms: 5,
            latency_max_ms: 20,
            latency_p50_ms: 10,
            latency_p95_ms: 18,
            latency_p99_ms: 19,
            source: format!("passive_{suffix}"),
            cfg_max_latency_ms: 500,
            cfg_status_min: 200,
            cfg_status_max: 399,
            cfg_target_pct: 99.9,
        };
        // Use different source to avoid UNIQUE constraint
        store
            .insert_sla_bucket(&bucket)
            .expect("test setup: insert sla bucket");
    }

    let cutoff = now - chrono::Duration::days(30);
    let pruned = store
        .prune_sla_buckets(&cutoff)
        .expect("test setup: prune sla buckets");
    assert_eq!(pruned, 1);
}

#[test]
fn test_store_sla_config_upsert_and_get() {
    let store = ConfigStore::open_in_memory().expect("test setup: open in-memory store");

    let route = lorica_config::models::Route {
        id: "r1".to_string(),
        hostname: "example.com".to_string(),
        path_prefix: "/".to_string(),
        certificate_id: None,
        load_balancing: lorica_config::models::LoadBalancing::RoundRobin,
        waf_enabled: false,
        waf_mode: lorica_config::models::WafMode::Detection,

        enabled: true,
        force_https: false,
        redirect_hostname: None,
        redirect_to: None,
        hostname_aliases: Vec::new(),
        proxy_headers: std::collections::HashMap::new(),
        response_headers: std::collections::HashMap::new(),
        security_headers: "moderate".to_string(),
        connect_timeout_s: 5,
        read_timeout_s: 60,
        send_timeout_s: 60,
        strip_path_prefix: None,
        add_path_prefix: None,
        path_rewrite_pattern: None,
        path_rewrite_replacement: None,
        access_log_enabled: true,
        proxy_headers_remove: Vec::new(),
        response_headers_remove: Vec::new(),
        max_request_body_bytes: None,
        websocket_enabled: true,
        rate_limit_rps: None,
        rate_limit_burst: None,
        ip_allowlist: Vec::new(),
        ip_denylist: Vec::new(),
        cors_allowed_origins: Vec::new(),
        cors_allowed_methods: Vec::new(),
        cors_max_age_s: None,
        compression_enabled: false,
        retry_attempts: None,
        cache_enabled: false,
        cache_ttl_s: 300,
        cache_max_bytes: 52428800,
        max_connections: None,
        slowloris_threshold_ms: 5000,
        auto_ban_threshold: None,
        auto_ban_duration_s: 3600,
        path_rules: vec![],
        return_status: None,
        sticky_session: false,
        basic_auth_username: None,
        basic_auth_password_hash: None,
        stale_while_revalidate_s: 10,
        stale_if_error_s: 60,
        retry_on_methods: vec![],
        maintenance_mode: false,
        error_page_html: None,
        cache_vary_headers: vec![],
        header_rules: vec![],
        traffic_splits: vec![],
        forward_auth: None,
        mirror: None,
        response_rewrite: None,
        mtls: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    store
        .create_route(&route)
        .expect("test setup: create route");

    // Default config (no row in DB)
    let config = store
        .get_sla_config("r1")
        .expect("test setup: get sla config");
    assert_eq!(config.target_pct, 99.9);
    assert_eq!(config.max_latency_ms, 500);

    // Custom config
    let mut custom = SlaConfig::default_for_route("r1");
    custom.target_pct = 99.5;
    custom.max_latency_ms = 200;
    store
        .upsert_sla_config(&custom)
        .expect("test setup: upsert sla config");

    let config = store
        .get_sla_config("r1")
        .expect("test setup: get sla config");
    assert_eq!(config.target_pct, 99.5);
    assert_eq!(config.max_latency_ms, 200);
}

#[test]
fn test_store_export_sla_data() {
    let store = ConfigStore::open_in_memory().expect("test setup: open in-memory store");

    let route = lorica_config::models::Route {
        id: "r1".to_string(),
        hostname: "example.com".to_string(),
        path_prefix: "/".to_string(),
        certificate_id: None,
        load_balancing: lorica_config::models::LoadBalancing::RoundRobin,
        waf_enabled: false,
        waf_mode: lorica_config::models::WafMode::Detection,

        enabled: true,
        force_https: false,
        redirect_hostname: None,
        redirect_to: None,
        hostname_aliases: Vec::new(),
        proxy_headers: std::collections::HashMap::new(),
        response_headers: std::collections::HashMap::new(),
        security_headers: "moderate".to_string(),
        connect_timeout_s: 5,
        read_timeout_s: 60,
        send_timeout_s: 60,
        strip_path_prefix: None,
        add_path_prefix: None,
        path_rewrite_pattern: None,
        path_rewrite_replacement: None,
        access_log_enabled: true,
        proxy_headers_remove: Vec::new(),
        response_headers_remove: Vec::new(),
        max_request_body_bytes: None,
        websocket_enabled: true,
        rate_limit_rps: None,
        rate_limit_burst: None,
        ip_allowlist: Vec::new(),
        ip_denylist: Vec::new(),
        cors_allowed_origins: Vec::new(),
        cors_allowed_methods: Vec::new(),
        cors_max_age_s: None,
        compression_enabled: false,
        retry_attempts: None,
        cache_enabled: false,
        cache_ttl_s: 300,
        cache_max_bytes: 52428800,
        max_connections: None,
        slowloris_threshold_ms: 5000,
        auto_ban_threshold: None,
        auto_ban_duration_s: 3600,
        path_rules: vec![],
        return_status: None,
        sticky_session: false,
        basic_auth_username: None,
        basic_auth_password_hash: None,
        stale_while_revalidate_s: 10,
        stale_if_error_s: 60,
        retry_on_methods: vec![],
        maintenance_mode: false,
        error_page_html: None,
        cache_vary_headers: vec![],
        header_rules: vec![],
        traffic_splits: vec![],
        forward_auth: None,
        mirror: None,
        response_rewrite: None,
        mtls: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    store
        .create_route(&route)
        .expect("test setup: create route");

    let now = current_bucket_start();
    let bucket = SlaBucket {
        id: None,
        route_id: "r1".to_string(),
        bucket_start: now,
        request_count: 50,
        success_count: 48,
        error_count: 2,
        latency_sum_ms: 2500,
        latency_min_ms: 10,
        latency_max_ms: 200,
        latency_p50_ms: 40,
        latency_p95_ms: 150,
        latency_p99_ms: 190,
        source: "passive".to_string(),
        cfg_max_latency_ms: 500,
        cfg_status_min: 200,
        cfg_status_max: 399,
        cfg_target_pct: 99.9,
    };
    store
        .insert_sla_bucket(&bucket)
        .expect("test setup: insert sla bucket");

    let from = now - chrono::Duration::hours(1);
    let to = now + chrono::Duration::hours(1);
    let export = store
        .export_sla_data("r1", &from, &to)
        .expect("test setup: export sla data");
    assert_eq!(export["route_id"], "r1");
    assert!(export["buckets"].is_array());
    assert_eq!(
        export["buckets"]
            .as_array()
            .expect("test setup: buckets field is an array")
            .len(),
        1
    );
}
