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

//! Tests for the reload module and proxy config construction from ConfigStore.

use std::sync::Arc;

use lorica_config::models::*;
use lorica_config::ConfigStore;

fn make_route(id: &str, hostname: &str, path_prefix: &str) -> Route {
    Route {
        id: id.to_string(),
        hostname: hostname.to_string(),
        path_prefix: path_prefix.to_string(),
        certificate_id: None,
        load_balancing: LoadBalancing::RoundRobin,
        waf_enabled: false,
        waf_mode: WafMode::Detection,
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
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn make_backend(id: &str, address: &str) -> Backend {
    Backend {
        id: id.to_string(),
        address: address.to_string(),
        name: String::new(),
        group_name: String::new(),
        weight: 1,
        health_status: HealthStatus::Healthy,
        health_check_enabled: true,
        health_check_interval_s: 10,
        health_check_path: None,
        lifecycle_state: LifecycleState::Normal,
        active_connections: 0,
        tls_upstream: false,
        tls_skip_verify: false,
        tls_sni: None,
        h2_upstream: false,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// Verify that reload_proxy_config loads routes and backends from the store
/// into a correct ProxyConfig structure.
#[tokio::test]
async fn test_reload_builds_proxy_config() {
    let store = ConfigStore::open_in_memory().unwrap();

    // Create routes with backends
    store
        .create_route(&make_route("r1", "example.com", "/"))
        .unwrap();
    store
        .create_route(&make_route("r2", "api.example.com", "/v1"))
        .unwrap();
    store
        .create_backend(&make_backend("b1", "10.0.0.1:80"))
        .unwrap();
    store
        .create_backend(&make_backend("b2", "10.0.0.2:80"))
        .unwrap();
    store.link_route_backend("r1", "b1").unwrap();
    store.link_route_backend("r1", "b2").unwrap();
    store.link_route_backend("r2", "b1").unwrap();

    let store = Arc::new(tokio::sync::Mutex::new(store));
    let proxy_config = Arc::new(arc_swap::ArcSwap::from_pointee(
        lorica::proxy_wiring::ProxyConfig::default(),
    ));

    lorica::reload::reload_proxy_config(&store, &proxy_config)
        .await
        .unwrap();

    let config = proxy_config.load();
    assert_eq!(config.routes_by_host.len(), 2);

    let example_routes = config.routes_by_host.get("example.com").unwrap();
    assert_eq!(example_routes.len(), 1);
    assert_eq!(example_routes[0].backends.len(), 2);

    let api_routes = config.routes_by_host.get("api.example.com").unwrap();
    assert_eq!(api_routes.len(), 1);
    assert_eq!(api_routes[0].backends.len(), 1);
}

/// Verify that each hostname maps to its own route entry.
#[tokio::test]
async fn test_multiple_hostnames_routed_independently() {
    let store = ConfigStore::open_in_memory().unwrap();

    store
        .create_route(&make_route("r1", "app1.test", "/"))
        .unwrap();
    store
        .create_route(&make_route("r2", "app2.test", "/api"))
        .unwrap();
    store
        .create_route(&make_route("r3", "app3.test", "/api/v2"))
        .unwrap();
    store
        .create_backend(&make_backend("b1", "10.0.0.1:80"))
        .unwrap();
    store.link_route_backend("r1", "b1").unwrap();
    store.link_route_backend("r2", "b1").unwrap();
    store.link_route_backend("r3", "b1").unwrap();

    let store = Arc::new(tokio::sync::Mutex::new(store));
    let proxy_config = Arc::new(arc_swap::ArcSwap::from_pointee(
        lorica::proxy_wiring::ProxyConfig::default(),
    ));

    lorica::reload::reload_proxy_config(&store, &proxy_config)
        .await
        .unwrap();

    let config = proxy_config.load();
    assert_eq!(config.routes_by_host.len(), 3);
    assert!(config.routes_by_host.contains_key("app1.test"));
    assert!(config.routes_by_host.contains_key("app2.test"));
    assert!(config.routes_by_host.contains_key("app3.test"));
}

/// Verify that disabled routes are excluded from the config.
#[tokio::test]
async fn test_disabled_routes_excluded() {
    let store = ConfigStore::open_in_memory().unwrap();

    let mut disabled = make_route("r1", "disabled.test", "/");
    disabled.enabled = false;
    store.create_route(&disabled).unwrap();
    store
        .create_route(&make_route("r2", "enabled.test", "/"))
        .unwrap();
    store
        .create_backend(&make_backend("b1", "10.0.0.1:80"))
        .unwrap();
    store.link_route_backend("r1", "b1").unwrap();
    store.link_route_backend("r2", "b1").unwrap();

    let store = Arc::new(tokio::sync::Mutex::new(store));
    let proxy_config = Arc::new(arc_swap::ArcSwap::from_pointee(
        lorica::proxy_wiring::ProxyConfig::default(),
    ));

    lorica::reload::reload_proxy_config(&store, &proxy_config)
        .await
        .unwrap();

    let config = proxy_config.load();
    // Disabled route should not appear
    assert!(!config.routes_by_host.contains_key("disabled.test"));
    // Enabled route should be present
    let routes = config.routes_by_host.get("enabled.test").unwrap();
    assert_eq!(routes.len(), 1);
}

/// Verify that routes with no backends are still loaded (but will return 502).
#[tokio::test]
async fn test_route_with_no_backends() {
    let store = ConfigStore::open_in_memory().unwrap();

    store
        .create_route(&make_route("r1", "empty.test", "/"))
        .unwrap();

    let store = Arc::new(tokio::sync::Mutex::new(store));
    let proxy_config = Arc::new(arc_swap::ArcSwap::from_pointee(
        lorica::proxy_wiring::ProxyConfig::default(),
    ));

    lorica::reload::reload_proxy_config(&store, &proxy_config)
        .await
        .unwrap();

    let config = proxy_config.load();
    let routes = config.routes_by_host.get("empty.test").unwrap();
    assert_eq!(routes.len(), 1);
    assert!(routes[0].backends.is_empty());
}

/// Verify config reload atomically swaps the config.
#[tokio::test]
async fn test_reload_atomic_swap() {
    let store = ConfigStore::open_in_memory().unwrap();

    store
        .create_route(&make_route("r1", "first.test", "/"))
        .unwrap();
    store
        .create_backend(&make_backend("b1", "10.0.0.1:80"))
        .unwrap();
    store.link_route_backend("r1", "b1").unwrap();

    let store = Arc::new(tokio::sync::Mutex::new(store));
    let proxy_config = Arc::new(arc_swap::ArcSwap::from_pointee(
        lorica::proxy_wiring::ProxyConfig::default(),
    ));

    // First load
    lorica::reload::reload_proxy_config(&store, &proxy_config)
        .await
        .unwrap();

    let config1 = proxy_config.load();
    assert!(config1.routes_by_host.contains_key("first.test"));

    // Add a new route and reload
    {
        let s = store.lock().await;
        s.create_route(&make_route("r2", "second.test", "/"))
            .unwrap();
        s.link_route_backend("r2", "b1").unwrap();
    }

    lorica::reload::reload_proxy_config(&store, &proxy_config)
        .await
        .unwrap();

    let config2 = proxy_config.load();
    assert!(config2.routes_by_host.contains_key("first.test"));
    assert!(config2.routes_by_host.contains_key("second.test"));
}

/// Verify that down backends are not counted in healthy list.
#[tokio::test]
async fn test_down_backends_filtered() {
    let store = ConfigStore::open_in_memory().unwrap();

    store
        .create_route(&make_route("r1", "app.test", "/"))
        .unwrap();

    let b1 = make_backend("b1", "10.0.0.1:80");
    let mut b2 = make_backend("b2", "10.0.0.2:80");
    b2.health_status = HealthStatus::Down;

    store.create_backend(&b1).unwrap();
    store.create_backend(&b2).unwrap();
    store.link_route_backend("r1", "b1").unwrap();
    store.link_route_backend("r1", "b2").unwrap();

    let store = Arc::new(tokio::sync::Mutex::new(store));
    let proxy_config = Arc::new(arc_swap::ArcSwap::from_pointee(
        lorica::proxy_wiring::ProxyConfig::default(),
    ));

    lorica::reload::reload_proxy_config(&store, &proxy_config)
        .await
        .unwrap();

    let config = proxy_config.load();
    let routes = config.routes_by_host.get("app.test").unwrap();
    // Both backends are in the config (filtering happens in upstream_peer)
    assert_eq!(routes[0].backends.len(), 2);
    // One is healthy, one is down
    let healthy: Vec<_> = routes[0]
        .backends
        .iter()
        .filter(|b| b.health_status != HealthStatus::Down)
        .collect();
    assert_eq!(healthy.len(), 1);
    assert_eq!(healthy[0].address, "10.0.0.1:80");
}
