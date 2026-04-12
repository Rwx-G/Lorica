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

//! Unit tests for ProxyConfig construction and route matching logic.

use lorica_config::models::*;
use lorica_config::ConfigStore;

// Re-export internal types for testing
// Since proxy.rs is in the binary crate, we test via the config store approach
// and through integration tests.

fn make_route(id: &str, hostname: &str, path_prefix: &str, enabled: bool) -> Route {
    Route {
        id: id.to_string(),
        hostname: hostname.to_string(),
        path_prefix: path_prefix.to_string(),
        certificate_id: None,
        load_balancing: LoadBalancing::RoundRobin,
        waf_enabled: false,
        waf_mode: WafMode::Detection,
        enabled,
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
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn make_backend(id: &str, address: &str, healthy: bool) -> Backend {
    Backend {
        id: id.to_string(),
        address: address.to_string(),
        name: String::new(),
        group_name: String::new(),
        weight: 1,
        health_status: if healthy {
            HealthStatus::Healthy
        } else {
            HealthStatus::Down
        },
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

#[test]
fn test_config_store_route_backend_linking() {
    let store = ConfigStore::open_in_memory().unwrap();

    let route = make_route("r1", "example.com", "/", true);
    let backend = make_backend("b1", "127.0.0.1:8081", true);

    store.create_route(&route).unwrap();
    store.create_backend(&backend).unwrap();
    store.link_route_backend("r1", "b1").unwrap();

    let backends = store.list_backends_for_route("r1").unwrap();
    assert_eq!(backends, vec!["b1"]);
}

#[test]
fn test_config_store_multiple_backends_per_route() {
    let store = ConfigStore::open_in_memory().unwrap();

    let route = make_route("r1", "example.com", "/", true);
    let b1 = make_backend("b1", "127.0.0.1:8081", true);
    let b2 = make_backend("b2", "127.0.0.1:8082", true);
    let b3 = make_backend("b3", "127.0.0.1:8083", false);

    store.create_route(&route).unwrap();
    store.create_backend(&b1).unwrap();
    store.create_backend(&b2).unwrap();
    store.create_backend(&b3).unwrap();
    store.link_route_backend("r1", "b1").unwrap();
    store.link_route_backend("r1", "b2").unwrap();
    store.link_route_backend("r1", "b3").unwrap();

    let backends = store.list_backends_for_route("r1").unwrap();
    assert_eq!(backends.len(), 3);
}

#[test]
fn test_config_store_disabled_route_not_linked() {
    let store = ConfigStore::open_in_memory().unwrap();

    let route = make_route("r1", "example.com", "/", false);
    store.create_route(&route).unwrap();

    let routes = store.list_routes().unwrap();
    assert_eq!(routes.len(), 1);
    assert!(!routes[0].enabled);
}

#[test]
fn test_config_store_multiple_routes_different_hosts() {
    let store = ConfigStore::open_in_memory().unwrap();

    let r1 = make_route("r1", "app1.example.com", "/", true);
    let r2 = make_route("r2", "app2.example.com", "/", true);

    store.create_route(&r1).unwrap();
    store.create_route(&r2).unwrap();

    let routes = store.list_routes().unwrap();
    assert_eq!(routes.len(), 2);
}

#[test]
fn test_config_store_duplicate_hostname_rejected() {
    let store = ConfigStore::open_in_memory().unwrap();

    let r1 = make_route("r1", "example.com", "/", true);
    let r2 = make_route("r2", "example.com", "/api", true);

    store.create_route(&r1).unwrap();
    let result = store.create_route(&r2);
    assert!(result.is_err(), "Duplicate hostname should be rejected");
}

#[test]
fn test_backend_health_status_update() {
    let store = ConfigStore::open_in_memory().unwrap();

    let mut backend = make_backend("b1", "127.0.0.1:8081", true);
    store.create_backend(&backend).unwrap();

    backend.health_status = HealthStatus::Down;
    store.update_backend(&backend).unwrap();

    let fetched = store.get_backend("b1").unwrap().unwrap();
    assert_eq!(fetched.health_status, HealthStatus::Down);
}

#[test]
fn test_route_backend_round_trip() {
    let store = ConfigStore::open_in_memory().unwrap();

    let route = make_route("r1", "app.test", "/", true);
    let b1 = make_backend("b1", "10.0.0.1:80", true);
    let b2 = make_backend("b2", "10.0.0.2:80", true);

    store.create_route(&route).unwrap();
    store.create_backend(&b1).unwrap();
    store.create_backend(&b2).unwrap();
    store.link_route_backend("r1", "b1").unwrap();
    store.link_route_backend("r1", "b2").unwrap();

    // Verify round-trip
    let routes = store.list_routes().unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].hostname, "app.test");

    let backends = store.list_backends_for_route("r1").unwrap();
    assert_eq!(backends.len(), 2);

    let all_backends = store.list_backends().unwrap();
    assert_eq!(all_backends.len(), 2);
}

#[test]
fn test_route_deletion_cascades_links() {
    let store = ConfigStore::open_in_memory().unwrap();

    let route = make_route("r1", "example.com", "/", true);
    let backend = make_backend("b1", "127.0.0.1:8081", true);

    store.create_route(&route).unwrap();
    store.create_backend(&backend).unwrap();
    store.link_route_backend("r1", "b1").unwrap();

    store.delete_route("r1").unwrap();

    // route_backends should be cascade-deleted
    let links = store.list_route_backends().unwrap();
    assert!(links.is_empty());

    // Backend itself still exists
    let b = store.get_backend("b1").unwrap();
    assert!(b.is_some());
}
