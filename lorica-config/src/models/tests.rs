use std::collections::HashMap;

use super::*;

// ---- LoadBalancing ----

#[test]
fn test_load_balancing_round_trip() {
    for (s, variant) in [
        ("round_robin", LoadBalancing::RoundRobin),
        ("consistent_hash", LoadBalancing::ConsistentHash),
        ("random", LoadBalancing::Random),
        ("peak_ewma", LoadBalancing::PeakEwma),
    ] {
        assert_eq!(
            s.parse::<LoadBalancing>().expect("test setup: parses"),
            variant
        );
        assert_eq!(variant.as_str(), s);
    }
}

#[test]
fn test_load_balancing_unknown() {
    assert!("unknown".parse::<LoadBalancing>().is_err());
}

// ---- WafMode ----

#[test]
fn test_waf_mode_round_trip() {
    for (s, variant) in [
        ("detection", WafMode::Detection),
        ("blocking", WafMode::Blocking),
    ] {
        assert_eq!(s.parse::<WafMode>().expect("test setup: parses"), variant);
        assert_eq!(variant.as_str(), s);
    }
}

#[test]
fn test_waf_mode_unknown() {
    assert!("permissive".parse::<WafMode>().is_err());
}

// ---- HealthStatus ----

#[test]
fn test_health_status_round_trip() {
    for (s, variant) in [
        ("healthy", HealthStatus::Healthy),
        ("degraded", HealthStatus::Degraded),
        ("down", HealthStatus::Down),
        ("unknown", HealthStatus::Unknown),
    ] {
        assert_eq!(
            s.parse::<HealthStatus>().expect("test setup: parses"),
            variant
        );
        assert_eq!(variant.as_str(), s);
    }
}

#[test]
fn test_health_status_unknown() {
    assert_eq!(
        "unknown"
            .parse::<HealthStatus>()
            .expect("test setup: parses"),
        HealthStatus::Unknown
    );
    assert!("invalid_status".parse::<HealthStatus>().is_err());
}

// ---- LifecycleState ----

#[test]
fn test_lifecycle_state_round_trip() {
    for (s, variant) in [
        ("normal", LifecycleState::Normal),
        ("closing", LifecycleState::Closing),
        ("closed", LifecycleState::Closed),
    ] {
        assert_eq!(
            s.parse::<LifecycleState>().expect("test setup: parses"),
            variant
        );
        assert_eq!(variant.as_str(), s);
    }
}

#[test]
fn test_lifecycle_state_unknown() {
    assert!("draining".parse::<LifecycleState>().is_err());
}

// ---- NotificationChannel ----

#[test]
fn test_notification_channel_round_trip() {
    for (s, variant) in [
        ("email", NotificationChannel::Email),
        ("webhook", NotificationChannel::Webhook),
        ("slack", NotificationChannel::Slack),
    ] {
        assert_eq!(
            s.parse::<NotificationChannel>()
                .expect("test setup: parses"),
            variant
        );
        assert_eq!(variant.as_str(), s);
    }
}

#[test]
fn test_notification_channel_unknown() {
    assert!("sms".parse::<NotificationChannel>().is_err());
}

// ---- PreferenceValue ----

#[test]
fn test_preference_value_round_trip() {
    for (s, variant) in [
        ("never", PreferenceValue::Never),
        ("always", PreferenceValue::Always),
        ("once", PreferenceValue::Once),
    ] {
        assert_eq!(
            s.parse::<PreferenceValue>().expect("test setup: parses"),
            variant
        );
        assert_eq!(variant.as_str(), s);
    }
}

#[test]
fn test_preference_value_unknown() {
    assert!("sometimes".parse::<PreferenceValue>().is_err());
}

// ---- GlobalSettings ----

#[test]
fn test_global_settings_defaults() {
    let settings = GlobalSettings::default();
    assert_eq!(settings.management_port, 9443);
    assert_eq!(settings.log_level, "info");
    assert_eq!(settings.default_health_check_interval_s, 10);
    assert_eq!(settings.cert_warning_days, 30);
    assert_eq!(settings.cert_critical_days, 7);
}

#[test]
fn test_global_settings_serde_round_trip() {
    let settings = GlobalSettings::default();
    let json = serde_json::to_string(&settings).expect("test setup: serializes to string");
    let deserialized: GlobalSettings =
        serde_json::from_str(&json).expect("test setup: deserializes from str");
    assert_eq!(deserialized.management_port, settings.management_port);
    assert_eq!(deserialized.log_level, settings.log_level);
}

#[test]
fn test_global_settings_cert_day_defaults_on_missing() {
    let json =
        r#"{"management_port":9443,"log_level":"info","default_health_check_interval_s":10}"#;
    let settings: GlobalSettings =
        serde_json::from_str(json).expect("test setup: deserializes from str");
    assert_eq!(settings.cert_warning_days, 30);
    assert_eq!(settings.cert_critical_days, 7);
}

#[test]
fn test_global_settings_custom_presets_default_empty() {
    let settings = GlobalSettings::default();
    assert!(settings.custom_security_presets.is_empty());
}

#[test]
fn test_global_settings_custom_presets_deserialized_on_missing() {
    let json =
        r#"{"management_port":9443,"log_level":"info","default_health_check_interval_s":10}"#;
    let settings: GlobalSettings =
        serde_json::from_str(json).expect("test setup: deserializes from str");
    assert!(settings.custom_security_presets.is_empty());
}

// ---- SecurityHeaderPreset ----

#[test]
fn test_builtin_security_presets_names() {
    let presets = builtin_security_presets();
    let names: Vec<&str> = presets.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, vec!["strict", "moderate", "none"]);
}

#[test]
fn test_builtin_strict_preset_has_expected_headers() {
    let presets = builtin_security_presets();
    let strict = presets
        .iter()
        .find(|p| p.name == "strict")
        .expect("test setup: find yields element");
    assert!(strict.headers.contains_key("Strict-Transport-Security"));
    assert!(strict.headers.contains_key("X-Frame-Options"));
    assert!(strict.headers.contains_key("Content-Security-Policy"));
    assert!(strict.headers.contains_key("Permissions-Policy"));
    assert_eq!(strict.headers["X-Frame-Options"], "DENY");
}

#[test]
fn test_builtin_moderate_preset_has_expected_headers() {
    let presets = builtin_security_presets();
    let moderate = presets
        .iter()
        .find(|p| p.name == "moderate")
        .expect("test setup: find yields element");
    assert!(moderate.headers.contains_key("X-Content-Type-Options"));
    assert!(moderate.headers.contains_key("Strict-Transport-Security"));
    assert_eq!(moderate.headers["X-Frame-Options"], "SAMEORIGIN");
}

#[test]
fn test_builtin_none_preset_is_empty() {
    let presets = builtin_security_presets();
    let none = presets
        .iter()
        .find(|p| p.name == "none")
        .expect("test setup: find yields element");
    assert!(none.headers.is_empty());
}

#[test]
fn test_resolve_security_preset_finds_by_name() {
    let presets = builtin_security_presets();
    let found = resolve_security_preset("strict", &presets);
    assert!(found.is_some());
    assert_eq!(found.expect("test setup: value present").name, "strict");
}

#[test]
fn test_resolve_security_preset_returns_none_for_unknown() {
    let presets = builtin_security_presets();
    assert!(resolve_security_preset("nonexistent", &presets).is_none());
}

// ---- SlaConfig ----

#[test]
fn test_sla_config_default_for_route() {
    let config = SlaConfig::default_for_route("route-1");
    assert_eq!(config.route_id, "route-1");
    assert!((config.target_pct - 99.9).abs() < f64::EPSILON);
    assert_eq!(config.max_latency_ms, 500);
    assert_eq!(config.success_status_min, 200);
    assert_eq!(config.success_status_max, 499);
}

#[test]
fn test_sla_config_is_success_within_bounds() {
    let config = SlaConfig::default_for_route("r1");
    assert!(config.is_success(200, 100));
    assert!(config.is_success(301, 400));
    assert!(config.is_success(399, 500)); // exactly at max latency
}

#[test]
fn test_sla_config_is_success_status_out_of_range() {
    let config = SlaConfig::default_for_route("r1");
    assert!(config.is_success(400, 100)); // 400 is within 200-499
    assert!(config.is_success(404, 100)); // 404 is a client error, not backend failure
    assert!(!config.is_success(500, 100)); // 500 is a server error
    assert!(!config.is_success(199, 100)); // 199 < 200
}

#[test]
fn test_sla_config_is_success_latency_exceeded() {
    let config = SlaConfig::default_for_route("r1");
    assert!(!config.is_success(200, 501)); // 501 > 500
    assert!(!config.is_success(200, 10000));
}

#[test]
fn test_sla_config_is_success_both_fail() {
    let config = SlaConfig::default_for_route("r1");
    assert!(!config.is_success(500, 1000));
}

// ---- Route defaults via serde ----

#[test]
fn test_route_serde_defaults_applied() {
    // Minimal JSON that omits all defaulted fields
    let json = r#"{
        "id": "r1",
        "hostname": "test.com",
        "path_prefix": "/",
        "certificate_id": null,
        "load_balancing": "round_robin",
        "waf_enabled": false,
        "waf_mode": "detection",
        "enabled": true,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z"
    }"#;
    let route: Route = serde_json::from_str(json).expect("test setup: deserializes from str");
    assert_eq!(route.security_headers, "moderate");
    assert_eq!(route.connect_timeout_s, 5);
    assert_eq!(route.read_timeout_s, 60);
    assert_eq!(route.send_timeout_s, 60);
    assert!(route.access_log_enabled);
    assert!(route.websocket_enabled);
    assert!(!route.compression_enabled);
    assert!(!route.cache_enabled);
    assert_eq!(route.cache_ttl_s, 300);
    assert_eq!(route.cache_max_bytes, 52428800);
    assert_eq!(route.slowloris_threshold_ms, 5000);
    assert_eq!(route.auto_ban_duration_s, 3600);
    assert!(!route.force_https);
    assert!(route.hostname_aliases.is_empty());
    assert!(route.rate_limit_rps.is_none());
    assert!(route.auto_ban_threshold.is_none());
}

// ---- GlobalSettings defaults via serde ----

#[test]
fn test_global_settings_loadtest_defaults_on_missing() {
    let json =
        r#"{"management_port":9443,"log_level":"info","default_health_check_interval_s":10}"#;
    let settings: GlobalSettings =
        serde_json::from_str(json).expect("test setup: deserializes from str");
    assert_eq!(settings.max_active_probes, 50);
    assert_eq!(settings.loadtest_max_concurrency, 100);
    assert_eq!(settings.loadtest_max_duration_s, 60);
    assert_eq!(settings.loadtest_max_rps, 1000);
}

#[test]
fn test_security_header_preset_serde_round_trip() {
    let preset = SecurityHeaderPreset {
        name: "custom".to_string(),
        headers: HashMap::from([("X-Custom".to_string(), "value".to_string())]),
    };
    let json = serde_json::to_string(&preset).expect("test setup: serializes to string");
    let deserialized: SecurityHeaderPreset =
        serde_json::from_str(&json).expect("test setup: deserializes from str");
    assert_eq!(deserialized.name, "custom");
    assert_eq!(deserialized.headers["X-Custom"], "value");
}

// ---- PathMatchType ----

#[test]
fn test_path_match_type_round_trip() {
    for (s, variant) in [
        ("prefix", PathMatchType::Prefix),
        ("exact", PathMatchType::Exact),
    ] {
        assert_eq!(
            s.parse::<PathMatchType>().expect("test setup: parses"),
            variant
        );
        assert_eq!(variant.as_str(), s);
    }
}

#[test]
fn test_path_match_type_unknown() {
    assert!("regex".parse::<PathMatchType>().is_err());
}

// ---- PathRule ----

#[test]
fn test_path_rule_matches_prefix() {
    let rule = PathRule {
        path: "/api/".to_string(),
        match_type: PathMatchType::Prefix,
        ..Default::default()
    };
    assert!(rule.matches("/api/users"));
    assert!(rule.matches("/api/"));
    assert!(!rule.matches("/other"));
}

#[test]
fn test_path_rule_matches_exact() {
    let rule = PathRule {
        path: "/health".to_string(),
        match_type: PathMatchType::Exact,
        ..Default::default()
    };
    assert!(rule.matches("/health"));
    assert!(!rule.matches("/health/check"));
    assert!(!rule.matches("/healthz"));
}

// ---- Route::with_path_rule_overrides ----

#[test]
fn test_route_with_path_rule_overrides_applies_some_fields() {
    let now = chrono::Utc::now();
    let route = Route {
        id: "r1".to_string(),
        hostname: "example.com".to_string(),
        path_prefix: "/".to_string(),
        certificate_id: None,
        load_balancing: LoadBalancing::RoundRobin,
        waf_enabled: false,
        waf_mode: WafMode::Detection,
        enabled: true,
        force_https: false,
        redirect_hostname: None,
        redirect_to: None,
        hostname_aliases: vec![],
        proxy_headers: HashMap::new(),
        response_headers: HashMap::new(),
        security_headers: "moderate".to_string(),
        connect_timeout_s: 5,
        read_timeout_s: 60,
        send_timeout_s: 60,
        strip_path_prefix: None,
        add_path_prefix: None,
        path_rewrite_pattern: None,
        path_rewrite_replacement: None,
        access_log_enabled: true,
        proxy_headers_remove: vec![],
        response_headers_remove: vec![],
        max_request_body_bytes: None,
        websocket_enabled: true,
        rate_limit_rps: None,
        rate_limit_burst: None,
        ip_allowlist: vec![],
        ip_denylist: vec![],
        cors_allowed_origins: vec![],
        cors_allowed_methods: vec![],
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
        cache_vary_headers: Vec::new(),
        header_rules: Vec::new(),
        traffic_splits: Vec::new(),
        forward_auth: None,
        mirror: None,
        response_rewrite: None,
        mtls: None,
        created_at: now,
        updated_at: now,
    };

    let rule = PathRule {
        path: "/api/".to_string(),
        match_type: PathMatchType::Prefix,
        cache_enabled: Some(true),
        cache_ttl_s: Some(60),
        rate_limit_rps: Some(100),
        return_status: Some(503),
        ..Default::default()
    };

    let overridden = route.with_path_rule_overrides(&rule);
    assert!(overridden.cache_enabled);
    assert_eq!(overridden.cache_ttl_s, 60);
    assert_eq!(overridden.rate_limit_rps, Some(100));
    assert_eq!(overridden.return_status, Some(503));
    // Fields not in the rule remain unchanged
    assert_eq!(overridden.hostname, "example.com");
    assert!(!overridden.force_https);
}
