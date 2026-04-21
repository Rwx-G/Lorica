#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use std::str::FromStr;

    use chrono::Utc;
    use tempfile::NamedTempFile;

    use crate::export::export_to_toml;
    use crate::import::{import_to_store, parse_toml};
    use crate::models::*;
    use crate::store::{new_id, ConfigStore};

    fn make_route() -> Route {
        let now = Utc::now();
        Route {
            id: new_id(),
            hostname: "example.com".into(),
            path_prefix: "/".into(),
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

    fn make_backend() -> Backend {
        let now = Utc::now();
        Backend {
            id: new_id(),
            address: "192.168.1.10:8080".into(),
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

    fn make_certificate() -> Certificate {
        let now = Utc::now();
        Certificate {
            id: new_id(),
            domain: "example.com".into(),
            san_domains: vec!["www.example.com".into()],
            fingerprint: "sha256:abc123".into(),
            cert_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".into(),
            key_pem: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----".into(),
            issuer: "Let's Encrypt".into(),
            not_before: now,
            not_after: now,
            is_acme: false,
            acme_auto_renew: false,
            created_at: now,
            acme_method: None,

            acme_dns_provider_id: None,
        }
    }

    fn make_dns_provider() -> DnsProvider {
        DnsProvider {
            id: new_id(),
            name: "Test OVH Provider".into(),
            provider_type: "ovh".into(),
            config:
                r#"{"provider":"ovh","api_token":"ak","api_secret":"as","ovh_consumer_key":"ck"}"#
                    .into(),
            created_at: Utc::now(),
        }
    }

    fn make_notification_config() -> NotificationConfig {
        NotificationConfig {
            id: new_id(),
            channel: NotificationChannel::Email,
            enabled: true,
            config: r#"{"smtp_host":"mail.example.com"}"#.into(),
            alert_types: vec!["cert_expiry".into(), "backend_down".into()],
        }
    }

    fn make_user_preference() -> UserPreference {
        let now = Utc::now();
        UserPreference {
            id: new_id(),
            preference_key: "self_signed_cert".into(),
            value: PreferenceValue::Never,
            created_at: now,
            updated_at: now,
        }
    }

    fn make_admin_user() -> AdminUser {
        AdminUser {
            id: new_id(),
            username: "admin".into(),
            password_hash: "$argon2id$v=19$m=65536,t=3,p=4$fakehash".into(),
            must_change_password: true,
            created_at: Utc::now(),
            last_login: None,
        }
    }

    fn make_load_test_config() -> LoadTestConfig {
        let now = Utc::now();
        LoadTestConfig {
            id: new_id(),
            name: "Test Load Config".into(),
            target_url: "http://localhost:8080/".into(),
            method: "GET".into(),
            headers: std::collections::HashMap::new(),
            body: None,
            concurrency: 10,
            requests_per_second: 100,
            duration_s: 30,
            error_threshold_pct: 5.0,
            schedule_cron: Some("0 * * * *".into()),
            enabled: true,
            created_at: now,
            updated_at: now,
        }
    }

    // ---- LoadTestConfig Clone ----

    #[test]
    fn test_clone_load_test_config() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let config = make_load_test_config();
        store
            .create_load_test_config(&config)
            .expect("test setup: load test config inserts");

        let cloned = store
            .clone_load_test_config(&config.id, "Cloned Test")
            .expect("test setup: value present");
        assert_ne!(cloned.id, config.id);
        assert_eq!(cloned.name, "Cloned Test");
        assert_eq!(cloned.target_url, config.target_url);
        assert_eq!(cloned.concurrency, config.concurrency);
        assert!(cloned.schedule_cron.is_none()); // schedule not copied
    }

    // ---- Route CRUD ----

    #[test]
    fn test_route_crud() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut route = make_route();

        // Create
        store
            .create_route(&route)
            .expect("test setup: route inserts");

        // Read
        let fetched = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert_eq!(fetched.hostname, "example.com");
        assert_eq!(fetched.path_prefix, "/");

        // List
        let routes = store.list_routes().expect("test setup: routes listed");
        assert_eq!(routes.len(), 1);

        // Update
        route.hostname = "updated.com".into();
        route.updated_at = Utc::now();
        store
            .update_route(&route)
            .expect("test setup: route updates");
        let fetched = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert_eq!(fetched.hostname, "updated.com");

        // Delete
        store
            .delete_route(&route.id)
            .expect("test setup: route deletes");
        assert!(store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .is_none());
    }

    #[test]
    fn test_route_group_name_round_trips_through_store() {
        // v1.4.1: group_name is a new column; make sure INSERT, UPDATE
        // and SELECT all carry it end-to-end. Uses two routes to also
        // exercise ordering in list_routes.
        let store = ConfigStore::open_in_memory().expect("test setup");
        let mut r1 = make_route();
        r1.id = "r1".into();
        r1.hostname = "a.example.com".into();
        r1.group_name = "prod".into();
        let mut r2 = make_route();
        r2.id = "r2".into();
        r2.hostname = "b.example.com".into();
        r2.group_name = "staging".into();

        store.create_route(&r1).expect("test setup");
        store.create_route(&r2).expect("test setup");

        // get_route
        let got = store
            .get_route("r1")
            .expect("test setup")
            .expect("test setup");
        assert_eq!(got.group_name, "prod");

        // list_routes preserves group_name
        let list = store.list_routes().expect("test setup");
        let groups: Vec<_> = list.iter().map(|r| r.group_name.clone()).collect();
        assert!(groups.contains(&"prod".to_string()));
        assert!(groups.contains(&"staging".to_string()));

        // update_route changes only group_name
        let mut r1_updated = r1.clone();
        r1_updated.group_name = "retired".into();
        r1_updated.updated_at = Utc::now();
        store.update_route(&r1_updated).expect("test setup");
        let got = store
            .get_route("r1")
            .expect("test setup")
            .expect("test setup");
        assert_eq!(got.group_name, "retired");
    }

    #[test]
    fn test_route_group_name_defaults_to_empty() {
        // A route created without touching the field should round-trip
        // as empty string. `make_route` does not set group_name so the
        // default Vec<String>::new() applies.
        let store = ConfigStore::open_in_memory().expect("test setup");
        let route = make_route();
        assert_eq!(route.group_name, "");
        store.create_route(&route).expect("test setup");
        let got = store
            .get_route(&route.id)
            .expect("test setup")
            .expect("test setup");
        assert_eq!(got.group_name, "");
    }

    #[test]
    fn test_route_not_found() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut route = make_route();
        route.id = "nonexistent".into();
        assert!(store.update_route(&route).is_err());
        assert!(store.delete_route("nonexistent").is_err());
    }

    // ---- Backend CRUD ----

    #[test]
    fn test_backend_crud() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut backend = make_backend();

        store
            .create_backend(&backend)
            .expect("test setup: backend inserts");

        let fetched = store
            .get_backend(&backend.id)
            .expect("test setup: backend fetch")
            .expect("test setup: value present");
        assert_eq!(fetched.address, "192.168.1.10:8080");
        assert_eq!(fetched.weight, 100);

        let backends = store.list_backends().expect("test setup: backends listed");
        assert_eq!(backends.len(), 1);

        backend.address = "10.0.0.1:9090".into();
        backend.updated_at = Utc::now();
        store
            .update_backend(&backend)
            .expect("test setup: backend updates");
        let fetched = store
            .get_backend(&backend.id)
            .expect("test setup: backend fetch")
            .expect("test setup: value present");
        assert_eq!(fetched.address, "10.0.0.1:9090");

        store
            .delete_backend(&backend.id)
            .expect("test setup: backend deletes");
        assert!(store
            .get_backend(&backend.id)
            .expect("test setup: backend fetch")
            .is_none());
    }

    // ---- Route-Backend links ----

    #[test]
    fn test_route_backend_links() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let route = make_route();
        let backend = make_backend();

        store
            .create_route(&route)
            .expect("test setup: route inserts");
        store
            .create_backend(&backend)
            .expect("test setup: backend inserts");
        store
            .link_route_backend(&route.id, &backend.id)
            .expect("test setup: route/backend link");

        let backends = store
            .list_backends_for_route(&route.id)
            .expect("test setup: backends for route listed");
        assert_eq!(backends, vec![backend.id.clone()]);

        let routes = store
            .list_routes_for_backend(&backend.id)
            .expect("test setup: routes for backend listed");
        assert_eq!(routes, vec![route.id.clone()]);

        store
            .unlink_route_backend(&route.id, &backend.id)
            .expect("test setup: route/backend unlink");
        let backends = store
            .list_backends_for_route(&route.id)
            .expect("test setup: backends for route listed");
        assert!(backends.is_empty());
    }

    // ---- Certificate CRUD ----

    #[test]
    fn test_certificate_crud() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut cert = make_certificate();

        store
            .create_certificate(&cert)
            .expect("test setup: certificate inserts");

        let fetched = store
            .get_certificate(&cert.id)
            .expect("test setup: certificate fetch")
            .expect("test setup: value present");
        assert_eq!(fetched.domain, "example.com");
        assert_eq!(fetched.san_domains, vec!["www.example.com"]);

        let certs = store
            .list_certificates()
            .expect("test setup: certificates listed");
        assert_eq!(certs.len(), 1);

        cert.domain = "updated.com".into();
        store
            .update_certificate(&cert)
            .expect("test setup: certificate updates");
        let fetched = store
            .get_certificate(&cert.id)
            .expect("test setup: certificate fetch")
            .expect("test setup: value present");
        assert_eq!(fetched.domain, "updated.com");

        store
            .delete_certificate(&cert.id)
            .expect("test setup: certificate deletes");
        assert!(store
            .get_certificate(&cert.id)
            .expect("test setup: certificate fetch")
            .is_none());
    }

    // ---- NotificationConfig CRUD ----

    #[test]
    fn test_notification_config_crud() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut nc = make_notification_config();

        store
            .create_notification_config(&nc)
            .expect("test setup: notification config inserts");

        let fetched = store
            .get_notification_config(&nc.id)
            .expect("test setup: notification config fetch")
            .expect("test setup: value present");
        assert_eq!(fetched.channel, NotificationChannel::Email);
        assert_eq!(fetched.alert_types.len(), 2);

        let configs = store
            .list_notification_configs()
            .expect("test setup: notification configs listed");
        assert_eq!(configs.len(), 1);

        nc.enabled = false;
        store
            .update_notification_config(&nc)
            .expect("test setup: notification config updates");
        let fetched = store
            .get_notification_config(&nc.id)
            .expect("test setup: notification config fetch")
            .expect("test setup: value present");
        assert!(!fetched.enabled);

        store
            .delete_notification_config(&nc.id)
            .expect("test setup: notification config deletes");
        assert!(store
            .get_notification_config(&nc.id)
            .expect("test setup: notification config fetch")
            .is_none());
    }

    // ---- DnsProvider CRUD ----

    #[test]
    fn test_dns_provider_crud() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut provider = make_dns_provider();

        store
            .create_dns_provider(&provider)
            .expect("test setup: dns provider inserts");

        let fetched = store
            .get_dns_provider(&provider.id)
            .expect("test setup: dns provider fetch")
            .expect("test setup: value present");
        assert_eq!(fetched.name, "Test OVH Provider");
        assert_eq!(fetched.provider_type, "ovh");
        assert!(fetched.config.contains("api_token"));

        let providers = store
            .list_dns_providers()
            .expect("test setup: dns providers listed");
        assert_eq!(providers.len(), 1);

        provider.name = "Updated Provider".into();
        store
            .update_dns_provider(&provider)
            .expect("test setup: dns provider updates");
        let fetched = store
            .get_dns_provider(&provider.id)
            .expect("test setup: dns provider fetch")
            .expect("test setup: value present");
        assert_eq!(fetched.name, "Updated Provider");

        // Not in use
        assert!(!store
            .dns_provider_in_use(&provider.id)
            .expect("test setup: dns provider in-use check"));

        store
            .delete_dns_provider(&provider.id)
            .expect("test setup: dns provider deletes");
        assert!(store
            .get_dns_provider(&provider.id)
            .expect("test setup: dns provider fetch")
            .is_none());
    }

    #[test]
    fn test_dns_provider_unique_name() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let p1 = make_dns_provider();
        store
            .create_dns_provider(&p1)
            .expect("test setup: dns provider inserts");

        let mut p2 = make_dns_provider();
        p2.name = p1.name.clone(); // same name, different id
        let result = store.create_dns_provider(&p2);
        assert!(result.is_err(), "duplicate name should fail");
    }

    #[test]
    fn test_dns_provider_in_use() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let provider = make_dns_provider();
        store
            .create_dns_provider(&provider)
            .expect("test setup: dns provider inserts");

        let mut cert = make_certificate();
        cert.acme_dns_provider_id = Some(provider.id.clone());
        store
            .create_certificate(&cert)
            .expect("test setup: certificate inserts");

        assert!(store
            .dns_provider_in_use(&provider.id)
            .expect("test setup: dns provider in-use check"));

        store
            .delete_certificate(&cert.id)
            .expect("test setup: certificate deletes");
        assert!(!store
            .dns_provider_in_use(&provider.id)
            .expect("test setup: dns provider in-use check"));
    }

    // ---- UserPreference CRUD ----

    #[test]
    fn test_user_preference_crud() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut pref = make_user_preference();

        store
            .create_user_preference(&pref)
            .expect("test setup: user preference inserts");

        let fetched = store
            .get_user_preference(&pref.id)
            .expect("test setup: user preference fetch")
            .expect("test setup: value present");
        assert_eq!(fetched.preference_key, "self_signed_cert");
        assert_eq!(fetched.value, PreferenceValue::Never);

        let by_key = store
            .get_user_preference_by_key("self_signed_cert")
            .expect("test setup: value present")
            .expect("test setup: value present");
        assert_eq!(by_key.id, pref.id);

        let prefs = store
            .list_user_preferences()
            .expect("test setup: user preferences listed");
        assert_eq!(prefs.len(), 1);

        pref.value = PreferenceValue::Always;
        pref.updated_at = Utc::now();
        store
            .update_user_preference(&pref)
            .expect("test setup: user preference updates");
        let fetched = store
            .get_user_preference(&pref.id)
            .expect("test setup: user preference fetch")
            .expect("test setup: value present");
        assert_eq!(fetched.value, PreferenceValue::Always);

        store
            .delete_user_preference(&pref.id)
            .expect("test setup: user preference deletes");
        assert!(store
            .get_user_preference(&pref.id)
            .expect("test setup: user preference fetch")
            .is_none());
    }

    // ---- AdminUser CRUD ----

    #[test]
    fn test_admin_user_crud() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut user = make_admin_user();

        store
            .create_admin_user(&user)
            .expect("test setup: admin user inserts");

        let fetched = store
            .get_admin_user(&user.id)
            .expect("test setup: admin user fetch")
            .expect("test setup: value present");
        assert_eq!(fetched.username, "admin");
        assert!(fetched.must_change_password);

        let by_name = store
            .get_admin_user_by_username("admin")
            .expect("test setup: admin user by username")
            .expect("test setup: value present");
        assert_eq!(by_name.id, user.id);

        let users = store
            .list_admin_users()
            .expect("test setup: admin users listed");
        assert_eq!(users.len(), 1);

        user.must_change_password = false;
        user.last_login = Some(Utc::now());
        store
            .update_admin_user(&user)
            .expect("test setup: admin user updates");
        let fetched = store
            .get_admin_user(&user.id)
            .expect("test setup: admin user fetch")
            .expect("test setup: value present");
        assert!(!fetched.must_change_password);
        assert!(fetched.last_login.is_some());

        store
            .delete_admin_user(&user.id)
            .expect("test setup: admin user deletes");
        assert!(store
            .get_admin_user(&user.id)
            .expect("test setup: admin user fetch")
            .is_none());
    }

    // ---- GlobalSettings ----

    #[test]
    fn test_global_settings() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");

        // Defaults from migration
        let settings = store
            .get_global_settings()
            .expect("test setup: global settings fetch");
        assert_eq!(settings.management_port, 9443);
        assert_eq!(settings.log_level, "info");
        assert_eq!(settings.default_health_check_interval_s, 10);

        // Update
        let new_settings = GlobalSettings {
            management_port: 8443,
            log_level: "debug".into(),
            default_health_check_interval_s: 30,
            cert_warning_days: 14,
            cert_critical_days: 3,

            ..GlobalSettings::default()
        };
        store
            .update_global_settings(&new_settings)
            .expect("test setup: global settings update");
        let fetched = store
            .get_global_settings()
            .expect("test setup: global settings fetch");
        assert_eq!(fetched.management_port, 8443);
        assert_eq!(fetched.log_level, "debug");
        assert_eq!(fetched.default_health_check_interval_s, 30);
    }

    #[test]
    fn test_global_settings_custom_security_presets_round_trip() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");

        // Initially empty
        let settings = store
            .get_global_settings()
            .expect("test setup: global settings fetch");
        assert!(settings.custom_security_presets.is_empty());

        // Store custom presets
        let custom = SecurityHeaderPreset {
            name: "api-only".to_string(),
            headers: std::collections::HashMap::from([
                ("X-API-Version".to_string(), "2".to_string()),
                ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
            ]),
        };
        let mut updated = settings;
        updated.custom_security_presets = vec![custom];
        store
            .update_global_settings(&updated)
            .expect("test setup: global settings update");

        // Read back
        let fetched = store
            .get_global_settings()
            .expect("test setup: global settings fetch");
        assert_eq!(fetched.custom_security_presets.len(), 1);
        assert_eq!(fetched.custom_security_presets[0].name, "api-only");
        assert_eq!(
            fetched.custom_security_presets[0].headers["X-API-Version"],
            "2"
        );
    }

    #[test]
    fn test_global_settings_trusted_proxies_round_trip() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");

        // Initially empty
        let settings = store
            .get_global_settings()
            .expect("test setup: global settings fetch");
        assert!(settings.trusted_proxies.is_empty());

        // Store trusted proxies
        let mut updated = settings;
        updated.trusted_proxies = vec!["192.168.0.0/16".to_string(), "10.0.0.1".to_string()];
        store
            .update_global_settings(&updated)
            .expect("test setup: global settings update");

        // Read back
        let fetched = store
            .get_global_settings()
            .expect("test setup: global settings fetch");
        assert_eq!(fetched.trusted_proxies.len(), 2);
        assert_eq!(fetched.trusted_proxies[0], "192.168.0.0/16");
        assert_eq!(fetched.trusted_proxies[1], "10.0.0.1");
    }

    #[test]
    fn test_global_settings_otlp_round_trip() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");

        // Defaults: endpoint None (OTel disabled), protocol http-proto,
        // service name "lorica", sampling 0.1.
        let settings = store
            .get_global_settings()
            .expect("test setup: global settings fetch");
        assert!(settings.otlp_endpoint.is_none());
        assert_eq!(settings.otlp_protocol, "http-proto");
        assert_eq!(settings.otlp_service_name, "lorica");
        assert!((settings.otlp_sampling_ratio - 0.1).abs() < f64::EPSILON);

        // Round-trip non-default values.
        let mut updated = settings;
        updated.otlp_endpoint = Some("http://tempo:4318".to_string());
        updated.otlp_protocol = "grpc".to_string();
        updated.otlp_service_name = "lorica-prod".to_string();
        updated.otlp_sampling_ratio = 0.25;
        store
            .update_global_settings(&updated)
            .expect("test setup: global settings update");

        let fetched = store
            .get_global_settings()
            .expect("test setup: global settings fetch");
        assert_eq!(fetched.otlp_endpoint.as_deref(), Some("http://tempo:4318"));
        assert_eq!(fetched.otlp_protocol, "grpc");
        assert_eq!(fetched.otlp_service_name, "lorica-prod");
        assert!((fetched.otlp_sampling_ratio - 0.25).abs() < f64::EPSILON);

        // Clearing the endpoint (empty string) deserialises back to None
        // so operators can turn OTel off via the dashboard without
        // dropping the row.
        let mut cleared = fetched;
        cleared.otlp_endpoint = None;
        store
            .update_global_settings(&cleared)
            .expect("test setup: global settings update");
        let fetched = store
            .get_global_settings()
            .expect("test setup: global settings fetch");
        assert!(fetched.otlp_endpoint.is_none());
    }

    // ---- Migration ----

    #[test]
    fn test_migration_version() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        assert_eq!(
            store
                .schema_version()
                .expect("test setup: schema version reads"),
            21
        );
    }

    #[test]
    fn test_migration_idempotent() {
        // Opening twice should not fail - migrations should be idempotent
        let tmp = NamedTempFile::new().expect("test setup: new() succeeds");
        let path = tmp.path();
        {
            let _store = ConfigStore::open(path, None).expect("test setup: store opens");
        }
        {
            let store = ConfigStore::open(path, None).expect("test setup: store opens");
            assert_eq!(
                store
                    .schema_version()
                    .expect("test setup: schema version reads"),
                21
            );
        }
    }

    // ---- Export/Import round-trip ----

    #[test]
    fn test_export_import_round_trip() {
        let store1 = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");

        // Populate with test data
        let cert = make_certificate();
        store1
            .create_certificate(&cert)
            .expect("test setup: certificate inserts");

        let mut route = make_route();
        route.certificate_id = Some(cert.id.clone());
        store1
            .create_route(&route)
            .expect("test setup: route inserts");

        let backend = make_backend();
        store1
            .create_backend(&backend)
            .expect("test setup: backend inserts");
        store1
            .link_route_backend(&route.id, &backend.id)
            .expect("test setup: route/backend link");

        let nc = make_notification_config();
        store1
            .create_notification_config(&nc)
            .expect("test setup: notification config inserts");

        let pref = make_user_preference();
        store1
            .create_user_preference(&pref)
            .expect("test setup: user preference inserts");

        let user = make_admin_user();
        store1
            .create_admin_user(&user)
            .expect("test setup: admin user inserts");

        let settings = GlobalSettings {
            management_port: 8443,
            log_level: "debug".into(),
            default_health_check_interval_s: 30,
            cert_warning_days: 14,
            cert_critical_days: 3,

            ..GlobalSettings::default()
        };
        store1
            .update_global_settings(&settings)
            .expect("test setup: global settings update");

        // Export
        let toml_str = export_to_toml(&store1).expect("test setup: toml export succeeds");

        // Verify password hash is redacted in export
        assert!(toml_str.contains("**REDACTED**"));
        assert!(!toml_str.contains(&user.password_hash));

        // Import into a fresh store - restore real hash since export redacts it
        let store2 = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let toml_for_import = toml_str.replace("**REDACTED**", &user.password_hash);
        let data = parse_toml(&toml_for_import).expect("test setup: toml parses");
        import_to_store(&store2, &data).expect("test setup: import succeeds");

        // Verify all data matches
        let routes2 = store2.list_routes().expect("test setup: routes listed");
        assert_eq!(routes2.len(), 1);
        assert_eq!(routes2[0].hostname, route.hostname);
        assert_eq!(routes2[0].certificate_id, Some(cert.id.clone()));

        let backends2 = store2.list_backends().expect("test setup: backends listed");
        assert_eq!(backends2.len(), 1);
        assert_eq!(backends2[0].address, backend.address);

        let links = store2
            .list_backends_for_route(&route.id)
            .expect("test setup: backends for route listed");
        assert_eq!(links, vec![backend.id.clone()]);

        let certs2 = store2
            .list_certificates()
            .expect("test setup: certificates listed");
        assert_eq!(certs2.len(), 1);
        assert_eq!(certs2[0].domain, cert.domain);

        let ncs2 = store2
            .list_notification_configs()
            .expect("test setup: notification configs listed");
        assert_eq!(ncs2.len(), 1);

        let prefs2 = store2
            .list_user_preferences()
            .expect("test setup: user preferences listed");
        assert_eq!(prefs2.len(), 1);
        assert_eq!(prefs2[0].preference_key, pref.preference_key);

        let users2 = store2
            .list_admin_users()
            .expect("test setup: admin users listed");
        assert_eq!(users2.len(), 1);
        assert_eq!(users2[0].username, user.username);

        let settings2 = store2
            .get_global_settings()
            .expect("test setup: global settings fetch");
        assert_eq!(settings2.management_port, 8443);
        assert_eq!(settings2.log_level, "debug");
    }

    // ---- WAL mode / crash safety ----

    #[test]
    fn test_wal_mode_enabled() {
        let tmp = NamedTempFile::new().expect("test setup: new() succeeds");
        let store = ConfigStore::open(tmp.path(), None).expect("test setup: store opens");

        // Verify WAL mode by writing and reading back
        let route = make_route();
        store
            .create_route(&route)
            .expect("test setup: route inserts");

        // Data survives re-open (simulates crash recovery)
        drop(store);
        let store2 = ConfigStore::open(tmp.path(), None).expect("test setup: store opens");
        let fetched = store2
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert_eq!(fetched.hostname, "example.com");
    }

    // ---- Import validation ----

    #[test]
    fn test_import_validates_references() {
        let toml_str = r#"
version = 1

[global_settings]
management_port = 9443
log_level = "info"
default_health_check_interval_s = 10

[[routes]]
id = "route-1"
hostname = "test.com"
path_prefix = "/"
certificate_id = "nonexistent-cert"
load_balancing = "round_robin"
waf_enabled = false
waf_mode = "detection"

enabled = true
created_at = "2026-01-01T00:00:00Z"
updated_at = "2026-01-01T00:00:00Z"
"#;
        let result = parse_toml(toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unknown certificate_id"));
    }

    #[test]
    fn test_import_validates_route_backend_refs() {
        let toml_str = r#"
version = 1

[global_settings]
management_port = 9443
log_level = "info"
default_health_check_interval_s = 10

[[route_backends]]
route_id = "nonexistent"
backend_id = "also-nonexistent"
"#;
        let result = parse_toml(toml_str);
        assert!(result.is_err());
    }

    // ---- File-based export/import ----

    #[test]
    fn test_file_export_import() {
        let store1 = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let route = make_route();
        store1
            .create_route(&route)
            .expect("test setup: route inserts");

        let tmp = NamedTempFile::new().expect("test setup: new() succeeds");
        crate::export::export_to_file(&store1, tmp.path()).expect("test setup: value present");

        let store2 = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        crate::import::import_from_file(&store2, tmp.path()).expect("test setup: value present");

        let routes = store2.list_routes().expect("test setup: routes listed");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].hostname, route.hostname);
    }

    // ---- Clear all ----

    #[test]
    fn test_clear_all() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        store
            .create_route(&make_route())
            .expect("test setup: route inserts");
        store
            .create_backend(&make_backend())
            .expect("test setup: backend inserts");
        store
            .create_certificate(&make_certificate())
            .expect("test setup: certificate inserts");

        store.clear_all().expect("test setup: value present");

        assert!(store
            .list_routes()
            .expect("test setup: routes listed")
            .is_empty());
        assert!(store
            .list_backends()
            .expect("test setup: backends listed")
            .is_empty());
        assert!(store
            .list_certificates()
            .expect("test setup: certificates listed")
            .is_empty());
    }

    // ---- Encryption at rest ----

    #[test]
    fn test_key_pem_encrypted_at_rest() {
        use crate::crypto::EncryptionKey;

        let key = EncryptionKey::generate().expect("test setup: key generates");
        let store = ConfigStore::open_in_memory_with_key(key)
            .expect("test setup: in-memory store opens with key");
        let cert = make_certificate();
        let original_key_pem = cert.key_pem.clone();

        store
            .create_certificate(&cert)
            .expect("test setup: certificate inserts");

        // Verify we can read back the decrypted key_pem
        let fetched = store
            .get_certificate(&cert.id)
            .expect("test setup: certificate fetch")
            .expect("test setup: value present");
        assert_eq!(fetched.key_pem, original_key_pem);

        // Verify it's stored encrypted in the DB (raw query)
        let raw: Vec<u8> = store
            .conn
            .query_row(
                "SELECT key_pem FROM certificates WHERE id=?1",
                rusqlite::params![cert.id],
                |row| row.get(0),
            )
            .expect("test setup: value present");
        // Encrypted data should differ from plaintext
        assert_ne!(raw, original_key_pem.as_bytes());
        // Encrypted data should be larger (nonce + tag overhead)
        assert!(raw.len() > original_key_pem.len());
    }

    #[test]
    fn test_key_pem_round_trip_with_encryption() {
        use crate::crypto::EncryptionKey;

        let key = EncryptionKey::generate().expect("test setup: key generates");
        let store = ConfigStore::open_in_memory_with_key(key)
            .expect("test setup: in-memory store opens with key");

        let cert = make_certificate();
        store
            .create_certificate(&cert)
            .expect("test setup: certificate inserts");

        // List also decrypts
        let certs = store
            .list_certificates()
            .expect("test setup: certificates listed");
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].key_pem, cert.key_pem);

        // Update also encrypts
        let mut updated = cert.clone();
        updated.key_pem = "-----BEGIN PRIVATE KEY-----\nnew key\n-----END PRIVATE KEY-----".into();
        store
            .update_certificate(&updated)
            .expect("test setup: certificate updates");

        let fetched = store
            .get_certificate(&updated.id)
            .expect("test setup: certificate fetch")
            .expect("test setup: value present");
        assert_eq!(fetched.key_pem, updated.key_pem);
    }

    // ---- ConfigDiff tests ----

    #[test]
    fn test_diff_empty_to_empty() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let toml_str = export_to_toml(&store).expect("test setup: toml export succeeds");
        let import_data = parse_toml(&toml_str).expect("test setup: toml parses");
        let diff =
            crate::diff::compute_diff(&store, &import_data).expect("test setup: diff computes");
        assert!(diff.is_empty());
    }

    #[test]
    fn test_diff_detects_added_route() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let route = make_route();

        // Build import data with one route, current store is empty
        let toml_str = {
            let temp = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
            temp.create_route(&route)
                .expect("test setup: route inserts");
            export_to_toml(&temp).expect("test setup: toml export succeeds")
        };
        let import_data = parse_toml(&toml_str).expect("test setup: toml parses");
        let diff =
            crate::diff::compute_diff(&store, &import_data).expect("test setup: diff computes");

        assert_eq!(diff.routes.added.len(), 1);
        assert!(diff.routes.removed.is_empty());
        assert!(diff.routes.modified.is_empty());
    }

    #[test]
    fn test_diff_detects_removed_backend() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let backend = make_backend();
        store
            .create_backend(&backend)
            .expect("test setup: backend inserts");

        // Import data with no backends
        let toml_str = {
            let temp = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
            export_to_toml(&temp).expect("test setup: toml export succeeds")
        };
        let import_data = parse_toml(&toml_str).expect("test setup: toml parses");
        let diff =
            crate::diff::compute_diff(&store, &import_data).expect("test setup: diff computes");

        assert!(diff.backends.added.is_empty());
        assert_eq!(diff.backends.removed.len(), 1);
    }

    #[test]
    fn test_diff_detects_modified_route() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let route = make_route();
        store
            .create_route(&route)
            .expect("test setup: route inserts");

        // Modify hostname in import data
        let mut modified = route.clone();
        modified.hostname = "modified.com".into();
        let toml_str = {
            let temp = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
            temp.create_route(&modified)
                .expect("test setup: route inserts");
            export_to_toml(&temp).expect("test setup: toml export succeeds")
        };
        let import_data = parse_toml(&toml_str).expect("test setup: toml parses");
        let diff =
            crate::diff::compute_diff(&store, &import_data).expect("test setup: diff computes");

        assert!(diff.routes.added.is_empty());
        assert!(diff.routes.removed.is_empty());
        assert_eq!(diff.routes.modified.len(), 1);
    }

    #[test]
    fn test_diff_detects_group_name_change() {
        // v1.4.1: changing only group_name must surface in compute_diff
        // so an import preview shows the classification drift. The
        // proxy does not reload on this field alone, but an import
        // diff is a user-facing view of "what will change".
        let store = ConfigStore::open_in_memory().expect("test setup");
        let mut route = make_route();
        route.group_name = "staging".into();
        store.create_route(&route).expect("test setup");

        let mut modified = route.clone();
        modified.group_name = "prod".into();
        let toml_str = {
            let temp = ConfigStore::open_in_memory().expect("test setup");
            temp.create_route(&modified).expect("test setup");
            export_to_toml(&temp).expect("test setup")
        };
        let import_data = parse_toml(&toml_str).expect("test setup");
        let diff = crate::diff::compute_diff(&store, &import_data).expect("test setup");

        assert_eq!(diff.routes.modified.len(), 1);
    }

    #[test]
    fn test_diff_detects_settings_change() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");

        let toml_str = r#"
version = 1

[global_settings]
management_port = 9443
log_level = "debug"
default_health_check_interval_s = 30
"#;
        let import_data = parse_toml(toml_str).expect("test setup: toml parses");
        let diff =
            crate::diff::compute_diff(&store, &import_data).expect("test setup: diff computes");

        assert_eq!(diff.global_settings.changes.len(), 2);
        assert!(!diff.is_empty());
    }

    // ---- Import validation edge cases ----

    #[test]
    fn test_import_version_zero_rejected() {
        let toml_str = r#"
version = 0

[global_settings]
management_port = 9443
log_level = "info"
default_health_check_interval_s = 10
"#;
        let result = parse_toml(toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("version must be >= 1"));
    }

    #[test]
    fn test_import_empty_string_fails() {
        let result = parse_toml("");
        assert!(result.is_err());
    }

    #[test]
    fn test_import_malformed_toml_syntax_fails() {
        let result = parse_toml("this is {{ not valid toml");
        assert!(result.is_err());
    }

    #[test]
    fn test_import_missing_global_settings_fails() {
        let toml_str = r#"
version = 1
"#;
        let result = parse_toml(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_import_route_backend_unknown_route_ref() {
        let toml_str = r#"
version = 1

[global_settings]
management_port = 9443
log_level = "info"
default_health_check_interval_s = 10

[[backends]]
id = "b1"
address = "10.0.0.1:8080"
weight = 100
health_status = "healthy"
health_check_enabled = true
health_check_interval_s = 10
lifecycle_state = "normal"
active_connections = 0
tls_upstream = false
created_at = "2026-01-01T00:00:00Z"
updated_at = "2026-01-01T00:00:00Z"

[[route_backends]]
route_id = "nonexistent-route"
backend_id = "b1"
"#;
        let result = parse_toml(toml_str);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown route_id"));
    }

    #[test]
    fn test_import_route_backend_unknown_backend_ref() {
        let toml_str = r#"
version = 1

[global_settings]
management_port = 9443
log_level = "info"
default_health_check_interval_s = 10

[[routes]]
id = "r1"
hostname = "test.com"
path_prefix = "/"
load_balancing = "round_robin"
waf_enabled = false
waf_mode = "detection"

enabled = true
created_at = "2026-01-01T00:00:00Z"
updated_at = "2026-01-01T00:00:00Z"

[[route_backends]]
route_id = "r1"
backend_id = "nonexistent-backend"
"#;
        let result = parse_toml(toml_str);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unknown backend_id"));
    }

    #[test]
    fn test_import_valid_minimal() {
        let toml_str = r#"
version = 1

[global_settings]
management_port = 9443
log_level = "info"
default_health_check_interval_s = 10
"#;
        let data = parse_toml(toml_str).expect("test setup: toml parses");
        assert_eq!(data.version, 1);
        assert!(data.routes.is_empty());
        assert!(data.backends.is_empty());
    }

    #[test]
    fn test_import_replaces_all_data() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");

        // Pre-populate
        store
            .create_route(&make_route())
            .expect("test setup: route inserts");
        store
            .create_backend(&make_backend())
            .expect("test setup: backend inserts");
        assert_eq!(
            store
                .list_routes()
                .expect("test setup: routes listed")
                .len(),
            1
        );
        assert_eq!(
            store
                .list_backends()
                .expect("test setup: backends listed")
                .len(),
            1
        );

        // Import empty config
        let toml_str = r#"
version = 1

[global_settings]
management_port = 9443
log_level = "info"
default_health_check_interval_s = 10
"#;
        let data = parse_toml(toml_str).expect("test setup: toml parses");
        import_to_store(&store, &data).expect("test setup: import succeeds");

        // Everything should be cleared
        assert!(store
            .list_routes()
            .expect("test setup: routes listed")
            .is_empty());
        assert!(store
            .list_backends()
            .expect("test setup: backends listed")
            .is_empty());
    }

    // ---- ConfigDiff edge cases ----

    #[test]
    fn test_diff_route_backends_added_and_removed() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let route = make_route();
        let backend1 = make_backend();
        store
            .create_route(&route)
            .expect("test setup: route inserts");
        store
            .create_backend(&backend1)
            .expect("test setup: backend inserts");
        store
            .link_route_backend(&route.id, &backend1.id)
            .expect("test setup: route/backend link");

        // Import data with a different backend link
        let mut backend2 = make_backend();
        backend2.id = "backend-new".into();
        let temp = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        temp.create_route(&route)
            .expect("test setup: route inserts");
        temp.create_backend(&backend2)
            .expect("test setup: backend inserts");
        temp.link_route_backend(&route.id, &backend2.id)
            .expect("test setup: route/backend link");
        let toml_str = export_to_toml(&temp).expect("test setup: toml export succeeds");

        let import_data = parse_toml(&toml_str).expect("test setup: toml parses");
        let diff =
            crate::diff::compute_diff(&store, &import_data).expect("test setup: diff computes");

        assert!(!diff.route_backends.added.is_empty());
        assert!(!diff.route_backends.removed.is_empty());
    }

    #[test]
    fn test_diff_notification_config_changes() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let nc = make_notification_config();
        store
            .create_notification_config(&nc)
            .expect("test setup: notification config inserts");

        // Import with modified notification
        let mut modified = nc.clone();
        modified.enabled = false;
        let temp = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        temp.create_notification_config(&modified)
            .expect("test setup: notification config inserts");
        let toml_str = export_to_toml(&temp).expect("test setup: toml export succeeds");

        let import_data = parse_toml(&toml_str).expect("test setup: toml parses");
        let diff =
            crate::diff::compute_diff(&store, &import_data).expect("test setup: diff computes");

        assert_eq!(diff.notification_configs.modified.len(), 1);
    }

    #[test]
    fn test_diff_admin_user_changes() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let user = make_admin_user();
        store
            .create_admin_user(&user)
            .expect("test setup: admin user inserts");

        // Import with modified username
        let mut modified = user.clone();
        modified.username = "superadmin".into();
        let temp = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        temp.create_admin_user(&modified)
            .expect("test setup: admin user inserts");
        let toml_str = export_to_toml(&temp).expect("test setup: toml export succeeds");

        // Restore real hash since export redacts it
        let toml_str = toml_str.replace("**REDACTED**", &modified.password_hash);
        let import_data = parse_toml(&toml_str).expect("test setup: toml parses");
        let diff =
            crate::diff::compute_diff(&store, &import_data).expect("test setup: diff computes");

        assert_eq!(diff.admin_users.modified.len(), 1);
    }

    #[test]
    fn test_diff_user_preference_changes() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let pref = make_user_preference();
        store
            .create_user_preference(&pref)
            .expect("test setup: user preference inserts");

        let mut modified = pref.clone();
        modified.value = PreferenceValue::Always;
        let temp = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        temp.create_user_preference(&modified)
            .expect("test setup: user preference inserts");
        let toml_str = export_to_toml(&temp).expect("test setup: toml export succeeds");

        let import_data = parse_toml(&toml_str).expect("test setup: toml parses");
        let diff =
            crate::diff::compute_diff(&store, &import_data).expect("test setup: diff computes");

        assert_eq!(diff.user_preferences.modified.len(), 1);
    }

    #[test]
    fn test_diff_all_settings_fields() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");

        let toml_str = r#"
version = 1

[global_settings]
management_port = 8443
log_level = "debug"
default_health_check_interval_s = 30
cert_warning_days = 14
cert_critical_days = 3
"#;
        let import_data = parse_toml(toml_str).expect("test setup: toml parses");
        let diff =
            crate::diff::compute_diff(&store, &import_data).expect("test setup: diff computes");

        // All 5 settings should differ from defaults
        assert_eq!(diff.global_settings.changes.len(), 5);
    }

    #[test]
    fn test_diff_certificate_changes() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let cert = make_certificate();
        store
            .create_certificate(&cert)
            .expect("test setup: certificate inserts");

        let mut modified = cert.clone();
        modified.domain = "new-domain.com".into();
        let temp = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        temp.create_certificate(&modified)
            .expect("test setup: certificate inserts");
        let toml_str = export_to_toml(&temp).expect("test setup: toml export succeeds");

        let import_data =
            crate::import::parse_toml_for_preview(&toml_str).expect("test setup: value present");
        let diff =
            crate::diff::compute_diff(&store, &import_data).expect("test setup: diff computes");

        assert_eq!(diff.certificates.modified.len(), 1);
    }

    // ---- Export tests ----

    #[test]
    fn test_export_empty_store_produces_valid_toml() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let toml_str = export_to_toml(&store).expect("test setup: toml export succeeds");
        assert!(toml_str.contains("version = 1"));
        assert!(toml_str.contains("[global_settings]"));
        // Should be re-importable
        let data = parse_toml(&toml_str).expect("test setup: toml parses");
        assert_eq!(data.version, 1);
    }

    #[test]
    fn test_export_preserves_all_entity_types() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");

        let cert = make_certificate();
        store
            .create_certificate(&cert)
            .expect("test setup: certificate inserts");

        let mut route = make_route();
        route.certificate_id = Some(cert.id.clone());
        store
            .create_route(&route)
            .expect("test setup: route inserts");

        let backend = make_backend();
        store
            .create_backend(&backend)
            .expect("test setup: backend inserts");
        store
            .link_route_backend(&route.id, &backend.id)
            .expect("test setup: route/backend link");

        let nc = make_notification_config();
        store
            .create_notification_config(&nc)
            .expect("test setup: notification config inserts");

        let pref = make_user_preference();
        store
            .create_user_preference(&pref)
            .expect("test setup: user preference inserts");

        let user = make_admin_user();
        store
            .create_admin_user(&user)
            .expect("test setup: admin user inserts");

        let toml_str = export_to_toml(&store).expect("test setup: toml export succeeds");

        // All sections should appear
        assert!(toml_str.contains("[[routes]]"));
        assert!(toml_str.contains("[[backends]]"));
        assert!(toml_str.contains("[[certificates]]"));
        assert!(toml_str.contains("[[route_backends]]"));
        assert!(toml_str.contains("[[notification_configs]]"));
        assert!(toml_str.contains("[[user_preferences]]"));
        assert!(toml_str.contains("[[admin_users]]"));
    }

    // ---- Error type tests ----

    #[test]
    fn test_config_error_display() {
        let err = crate::error::ConfigError::NotFound("route 1".into());
        assert_eq!(err.to_string(), "not found: route 1");

        let err = crate::error::ConfigError::Validation("bad ref".into());
        assert_eq!(err.to_string(), "validation error: bad ref");

        let err = crate::error::ConfigError::Serialization("toml fail".into());
        assert_eq!(err.to_string(), "serialization error: toml fail");
    }

    // ---- Backend address validation ----

    #[test]
    fn test_backend_address_missing_port_rejected() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut backend = make_backend();
        backend.address = "192.168.1.10".into(); // no port
        let result = store.create_backend(&backend);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("ip:port"));
    }

    #[test]
    fn test_backend_address_trailing_colon_rejected() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut backend = make_backend();
        backend.address = "192.168.1.10:".into();
        let result = store.create_backend(&backend);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("ip:port"));
    }

    #[test]
    fn test_backend_address_invalid_port_rejected() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut backend = make_backend();
        backend.address = "192.168.1.10:notaport".into();
        let result = store.create_backend(&backend);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid port"));
    }

    #[test]
    fn test_backend_address_port_out_of_range_rejected() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut backend = make_backend();
        backend.address = "192.168.1.10:99999".into(); // > u16::MAX
        let result = store.create_backend(&backend);
        assert!(result.is_err());
    }

    #[test]
    fn test_backend_address_valid_formats() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");

        // IPv4 with port
        let mut b1 = make_backend();
        b1.address = "10.0.0.1:443".into();
        assert!(store.create_backend(&b1).is_ok());

        // hostname:port
        let mut b2 = make_backend();
        b2.address = "backend.internal:8080".into();
        assert!(store.create_backend(&b2).is_ok());
    }

    #[test]
    fn test_backend_update_also_validates_address() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut backend = make_backend();
        store
            .create_backend(&backend)
            .expect("test setup: backend inserts");

        backend.address = "no-port-here".into();
        let result = store.update_backend(&backend);
        assert!(result.is_err());
    }

    // ---- Hostname uniqueness ----

    #[test]
    fn test_hostname_uniqueness_rejects_duplicate_primary() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let route1 = make_route();
        store
            .create_route(&route1)
            .expect("test setup: route inserts");

        let mut route2 = make_route();
        route2.hostname = "example.com".into(); // same hostname as route1
        let result = store.create_route(&route2);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("already used"));
    }

    #[test]
    fn test_hostname_uniqueness_rejects_alias_conflict_with_primary() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let route1 = make_route();
        store
            .create_route(&route1)
            .expect("test setup: route inserts");

        let mut route2 = make_route();
        route2.hostname = "other.com".into();
        route2.hostname_aliases = vec!["example.com".into()]; // alias conflicts with route1 primary
        let result = store.create_route(&route2);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("already used"));
    }

    #[test]
    fn test_hostname_uniqueness_rejects_primary_conflict_with_alias() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut route1 = make_route();
        route1.hostname_aliases = vec!["alias.example.com".into()];
        store
            .create_route(&route1)
            .expect("test setup: route inserts");

        let mut route2 = make_route();
        route2.hostname = "alias.example.com".into(); // primary conflicts with route1 alias
        let result = store.create_route(&route2);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("already used as alias"));
    }

    #[test]
    fn test_hostname_uniqueness_allows_update_own_hostname() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut route = make_route();
        store
            .create_route(&route)
            .expect("test setup: route inserts");

        // Updating route with same hostname should succeed
        route.path_prefix = "/api".into();
        route.updated_at = Utc::now();
        assert!(store.update_route(&route).is_ok());
    }

    // ---- Route with Epic 6/7 fields round-trip ----

    #[test]
    fn test_route_cache_and_protection_fields_round_trip() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut route = make_route();
        route.cache_enabled = true;
        route.cache_ttl_s = 600;
        route.cache_max_bytes = 104857600;
        route.rate_limit_rps = Some(500);
        route.rate_limit_burst = Some(100);
        route.auto_ban_threshold = Some(50);
        route.auto_ban_duration_s = 7200;
        route.max_connections = Some(1000);
        route.slowloris_threshold_ms = 10000;
        route.ip_allowlist = vec!["10.0.0.0/8".into()];
        route.ip_denylist = vec!["192.168.1.100".into()];
        route.cors_allowed_origins = vec!["https://example.com".into()];
        route.cors_allowed_methods = vec!["GET".into(), "POST".into()];
        route.cors_max_age_s = Some(3600);
        route.compression_enabled = true;
        route.retry_attempts = Some(3);
        route.max_request_body_bytes = Some(10485760);

        store
            .create_route(&route)
            .expect("test setup: route inserts");
        let fetched = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");

        assert!(fetched.cache_enabled);
        assert_eq!(fetched.cache_ttl_s, 600);
        assert_eq!(fetched.cache_max_bytes, 104857600);
        assert_eq!(fetched.rate_limit_rps, Some(500));
        assert_eq!(fetched.rate_limit_burst, Some(100));
        assert_eq!(fetched.auto_ban_threshold, Some(50));
        assert_eq!(fetched.auto_ban_duration_s, 7200);
        assert_eq!(fetched.max_connections, Some(1000));
        assert_eq!(fetched.slowloris_threshold_ms, 10000);
        assert_eq!(fetched.ip_allowlist, vec!["10.0.0.0/8"]);
        assert_eq!(fetched.ip_denylist, vec!["192.168.1.100"]);
        assert_eq!(fetched.cors_allowed_origins, vec!["https://example.com"]);
        assert_eq!(fetched.cors_allowed_methods, vec!["GET", "POST"]);
        assert_eq!(fetched.cors_max_age_s, Some(3600));
        assert!(fetched.compression_enabled);
        assert_eq!(fetched.retry_attempts, Some(3));
        assert_eq!(fetched.max_request_body_bytes, Some(10485760));
    }

    #[test]
    fn test_route_optional_fields_none_round_trip() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let route = make_route();
        // All optional fields are None/empty by default from make_route()

        store
            .create_route(&route)
            .expect("test setup: route inserts");
        let fetched = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");

        assert!(!fetched.cache_enabled);
        assert!(fetched.rate_limit_rps.is_none());
        assert!(fetched.rate_limit_burst.is_none());
        assert!(fetched.auto_ban_threshold.is_none());
        assert!(fetched.max_connections.is_none());
        assert!(fetched.retry_attempts.is_none());
        assert!(fetched.max_request_body_bytes.is_none());
        assert!(fetched.cors_max_age_s.is_none());
        assert!(fetched.ip_allowlist.is_empty());
        assert!(fetched.ip_denylist.is_empty());
    }

    #[test]
    fn test_route_advanced_config_fields_round_trip() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut route = make_route();
        route.force_https = true;
        route.redirect_hostname = Some("www.example.com".into());
        route.strip_path_prefix = Some("/api".into());
        route.add_path_prefix = Some("/v2".into());
        route.access_log_enabled = false;
        route.websocket_enabled = false;
        route.security_headers = "strict".into();
        route.connect_timeout_s = 10;
        route.read_timeout_s = 120;
        route.send_timeout_s = 120;
        route.proxy_headers =
            std::collections::HashMap::from([("X-Forwarded-For".into(), "$remote_addr".into())]);
        route.response_headers =
            std::collections::HashMap::from([("X-Powered-By".into(), "Lorica".into())]);
        route.proxy_headers_remove = vec!["X-Debug".into()];
        route.response_headers_remove = vec!["Server".into()];

        store
            .create_route(&route)
            .expect("test setup: route inserts");
        let fetched = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");

        assert!(fetched.force_https);
        assert_eq!(
            fetched.redirect_hostname.as_deref(),
            Some("www.example.com")
        );
        assert_eq!(fetched.strip_path_prefix.as_deref(), Some("/api"));
        assert_eq!(fetched.add_path_prefix.as_deref(), Some("/v2"));
        assert!(!fetched.access_log_enabled);
        assert!(!fetched.websocket_enabled);
        assert_eq!(fetched.security_headers, "strict");
        assert_eq!(fetched.connect_timeout_s, 10);
        assert_eq!(fetched.read_timeout_s, 120);
        assert_eq!(fetched.send_timeout_s, 120);
        assert_eq!(fetched.proxy_headers["X-Forwarded-For"], "$remote_addr");
        assert_eq!(fetched.response_headers["X-Powered-By"], "Lorica");
        assert_eq!(fetched.proxy_headers_remove, vec!["X-Debug"]);
        assert_eq!(fetched.response_headers_remove, vec!["Server"]);
    }

    // ---- Backend name and group fields ----

    #[test]
    fn test_backend_name_group_round_trip() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut backend = make_backend();
        backend.name = "web-server-1".into();
        backend.group_name = "web-pool".into();
        backend.health_check_path = Some("/healthz".into());

        store
            .create_backend(&backend)
            .expect("test setup: backend inserts");
        let fetched = store
            .get_backend(&backend.id)
            .expect("test setup: backend fetch")
            .expect("test setup: value present");

        assert_eq!(fetched.name, "web-server-1");
        assert_eq!(fetched.group_name, "web-pool");
        assert_eq!(fetched.health_check_path.as_deref(), Some("/healthz"));
    }

    #[test]
    fn test_export_import_with_encryption() {
        use crate::crypto::EncryptionKey;

        let key = EncryptionKey::generate().expect("test setup: key generates");
        let store1 = ConfigStore::open_in_memory_with_key(key.clone())
            .expect("test setup: in-memory store opens with key");

        let cert = make_certificate();
        store1
            .create_certificate(&cert)
            .expect("test setup: certificate inserts");

        // Export redacts key_pem
        let toml_str = export_to_toml(&store1).expect("test setup: toml export succeeds");
        assert!(toml_str.contains("**REDACTED**"));
        assert!(!toml_str.contains(&cert.key_pem));
    }

    #[test]
    fn test_encryption_key_rotation() {
        use crate::crypto::EncryptionKey;

        let key1 = EncryptionKey::generate().expect("test setup: key generates");
        let key2 = EncryptionKey::generate().expect("test setup: key generates");

        let store = ConfigStore::open_in_memory_with_key(key1)
            .expect("test setup: in-memory store opens with key");

        let cert = make_certificate();
        store
            .create_certificate(&cert)
            .expect("test setup: certificate inserts");

        let nc = make_notification_config();
        store
            .create_notification_config(&nc)
            .expect("test setup: notification config inserts");

        let count = store
            .rotate_encryption_key(&key2)
            .expect("test setup: value present");
        assert_eq!(count, 2);
    }

    #[test]
    fn test_sticky_session_persistence() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut route = make_route();
        route.sticky_session = true;
        store
            .create_route(&route)
            .expect("test setup: route inserts");

        let loaded = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert!(
            loaded.sticky_session,
            "sticky_session should persist as true"
        );

        // Toggle off
        let mut updated = loaded;
        updated.sticky_session = false;
        store
            .update_route(&updated)
            .expect("test setup: route updates");

        let reloaded = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert!(
            !reloaded.sticky_session,
            "sticky_session should persist as false"
        );
    }

    #[test]
    fn test_sticky_session_default_false() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let route = make_route();
        store
            .create_route(&route)
            .expect("test setup: route inserts");

        let loaded = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert!(
            !loaded.sticky_session,
            "sticky_session should default to false"
        );
    }

    #[test]
    fn test_load_balancing_least_conn_roundtrip() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut route = make_route();
        route.load_balancing = LoadBalancing::LeastConn;
        store
            .create_route(&route)
            .expect("test setup: route inserts");

        let loaded = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert_eq!(loaded.load_balancing, LoadBalancing::LeastConn);
    }

    #[test]
    fn test_load_balancing_from_str() {
        assert_eq!(
            LoadBalancing::from_str("least_conn").expect("test setup: deserializes from str"),
            LoadBalancing::LeastConn
        );
        assert_eq!(
            LoadBalancing::from_str("round_robin").expect("test setup: deserializes from str"),
            LoadBalancing::RoundRobin
        );
        assert!(LoadBalancing::from_str("invalid").is_err());
    }

    #[test]
    fn test_load_balancing_as_str() {
        assert_eq!(LoadBalancing::LeastConn.as_str(), "least_conn");
        assert_eq!(LoadBalancing::PeakEwma.as_str(), "peak_ewma");
    }

    #[test]
    fn test_basic_auth_roundtrip() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut route = make_route();
        route.basic_auth_username = Some("admin".to_string());
        route.basic_auth_password_hash =
            Some("$argon2id$v=19$m=19456,t=2,p=1$salt$hash".to_string());
        store
            .create_route(&route)
            .expect("test setup: route inserts");

        let loaded = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert_eq!(loaded.basic_auth_username.as_deref(), Some("admin"));
        assert_eq!(
            loaded.basic_auth_password_hash.as_deref(),
            Some("$argon2id$v=19$m=19456,t=2,p=1$salt$hash")
        );
    }

    #[test]
    fn test_basic_auth_default_none() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let route = make_route();
        store
            .create_route(&route)
            .expect("test setup: route inserts");

        let loaded = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert!(loaded.basic_auth_username.is_none());
        assert!(loaded.basic_auth_password_hash.is_none());
    }

    #[test]
    fn test_maintenance_mode_roundtrip() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut route = make_route();
        route.maintenance_mode = true;
        route.error_page_html = Some("<h1>Down for maintenance</h1>".to_string());
        store
            .create_route(&route)
            .expect("test setup: route inserts");

        let loaded = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert!(loaded.maintenance_mode);
        assert_eq!(
            loaded.error_page_html.as_deref(),
            Some("<h1>Down for maintenance</h1>")
        );
    }

    #[test]
    fn test_maintenance_mode_default_false() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let route = make_route();
        store
            .create_route(&route)
            .expect("test setup: route inserts");

        let loaded = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert!(!loaded.maintenance_mode);
        assert!(loaded.error_page_html.is_none());
    }

    #[test]
    fn test_stale_config_roundtrip() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut route = make_route();
        route.stale_while_revalidate_s = 30;
        route.stale_if_error_s = 120;
        store
            .create_route(&route)
            .expect("test setup: route inserts");

        let loaded = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert_eq!(loaded.stale_while_revalidate_s, 30);
        assert_eq!(loaded.stale_if_error_s, 120);
    }

    #[test]
    fn test_stale_config_default_values() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let route = make_route();
        store
            .create_route(&route)
            .expect("test setup: route inserts");

        let loaded = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert_eq!(
            loaded.stale_while_revalidate_s, 10,
            "default stale-while-revalidate should be 10s"
        );
        assert_eq!(
            loaded.stale_if_error_s, 60,
            "default stale-if-error should be 60s"
        );
    }

    #[test]
    fn test_basic_auth_clear() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut route = make_route();
        route.basic_auth_username = Some("user".to_string());
        route.basic_auth_password_hash = Some("hash".to_string());
        store
            .create_route(&route)
            .expect("test setup: route inserts");

        let mut updated = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        updated.basic_auth_username = None;
        updated.basic_auth_password_hash = None;
        store
            .update_route(&updated)
            .expect("test setup: route updates");

        let reloaded = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert!(reloaded.basic_auth_username.is_none());
        assert!(reloaded.basic_auth_password_hash.is_none());
    }

    #[test]
    fn test_cache_vary_headers_roundtrip() {
        // Regression guard: Phase 1.3 added cache_vary_headers via a
        // replace_all edit that skipped the get_route SELECT due to
        // differing indentation. The list_routes path happened to work;
        // get_route returned empty. This test exercises get_route
        // specifically so the two SELECTs can't drift again.
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut route = make_route();
        route.cache_vary_headers = vec!["Accept-Encoding".into(), "Accept-Language".into()];
        store
            .create_route(&route)
            .expect("test setup: route inserts");

        let via_get = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert_eq!(
            via_get.cache_vary_headers,
            vec!["Accept-Encoding".to_string(), "Accept-Language".to_string()]
        );

        let via_list: Vec<_> = store
            .list_routes()
            .expect("test setup: value present")
            .into_iter()
            .filter(|r| r.id == route.id)
            .collect();
        assert_eq!(via_list.len(), 1);
        assert_eq!(via_list[0].cache_vary_headers, via_get.cache_vary_headers);
    }

    #[test]
    fn test_header_rules_roundtrip() {
        // Schema V26: header_rules persists as a JSON array. Confirms the
        // migration is applied on a fresh DB and that the SELECT column
        // index (currently row index 56) stays in sync with create/update.
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut route = make_route();
        route.header_rules = vec![
            HeaderRule {
                header_name: "X-Tenant".into(),
                match_type: HeaderMatchType::Exact,
                value: "acme".into(),
                backend_ids: vec!["b1".into()],
            },
            HeaderRule {
                header_name: "User-Agent".into(),
                match_type: HeaderMatchType::Regex,
                value: "^Mobile".into(),
                backend_ids: vec![],
            },
        ];
        store
            .create_route(&route)
            .expect("test setup: route inserts");

        let loaded = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert_eq!(loaded.header_rules.len(), 2);
        assert_eq!(loaded.header_rules[0].header_name, "X-Tenant");
        assert!(matches!(
            loaded.header_rules[0].match_type,
            HeaderMatchType::Exact
        ));
        assert_eq!(loaded.header_rules[0].backend_ids, vec!["b1".to_string()]);
        assert!(matches!(
            loaded.header_rules[1].match_type,
            HeaderMatchType::Regex
        ));
        assert!(loaded.header_rules[1].backend_ids.is_empty());

        // Update clears the rules.
        let mut cleared = loaded.clone();
        cleared.header_rules.clear();
        store
            .update_route(&cleared)
            .expect("test setup: route updates");
        let after_update = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert!(after_update.header_rules.is_empty());
    }

    #[test]
    fn test_traffic_splits_roundtrip() {
        // Schema V27: traffic_splits persists as a JSON array. The column
        // index for reads is 57 - this test pins both create/get paths
        // and guards against a regression like the V25 cache_vary_headers
        // one (SELECT drift between get_route and list_routes).
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut route = make_route();
        route.traffic_splits = vec![
            TrafficSplit {
                name: "v2-canary".into(),
                weight_percent: 5,
                backend_ids: vec!["b-v2".into()],
            },
            TrafficSplit {
                name: String::new(),
                weight_percent: 0,
                backend_ids: vec!["b-v3".into()],
            },
        ];
        store
            .create_route(&route)
            .expect("test setup: route inserts");

        let via_get = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert_eq!(via_get.traffic_splits.len(), 2);
        assert_eq!(via_get.traffic_splits[0].name, "v2-canary");
        assert_eq!(via_get.traffic_splits[0].weight_percent, 5);
        assert_eq!(
            via_get.traffic_splits[0].backend_ids,
            vec!["b-v2".to_string()]
        );
        assert_eq!(via_get.traffic_splits[1].weight_percent, 0);

        let via_list: Vec<_> = store
            .list_routes()
            .expect("test setup: value present")
            .into_iter()
            .filter(|r| r.id == route.id)
            .collect();
        assert_eq!(via_list.len(), 1);
        assert_eq!(via_list[0].traffic_splits.len(), 2);

        // Clear via update.
        let mut cleared = via_get.clone();
        cleared.traffic_splits.clear();
        store
            .update_route(&cleared)
            .expect("test setup: route updates");
        let after = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert!(after.traffic_splits.is_empty());
    }

    #[test]
    fn test_forward_auth_roundtrip() {
        // Schema V28: forward_auth stored as nullable JSON at column 58.
        // Confirms create/get/list/update stay in sync and that the NULL
        // path (feature off by default) round-trips too.
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut route = make_route();
        route.forward_auth = Some(ForwardAuthConfig {
            address: "http://authelia.internal/api/verify".into(),
            timeout_ms: 2_500,
            response_headers: vec!["Remote-User".into(), "Remote-Groups".into()],
            verdict_cache_ttl_ms: 15_000,
        });
        store
            .create_route(&route)
            .expect("test setup: route inserts");

        let via_get = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        let fa = via_get
            .forward_auth
            .as_ref()
            .expect("test setup: option has value");
        assert_eq!(fa.address, "http://authelia.internal/api/verify");
        assert_eq!(fa.timeout_ms, 2_500);
        assert_eq!(
            fa.response_headers,
            vec!["Remote-User".to_string(), "Remote-Groups".to_string()]
        );
        assert_eq!(
            fa.verdict_cache_ttl_ms, 15_000,
            "verdict_cache_ttl_ms must round-trip through the JSON column"
        );

        let via_list: Vec<_> = store
            .list_routes()
            .expect("test setup: value present")
            .into_iter()
            .filter(|r| r.id == route.id)
            .collect();
        assert_eq!(via_list.len(), 1);
        assert!(via_list[0].forward_auth.is_some());

        // Clear via update: disable the feature on an existing route.
        let mut cleared = via_get.clone();
        cleared.forward_auth = None;
        store
            .update_route(&cleared)
            .expect("test setup: route updates");
        let after = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert!(after.forward_auth.is_none());
    }

    #[test]
    fn test_mirror_roundtrip() {
        // Schema V29: mirror stored as nullable JSON at column 59.
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut route = make_route();
        route.mirror = Some(MirrorConfig {
            backend_ids: vec!["shadow-a".into(), "shadow-b".into()],
            sample_percent: 10,
            timeout_ms: 3_000,
            max_body_bytes: 524_288,
        });
        store
            .create_route(&route)
            .expect("test setup: route inserts");

        let via_get = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        let m = via_get
            .mirror
            .as_ref()
            .expect("test setup: option has value");
        assert_eq!(
            m.backend_ids,
            vec!["shadow-a".to_string(), "shadow-b".to_string()]
        );
        assert_eq!(m.sample_percent, 10);
        assert_eq!(m.timeout_ms, 3_000);
        assert_eq!(m.max_body_bytes, 524_288);

        let via_list: Vec<_> = store
            .list_routes()
            .expect("test setup: value present")
            .into_iter()
            .filter(|r| r.id == route.id)
            .collect();
        assert_eq!(via_list.len(), 1);
        assert!(via_list[0].mirror.is_some());

        // Clear via update.
        let mut cleared = via_get.clone();
        cleared.mirror = None;
        store
            .update_route(&cleared)
            .expect("test setup: route updates");
        let after = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert!(after.mirror.is_none());
    }

    #[test]
    fn test_response_rewrite_roundtrip() {
        // Schema V30: response_rewrite stored as nullable JSON at column
        // 60. Regression guard against SELECT / UPDATE drift across the
        // 60 columns the row now carries.
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut route = make_route();
        route.response_rewrite = Some(ResponseRewriteConfig {
            rules: vec![
                ResponseRewriteRule {
                    pattern: "internal.local".into(),
                    replacement: "api.example.com".into(),
                    is_regex: false,
                    max_replacements: None,
                },
                ResponseRewriteRule {
                    pattern: r"\d+".into(),
                    replacement: "***".into(),
                    is_regex: true,
                    max_replacements: Some(5),
                },
            ],
            max_body_bytes: 524_288,
            content_type_prefixes: vec!["text/".into(), "application/json".into()],
        });
        store
            .create_route(&route)
            .expect("test setup: route inserts");

        let via_get = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        let rr = via_get
            .response_rewrite
            .as_ref()
            .expect("test setup: option has value");
        assert_eq!(rr.rules.len(), 2);
        assert_eq!(rr.rules[0].pattern, "internal.local");
        assert!(rr.rules[1].is_regex);
        assert_eq!(rr.rules[1].max_replacements, Some(5));
        assert_eq!(rr.max_body_bytes, 524_288);
        assert_eq!(rr.content_type_prefixes.len(), 2);

        let via_list: Vec<_> = store
            .list_routes()
            .expect("test setup: value present")
            .into_iter()
            .filter(|r| r.id == route.id)
            .collect();
        assert_eq!(via_list.len(), 1);
        assert!(via_list[0].response_rewrite.is_some());

        let mut cleared = via_get.clone();
        cleared.response_rewrite = None;
        store
            .update_route(&cleared)
            .expect("test setup: route updates");
        let after = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert!(after.response_rewrite.is_none());
    }

    #[test]
    fn test_response_rewrite_default_none() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let route = make_route();
        store
            .create_route(&route)
            .expect("test setup: route inserts");
        let loaded = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert!(loaded.response_rewrite.is_none());
    }

    #[test]
    fn test_mtls_roundtrip() {
        // Schema V31: mtls stored as nullable JSON at column 61.
        // Regression guard against SELECT / UPDATE drift now that the
        // row carries 61 columns.
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let mut route = make_route();
        route.mtls = Some(MtlsConfig {
            ca_cert_pem: "-----BEGIN CERTIFICATE-----\nMIIBdummy\n-----END CERTIFICATE-----\n"
                .into(),
            required: true,
            allowed_organizations: vec!["Acme Corp".into(), "Beta Inc".into()],
        });
        store
            .create_route(&route)
            .expect("test setup: route inserts");

        let via_get = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        let m = via_get.mtls.as_ref().expect("test setup: option has value");
        assert!(m.ca_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(m.required);
        assert_eq!(m.allowed_organizations, vec!["Acme Corp", "Beta Inc"]);

        let via_list: Vec<_> = store
            .list_routes()
            .expect("test setup: value present")
            .into_iter()
            .filter(|r| r.id == route.id)
            .collect();
        assert_eq!(via_list.len(), 1);
        assert!(via_list[0].mtls.is_some());

        let mut cleared = via_get.clone();
        cleared.mtls = None;
        store
            .update_route(&cleared)
            .expect("test setup: route updates");
        let after = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert!(after.mtls.is_none());
    }

    #[test]
    fn test_mtls_default_none() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let route = make_route();
        store
            .create_route(&route)
            .expect("test setup: route inserts");
        let loaded = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert!(loaded.mtls.is_none());
    }

    #[test]
    fn test_mirror_default_none() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let route = make_route();
        store
            .create_route(&route)
            .expect("test setup: route inserts");
        let loaded = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert!(loaded.mirror.is_none());
    }

    #[test]
    fn test_forward_auth_default_none() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let route = make_route();
        store
            .create_route(&route)
            .expect("test setup: route inserts");
        let loaded = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert!(loaded.forward_auth.is_none());
    }

    #[test]
    fn test_traffic_splits_default_empty() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let route = make_route();
        store
            .create_route(&route)
            .expect("test setup: route inserts");
        let loaded = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert!(loaded.traffic_splits.is_empty());
    }

    #[test]
    fn test_header_rules_default_empty() {
        // Default Route ctor: no header_rules persisted or loaded.
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let route = make_route();
        store
            .create_route(&route)
            .expect("test setup: route inserts");
        let loaded = store
            .get_route(&route.id)
            .expect("test setup: route fetch")
            .expect("test setup: value present");
        assert!(loaded.header_rules.is_empty());
    }
}
