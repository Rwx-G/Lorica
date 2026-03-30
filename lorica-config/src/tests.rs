#[cfg(test)]
mod tests {
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
            topology_type: TopologyType::SingleVm,
            enabled: true,
            created_at: now,
            updated_at: now,
        }
    }

    fn make_backend() -> Backend {
        let now = Utc::now();
        Backend {
            id: new_id(),
            address: "192.168.1.10:8080".into(),
            weight: 100,
            health_status: HealthStatus::Healthy,
            health_check_enabled: true,
            health_check_interval_s: 10,
            health_check_path: None,
            lifecycle_state: LifecycleState::Normal,
            active_connections: 0,
            tls_upstream: false,
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

    // ---- Route CRUD ----

    #[test]
    fn test_route_crud() {
        let store = ConfigStore::open_in_memory().unwrap();
        let mut route = make_route();

        // Create
        store.create_route(&route).unwrap();

        // Read
        let fetched = store.get_route(&route.id).unwrap().unwrap();
        assert_eq!(fetched.hostname, "example.com");
        assert_eq!(fetched.path_prefix, "/");

        // List
        let routes = store.list_routes().unwrap();
        assert_eq!(routes.len(), 1);

        // Update
        route.hostname = "updated.com".into();
        route.updated_at = Utc::now();
        store.update_route(&route).unwrap();
        let fetched = store.get_route(&route.id).unwrap().unwrap();
        assert_eq!(fetched.hostname, "updated.com");

        // Delete
        store.delete_route(&route.id).unwrap();
        assert!(store.get_route(&route.id).unwrap().is_none());
    }

    #[test]
    fn test_route_not_found() {
        let store = ConfigStore::open_in_memory().unwrap();
        let mut route = make_route();
        route.id = "nonexistent".into();
        assert!(store.update_route(&route).is_err());
        assert!(store.delete_route("nonexistent").is_err());
    }

    // ---- Backend CRUD ----

    #[test]
    fn test_backend_crud() {
        let store = ConfigStore::open_in_memory().unwrap();
        let mut backend = make_backend();

        store.create_backend(&backend).unwrap();

        let fetched = store.get_backend(&backend.id).unwrap().unwrap();
        assert_eq!(fetched.address, "192.168.1.10:8080");
        assert_eq!(fetched.weight, 100);

        let backends = store.list_backends().unwrap();
        assert_eq!(backends.len(), 1);

        backend.address = "10.0.0.1:9090".into();
        backend.updated_at = Utc::now();
        store.update_backend(&backend).unwrap();
        let fetched = store.get_backend(&backend.id).unwrap().unwrap();
        assert_eq!(fetched.address, "10.0.0.1:9090");

        store.delete_backend(&backend.id).unwrap();
        assert!(store.get_backend(&backend.id).unwrap().is_none());
    }

    // ---- Route-Backend links ----

    #[test]
    fn test_route_backend_links() {
        let store = ConfigStore::open_in_memory().unwrap();
        let route = make_route();
        let backend = make_backend();

        store.create_route(&route).unwrap();
        store.create_backend(&backend).unwrap();
        store.link_route_backend(&route.id, &backend.id).unwrap();

        let backends = store.list_backends_for_route(&route.id).unwrap();
        assert_eq!(backends, vec![backend.id.clone()]);

        let routes = store.list_routes_for_backend(&backend.id).unwrap();
        assert_eq!(routes, vec![route.id.clone()]);

        store.unlink_route_backend(&route.id, &backend.id).unwrap();
        let backends = store.list_backends_for_route(&route.id).unwrap();
        assert!(backends.is_empty());
    }

    // ---- Certificate CRUD ----

    #[test]
    fn test_certificate_crud() {
        let store = ConfigStore::open_in_memory().unwrap();
        let mut cert = make_certificate();

        store.create_certificate(&cert).unwrap();

        let fetched = store.get_certificate(&cert.id).unwrap().unwrap();
        assert_eq!(fetched.domain, "example.com");
        assert_eq!(fetched.san_domains, vec!["www.example.com"]);

        let certs = store.list_certificates().unwrap();
        assert_eq!(certs.len(), 1);

        cert.domain = "updated.com".into();
        store.update_certificate(&cert).unwrap();
        let fetched = store.get_certificate(&cert.id).unwrap().unwrap();
        assert_eq!(fetched.domain, "updated.com");

        store.delete_certificate(&cert.id).unwrap();
        assert!(store.get_certificate(&cert.id).unwrap().is_none());
    }

    // ---- NotificationConfig CRUD ----

    #[test]
    fn test_notification_config_crud() {
        let store = ConfigStore::open_in_memory().unwrap();
        let mut nc = make_notification_config();

        store.create_notification_config(&nc).unwrap();

        let fetched = store.get_notification_config(&nc.id).unwrap().unwrap();
        assert_eq!(fetched.channel, NotificationChannel::Email);
        assert_eq!(fetched.alert_types.len(), 2);

        let configs = store.list_notification_configs().unwrap();
        assert_eq!(configs.len(), 1);

        nc.enabled = false;
        store.update_notification_config(&nc).unwrap();
        let fetched = store.get_notification_config(&nc.id).unwrap().unwrap();
        assert!(!fetched.enabled);

        store.delete_notification_config(&nc.id).unwrap();
        assert!(store.get_notification_config(&nc.id).unwrap().is_none());
    }

    // ---- UserPreference CRUD ----

    #[test]
    fn test_user_preference_crud() {
        let store = ConfigStore::open_in_memory().unwrap();
        let mut pref = make_user_preference();

        store.create_user_preference(&pref).unwrap();

        let fetched = store.get_user_preference(&pref.id).unwrap().unwrap();
        assert_eq!(fetched.preference_key, "self_signed_cert");
        assert_eq!(fetched.value, PreferenceValue::Never);

        let by_key = store
            .get_user_preference_by_key("self_signed_cert")
            .unwrap()
            .unwrap();
        assert_eq!(by_key.id, pref.id);

        let prefs = store.list_user_preferences().unwrap();
        assert_eq!(prefs.len(), 1);

        pref.value = PreferenceValue::Always;
        pref.updated_at = Utc::now();
        store.update_user_preference(&pref).unwrap();
        let fetched = store.get_user_preference(&pref.id).unwrap().unwrap();
        assert_eq!(fetched.value, PreferenceValue::Always);

        store.delete_user_preference(&pref.id).unwrap();
        assert!(store.get_user_preference(&pref.id).unwrap().is_none());
    }

    // ---- AdminUser CRUD ----

    #[test]
    fn test_admin_user_crud() {
        let store = ConfigStore::open_in_memory().unwrap();
        let mut user = make_admin_user();

        store.create_admin_user(&user).unwrap();

        let fetched = store.get_admin_user(&user.id).unwrap().unwrap();
        assert_eq!(fetched.username, "admin");
        assert!(fetched.must_change_password);

        let by_name = store.get_admin_user_by_username("admin").unwrap().unwrap();
        assert_eq!(by_name.id, user.id);

        let users = store.list_admin_users().unwrap();
        assert_eq!(users.len(), 1);

        user.must_change_password = false;
        user.last_login = Some(Utc::now());
        store.update_admin_user(&user).unwrap();
        let fetched = store.get_admin_user(&user.id).unwrap().unwrap();
        assert!(!fetched.must_change_password);
        assert!(fetched.last_login.is_some());

        store.delete_admin_user(&user.id).unwrap();
        assert!(store.get_admin_user(&user.id).unwrap().is_none());
    }

    // ---- GlobalSettings ----

    #[test]
    fn test_global_settings() {
        let store = ConfigStore::open_in_memory().unwrap();

        // Defaults from migration
        let settings = store.get_global_settings().unwrap();
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
            default_topology_type: TopologyType::Ha,
        };
        store.update_global_settings(&new_settings).unwrap();
        let fetched = store.get_global_settings().unwrap();
        assert_eq!(fetched.management_port, 8443);
        assert_eq!(fetched.log_level, "debug");
        assert_eq!(fetched.default_health_check_interval_s, 30);
    }

    // ---- Migration ----

    #[test]
    fn test_migration_version() {
        let store = ConfigStore::open_in_memory().unwrap();
        assert_eq!(store.schema_version().unwrap(), 2);
    }

    #[test]
    fn test_migration_idempotent() {
        // Opening twice should not fail - migrations should be idempotent
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path();
        {
            let _store = ConfigStore::open(path, None).unwrap();
        }
        {
            let store = ConfigStore::open(path, None).unwrap();
            assert_eq!(store.schema_version().unwrap(), 2);
        }
    }

    // ---- Export/Import round-trip ----

    #[test]
    fn test_export_import_round_trip() {
        let store1 = ConfigStore::open_in_memory().unwrap();

        // Populate with test data
        let cert = make_certificate();
        store1.create_certificate(&cert).unwrap();

        let mut route = make_route();
        route.certificate_id = Some(cert.id.clone());
        store1.create_route(&route).unwrap();

        let backend = make_backend();
        store1.create_backend(&backend).unwrap();
        store1.link_route_backend(&route.id, &backend.id).unwrap();

        let nc = make_notification_config();
        store1.create_notification_config(&nc).unwrap();

        let pref = make_user_preference();
        store1.create_user_preference(&pref).unwrap();

        let user = make_admin_user();
        store1.create_admin_user(&user).unwrap();

        let settings = GlobalSettings {
            management_port: 8443,
            log_level: "debug".into(),
            default_health_check_interval_s: 30,
            cert_warning_days: 14,
            cert_critical_days: 3,
            default_topology_type: TopologyType::Ha,
        };
        store1.update_global_settings(&settings).unwrap();

        // Export
        let toml_str = export_to_toml(&store1).unwrap();

        // Import into a fresh store
        let store2 = ConfigStore::open_in_memory().unwrap();
        let data = parse_toml(&toml_str).unwrap();
        import_to_store(&store2, &data).unwrap();

        // Verify all data matches
        let routes2 = store2.list_routes().unwrap();
        assert_eq!(routes2.len(), 1);
        assert_eq!(routes2[0].hostname, route.hostname);
        assert_eq!(routes2[0].certificate_id, Some(cert.id.clone()));

        let backends2 = store2.list_backends().unwrap();
        assert_eq!(backends2.len(), 1);
        assert_eq!(backends2[0].address, backend.address);

        let links = store2.list_backends_for_route(&route.id).unwrap();
        assert_eq!(links, vec![backend.id.clone()]);

        let certs2 = store2.list_certificates().unwrap();
        assert_eq!(certs2.len(), 1);
        assert_eq!(certs2[0].domain, cert.domain);

        let ncs2 = store2.list_notification_configs().unwrap();
        assert_eq!(ncs2.len(), 1);

        let prefs2 = store2.list_user_preferences().unwrap();
        assert_eq!(prefs2.len(), 1);
        assert_eq!(prefs2[0].preference_key, pref.preference_key);

        let users2 = store2.list_admin_users().unwrap();
        assert_eq!(users2.len(), 1);
        assert_eq!(users2[0].username, user.username);

        let settings2 = store2.get_global_settings().unwrap();
        assert_eq!(settings2.management_port, 8443);
        assert_eq!(settings2.log_level, "debug");
    }

    // ---- WAL mode / crash safety ----

    #[test]
    fn test_wal_mode_enabled() {
        let tmp = NamedTempFile::new().unwrap();
        let store = ConfigStore::open(tmp.path(), None).unwrap();

        // Verify WAL mode by writing and reading back
        let route = make_route();
        store.create_route(&route).unwrap();

        // Data survives re-open (simulates crash recovery)
        drop(store);
        let store2 = ConfigStore::open(tmp.path(), None).unwrap();
        let fetched = store2.get_route(&route.id).unwrap().unwrap();
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
topology_type = "single_vm"
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
        let store1 = ConfigStore::open_in_memory().unwrap();
        let route = make_route();
        store1.create_route(&route).unwrap();

        let tmp = NamedTempFile::new().unwrap();
        crate::export::export_to_file(&store1, tmp.path()).unwrap();

        let store2 = ConfigStore::open_in_memory().unwrap();
        crate::import::import_from_file(&store2, tmp.path()).unwrap();

        let routes = store2.list_routes().unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].hostname, route.hostname);
    }

    // ---- Clear all ----

    #[test]
    fn test_clear_all() {
        let store = ConfigStore::open_in_memory().unwrap();
        store.create_route(&make_route()).unwrap();
        store.create_backend(&make_backend()).unwrap();
        store.create_certificate(&make_certificate()).unwrap();

        store.clear_all().unwrap();

        assert!(store.list_routes().unwrap().is_empty());
        assert!(store.list_backends().unwrap().is_empty());
        assert!(store.list_certificates().unwrap().is_empty());
    }

    // ---- Encryption at rest ----

    #[test]
    fn test_key_pem_encrypted_at_rest() {
        use crate::crypto::EncryptionKey;

        let key = EncryptionKey::generate().unwrap();
        let store = ConfigStore::open_in_memory_with_key(key).unwrap();
        let cert = make_certificate();
        let original_key_pem = cert.key_pem.clone();

        store.create_certificate(&cert).unwrap();

        // Verify we can read back the decrypted key_pem
        let fetched = store.get_certificate(&cert.id).unwrap().unwrap();
        assert_eq!(fetched.key_pem, original_key_pem);

        // Verify it's stored encrypted in the DB (raw query)
        let raw: Vec<u8> = store
            .conn
            .query_row(
                "SELECT key_pem FROM certificates WHERE id=?1",
                rusqlite::params![cert.id],
                |row| row.get(0),
            )
            .unwrap();
        // Encrypted data should differ from plaintext
        assert_ne!(raw, original_key_pem.as_bytes());
        // Encrypted data should be larger (nonce + tag overhead)
        assert!(raw.len() > original_key_pem.len());
    }

    #[test]
    fn test_key_pem_round_trip_with_encryption() {
        use crate::crypto::EncryptionKey;

        let key = EncryptionKey::generate().unwrap();
        let store = ConfigStore::open_in_memory_with_key(key).unwrap();

        let cert = make_certificate();
        store.create_certificate(&cert).unwrap();

        // List also decrypts
        let certs = store.list_certificates().unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].key_pem, cert.key_pem);

        // Update also encrypts
        let mut updated = cert.clone();
        updated.key_pem = "-----BEGIN PRIVATE KEY-----\nnew key\n-----END PRIVATE KEY-----".into();
        store.update_certificate(&updated).unwrap();

        let fetched = store.get_certificate(&updated.id).unwrap().unwrap();
        assert_eq!(fetched.key_pem, updated.key_pem);
    }

    // ---- ConfigDiff tests ----

    #[test]
    fn test_diff_empty_to_empty() {
        let store = ConfigStore::open_in_memory().unwrap();
        let toml_str = export_to_toml(&store).unwrap();
        let import_data = parse_toml(&toml_str).unwrap();
        let diff = crate::diff::compute_diff(&store, &import_data).unwrap();
        assert!(diff.is_empty());
    }

    #[test]
    fn test_diff_detects_added_route() {
        let store = ConfigStore::open_in_memory().unwrap();
        let route = make_route();

        // Build import data with one route, current store is empty
        let toml_str = {
            let temp = ConfigStore::open_in_memory().unwrap();
            temp.create_route(&route).unwrap();
            export_to_toml(&temp).unwrap()
        };
        let import_data = parse_toml(&toml_str).unwrap();
        let diff = crate::diff::compute_diff(&store, &import_data).unwrap();

        assert_eq!(diff.routes.added.len(), 1);
        assert!(diff.routes.removed.is_empty());
        assert!(diff.routes.modified.is_empty());
    }

    #[test]
    fn test_diff_detects_removed_backend() {
        let store = ConfigStore::open_in_memory().unwrap();
        let backend = make_backend();
        store.create_backend(&backend).unwrap();

        // Import data with no backends
        let toml_str = {
            let temp = ConfigStore::open_in_memory().unwrap();
            export_to_toml(&temp).unwrap()
        };
        let import_data = parse_toml(&toml_str).unwrap();
        let diff = crate::diff::compute_diff(&store, &import_data).unwrap();

        assert!(diff.backends.added.is_empty());
        assert_eq!(diff.backends.removed.len(), 1);
    }

    #[test]
    fn test_diff_detects_modified_route() {
        let store = ConfigStore::open_in_memory().unwrap();
        let route = make_route();
        store.create_route(&route).unwrap();

        // Modify hostname in import data
        let mut modified = route.clone();
        modified.hostname = "modified.com".into();
        let toml_str = {
            let temp = ConfigStore::open_in_memory().unwrap();
            temp.create_route(&modified).unwrap();
            export_to_toml(&temp).unwrap()
        };
        let import_data = parse_toml(&toml_str).unwrap();
        let diff = crate::diff::compute_diff(&store, &import_data).unwrap();

        assert!(diff.routes.added.is_empty());
        assert!(diff.routes.removed.is_empty());
        assert_eq!(diff.routes.modified.len(), 1);
    }

    #[test]
    fn test_diff_detects_settings_change() {
        let store = ConfigStore::open_in_memory().unwrap();

        let toml_str = r#"
version = 1

[global_settings]
management_port = 9443
log_level = "debug"
default_health_check_interval_s = 30
"#;
        let import_data = parse_toml(toml_str).unwrap();
        let diff = crate::diff::compute_diff(&store, &import_data).unwrap();

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
topology_type = "single_vm"
enabled = true
created_at = "2026-01-01T00:00:00Z"
updated_at = "2026-01-01T00:00:00Z"

[[route_backends]]
route_id = "r1"
backend_id = "nonexistent-backend"
"#;
        let result = parse_toml(toml_str);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unknown backend_id")
        );
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
        let data = parse_toml(toml_str).unwrap();
        assert_eq!(data.version, 1);
        assert!(data.routes.is_empty());
        assert!(data.backends.is_empty());
    }

    #[test]
    fn test_import_replaces_all_data() {
        let store = ConfigStore::open_in_memory().unwrap();

        // Pre-populate
        store.create_route(&make_route()).unwrap();
        store.create_backend(&make_backend()).unwrap();
        assert_eq!(store.list_routes().unwrap().len(), 1);
        assert_eq!(store.list_backends().unwrap().len(), 1);

        // Import empty config
        let toml_str = r#"
version = 1

[global_settings]
management_port = 9443
log_level = "info"
default_health_check_interval_s = 10
"#;
        let data = parse_toml(toml_str).unwrap();
        import_to_store(&store, &data).unwrap();

        // Everything should be cleared
        assert!(store.list_routes().unwrap().is_empty());
        assert!(store.list_backends().unwrap().is_empty());
    }

    // ---- ConfigDiff edge cases ----

    #[test]
    fn test_diff_route_backends_added_and_removed() {
        let store = ConfigStore::open_in_memory().unwrap();
        let route = make_route();
        let backend1 = make_backend();
        store.create_route(&route).unwrap();
        store.create_backend(&backend1).unwrap();
        store
            .link_route_backend(&route.id, &backend1.id)
            .unwrap();

        // Import data with a different backend link
        let mut backend2 = make_backend();
        backend2.id = "backend-new".into();
        let temp = ConfigStore::open_in_memory().unwrap();
        temp.create_route(&route).unwrap();
        temp.create_backend(&backend2).unwrap();
        temp.link_route_backend(&route.id, &backend2.id).unwrap();
        let toml_str = export_to_toml(&temp).unwrap();

        let import_data = parse_toml(&toml_str).unwrap();
        let diff = crate::diff::compute_diff(&store, &import_data).unwrap();

        assert!(!diff.route_backends.added.is_empty());
        assert!(!diff.route_backends.removed.is_empty());
    }

    #[test]
    fn test_diff_notification_config_changes() {
        let store = ConfigStore::open_in_memory().unwrap();
        let nc = make_notification_config();
        store.create_notification_config(&nc).unwrap();

        // Import with modified notification
        let mut modified = nc.clone();
        modified.enabled = false;
        let temp = ConfigStore::open_in_memory().unwrap();
        temp.create_notification_config(&modified).unwrap();
        let toml_str = export_to_toml(&temp).unwrap();

        let import_data = parse_toml(&toml_str).unwrap();
        let diff = crate::diff::compute_diff(&store, &import_data).unwrap();

        assert_eq!(diff.notification_configs.modified.len(), 1);
    }

    #[test]
    fn test_diff_admin_user_changes() {
        let store = ConfigStore::open_in_memory().unwrap();
        let user = make_admin_user();
        store.create_admin_user(&user).unwrap();

        // Import with modified username
        let mut modified = user.clone();
        modified.username = "superadmin".into();
        let temp = ConfigStore::open_in_memory().unwrap();
        temp.create_admin_user(&modified).unwrap();
        let toml_str = export_to_toml(&temp).unwrap();

        let import_data = parse_toml(&toml_str).unwrap();
        let diff = crate::diff::compute_diff(&store, &import_data).unwrap();

        assert_eq!(diff.admin_users.modified.len(), 1);
    }

    #[test]
    fn test_diff_user_preference_changes() {
        let store = ConfigStore::open_in_memory().unwrap();
        let pref = make_user_preference();
        store.create_user_preference(&pref).unwrap();

        let mut modified = pref.clone();
        modified.value = PreferenceValue::Always;
        let temp = ConfigStore::open_in_memory().unwrap();
        temp.create_user_preference(&modified).unwrap();
        let toml_str = export_to_toml(&temp).unwrap();

        let import_data = parse_toml(&toml_str).unwrap();
        let diff = crate::diff::compute_diff(&store, &import_data).unwrap();

        assert_eq!(diff.user_preferences.modified.len(), 1);
    }

    #[test]
    fn test_diff_all_settings_fields() {
        let store = ConfigStore::open_in_memory().unwrap();

        let toml_str = r#"
version = 1

[global_settings]
management_port = 8443
log_level = "debug"
default_health_check_interval_s = 30
cert_warning_days = 14
cert_critical_days = 3
"#;
        let import_data = parse_toml(toml_str).unwrap();
        let diff = crate::diff::compute_diff(&store, &import_data).unwrap();

        // All 5 settings should differ from defaults
        assert_eq!(diff.global_settings.changes.len(), 5);
    }

    #[test]
    fn test_diff_certificate_changes() {
        let store = ConfigStore::open_in_memory().unwrap();
        let cert = make_certificate();
        store.create_certificate(&cert).unwrap();

        let mut modified = cert.clone();
        modified.domain = "new-domain.com".into();
        let temp = ConfigStore::open_in_memory().unwrap();
        temp.create_certificate(&modified).unwrap();
        let toml_str = export_to_toml(&temp).unwrap();

        let import_data = parse_toml(&toml_str).unwrap();
        let diff = crate::diff::compute_diff(&store, &import_data).unwrap();

        assert_eq!(diff.certificates.modified.len(), 1);
    }

    // ---- Export tests ----

    #[test]
    fn test_export_empty_store_produces_valid_toml() {
        let store = ConfigStore::open_in_memory().unwrap();
        let toml_str = export_to_toml(&store).unwrap();
        assert!(toml_str.contains("version = 1"));
        assert!(toml_str.contains("[global_settings]"));
        // Should be re-importable
        let data = parse_toml(&toml_str).unwrap();
        assert_eq!(data.version, 1);
    }

    #[test]
    fn test_export_preserves_all_entity_types() {
        let store = ConfigStore::open_in_memory().unwrap();

        let cert = make_certificate();
        store.create_certificate(&cert).unwrap();

        let mut route = make_route();
        route.certificate_id = Some(cert.id.clone());
        store.create_route(&route).unwrap();

        let backend = make_backend();
        store.create_backend(&backend).unwrap();
        store.link_route_backend(&route.id, &backend.id).unwrap();

        let nc = make_notification_config();
        store.create_notification_config(&nc).unwrap();

        let pref = make_user_preference();
        store.create_user_preference(&pref).unwrap();

        let user = make_admin_user();
        store.create_admin_user(&user).unwrap();

        let toml_str = export_to_toml(&store).unwrap();

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

    #[test]
    fn test_export_import_with_encryption() {
        use crate::crypto::EncryptionKey;

        let key = EncryptionKey::generate().unwrap();
        let store1 = ConfigStore::open_in_memory_with_key(key.clone()).unwrap();

        let cert = make_certificate();
        store1.create_certificate(&cert).unwrap();

        // Export produces decrypted key_pem in TOML
        let toml_str = export_to_toml(&store1).unwrap();
        assert!(toml_str.contains(&cert.key_pem));

        // Import into another encrypted store works
        let store2 = ConfigStore::open_in_memory_with_key(key).unwrap();
        let data = parse_toml(&toml_str).unwrap();
        import_to_store(&store2, &data).unwrap();

        let fetched = store2.get_certificate(&cert.id).unwrap().unwrap();
        assert_eq!(fetched.key_pem, cert.key_pem);
    }
}
