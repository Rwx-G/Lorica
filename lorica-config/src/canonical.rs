//! Canonical configuration encoder (Story 9.1 AC #5) and its strict
//! decode path (AC #12).
//!
//! Produces byte-stable output for a given logical configuration so
//! two nodes - or one node across a restart - hash the same config to
//! the same value. This is the drift-detection and replication
//! payload for the Epic 9 cluster plane; it is deliberately NOT the
//! TOML export path, which redacts `key_pem` and every channel secret
//! and whose import rejects those placeholders.
//!
//! # Determinism argument
//!
//! Three instability sources exist, and each is closed:
//!
//! 1. **`HashMap` iteration order** (`Route.proxy_headers` /
//!    `response_headers`, `PathRule.response_headers`,
//!    `SecurityHeaderPreset.headers`) is `RandomState`-seeded per
//!    instance, and serde serialises a `HashMap` in iteration order.
//!    The encoder therefore converts the whole snapshot to
//!    `serde_json::Value` and recursively rewrites every object with
//!    its keys sorted (`sort_object_keys`), which is deterministic
//!    regardless of the map seed AND of whether any crate in the
//!    workspace turns on serde_json's `preserve_order` feature.
//! 2. **SQL row ordering** with tie-prone keys (`certificates ORDER BY
//!    domain`, `notification_configs ORDER BY channel` - neither is a
//!    unique key). Every top-level entity set is explicitly re-sorted
//!    by the serialised-JSON representation of each element, which is
//!    a total order even when natural keys collide.
//! 3. **Inner arrays** (`path_rules`, `header_rules`,
//!    `traffic_splits`, rewrite rules, backend id lists) are NOT
//!    sorted: their declaration order is semantic (first match wins)
//!    and already stable - they round-trip through JSON columns and
//!    the replica apply verbatim. Sorting them would silently change
//!    routing behaviour on the follower.
//!
//! Timestamps are bound from the model on insert (not
//! `datetime('now')`), so a follower that re-encodes its applied
//! replica reproduces the control plane's bytes.
//!
//! # Secrets and node-local fields
//!
//! Secrets ARE included (certificate `key_pem`, notification / DNS
//! provider credentials - the store listings decrypt transparently):
//! the blob travels only over the cluster plane's mutual TLS and is
//! what a follower needs to actually serve. Node-local machine facts
//! are excluded BY CONSTRUCTION: [`CanonicalGlobalSettings`] simply
//! has no field for them, so a control-plane compromise cannot turn
//! replication into an arbitrary-path file-write primitive on the
//! fleet (Story 9.4 AC #1).

use serde::{Deserialize, Serialize};

use crate::error::{ConfigError, Result};
use crate::models::{
    Backend, CertExportAcl, Certificate, CustomCrawler, DnsProvider, GlobalSettings,
    NotificationConfig, ProbeConfig, Route, RouteBackend, SecurityHeaderPreset, SlaConfig,
    SpoofedFallback,
};
use crate::store::ConfigStore;

/// Version stamped into every canonical blob so a future shape change
/// is detectable instead of silently mis-decoded.
pub const CANONICAL_FORMAT_VERSION: u32 = 1;

/// One WAF custom rule in canonical form. The store keeps these as
/// bare tuples; the blob needs a named, strict shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalWafRule {
    /// Operator-chosen rule id (also the primary key).
    pub id: u32,
    /// Human-readable description.
    pub description: String,
    /// Rule category label.
    pub category: String,
    /// Match pattern source.
    pub pattern: String,
    /// Severity 1-5.
    pub severity: u8,
    /// Whether the rule is active.
    pub enabled: bool,
}

/// The fleet-policy subset of [`GlobalSettings`]. Node-local fields
/// (filesystem paths, uids/gids/modes, listener ports, machine
/// secrets) have no field here, so they cannot replicate.
///
/// Node-local by the Epic 9 PRD (Story 9.4 AC #1): every
/// `cert_export_*` field, `management_port` /
/// `management_cert_pem_path` / `management_key_pem_path`,
/// `geoip_db_path` / `asn_db_path` and their auto-update toggles,
/// `upgrade_signing_pubkey_path`, `prometheus_scrape_token`,
/// `bot_hmac_secret_hex`, `trusted_proxies`, `metrics_require_auth`,
/// `log_level`. Additionally, every Story 9.8 `syslog_*` / `otlp_*`
/// log-sink and exporter field is treated as node-local here:
/// collectors and their credentials are per-node infrastructure the
/// PRD predates - Story 9.4 revisits that split if fleet-wide sink
/// policy is wanted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalGlobalSettings {
    /// Fallback health-check interval (s).
    pub default_health_check_interval_s: i32,
    /// Certificate expiry warning threshold (days).
    pub cert_warning_days: i32,
    /// Certificate expiry critical threshold (days).
    pub cert_critical_days: i32,
    /// Cap on concurrently configured active probes.
    pub max_active_probes: i32,
    /// Cap on concurrent backend health-check probes.
    pub health_max_concurrent_probes: i32,
    /// Load-test guard: max concurrency.
    pub loadtest_max_concurrency: i32,
    /// Load-test guard: max duration (s).
    pub loadtest_max_duration_s: i32,
    /// Load-test guard: max requests per second.
    pub loadtest_max_rps: i32,
    /// Whether the global IP blocklist is enforced.
    pub ip_blocklist_enabled: bool,
    /// Global concurrent-connection cap (0 = unlimited).
    pub max_global_connections: i32,
    /// Adaptive flood-defence trigger (proxy-wide rps, 0 = off).
    pub flood_threshold_rps: i32,
    /// Flood strict admission rate (0 = auto).
    pub flood_strict_rps: u32,
    /// Global slowloris header-read floor (s).
    pub header_timeout_s: u32,
    /// WAF auto-ban threshold.
    pub waf_ban_threshold: i32,
    /// WAF auto-ban duration (s).
    pub waf_ban_duration_s: i32,
    /// Operator-defined security-header presets (sorted by name).
    pub custom_security_presets: Vec<SecurityHeaderPreset>,
    /// Access-log retention row cap.
    pub access_log_retention: i64,
    /// WAF-event retention row cap.
    pub waf_event_retention: i64,
    /// Whether SLA bucket purging runs.
    pub sla_purge_enabled: bool,
    /// SLA bucket retention window (days).
    pub sla_purge_retention_days: i32,
    /// SLA purge schedule label.
    pub sla_purge_schedule: String,
    /// IPs / CIDRs bypassing WAF + rate-limit + auto-ban.
    pub waf_whitelist_ips: Vec<String>,
    /// CIDRs denied at TCP accept time.
    pub connection_deny_cidrs: Vec<String>,
    /// CIDRs allowed at TCP accept time (default-deny when set).
    pub connection_allow_cidrs: Vec<String>,
    /// Per-source-IP TCP connection cap.
    pub connection_limits_per_ip: Option<u32>,
    /// Global spoofed-AI-bot fallback policy.
    pub ai_bot_treat_spoofed_as: SpoofedFallback,
    /// Whether verified-bot headers are injected upstream.
    pub ai_bot_inject_headers: bool,
    /// Password minimum length policy.
    pub password_min_length: u32,
    /// Password complexity-classes policy.
    pub password_require_complexity: bool,
    /// Audit-log retention (days).
    pub audit_log_retention_days: u32,
    /// Global cap on pending bot challenges.
    pub bot_stash_max_entries: u32,
    /// Per-IP-prefix cap on pending bot challenges.
    pub bot_stash_per_prefix_max: u32,
    /// Per-route mirror concurrency cap.
    pub mirror_max_concurrent_per_route: u32,
    /// Global mirror concurrency cap.
    pub mirror_max_concurrent_global: u32,
}

impl From<&GlobalSettings> for CanonicalGlobalSettings {
    fn from(s: &GlobalSettings) -> Self {
        Self {
            default_health_check_interval_s: s.default_health_check_interval_s,
            cert_warning_days: s.cert_warning_days,
            cert_critical_days: s.cert_critical_days,
            max_active_probes: s.max_active_probes,
            health_max_concurrent_probes: s.health_max_concurrent_probes,
            loadtest_max_concurrency: s.loadtest_max_concurrency,
            loadtest_max_duration_s: s.loadtest_max_duration_s,
            loadtest_max_rps: s.loadtest_max_rps,
            ip_blocklist_enabled: s.ip_blocklist_enabled,
            max_global_connections: s.max_global_connections,
            flood_threshold_rps: s.flood_threshold_rps,
            flood_strict_rps: s.flood_strict_rps,
            header_timeout_s: s.header_timeout_s,
            waf_ban_threshold: s.waf_ban_threshold,
            waf_ban_duration_s: s.waf_ban_duration_s,
            custom_security_presets: s.custom_security_presets.clone(),
            access_log_retention: s.access_log_retention,
            waf_event_retention: s.waf_event_retention,
            sla_purge_enabled: s.sla_purge_enabled,
            sla_purge_retention_days: s.sla_purge_retention_days,
            sla_purge_schedule: s.sla_purge_schedule.clone(),
            waf_whitelist_ips: s.waf_whitelist_ips.clone(),
            connection_deny_cidrs: s.connection_deny_cidrs.clone(),
            connection_allow_cidrs: s.connection_allow_cidrs.clone(),
            connection_limits_per_ip: s.connection_limits_per_ip,
            ai_bot_treat_spoofed_as: s.ai_bot_treat_spoofed_as,
            ai_bot_inject_headers: s.ai_bot_inject_headers,
            password_min_length: s.password_min_length,
            password_require_complexity: s.password_require_complexity,
            audit_log_retention_days: s.audit_log_retention_days,
            bot_stash_max_entries: s.bot_stash_max_entries,
            bot_stash_per_prefix_max: s.bot_stash_per_prefix_max,
            mirror_max_concurrent_per_route: s.mirror_max_concurrent_per_route,
            mirror_max_concurrent_global: s.mirror_max_concurrent_global,
        }
    }
}

/// The canonical, byte-stable snapshot of everything the cluster
/// replicates. Users and user preferences are deliberately absent
/// (follower-local per the Epic 9 PRD), as are load tests, sessions,
/// and all telemetry tables.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalConfig {
    /// [`CANONICAL_FORMAT_VERSION`] at encode time.
    pub version: u32,
    /// Fleet-policy settings subset.
    pub global: CanonicalGlobalSettings,
    /// Routes, sorted canonically.
    pub routes: Vec<Route>,
    /// Backends, sorted canonically.
    pub backends: Vec<Backend>,
    /// Route-to-backend links, sorted canonically.
    pub route_backends: Vec<RouteBackend>,
    /// Certificates INCLUDING private keys (see module doc).
    pub certificates: Vec<Certificate>,
    /// Notification channels INCLUDING their secrets.
    pub notification_configs: Vec<NotificationConfig>,
    /// DNS providers INCLUDING their credentials.
    pub dns_providers: Vec<DnsProvider>,
    /// Operator WAF custom rules.
    pub waf_custom_rules: Vec<CanonicalWafRule>,
    /// Disabled built-in WAF rule ids, ascending.
    pub waf_disabled_rules: Vec<u32>,
    /// Certificate filesystem-export ACL patterns. The export
    /// DIRECTORY and ownership stay node-local; the pattern policy of
    /// which hostnames may be exported is fleet policy.
    pub cert_export_acls: Vec<CertExportAcl>,
    /// Operator-defined AI crawler entries (keyed on unique `name`).
    pub ai_crawlers_custom: Vec<CustomCrawler>,
    /// Active-probe definitions.
    pub probe_configs: Vec<ProbeConfig>,
    /// SLA target definitions.
    pub sla_configs: Vec<SlaConfig>,
}

/// Recursively rewrite every JSON object with its keys in sorted
/// order. Rebuilding entry-by-entry (instead of relying on the
/// backing map type) stays deterministic whether `serde_json::Map` is
/// the default `BTreeMap` or the `preserve_order` `IndexMap`.
fn sort_object_keys(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(String, serde_json::Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut sorted = serde_json::Map::new();
            for (key, inner) in entries {
                sorted.insert(key, sort_object_keys(inner));
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(sort_object_keys).collect())
        }
        other => other,
    }
}

/// Sort a collection by the canonical (key-sorted) JSON form of each
/// element - a total order that needs no per-type key knowledge and
/// cannot tie two logically distinct elements. The key must be the
/// canonical form, not the raw serialisation: a raw `HashMap` field
/// would make the same entity produce different sort keys per
/// process. Serialisation of these plain data models cannot fail (no
/// non-string map keys, no NaN floats); the empty-string fallback
/// keeps the sort total even if it ever did, at the cost of grouping
/// unencodable elements first.
fn sort_by_canonical_repr<T: Serialize>(items: &mut [T]) {
    items.sort_by_cached_key(|item| {
        serde_json::to_value(item)
            .map(|v| sort_object_keys(v).to_string())
            .unwrap_or_default()
    });
}

/// Assemble the canonical snapshot from a store, sorted and ready to
/// encode.
pub fn canonical_config(store: &ConfigStore) -> Result<CanonicalConfig> {
    let settings = store.get_global_settings()?;
    let mut global = CanonicalGlobalSettings::from(&settings);
    sort_by_canonical_repr(&mut global.custom_security_presets);

    let mut cfg = CanonicalConfig {
        version: CANONICAL_FORMAT_VERSION,
        global,
        routes: store.list_routes()?,
        backends: store.list_backends()?,
        route_backends: store.list_route_backends()?,
        certificates: store.list_certificates()?,
        notification_configs: store.list_notification_configs()?,
        dns_providers: store.list_dns_providers()?,
        waf_custom_rules: store
            .load_waf_custom_rules()?
            .into_iter()
            .map(
                |(id, description, category, pattern, severity, enabled)| CanonicalWafRule {
                    id,
                    description,
                    category,
                    pattern,
                    severity,
                    enabled,
                },
            )
            .collect(),
        waf_disabled_rules: store.load_waf_disabled_rules()?,
        cert_export_acls: store.list_cert_export_acls()?,
        ai_crawlers_custom: store.list_custom_crawlers()?,
        probe_configs: store.list_probe_configs()?,
        sla_configs: store.list_sla_configs()?,
    };

    sort_by_canonical_repr(&mut cfg.routes);
    sort_by_canonical_repr(&mut cfg.backends);
    sort_by_canonical_repr(&mut cfg.route_backends);
    sort_by_canonical_repr(&mut cfg.certificates);
    sort_by_canonical_repr(&mut cfg.notification_configs);
    sort_by_canonical_repr(&mut cfg.dns_providers);
    sort_by_canonical_repr(&mut cfg.waf_custom_rules);
    cfg.waf_disabled_rules.sort_unstable();
    sort_by_canonical_repr(&mut cfg.cert_export_acls);
    sort_by_canonical_repr(&mut cfg.ai_crawlers_custom);
    sort_by_canonical_repr(&mut cfg.probe_configs);
    sort_by_canonical_repr(&mut cfg.sla_configs);

    Ok(cfg)
}

/// Encode the store's current configuration to canonical bytes.
pub fn canonical_bytes(store: &ConfigStore) -> Result<Vec<u8>> {
    let cfg = canonical_config(store)?;
    let value = serde_json::to_value(&cfg)
        .map_err(|e| ConfigError::Validation(format!("canonical encode failed: {e}")))?;
    serde_json::to_vec(&sort_object_keys(value))
        .map_err(|e| ConfigError::Validation(format!("canonical encode failed: {e}")))
}

/// SHA-256 of [`canonical_bytes`], lowercase hex. The value compared
/// for drift detection across the fleet.
pub fn canonical_hash(store: &ConfigStore) -> Result<String> {
    let bytes = canonical_bytes(store)?;
    let digest = ring::digest::digest(&ring::digest::SHA256, &bytes);
    Ok(digest
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>())
}

/// Strict decode of a replicated blob (Story 9.1 AC #12). A follower
/// on schema N-1 receiving a blob from schema N fails loudly here
/// instead of silently discarding unknown fields and reporting
/// "applied ok" - including for a new security-relevant setting.
pub fn decode_canonical(bytes: &[u8]) -> Result<CanonicalConfig> {
    serde_json::from_slice(bytes)
        .map_err(|e| ConfigError::Validation(format!("canonical decode failed: {e}")))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::{DateTime, Utc};

    use super::*;
    use crate::models::{
        HealthStatus, LifecycleState, LoadBalancing, NotificationChannel, PathRule, WafMode,
    };

    /// Fixed timestamp so the same logical entity inserted into two
    /// stores serialises to identical bytes.
    fn fixed_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("test setup: valid timestamp")
            .with_timezone(&Utc)
    }

    fn make_route(id: &str, hostname: &str) -> Route {
        let now = fixed_now();
        let mut proxy_headers = HashMap::new();
        proxy_headers.insert("X-Alpha".to_string(), "1".to_string());
        proxy_headers.insert("X-Beta".to_string(), "2".to_string());
        proxy_headers.insert("X-Gamma".to_string(), "3".to_string());
        let mut response_headers = HashMap::new();
        response_headers.insert("X-Frame-Options".to_string(), "DENY".to_string());
        response_headers.insert("X-Zulu".to_string(), "z".to_string());
        let mut rule_headers = HashMap::new();
        rule_headers.insert("Cache-Control".to_string(), "no-store".to_string());
        rule_headers.insert("X-Rule".to_string(), "on".to_string());
        Route {
            id: id.to_string(),
            hostname: hostname.to_string(),
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
            proxy_headers,
            response_headers,
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
            cache_max_bytes: 52_428_800,
            max_connections: None,
            slowloris_threshold_ms: 5000,
            auto_ban_threshold: None,
            auto_ban_duration_s: 3600,
            path_rules: vec![PathRule {
                path: "/api".into(),
                response_headers: Some(rule_headers),
                ..PathRule::default()
            }],
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
            ai_bot_policy: None,
            ai_bot_spoofed_fallback: None,
            serve_robots_txt: false,
            created_at: now,
            updated_at: now,
        }
    }

    fn make_backend(id: &str, address: &str) -> Backend {
        let now = fixed_now();
        Backend {
            id: id.to_string(),
            address: address.to_string(),
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

    /// Both certs share `domain` on purpose: `list_certificates`'
    /// `ORDER BY domain` is not a total order, so this exercises the
    /// canonical re-sort on tied keys.
    fn make_certificate(id: &str, fingerprint: &str) -> Certificate {
        let now = fixed_now();
        Certificate {
            id: id.to_string(),
            domain: "tls.example.com".into(),
            san_domains: vec!["www.example.com".into()],
            fingerprint: fingerprint.to_string(),
            cert_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".into(),
            key_pem: "-----BEGIN PRIVATE KEY-----\ncanonical-secret-key-material\n-----END PRIVATE KEY-----".into(),
            issuer: "Test CA".into(),
            not_before: now,
            not_after: now,
            is_acme: false,
            acme_auto_renew: false,
            created_at: now,
            acme_method: None,
            acme_dns_provider_id: None,
        }
    }

    fn make_notification(id: &str) -> NotificationConfig {
        NotificationConfig {
            id: id.to_string(),
            channel: NotificationChannel::Email,
            enabled: true,
            config: r#"{"smtp_host":"mail.example.com","smtp_password":"canonical-smtp-secret"}"#
                .into(),
            alert_types: vec!["cert_expiry".into(), "backend_down".into()],
        }
    }

    fn preset(name: &str) -> SecurityHeaderPreset {
        let mut headers = HashMap::new();
        headers.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());
        headers.insert("Referrer-Policy".to_string(), "no-referrer".to_string());
        headers.insert("X-Frame-Options".to_string(), "DENY".to_string());
        SecurityHeaderPreset {
            name: name.to_string(),
            headers,
        }
    }

    /// Populate a store with a fixed logical config; `reversed` flips
    /// every insertion order so SQL rowids differ between the two
    /// stores of the determinism test. Entity ids are fixed (not
    /// `new_id()`) so both stores hold identical logical entities.
    fn populate(store: &ConfigStore, reversed: bool) {
        let mut routes = vec![
            make_route("r1-fixed", "a.example.com"),
            make_route("r2-fixed", "b.example.com"),
        ];
        let mut backends = vec![
            make_backend("b1-fixed", "10.0.0.10:8080"),
            make_backend("b2-fixed", "10.0.0.11:8080"),
        ];
        let mut certs = vec![
            make_certificate("c1-fixed", "sha256:aaa"),
            make_certificate("c2-fixed", "sha256:bbb"),
        ];
        let mut presets = vec![preset("team-a"), preset("team-b")];
        if reversed {
            routes.reverse();
            backends.reverse();
            certs.reverse();
            presets.reverse();
        }
        for r in &routes {
            store.create_route(r).expect("test setup: route inserts");
        }
        for b in &backends {
            store.create_backend(b).expect("test setup: backend inserts");
        }
        let mut links: Vec<(&str, &str)> = routes
            .iter()
            .flat_map(|r| backends.iter().map(move |b| (r.id.as_str(), b.id.as_str())))
            .collect();
        if reversed {
            links.reverse();
        }
        for (rid, bid) in links {
            store
                .link_route_backend(rid, bid)
                .expect("test setup: link inserts");
        }
        for c in &certs {
            store
                .create_certificate(c)
                .expect("test setup: certificate inserts");
        }
        store
            .create_notification_config(&make_notification("n1-fixed"))
            .expect("test setup: notification inserts");
        let mut settings = store
            .get_global_settings()
            .expect("test setup: settings read");
        settings.custom_security_presets = presets;
        settings.waf_ban_threshold = 7;
        store
            .update_global_settings(&settings)
            .expect("test setup: settings write");
    }

    #[test]
    fn canonical_bytes_are_identical_across_insertion_orders() {
        let store_a = ConfigStore::open_in_memory().expect("test setup: store opens");
        let store_b = ConfigStore::open_in_memory().expect("test setup: store opens");
        populate(&store_a, false);
        populate(&store_b, true);

        let bytes_a = canonical_bytes(&store_a).expect("encode a");
        let bytes_b = canonical_bytes(&store_b).expect("encode b");
        assert_eq!(bytes_a, bytes_b);
        assert_eq!(
            canonical_hash(&store_a).expect("hash a"),
            canonical_hash(&store_b).expect("hash b")
        );
    }

    #[test]
    fn secrets_are_included_in_canonical_bytes() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        populate(&store, false);

        let text = String::from_utf8(canonical_bytes(&store).expect("encode")).expect("utf8");
        assert!(text.contains("canonical-secret-key-material"));
        assert!(text.contains("canonical-smtp-secret"));
    }

    #[test]
    fn node_local_fields_are_absent_from_canonical_bytes() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        populate(&store, false);
        let mut settings = store.get_global_settings().expect("settings read");
        settings.bot_hmac_secret_hex = "feedfacefeedfacefeedfacefeedface".into();
        settings.cert_export_dir = Some("/var/lib/lorica-export-nodelocal".into());
        settings.syslog_endpoint = Some("collector.internal.example.org:6514".into());
        store
            .update_global_settings(&settings)
            .expect("settings write");

        let text = String::from_utf8(canonical_bytes(&store).expect("encode")).expect("utf8");
        assert!(!text.contains("feedfacefeedfacefeedfacefeedface"));
        assert!(!text.contains("lorica-export-nodelocal"));
        assert!(!text.contains("collector.internal.example.org"));
        // Field names are excluded too, not just the values.
        assert!(!text.contains("bot_hmac_secret_hex"));
        assert!(!text.contains("cert_export_dir"));
        assert!(!text.contains("syslog_endpoint"));
    }

    #[test]
    fn decode_rejects_unknown_fields() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        populate(&store, false);
        let bytes = canonical_bytes(&store).expect("encode");
        assert!(decode_canonical(&bytes).is_ok());

        // Unknown field at the blob root.
        let mut root: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        root.as_object_mut().expect("object").insert(
            "added_in_a_newer_schema".into(),
            serde_json::Value::Bool(true),
        );
        let tampered = serde_json::to_vec(&root).expect("re-encode");
        assert!(decode_canonical(&tampered).is_err());

        // Unknown field nested inside an embedded model struct.
        let mut root: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        root["routes"][0]
            .as_object_mut()
            .expect("route object")
            .insert("new_security_toggle".into(), serde_json::Value::Bool(true));
        let tampered = serde_json::to_vec(&root).expect("re-encode");
        assert!(decode_canonical(&tampered).is_err());
    }

    #[test]
    fn hash_tracks_replicated_changes_and_ignores_node_local_ones() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        populate(&store, false);
        let baseline = canonical_hash(&store).expect("hash");

        // Node-local change: no hash movement.
        let mut settings = store.get_global_settings().expect("settings read");
        settings.log_level = "debug".into();
        store
            .update_global_settings(&settings)
            .expect("settings write");
        assert_eq!(baseline, canonical_hash(&store).expect("hash"));

        // Replicated change: hash moves.
        let mut settings = store.get_global_settings().expect("settings read");
        settings.waf_ban_threshold += 1;
        store
            .update_global_settings(&settings)
            .expect("settings write");
        assert_ne!(baseline, canonical_hash(&store).expect("hash"));
    }
}
