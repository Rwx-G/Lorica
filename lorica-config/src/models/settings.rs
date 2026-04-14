use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// --- Security Header Presets ---

/// A named collection of HTTP security headers that can be applied to routes.
///
/// Routes reference a preset by name via `security_headers`. The proxy engine
/// resolves the name against builtin presets first, then custom presets from
/// `GlobalSettings`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityHeaderPreset {
    pub name: String,
    pub headers: HashMap<String, String>,
}

/// Return the three builtin security header presets: "strict", "moderate", and "none".
///
/// These match the original hardcoded header sets that were previously inlined
/// in the proxy `response_filter`.
pub fn builtin_security_presets() -> Vec<SecurityHeaderPreset> {
    vec![
        SecurityHeaderPreset {
            name: "strict".to_string(),
            headers: HashMap::from([
                (
                    "Strict-Transport-Security".to_string(),
                    "max-age=63072000; includeSubDomains; preload".to_string(),
                ),
                ("X-Frame-Options".to_string(), "DENY".to_string()),
                ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
                ("Referrer-Policy".to_string(), "no-referrer".to_string()),
                (
                    "Content-Security-Policy".to_string(),
                    "default-src 'self'".to_string(),
                ),
                (
                    "Permissions-Policy".to_string(),
                    "geolocation=(), camera=(), microphone=()".to_string(),
                ),
                ("X-XSS-Protection".to_string(), "1; mode=block".to_string()),
            ]),
        },
        SecurityHeaderPreset {
            name: "moderate".to_string(),
            headers: HashMap::from([
                ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
                ("X-Frame-Options".to_string(), "SAMEORIGIN".to_string()),
                ("X-XSS-Protection".to_string(), "1; mode=block".to_string()),
                (
                    "Strict-Transport-Security".to_string(),
                    "max-age=31536000; includeSubDomains".to_string(),
                ),
                (
                    "Referrer-Policy".to_string(),
                    "strict-origin-when-cross-origin".to_string(),
                ),
            ]),
        },
        SecurityHeaderPreset {
            name: "none".to_string(),
            headers: HashMap::new(),
        },
    ]
}

/// Resolve a preset name against the given presets list.
///
/// Searches builtin presets first, then custom presets. Returns `None` when the
/// name does not match any known preset (the caller should skip header injection
/// in that case, matching the previous "none or anything else" fallback).
pub fn resolve_security_preset<'a>(
    name: &str,
    custom_presets: &'a [SecurityHeaderPreset],
) -> Option<&'a SecurityHeaderPreset> {
    custom_presets.iter().find(|p| p.name == name)
}

/// Process-wide tunables persisted in the `global_settings` key-value
/// table. Read with `ConfigStore::get_global_settings` (which fills in
/// defaults from [`GlobalSettings::default`] for any missing keys) and
/// rewritten in full by `update_global_settings`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSettings {
    pub management_port: u16,
    pub log_level: String,
    pub default_health_check_interval_s: i32,
    #[serde(default = "default_cert_warning_days")]
    pub cert_warning_days: i32,
    #[serde(default = "default_cert_critical_days")]
    pub cert_critical_days: i32,
    #[serde(default = "default_max_active_probes")]
    pub max_active_probes: i32,
    #[serde(default = "default_loadtest_max_concurrency")]
    pub loadtest_max_concurrency: i32,
    #[serde(default = "default_loadtest_max_duration_s")]
    pub loadtest_max_duration_s: i32,
    #[serde(default = "default_loadtest_max_rps")]
    pub loadtest_max_rps: i32,
    /// Maximum total proxy connections across all routes.
    /// New requests receive 503 when this limit is reached. 0 = unlimited (default).
    #[serde(default)]
    pub max_global_connections: i32,
    /// Whether the IP blocklist is enabled. Persisted so it survives restarts.
    #[serde(default)]
    pub ip_blocklist_enabled: bool,
    /// Global flood detection threshold (requests per second).
    /// When the proxy-wide RPS exceeds this value, per-IP rate limits are
    /// halved to provide stricter protection. 0 = disabled (default).
    #[serde(default)]
    pub flood_threshold_rps: i32,
    /// Number of WAF blocks before an IP is auto-banned. 0 = disabled (default 5).
    #[serde(default = "default_waf_ban_threshold")]
    pub waf_ban_threshold: i32,
    /// Duration in seconds for WAF-triggered IP bans. Default 3600 (1h).
    #[serde(default = "default_waf_ban_duration_s")]
    pub waf_ban_duration_s: i32,
    /// User-defined security header presets, stored as JSON.
    /// These extend the builtin presets ("strict", "moderate", "none").
    /// If a custom preset shares a name with a builtin, the custom one wins.
    #[serde(default)]
    pub custom_security_presets: Vec<SecurityHeaderPreset>,
    /// Maximum number of access log entries to retain in the persistent store.
    /// Older entries are purged periodically. 0 = unlimited. Default: 100000.
    #[serde(default = "default_access_log_retention")]
    pub access_log_retention: i64,
    /// Whether automatic SLA data purge is enabled. Default: true
    /// (bounded disk usage out of the box; operators who need full
    /// history can opt out via the dashboard Settings tab).
    #[serde(default = "default_sla_purge_enabled")]
    pub sla_purge_enabled: bool,
    /// Number of days to retain SLA buckets. Buckets older than this are deleted.
    /// Default: 90 days.
    #[serde(default = "default_sla_purge_retention_days")]
    pub sla_purge_retention_days: i32,
    /// Purge schedule: "first_of_month", "daily", or a day number (1-28).
    /// Default: "first_of_month".
    #[serde(default = "default_sla_purge_schedule")]
    pub sla_purge_schedule: String,
    /// CIDR ranges of trusted reverse proxies. Only when the direct TCP client
    /// IP falls within one of these ranges will X-Forwarded-For be used to
    /// determine the real client IP. Empty list = trust no XFF (secure default).
    /// Examples: `["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]`.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// IP addresses or CIDR ranges that bypass WAF evaluation, rate limiting,
    /// and auto-ban entirely. Use for admin/operator IPs to prevent self-blocking.
    /// Examples: `["203.0.113.50", "10.0.0.0/8"]`.
    #[serde(default)]
    pub waf_whitelist_ips: Vec<String>,
    /// IP addresses or CIDR ranges denied at TCP accept time, before TLS
    /// handshake. Matching connections are dropped immediately. Evaluated
    /// after `connection_allow_cidrs` so a deny entry always wins.
    /// Examples: `["198.51.100.0/24"]`.
    #[serde(default)]
    pub connection_deny_cidrs: Vec<String>,
    /// IP addresses or CIDR ranges allowed at TCP accept time. When non-empty,
    /// this switches the pre-filter to default-deny: only listed IPs are
    /// accepted, all other connections are dropped before TLS handshake.
    /// Leave empty for default-allow (only `connection_deny_cidrs` applies).
    /// Examples: `["10.0.0.0/8", "192.168.0.0/16"]`.
    #[serde(default)]
    pub connection_allow_cidrs: Vec<String>,
    /// OTLP collector endpoint (e.g. `http://localhost:4317` for gRPC,
    /// `http://localhost:4318` for HTTP). Empty / None = OTel tracing
    /// disabled at runtime, even when the binary was built with
    /// `--features otel`. Changes take effect on the next config reload.
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
    /// OTLP transport protocol: `grpc`, `http-proto`, or `http-json`.
    /// Default `http-proto` since every major collector (Tempo, Jaeger v2,
    /// Datadog agent) accepts it and it is cheaper than gRPC when the
    /// collector sits behind an L7 load balancer.
    #[serde(default = "default_otlp_protocol")]
    pub otlp_protocol: String,
    /// Service name reported to the tracing backend
    /// (`service.name` OTel attribute). Defaults to `lorica`. Set to a
    /// per-deployment value like `lorica-prod-eu-west-1` when multiple
    /// instances share a collector.
    #[serde(default = "default_otlp_service_name")]
    pub otlp_service_name: String,
    /// Head sampler ratio in 0.0..=1.0. 0.0 disables tracing even when
    /// the endpoint is set; 1.0 samples every request. Default 0.1
    /// (matches Tempo / Grafana guidance for steady-state overhead
    /// under ~2 %). Child spans inherit the root-span decision so there
    /// are no partial traces.
    #[serde(default = "default_otlp_sampling_ratio")]
    pub otlp_sampling_ratio: f64,
    /// Filesystem path to the `.mmdb` GeoIP database. `None` = GeoIP
    /// disabled at runtime even when per-route `GeoIpConfig` is set
    /// (the request_filter check becomes a no-op). Default data source
    /// is DB-IP Lite Country (CC-BY 4.0, no account required). The
    /// `.mmdb` format is identical to MaxMind's GeoLite2, so operators
    /// with a MaxMind license can just swap this path with no other
    /// changes.
    #[serde(default)]
    pub geoip_db_path: Option<String>,
    /// Whether Lorica should periodically download a fresh DB-IP
    /// Lite Country snapshot and hot-swap the in-memory reader.
    /// Default `false` — operators opt in via the dashboard after
    /// they have read the CC-BY 4.0 attribution requirement. When
    /// `true`, the supervisor runs a weekly refresh task inside its
    /// tokio runtime; failures fall back to serving the previously
    /// loaded DB so a transient network blip never blocks requests.
    #[serde(default)]
    pub geoip_auto_update_enabled: bool,
}

fn default_waf_ban_threshold() -> i32 {
    3
}

fn default_waf_ban_duration_s() -> i32 {
    3600
}

fn default_cert_warning_days() -> i32 {
    30
}

fn default_cert_critical_days() -> i32 {
    7
}

fn default_max_active_probes() -> i32 {
    50
}

fn default_loadtest_max_concurrency() -> i32 {
    100
}

fn default_loadtest_max_duration_s() -> i32 {
    60
}

fn default_loadtest_max_rps() -> i32 {
    1000
}

fn default_access_log_retention() -> i64 {
    100_000
}

fn default_sla_purge_enabled() -> bool {
    true
}

fn default_sla_purge_retention_days() -> i32 {
    90
}

fn default_sla_purge_schedule() -> String {
    "first_of_month".to_string()
}

fn default_otlp_protocol() -> String {
    "http-proto".to_string()
}

fn default_otlp_service_name() -> String {
    "lorica".to_string()
}

fn default_otlp_sampling_ratio() -> f64 {
    0.1
}

impl Default for GlobalSettings {
    fn default() -> Self {
        Self {
            management_port: 9443,
            log_level: "info".to_string(),
            default_health_check_interval_s: 10,
            cert_warning_days: 30,
            cert_critical_days: 7,
            max_active_probes: 50,
            loadtest_max_concurrency: 100,
            loadtest_max_duration_s: 60,
            loadtest_max_rps: 1000,
            ip_blocklist_enabled: false,
            max_global_connections: 0,
            flood_threshold_rps: 0,
            waf_ban_threshold: default_waf_ban_threshold(),
            waf_ban_duration_s: default_waf_ban_duration_s(),
            custom_security_presets: Vec::new(),
            access_log_retention: default_access_log_retention(),
            sla_purge_enabled: default_sla_purge_enabled(),
            sla_purge_retention_days: default_sla_purge_retention_days(),
            sla_purge_schedule: default_sla_purge_schedule(),
            trusted_proxies: Vec::new(),
            waf_whitelist_ips: Vec::new(),
            connection_deny_cidrs: Vec::new(),
            connection_allow_cidrs: Vec::new(),
            otlp_endpoint: None,
            otlp_protocol: default_otlp_protocol(),
            otlp_service_name: default_otlp_service_name(),
            otlp_sampling_ratio: default_otlp_sampling_ratio(),
            geoip_db_path: None,
            geoip_auto_update_enabled: false,
        }
    }
}
