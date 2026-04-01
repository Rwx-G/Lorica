use std::collections::HashMap;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// --- Enums ---

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancing {
    RoundRobin,
    ConsistentHash,
    Random,
    PeakEwma,
}

impl LoadBalancing {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RoundRobin => "round_robin",
            Self::ConsistentHash => "consistent_hash",
            Self::Random => "random",
            Self::PeakEwma => "peak_ewma",
        }
    }
}

impl FromStr for LoadBalancing {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "round_robin" => Ok(Self::RoundRobin),
            "consistent_hash" => Ok(Self::ConsistentHash),
            "random" => Ok(Self::Random),
            "peak_ewma" => Ok(Self::PeakEwma),
            other => Err(format!("unknown load balancing algorithm: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafMode {
    Detection,
    Blocking,
}

impl WafMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Detection => "detection",
            Self::Blocking => "blocking",
        }
    }
}

impl FromStr for WafMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "detection" => Ok(Self::Detection),
            "blocking" => Ok(Self::Blocking),
            other => Err(format!("unknown WAF mode: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyType {
    SingleVm,
    Ha,
    DockerSwarm,
    Kubernetes,
    Custom,
}

impl TopologyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SingleVm => "single_vm",
            Self::Ha => "ha",
            Self::DockerSwarm => "docker_swarm",
            Self::Kubernetes => "kubernetes",
            Self::Custom => "custom",
        }
    }
}

impl FromStr for TopologyType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "single_vm" => Ok(Self::SingleVm),
            "ha" => Ok(Self::Ha),
            "docker_swarm" => Ok(Self::DockerSwarm),
            "kubernetes" => Ok(Self::Kubernetes),
            "custom" => Ok(Self::Custom),
            other => Err(format!("unknown topology type: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Down,
    Unknown,
}

impl HealthStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Down => "down",
            Self::Unknown => "unknown",
        }
    }
}

impl FromStr for HealthStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "healthy" => Ok(Self::Healthy),
            "degraded" => Ok(Self::Degraded),
            "down" => Ok(Self::Down),
            "unknown" => Ok(Self::Unknown),
            other => Err(format!("unknown health status: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Normal,
    Closing,
    Closed,
}

impl LifecycleState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Closing => "closing",
            Self::Closed => "closed",
        }
    }
}

impl FromStr for LifecycleState {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "normal" => Ok(Self::Normal),
            "closing" => Ok(Self::Closing),
            "closed" => Ok(Self::Closed),
            other => Err(format!("unknown lifecycle state: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationChannel {
    Email,
    Webhook,
}

impl NotificationChannel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Webhook => "webhook",
        }
    }
}

impl FromStr for NotificationChannel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "email" => Ok(Self::Email),
            "webhook" => Ok(Self::Webhook),
            other => Err(format!("unknown notification channel: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreferenceValue {
    Never,
    Always,
    Once,
}

impl PreferenceValue {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::Always => "always",
            Self::Once => "once",
        }
    }
}

impl FromStr for PreferenceValue {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "never" => Ok(Self::Never),
            "always" => Ok(Self::Always),
            "once" => Ok(Self::Once),
            other => Err(format!("unknown preference value: {other}")),
        }
    }
}

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

// --- Data Models ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub id: String,
    pub hostname: String,
    pub path_prefix: String,
    pub certificate_id: Option<String>,
    pub load_balancing: LoadBalancing,
    pub waf_enabled: bool,
    pub waf_mode: WafMode,
    pub topology_type: TopologyType,
    pub enabled: bool,
    #[serde(default)]
    pub force_https: bool,
    #[serde(default)]
    pub redirect_hostname: Option<String>,
    #[serde(default)]
    pub hostname_aliases: Vec<String>,
    #[serde(default)]
    pub proxy_headers: HashMap<String, String>,
    #[serde(default)]
    pub response_headers: HashMap<String, String>,
    #[serde(default = "default_security_headers")]
    pub security_headers: String,
    #[serde(default = "default_connect_timeout_s")]
    pub connect_timeout_s: i32,
    #[serde(default = "default_read_timeout_s")]
    pub read_timeout_s: i32,
    #[serde(default = "default_send_timeout_s")]
    pub send_timeout_s: i32,
    #[serde(default)]
    pub strip_path_prefix: Option<String>,
    #[serde(default)]
    pub add_path_prefix: Option<String>,
    #[serde(default = "default_access_log_enabled")]
    pub access_log_enabled: bool,
    #[serde(default)]
    pub proxy_headers_remove: Vec<String>,
    #[serde(default)]
    pub response_headers_remove: Vec<String>,
    #[serde(default)]
    pub max_request_body_bytes: Option<u64>,
    #[serde(default = "default_websocket_enabled")]
    pub websocket_enabled: bool,
    #[serde(default)]
    pub rate_limit_rps: Option<u32>,
    #[serde(default)]
    pub rate_limit_burst: Option<u32>,
    #[serde(default)]
    pub ip_allowlist: Vec<String>,
    #[serde(default)]
    pub ip_denylist: Vec<String>,
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
    #[serde(default)]
    pub cors_allowed_methods: Vec<String>,
    #[serde(default)]
    pub cors_max_age_s: Option<i32>,
    #[serde(default = "default_compression_enabled")]
    pub compression_enabled: bool,
    #[serde(default)]
    pub retry_attempts: Option<u32>,
    #[serde(default)]
    pub cache_enabled: bool,
    #[serde(default = "default_cache_ttl_s")]
    pub cache_ttl_s: i32,
    #[serde(default = "default_cache_max_bytes")]
    pub cache_max_bytes: i64,
    #[serde(default)]
    pub max_connections: Option<u32>,
    #[serde(default = "default_slowloris_threshold_ms")]
    pub slowloris_threshold_ms: i32,
    #[serde(default)]
    pub auto_ban_threshold: Option<u32>,
    #[serde(default = "default_auto_ban_duration_s")]
    pub auto_ban_duration_s: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backend {
    pub id: String,
    pub address: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub group_name: String,
    pub weight: i32,
    pub health_status: HealthStatus,
    pub health_check_enabled: bool,
    pub health_check_interval_s: i32,
    /// Optional HTTP health check path (e.g. "/healthz"). When set, HTTP GET
    /// is used instead of TCP connect for health checks.
    #[serde(default)]
    pub health_check_path: Option<String>,
    pub lifecycle_state: LifecycleState,
    pub active_connections: i32,
    pub tls_upstream: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteBackend {
    pub route_id: String,
    pub backend_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub id: String,
    pub domain: String,
    pub san_domains: Vec<String>,
    pub fingerprint: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub issuer: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub is_acme: bool,
    pub acme_auto_renew: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub id: String,
    pub channel: NotificationChannel,
    pub enabled: bool,
    pub config: String,
    pub alert_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPreference {
    pub id: String,
    pub preference_key: String,
    pub value: PreferenceValue,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminUser {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub must_change_password: bool,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSettings {
    pub management_port: u16,
    pub log_level: String,
    pub default_health_check_interval_s: i32,
    #[serde(default = "default_cert_warning_days")]
    pub cert_warning_days: i32,
    #[serde(default = "default_cert_critical_days")]
    pub cert_critical_days: i32,
    #[serde(default = "default_topology_type")]
    pub default_topology_type: TopologyType,
    #[serde(default = "default_max_active_probes")]
    pub max_active_probes: i32,
    #[serde(default = "default_loadtest_max_concurrency")]
    pub loadtest_max_concurrency: i32,
    #[serde(default = "default_loadtest_max_duration_s")]
    pub loadtest_max_duration_s: i32,
    #[serde(default = "default_loadtest_max_rps")]
    pub loadtest_max_rps: i32,
    /// Global flood detection threshold (requests per second).
    /// When the proxy-wide RPS exceeds this value, per-IP rate limits are
    /// halved to provide stricter protection. 0 = disabled (default).
    #[serde(default)]
    pub flood_threshold_rps: i32,
    /// User-defined security header presets, stored as JSON.
    /// These extend the builtin presets ("strict", "moderate", "none").
    /// If a custom preset shares a name with a builtin, the custom one wins.
    #[serde(default)]
    pub custom_security_presets: Vec<SecurityHeaderPreset>,
}

fn default_security_headers() -> String {
    "moderate".to_string()
}

fn default_connect_timeout_s() -> i32 {
    5
}

fn default_read_timeout_s() -> i32 {
    60
}

fn default_send_timeout_s() -> i32 {
    60
}

fn default_access_log_enabled() -> bool {
    true
}

fn default_websocket_enabled() -> bool {
    true
}

fn default_compression_enabled() -> bool {
    false
}

fn default_cache_ttl_s() -> i32 {
    300
}

fn default_cache_max_bytes() -> i64 {
    52428800
}

fn default_slowloris_threshold_ms() -> i32 {
    5000
}

fn default_auto_ban_duration_s() -> i32 {
    3600
}

fn default_cert_warning_days() -> i32 {
    30
}

fn default_cert_critical_days() -> i32 {
    7
}

fn default_topology_type() -> TopologyType {
    TopologyType::SingleVm
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

impl Default for GlobalSettings {
    fn default() -> Self {
        Self {
            management_port: 9443,
            log_level: "info".to_string(),
            default_health_check_interval_s: 10,
            cert_warning_days: 30,
            cert_critical_days: 7,
            default_topology_type: TopologyType::SingleVm,
            max_active_probes: 50,
            loadtest_max_concurrency: 100,
            loadtest_max_duration_s: 60,
            loadtest_max_rps: 1000,
            flood_threshold_rps: 0,
            custom_security_presets: Vec::new(),
        }
    }
}

// --- SLA Models ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaConfig {
    pub route_id: String,
    pub target_pct: f64,
    pub max_latency_ms: i64,
    pub success_status_min: i32,
    pub success_status_max: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SlaConfig {
    pub fn default_for_route(route_id: &str) -> Self {
        let now = Utc::now();
        Self {
            route_id: route_id.to_string(),
            target_pct: 99.9,
            max_latency_ms: 500,
            success_status_min: 200,
            success_status_max: 499,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn is_success(&self, status: u16, latency_ms: u64) -> bool {
        let status_ok = (status as i32) >= self.success_status_min
            && (status as i32) <= self.success_status_max;
        let latency_ok = (latency_ms as i64) <= self.max_latency_ms;
        status_ok && latency_ok
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaBucket {
    pub id: Option<i64>,
    pub route_id: String,
    pub bucket_start: DateTime<Utc>,
    pub request_count: i64,
    pub success_count: i64,
    pub error_count: i64,
    pub latency_sum_ms: i64,
    pub latency_min_ms: i64,
    pub latency_max_ms: i64,
    pub latency_p50_ms: i64,
    pub latency_p95_ms: i64,
    pub latency_p99_ms: i64,
    pub source: String,
    /// Snapshot of SLA config active when this bucket was recorded.
    /// Ensures historical reporting stays consistent after config changes.
    #[serde(default = "default_cfg_max_latency")]
    pub cfg_max_latency_ms: i64,
    #[serde(default = "default_cfg_status_min")]
    pub cfg_status_min: i32,
    #[serde(default = "default_cfg_status_max")]
    pub cfg_status_max: i32,
    #[serde(default = "default_cfg_target_pct")]
    pub cfg_target_pct: f64,
}

fn default_cfg_max_latency() -> i64 {
    500
}
fn default_cfg_status_min() -> i32 {
    200
}
fn default_cfg_status_max() -> i32 {
    399
}
fn default_cfg_target_pct() -> f64 {
    99.9
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaSummary {
    pub route_id: String,
    pub window: String,
    pub total_requests: i64,
    pub successful_requests: i64,
    pub sla_pct: f64,
    pub avg_latency_ms: f64,
    pub p50_latency_ms: i64,
    pub p95_latency_ms: i64,
    pub p99_latency_ms: i64,
    pub target_pct: f64,
    pub meets_target: bool,
}

// --- Probe Models ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeConfig {
    pub id: String,
    pub route_id: String,
    pub method: String,
    pub path: String,
    pub expected_status: i32,
    pub interval_s: i32,
    pub timeout_ms: i32,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// --- Load Test Models ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestConfig {
    pub id: String,
    pub name: String,
    pub target_url: String,
    pub method: String,
    pub headers: std::collections::HashMap<String, String>,
    pub body: Option<String>,
    pub concurrency: i32,
    pub requests_per_second: i32,
    pub duration_s: i32,
    pub error_threshold_pct: f64,
    pub schedule_cron: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Default safe limits for load tests.
pub const SAFE_LIMIT_CONCURRENCY: i32 = 100;
pub const SAFE_LIMIT_DURATION_S: i32 = 60;
pub const SAFE_LIMIT_RPS: i32 = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestResult {
    pub id: String,
    pub config_id: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub total_requests: i64,
    pub successful_requests: i64,
    pub failed_requests: i64,
    pub avg_latency_ms: f64,
    pub p50_latency_ms: i64,
    pub p95_latency_ms: i64,
    pub p99_latency_ms: i64,
    pub min_latency_ms: i64,
    pub max_latency_ms: i64,
    pub throughput_rps: f64,
    pub aborted: bool,
    pub abort_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestComparison {
    pub current: LoadTestResult,
    pub previous: Option<LoadTestResult>,
    pub latency_delta_pct: Option<f64>,
    pub throughput_delta_pct: Option<f64>,
}

#[cfg(test)]
mod tests {
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
            assert_eq!(s.parse::<LoadBalancing>().unwrap(), variant);
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
            assert_eq!(s.parse::<WafMode>().unwrap(), variant);
            assert_eq!(variant.as_str(), s);
        }
    }

    #[test]
    fn test_waf_mode_unknown() {
        assert!("permissive".parse::<WafMode>().is_err());
    }

    // ---- TopologyType ----

    #[test]
    fn test_topology_type_round_trip() {
        for (s, variant) in [
            ("single_vm", TopologyType::SingleVm),
            ("ha", TopologyType::Ha),
            ("docker_swarm", TopologyType::DockerSwarm),
            ("kubernetes", TopologyType::Kubernetes),
            ("custom", TopologyType::Custom),
        ] {
            assert_eq!(s.parse::<TopologyType>().unwrap(), variant);
            assert_eq!(variant.as_str(), s);
        }
    }

    #[test]
    fn test_topology_type_unknown() {
        assert!("bare_metal".parse::<TopologyType>().is_err());
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
            assert_eq!(s.parse::<HealthStatus>().unwrap(), variant);
            assert_eq!(variant.as_str(), s);
        }
    }

    #[test]
    fn test_health_status_unknown() {
        assert_eq!(
            "unknown".parse::<HealthStatus>().unwrap(),
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
            assert_eq!(s.parse::<LifecycleState>().unwrap(), variant);
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
        ] {
            assert_eq!(s.parse::<NotificationChannel>().unwrap(), variant);
            assert_eq!(variant.as_str(), s);
        }
    }

    #[test]
    fn test_notification_channel_unknown() {
        assert!("slack".parse::<NotificationChannel>().is_err());
    }

    // ---- PreferenceValue ----

    #[test]
    fn test_preference_value_round_trip() {
        for (s, variant) in [
            ("never", PreferenceValue::Never),
            ("always", PreferenceValue::Always),
            ("once", PreferenceValue::Once),
        ] {
            assert_eq!(s.parse::<PreferenceValue>().unwrap(), variant);
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
        let json = serde_json::to_string(&settings).unwrap();
        let deserialized: GlobalSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.management_port, settings.management_port);
        assert_eq!(deserialized.log_level, settings.log_level);
    }

    #[test]
    fn test_global_settings_cert_day_defaults_on_missing() {
        let json =
            r#"{"management_port":9443,"log_level":"info","default_health_check_interval_s":10}"#;
        let settings: GlobalSettings = serde_json::from_str(json).unwrap();
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
        let settings: GlobalSettings = serde_json::from_str(json).unwrap();
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
        let strict = presets.iter().find(|p| p.name == "strict").unwrap();
        assert!(strict.headers.contains_key("Strict-Transport-Security"));
        assert!(strict.headers.contains_key("X-Frame-Options"));
        assert!(strict.headers.contains_key("Content-Security-Policy"));
        assert!(strict.headers.contains_key("Permissions-Policy"));
        assert_eq!(strict.headers["X-Frame-Options"], "DENY");
    }

    #[test]
    fn test_builtin_moderate_preset_has_expected_headers() {
        let presets = builtin_security_presets();
        let moderate = presets.iter().find(|p| p.name == "moderate").unwrap();
        assert!(moderate.headers.contains_key("X-Content-Type-Options"));
        assert!(moderate.headers.contains_key("Strict-Transport-Security"));
        assert_eq!(moderate.headers["X-Frame-Options"], "SAMEORIGIN");
    }

    #[test]
    fn test_builtin_none_preset_is_empty() {
        let presets = builtin_security_presets();
        let none = presets.iter().find(|p| p.name == "none").unwrap();
        assert!(none.headers.is_empty());
    }

    #[test]
    fn test_resolve_security_preset_finds_by_name() {
        let presets = builtin_security_presets();
        let found = resolve_security_preset("strict", &presets);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "strict");
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
            "topology_type": "single_vm",
            "enabled": true,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z"
        }"#;
        let route: Route = serde_json::from_str(json).unwrap();
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
        let settings: GlobalSettings = serde_json::from_str(json).unwrap();
        assert_eq!(settings.max_active_probes, 50);
        assert_eq!(settings.loadtest_max_concurrency, 100);
        assert_eq!(settings.loadtest_max_duration_s, 60);
        assert_eq!(settings.loadtest_max_rps, 1000);
        assert_eq!(settings.default_topology_type, TopologyType::SingleVm);
    }

    #[test]
    fn test_security_header_preset_serde_round_trip() {
        let preset = SecurityHeaderPreset {
            name: "custom".to_string(),
            headers: HashMap::from([("X-Custom".to_string(), "value".to_string())]),
        };
        let json = serde_json::to_string(&preset).unwrap();
        let deserialized: SecurityHeaderPreset = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "custom");
        assert_eq!(deserialized.headers["X-Custom"], "value");
    }
}
