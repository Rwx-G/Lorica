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
    LeastConn,
}

impl LoadBalancing {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RoundRobin => "round_robin",
            Self::ConsistentHash => "consistent_hash",
            Self::Random => "random",
            Self::PeakEwma => "peak_ewma",
            Self::LeastConn => "least_conn",
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
            "least_conn" => Ok(Self::LeastConn),
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
    Slack,
}

impl NotificationChannel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Webhook => "webhook",
            Self::Slack => "slack",
        }
    }
}

impl FromStr for NotificationChannel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "email" => Ok(Self::Email),
            "webhook" => Ok(Self::Webhook),
            "slack" => Ok(Self::Slack),
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
#[serde(rename_all = "snake_case")]
pub enum PathMatchType {
    #[default]
    Prefix,
    Exact,
}

impl PathMatchType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Prefix => "prefix",
            Self::Exact => "exact",
        }
    }
}

impl FromStr for PathMatchType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "prefix" => Ok(Self::Prefix),
            "exact" => Ok(Self::Exact),
            other => Err(format!("unknown path match type: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathRule {
    pub path: String,
    #[serde(default)]
    pub match_type: PathMatchType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_ttl_s: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_headers: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_headers_remove: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_rps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_burst: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_status: Option<u16>,
}

impl PathRule {
    pub fn matches(&self, request_path: &str) -> bool {
        match self.match_type {
            PathMatchType::Prefix => request_path.starts_with(&self.path),
            PathMatchType::Exact => request_path == self.path,
        }
    }
}

/// Match semantics for a [`HeaderRule`].
///
/// `Regex` is compiled at route-load time; a malformed regex produces a
/// warning and disables the rule rather than failing the whole reload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HeaderMatchType {
    #[default]
    Exact,
    Prefix,
    Regex,
}

impl HeaderMatchType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Prefix => "prefix",
            Self::Regex => "regex",
        }
    }
}

impl FromStr for HeaderMatchType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "exact" => Ok(Self::Exact),
            "prefix" => Ok(Self::Prefix),
            "regex" => Ok(Self::Regex),
            other => Err(format!("unknown header match type: {other}")),
        }
    }
}

/// Route a request to a specific backend group based on one of its HTTP
/// request headers. Enables A/B testing (`X-Version: beta`), tenant
/// isolation (`X-Tenant: acme`), and similar content-negotiation-adjacent
/// patterns without changing upstream URLs.
///
/// Rules are evaluated in declaration order; first match wins. Header
/// names are matched case-insensitively as required by RFC 7230. An
/// empty `backend_ids` is allowed and means "match this rule but keep
/// the route's default backends" - useful when future fields (canary
/// split, headers override) extend this struct without requiring an
/// explicit backend set.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeaderRule {
    pub header_name: String,
    #[serde(default)]
    pub match_type: HeaderMatchType,
    pub value: String,
    #[serde(default)]
    pub backend_ids: Vec<String>,
}

impl HeaderRule {
    /// Test this rule against a single header value. The `regex_match`
    /// closure is invoked only for `HeaderMatchType::Regex` rules; the
    /// proxy engine passes a closure wrapping a precompiled `regex::Regex`,
    /// and tests that don't care about regex semantics can pass
    /// `|_| false`. `lorica-config` deliberately does not depend on the
    /// `regex` crate so the schema stays light.
    pub fn matches<F: FnOnce(&str) -> bool>(&self, value: &str, regex_match: F) -> bool {
        match self.match_type {
            HeaderMatchType::Exact => value == self.value,
            HeaderMatchType::Prefix => value.starts_with(&self.value),
            HeaderMatchType::Regex => regex_match(value),
        }
    }
}

/// Forward-authentication config: before proxying to upstream, issue a
/// sub-request to an external authentication service (Authelia,
/// Authentik, Keycloak, oauth2-proxy, ...) and honour its verdict.
///
/// Semantics (matches Traefik / Nginx `auth_request` / Caddy
/// `forward_auth` conventions):
///
/// - A `GET` request is sent to [`address`] with a standard header set
///   (Host as `X-Forwarded-Host`, client IP as `X-Forwarded-For`, the
///   original method and path as `X-Forwarded-Method`/`-Uri`, plus
///   cookies, `Authorization`, and `User-Agent` verbatim). These are
///   the five bits Authelia/Authentik need to identify the session and
///   make a decision.
/// - 2xx: the request is allowed to continue to the upstream. Any
///   header named in [`response_headers`] is copied from the auth
///   response into the upstream request (common: `Remote-User`,
///   `Remote-Groups`, `Remote-Email`).
/// - 401 / 403: denial is surfaced verbatim to the client, body and
///   headers included. Critical for Authelia's login-redirect flow.
/// - Timeout / connection error / unexpected status: fail closed with
///   503.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardAuthConfig {
    /// Absolute URL of the auth service endpoint (scheme + host +
    /// optional port + path). Example: `http://authelia.internal:9091/api/verify`.
    pub address: String,
    /// Per-sub-request timeout in milliseconds. Applies to the total
    /// round-trip (connect + response). Default 5000.
    #[serde(default = "default_forward_auth_timeout_ms")]
    pub timeout_ms: u32,
    /// Header names to copy from the auth service's 2xx response into
    /// the upstream request. Empty = do not copy any (default).
    #[serde(default)]
    pub response_headers: Vec<String>,
}

fn default_forward_auth_timeout_ms() -> u32 {
    5_000
}

/// Canary traffic split: send `weight_percent` of a route's requests to
/// a specific backend group, the rest fall through to the next split or
/// (if cumulative weights < 100) to the route's default backends.
///
/// Splits are evaluated in cumulative order with buckets assigned by
/// hashing the client IP together with the route ID:
///
/// ```text
///   splits = [A: 5%, B: 10%]
///   buckets = 0..=4 -> A, 5..=14 -> B, 15..=99 -> default
/// ```
///
/// Using the client IP (not a per-request random) makes the assignment
/// *sticky*: the same user stays on the same version across multiple
/// requests on the same route. Mixing the route ID prevents an unlucky
/// client from being in every service's canary bucket simultaneously
/// (which would happen if we hashed the IP alone).
///
/// Requests with no client IP - e.g. Unix-socket listeners used in
/// tests - skip the canary entirely and serve from the route defaults.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrafficSplit {
    /// Human-readable label; surfaced in dashboards and access logs.
    /// Optional but recommended so on-call can answer "which bucket?"
    /// at a glance.
    #[serde(default)]
    pub name: String,
    /// Percentage of eligible traffic that should hit this split.
    /// Valid range 0..=100. 0 is allowed (rule kept but inactive -
    /// useful while preparing a rollout).
    pub weight_percent: u8,
    /// Backends that serve this split. Must be non-empty for the split
    /// to actually divert traffic; an empty list means "match but do
    /// nothing" and is rejected by the API.
    #[serde(default)]
    pub backend_ids: Vec<String>,
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
    pub enabled: bool,
    #[serde(default)]
    pub force_https: bool,
    #[serde(default)]
    pub redirect_hostname: Option<String>,
    #[serde(default)]
    pub redirect_to: Option<String>,
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
    /// Regex pattern for path rewriting (e.g. `^/api/v1/(.*)`).
    /// Applied after strip/add prefix. Rust regex crate (linear time, ReDoS-safe).
    #[serde(default)]
    pub path_rewrite_pattern: Option<String>,
    /// Replacement string for regex rewrite (e.g. `/v2/$1`).
    #[serde(default)]
    pub path_rewrite_replacement: Option<String>,
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
    #[serde(default)]
    pub path_rules: Vec<PathRule>,
    #[serde(default)]
    pub return_status: Option<u16>,
    /// Enable cookie-based sticky sessions (session affinity).
    /// When enabled, a `LORICA_SRV` cookie is set with the backend ID.
    #[serde(default)]
    pub sticky_session: bool,
    #[serde(default)]
    pub basic_auth_username: Option<String>,
    #[serde(default)]
    pub basic_auth_password_hash: Option<String>,
    #[serde(default = "default_stale_while_revalidate_s")]
    pub stale_while_revalidate_s: i32,
    #[serde(default = "default_stale_if_error_s")]
    pub stale_if_error_s: i32,
    #[serde(default)]
    pub retry_on_methods: Vec<String>,
    #[serde(default)]
    pub maintenance_mode: bool,
    #[serde(default)]
    pub error_page_html: Option<String>,
    /// Request header names that partition the cache for this route.
    /// Each listed header contributes its value to a variance key so
    /// different values get separate cache entries (e.g.
    /// `["Accept-Encoding"]` keeps gzip and identity responses separate).
    /// Merged with any `Vary` header the origin returns.
    #[serde(default)]
    pub cache_vary_headers: Vec<String>,
    /// Header-based routing rules. Evaluated before path rules; first match
    /// selects `matched_backends`. A later path rule with its own
    /// `backend_ids` overrides the header rule's selection.
    #[serde(default)]
    pub header_rules: Vec<HeaderRule>,
    /// Canary traffic splits. Evaluated AFTER header rules (header rules
    /// are explicit opt-in and should win) and BEFORE path rules (path
    /// rules are URL-specific and should win).
    #[serde(default)]
    pub traffic_splits: Vec<TrafficSplit>,
    /// Forward-auth config. When set, every request on this route is
    /// gated by a sub-request to the configured auth service. Evaluated
    /// after route match but before any backend selection, so a denied
    /// request never touches the upstream.
    #[serde(default)]
    pub forward_auth: Option<ForwardAuthConfig>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Route {
    pub fn with_path_rule_overrides(&self, rule: &PathRule) -> Route {
        let mut r = self.clone();
        if let Some(ref h) = rule.response_headers {
            r.response_headers = h.clone();
        }
        if let Some(ref h) = rule.response_headers_remove {
            r.response_headers_remove = h.clone();
        }
        if let Some(v) = rule.cache_enabled {
            r.cache_enabled = v;
        }
        if let Some(v) = rule.cache_ttl_s {
            r.cache_ttl_s = v;
        }
        if let Some(v) = rule.rate_limit_rps {
            r.rate_limit_rps = Some(v);
        }
        if let Some(v) = rule.rate_limit_burst {
            r.rate_limit_burst = Some(v);
        }
        if rule.redirect_to.is_some() {
            r.redirect_to = rule.redirect_to.clone();
        }
        if rule.return_status.is_some() {
            r.return_status = rule.return_status;
        }
        r
    }
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
    /// Skip TLS certificate verification when connecting to this backend.
    /// Use for self-signed certificates. Default false.
    #[serde(default)]
    pub tls_skip_verify: bool,
    /// Override the SNI sent to this backend during TLS handshake.
    /// When empty, the route hostname is used instead.
    #[serde(default)]
    pub tls_sni: Option<String>,
    /// Force HTTP/2 when connecting to this backend (h2c for plaintext,
    /// ALPN h2 for TLS). Default false (HTTP/1.1).
    #[serde(default)]
    pub h2_upstream: bool,
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
    /// ACME provisioning method: "http01", "dns01-ovh", "dns01-cloudflare",
    /// "dns01-route53", "dns01-manual". None for non-ACME certificates.
    #[serde(default)]
    pub acme_method: Option<String>,
    /// Reference to a global DNS provider (dns_providers.id).
    #[serde(default)]
    pub acme_dns_provider_id: Option<String>,
}

/// A global DNS provider with encrypted credentials.
///
/// Instead of storing DNS credentials on each certificate, providers are
/// configured once and referenced by ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProvider {
    pub id: String,
    /// User-friendly name (e.g. "OVH rwx-g.fr").
    pub name: String,
    /// Provider type: "ovh", "cloudflare", "route53".
    pub provider_type: String,
    /// Encrypted JSON with provider credentials.
    pub config: String,
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
    /// Whether automatic SLA data purge is enabled. Default: false.
    #[serde(default)]
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
}

fn default_security_headers() -> String {
    "moderate".to_string()
}

fn default_stale_while_revalidate_s() -> i32 {
    10
}

fn default_stale_if_error_s() -> i32 {
    60
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

fn default_waf_ban_threshold() -> i32 {
    3
}

fn default_waf_ban_duration_s() -> i32 {
    3600
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

fn default_sla_purge_retention_days() -> i32 {
    90
}

fn default_sla_purge_schedule() -> String {
    "first_of_month".to_string()
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
            sla_purge_enabled: false,
            sla_purge_retention_days: default_sla_purge_retention_days(),
            sla_purge_schedule: default_sla_purge_schedule(),
            trusted_proxies: Vec::new(),
            waf_whitelist_ips: Vec::new(),
            connection_deny_cidrs: Vec::new(),
            connection_allow_cidrs: Vec::new(),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResultRow {
    pub id: i64,
    pub probe_id: String,
    pub route_id: String,
    pub status_code: u16,
    pub latency_ms: u64,
    pub success: bool,
    pub error: Option<String>,
    pub executed_at: String,
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
            ("slack", NotificationChannel::Slack),
        ] {
            assert_eq!(s.parse::<NotificationChannel>().unwrap(), variant);
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

    // ---- PathMatchType ----

    #[test]
    fn test_path_match_type_round_trip() {
        for (s, variant) in [
            ("prefix", PathMatchType::Prefix),
            ("exact", PathMatchType::Exact),
        ] {
            assert_eq!(s.parse::<PathMatchType>().unwrap(), variant);
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
}
