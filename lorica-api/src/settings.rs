//! Global settings, notification channels, and per-user UI preferences endpoints.

use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::db::{db_blocking, log_db_blocking};
use crate::error::{json_data, json_data_with_status, ApiError};
use crate::middleware::auth::Session;
use crate::server::AppState;

// ---- Settings field bounds (single source of truth) ----
//
// Story 8.10 AC #7. These constants are the ONLY place the numeric
// ranges and enum choice sets for the operator-tunable global settings
// are declared. Both `update_settings` (the validator) and
// `settings_schema` (the `GET /api/v1/settings/schema` payload) read
// them, so the enforced bound and the advertised bound cannot drift.
// Defaults are read from `GlobalSettings::default()` for the same
// reason.

const HEALTH_MAX_CONCURRENT_PROBES_MIN: i32 = 1;
const HEALTH_MAX_CONCURRENT_PROBES_MAX: i32 = 512;
const DEFAULT_HEALTH_CHECK_INTERVAL_S_MIN: i32 = 1;
const CERT_WARNING_DAYS_MIN: i32 = 1;
const CERT_CRITICAL_DAYS_MIN: i32 = 1;
const MAX_GLOBAL_CONNECTIONS_MIN: i32 = 0;
const FLOOD_THRESHOLD_RPS_MIN: i32 = 0;
const FLOOD_STRICT_RPS_MIN: u32 = 0;
const FLOOD_STRICT_RPS_MAX: u32 = 10_000_000;
const HEADER_TIMEOUT_S_MIN: u32 = 0;
const HEADER_TIMEOUT_S_MAX: u32 = 3600;
const WAF_BAN_THRESHOLD_MIN: i32 = 0;
const WAF_BAN_DURATION_S_MIN: i32 = 0;
const ACCESS_LOG_RETENTION_MIN: i64 = 0;
const WAF_EVENT_RETENTION_MIN: i64 = 0;
const SLA_PURGE_RETENTION_DAYS_MIN: i32 = 1;
const SLA_PURGE_RETENTION_DAYS_MAX: i32 = 3650;
const OTLP_SAMPLING_RATIO_MIN: f64 = 0.0;
const OTLP_SAMPLING_RATIO_MAX: f64 = 1.0;
const CERT_EXPORT_MODE_MAX: u32 = 0o777;
const MANAGEMENT_PORT_MAX: u16 = u16::MAX;

const LOG_LEVEL_CHOICES: [&str; 5] = ["trace", "debug", "info", "warn", "error"];
const OTLP_PROTOCOL_CHOICES: [&str; 3] = ["grpc", "http-proto", "http-json"];
const SPOOFED_FALLBACK_CHOICES: [&str; 3] = ["deny", "log", "allow"];
const SYSLOG_TRANSPORT_CHOICES: [&str; 3] = ["udp", "tcp", "tcp-tls"];
const SYSLOG_FACILITY_MAX: u32 = 23;
const SYSLOG_SEVERITY_MAX: u32 = 7;

/// Build the machine-readable settings schema (Story 8.10 AC #7).
///
/// Returns a JSON object keyed by field name; each value carries a
/// `type` (`"integer"` / `"number"` / `"boolean"` / `"string"` /
/// `"enum"`), optional numeric `min` / `max`, a `default`, and, for
/// enum fields, the `choices` array. Numeric bounds come from the
/// shared `*_MIN` / `*_MAX` constants that `update_settings` enforces;
/// defaults come from [`GlobalSettings::default`]. Fields whose
/// validator only enforces a lower bound omit `max` (the server sets
/// no ceiling; the dashboard supplies a UI-only cap).
///
/// # Examples
///
/// ```
/// let schema = lorica_api::settings::settings_schema();
/// assert_eq!(schema["header_timeout_s"]["max"], 3600);
/// ```
pub fn settings_schema() -> serde_json::Value {
    let d: lorica_config::models::GlobalSettings = lorica_config::models::GlobalSettings::default();
    serde_json::json!({
        "management_port": {
            "type": "integer",
            "min": 0,
            "max": MANAGEMENT_PORT_MAX,
            "default": d.management_port,
        },
        "log_level": {
            "type": "enum",
            "choices": LOG_LEVEL_CHOICES,
            "default": d.log_level,
        },
        "default_health_check_interval_s": {
            "type": "integer",
            "min": DEFAULT_HEALTH_CHECK_INTERVAL_S_MIN,
            "default": d.default_health_check_interval_s,
        },
        "health_max_concurrent_probes": {
            "type": "integer",
            "min": HEALTH_MAX_CONCURRENT_PROBES_MIN,
            "max": HEALTH_MAX_CONCURRENT_PROBES_MAX,
            "default": d.health_max_concurrent_probes,
        },
        "cert_warning_days": {
            "type": "integer",
            "min": CERT_WARNING_DAYS_MIN,
            "default": d.cert_warning_days,
        },
        "cert_critical_days": {
            "type": "integer",
            "min": CERT_CRITICAL_DAYS_MIN,
            "default": d.cert_critical_days,
        },
        "max_global_connections": {
            "type": "integer",
            "min": MAX_GLOBAL_CONNECTIONS_MIN,
            "default": d.max_global_connections,
        },
        "flood_threshold_rps": {
            "type": "integer",
            "min": FLOOD_THRESHOLD_RPS_MIN,
            "default": d.flood_threshold_rps,
        },
        "flood_strict_rps": {
            "type": "integer",
            "min": FLOOD_STRICT_RPS_MIN,
            "max": FLOOD_STRICT_RPS_MAX,
            "default": d.flood_strict_rps,
        },
        "header_timeout_s": {
            "type": "integer",
            "min": HEADER_TIMEOUT_S_MIN,
            "max": HEADER_TIMEOUT_S_MAX,
            "default": d.header_timeout_s,
        },
        "waf_ban_threshold": {
            "type": "integer",
            "min": WAF_BAN_THRESHOLD_MIN,
            "default": d.waf_ban_threshold,
        },
        "waf_ban_duration_s": {
            "type": "integer",
            "min": WAF_BAN_DURATION_S_MIN,
            "default": d.waf_ban_duration_s,
        },
        "access_log_retention": {
            "type": "integer",
            "min": ACCESS_LOG_RETENTION_MIN,
            "default": d.access_log_retention,
        },
        "waf_event_retention": {
            "type": "integer",
            "min": WAF_EVENT_RETENTION_MIN,
            "default": d.waf_event_retention,
        },
        "sla_purge_enabled": {
            "type": "boolean",
            "default": d.sla_purge_enabled,
        },
        "sla_purge_retention_days": {
            "type": "integer",
            "min": SLA_PURGE_RETENTION_DAYS_MIN,
            "max": SLA_PURGE_RETENTION_DAYS_MAX,
            "default": d.sla_purge_retention_days,
        },
        "otlp_protocol": {
            "type": "enum",
            "choices": OTLP_PROTOCOL_CHOICES,
            "default": d.otlp_protocol,
        },
        "otlp_sampling_ratio": {
            "type": "number",
            "min": OTLP_SAMPLING_RATIO_MIN,
            "max": OTLP_SAMPLING_RATIO_MAX,
            "default": d.otlp_sampling_ratio,
        },
        "cert_export_file_mode": {
            "type": "integer",
            "min": 0,
            "max": CERT_EXPORT_MODE_MAX,
            "default": d.cert_export_file_mode,
        },
        "cert_export_dir_mode": {
            "type": "integer",
            "min": 0,
            "max": CERT_EXPORT_MODE_MAX,
            "default": d.cert_export_dir_mode,
        },
        "ai_bot_treat_spoofed_as": {
            "type": "enum",
            "choices": SPOOFED_FALLBACK_CHOICES,
            "default": d.ai_bot_treat_spoofed_as,
        },
        "syslog_transport": {
            "type": "enum",
            "choices": SYSLOG_TRANSPORT_CHOICES,
            "default": d.syslog_transport,
        },
        "syslog_facility": {
            "type": "integer",
            "min": 0,
            "max": SYSLOG_FACILITY_MAX,
            "default": d.syslog_facility,
        },
        "syslog_severity_access": {
            "type": "integer",
            "min": 0,
            "max": SYSLOG_SEVERITY_MAX,
            "default": d.syslog_severity_access,
        },
        "syslog_severity_waf": {
            "type": "integer",
            "min": 0,
            "max": SYSLOG_SEVERITY_MAX,
            "default": d.syslog_severity_waf,
        },
        "syslog_severity_audit": {
            "type": "integer",
            "min": 0,
            "max": SYSLOG_SEVERITY_MAX,
            "default": d.syslog_severity_audit,
        },
    })
}

/// GET /api/v1/settings/schema - return the operator-tunable global
/// settings field bounds (Story 8.10 AC #7).
///
/// Read-only metadata; no store access. Gated like `GET /settings`
/// (Viewer+) by the authorize middleware since the path falls under
/// the GET/HEAD Viewer default before the settings-write SuperAdmin
/// overlay. The dashboard consumes this to render input constraints
/// instead of hardcoding them.
pub async fn get_settings_schema() -> Json<serde_json::Value> {
    json_data(settings_schema())
}

// ---- Global Settings ----

/// GET /api/v1/settings - return the global settings document.
///
/// `bot_hmac_secret_hex` is scrubbed before serialisation (v1.5.1
/// audit H-1). The field's own doc on `GlobalSettings` claims this
/// scrub was already in place ; it was not. A leaked hex secret is
/// equivalent to a forgeable bot-protection cookie for every IP
/// across every route until the next certificate renewal rotates it.
///
/// Three-state output (H-1 followup) so a consumer can tell apart
/// "secret never initialised" from "secret in place but masked" :
///
/// - `""` (empty string) - secret has not been generated yet
///   (fresh boot, or import of a historical export with the field
///   already empty). The next reload will populate it.
/// - `"**REDACTED**"` (the same sentinel the TOML exporter uses)
///   - secret is set in the store but withheld from the response.
///
/// The actual hex value is never returned by this endpoint and
/// `UpdateSettingsRequest` does not expose a write path either,
/// so the secret stays inside the store + cookie-signing code.
pub async fn get_settings(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut settings = db_blocking(&state.store, move |store| store.get_global_settings()).await?;
    mask_settings_secrets(&mut settings);
    Ok(json_data(settings))
}

/// Replace every secret field of a settings row with the
/// `**REDACTED**` sentinel before serialisation. Applied by BOTH the
/// GET and the PUT response paths: the PUT handler used to return the
/// merged row unmasked, handing the raw bot HMAC secret / scrape
/// token / syslog client key / OTLP auth header back to the caller on
/// every save (QA finding, CWE-200). The write path treats the
/// sentinel as "leave unchanged", so a masked value round-trips
/// safely.
///
/// `bot_hmac_secret_hex` keeps its three-state contract (v1.5.1 audit
/// H-1): empty = never initialised, sentinel = set but withheld.
fn mask_settings_secrets(settings: &mut lorica_config::models::GlobalSettings) {
    settings.bot_hmac_secret_hex = if settings.bot_hmac_secret_hex.is_empty() {
        String::new()
    } else {
        "**REDACTED**".to_string()
    };
    // Story 8.8 AC #4: a leaked scrape token grants unauthenticated
    // /metrics access when metrics_require_auth is on. `None` stays
    // `None`, a configured value becomes the sentinel.
    settings.prometheus_scrape_token = settings
        .prometheus_scrape_token
        .as_ref()
        .map(|_| "**REDACTED**".to_string());
    // Story 9.8 AC #8: log-sink secrets get the same treatment.
    settings.syslog_tls_client_key_pem = settings
        .syslog_tls_client_key_pem
        .as_ref()
        .map(|_| "**REDACTED**".to_string());
    settings.otlp_logs_auth_header = settings
        .otlp_logs_auth_header
        .as_ref()
        .map(|_| "**REDACTED**".to_string());
}

/// JSON body for `PUT /api/v1/settings`. Only the supplied fields are
/// mutated ; each field mirrors the matching
/// [`lorica_config::models::GlobalSettings`] key.
///
/// `Serialize` exists solely for the audit-log payload hash (Story
/// 8.9): the request body carries no secret (there is no write path
/// for `bot_hmac_secret_hex`), unlike the full `GlobalSettings` row.
#[derive(Deserialize, Serialize)]
pub struct UpdateSettingsRequest {
    /// Management API TCP port.
    pub management_port: Option<u16>,
    /// `tracing` subscriber filter.
    pub log_level: Option<String>,
    /// Fallback health-check interval (s).
    pub default_health_check_interval_s: Option<i32>,
    /// Cap on concurrent backend health-check probes.
    pub health_max_concurrent_probes: Option<i32>,
    /// Cert expiry warning threshold (days).
    pub cert_warning_days: Option<i32>,
    /// Cert expiry critical threshold (days).
    pub cert_critical_days: Option<i32>,
    /// Hard cap on global concurrent connections (0 = unlimited).
    pub max_global_connections: Option<i32>,
    /// Proxy-wide flood threshold (RPS).
    pub flood_threshold_rps: Option<i32>,
    /// Per-IP admission rate enforced during flood mode (Story 8.10
    /// AC #2). `0` = auto (`flood_threshold_rps / 2`).
    pub flood_strict_rps: Option<u32>,
    /// Global header-phase read timeout in seconds (Story 8.10 AC #1).
    pub header_timeout_s: Option<u32>,
    /// Number of WAF blocks before auto-ban.
    pub waf_ban_threshold: Option<i32>,
    /// WAF auto-ban duration (s).
    pub waf_ban_duration_s: Option<i32>,
    /// Retention cap on the persistent access-log buffer.
    pub access_log_retention: Option<i64>,
    /// Retention cap on the persistent WAF-event buffer.
    pub waf_event_retention: Option<i64>,
    /// Toggle the periodic SLA bucket purge.
    pub sla_purge_enabled: Option<bool>,
    /// SLA bucket retention window (days).
    pub sla_purge_retention_days: Option<i32>,
    /// Purge schedule (`"first_of_month"`, `"daily"`, or day number).
    pub sla_purge_schedule: Option<String>,
    /// Operator-defined security-header presets.
    pub custom_security_presets: Option<Vec<lorica_config::models::SecurityHeaderPreset>>,
    /// CIDRs of trusted reverse proxies (XFF parsing gate).
    pub trusted_proxies: Option<Vec<String>>,
    /// IPs / CIDRs that bypass WAF + rate-limit + auto-ban.
    pub waf_whitelist_ips: Option<Vec<String>>,
    /// CIDRs denied at TCP accept time.
    pub connection_deny_cidrs: Option<Vec<String>>,
    /// CIDRs allowed at TCP accept time (default-deny when non-empty).
    pub connection_allow_cidrs: Option<Vec<String>>,
    /// OTLP collector endpoint URL.
    pub otlp_endpoint: Option<String>,
    /// OTLP transport protocol (`grpc` / `http-proto` / `http-json`).
    pub otlp_protocol: Option<String>,
    /// OTel `service.name` attribute.
    pub otlp_service_name: Option<String>,
    /// Head sampler ratio (0.0..=1.0).
    pub otlp_sampling_ratio: Option<f64>,
    /// Filesystem path to the GeoIP `.mmdb`.
    pub geoip_db_path: Option<String>,
    /// Whether Lorica auto-updates the GeoIP DB.
    pub geoip_auto_update_enabled: Option<bool>,
    /// Filesystem path to the ASN `.mmdb`.
    pub asn_db_path: Option<String>,
    /// Whether Lorica auto-updates the ASN DB.
    pub asn_auto_update_enabled: Option<bool>,
    /// Toggle filesystem cert export.
    pub cert_export_enabled: Option<bool>,
    /// Absolute path of the export directory.
    pub cert_export_dir: Option<String>,
    /// Owner uid applied to exported files.
    pub cert_export_owner_uid: Option<u32>,
    /// Group gid applied to exported files.
    pub cert_export_group_gid: Option<u32>,
    /// Octal file mode for exported `.pem` files.
    pub cert_export_file_mode: Option<u32>,
    /// Octal directory mode for the export root + per-hostname dirs.
    pub cert_export_dir_mode: Option<u32>,
    /// Story 8.2 AC #3. Default applied when an AI-bot crawler's
    /// verification (Rdns / IpRanges) fails. Per-route override
    /// available via `Route.ai_bot_spoofed_fallback`.
    pub ai_bot_treat_spoofed_as: Option<lorica_config::models::SpoofedFallback>,
    /// Story 8.2 AC #11. Inject `X-Lorica-Verified-Bot` +
    /// `X-Lorica-Bot-Verification` headers upstream on
    /// verification-confirmed AI-bot requests.
    pub ai_bot_inject_headers: Option<bool>,
    /// Story 8.4. Absolute path to the Ed25519 public key the
    /// hot-upgrade endpoint verifies uploaded binaries against. An
    /// empty (after trim) value clears it, disabling hot binary
    /// upgrade. Without this write path the operator could never
    /// configure a signing key and every upload returned 400.
    pub upgrade_signing_pubkey_path: Option<String>,
    /// Story 8.8 AC #4. Require auth on `/metrics`.
    pub metrics_require_auth: Option<bool>,
    /// Story 8.8 AC #4. Static bearer token accepted on `/metrics`.
    /// An empty (after trim) value clears the token. The masking
    /// sentinel `**REDACTED**` returned by `GET /settings` is treated
    /// as "leave unchanged" so a dashboard round-trip never clobbers
    /// the stored token.
    pub prometheus_scrape_token: Option<String>,
    /// Story 8.8 AC #2. Absolute path to the operator management-TLS
    /// certificate chain (PEM). Empty clears it.
    pub management_cert_pem_path: Option<String>,
    /// Story 8.8 AC #2. Absolute path to the operator management-TLS
    /// private key (PEM). Empty clears it.
    pub management_key_pem_path: Option<String>,
    /// Story 9.8 AC #1. Syslog collector `host:port`. Empty clears it
    /// (sink disabled).
    pub syslog_endpoint: Option<String>,
    /// Story 9.8 AC #1. Syslog transport (`udp` / `tcp` / `tcp-tls`).
    pub syslog_transport: Option<String>,
    /// Story 9.8 AC #1. RFC 5424 facility code (0-23).
    pub syslog_facility: Option<u32>,
    /// Story 9.8 AC #1. Severity for access-log messages (0-7).
    pub syslog_severity_access: Option<u32>,
    /// Story 9.8 AC #1. Severity for WAF-event messages (0-7).
    pub syslog_severity_waf: Option<u32>,
    /// Story 9.8 AC #1. Severity for audit messages (0-7).
    pub syslog_severity_audit: Option<u32>,
    /// Story 9.8 AC #1. Ship access logs to syslog.
    pub syslog_access_enabled: Option<bool>,
    /// Story 9.8 AC #1. Ship WAF events to syslog.
    pub syslog_waf_enabled: Option<bool>,
    /// Story 9.8 AC #1. Ship audit entries to syslog.
    pub syslog_audit_enabled: Option<bool>,
    /// Story 9.8 AC #1. PEM CA bundle trusted for `tcp-tls`. Empty
    /// clears it (platform trust store).
    pub syslog_tls_ca_pem: Option<String>,
    /// Story 9.8 AC #1. PEM client certificate chain for collector
    /// mTLS. Empty clears it.
    pub syslog_tls_client_cert_pem: Option<String>,
    /// Story 9.8 AC #8. PEM client key paired with the client
    /// certificate. Secret: empty clears, the `**REDACTED**` sentinel
    /// leaves the stored value unchanged.
    pub syslog_tls_client_key_pem: Option<String>,
    /// Story 9.8 AC #1. Extra static structured-data parameters as
    /// comma-separated `key=value` pairs. Empty clears.
    pub syslog_extra_sd: Option<String>,
    /// Story 9.8 AC #2. Export logs as OTLP log records to the
    /// `otlp_endpoint` collector (needs a binary built with
    /// `--features otel`).
    pub otlp_logs_enabled: Option<bool>,
    /// Story 9.8 AC #8. `Authorization` header for the OTLP logs
    /// exporter. Secret: empty clears, `**REDACTED**` leaves
    /// unchanged.
    pub otlp_logs_auth_header: Option<String>,
}

/// PUT /api/v1/settings - patch the global settings document and trigger a proxy reload.
///
/// Field application order matters: it matches the historical inline
/// sequence so any future cross-field validation keeps seeing earlier
/// assignments. Bound inconsistencies inherited from that inline era
/// are kept on purpose (normalising them is a behaviour change) and
/// flagged with `// NOTE: bound drift` comments for the next audit.
pub async fn update_settings(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Json(body): Json<UpdateSettingsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Audit payload = the PATCH body (secret-free by construction),
    // never the resulting GlobalSettings row (carries
    // `bot_hmac_secret_hex`). Serialized before the closure consumes
    // the body; recorded only after the mutation succeeds.
    let audit_after = serde_json::to_value(&body).ok();
    // The whole get -> validate/assign -> update sequence is sync and
    // runs in one closure on the blocking pool; the store mutex hold
    // window is unchanged.
    let settings = db_blocking(&state.store, move |store| {
        let mut settings = store.get_global_settings()?;

        // NOTE: bound drift - no validation; port 0 is accepted.
        apply_plain(body.management_port, &mut settings.management_port);
        apply_string_choice(
            body.log_level,
            &mut settings.log_level,
            &LOG_LEVEL_CHOICES,
            "log_level",
        )?;
        // NOTE: bound drift - lower bound only, no upper cap unlike
        // health_max_concurrent_probes.
        apply_min_i32(
            body.default_health_check_interval_s,
            &mut settings.default_health_check_interval_s,
            DEFAULT_HEALTH_CHECK_INTERVAL_S_MIN,
            "default_health_check_interval_s",
        )?;
        apply_ranged_i32(
            body.health_max_concurrent_probes,
            &mut settings.health_max_concurrent_probes,
            HEALTH_MAX_CONCURRENT_PROBES_MIN..=HEALTH_MAX_CONCURRENT_PROBES_MAX,
            &format!(
                "health_max_concurrent_probes must be in {HEALTH_MAX_CONCURRENT_PROBES_MIN}..={HEALTH_MAX_CONCURRENT_PROBES_MAX}"
            ),
        )?;
        // NOTE: bound drift - cert thresholds have no upper bound and
        // no warning > critical cross-check.
        apply_min_i32(
            body.cert_warning_days,
            &mut settings.cert_warning_days,
            CERT_WARNING_DAYS_MIN,
            "cert_warning_days",
        )?;
        apply_min_i32(
            body.cert_critical_days,
            &mut settings.cert_critical_days,
            CERT_CRITICAL_DAYS_MIN,
            "cert_critical_days",
        )?;
        apply_min_i32(
            body.max_global_connections,
            &mut settings.max_global_connections,
            MAX_GLOBAL_CONNECTIONS_MIN,
            "max_global_connections",
        )?;
        apply_min_i32(
            body.flood_threshold_rps,
            &mut settings.flood_threshold_rps,
            FLOOD_THRESHOLD_RPS_MIN,
            "flood_threshold_rps",
        )?;
        // Story 8.10 AC #2. `0` is accepted and means "auto"
        // (`flood_threshold_rps / 2`), resolved at enforcement time.
        apply_ranged_u32(
            body.flood_strict_rps,
            &mut settings.flood_strict_rps,
            FLOOD_STRICT_RPS_MIN..=FLOOD_STRICT_RPS_MAX,
            &format!("flood_strict_rps must be in {FLOOD_STRICT_RPS_MIN}..={FLOOD_STRICT_RPS_MAX}"),
        )?;
        // Story 8.10 AC #1. `0` disables the global header-phase floor.
        apply_ranged_u32(
            body.header_timeout_s,
            &mut settings.header_timeout_s,
            HEADER_TIMEOUT_S_MIN..=HEADER_TIMEOUT_S_MAX,
            &format!("header_timeout_s must be in {HEADER_TIMEOUT_S_MIN}..={HEADER_TIMEOUT_S_MAX}"),
        )?;
        apply_min_i32(
            body.waf_ban_threshold,
            &mut settings.waf_ban_threshold,
            WAF_BAN_THRESHOLD_MIN,
            "waf_ban_threshold",
        )?;
        // NOTE: bound drift - 0 accepted (zero-duration ban), while the
        // interval fields above require >= 1.
        apply_min_i32(
            body.waf_ban_duration_s,
            &mut settings.waf_ban_duration_s,
            WAF_BAN_DURATION_S_MIN,
            "waf_ban_duration_s",
        )?;
        apply_min_i64(
            body.access_log_retention,
            &mut settings.access_log_retention,
            ACCESS_LOG_RETENTION_MIN,
            "access_log_retention",
        )?;
        apply_min_i64(
            body.waf_event_retention,
            &mut settings.waf_event_retention,
            WAF_EVENT_RETENTION_MIN,
            "waf_event_retention",
        )?;
        apply_plain(body.sla_purge_enabled, &mut settings.sla_purge_enabled);
        apply_ranged_i32(
            body.sla_purge_retention_days,
            &mut settings.sla_purge_retention_days,
            SLA_PURGE_RETENTION_DAYS_MIN..=SLA_PURGE_RETENTION_DAYS_MAX,
            &format!(
                "sla_purge_retention_days must be in {SLA_PURGE_RETENTION_DAYS_MIN}..={SLA_PURGE_RETENTION_DAYS_MAX} (10 years)"
            ),
        )?;
        apply_sla_purge_schedule(body.sla_purge_schedule, &mut settings.sla_purge_schedule)?;
        apply_plain(
            body.custom_security_presets,
            &mut settings.custom_security_presets,
        );
        apply_cidr_list(
            body.trusted_proxies,
            &mut settings.trusted_proxies,
            "trusted proxy",
        )?;
        apply_cidr_list(
            body.waf_whitelist_ips,
            &mut settings.waf_whitelist_ips,
            "WAF whitelist",
        )?;
        apply_cidr_list(
            body.connection_deny_cidrs,
            &mut settings.connection_deny_cidrs,
            "connection_deny_cidrs",
        )?;
        apply_cidr_list(
            body.connection_allow_cidrs,
            &mut settings.connection_allow_cidrs,
            "connection_allow_cidrs",
        )?;
        apply_otlp_endpoint(body.otlp_endpoint, &mut settings.otlp_endpoint)?;
        apply_string_choice(
            body.otlp_protocol,
            &mut settings.otlp_protocol,
            &OTLP_PROTOCOL_CHOICES,
            "otlp_protocol",
        )?;
        apply_otlp_service_name(body.otlp_service_name, &mut settings.otlp_service_name)?;
        apply_otlp_sampling_ratio(body.otlp_sampling_ratio, &mut settings.otlp_sampling_ratio)?;
        apply_optional_abs_path(body.geoip_db_path, &mut settings.geoip_db_path, "geoip_db_path")?;
        apply_plain(
            body.geoip_auto_update_enabled,
            &mut settings.geoip_auto_update_enabled,
        );
        apply_optional_abs_path(body.asn_db_path, &mut settings.asn_db_path, "asn_db_path")?;
        apply_plain(
            body.asn_auto_update_enabled,
            &mut settings.asn_auto_update_enabled,
        );
        apply_plain(body.cert_export_enabled, &mut settings.cert_export_enabled);
        apply_optional_abs_path(
            body.cert_export_dir,
            &mut settings.cert_export_dir,
            "cert_export_dir",
        )?;
        // NOTE: bound drift - uid/gid persisted without any range or
        // existence check.
        apply_plain(
            body.cert_export_owner_uid.map(Some),
            &mut settings.cert_export_owner_uid,
        );
        apply_plain(
            body.cert_export_group_gid.map(Some),
            &mut settings.cert_export_group_gid,
        );
        apply_mode_u32(
            body.cert_export_file_mode,
            &mut settings.cert_export_file_mode,
            "cert_export_file_mode",
        )?;
        apply_mode_u32(
            body.cert_export_dir_mode,
            &mut settings.cert_export_dir_mode,
            "cert_export_dir_mode",
        )?;
        // Story 8.2 AC #3 + AC #11. Serde-derive parsing on
        // `body.ai_bot_treat_spoofed_as` already validates the enum
        // tag ("deny" | "log" | "allow"), so both are passthrough.
        apply_plain(
            body.ai_bot_treat_spoofed_as,
            &mut settings.ai_bot_treat_spoofed_as,
        );
        apply_plain(body.ai_bot_inject_headers, &mut settings.ai_bot_inject_headers);
        // Story 8.4. Mirrors `geoip_db_path` plumbing: absolute-path
        // validation, empty string clears to None.
        apply_optional_abs_path(
            body.upgrade_signing_pubkey_path,
            &mut settings.upgrade_signing_pubkey_path,
            "upgrade_signing_pubkey_path",
        )?;
        // Story 8.8 AC #4 + AC #2.
        apply_plain(body.metrics_require_auth, &mut settings.metrics_require_auth);
        apply_secret_token(
            body.prometheus_scrape_token,
            &mut settings.prometheus_scrape_token,
        );
        apply_optional_abs_path(
            body.management_cert_pem_path,
            &mut settings.management_cert_pem_path,
            "management_cert_pem_path",
        )?;
        apply_optional_abs_path(
            body.management_key_pem_path,
            &mut settings.management_key_pem_path,
            "management_key_pem_path",
        )?;
        // Story 9.8: log-export sinks.
        apply_syslog_endpoint(body.syslog_endpoint, &mut settings.syslog_endpoint)?;
        apply_string_choice(
            body.syslog_transport,
            &mut settings.syslog_transport,
            &SYSLOG_TRANSPORT_CHOICES,
            "syslog_transport",
        )?;
        apply_ranged_u32(
            body.syslog_facility,
            &mut settings.syslog_facility,
            0..=SYSLOG_FACILITY_MAX,
            &format!("syslog_facility must be in 0..={SYSLOG_FACILITY_MAX}"),
        )?;
        apply_ranged_u32(
            body.syslog_severity_access,
            &mut settings.syslog_severity_access,
            0..=SYSLOG_SEVERITY_MAX,
            &format!("syslog_severity_access must be in 0..={SYSLOG_SEVERITY_MAX}"),
        )?;
        apply_ranged_u32(
            body.syslog_severity_waf,
            &mut settings.syslog_severity_waf,
            0..=SYSLOG_SEVERITY_MAX,
            &format!("syslog_severity_waf must be in 0..={SYSLOG_SEVERITY_MAX}"),
        )?;
        apply_ranged_u32(
            body.syslog_severity_audit,
            &mut settings.syslog_severity_audit,
            0..=SYSLOG_SEVERITY_MAX,
            &format!("syslog_severity_audit must be in 0..={SYSLOG_SEVERITY_MAX}"),
        )?;
        apply_plain(body.syslog_access_enabled, &mut settings.syslog_access_enabled);
        apply_plain(body.syslog_waf_enabled, &mut settings.syslog_waf_enabled);
        apply_plain(body.syslog_audit_enabled, &mut settings.syslog_audit_enabled);
        apply_optional_pem(
            body.syslog_tls_ca_pem,
            &mut settings.syslog_tls_ca_pem,
            "CERTIFICATE",
            "syslog_tls_ca_pem",
        )?;
        apply_optional_pem(
            body.syslog_tls_client_cert_pem,
            &mut settings.syslog_tls_client_cert_pem,
            "CERTIFICATE",
            "syslog_tls_client_cert_pem",
        )?;
        // Secret semantics (empty clears, sentinel leaves unchanged);
        // PEM shape is checked by the sink when it builds the TLS
        // connector, mirroring how the scrape token skips validation.
        apply_secret_token(
            body.syslog_tls_client_key_pem,
            &mut settings.syslog_tls_client_key_pem,
        );
        apply_syslog_extra_sd(body.syslog_extra_sd, &mut settings.syslog_extra_sd)?;
        apply_plain(body.otlp_logs_enabled, &mut settings.otlp_logs_enabled);
        apply_secret_token(body.otlp_logs_auth_header, &mut settings.otlp_logs_auth_header);

        // Cross-field invariants (backlog #48). Per-field bounds are applied
        // above; these reject a partial update that inverts a related pair
        // (e.g. cert warning <= critical) on the merged result.
        settings
            .validate_cross_fields()
            .map_err(ApiError::BadRequest)?;
        // Story 9.8 QA: validate syslog TLS material by building the
        // exact connector the sink will use, so a bad pasted PEM is a
        // 400 here instead of a permanently dead sink discovered one
        // warn-line later.
        let sinks = crate::log_sinks::LogSinksConfig::from_settings(&settings, false);
        if let Some(syslog_cfg) = &sinks.syslog {
            crate::log_sinks::syslog::validate_tls_config(syslog_cfg)
                .map_err(ApiError::BadRequest)?;
        }
        store.update_global_settings(&settings)?;
        Ok::<_, ApiError>(settings)
    })
    .await?;
    state.notify_config_changed();

    // Story 9.8 QA (CWE-319 advisory): the exported records carry the
    // audit trail, client IPs and WAF match excerpts; say so loudly
    // when they ride a cleartext transport. Mirrors the plaintext
    // `http://` warning on the OTLP endpoint.
    if settings.syslog_endpoint.is_some() && settings.syslog_transport != "tcp-tls" {
        tracing::warn!(
            transport = %settings.syslog_transport,
            "syslog export configured over a cleartext transport; \
             exported audit/access/WAF records are readable and \
             forgeable on-path - prefer tcp-tls"
        );
    }

    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &audit_ctx,
        "settings.update",
        ("settings", ""),
        None,
        audit_after.as_ref(),
    )
    .await;

    let mut settings = settings;
    mask_settings_secrets(&mut settings);
    Ok(json_data(settings))
}

// ---- update_settings field-application helpers ----
//
// Each helper implements one shape of the historical inline
// `if let Some(x) = body.x { <check>; settings.x = x; }` blocks.
// `None` always means "field absent from the PATCH body, leave the
// stored value untouched". Error messages are byte-identical to the
// pre-refactor inline strings; several are pinned by integration
// tests in `tests.rs`.

/// Assign `value` to `target` when present. No validation.
fn apply_plain<T>(value: Option<T>, target: &mut T) {
    if let Some(v) = value {
        *target = v;
    }
}

/// Assign an `i32` field when present, rejecting values below `min`
/// with `400 "<label> must be >= <min>"`.
fn apply_min_i32(
    value: Option<i32>,
    target: &mut i32,
    min: i32,
    label: &str,
) -> Result<(), ApiError> {
    if let Some(v) = value {
        if v < min {
            return Err(ApiError::BadRequest(format!("{label} must be >= {min}")));
        }
        *target = v;
    }
    Ok(())
}

/// `i64` variant of [`apply_min_i32`].
fn apply_min_i64(
    value: Option<i64>,
    target: &mut i64,
    min: i64,
    label: &str,
) -> Result<(), ApiError> {
    if let Some(v) = value {
        if v < min {
            return Err(ApiError::BadRequest(format!("{label} must be >= {min}")));
        }
        *target = v;
    }
    Ok(())
}

/// Assign an `i32` field when present, rejecting values outside
/// `range` with `400` and the caller-supplied `error_msg`. The full
/// message is passed in (rather than built from a label) because the
/// historical strings carry field-specific suffixes, e.g.
/// `"(10 years)"`.
fn apply_ranged_i32(
    value: Option<i32>,
    target: &mut i32,
    range: std::ops::RangeInclusive<i32>,
    error_msg: &str,
) -> Result<(), ApiError> {
    if let Some(v) = value {
        if !range.contains(&v) {
            return Err(ApiError::BadRequest(error_msg.to_string()));
        }
        *target = v;
    }
    Ok(())
}

/// `u32` variant of [`apply_ranged_i32`]. Used by the Story 8.10
/// settings (`flood_strict_rps`, `header_timeout_s`) which are `u32`
/// on `GlobalSettings`.
fn apply_ranged_u32(
    value: Option<u32>,
    target: &mut u32,
    range: std::ops::RangeInclusive<u32>,
    error_msg: &str,
) -> Result<(), ApiError> {
    if let Some(v) = value {
        if !range.contains(&v) {
            return Err(ApiError::BadRequest(error_msg.to_string()));
        }
        *target = v;
    }
    Ok(())
}

/// Assign a string field when present, rejecting values not in
/// `valid` with `400 "invalid <label>: <value>. Must be one of:
/// <valid:?>"`.
fn apply_string_choice(
    value: Option<String>,
    target: &mut String,
    valid: &[&str],
    label: &str,
) -> Result<(), ApiError> {
    if let Some(v) = value {
        if !valid.contains(&v.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "invalid {label}: {v}. Must be one of: {valid:?}"
            )));
        }
        *target = v;
    }
    Ok(())
}

/// Assign a CIDR/IP list field when present. Every non-empty entry
/// must parse as a bare IP (1.2.3.4) or CIDR (1.2.3.0/24); the first
/// invalid entry yields `400 "invalid <label> CIDR or IP: <entry>"`.
fn apply_cidr_list(
    value: Option<Vec<String>>,
    target: &mut Vec<String>,
    label: &str,
) -> Result<(), ApiError> {
    if let Some(cidrs) = value {
        validate_cidr_list(&cidrs, label)?;
        *target = cidrs;
    }
    Ok(())
}

/// Assign an optional secret string field (Story 8.8 AC #4 scrape
/// token). `None` leaves the stored value untouched. An empty (after
/// trim) value clears the secret to `None`. The masking sentinel the
/// `GET /settings` handler returns (`**REDACTED**`) is treated as
/// "leave unchanged" so a dashboard PUT that echoes the masked value
/// never overwrites the real token. Any other value is stored verbatim.
fn apply_secret_token(value: Option<String>, target: &mut Option<String>) {
    let Some(v) = value else {
        return;
    };
    let trimmed = v.trim();
    if trimmed == "**REDACTED**" {
        return;
    }
    *target = if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    };
}

/// Assign the syslog collector endpoint (Story 9.8 AC #1). `None`
/// leaves the stored value untouched; empty (after trim) clears the
/// endpoint, disabling the sink. A non-empty value must be
/// `host:port` (bracketed IPv6 accepted).
fn apply_syslog_endpoint(
    value: Option<String>,
    target: &mut Option<String>,
) -> Result<(), ApiError> {
    let Some(v) = value else {
        return Ok(());
    };
    let trimmed = v.trim();
    if trimmed.is_empty() {
        *target = None;
        return Ok(());
    }
    if crate::log_sinks::syslog::split_host_port(trimmed).is_none() {
        return Err(ApiError::BadRequest(format!(
            "syslog_endpoint must be host:port (got {trimmed:?})"
        )));
    }
    if trimmed.len() > 512 {
        return Err(ApiError::BadRequest(
            "syslog_endpoint too long (max 512 chars)".to_string(),
        ));
    }
    *target = Some(trimmed.to_string());
    Ok(())
}

/// Assign an optional PEM field (Story 9.8 syslog TLS material).
/// `None` leaves the stored value untouched; empty (after trim)
/// clears it. A non-empty value must contain at least one
/// `-----BEGIN <block>-----` marker; deep parsing is left to the sink
/// when it builds the TLS connector (same loader the connection will
/// actually use, so no parser drift).
fn apply_optional_pem(
    value: Option<String>,
    target: &mut Option<String>,
    block: &str,
    label: &str,
) -> Result<(), ApiError> {
    let Some(v) = value else {
        return Ok(());
    };
    let trimmed = v.trim();
    if trimmed.is_empty() {
        *target = None;
        return Ok(());
    }
    if !trimmed.contains(&format!("-----BEGIN {block}")) {
        return Err(ApiError::BadRequest(format!(
            "{label} must be PEM ({block} block)"
        )));
    }
    *target = Some(trimmed.to_string());
    Ok(())
}

/// Assign the syslog extra structured-data field (Story 9.8 AC #1).
/// `None` leaves untouched; empty clears. A non-empty value must be
/// comma-separated `key=value` pairs whose keys are printable
/// US-ASCII without `=`, `]`, `"` or spaces (RFC 5424 SD-NAME).
fn apply_syslog_extra_sd(
    value: Option<String>,
    target: &mut Option<String>,
) -> Result<(), ApiError> {
    let Some(v) = value else {
        return Ok(());
    };
    let trimmed = v.trim();
    if trimmed.is_empty() {
        *target = None;
        return Ok(());
    }
    if trimmed.len() > 512 {
        return Err(ApiError::BadRequest(
            "syslog_extra_sd too long (max 512 chars)".to_string(),
        ));
    }
    for pair in trimmed.split(',') {
        let Some((key, val)) = pair.split_once('=') else {
            return Err(ApiError::BadRequest(format!(
                "syslog_extra_sd entries must be key=value (got {pair:?})"
            )));
        };
        let key = key.trim();
        if key.is_empty()
            || !key
                .chars()
                .all(|c| c.is_ascii_graphic() && c != '=' && c != ']' && c != '"')
        {
            return Err(ApiError::BadRequest(format!(
                "syslog_extra_sd key {key:?} must be printable ASCII without '=', ']' or '\"'"
            )));
        }
        // Control characters in a value would split the message on
        // LF-framed collectors (the encoder also sanitizes them, but
        // rejecting here surfaces the mistake to the operator).
        if val.chars().any(char::is_control) {
            return Err(ApiError::BadRequest(format!(
                "syslog_extra_sd value for key {key:?} must not contain control characters"
            )));
        }
    }
    *target = Some(trimmed.to_string());
    Ok(())
}

/// Assign a Unix permission mode field when present, rejecting values
/// above `0o777` with `400 "<label> must fit in 9 permission bits
/// (<= 0o777)"`.
fn apply_mode_u32(value: Option<u32>, target: &mut u32, label: &str) -> Result<(), ApiError> {
    if let Some(mode) = value {
        if mode > 0o777 {
            return Err(ApiError::BadRequest(format!(
                "{label} must fit in 9 permission bits (<= 0o777)"
            )));
        }
        *target = mode;
    }
    Ok(())
}

/// Assign an optional absolute-filesystem-path field when present.
/// An empty (after trim) value clears the field to `None`; otherwise
/// the path must start with `/`, be at most 4096 chars, and contain
/// no `..` traversal component.
fn apply_optional_abs_path(
    value: Option<String>,
    target: &mut Option<String>,
    label: &str,
) -> Result<(), ApiError> {
    let Some(path) = value else {
        return Ok(());
    };
    let trimmed = path.trim();
    if trimmed.is_empty() {
        *target = None;
        return Ok(());
    }
    if !trimmed.starts_with('/') {
        return Err(ApiError::BadRequest(format!(
            "{label} must be an absolute path (starting with '/')"
        )));
    }
    if trimmed.len() > 4096 {
        return Err(ApiError::BadRequest(format!(
            "{label} too long (> 4096 chars)"
        )));
    }
    // Reject path traversal components. The path is operator-
    // supplied via the authenticated API, but defence-in-depth
    // prevents accidentally writing outside /var/lib/lorica.
    if trimmed.contains("/../") || trimmed.ends_with("/..") {
        return Err(ApiError::BadRequest(format!(
            "{label} must not contain path traversal (../)"
        )));
    }
    *target = Some(trimmed.to_string());
    Ok(())
}

/// Assign `sla_purge_schedule` when present. Accepts
/// `"first_of_month"`, `"daily"`, or a day number `1..=28`.
fn apply_sla_purge_schedule(value: Option<String>, target: &mut String) -> Result<(), ApiError> {
    let Some(schedule) = value else {
        return Ok(());
    };
    let valid = matches!(schedule.as_str(), "first_of_month" | "daily")
        || schedule.parse::<i32>().is_ok_and(|d| (1..=28).contains(&d));
    if !valid {
        return Err(ApiError::BadRequest(
            "sla_purge_schedule must be 'first_of_month', 'daily', or a day number (1-28)".into(),
        ));
    }
    *target = schedule;
    Ok(())
}

/// Assign `otlp_endpoint` when present. An empty (after trim) value
/// clears the field to `None`; otherwise the URL must carry an
/// `http://` / `https://` scheme, a hostname, and at most 2048
/// chars. A plaintext `http://` endpoint is accepted but logged at
/// `warn` level (side effect kept from the inline block).
fn apply_otlp_endpoint(
    value: Option<String>,
    target: &mut Option<String>,
) -> Result<(), ApiError> {
    let Some(endpoint) = value else {
        return Ok(());
    };
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        *target = None;
        return Ok(());
    }
    // Validate scheme + host to reject malformed input.
    // RFC-1918 / loopback targets are NOT blocked because
    // internal collectors (docker-compose, k8s sidecar) are
    // the primary deployment pattern and the API is auth-gated.
    let is_https = trimmed.starts_with("https://");
    let is_http = trimmed.starts_with("http://");
    if !is_http && !is_https {
        return Err(ApiError::BadRequest(
            "otlp_endpoint must start with http:// or https://".into(),
        ));
    }
    let after_scheme = if is_https {
        &trimmed[8..]
    } else {
        &trimmed[7..]
    };
    if after_scheme.is_empty() || after_scheme.starts_with('/') || after_scheme.starts_with(':') {
        return Err(ApiError::BadRequest(
            "otlp_endpoint must contain a hostname after the scheme".into(),
        ));
    }
    if trimmed.len() > 2048 {
        return Err(ApiError::BadRequest(
            "otlp_endpoint too long (> 2048 chars)".into(),
        ));
    }
    if is_http {
        tracing::warn!(
            endpoint = %trimmed,
            "OTLP endpoint uses plaintext HTTP; trace data \
             (URLs, IPs, error messages) will transit in cleartext. \
             Use https:// in production."
        );
    }
    *target = Some(trimmed.to_string());
    Ok(())
}

/// Assign `otlp_service_name` when present. The trimmed value must be
/// 1-256 chars and free of ASCII control characters (including DEL).
fn apply_otlp_service_name(value: Option<String>, target: &mut String) -> Result<(), ApiError> {
    let Some(name) = value else {
        return Ok(());
    };
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        return Err(ApiError::BadRequest(
            "otlp_service_name must be 1-256 characters".into(),
        ));
    }
    if trimmed.chars().any(|c| (c as u32) < 0x20 || c == '\u{7f}') {
        return Err(ApiError::BadRequest(
            "otlp_service_name must not contain control characters".into(),
        ));
    }
    *target = trimmed.to_string();
    Ok(())
}

/// Assign `otlp_sampling_ratio` when present. The value must be a
/// finite number in `0.0..=1.0` (NaN and infinities rejected).
fn apply_otlp_sampling_ratio(value: Option<f64>, target: &mut f64) -> Result<(), ApiError> {
    let Some(ratio) = value else {
        return Ok(());
    };
    if !(0.0..=1.0).contains(&ratio) || !ratio.is_finite() {
        return Err(ApiError::BadRequest(
            "otlp_sampling_ratio must be a finite number in 0.0..=1.0".into(),
        ));
    }
    *target = ratio;
    Ok(())
}

/// POST /api/v1/settings/otel/test - probe the currently-persisted
/// OTLP endpoint for reachability. Used by the dashboard's
/// "Test connection" button. Does NOT mutate state; does NOT
/// re-init the OTel provider. Just opens a plain HTTP(S)
/// connection to the endpoint's `/v1/traces` path (for http-proto
/// / http-json) or to the base URL (grpc — we cannot speak the
/// HTTP/2 gRPC preamble from reqwest so "TCP open" is all we
/// assert) and reports status + round-trip latency.
///
/// Any HTTP status code (including 4xx and 5xx) counts as
/// "reachable" — the collector is answering, even if it does not
/// like our empty request. Connection refused, DNS failure or
/// timeout count as "unreachable".
pub async fn test_otel_connection(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let settings = db_blocking(&state.store, move |store| store.get_global_settings()).await?;

    let endpoint = settings
        .otlp_endpoint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let Some(endpoint) = endpoint else {
        return Ok(json_data(serde_json::json!({
            "ok": false,
            "message": "otlp_endpoint is not set; save a collector URL first.",
        })));
    };

    Ok(json_data(
        probe_otlp_endpoint(endpoint, &settings.otlp_protocol, "/v1/traces", None).await,
    ))
}

/// Shared OTLP reachability probe behind the trace and logs test
/// endpoints (QA finding: the two handlers were ~80 near-identical
/// lines). For HTTP transports the collector canonically exposes the
/// signal under `signal_path`; for gRPC we hit the base URL - the
/// plain HTTP client gets a protocol error from the gRPC listener,
/// which still means "TCP is open". A minimal empty POST is the most
/// representative probe: real traffic is also POST, and a 400 / 415
/// rejection still proves reachability.
async fn probe_otlp_endpoint(
    endpoint: &str,
    protocol: &str,
    signal_path: &str,
    auth_header: Option<&str>,
) -> serde_json::Value {
    use std::time::{Duration, Instant};

    let probe_url = match protocol {
        "http-proto" | "http-json" => {
            let trimmed = endpoint.trim_end_matches('/');
            if trimmed.ends_with(signal_path) {
                trimmed.to_string()
            } else {
                format!("{trimmed}{signal_path}")
            }
        }
        _ => endpoint.to_string(),
    };

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return serde_json::json!({
                "ok": false,
                "message": format!("reqwest client build failed: {e}"),
            });
        }
    };

    let start = Instant::now();
    let mut request = client
        .post(&probe_url)
        .header("Content-Type", "application/x-protobuf")
        .body(Vec::<u8>::new());
    if let Some(auth) = auth_header.filter(|a| !a.trim().is_empty()) {
        request = request.header("Authorization", auth);
    }
    let result = request.send().await;
    let latency_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let detail = if status >= 400 {
                format!(
                    "collector responded (HTTP {status}); \
                     endpoint is reachable but rejected the probe - \
                     check authentication or content-type settings"
                )
            } else {
                format!("reachable (HTTP {status})")
            };
            serde_json::json!({
                "ok": true,
                "message": detail,
                "latency_ms": latency_ms,
            })
        }
        Err(e) => serde_json::json!({
            "ok": false,
            "message": format!("unreachable: {e}"),
            "latency_ms": latency_ms,
        }),
    }
}

/// POST /api/v1/settings/syslog/test - send one synthetic RFC 5424
/// test message over the currently-persisted syslog configuration
/// (Story 9.8 AC #6). Same contract as the OTel test: always 200,
/// outcome in the body (`ok` / `message` / `latency_ms`). For UDP a
/// successful send proves resolution and a writable socket, not
/// collector receipt; the message says so.
pub async fn test_syslog_connection(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
) -> Result<Json<serde_json::Value>, ApiError> {
    use std::time::Instant;

    let settings = db_blocking(&state.store, move |store| store.get_global_settings()).await?;
    let sinks = crate::log_sinks::LogSinksConfig::from_settings(&settings, false);
    let Some(syslog_cfg) = sinks.syslog else {
        return Ok(json_data(serde_json::json!({
            "ok": false,
            "message": "syslog_endpoint is not set; save a collector address first.",
        })));
    };

    let start = Instant::now();
    let result =
        crate::log_sinks::syslog::send_test_message(&syslog_cfg, &sinks.node_id, &sinks.node_name)
            .await;
    let latency_ms = start.elapsed().as_millis() as u64;

    // The test opens a socket to an operator-configured host and
    // writes a real frame: an unrecorded network side effect would be
    // a gap in the tamper-evident trail (QA finding).
    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &audit_ctx,
        "log_sink.test",
        ("settings", "syslog"),
        None,
        None,
    )
    .await;

    let payload = match result {
        Ok(()) => {
            let caveat = if syslog_cfg.transport == crate::log_sinks::SyslogTransport::Udp {
                " (UDP is fire-and-forget; delivery is not confirmed)"
            } else {
                ""
            };
            serde_json::json!({
                "ok": true,
                "message": format!(
                    "test message sent over {}{caveat}",
                    settings.syslog_transport
                ),
                "latency_ms": latency_ms,
            })
        }
        Err(e) => serde_json::json!({
            "ok": false,
            "message": e,
            "latency_ms": latency_ms,
        }),
    };
    Ok(json_data(payload))
}

/// POST /api/v1/settings/otlp-logs/test - probe the persisted OTLP
/// endpoint's `/v1/logs` path for reachability (Story 9.8 AC #6).
/// Mirrors [`test_otel_connection`], with the logs signal path and
/// the `otlp_logs_auth_header` attached when configured, so an
/// authenticated collector answers 2xx instead of 401.
pub async fn test_otlp_logs_connection(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let settings = db_blocking(&state.store, move |store| store.get_global_settings()).await?;

    let endpoint = settings
        .otlp_endpoint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let Some(endpoint) = endpoint else {
        return Ok(json_data(serde_json::json!({
            "ok": false,
            "message": "otlp_endpoint is not set; save a collector URL first.",
        })));
    };

    let payload = probe_otlp_endpoint(
        endpoint,
        &settings.otlp_protocol,
        "/v1/logs",
        settings.otlp_logs_auth_header.as_deref(),
    )
    .await;

    // The probe transmits the stored bearer credential to the stored
    // URL: record who triggered it (QA finding).
    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &audit_ctx,
        "log_sink.test",
        ("settings", "otlp_logs"),
        None,
        None,
    )
    .await;

    Ok(json_data(payload))
}

fn validate_cidr_list(entries: &[String], field: &str) -> Result<(), ApiError> {
    for entry in entries {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.parse::<std::net::IpAddr>().is_err() && trimmed.parse::<ipnet::IpNet>().is_err()
        {
            return Err(ApiError::BadRequest(format!(
                "invalid {field} CIDR or IP: {trimmed}"
            )));
        }
    }
    Ok(())
}

// ---- Notification Configs ----

/// GET /api/v1/notifications - list notification channels with secrets masked.
pub async fn list_notifications(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let configs = db_blocking(&state.store, move |store| {
        let mut configs = store.list_notification_configs()?;
        for nc in &mut configs {
            nc.config = mask_sensitive_config(&nc.channel, &nc.config);
        }
        Ok::<_, ApiError>(configs)
    })
    .await?;
    Ok(json_data(serde_json::json!({ "notifications": configs })))
}

/// JSON body for creating or updating a notification channel.
#[derive(Deserialize)]
pub struct CreateNotificationRequest {
    /// Channel type (`"email"`, `"webhook"`, `"slack"`).
    pub channel: String,
    /// Whether this channel is dispatched.
    pub enabled: Option<bool>,
    /// Channel-specific JSON config payload (encrypted at rest).
    pub config: String,
    /// Alert types this destination subscribes to.
    pub alert_types: Vec<String>,
}

/// POST /api/v1/notifications - register a new notification channel.
pub async fn create_notification(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Json(body): Json<CreateNotificationRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let channel: lorica_config::models::NotificationChannel = body
        .channel
        .parse()
        .map_err(|e: strum::ParseError| ApiError::BadRequest(e.to_string()))?;

    validate_notification_config(&body.config)?;

    let nc = lorica_config::models::NotificationConfig {
        id: lorica_config::store::new_id(),
        channel,
        enabled: body.enabled.unwrap_or(true),
        config: body.config,
        alert_types: body.alert_types,
    };

    let masked = db_blocking(&state.store, move |store| {
        store.create_notification_config(&nc)?;
        let mut masked = nc;
        masked.config = mask_sensitive_config(&masked.channel, &masked.config);
        Ok::<_, ApiError>(masked)
    })
    .await?;

    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    // body carries credentials: not even a hash
    crate::audit::record(
        &state,
        &audit_ctx,
        "notification.create",
        ("notification", &masked.id),
        None,
        None,
    )
    .await;

    Ok(json_data_with_status(StatusCode::CREATED, masked))
}

/// POST /api/v1/notifications/:id/test - send a real test alert through the configured channel.
pub async fn test_notification(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let notification_id = id.clone();
    let nc = db_blocking(&state.store, move |store| {
        store
            .get_notification_config(&id)?
            .ok_or_else(|| ApiError::NotFound(format!("notification_config {id}")))
    })
    .await?;

    let test_event = lorica_notify::events::AlertEvent::new(
        lorica_notify::events::AlertType::ConfigChanged,
        "Lorica test notification - if you receive this, your channel is working!",
    );

    // Audit L-4 : the v1.5.1 M-12 work sanitised `ApiError::Internal`
    // bodies but the BadRequest path still echoed verbatim
    // `serde_json::Error` Display, which can include input bytes from
    // the malformed JSON ("expected value at line 1 column 23"). On
    // a dashboard toast that's surfaced to the operator's screen.
    // Log the full inner detail at `tracing::warn!` (operator
    // forensics trail preserved) and return a fixed user-facing
    // string keyed to the channel kind.
    match nc.channel {
        lorica_config::models::NotificationChannel::Email => {
            let config: lorica_notify::channels::EmailConfig = serde_json::from_str(&nc.config)
                .map_err(|e| {
                    tracing::warn!(channel = "email", error = %e, "stored notification config failed JSON deserialisation");
                    ApiError::BadRequest("stored email notification config is malformed".into())
                })?;
            lorica_notify::channels::email::send(&config, &test_event)
                .await
                .map_err(|e| ApiError::Internal(format!("email send failed: {e}")))?;
        }
        lorica_config::models::NotificationChannel::Webhook => {
            let config: lorica_notify::channels::WebhookConfig =
                serde_json::from_str(&nc.config).map_err(|e| {
                    tracing::warn!(channel = "webhook", error = %e, "stored notification config failed JSON deserialisation");
                    ApiError::BadRequest("stored webhook notification config is malformed".into())
                })?;
            lorica_notify::channels::webhook::send(&config, &test_event)
                .await
                .map_err(|e| ApiError::Internal(format!("webhook send failed: {e}")))?;
        }
        lorica_config::models::NotificationChannel::Slack => {
            let config: lorica_notify::channels::WebhookConfig =
                serde_json::from_str(&nc.config).map_err(|e| {
                    tracing::warn!(channel = "slack", error = %e, "stored notification config failed JSON deserialisation");
                    ApiError::BadRequest("stored slack notification config is malformed".into())
                })?;
            lorica_notify::channels::slack::send(&config, &test_event)
                .await
                .map_err(|e| ApiError::Internal(format!("slack send failed: {e}")))?;
        }
    }

    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &audit_ctx,
        "notification.test",
        ("notification", &notification_id),
        None,
        None,
    )
    .await;

    Ok(json_data(serde_json::json!({
        "message": "test notification sent successfully",
        "channel": nc.channel.as_str(),
    })))
}

/// GET /api/v1/notifications/history - return the recent notification dispatch history.
///
/// `events` is a page (most recent 200 rows) ; `total` is the
/// real row count from a `SELECT COUNT(*)` so it is not capped
/// at the page size. Same class of fix as `get_waf_stats` - the
/// previous implementation returned `events.len()` as the total
/// and would have silently plateaued at 200 once the history
/// table filled up.
pub async fn notification_history(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Read from persistent log store (survives restarts).
    // Off the tokio worker (audit M-7 / backlog #23) - both calls
    // hit the SQLite WAL via `Mutex<Connection>` and an unrelated
    // proxy-side write would otherwise stall the reactor.
    if let Some(ref log_store) = state.log_store {
        let (events, total) = log_db_blocking(log_store, move |store| {
            let events = store.list_notification_history(200)?;
            let total = store.notification_history_count()?;
            Ok((events, total))
        })
        .await?;
        return Ok(json_data(serde_json::json!({
            "events": events,
            "total": total,
        })));
    }
    // Fallback to in-memory history. The in-memory ring buffer
    // is bounded so `events.len()` IS the real total here.
    let events = if let Some(ref history) = state.notification_history {
        let h = history.lock();
        h.iter().rev().cloned().collect::<Vec<_>>()
    } else {
        vec![]
    };
    Ok(json_data(serde_json::json!({
        "events": events,
        "total": events.len(),
    })))
}

fn mask_sensitive_config(
    channel: &lorica_config::models::NotificationChannel,
    config: &str,
) -> String {
    use lorica_config::models::NotificationChannel;

    let mut val = match serde_json::from_str::<serde_json::Value>(config) {
        Ok(v) => v,
        Err(_) => return config.to_string(),
    };

    // Mirror the v1.5.1 audit L-5 TOML-export scrub : non-empty
    // `smtp_password` (Email), `url` + `auth_header` (Webhook + Slack)
    // are bearer-style credentials that the JSON GET path was leaking
    // verbatim. v1.5.2 audit M-1 closure : same field set, same
    // sentinel (`********`), same accept-back contract on PUT.
    let secret_fields: &[&str] = match channel {
        NotificationChannel::Email => &["smtp_password"],
        NotificationChannel::Webhook | NotificationChannel::Slack => &["url", "auth_header"],
    };
    for field in secret_fields {
        if val
            .get(field)
            .is_some_and(|v| v.as_str().is_some_and(|s| !s.is_empty()))
        {
            val[*field] = serde_json::json!("********");
        }
    }
    serde_json::to_string(&val).unwrap_or_else(|_| config.to_string())
}

fn validate_notification_config(config: &str) -> Result<(), ApiError> {
    if config.is_empty() {
        return Err(ApiError::BadRequest("config must not be empty".into()));
    }
    serde_json::from_str::<serde_json::Value>(config)
        .map_err(|e| ApiError::BadRequest(format!("config must be valid JSON: {e}")))?;
    Ok(())
}

/// PUT /api/v1/notifications/:id - update channel config; `********` placeholders preserve stored secrets.
pub async fn update_notification(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
    Json(body): Json<CreateNotificationRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let channel: lorica_config::models::NotificationChannel = body
        .channel
        .parse()
        .map_err(|e: strum::ParseError| ApiError::BadRequest(e.to_string()))?;

    validate_notification_config(&body.config)?;

    // If the submitted config carries the `"********"` sentinel for
    // any secret field, restore the previously stored value for that
    // field. Any failure in the restore path must surface as an error
    // - silently falling through would persist the literal mask
    // string and erase the real secret. Email gets `smtp_password` ;
    // Webhook + Slack get `url` + `auth_header` (v1.5.2 audit M-1
    // closes the asymmetry between TOML export scrub and JSON GET
    // scrub).
    let restore_fields: &[&str] = match channel {
        lorica_config::models::NotificationChannel::Email => &["smtp_password"],
        lorica_config::models::NotificationChannel::Webhook
        | lorica_config::models::NotificationChannel::Slack => &["url", "auth_header"],
    };
    let mut config = body.config.clone();
    if !restore_fields.is_empty() {
        if let Ok(mut new_val) = serde_json::from_str::<serde_json::Value>(&config) {
            let needs_restore = restore_fields.iter().any(|f| {
                new_val
                    .get(*f)
                    .is_some_and(|v| v.as_str() == Some("********"))
            });
            if needs_restore {
                let lookup_id = id.clone();
                config = db_blocking(&state.store, move |store| {
                    let existing = store.get_notification_config(&lookup_id)?.ok_or_else(|| {
                        ApiError::BadRequest(
                            "cannot restore masked secret: no existing config for this channel"
                                .into(),
                        )
                    })?;
                    let existing_val: serde_json::Value = serde_json::from_str(&existing.config)
                        .map_err(|e| {
                            ApiError::BadRequest(format!(
                                "existing notification config is corrupt; cannot restore secrets: {e}"
                            ))
                        })?;
                    for field in restore_fields {
                        if new_val
                            .get(*field)
                            .is_some_and(|v| v.as_str() == Some("********"))
                        {
                            let v = existing_val.get(*field).ok_or_else(|| {
                                ApiError::BadRequest(format!(
                                    "existing config has no `{field}` to restore"
                                ))
                            })?;
                            new_val[*field] = v.clone();
                        }
                    }
                    serde_json::to_string(&new_val).map_err(|e| {
                        ApiError::BadRequest(format!(
                            "failed to re-serialize notification config: {e}"
                        ))
                    })
                })
                .await?;
            }
        }
    }

    let nc = lorica_config::models::NotificationConfig {
        id,
        channel,
        enabled: body.enabled.unwrap_or(true),
        config,
        alert_types: body.alert_types,
    };

    let masked = db_blocking(&state.store, move |store| {
        store.update_notification_config(&nc)?;
        let mut masked = nc;
        masked.config = mask_sensitive_config(&masked.channel, &masked.config);
        Ok::<_, ApiError>(masked)
    })
    .await?;

    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    // body carries credentials: not even a hash
    crate::audit::record(
        &state,
        &audit_ctx,
        "notification.update",
        ("notification", &masked.id),
        None,
        None,
    )
    .await;

    Ok(json_data(masked))
}

/// DELETE /api/v1/notifications/:id - remove a notification channel.
pub async fn delete_notification(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let notification_id = id.clone();
    db_blocking(&state.store, move |store| {
        store.delete_notification_config(&id)
    })
    .await?;

    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &audit_ctx,
        "notification.delete",
        ("notification", &notification_id),
        None,
        None,
    )
    .await;

    Ok(json_data(
        serde_json::json!({"message": "notification config deleted"}),
    ))
}

// ---- User Preferences ----

/// GET /api/v1/preferences - list every per-user UI preference key/value.
pub async fn list_preferences(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let prefs = db_blocking(&state.store, move |store| store.list_user_preferences()).await?;
    Ok(json_data(serde_json::json!({ "preferences": prefs })))
}

/// JSON body for `PUT /api/v1/preferences/:id`.
#[derive(Deserialize)]
pub struct UpdatePreferenceRequest {
    /// New value to store for the preference (`"never"` / `"always"`
    /// / `"once"`).
    pub value: String,
}

/// PUT /api/v1/preferences/:id - update one user preference value.
pub async fn update_preference(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
    Json(body): Json<UpdatePreferenceRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let value: lorica_config::models::PreferenceValue = body
        .value
        .parse()
        .map_err(|e: strum::ParseError| ApiError::BadRequest(e.to_string()))?;

    let preference_id = id.clone();
    let (before_pref, updated) = db_blocking(&state.store, move |store| {
        let existing = store
            .get_user_preference(&id)?
            .ok_or_else(|| ApiError::NotFound(format!("preference {id}")))?;
        let before_pref = existing.clone();

        let updated = lorica_config::models::UserPreference {
            value,
            updated_at: chrono::Utc::now(),
            ..existing
        };

        store.update_user_preference(&updated)?;
        Ok::<_, ApiError>((before_pref, updated))
    })
    .await?;

    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    let before = serde_json::to_value(&before_pref).ok();
    let after = serde_json::to_value(&updated).ok();
    crate::audit::record(
        &state,
        &audit_ctx,
        "preference.update",
        ("preference", &preference_id),
        before.as_ref(),
        after.as_ref(),
    )
    .await;

    Ok(json_data(updated))
}

/// DELETE /api/v1/preferences/:id - remove a user preference.
pub async fn delete_preference(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let preference_id = id.clone();
    db_blocking(&state.store, move |store| store.delete_user_preference(&id)).await?;

    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &audit_ctx,
        "preference.delete",
        ("preference", &preference_id),
        None,
        None,
    )
    .await;

    Ok(json_data(
        serde_json::json!({"message": "preference deleted"}),
    ))
}
