//! Global settings, notification channels, and per-user UI preferences endpoints.

use std::sync::Arc;

use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::error::{json_data, json_data_with_status, ApiError};
use crate::server::AppState;

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
    let store = state.store.lock().await;
    let mut settings = store.get_global_settings()?;
    settings.bot_hmac_secret_hex = if settings.bot_hmac_secret_hex.is_empty() {
        String::new()
    } else {
        "**REDACTED**".to_string()
    };
    Ok(json_data(settings))
}

/// JSON body for `PUT /api/v1/settings`. Only the supplied fields are
/// mutated ; each field mirrors the matching
/// [`lorica_config::models::GlobalSettings`] key.
#[derive(Deserialize)]
pub struct UpdateSettingsRequest {
    /// Management API TCP port.
    pub management_port: Option<u16>,
    /// `tracing` subscriber filter.
    pub log_level: Option<String>,
    /// Fallback health-check interval (s).
    pub default_health_check_interval_s: Option<i32>,
    /// Cert expiry warning threshold (days).
    pub cert_warning_days: Option<i32>,
    /// Cert expiry critical threshold (days).
    pub cert_critical_days: Option<i32>,
    /// Hard cap on global concurrent connections (0 = unlimited).
    pub max_global_connections: Option<i32>,
    /// Proxy-wide flood threshold (RPS).
    pub flood_threshold_rps: Option<i32>,
    /// Number of WAF blocks before auto-ban.
    pub waf_ban_threshold: Option<i32>,
    /// WAF auto-ban duration (s).
    pub waf_ban_duration_s: Option<i32>,
    /// Retention cap on the persistent access-log buffer.
    pub access_log_retention: Option<i64>,
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
}

/// PUT /api/v1/settings - patch the global settings document and trigger a proxy reload.
pub async fn update_settings(
    Extension(state): Extension<AppState>,
    Json(body): Json<UpdateSettingsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let mut settings = store.get_global_settings()?;

    if let Some(port) = body.management_port {
        settings.management_port = port;
    }
    if let Some(ref level) = body.log_level {
        let valid = ["trace", "debug", "info", "warn", "error"];
        if !valid.contains(&level.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "invalid log_level: {level}. Must be one of: {valid:?}"
            )));
        }
        settings.log_level = level.clone();
    }
    if let Some(interval) = body.default_health_check_interval_s {
        if interval < 1 {
            return Err(ApiError::BadRequest(
                "default_health_check_interval_s must be >= 1".into(),
            ));
        }
        settings.default_health_check_interval_s = interval;
    }
    if let Some(days) = body.cert_warning_days {
        if days < 1 {
            return Err(ApiError::BadRequest(
                "cert_warning_days must be >= 1".into(),
            ));
        }
        settings.cert_warning_days = days;
    }
    if let Some(days) = body.cert_critical_days {
        if days < 1 {
            return Err(ApiError::BadRequest(
                "cert_critical_days must be >= 1".into(),
            ));
        }
        settings.cert_critical_days = days;
    }
    if let Some(max_conn) = body.max_global_connections {
        if max_conn < 0 {
            return Err(ApiError::BadRequest(
                "max_global_connections must be >= 0".into(),
            ));
        }
        settings.max_global_connections = max_conn;
    }
    if let Some(threshold) = body.flood_threshold_rps {
        if threshold < 0 {
            return Err(ApiError::BadRequest(
                "flood_threshold_rps must be >= 0".into(),
            ));
        }
        settings.flood_threshold_rps = threshold;
    }
    if let Some(threshold) = body.waf_ban_threshold {
        if threshold < 0 {
            return Err(ApiError::BadRequest(
                "waf_ban_threshold must be >= 0".into(),
            ));
        }
        settings.waf_ban_threshold = threshold;
    }
    if let Some(duration) = body.waf_ban_duration_s {
        if duration < 0 {
            return Err(ApiError::BadRequest(
                "waf_ban_duration_s must be >= 0".into(),
            ));
        }
        settings.waf_ban_duration_s = duration;
    }
    if let Some(retention) = body.access_log_retention {
        if retention < 0 {
            return Err(ApiError::BadRequest(
                "access_log_retention must be >= 0".into(),
            ));
        }
        settings.access_log_retention = retention;
    }
    if let Some(enabled) = body.sla_purge_enabled {
        settings.sla_purge_enabled = enabled;
    }
    if let Some(days) = body.sla_purge_retention_days {
        if !(1..=3650).contains(&days) {
            return Err(ApiError::BadRequest(
                "sla_purge_retention_days must be in 1..=3650 (10 years)".into(),
            ));
        }
        settings.sla_purge_retention_days = days;
    }
    if let Some(ref schedule) = body.sla_purge_schedule {
        let valid = matches!(schedule.as_str(), "first_of_month" | "daily")
            || schedule.parse::<i32>().is_ok_and(|d| (1..=28).contains(&d));
        if !valid {
            return Err(ApiError::BadRequest(
                "sla_purge_schedule must be 'first_of_month', 'daily', or a day number (1-28)"
                    .into(),
            ));
        }
        settings.sla_purge_schedule = schedule.clone();
    }
    if let Some(presets) = body.custom_security_presets {
        settings.custom_security_presets = presets;
    }
    if let Some(ref proxies) = body.trusted_proxies {
        // Validate each entry is a valid CIDR or IP address
        for entry in proxies {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                continue;
            }
            // Accept both bare IPs (1.2.3.4) and CIDR notation (1.2.3.0/24)
            if trimmed.parse::<std::net::IpAddr>().is_err()
                && trimmed.parse::<ipnet::IpNet>().is_err()
            {
                return Err(ApiError::BadRequest(format!(
                    "invalid trusted proxy CIDR or IP: {trimmed}"
                )));
            }
        }
        settings.trusted_proxies = proxies.clone();
    }
    if let Some(ref ips) = body.waf_whitelist_ips {
        for entry in ips {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.parse::<std::net::IpAddr>().is_err()
                && trimmed.parse::<ipnet::IpNet>().is_err()
            {
                return Err(ApiError::BadRequest(format!(
                    "invalid WAF whitelist CIDR or IP: {trimmed}"
                )));
            }
        }
        settings.waf_whitelist_ips = ips.clone();
    }
    if let Some(ref cidrs) = body.connection_deny_cidrs {
        validate_cidr_list(cidrs, "connection_deny_cidrs")?;
        settings.connection_deny_cidrs = cidrs.clone();
    }
    if let Some(ref cidrs) = body.connection_allow_cidrs {
        validate_cidr_list(cidrs, "connection_allow_cidrs")?;
        settings.connection_allow_cidrs = cidrs.clone();
    }
    if let Some(ref endpoint) = body.otlp_endpoint {
        let trimmed = endpoint.trim();
        if trimmed.is_empty() {
            settings.otlp_endpoint = None;
        } else {
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
            if after_scheme.is_empty()
                || after_scheme.starts_with('/')
                || after_scheme.starts_with(':')
            {
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
            settings.otlp_endpoint = Some(trimmed.to_string());
        }
    }
    if let Some(ref protocol) = body.otlp_protocol {
        let valid = ["grpc", "http-proto", "http-json"];
        if !valid.contains(&protocol.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "invalid otlp_protocol: {protocol}. Must be one of: {valid:?}"
            )));
        }
        settings.otlp_protocol = protocol.clone();
    }
    if let Some(ref name) = body.otlp_service_name {
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
        settings.otlp_service_name = trimmed.to_string();
    }
    if let Some(ratio) = body.otlp_sampling_ratio {
        if !(0.0..=1.0).contains(&ratio) || !ratio.is_finite() {
            return Err(ApiError::BadRequest(
                "otlp_sampling_ratio must be a finite number in 0.0..=1.0".into(),
            ));
        }
        settings.otlp_sampling_ratio = ratio;
    }
    if let Some(ref path) = body.geoip_db_path {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            settings.geoip_db_path = None;
        } else {
            if !trimmed.starts_with('/') {
                return Err(ApiError::BadRequest(
                    "geoip_db_path must be an absolute path (starting with '/')".into(),
                ));
            }
            if trimmed.len() > 4096 {
                return Err(ApiError::BadRequest(
                    "geoip_db_path too long (> 4096 chars)".into(),
                ));
            }
            // Reject path traversal components. The path is operator-
            // supplied via the authenticated API, but defence-in-depth
            // prevents accidentally writing outside /var/lib/lorica.
            if trimmed.contains("/../") || trimmed.ends_with("/..") {
                return Err(ApiError::BadRequest(
                    "geoip_db_path must not contain path traversal (../)".into(),
                ));
            }
            settings.geoip_db_path = Some(trimmed.to_string());
        }
    }
    if let Some(auto_update) = body.geoip_auto_update_enabled {
        settings.geoip_auto_update_enabled = auto_update;
    }
    if let Some(ref path) = body.asn_db_path {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            settings.asn_db_path = None;
        } else {
            if !trimmed.starts_with('/') {
                return Err(ApiError::BadRequest(
                    "asn_db_path must be an absolute path (starting with '/')".into(),
                ));
            }
            if trimmed.len() > 4096 {
                return Err(ApiError::BadRequest(
                    "asn_db_path too long (> 4096 chars)".into(),
                ));
            }
            if trimmed.contains("/../") || trimmed.ends_with("/..") {
                return Err(ApiError::BadRequest(
                    "asn_db_path must not contain path traversal (../)".into(),
                ));
            }
            settings.asn_db_path = Some(trimmed.to_string());
        }
    }
    if let Some(auto_update) = body.asn_auto_update_enabled {
        settings.asn_auto_update_enabled = auto_update;
    }
    if let Some(enabled) = body.cert_export_enabled {
        settings.cert_export_enabled = enabled;
    }
    if let Some(ref dir) = body.cert_export_dir {
        let trimmed = dir.trim();
        if trimmed.is_empty() {
            settings.cert_export_dir = None;
        } else {
            if !trimmed.starts_with('/') {
                return Err(ApiError::BadRequest(
                    "cert_export_dir must be an absolute path (starting with '/')".into(),
                ));
            }
            if trimmed.len() > 4096 {
                return Err(ApiError::BadRequest(
                    "cert_export_dir too long (> 4096 chars)".into(),
                ));
            }
            if trimmed.contains("/../") || trimmed.ends_with("/..") {
                return Err(ApiError::BadRequest(
                    "cert_export_dir must not contain path traversal (../)".into(),
                ));
            }
            settings.cert_export_dir = Some(trimmed.to_string());
        }
    }
    if let Some(uid) = body.cert_export_owner_uid {
        settings.cert_export_owner_uid = Some(uid);
    }
    if let Some(gid) = body.cert_export_group_gid {
        settings.cert_export_group_gid = Some(gid);
    }
    if let Some(mode) = body.cert_export_file_mode {
        if mode > 0o777 {
            return Err(ApiError::BadRequest(
                "cert_export_file_mode must fit in 9 permission bits (<= 0o777)".into(),
            ));
        }
        settings.cert_export_file_mode = mode;
    }
    if let Some(mode) = body.cert_export_dir_mode {
        if mode > 0o777 {
            return Err(ApiError::BadRequest(
                "cert_export_dir_mode must fit in 9 permission bits (<= 0o777)".into(),
            ));
        }
        settings.cert_export_dir_mode = mode;
    }

    store.update_global_settings(&settings)?;
    drop(store);
    state.notify_config_changed();
    Ok(json_data(settings))
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
    use std::time::{Duration, Instant};

    let store = state.store.lock().await;
    let settings = store.get_global_settings()?;
    drop(store);

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

    // Compose the probe URL: for HTTP transports collectors
    // canonically expose `/v1/traces`. For gRPC we just hit the
    // base URL — the plain HTTP client will get a protocol error
    // from the gRPC listener, which still means "TCP is open".
    let protocol = settings.otlp_protocol.as_str();
    let probe_url = match protocol {
        "http-proto" | "http-json" => {
            let trimmed = endpoint.trim_end_matches('/');
            if trimmed.ends_with("/v1/traces") {
                trimmed.to_string()
            } else {
                format!("{trimmed}/v1/traces")
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
            return Ok(json_data(serde_json::json!({
                "ok": false,
                "message": format!("reqwest client build failed: {e}"),
            })));
        }
    };

    let start = Instant::now();
    // A minimal empty POST is the most representative probe: real
    // traffic is also POST. Collectors reject it with 400 / 415
    // (wrong content type) which still proves reachability.
    let result = client
        .post(&probe_url)
        .header("Content-Type", "application/x-protobuf")
        .body(Vec::<u8>::new())
        .send()
        .await;
    let latency_ms = start.elapsed().as_millis() as u64;

    let payload = match result {
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
    };

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
    let store = state.store.lock().await;
    let mut configs = store.list_notification_configs()?;
    for nc in &mut configs {
        nc.config = mask_sensitive_config(&nc.channel, &nc.config);
    }
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
    Extension(state): Extension<AppState>,
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

    let store = state.store.lock().await;
    store.create_notification_config(&nc)?;
    let mut masked = nc;
    masked.config = mask_sensitive_config(&masked.channel, &masked.config);
    Ok(json_data_with_status(StatusCode::CREATED, masked))
}

/// POST /api/v1/notifications/:id/test - send a real test alert through the configured channel.
pub async fn test_notification(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let nc = store
        .get_notification_config(&id)?
        .ok_or_else(|| ApiError::NotFound(format!("notification_config {id}")))?;
    drop(store);

    let test_event = lorica_notify::events::AlertEvent::new(
        lorica_notify::events::AlertType::ConfigChanged,
        "Lorica test notification - if you receive this, your channel is working!",
    );

    match nc.channel {
        lorica_config::models::NotificationChannel::Email => {
            let config: lorica_notify::channels::EmailConfig = serde_json::from_str(&nc.config)
                .map_err(|e| ApiError::BadRequest(format!("invalid email config: {e}")))?;
            lorica_notify::channels::email::send(&config, &test_event)
                .await
                .map_err(|e| ApiError::Internal(format!("email send failed: {e}")))?;
        }
        lorica_config::models::NotificationChannel::Webhook => {
            let config: lorica_notify::channels::WebhookConfig =
                serde_json::from_str(&nc.config)
                    .map_err(|e| ApiError::BadRequest(format!("invalid webhook config: {e}")))?;
            lorica_notify::channels::webhook::send(&config, &test_event)
                .await
                .map_err(|e| ApiError::Internal(format!("webhook send failed: {e}")))?;
        }
        lorica_config::models::NotificationChannel::Slack => {
            let config: lorica_notify::channels::WebhookConfig =
                serde_json::from_str(&nc.config)
                    .map_err(|e| ApiError::BadRequest(format!("invalid slack config: {e}")))?;
            lorica_notify::channels::slack::send(&config, &test_event)
                .await
                .map_err(|e| ApiError::Internal(format!("slack send failed: {e}")))?;
        }
    }

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
        let store = Arc::clone(log_store);
        let (events, total) = tokio::task::spawn_blocking(move || {
            let events = store.list_notification_history(200)?;
            let total = store.notification_history_count()?;
            Ok::<_, String>((events, total))
        })
        .await
        .map_err(|e| ApiError::Internal(format!("notification history join failed: {e}")))?
        .map_err(ApiError::Internal)?;
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
    if *channel == lorica_config::models::NotificationChannel::Email {
        if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(config) {
            if val
                .get("smtp_password")
                .is_some_and(|v| v.as_str().is_some_and(|s| !s.is_empty()))
            {
                val["smtp_password"] = serde_json::json!("********");
            }
            return serde_json::to_string(&val).unwrap_or_else(|_| config.to_string());
        }
    }
    config.to_string()
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
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Json(body): Json<CreateNotificationRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let channel: lorica_config::models::NotificationChannel = body
        .channel
        .parse()
        .map_err(|e: strum::ParseError| ApiError::BadRequest(e.to_string()))?;

    validate_notification_config(&body.config)?;

    let mut config = body.config.clone();
    if channel == lorica_config::models::NotificationChannel::Email {
        // If the submitted config carries the sentinel mask
        // `"********"` for the password, the UI wants us to keep the
        // previously stored value. Any failure in that restore path
        // (config unparseable, no existing row, no password in the
        // existing row) must be surfaced as an error; silently
        // falling through would persist the literal mask string and
        // erase the real SMTP password.
        if let Ok(mut new_val) = serde_json::from_str::<serde_json::Value>(&config) {
            if new_val
                .get("smtp_password")
                .is_some_and(|v| v.as_str() == Some("********"))
            {
                let store = state.store.lock().await;
                let existing = store.get_notification_config(&id)?.ok_or_else(|| {
                    ApiError::BadRequest(
                        "cannot restore masked smtp_password: no existing config for this channel"
                            .into(),
                    )
                })?;
                let existing_val: serde_json::Value = serde_json::from_str(&existing.config)
                    .map_err(|e| {
                        ApiError::BadRequest(format!(
                            "existing email config is corrupt; cannot restore smtp_password: {e}"
                        ))
                    })?;
                let pwd = existing_val.get("smtp_password").ok_or_else(|| {
                    ApiError::BadRequest(
                        "existing email config has no smtp_password to restore".into(),
                    )
                })?;
                new_val["smtp_password"] = pwd.clone();
                config = serde_json::to_string(&new_val).map_err(|e| {
                    ApiError::BadRequest(format!("failed to re-serialize notification config: {e}"))
                })?;
                drop(store);
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

    let store = state.store.lock().await;
    store.update_notification_config(&nc)?;
    let mut masked = nc;
    masked.config = mask_sensitive_config(&masked.channel, &masked.config);
    Ok(json_data(masked))
}

/// DELETE /api/v1/notifications/:id - remove a notification channel.
pub async fn delete_notification(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    store.delete_notification_config(&id)?;
    Ok(json_data(
        serde_json::json!({"message": "notification config deleted"}),
    ))
}

// ---- User Preferences ----

/// GET /api/v1/preferences - list every per-user UI preference key/value.
pub async fn list_preferences(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let prefs = store.list_user_preferences()?;
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
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Json(body): Json<UpdatePreferenceRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let value: lorica_config::models::PreferenceValue = body
        .value
        .parse()
        .map_err(|e: strum::ParseError| ApiError::BadRequest(e.to_string()))?;

    let store = state.store.lock().await;
    let existing = store
        .get_user_preference(&id)?
        .ok_or_else(|| ApiError::NotFound(format!("preference {id}")))?;

    let updated = lorica_config::models::UserPreference {
        value,
        updated_at: chrono::Utc::now(),
        ..existing
    };

    store.update_user_preference(&updated)?;
    Ok(json_data(updated))
}

/// DELETE /api/v1/preferences/:id - remove a user preference.
pub async fn delete_preference(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    store.delete_user_preference(&id)?;
    Ok(json_data(
        serde_json::json!({"message": "preference deleted"}),
    ))
}
