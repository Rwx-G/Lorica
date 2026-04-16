//! Global settings, notification channels, and per-user UI preferences endpoints.

use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::error::{json_data, json_data_with_status, ApiError};
use crate::server::AppState;

// ---- Global Settings ----

/// GET /api/v1/settings - return the global settings document.
pub async fn get_settings(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let settings = store.get_global_settings()?;
    Ok(json_data(settings))
}

/// JSON body for `PUT /api/v1/settings`. Only the supplied fields are mutated.
#[derive(Deserialize)]
pub struct UpdateSettingsRequest {
    pub management_port: Option<u16>,
    pub log_level: Option<String>,
    pub default_health_check_interval_s: Option<i32>,
    pub cert_warning_days: Option<i32>,
    pub cert_critical_days: Option<i32>,
    pub max_global_connections: Option<i32>,
    pub flood_threshold_rps: Option<i32>,
    pub waf_ban_threshold: Option<i32>,
    pub waf_ban_duration_s: Option<i32>,
    pub access_log_retention: Option<i64>,
    pub sla_purge_enabled: Option<bool>,
    pub sla_purge_retention_days: Option<i32>,
    pub sla_purge_schedule: Option<String>,
    pub custom_security_presets: Option<Vec<lorica_config::models::SecurityHeaderPreset>>,
    pub trusted_proxies: Option<Vec<String>>,
    pub waf_whitelist_ips: Option<Vec<String>>,
    pub connection_deny_cidrs: Option<Vec<String>>,
    pub connection_allow_cidrs: Option<Vec<String>>,
    pub otlp_endpoint: Option<String>,
    pub otlp_protocol: Option<String>,
    pub otlp_service_name: Option<String>,
    pub otlp_sampling_ratio: Option<f64>,
    pub geoip_db_path: Option<String>,
    pub geoip_auto_update_enabled: Option<bool>,
    pub asn_db_path: Option<String>,
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
        if days < 1 {
            return Err(ApiError::BadRequest(
                "sla_purge_retention_days must be >= 1".into(),
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
            // Accept http:// or https:// URLs (OTLP/HTTP and OTLP/gRPC both
            // use HTTP-scheme URLs; gRPC transport is negotiated by the
            // `otlp_protocol` field, not the URL scheme).
            if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
                return Err(ApiError::BadRequest(
                    "otlp_endpoint must start with http:// or https://".into(),
                ));
            }
            if trimmed.len() > 2048 {
                return Err(ApiError::BadRequest(
                    "otlp_endpoint too long (> 2048 chars)".into(),
                ));
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
            // Require an absolute path so the supervisor does not end
            // up looking for the DB relative to whatever cwd it was
            // started from. Bounded at 4 KiB to match typical PATH_MAX
            // on Linux without trusting libc's limits.
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
            settings.asn_db_path = Some(trimmed.to_string());
        }
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
    pub channel: String,
    pub enabled: Option<bool>,
    pub config: String,
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
pub async fn notification_history(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Read from persistent log store (survives restarts)
    if let Some(ref log_store) = state.log_store {
        let events = log_store
            .list_notification_history(200)
            .map_err(ApiError::Internal)?;
        let total = events.len();
        return Ok(json_data(serde_json::json!({
            "events": events,
            "total": total,
        })));
    }
    // Fallback to in-memory history
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
                    .map_err(|_| {
                        ApiError::BadRequest(
                            "existing email config is corrupt; cannot restore smtp_password".into(),
                        )
                    })?;
                let pwd = existing_val.get("smtp_password").ok_or_else(|| {
                    ApiError::BadRequest(
                        "existing email config has no smtp_password to restore".into(),
                    )
                })?;
                new_val["smtp_password"] = pwd.clone();
                config = serde_json::to_string(&new_val).map_err(|_| {
                    ApiError::BadRequest("failed to re-serialize notification config".into())
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
