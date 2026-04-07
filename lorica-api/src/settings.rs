use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::error::{json_data, json_data_with_status, ApiError};
use crate::server::AppState;

// ---- Global Settings ----

/// GET /api/v1/settings
pub async fn get_settings(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let settings = store.get_global_settings()?;
    Ok(json_data(settings))
}

#[derive(Deserialize)]
pub struct UpdateSettingsRequest {
    pub management_port: Option<u16>,
    pub log_level: Option<String>,
    pub default_health_check_interval_s: Option<i32>,
    pub cert_warning_days: Option<i32>,
    pub cert_critical_days: Option<i32>,
    pub default_topology_type: Option<String>,
    pub max_global_connections: Option<i32>,
    pub flood_threshold_rps: Option<i32>,
    pub waf_ban_threshold: Option<i32>,
    pub waf_ban_duration_s: Option<i32>,
    pub access_log_retention: Option<i64>,
    pub sla_purge_enabled: Option<bool>,
    pub sla_purge_retention_days: Option<i32>,
    pub sla_purge_schedule: Option<String>,
    pub custom_security_presets: Option<Vec<lorica_config::models::SecurityHeaderPreset>>,
}

/// PUT /api/v1/settings
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
    if let Some(ref topo) = body.default_topology_type {
        settings.default_topology_type = topo
            .parse::<lorica_config::models::TopologyType>()
            .map_err(ApiError::BadRequest)?;
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

    store.update_global_settings(&settings)?;
    drop(store);
    state.notify_config_changed();
    Ok(json_data(settings))
}

// ---- Notification Configs ----

/// GET /api/v1/notifications
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

#[derive(Deserialize)]
pub struct CreateNotificationRequest {
    pub channel: String,
    pub enabled: Option<bool>,
    pub config: String,
    pub alert_types: Vec<String>,
}

/// POST /api/v1/notifications
pub async fn create_notification(
    Extension(state): Extension<AppState>,
    Json(body): Json<CreateNotificationRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let channel: lorica_config::models::NotificationChannel = body
        .channel
        .parse()
        .map_err(|e: String| ApiError::BadRequest(e))?;

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

/// POST /api/v1/notifications/:id/test - send a real test notification
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

/// GET /api/v1/notifications/history
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

/// PUT /api/v1/notifications/:id
pub async fn update_notification(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Json(body): Json<CreateNotificationRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let channel: lorica_config::models::NotificationChannel = body
        .channel
        .parse()
        .map_err(|e: String| ApiError::BadRequest(e))?;

    validate_notification_config(&body.config)?;

    let mut config = body.config.clone();
    if channel == lorica_config::models::NotificationChannel::Email {
        if let Ok(mut new_val) = serde_json::from_str::<serde_json::Value>(&config) {
            if new_val
                .get("smtp_password")
                .is_some_and(|v| v.as_str() == Some("********"))
            {
                let store = state.store.lock().await;
                if let Some(existing) = store.get_notification_config(&id)? {
                    if let Ok(existing_val) =
                        serde_json::from_str::<serde_json::Value>(&existing.config)
                    {
                        if let Some(pwd) = existing_val.get("smtp_password") {
                            new_val["smtp_password"] = pwd.clone();
                            config = serde_json::to_string(&new_val).unwrap_or(config);
                        }
                    }
                }
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

/// DELETE /api/v1/notifications/:id
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

/// GET /api/v1/preferences
pub async fn list_preferences(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let prefs = store.list_user_preferences()?;
    Ok(json_data(serde_json::json!({ "preferences": prefs })))
}

#[derive(Deserialize)]
pub struct UpdatePreferenceRequest {
    pub value: String,
}

/// PUT /api/v1/preferences/:id
pub async fn update_preference(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Json(body): Json<UpdatePreferenceRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let value: lorica_config::models::PreferenceValue = body
        .value
        .parse()
        .map_err(|e: String| ApiError::BadRequest(e))?;

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

/// DELETE /api/v1/preferences/:id
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
