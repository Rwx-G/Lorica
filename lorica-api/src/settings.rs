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
    let configs = store.list_notification_configs()?;
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
    Ok(json_data_with_status(StatusCode::CREATED, nc))
}

/// POST /api/v1/notifications/:id/test - validate notification config reachability
pub async fn test_notification(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let nc = store
        .get_notification_config(&id)?
        .ok_or_else(|| ApiError::NotFound(format!("notification_config {id}")))?;

    let config_json: serde_json::Value = serde_json::from_str(&nc.config)
        .map_err(|e| ApiError::BadRequest(format!("invalid config JSON: {e}")))?;

    match nc.channel {
        lorica_config::models::NotificationChannel::Email => {
            if config_json.get("smtp_host").is_none() {
                return Err(ApiError::BadRequest(
                    "email config missing required field: smtp_host".into(),
                ));
            }
        }
        lorica_config::models::NotificationChannel::Webhook => {
            if config_json.get("url").is_none() {
                return Err(ApiError::BadRequest(
                    "webhook config missing required field: url".into(),
                ));
            }
        }
    }

    Ok(json_data(serde_json::json!({
        "message": "notification config is valid",
        "channel": nc.channel.as_str(),
    })))
}

/// GET /api/v1/notifications/history
pub async fn notification_history(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let events = if let Some(ref history) = state.notification_history {
        let h = history.lock().unwrap();
        h.iter().rev().cloned().collect::<Vec<_>>()
    } else {
        vec![]
    };
    Ok(json_data(serde_json::json!({
        "events": events,
        "total": events.len(),
    })))
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

    let nc = lorica_config::models::NotificationConfig {
        id,
        channel,
        enabled: body.enabled.unwrap_or(true),
        config: body.config,
        alert_types: body.alert_types,
    };

    let store = state.store.lock().await;
    store.update_notification_config(&nc)?;
    Ok(json_data(nc))
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
