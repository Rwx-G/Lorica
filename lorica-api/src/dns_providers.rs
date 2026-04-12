use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::{json_data, json_data_with_status, ApiError};
use crate::server::AppState;

/// Response for a DNS provider (credentials are never returned).
#[derive(Debug, Serialize)]
pub struct DnsProviderResponse {
    pub id: String,
    pub name: String,
    pub provider_type: String,
    pub created_at: String,
}

fn provider_to_response(p: &lorica_config::models::DnsProvider) -> DnsProviderResponse {
    DnsProviderResponse {
        id: p.id.clone(),
        name: p.name.clone(),
        provider_type: p.provider_type.clone(),
        created_at: p.created_at.to_rfc3339(),
    }
}

/// GET /api/v1/dns-providers
pub async fn list_dns_providers(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let providers = store.list_dns_providers()?;
    let responses: Vec<DnsProviderResponse> = providers.iter().map(provider_to_response).collect();
    Ok(json_data(serde_json::json!({ "dns_providers": responses })))
}

/// Request body for creating/updating a DNS provider.
#[derive(Debug, Deserialize)]
pub struct CreateDnsProviderRequest {
    pub name: String,
    pub provider_type: String,
    pub config: DnsProviderConfig,
}

/// Provider-specific credential fields (flattened).
#[derive(Debug, Deserialize, Serialize)]
pub struct DnsProviderConfig {
    // OVH
    pub ovh_endpoint: Option<String>,
    pub ovh_application_key: Option<String>,
    pub ovh_application_secret: Option<String>,
    pub ovh_consumer_key: Option<String>,
    // Cloudflare
    pub api_token: Option<String>,
    pub zone_id: Option<String>,
    // Route53
    pub aws_access_key_id: Option<String>,
    pub aws_secret_access_key: Option<String>,
    pub aws_region: Option<String>,
    pub hosted_zone_id: Option<String>,
}

impl DnsProviderConfig {
    /// Convert to the DnsChallengeConfig format used by the ACME module.
    fn to_dns_challenge_json(&self, provider_type: &str) -> Result<String, ApiError> {
        let config = match provider_type {
            "ovh" => {
                let app_key = self.ovh_application_key.as_deref().unwrap_or("");
                let app_secret = self.ovh_application_secret.as_deref().unwrap_or("");
                let consumer_key = self.ovh_consumer_key.as_deref().unwrap_or("");
                if app_key.is_empty() || app_secret.is_empty() || consumer_key.is_empty() {
                    return Err(ApiError::BadRequest(
                        "OVH requires ovh_application_key, ovh_application_secret, and ovh_consumer_key".into(),
                    ));
                }
                serde_json::json!({
                    "provider": "ovh",
                    "api_token": app_key,
                    "api_secret": app_secret,
                    "ovh_endpoint": self.ovh_endpoint.as_deref().unwrap_or("eu.api.ovh.com"),
                    "ovh_consumer_key": consumer_key,
                    "zone_id": ""
                })
            }
            "cloudflare" => {
                let token = self.api_token.as_deref().unwrap_or("");
                let zone = self.zone_id.as_deref().unwrap_or("");
                if token.is_empty() || zone.is_empty() {
                    return Err(ApiError::BadRequest(
                        "Cloudflare requires api_token and zone_id".into(),
                    ));
                }
                serde_json::json!({
                    "provider": "cloudflare",
                    "api_token": token,
                    "zone_id": zone
                })
            }
            "route53" => {
                let key_id = self.aws_access_key_id.as_deref().unwrap_or("");
                let secret = self.aws_secret_access_key.as_deref().unwrap_or("");
                let zone = self.hosted_zone_id.as_deref().unwrap_or("");
                if key_id.is_empty() || secret.is_empty() || zone.is_empty() {
                    return Err(ApiError::BadRequest(
                        "Route53 requires aws_access_key_id, aws_secret_access_key, and hosted_zone_id".into(),
                    ));
                }
                serde_json::json!({
                    "provider": "route53",
                    "api_token": key_id,
                    "api_secret": secret,
                    "zone_id": zone
                })
            }
            other => {
                return Err(ApiError::BadRequest(format!(
                    "unsupported provider_type '{other}': expected 'ovh', 'cloudflare', or 'route53'"
                )));
            }
        };
        Ok(serde_json::to_string(&config).unwrap_or_default())
    }
}

/// POST /api/v1/dns-providers
pub async fn create_dns_provider(
    Extension(state): Extension<AppState>,
    Json(body): Json<CreateDnsProviderRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let name = body.name.trim().to_string();
    if name.is_empty() {
        return Err(ApiError::BadRequest("name is required".into()));
    }

    let config_json = body.config.to_dns_challenge_json(&body.provider_type)?;

    let provider = lorica_config::models::DnsProvider {
        id: lorica_config::store::new_id(),
        name,
        provider_type: body.provider_type,
        config: config_json,
        created_at: chrono::Utc::now(),
    };

    let store = state.store.lock().await;
    store.create_dns_provider(&provider)?;
    Ok(json_data_with_status(
        StatusCode::CREATED,
        provider_to_response(&provider),
    ))
}

/// PUT /api/v1/dns-providers/:id
pub async fn update_dns_provider(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Json(body): Json<CreateDnsProviderRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let name = body.name.trim().to_string();
    if name.is_empty() {
        return Err(ApiError::BadRequest("name is required".into()));
    }

    let config_json = body.config.to_dns_challenge_json(&body.provider_type)?;

    let store = state.store.lock().await;
    let existing = store
        .get_dns_provider(&id)?
        .ok_or_else(|| ApiError::NotFound(format!("dns_provider {id}")))?;

    let provider = lorica_config::models::DnsProvider {
        id: existing.id,
        name,
        provider_type: body.provider_type,
        config: config_json,
        created_at: existing.created_at,
    };

    store.update_dns_provider(&provider)?;
    Ok(json_data(provider_to_response(&provider)))
}

/// DELETE /api/v1/dns-providers/:id
pub async fn delete_dns_provider(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;

    // Check if any certificates reference this provider
    if store.dns_provider_in_use(&id)? {
        return Err(ApiError::Conflict(
            "cannot delete DNS provider: referenced by one or more certificates".into(),
        ));
    }

    store.delete_dns_provider(&id)?;
    Ok(json_data(serde_json::json!({
        "message": "DNS provider deleted"
    })))
}

/// POST /api/v1/dns-providers/:id/test - test DNS provider connectivity
pub async fn test_dns_provider(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let provider = store
        .get_dns_provider(&id)?
        .ok_or_else(|| ApiError::NotFound(format!("dns_provider {id}")))?;
    drop(store);

    let dns_config: crate::acme::DnsChallengeConfig = serde_json::from_str(&provider.config)
        .map_err(|e| ApiError::Internal(format!("invalid DNS provider config: {e}")))?;

    if let Err(e) = dns_config.validate() {
        return Err(ApiError::BadRequest(format!("invalid DNS config: {e}")));
    }

    // Try to build the challenger (validates credentials are well-formed)
    let _challenger = crate::acme::build_dns_challenger(&dns_config)
        .await
        .map_err(|e| ApiError::Internal(format!("DNS provider test failed: {e}")))?;

    Ok(json_data(serde_json::json!({
        "message": "DNS provider configuration is valid",
        "provider_type": provider.provider_type,
    })))
}
