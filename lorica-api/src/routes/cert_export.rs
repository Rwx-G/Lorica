//! HTTP endpoints for the certificate export zone (v1.4.1):
//! settings status + ACL CRUD. The settings themselves land on
//! `GlobalSettings` so they come in via `PUT /api/v1/settings`
//! with the other global keys; this module only exposes the
//! per-pattern ACL list and the "trigger a full re-export now"
//! convenience endpoint.

use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use lorica_config::models::CertExportAcl;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{json_data, json_data_with_status, ApiError};
use crate::server::AppState;

/// JSON body for `POST /api/v1/cert-export/acls`.
#[derive(Deserialize)]
pub struct CreateAclRequest {
    /// Hostname pattern (exact, leading-wildcard, or `*`).
    pub hostname_pattern: String,
    /// Per-ACL owner uid override ; `None` inherits the global
    /// default.
    #[serde(default)]
    pub allowed_uid: Option<u32>,
    /// Per-ACL group gid override ; `None` inherits the global
    /// default.
    #[serde(default)]
    pub allowed_gid: Option<u32>,
}

/// JSON projection of a stored ACL.
#[derive(Serialize)]
pub struct AclResponse {
    /// ACL row id.
    pub id: String,
    /// Hostname pattern (exact / wildcard / catch-all).
    pub hostname_pattern: String,
    /// Owner uid override, `None` = inherit global default.
    pub allowed_uid: Option<u32>,
    /// Group gid override, `None` = inherit global default.
    pub allowed_gid: Option<u32>,
    /// RFC 3339 insert timestamp.
    pub created_at: String,
}

/// Shape-check an ACL pattern. Accepts `*`, `*.<label>...`, or an
/// exact hostname. Same alphabet as `validate_hostname_alias`
/// (ASCII letters, digits, `-`, `.`) with the additional `*`
/// allowed on the first two characters.
fn validate_pattern(raw: &str) -> Result<String, ApiError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest(
            "cert export ACL hostname_pattern must not be empty".into(),
        ));
    }
    if trimmed.len() > 253 {
        return Err(ApiError::BadRequest(
            "cert export ACL hostname_pattern is longer than 253 characters".into(),
        ));
    }
    if trimmed == "*" {
        return Ok(trimmed.to_string());
    }
    let body: &str = if let Some(rest) = trimmed.strip_prefix("*.") {
        rest
    } else if trimmed.contains('*') {
        return Err(ApiError::BadRequest(
            "cert export ACL hostname_pattern may only use `*` as a leading `*.` wildcard or a bare `*`".into(),
        ));
    } else {
        trimmed
    };
    // Body must be a valid DNS-ish string (letters, digits, `-`, `.`).
    if body.is_empty() || body.starts_with('.') || body.ends_with('.') {
        return Err(ApiError::BadRequest(
            "cert export ACL hostname_pattern body must not start or end with a dot".into(),
        ));
    }
    for label in body.split('.') {
        if label.is_empty() {
            return Err(ApiError::BadRequest(
                "cert export ACL hostname_pattern contains an empty DNS label".into(),
            ));
        }
        if label.len() > 63 {
            return Err(ApiError::BadRequest(
                "cert export ACL hostname_pattern has a label longer than 63 characters".into(),
            ));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(ApiError::BadRequest(
                "cert export ACL hostname_pattern may only contain ASCII letters, digits, `-`, `.`, and a leading `*.`".into(),
            ));
        }
    }
    Ok(trimmed.to_string())
}

/// POST /api/v1/cert-export/acls - add a new ACL row.
pub async fn create_acl(
    Extension(state): Extension<AppState>,
    Json(body): Json<CreateAclRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let pattern = validate_pattern(&body.hostname_pattern)?;
    let acl = CertExportAcl {
        id: Uuid::new_v4().to_string(),
        hostname_pattern: pattern,
        allowed_uid: body.allowed_uid,
        allowed_gid: body.allowed_gid,
        created_at: Utc::now(),
    };
    let store = state.store.lock().await;
    store.create_cert_export_acl(&acl)?;
    drop(store);
    Ok(json_data_with_status(
        StatusCode::CREATED,
        AclResponse {
            id: acl.id,
            hostname_pattern: acl.hostname_pattern,
            allowed_uid: acl.allowed_uid,
            allowed_gid: acl.allowed_gid,
            created_at: acl.created_at.to_rfc3339(),
        },
    ))
}

/// GET /api/v1/cert-export/acls - list every ACL.
pub async fn list_acls(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let acls = store.list_cert_export_acls()?;
    let items: Vec<AclResponse> = acls
        .into_iter()
        .map(|a| AclResponse {
            id: a.id,
            hostname_pattern: a.hostname_pattern,
            allowed_uid: a.allowed_uid,
            allowed_gid: a.allowed_gid,
            created_at: a.created_at.to_rfc3339(),
        })
        .collect();
    Ok(json_data(serde_json::json!({ "acls": items })))
}

/// DELETE /api/v1/cert-export/acls/:id - remove one ACL. Idempotent.
pub async fn delete_acl(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    store.delete_cert_export_acl(&id)?;
    drop(store);
    Ok(json_data(serde_json::json!({ "deleted": id })))
}

/// POST /api/v1/cert-export/reapply - force a full re-export of
/// every certificate in the store. Useful when the operator has
/// just changed ACL rules or the default mode and wants the
/// on-disk files realigned without waiting for the next ACME
/// renewal.
pub async fn reapply(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let settings = store.get_global_settings()?;
    let acls = store.list_cert_export_acls().unwrap_or_default();
    let certs = store.list_certificates()?;
    drop(store);
    let (ok, err, skipped) = crate::cert_export::reexport_all(&settings, &acls, &certs).await;
    Ok(json_data(serde_json::json!({
        "enabled": settings.cert_export_enabled,
        "exported": ok,
        "failed": err,
        // `skipped` counts certs whose hostname did not match any
        // configured ACL pattern. The frontend surfaces it next to
        // `exported` so the operator understands a low number is a
        // narrow allowlist, not a broken exporter.
        "skipped": skipped,
    })))
}

/// JSON projection of an orphan subdirectory on disk.
#[derive(Serialize)]
pub struct OrphanResponse {
    /// Subdirectory name (already sanitised, safe to display).
    pub name: String,
    /// RFC 3339 modification timestamp (empty when stat failed).
    pub modified_at: String,
    /// Total bytes summed across the four expected PEM files.
    pub size_bytes: u64,
}

/// GET /api/v1/cert-export/orphans - list per-hostname subdirectories
/// under the export root that no longer correspond to any live
/// certificate. The dashboard uses this to surface a "sweep" flow
/// without the operator having to SSH into the box.
pub async fn list_orphans(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let settings = store.get_global_settings()?;
    let certs = store.list_certificates()?;
    drop(store);
    let orphans = crate::cert_export::scan_orphans(&settings, &certs)
        .map_err(|e| ApiError::Internal(format!("cert-export orphan scan failed: {e}")))?;
    let items: Vec<OrphanResponse> = orphans
        .into_iter()
        .map(|o| OrphanResponse {
            name: o.name,
            modified_at: o.modified_at,
            size_bytes: o.size_bytes,
        })
        .collect();
    Ok(json_data(serde_json::json!({
        "enabled": settings.cert_export_enabled,
        "orphans": items,
    })))
}

/// DELETE /api/v1/cert-export/orphans/:name - remove a single orphan
/// subdirectory. The name is re-validated server-side (sanitiser +
/// live-cert re-check) before any filesystem write, so a stale or
/// racy dashboard click cannot blow away a legitimate directory.
pub async fn delete_orphan(
    Extension(state): Extension<AppState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let settings = store.get_global_settings()?;
    let certs = store.list_certificates()?;
    drop(store);
    let removed =
        crate::cert_export::delete_orphan(&settings, &certs, &name).map_err(|e| match e {
            crate::cert_export::ExportError::InvalidHostname(_) => {
                ApiError::BadRequest(format!("invalid orphan name: {name:?}"))
            }
            crate::cert_export::ExportError::BadConfig(m) => ApiError::BadRequest(m),
            other => ApiError::Internal(format!("cert-export orphan delete failed: {other}")),
        })?;
    tracing::warn!(
        target = %name,
        removed,
        "cert export: orphan deletion requested"
    );
    Ok(json_data(serde_json::json!({
        "name": name,
        "removed": removed,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expect_err(raw: &str) -> String {
        match validate_pattern(raw) {
            Ok(v) => panic!("expected validation error for {raw:?}, got Ok({v:?})"),
            Err(ApiError::BadRequest(m)) => m,
            Err(e) => panic!("expected BadRequest, got {e:?}"),
        }
    }

    #[test]
    fn accepts_exact_wildcard_and_catchall() {
        assert_eq!(
            validate_pattern("grafana.mibu.fr").unwrap(),
            "grafana.mibu.fr"
        );
        assert_eq!(validate_pattern("*.mibu.fr").unwrap(), "*.mibu.fr");
        assert_eq!(validate_pattern("*").unwrap(), "*");
    }

    #[test]
    fn rejects_interior_wildcard() {
        assert!(expect_err("foo.*.bar").contains("leading"));
    }

    #[test]
    fn rejects_empty_and_malformed() {
        assert!(expect_err("").contains("must not be empty"));
        assert!(expect_err(".bad.com").contains("start or end with a dot"));
        assert!(expect_err("bad.com.").contains("start or end with a dot"));
        assert!(expect_err("bad..com").contains("empty DNS label"));
    }

    #[test]
    fn rejects_non_ascii_and_underscore() {
        assert!(expect_err("my_group.com").contains("ASCII"));
        assert!(expect_err("café.com").contains("ASCII"));
    }

    #[test]
    fn rejects_label_too_long() {
        let long = "a".repeat(64);
        let input = format!("*.{long}.com");
        assert!(expect_err(&input).contains("63"));
    }
}
