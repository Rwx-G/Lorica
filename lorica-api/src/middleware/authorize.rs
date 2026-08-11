//! Role-based authorization middleware (Story 8.3 AC #6).
//!
//! Runs AFTER [`super::auth::require_auth`] on the protected router,
//! so the [`Session`] extension (with its role) is always present.
//!
//! The whole authorization matrix lives in [`required_role`] instead
//! of per-route layers or in-handler macros, for three reasons:
//! the policy stays reviewable in one screen; the default for any
//! state-mutating method is fail-closed (Operator minimum, so a new
//! endpoint added without touching this file cannot be mutated by a
//! Viewer); and WebSocket upgrades are covered at upgrade time like
//! any other GET.
//!
//! Handler-level guards that need the caller identity (self-delete
//! protection, last-super-admin protection in the users CRUD) still
//! read `Extension<Session>` directly.

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use lorica_config::models::Role;

use super::auth::Session;
use crate::error::ApiError;

/// Minimum role required for a request on the protected router.
///
/// Rules, in precedence order:
/// 1. `/api/v1/users*` is SuperAdmin for EVERY method (AC #5: even
///    listing accounts is user management).
/// 2. Read methods (GET / HEAD) are Viewer-accessible, except
///    certificate downloads (`.../download` can serve the private
///    key depending on `format`) which need Operator.
/// 3. Every other method defaults to Operator (fail-closed), with a
///    SuperAdmin overlay for settings writes, DNS providers,
///    notification configs, cert-export ACLs, config import, and
///    the hot binary upgrade; and a Viewer floor for the self
///    password change.
pub fn required_role(method: &http::Method, path: &str) -> Role {
    if path == "/api/v1/users" || path.starts_with("/api/v1/users/") {
        return Role::SuperAdmin;
    }

    if method == http::Method::GET || method == http::Method::HEAD {
        // `format=key` / `format=full` return the private key; the
        // whole download endpoint is treated as secret material
        // rather than parsing the query string here.
        if path.starts_with("/api/v1/certificates/") && path.ends_with("/download") {
            return Role::Operator;
        }
        return Role::Viewer;
    }

    // Self password rotation is open to every authenticated role.
    if path == "/api/v1/auth/password" {
        return Role::Viewer;
    }

    // SuperAdmin overlay (AC #6): settings / DNS providers /
    // notification configs / cert-export ACL editing / config
    // import / binary upgrade.
    if path == "/api/v1/settings"
        || path.starts_with("/api/v1/settings/")
        || path == "/api/v1/dns-providers"
        || path.starts_with("/api/v1/dns-providers/")
        || path == "/api/v1/notifications"
        || path.starts_with("/api/v1/notifications/")
        || path.starts_with("/api/v1/cert-export/")
        || path.starts_with("/api/v1/config/import")
        || path == "/api/v1/system/upgrade"
    {
        return Role::SuperAdmin;
    }

    Role::Operator
}

/// Axum middleware enforcing [`required_role`] against the session
/// role. 403 on insufficient role; the message names the required
/// role so the dashboard can render a meaningful toast.
pub async fn authorize(req: Request, next: Next) -> Result<Response, ApiError> {
    let session = req
        .extensions()
        .get::<Session>()
        .ok_or_else(|| ApiError::Internal("session missing in authorize middleware".into()))?;

    let min_role = required_role(req.method(), req.uri().path());
    if session.role < min_role {
        return Err(ApiError::Forbidden(format!(
            "requires {} role",
            min_role.as_str()
        )));
    }

    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    #[test]
    fn users_endpoints_are_super_admin_for_all_methods() {
        assert_eq!(required_role(&Method::GET, "/api/v1/users"), Role::SuperAdmin);
        assert_eq!(
            required_role(&Method::POST, "/api/v1/users"),
            Role::SuperAdmin
        );
        assert_eq!(
            required_role(&Method::DELETE, "/api/v1/users/abc"),
            Role::SuperAdmin
        );
    }

    #[test]
    fn reads_are_viewer_accessible() {
        assert_eq!(required_role(&Method::GET, "/api/v1/routes"), Role::Viewer);
        assert_eq!(required_role(&Method::GET, "/api/v1/settings"), Role::Viewer);
        assert_eq!(required_role(&Method::GET, "/api/v1/logs/ws"), Role::Viewer);
    }

    #[test]
    fn cert_download_needs_operator() {
        assert_eq!(
            required_role(&Method::GET, "/api/v1/certificates/abc/download"),
            Role::Operator
        );
        // The certificate detail read stays Viewer-accessible.
        assert_eq!(
            required_role(&Method::GET, "/api/v1/certificates/abc"),
            Role::Viewer
        );
    }

    #[test]
    fn mutations_default_to_operator() {
        assert_eq!(required_role(&Method::POST, "/api/v1/routes"), Role::Operator);
        assert_eq!(
            required_role(&Method::DELETE, "/api/v1/bans/1.2.3.4"),
            Role::Operator
        );
        assert_eq!(
            required_role(&Method::POST, "/api/v1/config/export"),
            Role::Operator
        );
        assert_eq!(
            required_role(&Method::POST, "/api/v1/waf/rules/custom"),
            Role::Operator
        );
    }

    #[test]
    fn super_admin_overlay_covers_ac6_domains() {
        assert_eq!(
            required_role(&Method::PUT, "/api/v1/settings"),
            Role::SuperAdmin
        );
        assert_eq!(
            required_role(&Method::POST, "/api/v1/dns-providers"),
            Role::SuperAdmin
        );
        assert_eq!(
            required_role(&Method::DELETE, "/api/v1/notifications/n1"),
            Role::SuperAdmin
        );
        assert_eq!(
            required_role(&Method::POST, "/api/v1/cert-export/acls"),
            Role::SuperAdmin
        );
        assert_eq!(
            required_role(&Method::POST, "/api/v1/config/import"),
            Role::SuperAdmin
        );
        assert_eq!(
            required_role(&Method::POST, "/api/v1/system/upgrade"),
            Role::SuperAdmin
        );
    }

    #[test]
    fn password_change_is_open_to_every_role() {
        assert_eq!(
            required_role(&Method::PUT, "/api/v1/auth/password"),
            Role::Viewer
        );
    }
}
