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
use crate::cluster::ClusterRuntime;
use crate::error::ApiError;
use crate::server::AppState;

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

    // Audit log (Story 8.9 AC #3/#8): reads are Operator+, the chain
    // verification is SuperAdmin-only. Both are carved out of the
    // Viewer-open GET default below.
    if path == "/api/v1/audit/verify" {
        return Role::SuperAdmin;
    }
    if path == "/api/v1/audit" {
        return Role::Operator;
    }

    // Cluster registry (Story 9.3 AC #10). A join token is a
    // credential, so the token endpoints are SuperAdmin for every
    // method; node mutations (activate, revoke) and leaving the fleet
    // are SuperAdmin; roster and status reads stay Viewer.
    if path == "/api/v1/cluster/tokens"
        || path.starts_with("/api/v1/cluster/tokens/")
        || path == "/api/v1/cluster/leave"
    {
        return Role::SuperAdmin;
    }
    // Break-glass (Story 9.4 AC #11) re-enables local mutations on a
    // follower: SuperAdmin for every method, including reading who
    // opened it.
    if path == "/api/v1/cluster/break-glass" {
        return Role::SuperAdmin;
    }
    // ISSUING a fleet-wide ban takes a client off every node at once
    // (Story 9.6 AC #10): the same floor as the other fleet-wide
    // actions, not the Operator floor the local ban endpoints use.
    // READING the fan-in view falls through to the Viewer floor every
    // other cluster read uses.
    if path == "/api/v1/cluster/bans"
        && method != http::Method::GET
        && method != http::Method::HEAD
    {
        return Role::SuperAdmin;
    }
    if path.starts_with("/api/v1/cluster/nodes")
        && method != http::Method::GET
        && method != http::Method::HEAD
    {
        return Role::SuperAdmin;
    }
    // Fleet READS sit at the Operator floor (Epic 9 close, backlog
    // #69 decided). The roster discloses each follower's source
    // address and the hostnames whose private keys it holds; the
    // fan-in views return every node's client addresses, paths and
    // matched payloads; the replication and drift reports name which
    // node runs what. On a delegated fleet that is cross-node data in
    // the least-trusted role's hands. `status` stays Viewer: it
    // carries no address, no selector and no row, and the header
    // badge every role sees is built from it.
    if path.starts_with("/api/v1/cluster/nodes")
        || path == "/api/v1/cluster/replication"
        || path == "/api/v1/cluster/drift"
        || path == "/api/v1/cluster/logs"
        || path == "/api/v1/cluster/waf-events"
        || path == "/api/v1/cluster/bans"
    {
        return Role::Operator;
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

/// Whether a request is follower-local by design and stays reachable
/// while the follower is read-only (Story 9.4 AC #10): reads, session
/// and account management, the audit log, the cluster commands the
/// follower itself owns (leave, break-glass, status), validation and
/// test endpoints that mutate nothing, config export and import
/// preview, and load-test start / abort (a probe, not configuration).
/// Everything else that is not GET / HEAD is a configuration mutation
/// owned by the control plane.
pub fn follower_local_request(method: &http::Method, path: &str) -> bool {
    if method == http::Method::GET || method == http::Method::HEAD {
        return true;
    }
    // `/api/v1/users` and `/api/v1/audit` are spelled with and
    // without the trailing slash rather than as bare prefixes: a bare
    // `starts_with` would also admit a future `/api/v1/users-export`
    // or `/api/v1/audit-archive`, which is the open-ended matching the
    // probe list below already refuses to rely on.
    //
    // The cluster commands a follower owns are spelled out for the
    // same reason. A bare `/api/v1/cluster/` prefix admitted every
    // fleet mutation (mint a token, activate, revoke, fleet ban) and
    // left each handler's own `control_plane(&state)?` check as the
    // only thing standing between a follower and a 409; the doc
    // comment above described a list of three while the code
    // admitted the prefix (Epic 9 close, security audit).
    const PREFIXES: &[&str] = &[
        "/api/v1/auth/",
        "/api/v1/users/",
        "/api/v1/audit/",
        "/api/v1/validate/",
        "/api/v1/loadtest/start/",
    ];
    const EXACT: &[&str] = &[
        "/api/v1/users",
        "/api/v1/audit",
        "/api/v1/cluster/leave",
        "/api/v1/cluster/break-glass",
        "/api/v1/config/export",
        "/api/v1/config/import/preview",
        "/api/v1/loadtest/abort",
        "/api/v1/acme/provision-dns-manual/check",
    ];
    // The connectivity probes, spelled out rather than matched by a
    // `/test` suffix. This gate must fail closed by default, and an
    // open-ended suffix silently exempts any future endpoint that
    // happens to end the same way, with no test failing. `{id}` paths
    // are matched as prefix plus suffix because the id is opaque.
    const PROBE_EXACT: &[&str] = &[
        "/api/v1/settings/otel/test",
        "/api/v1/settings/syslog/test",
        "/api/v1/settings/otlp-logs/test",
    ];
    const PROBE_SCOPED: &[&str] = &["/api/v1/notifications/", "/api/v1/dns-providers/"];
    let is_probe = PROBE_EXACT.contains(&path)
        || (path.ends_with("/test")
            && PROBE_SCOPED.iter().any(|prefix| path.starts_with(prefix)));
    PREFIXES.iter().any(|p| path.starts_with(p)) || EXACT.contains(&path) || is_probe
}

/// Axum middleware for the follower read-only gate (Story 9.4 AC #10):
/// on a follower without an active break-glass window, a configuration
/// mutation answers `409 Conflict` naming the control plane. Runs
/// after `authorize`, so an unauthorised caller still gets 401/403
/// first and learns nothing about the fleet role.
pub async fn follower_read_only(req: Request, next: Next) -> Result<Response, ApiError> {
    // Fails CLOSED on a missing extension, like `authorize` above. The
    // router installs it outside this layer today, so the branch is
    // unreachable; treating it as "not a follower" would make a
    // re-layering silently disable the whole gate, with no error and
    // no test failure.
    let state = req.extensions().get::<AppState>().ok_or_else(|| {
        ApiError::Internal("application state missing in the follower read-only middleware".into())
    })?;
    if let ClusterRuntime::Follower(follower) = &state.cluster {
        if !follower.break_glass_active() && !follower_local_request(req.method(), req.uri().path())
        {
            return Err(ApiError::Conflict(format!(
                "this node is a follower of {}: configuration is owned by the control \
                 plane; change it there, or open a break-glass window \
                 (POST /api/v1/cluster/break-glass) for local emergency changes",
                follower.control_plane
            )));
        }
    }
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    #[test]
    fn follower_gate_keeps_the_read_like_posts_reachable() {
        for (method, path) in [
            (Method::GET, "/api/v1/routes"),
            (Method::POST, "/api/v1/auth/login"),
            (Method::POST, "/api/v1/users"),
            (Method::DELETE, "/api/v1/users/u1"),
            (Method::POST, "/api/v1/cluster/leave"),
            (Method::POST, "/api/v1/cluster/break-glass"),
            (Method::POST, "/api/v1/validate/mtls-pem"),
            (Method::POST, "/api/v1/config/export"),
            (Method::POST, "/api/v1/config/import/preview"),
            (Method::POST, "/api/v1/loadtest/start/c1"),
            (Method::POST, "/api/v1/loadtest/abort"),
            (Method::POST, "/api/v1/notifications/n1/test"),
            (Method::POST, "/api/v1/dns-providers/d1/test"),
        ] {
            assert!(follower_local_request(&method, path), "{method} {path}");
        }
        for (method, path) in [
            (Method::POST, "/api/v1/routes"),
            (Method::PUT, "/api/v1/routes/r1"),
            (Method::DELETE, "/api/v1/backends/b1"),
            (Method::PUT, "/api/v1/settings"),
            (Method::POST, "/api/v1/config/import"),
            (Method::POST, "/api/v1/waf/rules/custom"),
            (Method::POST, "/api/v1/certificates"),
            // Fleet mutations are the control plane's, whatever node
            // the request lands on; the handler's own 409 is the
            // second line, not the first.
            (Method::POST, "/api/v1/cluster/tokens"),
            (Method::DELETE, "/api/v1/cluster/tokens/t1"),
            (Method::POST, "/api/v1/cluster/nodes/n1/activate"),
            (Method::DELETE, "/api/v1/cluster/nodes/n1"),
            (Method::POST, "/api/v1/cluster/bans"),
        ] {
            assert!(!follower_local_request(&method, path), "{method} {path}");
        }
    }

    /// The dashboard hides a control on a follower unless this
    /// function admits its path (Story 9.7 D19). Those two facts live
    /// in different languages with nothing between them, and one
    /// manual review pass across the dashboard found four controls
    /// hidden from a follower that this list admits, so the seam does
    /// not hold on review alone.
    ///
    /// This pins the direction that fails silently: the list is
    /// narrowed, the dashboard keeps offering the control, and an
    /// operator presses a button that answers 409 during an incident.
    ///
    /// It does NOT catch the reverse, a `.svelte` file switching from
    /// `canWriteRole` to `canWrite`. Catching that needs the allow-list
    /// served as data, which is not worth building for six paths.
    #[test]
    fn every_path_the_dashboard_offers_on_a_follower_is_still_admitted() {
        for (method, path, offered_by) in [
            // routes/LoadTest.svelte, `$canWriteRole` on Run
            (Method::POST, "/api/v1/loadtest/start/c1", "LoadTest.svelte"),
            // routes/LoadTest.svelte, `$canWriteRole` on Abort
            (Method::POST, "/api/v1/loadtest/abort", "LoadTest.svelte"),
            // components/settings-tabs/ExportImportTab.svelte,
            // `$canWriteRole` on Download TOML
            (Method::POST, "/api/v1/config/export", "ExportImportTab.svelte"),
            // routes/Security.svelte, `$isSuperAdminRole` on Verify
            (Method::POST, "/api/v1/audit/verify", "Security.svelte"),
            // routes/Settings.svelte, `$isSuperAdminRole` on the tab
            (Method::POST, "/api/v1/users", "Settings.svelte"),
            // routes/Cluster.svelte, `superAdminRole` on the two ways
            // out of read-only mode
            (Method::POST, "/api/v1/cluster/break-glass", "Cluster.svelte"),
            (Method::DELETE, "/api/v1/cluster/break-glass", "Cluster.svelte"),
            (Method::POST, "/api/v1/cluster/leave", "Cluster.svelte"),
        ] {
            assert!(
                follower_local_request(&method, path),
                "{offered_by} offers {method} {path} on a follower, but this gate now refuses it: either restore the path or change that control to `canWrite` / `isSuperAdmin`"
            );
        }
    }

    #[test]
    fn break_glass_is_super_admin() {
        assert_eq!(
            required_role(&Method::POST, "/api/v1/cluster/break-glass"),
            Role::SuperAdmin
        );
        assert_eq!(
            required_role(&Method::GET, "/api/v1/cluster/break-glass"),
            Role::SuperAdmin
        );
        // Operator since the Epic 9 close (#69): both name which node
        // runs what.
        assert_eq!(
            required_role(&Method::GET, "/api/v1/cluster/drift"),
            Role::Operator
        );
        assert_eq!(
            required_role(&Method::GET, "/api/v1/cluster/replication"),
            Role::Operator
        );
    }

    #[test]
    fn cluster_endpoints_follow_the_story_9_3_floors() {
        assert_eq!(
            required_role(&Method::GET, "/api/v1/cluster/tokens"),
            Role::SuperAdmin
        );
        assert_eq!(
            required_role(&Method::POST, "/api/v1/cluster/tokens"),
            Role::SuperAdmin
        );
        assert_eq!(
            required_role(&Method::DELETE, "/api/v1/cluster/tokens/abc"),
            Role::SuperAdmin
        );
        assert_eq!(
            required_role(&Method::POST, "/api/v1/cluster/leave"),
            Role::SuperAdmin
        );
        // Fleet reads are Operator since the Epic 9 close (#69); the
        // status the header badge is built from stays Viewer.
        for path in [
            "/api/v1/cluster/nodes",
            "/api/v1/cluster/nodes/abc",
            "/api/v1/cluster/replication",
            "/api/v1/cluster/drift",
            "/api/v1/cluster/logs",
            "/api/v1/cluster/waf-events",
            "/api/v1/cluster/bans",
        ] {
            assert_eq!(required_role(&Method::GET, path), Role::Operator, "{path}");
        }
        assert_eq!(
            required_role(&Method::GET, "/api/v1/cluster/status"),
            Role::Viewer
        );
        assert_eq!(
            required_role(&Method::POST, "/api/v1/cluster/nodes/abc/activate"),
            Role::SuperAdmin
        );
        assert_eq!(
            required_role(&Method::DELETE, "/api/v1/cluster/nodes/abc"),
            Role::SuperAdmin
        );
    }

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
    fn audit_endpoints_are_carved_out_of_viewer_reads() {
        assert_eq!(required_role(&Method::GET, "/api/v1/audit"), Role::Operator);
        assert_eq!(
            required_role(&Method::GET, "/api/v1/audit/verify"),
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
