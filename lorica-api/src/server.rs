use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Instant;

use axum::middleware;
use axum::routing::{delete, get, post, put};
use axum::Router;
use tokio::sync::{watch, Mutex};
use tracing::info;

use crate::logs::LogBuffer;
use crate::middleware::auth::{require_auth, SessionStore};
use crate::middleware::rate_limit::RateLimiter;
use crate::system::SystemCache;
use crate::workers::WorkerMetrics;

/// Shared application state holding the config store, log buffer, and start time.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Mutex<lorica_config::ConfigStore>>,
    pub log_buffer: Arc<LogBuffer>,
    pub system_cache: Arc<Mutex<SystemCache>>,
    pub active_connections: Arc<AtomicU64>,
    pub started_at: Instant,
    /// Sender that signals the proxy engine to reload its configuration.
    /// Incremented on each mutation. `None` in tests or when no proxy is running.
    pub config_reload_tx: Option<watch::Sender<u64>>,
    /// Per-worker heartbeat metrics. `None` in single-process mode.
    pub worker_metrics: Option<Arc<WorkerMetrics>>,
    /// WAF event ring buffer. `None` if WAF engine not initialized.
    pub waf_event_buffer: Option<Arc<std::sync::Mutex<VecDeque<lorica_waf::WafEvent>>>>,
    /// WAF engine reference for rule management. `None` if not initialized.
    pub waf_engine: Option<Arc<lorica_waf::WafEngine>>,
    /// Number of loaded WAF rules.
    pub waf_rule_count: Option<usize>,
    /// ACME HTTP-01 challenge store.
    pub acme_challenge_store: Option<crate::acme::AcmeChallengeStore>,
}

impl AppState {
    /// Signal the proxy engine to reload its configuration from the database.
    pub fn notify_config_changed(&self) {
        if let Some(tx) = &self.config_reload_tx {
            let next = *tx.borrow() + 1;
            let _ = tx.send(next);
        }
    }
}

/// Build the axum router with all API routes.
pub fn build_router(
    state: AppState,
    session_store: SessionStore,
    rate_limiter: RateLimiter,
) -> Router {
    // Public routes (no auth required)
    let auth_routes = Router::new()
        .route("/api/v1/auth/login", post(crate::auth::login))
        .route("/api/v1/auth/logout", post(crate::auth::logout));

    // Metrics and ACME challenge endpoints (no auth)
    let metrics_routes = Router::new()
        .route("/metrics", get(crate::metrics::get_metrics))
        .route(
            "/.well-known/acme-challenge/:token",
            get(crate::acme::serve_challenge),
        );

    // Protected routes (auth required)
    let protected_routes = Router::new()
        .route("/api/v1/auth/password", put(crate::auth::change_password))
        .route("/api/v1/routes", get(crate::routes::list_routes))
        .route("/api/v1/routes", post(crate::routes::create_route))
        .route("/api/v1/routes/:id", get(crate::routes::get_route))
        .route("/api/v1/routes/:id", put(crate::routes::update_route))
        .route("/api/v1/routes/:id", delete(crate::routes::delete_route))
        .route("/api/v1/backends", get(crate::backends::list_backends))
        .route("/api/v1/backends", post(crate::backends::create_backend))
        .route("/api/v1/backends/:id", get(crate::backends::get_backend))
        .route("/api/v1/backends/:id", put(crate::backends::update_backend))
        .route(
            "/api/v1/backends/:id",
            delete(crate::backends::delete_backend),
        )
        .route(
            "/api/v1/certificates",
            get(crate::certificates::list_certificates),
        )
        .route(
            "/api/v1/certificates",
            post(crate::certificates::create_certificate),
        )
        .route(
            "/api/v1/certificates/self-signed",
            post(crate::certificates::generate_self_signed),
        )
        .route(
            "/api/v1/certificates/:id",
            get(crate::certificates::get_certificate),
        )
        .route(
            "/api/v1/certificates/:id",
            put(crate::certificates::update_certificate),
        )
        .route(
            "/api/v1/certificates/:id",
            delete(crate::certificates::delete_certificate),
        )
        .route("/api/v1/status", get(crate::status::get_status))
        .route("/api/v1/logs", get(crate::logs::get_logs))
        .route("/api/v1/logs", delete(crate::logs::clear_logs))
        .route("/api/v1/logs/ws", get(crate::logs::logs_ws))
        .route("/api/v1/system", get(crate::system::get_system))
        .route("/api/v1/workers", get(crate::workers::get_workers))
        .route("/api/v1/config/export", post(crate::config::export_config))
        .route("/api/v1/config/import", post(crate::config::import_config))
        .route(
            "/api/v1/config/import/preview",
            post(crate::config::import_preview),
        )
        .route("/api/v1/settings", get(crate::settings::get_settings))
        .route("/api/v1/settings", put(crate::settings::update_settings))
        .route(
            "/api/v1/notifications",
            get(crate::settings::list_notifications),
        )
        .route(
            "/api/v1/notifications",
            post(crate::settings::create_notification),
        )
        .route(
            "/api/v1/notifications/:id",
            put(crate::settings::update_notification),
        )
        .route(
            "/api/v1/notifications/:id",
            delete(crate::settings::delete_notification),
        )
        .route(
            "/api/v1/notifications/:id/test",
            post(crate::settings::test_notification),
        )
        .route(
            "/api/v1/preferences",
            get(crate::settings::list_preferences),
        )
        .route(
            "/api/v1/preferences/:id",
            put(crate::settings::update_preference),
        )
        .route(
            "/api/v1/preferences/:id",
            delete(crate::settings::delete_preference),
        )
        .route("/api/v1/waf/events", get(crate::waf::get_waf_events))
        .route("/api/v1/waf/events", delete(crate::waf::clear_waf_events))
        .route("/api/v1/waf/stats", get(crate::waf::get_waf_stats))
        .route(
            "/api/v1/waf/blocklist",
            get(crate::waf::get_blocklist_status),
        )
        .route(
            "/api/v1/waf/blocklist",
            put(crate::waf::toggle_blocklist),
        )
        .route(
            "/api/v1/waf/blocklist/reload",
            post(crate::waf::reload_blocklist),
        )
        .route(
            "/api/v1/acme/provision",
            post(crate::acme::provision_certificate),
        )
        .route(
            "/api/v1/acme/provision-dns",
            post(crate::acme::provision_certificate_dns),
        )
        .route("/api/v1/waf/rules", get(crate::waf::get_waf_rules))
        .route(
            "/api/v1/waf/rules/custom",
            get(crate::waf::list_custom_rules),
        )
        .route(
            "/api/v1/waf/rules/custom",
            post(crate::waf::create_custom_rule),
        )
        .route(
            "/api/v1/waf/rules/custom/:id",
            delete(crate::waf::delete_custom_rule),
        )
        .route(
            "/api/v1/waf/rules/:id",
            put(crate::waf::toggle_waf_rule),
        )
        .layer(middleware::from_fn(require_auth));

    // Dashboard routes serve embedded frontend assets (SPA with fallback)
    let dashboard_routes = lorica_dashboard::router();

    Router::new()
        .merge(auth_routes)
        .merge(metrics_routes)
        .merge(protected_routes)
        .merge(dashboard_routes)
        .layer(axum::Extension(state))
        .layer(axum::Extension(session_store))
        .layer(axum::Extension(rate_limiter))
}

/// Start the API server on localhost only.
pub async fn start_server(
    port: u16,
    state: AppState,
    session_store: SessionStore,
    rate_limiter: RateLimiter,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = build_router(state, session_store, rate_limiter);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    info!(port = port, "API server listening on localhost only");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
