use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::middleware;
use axum::routing::{delete, get, post, put};
use axum::Router;
use tokio::sync::Mutex;
use tracing::info;

use crate::logs::LogBuffer;
use crate::middleware::auth::{require_auth, SessionStore};
use crate::middleware::rate_limit::RateLimiter;
use crate::system::SystemCache;

/// Shared application state holding the config store, log buffer, and start time.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Mutex<lorica_config::ConfigStore>>,
    pub log_buffer: Arc<LogBuffer>,
    pub system_cache: Arc<Mutex<SystemCache>>,
    pub started_at: Instant,
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
        .route("/api/v1/system", get(crate::system::get_system))
        .route("/api/v1/config/export", post(crate::config::export_config))
        .route("/api/v1/config/import", post(crate::config::import_config))
        .layer(middleware::from_fn(require_auth));

    // Dashboard routes serve embedded frontend assets (SPA with fallback)
    let dashboard_routes = lorica_dashboard::router();

    Router::new()
        .merge(auth_routes)
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
