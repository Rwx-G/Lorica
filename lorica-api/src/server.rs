use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;

use axum::middleware;
use axum::routing::{delete, get, post, put};
use axum::Router;
use http::Method;
use tokio::sync::{watch, Mutex};
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

use crate::logs::LogBuffer;
use crate::middleware::auth::{require_auth, SessionStore};
use crate::middleware::rate_limit::RateLimiter;
use crate::system::SystemCache;
use crate::workers::WorkerMetrics;

/// Type-erased metrics refresher closure (WPAR-7 pull-on-scrape).
///
/// Returning a `BoxFuture` keeps `lorica-api` decoupled from the
/// supervisor-side implementation (which lives in the `lorica`
/// binary and depends on `lorica-command`). The supervisor wires
/// this closure at startup with access to the per-worker RPC
/// endpoints, the AggregatedMetrics handle, and a dedup lock; the
/// /metrics handler awaits it with a bounded overall timeout.
pub type MetricsRefresher =
    Arc<dyn Fn() -> futures_util::future::BoxFuture<'static, ()> + Send + Sync>;

/// Shared application state holding the config store, log buffer, and start time.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Mutex<lorica_config::ConfigStore>>,
    pub log_buffer: Arc<LogBuffer>,
    pub system_cache: Arc<Mutex<SystemCache>>,
    pub active_connections: Arc<AtomicU64>,
    pub started_at: Instant,
    /// Lorica data directory (`--data-dir`, typically `/var/lib/lorica`).
    /// Used by `get_system` to report the disk usage of the filesystem
    /// that actually holds Lorica's SQLite DB, TLS archives, and MMDB
    /// files - which is what an operator cares about, distinct from
    /// the root filesystem.
    pub data_dir: PathBuf,
    /// HTTP proxy port (for load test URL construction).
    pub http_port: u16,
    /// HTTPS proxy port (for load test URL construction).
    pub https_port: u16,
    /// Sender that signals the proxy engine to reload its configuration.
    /// Incremented on each mutation. `None` in tests or when no proxy is running.
    pub config_reload_tx: Option<watch::Sender<u64>>,
    /// Per-worker heartbeat metrics. `None` in single-process mode.
    pub worker_metrics: Option<Arc<WorkerMetrics>>,
    /// WAF event ring buffer. `None` if WAF engine not initialized.
    pub waf_event_buffer: Option<Arc<parking_lot::Mutex<VecDeque<lorica_waf::WafEvent>>>>,
    /// WAF engine reference for rule management. `None` if not initialized.
    pub waf_engine: Option<Arc<lorica_waf::WafEngine>>,
    /// Number of loaded WAF rules.
    pub waf_rule_count: Option<usize>,
    /// ACME HTTP-01 challenge store.
    pub acme_challenge_store: Option<crate::acme::AcmeChallengeStore>,
    /// Pending manual DNS-01 challenges (two-step flow).
    pub pending_dns_challenges: crate::acme::PendingDnsChallenges,
    /// Passive SLA metrics collector.
    pub sla_collector: Option<Arc<lorica_bench::SlaCollector>>,
    /// Load test engine.
    pub load_test_engine: Option<Arc<lorica_bench::LoadTestEngine>>,
    /// Cache hit counter shared with the proxy engine.
    pub cache_hits: Option<Arc<AtomicU64>>,
    /// Cache miss counter shared with the proxy engine.
    pub cache_misses: Option<Arc<AtomicU64>>,
    /// Ban list shared with the proxy engine: IP -> (ban timestamp, ban duration in seconds).
    pub ban_list: Option<Arc<DashMap<String, (std::time::Instant, u64)>>>,
    /// Cache backend for purging cached entries.
    pub cache_backend: Option<&'static lorica_cache::MemCache>,
    /// EWMA scores per backend address (microseconds). Shared with the proxy engine.
    pub ewma_scores: Option<Arc<parking_lot::RwLock<HashMap<String, f64>>>>,
    /// Per-backend active connection counters. Shared with the proxy engine.
    /// `None` in supervisor mode (use aggregated_metrics instead).
    pub backend_connections: Option<Arc<crate::connections::BackendConnections>>,
    /// Notification event history ring buffer (shared with NotifyDispatcher).
    pub notification_history: Option<Arc<parking_lot::Mutex<VecDeque<lorica_notify::AlertEvent>>>>,
    /// Persistent access log store (SQLite). `None` in tests or worker mode.
    pub log_store: Option<Arc<crate::log_store::LogStore>>,
    /// Aggregated proxy metrics from worker processes. `None` in single-process mode.
    pub aggregated_metrics: Option<Arc<crate::workers::AggregatedMetrics>>,
    /// Pipelined metrics refresh closure (WPAR-7 pull-on-scrape).
    /// `Some` in worker mode when the supervisor has wired the
    /// `MetricsPullCoordinator`; `None` in single-process mode or
    /// when the supervisor has not yet registered any worker RPC
    /// endpoint. Called from the `/metrics` handler before reading
    /// `aggregated_metrics` so Prometheus scrapes see sub-second
    /// fresh data. Internally dedups: concurrent scrapes within a
    /// short window collapse into a single supervisor fan-out.
    pub metrics_refresher: Option<MetricsRefresher>,
    /// Tracker for background tasks that must be drained on graceful
    /// shutdown (ACME polling, session-store writes, WAF refresh,
    /// backend drain watchdog, etc.). The supervisor shutdown path
    /// calls `task_tracker.close(); task_tracker.wait().await` so
    /// in-flight work completes rather than being dropped mid-step.
    /// Cheap to clone (internal `Arc`).
    pub task_tracker: tokio_util::task::TaskTracker,
}

impl AppState {
    /// Signal the proxy engine to reload its configuration from the database.
    pub fn notify_config_changed(&self) {
        if let Some(tx) = &self.config_reload_tx {
            let next = *tx.borrow() + 1;
            let _ = tx.send(next);
        }
    }

    /// Rotate the bot-protection HMAC secret (v1.4.0 Epic 3,
    /// follow-up to story 3.5a). Called from every certificate
    /// install / renew success path — the design doc calls for
    /// "rotate the secret on every cert renewal so cookie
    /// lifetime is capped at the cert TTL".
    ///
    /// Generates fresh 32 bytes via `OsRng`, persists the hex
    /// form to `GlobalSettings.bot_hmac_secret_hex`, and leaves
    /// the actual in-memory swap to the next
    /// `apply_bot_secret_from_store` invocation (which fires on
    /// every subsequent `reload_proxy_config*`, triggered by the
    /// cert-save site's own `notify_config_changed` call). Two
    /// consecutive writes would double-rotate in a tight renewal
    /// loop, which is fine — the user just solves the challenge
    /// once more.
    ///
    /// Tolerates failures: a DB write error is `warn!`-logged
    /// and silently ignored so a bot-protection secret issue
    /// cannot block a certificate renewal (cert renewal is the
    /// higher-priority operation).
    pub async fn rotate_bot_hmac_on_cert_event(&self) {
        let new_bytes: [u8; 32] = {
            use rand::RngCore;
            let mut out = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut out);
            out
        };
        let mut hex_buf = String::with_capacity(64);
        for b in new_bytes.iter() {
            hex_buf.push_str(&format!("{b:02x}"));
        }
        let s = self.store.lock().await;
        match s.get_global_settings() {
            Ok(mut cur) => {
                cur.bot_hmac_secret_hex = hex_buf;
                if let Err(e) = s.update_global_settings(&cur) {
                    tracing::warn!(
                        error = %e,
                        "failed to persist rotated bot HMAC secret; previous secret stays live"
                    );
                    return;
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "failed to read global settings for bot HMAC rotation"
                );
                return;
            }
        }
        drop(s);
        tracing::info!(
            "bot-protection HMAC secret rotated on cert event (outstanding verdict cookies invalidated)"
        );
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
        .route(
            "/api/v1/validate/mtls-pem",
            post(crate::routes::validate_mtls_pem),
        )
        .route(
            "/api/v1/validate/forward-auth",
            post(crate::routes::validate_forward_auth),
        )
        .route(
            "/api/v1/cache/routes/:id",
            delete(crate::cache::purge_route_cache),
        )
        .route("/api/v1/cache/stats", get(crate::cache::get_cache_stats))
        .route("/api/v1/bans", get(crate::cache::list_bans))
        .route("/api/v1/bans/:ip", delete(crate::cache::delete_ban))
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
        .route(
            "/api/v1/certificates/:id/download",
            get(crate::certificates::download_certificate),
        )
        .route(
            "/api/v1/cert-export/acls",
            get(crate::routes::cert_export::list_acls),
        )
        .route(
            "/api/v1/cert-export/acls",
            post(crate::routes::cert_export::create_acl),
        )
        .route(
            "/api/v1/cert-export/acls/:id",
            delete(crate::routes::cert_export::delete_acl),
        )
        .route(
            "/api/v1/cert-export/reapply",
            post(crate::routes::cert_export::reapply),
        )
        .route("/api/v1/status", get(crate::status::get_status))
        .route("/api/v1/logs", get(crate::logs::get_logs))
        .route("/api/v1/logs", delete(crate::logs::clear_logs))
        .route("/api/v1/logs/export", get(crate::logs::export_logs))
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
            "/api/v1/settings/otel/test",
            post(crate::settings::test_otel_connection),
        )
        .route(
            "/api/v1/dns-providers",
            get(crate::dns_providers::list_dns_providers),
        )
        .route(
            "/api/v1/dns-providers",
            post(crate::dns_providers::create_dns_provider),
        )
        .route(
            "/api/v1/dns-providers/:id",
            put(crate::dns_providers::update_dns_provider),
        )
        .route(
            "/api/v1/dns-providers/:id",
            delete(crate::dns_providers::delete_dns_provider),
        )
        .route(
            "/api/v1/dns-providers/:id/test",
            post(crate::dns_providers::test_dns_provider),
        )
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
            "/api/v1/notifications/history",
            get(crate::settings::notification_history),
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
        .route("/api/v1/waf/blocklist", put(crate::waf::toggle_blocklist))
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
        .route(
            "/api/v1/acme/provision-dns-manual",
            post(crate::acme::provision_dns_manual),
        )
        .route(
            "/api/v1/acme/provision-dns-manual/check",
            post(crate::acme::check_dns_manual),
        )
        .route(
            "/api/v1/acme/provision-dns-manual/confirm",
            post(crate::acme::provision_dns_manual_confirm),
        )
        .route(
            "/api/v1/certificates/:id/renew",
            post(crate::acme::renew_certificate),
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
        .route("/api/v1/waf/rules/:id", put(crate::waf::toggle_waf_rule))
        .route("/api/v1/sla/overview", get(crate::sla::get_sla_overview))
        .route("/api/v1/sla/routes/:id", get(crate::sla::get_route_sla))
        .route(
            "/api/v1/sla/routes/:id/buckets",
            get(crate::sla::get_route_sla_buckets),
        )
        .route(
            "/api/v1/sla/routes/:id/config",
            get(crate::sla::get_sla_config),
        )
        .route(
            "/api/v1/sla/routes/:id/config",
            put(crate::sla::update_sla_config),
        )
        .route(
            "/api/v1/sla/routes/:id/export",
            get(crate::sla::export_sla_data),
        )
        .route(
            "/api/v1/sla/routes/:id/data",
            delete(crate::sla::clear_route_sla),
        )
        .route(
            "/api/v1/sla/routes/:id/active",
            get(crate::probes::get_active_sla),
        )
        .route("/api/v1/probes", get(crate::probes::list_probes))
        .route("/api/v1/probes", post(crate::probes::create_probe))
        .route(
            "/api/v1/probes/route/:route_id",
            get(crate::probes::list_probes_for_route),
        )
        .route(
            "/api/v1/probes/:id/history",
            get(crate::probes::probe_history),
        )
        .route("/api/v1/probes/:id", put(crate::probes::update_probe))
        .route("/api/v1/probes/:id", delete(crate::probes::delete_probe))
        .route(
            "/api/v1/loadtest/configs",
            get(crate::loadtest::list_configs),
        )
        .route(
            "/api/v1/loadtest/configs",
            post(crate::loadtest::create_config),
        )
        .route(
            "/api/v1/loadtest/configs/:id",
            put(crate::loadtest::update_config),
        )
        .route(
            "/api/v1/loadtest/configs/:id",
            delete(crate::loadtest::delete_config),
        )
        .route(
            "/api/v1/loadtest/configs/:id/clone",
            post(crate::loadtest::clone_config),
        )
        .route(
            "/api/v1/loadtest/start/:config_id",
            post(crate::loadtest::start_test),
        )
        .route(
            "/api/v1/loadtest/start/:config_id/confirm",
            post(crate::loadtest::start_test_confirmed),
        )
        .route("/api/v1/loadtest/status", get(crate::loadtest::get_status))
        .route("/api/v1/loadtest/ws", get(crate::loadtest::loadtest_ws))
        .route("/api/v1/loadtest/abort", post(crate::loadtest::abort_test))
        .route(
            "/api/v1/loadtest/results/:config_id",
            get(crate::loadtest::get_results),
        )
        .route(
            "/api/v1/loadtest/results/:config_id/compare",
            get(crate::loadtest::compare_results),
        )
        .layer(middleware::from_fn(require_auth));

    // Dashboard routes serve embedded frontend assets (SPA with fallback)
    let dashboard_routes = lorica_dashboard::router();

    Router::new()
        .merge(auth_routes)
        .merge(metrics_routes)
        .merge(protected_routes)
        .merge(dashboard_routes)
        .layer(
            CorsLayer::new()
                // Dashboard is served from the same origin as the API
                // (same port, same host). Restrict CORS to same-origin
                // requests only. AllowOrigin::mirror_request reflects
                // the Origin header back so browsers allow the call
                // from any scheme://host:port that can reach the API
                // (typically https://localhost:9443 or the operator's
                // custom domain). This is tighter than Any because it
                // only applies when an Origin is actually sent.
                .allow_origin(tower_http::cors::AllowOrigin::mirror_request())
                .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
                .allow_headers(Any),
        )
        .layer(axum::extract::DefaultBodyLimit::max(10 * 1024 * 1024)) // 10 MB
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
    let app = build_router(state, session_store, rate_limiter)
        .into_make_service_with_connect_info::<SocketAddr>();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    info!(port = port, "API server listening on localhost only");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
