#![deny(clippy::all)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

//! REST management API for the Lorica reverse proxy.
//!
//! Hosts the axum router, the [`AppState`] shared with handlers, the
//! ACME / mTLS provisioning logic, the forward-auth and WAF management
//! endpoints, and the Prometheus `/metrics` surface. The proxy hot
//! path lives in the top-level `lorica` crate; this crate is the
//! management plane only.
//!
//! [`AppState`]: crate::server::AppState

pub mod acme;
pub mod ai_crawlers;
pub mod audit;
pub mod auth;
pub mod backends;
pub mod ban;
pub mod cache;
pub mod cert_export;
pub mod certificates;
pub mod config;
pub mod connections;
pub mod db;
pub mod dns_providers;
pub mod error;
pub mod loadtest;
pub mod log_sinks;
pub mod log_store;
pub mod management_tls;
pub mod log_writer;
pub mod logs;
pub mod metrics;
pub mod middleware;
pub mod password_policy;
pub mod probes;
pub mod routes;
/// Axum router + shared `AppState` construction.
pub mod server;
pub mod settings;
pub mod sla;
pub mod status;
pub mod system;
/// Hot binary-upgrade verification + staging (Story 8.4).
pub mod upgrade;
pub mod users;
pub mod waf;
pub mod workers;

#[cfg(test)]
mod tests;
