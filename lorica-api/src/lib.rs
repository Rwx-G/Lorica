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
pub mod auth;
pub mod backends;
pub mod cache;
pub mod cert_export;
pub mod certificates;
pub mod config;
pub mod connections;
pub mod dns_providers;
pub mod error;
pub mod loadtest;
pub mod log_store;
pub mod logs;
pub mod metrics;
pub mod middleware;
pub mod probes;
pub mod routes;
/// Axum router + shared `AppState` construction.
pub mod server;
pub mod settings;
pub mod sla;
pub mod status;
pub mod system;
pub mod waf;
pub mod workers;

#[cfg(test)]
mod tests;
