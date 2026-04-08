#![deny(clippy::all)]

pub mod acme;
pub mod auth;
pub mod backends;
pub mod cache;
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
pub mod server;
pub mod settings;
pub mod sla;
pub mod status;
pub mod system;
pub mod waf;
pub mod workers;

#[cfg(test)]
mod tests;
