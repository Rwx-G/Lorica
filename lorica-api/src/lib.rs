#![deny(clippy::all)]

pub mod auth;
pub mod backends;
pub mod certificates;
pub mod config;
pub mod error;
pub mod logs;
pub mod middleware;
pub mod routes;
pub mod server;
pub mod status;
pub mod system;

#[cfg(test)]
mod tests;
