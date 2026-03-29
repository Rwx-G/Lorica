#![deny(clippy::all)]

pub mod auth;
pub mod backends;
pub mod certificates;
pub mod config;
pub mod error;
pub mod middleware;
pub mod routes;
pub mod server;
pub mod status;

#[cfg(test)]
mod tests;
