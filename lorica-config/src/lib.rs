#![deny(clippy::all)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Configuration state and persistence for the Lorica reverse proxy.
//!
//! Hosts the SQLite-backed [`ConfigStore`], the serializable [`models`]
//! that describe routes / backends / certificates / notifications, the
//! typed [`ConfigError`], and the crypto primitives used to protect
//! sensitive fields at rest.

/// Cross-crate single source of truth for the AI / LLM crawler
/// built-in registry data and baseline-UA corpus (Story 8.2).
pub mod ai_crawler_registry;
/// AES-GCM encryption primitives for sensitive fields at rest.
pub mod crypto;
/// Typed diff between two configuration snapshots.
pub mod diff;
/// `ConfigError` and the crate-wide `Result` alias.
pub mod error;
/// TOML / JSON dump of the current config state.
pub mod export;
/// Import path complementing `export` (schema-validated, round-trip).
pub mod import;
/// Serialisable model types (routes, backends, certs, settings, ...).
pub mod models;
/// SQLite-backed `ConfigStore` and its per-table helper modules.
pub mod store;

#[cfg(test)]
mod tests;

pub use crypto::EncryptionKey;
pub use error::{ConfigError, Result};
pub use store::bot_stash::{BotStashEntry, BotStashInsertOutcome};
pub use store::ConfigStore;
