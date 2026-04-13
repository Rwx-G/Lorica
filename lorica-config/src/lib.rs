#![deny(clippy::all)]
#![deny(unsafe_code)]

//! Configuration state and persistence for the Lorica reverse proxy.
//!
//! Hosts the SQLite-backed [`ConfigStore`], the serializable [`models`]
//! that describe routes / backends / certificates / notifications, the
//! typed [`ConfigError`], and the crypto primitives used to protect
//! sensitive fields at rest.

pub mod crypto;
pub mod diff;
pub mod error;
pub mod export;
pub mod import;
pub mod models;
pub mod store;

#[cfg(test)]
mod tests;

pub use crypto::EncryptionKey;
pub use error::{ConfigError, Result};
pub use store::ConfigStore;
