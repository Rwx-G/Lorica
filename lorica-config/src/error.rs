use thiserror::Error;

/// Error type returned by every fallible operation in `lorica-config`.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Underlying SQLite error (constraint violation, IO at the DB
    /// layer, malformed schema, ...). Auto-converted from
    /// `rusqlite::Error`.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// JSON / TOML (de)serialization failure, including
    /// `toml::ser::Error` from `export_to_toml` and `toml::de::Error`
    /// from `parse_toml`.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Business-rule violation that the store enforces above the SQL
    /// layer: hostname uniqueness, `host:port` shape on a backend
    /// address, encryption/decryption failure, an enum string that
    /// does not parse, or a malformed encrypted payload.
    #[error("validation error: {0}")]
    Validation(String),

    /// Update or delete targeted a row that does not exist. The string
    /// payload carries the entity name and ID, e.g. `route abc123`.
    #[error("not found: {0}")]
    NotFound(String),

    /// Filesystem error (key file, export/import file, ...).
    /// Auto-converted from `std::io::Error`.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience alias: `Result<T, ConfigError>`.
pub type Result<T> = std::result::Result<T, ConfigError>;
