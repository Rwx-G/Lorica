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
    /// address, a cap over its limit, a reference naming no row.
    ///
    /// The server understood the write and refuses it on its merits,
    /// so `lorica-api` answers 422 for it. A payload the server could
    /// not READ is [`ConfigError::Malformed`] and answers 400.
    #[error("validation error: {0}")]
    Validation(String),

    /// A stored or supplied payload could not be PARSED: a JSON column
    /// that is not JSON, an encrypted blob of the wrong length, a
    /// timestamp that is not a timestamp.
    ///
    /// Distinct from [`ConfigError::Validation`] because the two answer
    /// different questions, and the API turns that difference into a
    /// status code: the server could not read the input (400) versus
    /// the server read it perfectly and refuses it on its merits (422).
    /// See `ApiError`'s 400-versus-422 rule in `lorica-api`.
    #[error("malformed input: {0}")]
    Malformed(String),

    /// A value this process wrote back cannot be read: the database is
    /// corrupt or was written by a newer schema.
    ///
    /// The third member of the family, and the one that is not about
    /// the caller at all. [`ConfigError::Validation`] and
    /// [`ConfigError::Malformed`] both answer "what you sent is wrong",
    /// with 422 and 400. This one answers "what WE stored is wrong": a
    /// JSON column this same code serialised no longer deserialises, so
    /// either the file is damaged or a newer Lorica wrote a shape this
    /// one cannot read. Nothing the caller changes about the request
    /// makes it succeed, which is the definition of a 500, and reporting
    /// it as a client mistake sent operators hunting through their own
    /// payloads for a fault in the node.
    #[error("corrupt stored value: {0}")]
    Corrupt(String),

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
