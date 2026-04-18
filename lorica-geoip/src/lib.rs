// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! GeoIP country-code lookups for Lorica.
//!
//! Wraps the [`maxminddb`](https://crates.io/crates/maxminddb) reader
//! with an [`arc_swap::ArcSwapOption`] so the underlying `.mmdb` file
//! can be hot-swapped on a monthly refresh without blocking the proxy
//! request path. Lookups are a single `IpAddr -> Option<CountryCode>`
//! call; when no database is loaded (operator left the feature off)
//! the resolver returns `None` for everything and the caller treats
//! that as "do not apply GeoIP rules".
//!
//! ## Data source
//!
//! Lorica's default data source is [DB-IP Lite Country](https://db-ip.com/db/download/ip-to-country-lite)
//! (CC-BY 4.0, no account required, monthly refresh). The `.mmdb`
//! binary format is identical to MaxMind's commercial GeoLite2, so
//! operators who already have a MaxMind license can just swap the
//! file path via `GlobalSettings.geoip_db_path` without any other
//! changes. Attribution is satisfied by a note in the project
//! `NOTICE` + docs rather than on every 403 page.
//!
//! ## Error handling
//!
//! Load failures are typed via [`GeoIpError`] so the caller (the
//! supervisor's auto-update job in story 2.3) can distinguish a
//! temporary download failure from a corrupt file — the auto-update
//! job keeps serving the old DB on transient errors and only swaps
//! once a fresh copy has passed a sanity check.

pub mod asn;
pub mod updater;

pub use asn::{AsnDbStatus, AsnResolver};

/// Minimal abstraction over a resolver that loads an `.mmdb` file
/// from disk and validates it in-place. Used by the auto-update task
/// so the same downloader pipeline can refresh either a country DB
/// (`GeoIpResolver`) or an ASN DB (`AsnResolver`).
pub trait MmdbResolver: Send + Sync {
    /// Load the database at `path` into the live slot. Returns
    /// `GeoIpError` on parse / sanity-probe failure; the slot is left
    /// unchanged on error so the previously-loaded DB stays live.
    fn load_from_path(&self, path: &Path) -> Result<(), GeoIpError>;
}

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// ISO 3166-1 alpha-2 country code (two uppercase ASCII letters).
///
/// Stored as a newtype so the type system can distinguish a country
/// code from any other `String`. The inner value is always two ASCII
/// uppercase letters; [`CountryCode::new`] rejects anything else.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CountryCode(String);

impl CountryCode {
    /// Parse an ISO 3166-1 alpha-2 country code. Accepts lower- or
    /// upper-case hex, normalises to upper. Returns `None` for any
    /// string that is not exactly two ASCII letters.
    pub fn new(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.len() != 2 || !s.chars().all(|c| c.is_ascii_alphabetic()) {
            return None;
        }
        Some(Self(s.to_ascii_uppercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CountryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Typed errors for database load / lookup paths.
#[derive(Debug, Error)]
pub enum GeoIpError {
    #[error("database file not found or unreadable: {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("database file is malformed: {source}")]
    Parse {
        #[source]
        source: maxminddb::MaxMindDbError,
    },
    #[error("database sanity check failed: {0}")]
    SanityCheck(String),
}

/// Snapshot metadata exposed to the API / dashboard so operators can
/// tell whether the DB is fresh and how big it is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpDbStatus {
    /// Filesystem path the DB was loaded from (so the dashboard can
    /// show it for diagnostics).
    pub path: String,
    /// When this DB was last loaded into Lorica (UTC). Distinct from
    /// the DB's own build_epoch — a loaded DB may be months old on
    /// disk but freshly opened by Lorica on restart.
    pub loaded_at: DateTime<Utc>,
    /// Number of IPv4 + IPv6 prefixes the DB indexes. Rough proxy for
    /// DB quality; DB-IP Lite Country ships ~350k nodes.
    pub node_count: u32,
    /// Build epoch from the DB metadata (seconds since UNIX epoch).
    /// Lets the dashboard show "published 14 days ago".
    pub build_epoch: u64,
}

/// Hot-swappable GeoIP resolver. Holds zero or one live
/// [`maxminddb::Reader`] behind an `Arc` so concurrent request-path
/// lookups are lock-free. A reload (story 2.3's auto-update job)
/// constructs a fresh reader and publishes it atomically; in-flight
/// lookups on the old reader complete as usual.
pub struct GeoIpResolver {
    inner: ArcSwapOption<LoadedDb>,
}

struct LoadedDb {
    reader: maxminddb::Reader<Vec<u8>>,
    status: GeoIpDbStatus,
}

impl GeoIpResolver {
    /// Create a resolver with no DB loaded. `lookup_country` returns
    /// `None` until [`GeoIpResolver::load_from_path`] succeeds.
    pub fn empty() -> Self {
        Self {
            inner: ArcSwapOption::from(None),
        }
    }

    /// Open a `.mmdb` file and atomically replace the currently-loaded
    /// DB (if any). The file is read in full into memory (a
    /// ~3 MiB allocation for DB-IP Lite Country) so the resolver does
    /// not depend on the file staying present after `load_from_path`
    /// returns. Sanity-checked by looking up `8.8.8.8` and asserting
    /// the lookup returns a non-empty country code — rejects files
    /// that parse as `.mmdb` but index nothing useful (empty / broken
    /// / wrong database type).
    pub fn load_from_path<P: AsRef<Path>>(&self, path: P) -> Result<(), GeoIpError> {
        let path_ref = path.as_ref();
        let reader = maxminddb::Reader::open_readfile(path_ref).map_err(|e| match e {
            maxminddb::MaxMindDbError::Io(source) => GeoIpError::Io {
                path: path_ref.to_path_buf(),
                source,
            },
            other => GeoIpError::Parse { source: other },
        })?;

        // Sanity-check: look up a list of well-known public IPs and
        // a probe from the MaxMind `GeoIP2-Country-Test.mmdb` fixture
        // so the check passes on real production DBs (DB-IP / MaxMind
        // GeoLite2, which all index 8.8.8.8 / 1.1.1.1) AND on the
        // open-licensed test fixture we ship in `tests-e2e-docker/`
        // (which only indexes 214.78.120.0/22). Accept the DB as
        // valid if ANY of the probes resolves — a DB that parses as
        // `.mmdb` but returns None for every one of these is either
        // empty, the wrong database type, or corrupt in a way the
        // format parser missed.
        let sanity_probes: &[&str] = &[
            "8.8.8.8",      // Google DNS (US) — every real country DB
            "1.1.1.1",      // Cloudflare (AU) — fallback if GOOG is missing
            "214.78.120.5", // MaxMind GeoIP2-Country-Test fixture hit (US)
        ];
        let any_hit = sanity_probes
            .iter()
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .any(|ip| maxminddb_lookup_country(&reader, ip).is_some());
        if !any_hit {
            return Err(GeoIpError::SanityCheck(format!(
                "no sanity probe resolved to a country (tried {}); DB likely wrong type or empty",
                sanity_probes.join(", ")
            )));
        }

        let meta = reader.metadata.clone();
        let status = GeoIpDbStatus {
            path: path_ref.display().to_string(),
            loaded_at: Utc::now(),
            node_count: meta.node_count,
            build_epoch: meta.build_epoch,
        };

        self.inner
            .store(Some(Arc::new(LoadedDb { reader, status })));
        tracing::info!(
            path = %path_ref.display(),
            node_count = meta.node_count,
            build_epoch = meta.build_epoch,
            "GeoIP database loaded"
        );
        Ok(())
    }

    /// Drop the currently-loaded DB. Subsequent lookups return `None`
    /// until the next `load_from_path` succeeds. Used by the config
    /// reload path when the operator clears `GlobalSettings.geoip_db_path`.
    pub fn unload(&self) {
        self.inner.store(None);
    }

    /// Look up the country for an IP. Returns `None` when no DB is
    /// loaded, when the IP is in a reserved / private range the DB
    /// does not index (RFC 1918 / link-local / multicast / etc.), or
    /// when the lookup fails for any other reason. Callers that
    /// apply allow / deny rules should fall through (not fail-close)
    /// on `None` so a legitimate client behind a corporate NAT is
    /// not accidentally blocked.
    pub fn lookup_country(&self, ip: IpAddr) -> Option<CountryCode> {
        let guard = self.inner.load();
        let loaded = guard.as_ref()?;
        maxminddb_lookup_country(&loaded.reader, ip)
    }

    /// Snapshot status for the dashboard. `None` when no DB is loaded.
    pub fn status(&self) -> Option<GeoIpDbStatus> {
        self.inner.load().as_ref().map(|d| d.status.clone())
    }
}

impl Default for GeoIpResolver {
    fn default() -> Self {
        Self::empty()
    }
}

impl MmdbResolver for GeoIpResolver {
    fn load_from_path(&self, path: &Path) -> Result<(), GeoIpError> {
        GeoIpResolver::load_from_path(self, path)
    }
}

impl MmdbResolver for AsnResolver {
    fn load_from_path(&self, path: &Path) -> Result<(), GeoIpError> {
        AsnResolver::load_from_path(self, path)
    }
}

/// Shared lookup helper, used by both the public `lookup_country` and
/// the sanity-check in `load_from_path` so they stay in sync on schema
/// differences between MaxMind and DB-IP .mmdb dialects.
fn maxminddb_lookup_country(
    reader: &maxminddb::Reader<Vec<u8>>,
    ip: IpAddr,
) -> Option<CountryCode> {
    // Both GeoLite2-Country and DB-IP Lite Country expose
    // `country.iso_code` at the same JSON path. maxminddb 0.27 offers
    // a `decode_path` primitive that decodes only the target field
    // instead of deserialising the whole record — ~2x cheaper at
    // lookup time and no struct boilerplate to keep in sync with
    // upstream schema tweaks.
    use maxminddb::PathElement;

    let result = reader.lookup(ip).ok()?;
    if !result.has_data() {
        return None;
    }
    let iso: Option<String> = result
        .decode_path(&[PathElement::Key("country"), PathElement::Key("iso_code")])
        .ok()
        .flatten();
    CountryCode::new(&iso?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn country_code_accepts_two_letters() {
        assert_eq!(CountryCode::new("FR").unwrap().as_str(), "FR");
        // Normalises to upper.
        assert_eq!(CountryCode::new("fr").unwrap().as_str(), "FR");
        assert_eq!(CountryCode::new(" GB ").unwrap().as_str(), "GB");
    }

    #[test]
    fn country_code_rejects_bad_input() {
        assert!(CountryCode::new("FRA").is_none()); // too long
        assert!(CountryCode::new("F").is_none()); // too short
        assert!(CountryCode::new("F1").is_none()); // not alphabetic
        assert!(CountryCode::new("").is_none());
        assert!(CountryCode::new("  ").is_none());
    }

    #[test]
    fn empty_resolver_returns_none() {
        let r = GeoIpResolver::empty();
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(r.lookup_country(ip).is_none());
        assert!(r.status().is_none());
    }

    #[test]
    fn load_missing_path_errors() {
        let r = GeoIpResolver::empty();
        let err = r
            .load_from_path("/nonexistent/definitely-not-a-real-path.mmdb")
            .expect_err("missing path must error");
        // Match on enum variant so we catch regressions where a new
        // error type slips in without the caller noticing.
        match err {
            GeoIpError::Io { .. } => {}
            other => panic!("expected Io error, got {other:?}"),
        }
    }

    #[test]
    fn load_corrupt_file_errors() {
        let r = GeoIpResolver::empty();
        let tmp = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(tmp.path(), b"not-a-maxminddb-file").expect("write tmp");
        let err = r
            .load_from_path(tmp.path())
            .expect_err("corrupt file must error");
        match err {
            GeoIpError::Parse { .. } => {}
            other => panic!("expected Parse error, got {other:?}"),
        }
    }

    #[test]
    fn unload_clears_state() {
        let r = GeoIpResolver::empty();
        r.unload(); // idempotent on an already-empty resolver
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(r.lookup_country(ip).is_none());
    }
}
