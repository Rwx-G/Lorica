// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Autonomous System Number (ASN) lookup.
//!
//! Mirrors [`crate::GeoIpResolver`] for the DB-IP ASN Lite dataset
//! (CC-BY 4.0, no account required, monthly refresh). Same `.mmdb`
//! binary format, same hot-swap pattern (`ArcSwapOption`), same
//! sanity-check-on-load contract: if the DB does not resolve a
//! well-known public IP, we reject the file rather than publish a
//! broken reader.
//!
//! The two resolvers are kept separate types instead of generic-over-
//! lookup because the per-record schema differs (`country.iso_code`
//! on Country, `autonomous_system_number` on ASN) and the decode
//! paths are cheaper to audit when each is explicit.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::GeoIpError;

/// DB freshness metadata surfaced to the dashboard + status API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnDbStatus {
    pub path: String,
    pub loaded_at: DateTime<Utc>,
    pub node_count: u32,
    pub build_epoch: u64,
}

struct LoadedAsnDb {
    reader: maxminddb::Reader<Vec<u8>>,
    status: AsnDbStatus,
}

/// Hot-swappable ASN resolver. Same shape as
/// [`crate::GeoIpResolver`]. Zero-cost when no DB is loaded.
pub struct AsnResolver {
    inner: ArcSwapOption<LoadedAsnDb>,
}

impl AsnResolver {
    pub fn empty() -> Self {
        Self {
            inner: ArcSwapOption::from(None),
        }
    }

    /// Open a `.mmdb` ASN database and atomically publish it.
    ///
    /// Sanity-check parallels the GeoIP loader: try a list of
    /// well-known public IPs and accept the DB if ANY resolves to
    /// a non-zero ASN. A DB that parses but returns no ASN for
    /// every probe is almost certainly wrong (country DB
    /// mistakenly loaded as ASN, empty fixture, corrupted file).
    pub fn load_from_path<P: AsRef<Path>>(&self, path: P) -> Result<(), GeoIpError> {
        let path_ref = path.as_ref();
        let reader =
            maxminddb::Reader::open_readfile(path_ref).map_err(|e| match e {
                maxminddb::MaxMindDbError::Io(source) => GeoIpError::Io {
                    path: path_ref.to_path_buf(),
                    source,
                },
                other => GeoIpError::Parse { source: other },
            })?;

        let sanity_probes: &[&str] = &[
            "8.8.8.8",    // Google (AS15169) — every real ASN DB
            "1.1.1.1",    // Cloudflare (AS13335) — fallback
            "208.67.222.222", // OpenDNS (AS36692) — second fallback
            "1.0.0.1",    // MaxMind GeoLite2-ASN-Test fixture hit
                          // (AS15169 in the open test dataset we
                          // ship under tests-e2e-docker/fixtures/).
        ];
        let any_hit = sanity_probes
            .iter()
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .any(|ip| lookup_asn_inner(&reader, ip).is_some());
        if !any_hit {
            return Err(GeoIpError::SanityCheck(format!(
                "no sanity probe resolved to an ASN (tried {}); DB likely wrong type or empty",
                sanity_probes.join(", ")
            )));
        }

        let meta = reader.metadata.clone();
        let status = AsnDbStatus {
            path: path_ref.display().to_string(),
            loaded_at: Utc::now(),
            node_count: meta.node_count,
            build_epoch: meta.build_epoch,
        };

        self.inner.store(Some(Arc::new(LoadedAsnDb { reader, status })));
        tracing::info!(
            path = %path_ref.display(),
            node_count = meta.node_count,
            build_epoch = meta.build_epoch,
            "ASN database loaded"
        );
        Ok(())
    }

    pub fn unload(&self) {
        self.inner.store(None);
    }

    /// Look up the ASN for an IP. Returns `None` when no DB is
    /// loaded OR the IP is not indexed (reserved / private). The
    /// `autonomous_system_number` field in both MaxMind GeoLite2
    /// and DB-IP ASN Lite is a `u32` — capped by real IANA
    /// allocations at ~400k ASNs, well within u32 range.
    pub fn lookup_asn(&self, ip: IpAddr) -> Option<u32> {
        let guard = self.inner.load();
        let loaded = guard.as_ref()?;
        lookup_asn_inner(&loaded.reader, ip)
    }

    pub fn status(&self) -> Option<AsnDbStatus> {
        self.inner.load().as_ref().map(|d| d.status.clone())
    }
}

impl Default for AsnResolver {
    fn default() -> Self {
        Self::empty()
    }
}

/// Module-private lookup helper. Decodes only the
/// `autonomous_system_number` field — ~2x cheaper than deserialising
/// the full record and no struct boilerplate to keep in sync.
fn lookup_asn_inner(
    reader: &maxminddb::Reader<Vec<u8>>,
    ip: IpAddr,
) -> Option<u32> {
    use maxminddb::PathElement;

    let result = reader.lookup(ip).ok()?;
    if !result.has_data() {
        return None;
    }
    let asn: Option<u32> = result
        .decode_path(&[PathElement::Key("autonomous_system_number")])
        .ok()
        .flatten();
    asn.filter(|n| *n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_resolver_returns_none() {
        let r = AsnResolver::empty();
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(r.lookup_asn(ip).is_none());
        assert!(r.status().is_none());
    }

    #[test]
    fn load_missing_path_errors() {
        let r = AsnResolver::empty();
        let err = r
            .load_from_path("/nonexistent/asn.mmdb")
            .expect_err("missing path must error");
        match err {
            GeoIpError::Io { .. } => {}
            other => panic!("expected Io error, got {other:?}"),
        }
    }

    #[test]
    fn load_corrupt_file_errors() {
        let r = AsnResolver::empty();
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
    fn unload_is_idempotent_on_empty() {
        let r = AsnResolver::empty();
        r.unload();
        r.unload();
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(r.lookup_asn(ip).is_none());
    }
}
