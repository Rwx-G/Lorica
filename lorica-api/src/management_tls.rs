// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Management-plane TLS material for the localhost API listener
//! (Story 8.8 AC #1 / #2).
//!
//! The management API used to serve plaintext HTTP. This module produces
//! the rustls [`ServerConfig`] the listener now runs on:
//!
//! - **Self-signed (default, AC #1):** a self-signed leaf is generated on
//!   first boot with SANs `localhost`, the machine hostname, `127.0.0.1`
//!   and `::1`, ~1 year validity, and persisted under
//!   `<data_dir>/management/` (`cert.pem` + `key.pem`, key mode `0600`,
//!   dir `0700`). On every boot the persisted leaf is reused unless it is
//!   missing, unparseable, or expires within 30 days, in which case it is
//!   regenerated in place.
//! - **Operator override (AC #2):** when both `management_cert_pem_path`
//!   and `management_key_pem_path` point at readable files, that
//!   certificate and key are loaded verbatim and no self-signed material
//!   is generated or rotated.

use std::path::{Path, PathBuf};

use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tracing::info;

/// Regenerate the self-signed leaf once it expires within this many days
/// (AC #1 rotation trigger).
const ROTATE_WITHIN_DAYS: i64 = 30;

/// Validity window of a freshly generated self-signed leaf (AC #1: ~1
/// year). Rotation kicks in [`ROTATE_WITHIN_DAYS`] before this elapses.
const SELF_SIGNED_VALIDITY_DAYS: i64 = 365;

/// Failure modes while assembling the management-plane TLS config.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ManagementTlsError {
    /// An operator override path (`management_cert_pem_path` /
    /// `management_key_pem_path`) was set but the file could not be read.
    #[error("failed to read operator management TLS file {path}: {source}")]
    OverrideRead {
        /// The offending path.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The `<data_dir>/management/` directory or a file within it could
    /// not be created or written.
    #[error("management TLS persistence failed at {path}: {source}")]
    Persist {
        /// The path being created or written.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// `rcgen` could not generate the self-signed certificate.
    #[error("self-signed management certificate generation failed: {0}")]
    Generate(String),
    /// The PEM material contained no usable certificate or private key.
    #[error("management TLS PEM parse failed: {0}")]
    Parse(String),
    /// rustls rejected the certificate/key pair.
    #[error("rustls rejected the management certificate/key: {0}")]
    Rustls(String),
}

/// Build the rustls [`ServerConfig`] for the management-API listener.
///
/// `data_dir` is the Lorica data directory (`--data-dir`, typically
/// `/var/lib/lorica`); the self-signed material lives in its
/// `management/` subdirectory. When both `cert_override` and
/// `key_override` are `Some` and readable, that operator-supplied pair is
/// used and no self-signed material is generated or rotated (AC #2).
pub(crate) fn build_management_server_config(
    data_dir: &Path,
    cert_override: Option<&str>,
    key_override: Option<&str>,
) -> Result<ServerConfig, ManagementTlsError> {
    let (cert_pem, key_pem): (String, String) = match (cert_override, key_override) {
        (Some(cert_path), Some(key_path)) => {
            info!(
                cert = cert_path,
                key = key_path,
                "management API using operator-supplied TLS certificate"
            );
            let cert_pem: String = std::fs::read_to_string(cert_path).map_err(|source| {
                ManagementTlsError::OverrideRead {
                    path: cert_path.to_string(),
                    source,
                }
            })?;
            let key_pem: String = std::fs::read_to_string(key_path).map_err(|source| {
                ManagementTlsError::OverrideRead {
                    path: key_path.to_string(),
                    source,
                }
            })?;
            (cert_pem, key_pem)
        }
        _ => load_or_generate_self_signed(data_dir)?,
    };

    server_config_from_pem(&cert_pem, &key_pem)
}

/// Reuse the persisted self-signed leaf, or (re)generate it when it is
/// missing, unparseable, or within [`ROTATE_WITHIN_DAYS`] of expiry.
fn load_or_generate_self_signed(data_dir: &Path) -> Result<(String, String), ManagementTlsError> {
    let dir: PathBuf = data_dir.join("management");
    let cert_path: PathBuf = dir.join("cert.pem");
    let key_path: PathBuf = dir.join("key.pem");

    if let (Ok(cert_pem), Ok(key_pem)) = (
        std::fs::read_to_string(&cert_path),
        std::fs::read_to_string(&key_path),
    ) {
        if !needs_rotation(&cert_pem) {
            info!(
                path = %cert_path.display(),
                "management API reusing persisted self-signed certificate"
            );
            return Ok((cert_pem, key_pem));
        }
        info!(
            path = %cert_path.display(),
            "management self-signed certificate expiring within {ROTATE_WITHIN_DAYS} days; regenerating"
        );
    }

    let (cert_pem, key_pem) = generate_self_signed(SELF_SIGNED_VALIDITY_DAYS)?;
    persist_self_signed(&dir, &cert_path, &key_path, &cert_pem, &key_pem)?;
    info!(
        path = %cert_path.display(),
        "management API generated a new self-signed certificate"
    );
    Ok((cert_pem, key_pem))
}

/// `true` when the persisted certificate should be regenerated: it does
/// not parse, or its `notAfter` is within [`ROTATE_WITHIN_DAYS`] of now.
fn needs_rotation(cert_pem: &str) -> bool {
    let parsed = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
        .ok()
        .and_then(|(_, pem)| pem.parse_x509().ok().map(|c| c.validity().not_after.timestamp()));
    match parsed {
        Some(not_after) => {
            let cutoff: i64 = chrono::Utc::now().timestamp() + ROTATE_WITHIN_DAYS * 24 * 3600;
            not_after <= cutoff
        }
        None => true,
    }
}

/// Generate a self-signed leaf valid for `validity_days`, with SANs
/// `localhost`, the machine hostname, `127.0.0.1` and `::1`. Returns the
/// `(cert_pem, key_pem)` pair.
fn generate_self_signed(validity_days: i64) -> Result<(String, String), ManagementTlsError> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use chrono::Datelike;
    use rcgen::{CertificateParams, DistinguishedName, DnType, Ia5String, KeyPair, SanType};

    let mut sans: Vec<SanType> = Vec::with_capacity(4);
    let dns = |name: &str| -> Result<SanType, ManagementTlsError> {
        Ia5String::try_from(name.to_string())
            .map(SanType::DnsName)
            .map_err(|e| ManagementTlsError::Generate(format!("invalid DNS SAN {name:?}: {e}")))
    };
    sans.push(dns("localhost")?);
    if let Some(host) = machine_hostname() {
        if host != "localhost" {
            sans.push(dns(&host)?);
        }
    }
    sans.push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    sans.push(SanType::IpAddress(IpAddr::V6(Ipv6Addr::LOCALHOST)));

    let mut params: CertificateParams = CertificateParams::default();
    params.subject_alt_names = sans;
    params.is_ca = rcgen::IsCa::NoCa;
    let mut dn: DistinguishedName = DistinguishedName::new();
    dn.push(DnType::CommonName, "Lorica management");
    params.distinguished_name = dn;

    // Backdate `notBefore` by a day to absorb small clock skew between the
    // generating host and any client. `notAfter` is computed with chrono
    // arithmetic (leap-day safe) then handed to rcgen's date helper, so
    // no direct `time` crate dependency is needed.
    let now = chrono::Utc::now();
    let not_before = now - chrono::Duration::days(1);
    let not_after = now + chrono::Duration::days(validity_days);
    params.not_before = rcgen::date_time_ymd(
        not_before.year(),
        not_before.month() as u8,
        not_before.day() as u8,
    );
    params.not_after =
        rcgen::date_time_ymd(not_after.year(), not_after.month() as u8, not_after.day() as u8);

    let key_pair: KeyPair =
        KeyPair::generate().map_err(|e| ManagementTlsError::Generate(e.to_string()))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| ManagementTlsError::Generate(e.to_string()))?;

    Ok((cert.pem(), key_pair.serialize_pem()))
}

/// Best-effort running hostname, read from `/proc/sys/kernel/hostname`
/// (Linux-only runtime) with `HOSTNAME` as a fallback. `None` when
/// neither yields a non-empty value; the caller then ships only the
/// loopback SANs.
fn machine_hostname() -> Option<String> {
    let from_proc = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string());
    from_proc
        .or_else(|| std::env::var("HOSTNAME").ok())
        .filter(|h| !h.is_empty())
}

/// Persist the self-signed material: `dir` at `0700`, `key.pem` at
/// `0600`, `cert.pem` world-readable (it is public material).
fn persist_self_signed(
    dir: &Path,
    cert_path: &Path,
    key_path: &Path,
    cert_pem: &str,
    key_pem: &str,
) -> Result<(), ManagementTlsError> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

    fn persist_err(path: &Path, source: std::io::Error) -> ManagementTlsError {
        ManagementTlsError::Persist {
            path: path.display().to_string(),
            source,
        }
    }

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| persist_err(dir, e))?;
    // `mode` on DirBuilder only applies on creation; force 0700 in case
    // the directory pre-existed with looser permissions.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| persist_err(dir, e))?;

    std::fs::write(cert_path, cert_pem).map_err(|e| persist_err(cert_path, e))?;

    let mut key_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(key_path)
        .map_err(|e| persist_err(key_path, e))?;
    // `mode` only applies on creation; force 0600 if the file pre-existed.
    std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| persist_err(key_path, e))?;
    key_file
        .write_all(key_pem.as_bytes())
        .map_err(|e| persist_err(key_path, e))?;

    Ok(())
}

/// Assemble a single-cert rustls [`ServerConfig`] (no client auth) from
/// PEM strings, advertising `h2` and `http/1.1` via ALPN so the
/// `hyper-util` auto server can serve both. Relies on the process-wide
/// ring crypto provider installed at startup.
fn server_config_from_pem(
    cert_pem: &str,
    key_pem: &str,
) -> Result<ServerConfig, ManagementTlsError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .filter_map(Result::ok)
        .map(|c| c.into_owned())
        .collect();
    if certs.is_empty() {
        return Err(ManagementTlsError::Parse(
            "no certificate found in management cert PEM".to_string(),
        ));
    }

    let key: PrivateKeyDer<'static> = lorica_tls::load_first_private_key(key_pem.as_bytes())
        .map_err(|e| ManagementTlsError::Parse(e.to_string()))?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ManagementTlsError::Rustls(e.to_string()))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn install_ring() {
        // The management ServerConfig builder needs a default crypto
        // provider; the binary installs ring at startup, tests do it here.
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn generated_leaf_is_not_flagged_for_rotation() {
        let (cert_pem, _key) = generate_self_signed(SELF_SIGNED_VALIDITY_DAYS).expect("generate");
        assert!(
            !needs_rotation(&cert_pem),
            "a fresh 1-year leaf must not be due for rotation"
        );
    }

    #[test]
    fn near_expiry_leaf_is_flagged_for_rotation() {
        // 10 days of validity is inside the 30-day rotation window.
        let (cert_pem, _key) = generate_self_signed(10).expect("generate");
        assert!(
            needs_rotation(&cert_pem),
            "a leaf expiring in 10 days must be due for rotation"
        );
    }

    #[test]
    fn garbage_pem_is_flagged_for_rotation() {
        assert!(needs_rotation("not a certificate"));
    }

    #[test]
    fn self_signed_is_generated_persisted_and_reused() {
        install_ring();
        let dir = tempfile::tempdir().expect("tempdir");

        // First call generates and persists.
        let cfg = build_management_server_config(dir.path(), None, None);
        assert!(cfg.is_ok(), "first build should generate a self-signed cert");

        let cert_path = dir.path().join("management").join("cert.pem");
        let key_path = dir.path().join("management").join("key.pem");
        assert!(cert_path.exists(), "cert.pem must be persisted");
        assert!(key_path.exists(), "key.pem must be persisted");

        // Key file must be 0600, directory 0700.
        use std::os::unix::fs::PermissionsExt;
        let key_mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(key_mode, 0o600, "key.pem must be owner-read/write only");
        let dir_mode = std::fs::metadata(dir.path().join("management"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "management dir must be 0700");

        // Second call reuses the same material (no rewrite of a valid leaf).
        let cert_before = std::fs::read_to_string(&cert_path).unwrap();
        let cfg2 = build_management_server_config(dir.path(), None, None);
        assert!(cfg2.is_ok(), "second build should reuse the persisted cert");
        let cert_after = std::fs::read_to_string(&cert_path).unwrap();
        assert_eq!(cert_before, cert_after, "valid leaf must not be regenerated");
    }

    #[test]
    fn operator_override_is_loaded_and_skips_generation() {
        install_ring();
        let dir = tempfile::tempdir().expect("tempdir");

        // Produce a valid cert/key pair to act as the operator override.
        let (cert_pem, key_pem) = generate_self_signed(SELF_SIGNED_VALIDITY_DAYS).expect("gen");
        let cert_path = dir.path().join("operator-cert.pem");
        let key_path = dir.path().join("operator-key.pem");
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();

        let cfg = build_management_server_config(
            dir.path(),
            Some(cert_path.to_str().unwrap()),
            Some(key_path.to_str().unwrap()),
        );
        assert!(cfg.is_ok(), "operator override should load");
        // The self-signed path must not have been taken.
        assert!(
            !dir.path().join("management").exists(),
            "override must skip self-signed generation"
        );
    }

    #[test]
    fn operator_override_missing_file_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = build_management_server_config(
            dir.path(),
            Some("/nonexistent/cert.pem"),
            Some("/nonexistent/key.pem"),
        );
        assert!(matches!(cfg, Err(ManagementTlsError::OverrideRead { .. })));
    }
}
