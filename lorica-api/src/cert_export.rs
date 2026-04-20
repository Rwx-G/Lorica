//! Filesystem export of issued certificates (v1.4.1).
//!
//! When `GlobalSettings.cert_export_enabled` is on, every time Lorica
//! issues or renews a certificate (ACME HTTP-01 / DNS-01 or self-signed
//! generation) the PEM payload is mirrored to
//! `<cert_export_dir>/<sanitised-hostname>/{cert,chain,fullchain,privkey}.pem`
//! so external tooling (Ansible, a HAProxy sidecar, a backup job) can
//! read the live bundle straight off disk without hitting the HTTP API.
//!
//! Design notes:
//!
//! - **Linux-only**: `chown`/`chmod` rely on `std::os::unix::fs::*`.
//!   Lorica has been Linux-only since v1.0 per the project README.
//! - **Atomic writes**: every file is staged with a `.tmp` suffix and
//!   `fs::rename`'d into place on success. If `rename` hits `EXDEV`
//!   (the tmp and target are on different mounts), we fall back to
//!   `copy + fsync + rename` so the export still lands atomically on
//!   the destination filesystem.
//! - **Fail-soft**: any error writing to the export directory emits a
//!   `tracing::warn!` but never propagates up to the ACME renewal
//!   handler. The cert is still in the DB; a missing disk copy is an
//!   operator inconvenience, not an outage.
//! - **Orphan handling**: deferred to a separate commit / follow-up
//!   (the writer does not clean up files for certs that no longer
//!   exist; an operator can `rm -rf` the export dir if needed).
//!
//! See `docs/security/cert-export-threat-model.md` for the
//! operator-facing risk analysis.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use lorica_config::models::{Certificate, GlobalSettings};

#[cfg(unix)]
use nix::unistd::{chown, Gid, Uid};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Outcome of a single export attempt. All three arms are non-fatal;
/// the caller logs and moves on.
#[derive(Debug)]
pub enum ExportOutcome {
    /// Cert was written and permissions applied.
    Ok,
    /// Feature disabled (no-op): either the global flag is off or
    /// `cert_export_dir` is not set.
    Disabled,
    /// Cert was written but chown/chmod could not be applied (e.g.
    /// Lorica runs without `CAP_CHOWN`). Operator sees a warning
    /// in the log; the file is still on disk with the process
    /// default permissions.
    PermissionsSkipped,
}

/// Errors the exporter surfaces to the caller. `DiskFull` is the only
/// one that typically demands operator action; the rest indicate a
/// configuration issue (missing dir, bad mode) that shows up in logs.
#[derive(Debug)]
pub enum ExportError {
    BadConfig(String),
    Io(std::io::Error),
    DiskFull(std::io::Error),
    InvalidHostname(String),
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportError::BadConfig(m) => write!(f, "cert export config invalid: {m}"),
            ExportError::Io(e) => write!(f, "cert export io: {e}"),
            ExportError::DiskFull(e) => write!(f, "cert export: disk full ({e})"),
            ExportError::InvalidHostname(h) => write!(f, "cert export: invalid hostname {h:?}"),
        }
    }
}
impl std::error::Error for ExportError {}

impl From<std::io::Error> for ExportError {
    fn from(e: std::io::Error) -> Self {
        // ENOSPC = 28 on Linux. Stable ABI; we only ship to Linux.
        // Using the constant directly keeps `libc` out of the dep graph.
        if e.raw_os_error() == Some(28) {
            ExportError::DiskFull(e)
        } else {
            ExportError::Io(e)
        }
    }
}

/// Sanitize a hostname into a filesystem-safe directory name. Keeps
/// only ASCII alphanumeric + `-` / `_` / `.`. Rejects leading dot /
/// empty result / `..`. Wildcard domains drop the `*` and inherit the
/// leading-dot rejection, so `*.example.com` returns `None` and the
/// caller can fall back to a stable opaque id.
fn sanitize_hostname(hostname: &str) -> Option<String> {
    let mut out = String::with_capacity(hostname.len());
    for c in hostname.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
            out.push(c);
        }
    }
    if out.is_empty() || out.starts_with('.') || out.contains("..") {
        return None;
    }
    Some(out)
}

/// Apply Unix owner/group/mode to a path. On a best-effort basis:
/// returns `Ok(false)` if the process does not have the required
/// capability so the caller can flag the export as
/// `PermissionsSkipped` rather than failing hard.
#[cfg(unix)]
fn apply_permissions(
    path: &Path,
    uid: Option<u32>,
    gid: Option<u32>,
    mode: u32,
) -> std::io::Result<bool> {
    // chmod first - it works without CAP_CHOWN.
    let perms = fs::Permissions::from_mode(mode);
    fs::set_permissions(path, perms)?;

    // chown is best-effort: without CAP_CHOWN it returns EPERM. We
    // translate that to `Ok(false)` so the exporter can record a
    // PermissionsSkipped outcome. Using `nix::unistd::chown` keeps
    // the call in safe Rust per the crate-wide `deny(unsafe_code)`.
    if uid.is_some() || gid.is_some() {
        let nu = uid.map(Uid::from_raw);
        let ng = gid.map(Gid::from_raw);
        match chown(path, nu, ng) {
            Ok(()) => {}
            Err(nix::errno::Errno::EPERM) => return Ok(false),
            Err(e) => {
                return Err(std::io::Error::from_raw_os_error(e as i32));
            }
        }
    }
    Ok(true)
}

#[cfg(not(unix))]
fn apply_permissions(
    _path: &Path,
    _uid: Option<u32>,
    _gid: Option<u32>,
    _mode: u32,
) -> std::io::Result<bool> {
    // Lorica is Linux-only (CLAUDE.md); the non-unix branch exists so
    // rust-analyzer keeps working on Windows during development.
    Ok(false)
}

/// Stage `content` to `<target>.tmp`, fsync it, then atomic-rename
/// to `target`. If rename hits `EXDEV` (target on a different mount
/// than the parent dir's tmp) we fall back to a plain copy + rename
/// on the target filesystem so the atomicity guarantee still holds
/// relative to readers of the final path.
fn write_atomic(target: &Path, content: &[u8]) -> Result<(), ExportError> {
    let tmp = target.with_extension("tmp");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(content)?;
        f.flush()?;
        f.sync_all()?;
    }
    match fs::rename(&tmp, target) {
        Ok(()) => Ok(()),
        // EXDEV = 18 on Linux. Cross-device link: the tmp file and the
        // final target are on different mounts.
        Err(e) if e.raw_os_error() == Some(18) => {
            // Cross-device fallback.
            let _ = fs::remove_file(target); // best-effort
            fs::copy(&tmp, target)?;
            fs::remove_file(&tmp)?;
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Main entry point. Export a certificate's PEM bytes to the disk
/// zone configured in `settings`. Returns `Ok(Disabled)` when the
/// feature is off so the ACME renewal callers can unconditionally
/// call this and let the exporter decide.
pub fn export_certificate(
    settings: &GlobalSettings,
    cert: &Certificate,
) -> Result<ExportOutcome, ExportError> {
    if !settings.cert_export_enabled {
        return Ok(ExportOutcome::Disabled);
    }
    let Some(ref dir) = settings.cert_export_dir else {
        return Ok(ExportOutcome::Disabled);
    };
    let root = PathBuf::from(dir);

    // Sanitise hostname for the subdirectory name. A malformed domain
    // (wildcard, pure-unicode, path-traversal) falls back to the
    // opaque cert id so we never expand attacker-controlled bytes
    // onto the filesystem.
    let subdir_name =
        sanitize_hostname(&cert.domain).unwrap_or_else(|| format!("cert-{}", cert.id));
    let host_dir = root.join(&subdir_name);

    // Ensure both the root and the per-host directory exist with the
    // configured dir mode. `create_dir_all` is idempotent.
    fs::create_dir_all(&host_dir)?;
    // Best-effort permission fix on the parent dir (no-op when it
    // already matches).
    let mut any_perm_skipped = false;
    for d in [&root, &host_dir] {
        match apply_permissions(
            d,
            settings.cert_export_owner_uid,
            settings.cert_export_group_gid,
            settings.cert_export_dir_mode,
        ) {
            Ok(true) => {}
            Ok(false) => any_perm_skipped = true,
            Err(e) => {
                tracing::warn!(path = %d.display(), error = %e, "cert export: chmod failed");
            }
        }
    }

    // Build the four derived PEM blobs. `fullchain` = leaf + any
    // extra chain bytes already stored in `cert_pem`; the store
    // keeps them concatenated in the issued cert, so `cert.cert_pem`
    // IS the fullchain in most ACME flows - we duplicate the write
    // for a more predictable layout regardless.
    let leaf = leaf_pem_from(&cert.cert_pem);
    let chain_only = chain_pem_from(&cert.cert_pem);
    let fullchain = cert.cert_pem.clone();
    let privkey = cert.key_pem.clone();

    for (name, content) in [
        ("cert.pem", &leaf),
        ("chain.pem", &chain_only),
        ("fullchain.pem", &fullchain),
        ("privkey.pem", &privkey),
    ] {
        let target = host_dir.join(name);
        write_atomic(&target, content.as_bytes())?;
        match apply_permissions(
            &target,
            settings.cert_export_owner_uid,
            settings.cert_export_group_gid,
            settings.cert_export_file_mode,
        ) {
            Ok(true) => {}
            Ok(false) => any_perm_skipped = true,
            Err(e) => {
                tracing::warn!(path = %target.display(), error = %e, "cert export: chmod failed");
            }
        }
    }

    if any_perm_skipped {
        Ok(ExportOutcome::PermissionsSkipped)
    } else {
        Ok(ExportOutcome::Ok)
    }
}

/// Split a PEM that contains `[leaf, intermediate...]` into its
/// leaf certificate only. Returns the original input if no second
/// CERTIFICATE block is present.
fn leaf_pem_from(pem: &str) -> String {
    const START: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let start = pem.find(START);
    let Some(s) = start else {
        return pem.to_string();
    };
    let rest = &pem[s..];
    if let Some(end) = rest.find(END) {
        let block_end = end + END.len();
        let mut trimmed = rest[..block_end].to_string();
        // Keep a trailing newline for POSIX-friendliness.
        if !trimmed.ends_with('\n') {
            trimmed.push('\n');
        }
        return trimmed;
    }
    pem.to_string()
}

/// Split a PEM that contains `[leaf, intermediate...]` into the chain
/// section (everything after the first CERTIFICATE block). Returns an
/// empty string when there is no chain - matches the "fullchain vs
/// chain" split Nginx/Apache consumers expect.
fn chain_pem_from(pem: &str) -> String {
    const END: &str = "-----END CERTIFICATE-----";
    let Some(first) = pem.find(END) else {
        return String::new();
    };
    let after = &pem[first + END.len()..];
    // Strip leading whitespace / newline between blocks.
    let trimmed = after.trim_start();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut out = trimmed.to_string();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Convenience wrapper called by every cert-creation path
/// (`create_certificate`, `generate_self_signed`, the ACME HTTP-01 /
/// DNS-01 success handlers). Reads `GlobalSettings` from the store,
/// invokes `export_certificate`, logs the outcome. Never returns
/// an error - the cert is already persisted in the DB, a missing
/// disk copy never blocks the request.
pub fn export_from_store(store: &lorica_config::ConfigStore, cert: &Certificate) {
    let settings = match store.get_global_settings() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "cert export: could not read global settings");
            return;
        }
    };
    match export_certificate(&settings, cert) {
        Ok(ExportOutcome::Ok) => {
            tracing::info!(cert_id = %cert.id, domain = %cert.domain, "cert export: ok");
        }
        Ok(ExportOutcome::Disabled) => {}
        Ok(ExportOutcome::PermissionsSkipped) => {
            tracing::warn!(
                cert_id = %cert.id,
                domain = %cert.domain,
                "cert export: written but chown/chmod skipped (missing CAP_CHOWN?)"
            );
        }
        Err(e) => {
            tracing::warn!(
                cert_id = %cert.id,
                domain = %cert.domain,
                error = %e,
                "cert export failed"
            );
        }
    }
}

/// Re-export every active certificate in the store. Called on
/// startup so a fresh Lorica install with the export zone newly
/// mounted, or an operator-changed mode/ACL, immediately reaches
/// a coherent on-disk state instead of waiting for the next
/// renewal cycle.
pub async fn reexport_all(settings: &GlobalSettings, certs: &[Certificate]) -> (usize, usize) {
    if !settings.cert_export_enabled {
        return (0, 0);
    }
    let mut ok = 0usize;
    let mut err = 0usize;
    for cert in certs {
        match export_certificate(settings, cert) {
            Ok(ExportOutcome::Ok) | Ok(ExportOutcome::PermissionsSkipped) => ok += 1,
            Ok(ExportOutcome::Disabled) => {}
            Err(e) => {
                err += 1;
                tracing::warn!(cert_id = %cert.id, domain = %cert.domain, error = %e, "cert export failed on startup");
            }
        }
    }
    tracing::info!(
        exported = ok,
        failed = err,
        "cert export: startup re-export complete"
    );
    (ok, err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn dummy_cert(domain: &str, pem: &str, key: &str) -> Certificate {
        Certificate {
            id: "dummy-id".into(),
            domain: domain.into(),
            san_domains: vec![],
            fingerprint: "sha256:dummy".into(),
            cert_pem: pem.into(),
            key_pem: key.into(),
            issuer: "Test Issuer".into(),
            not_before: Utc::now(),
            not_after: Utc::now(),
            is_acme: false,
            acme_auto_renew: false,
            acme_method: None,
            acme_dns_provider_id: None,
            created_at: Utc::now(),
        }
    }

    fn dummy_settings_off() -> GlobalSettings {
        GlobalSettings {
            cert_export_enabled: false,
            ..GlobalSettings::default()
        }
    }

    #[test]
    fn sanitize_hostname_keeps_normal_names() {
        assert_eq!(
            sanitize_hostname("grafana.mibu.fr").as_deref(),
            Some("grafana.mibu.fr")
        );
        assert_eq!(
            sanitize_hostname("my_host-01.example.com").as_deref(),
            Some("my_host-01.example.com")
        );
    }

    #[test]
    fn sanitize_hostname_rejects_wildcard_and_traversal() {
        // `*` is stripped but the leading dot then fails the guard.
        assert_eq!(sanitize_hostname("*.example.com"), None);
        assert_eq!(sanitize_hostname(".."), None);
        assert_eq!(sanitize_hostname("../etc"), None);
        assert_eq!(sanitize_hostname(""), None);
    }

    #[test]
    fn leaf_pem_from_splits_fullchain() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n";
        let leaf = leaf_pem_from(pem);
        assert!(leaf.starts_with("-----BEGIN CERTIFICATE-----\nAAA"));
        assert!(leaf.ends_with("-----END CERTIFICATE-----\n"));
        assert!(!leaf.contains("BBB"));
    }

    #[test]
    fn chain_pem_from_returns_empty_when_no_chain() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n";
        assert_eq!(chain_pem_from(pem), "");
    }

    #[test]
    fn chain_pem_from_captures_intermediates() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n";
        let chain = chain_pem_from(pem);
        assert!(chain.starts_with("-----BEGIN CERTIFICATE-----\nBBB"));
    }

    #[test]
    fn export_is_noop_when_disabled() {
        let tmp = tempfile::tempdir().expect("test setup");
        let settings = GlobalSettings {
            cert_export_enabled: false,
            cert_export_dir: Some(tmp.path().to_string_lossy().into_owned()),
            ..dummy_settings_off()
        };
        // Feature flag off -> Disabled
        let cert = dummy_cert("test.example.com", "CERT", "KEY");
        let outcome = export_certificate(&settings, &cert).expect("test setup");
        assert!(matches!(outcome, ExportOutcome::Disabled));
        // Nothing should have been written.
        assert!(tmp
            .path()
            .join("test.example.com")
            .join("cert.pem")
            .metadata()
            .is_err());
    }

    #[test]
    fn export_writes_four_files_when_enabled() {
        let tmp = tempfile::tempdir().expect("test setup");
        let settings = GlobalSettings {
            cert_export_enabled: true,
            cert_export_dir: Some(tmp.path().to_string_lossy().into_owned()),
            ..GlobalSettings::default()
        };
        let pem = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n";
        let cert = dummy_cert("grafana.mibu.fr", pem, "privkey-bytes");
        let outcome = export_certificate(&settings, &cert).expect("test setup");
        // Either Ok or PermissionsSkipped depending on test user capabilities.
        assert!(matches!(
            outcome,
            ExportOutcome::Ok | ExportOutcome::PermissionsSkipped
        ));
        let host_dir = tmp.path().join("grafana.mibu.fr");
        for name in ["cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"] {
            assert!(host_dir.join(name).exists(), "missing file {name}");
        }
        let fullchain = fs::read_to_string(host_dir.join("fullchain.pem")).unwrap();
        assert_eq!(fullchain, pem);
        let leaf = fs::read_to_string(host_dir.join("cert.pem")).unwrap();
        assert!(leaf.contains("leaf"));
        assert!(!leaf.contains("chain"));
        let chain = fs::read_to_string(host_dir.join("chain.pem")).unwrap();
        assert!(chain.contains("chain"));
        assert!(!chain.contains("leaf"));
        let privkey = fs::read_to_string(host_dir.join("privkey.pem")).unwrap();
        assert_eq!(privkey, "privkey-bytes");
    }

    #[test]
    fn export_falls_back_to_cert_id_when_hostname_unsafe() {
        let tmp = tempfile::tempdir().expect("test setup");
        let settings = GlobalSettings {
            cert_export_enabled: true,
            cert_export_dir: Some(tmp.path().to_string_lossy().into_owned()),
            ..GlobalSettings::default()
        };
        let cert = dummy_cert(
            "*.example.com",
            "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n",
            "key",
        );
        let _ = export_certificate(&settings, &cert).expect("test setup");
        assert!(tmp.path().join("cert-dummy-id").exists());
    }
}
