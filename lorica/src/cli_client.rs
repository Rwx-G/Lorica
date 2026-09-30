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

//! The loopback management-API client every CLI subcommand shares
//! (`unban`, `upgrade`, the `cluster` family, `automation token create`,
//! `mcp token create`): one place for the trust decision, the login
//! contract and the password sources.
//!
//! # The trust decision (backlog #90)
//!
//! The management port is unprivileged, so while the node is stopped or
//! restarting any local user can bind it. Loopback is therefore no proof
//! of identity, and the password is sent only to a peer that completes
//! the handshake with the exact certificate the node serves. The node
//! records that certificate at
//! [`lorica_api::management_tls::served_certificate_path`] each time its
//! management listener starts. The file lives in the node's `0700`
//! `management/` directory, so a process that can squat the port can
//! neither read nor replace it, and without the matching private key it
//! cannot present it. A caller who cannot read the file is refused
//! rather than falling back to trusting whatever answers.
//!
//! # A node older than 1.9.0
//!
//! Such a node never writes that record, and `lorica upgrade` from the
//! new binary is exactly the command that meets one still running. When
//! the record is absent, the CLI pins the certificate a node of that
//! age serves, chosen the way it chose it: the operator's
//! `management_cert_pem_path` when the stored settings name both it and
//! the key, the self-signed `management/cert.pem` otherwise. That is
//! still one certificate compared byte for byte, read from a file the
//! port squatter can neither read nor replace, never "whatever
//! answers". If that certificate cannot be read either, the command is
//! refused as before. A 1.9.0 node writes the record on its first
//! start, after which this path is never taken for it again.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};

/// Exit with a message on stderr (the CLI's failure contract).
pub(crate) fn fail(message: impl std::fmt::Display) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}

/// The management API URL of `path` (`/api/v1/...`) on `port`.
///
/// Loopback and nothing else: the pin below is an identity for the
/// node's own management listener, which binds `127.0.0.1` alone, so
/// the host is part of the trust decision rather than something each
/// command spells.
pub(crate) fn management_url(port: u16, path: &str) -> String {
    format!("https://127.0.0.1:{port}{path}")
}

/// A logged-in client for the loopback management API of the node whose
/// data directory is `data_dir`, or exit with a diagnostic. Nothing is
/// sent, the password included, unless the peer on `port` presents the
/// certificate the node records as served.
pub(crate) async fn management_session(
    data_dir: &Path,
    port: u16,
    user: &str,
    password: &str,
) -> reqwest::Client {
    let pin = Arc::new(PinnedLeaf::load(data_dir).unwrap_or_else(|refused| fail(refused)));
    open_session(pin, port, user, password)
        .await
        .unwrap_or_else(|refused| fail(refused))
}

/// Build the pinned client and log in.
///
/// # Errors
///
/// The operator-facing reason: the peer is not the node, the
/// credentials were refused, or nothing answered.
async fn open_session(
    pin: Arc<PinnedLeaf>,
    port: u16,
    user: &str,
    password: &str,
) -> Result<reqwest::Client, String> {
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| format!("TLS configuration: {e}"))?
    .dangerous()
    .with_custom_certificate_verifier(Arc::clone(&pin) as Arc<dyn ServerCertVerifier>)
    .with_no_client_auth();
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .use_preconfigured_tls(tls)
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;

    let login_url = management_url(port, "/api/v1/auth/login");
    match client
        .post(&login_url)
        .json(&serde_json::json!({ "username": user, "password": password }))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => Ok(client),
        Ok(r) => Err(format!("Login failed ({}). Check credentials.", r.status())),
        Err(_) if pin.refused_a_peer() => Err(format!(
            "The process answering on 127.0.0.1:{port} did not present the certificate the \
             node records as served ({}). Another process may hold the management port; the \
             password was not sent. Check what listens there (ss -ltnp) before retrying.",
            pin.path.display()
        )),
        Err(e) => Err(format!(
            "Cannot connect to management API on port {port}: {e}. \
             Hint: is lorica running and is --management-port correct?"
        )),
    }
}

/// The one certificate the CLI accepts from the management port: the
/// leaf the node records as served, compared byte for byte.
///
/// Validity dates, names and chains are deliberately not checked: the
/// pin is an identity, not a trust anchor, and the node replaces the
/// file whenever it serves another certificate. The handshake signature
/// is still verified, so presenting the certificate without its key
/// fails too.
#[derive(Debug)]
struct PinnedLeaf {
    path: PathBuf,
    leaf: CertificateDer<'static>,
    algorithms: WebPkiSupportedAlgorithms,
    refused: AtomicBool,
}

impl PinnedLeaf {
    /// Read the served certificate of the node whose data directory is
    /// `data_dir`.
    ///
    /// # Errors
    ///
    /// Why the certificate cannot be pinned, in words an operator acts
    /// on; the password is never sent in that case.
    fn load(data_dir: &Path) -> Result<Self, String> {
        let path: PathBuf = lorica_api::management_tls::served_certificate_path(data_dir);
        match std::fs::read(&path) {
            Ok(pem) => Self::from_pem(path, &pem),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let neither = |why: String| {
                    format!(
                        "{} does not exist: lorica writes it when its management listener \
                         starts. Is lorica running, and does --data-dir name its data \
                         directory? A node older than 1.9.0 does not write it, and the \
                         certificate such a node serves cannot be pinned instead: {why}. The \
                         password was not sent.",
                        path.display()
                    )
                };
                let legacy: PathBuf = pre_1_9_served_certificate_path(data_dir).map_err(neither)?;
                let pem: Vec<u8> = std::fs::read(&legacy)
                    .map_err(|e| neither(format!("cannot read {}: {e}", legacy.display())))?;
                eprintln!(
                    "note: {} does not exist, which is what a node older than 1.9.0 looks like; \
                     pinning {}, the certificate such a node serves.",
                    path.display(),
                    legacy.display()
                );
                Self::from_pem(legacy, &pem)
            }
            Err(e) => Err(unreadable_pin(&path, &e)),
        }
    }

    fn from_pem(path: PathBuf, pem: &[u8]) -> Result<Self, String> {
        // The first certificate is the one rustls serves as the end
        // entity (`with_single_cert` takes the chain leaf first).
        let leaf = CertificateDer::pem_slice_iter(pem)
            .next()
            .and_then(Result::ok)
            .ok_or_else(|| {
                format!(
                    "{} holds no certificate; restart lorica so it records the one it serves. \
                     The password was not sent.",
                    path.display()
                )
            })?;
        Ok(Self {
            path,
            leaf,
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
            refused: AtomicBool::new(false),
        })
    }

    fn refused_a_peer(&self) -> bool {
        self.refused.load(Ordering::SeqCst)
    }
}

/// The operator-facing reason the served certificate could not be read.
fn unreadable_pin(path: &Path, error: &std::io::Error) -> String {
    let path = path.display();
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => format!(
            "Cannot read {path}, the certificate the node serves on its management port: \
             permission denied. Run this command as root or as the lorica user. The password \
             was not sent."
        ),
        _ => format!("Cannot read {path}: {error}. The password was not sent."),
    }
}

/// The certificate a node older than 1.9.0 serves on its management
/// port, which writes no served-certificate record: the operator's
/// `management_cert_pem_path` when the stored settings name both it and
/// the key, `<data_dir>/management/cert.pem` otherwise. That is the
/// choice such a node made at startup (Story 8.8 AC #1 and #2).
///
/// # Errors
///
/// Why the choice cannot be made: the settings live in `lorica.db`, and
/// guessing without them could pin the wrong certificate. The database
/// is opened the way the other CLI commands open it; 1.9.0 adds no
/// migration, so opening a 1.8.0 database changes nothing in it.
fn pre_1_9_served_certificate_path(data_dir: &Path) -> Result<PathBuf, String> {
    let database: PathBuf = data_dir.join("lorica.db");
    if !database.is_file() {
        return Err(format!("{} does not exist", database.display()));
    }
    let settings = lorica_config::ConfigStore::open(&database, None)
        .and_then(|store| store.get_global_settings())
        .map_err(|e| format!("cannot read the settings in {}: {e}", database.display()))?;
    Ok(
        match (
            settings.management_cert_pem_path,
            settings.management_key_pem_path,
        ) {
            (Some(cert), Some(_)) => PathBuf::from(cert),
            _ => data_dir.join("management").join("cert.pem"),
        },
    )
}

impl ServerCertVerifier for PinnedLeaf {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.leaf.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            self.refused.store(true, Ordering::SeqCst);
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// The `data` envelope of a management API answer, or exit with the
/// body.
pub(crate) async fn management_data(response: reqwest::Response, what: &str) -> serde_json::Value {
    let status = response.status();
    let body = response
        .text()
        .await
        .unwrap_or_else(|e| fail(format!("{what} ({status}): reading the answer failed: {e}")));
    if !status.is_success() {
        fail(format!("{what} failed ({status}): {body}"));
    }
    serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("data").cloned())
        .unwrap_or_else(|| fail(format!("{what}: unexpected answer: {body}")))
}

/// The environment variable the management password is read from
/// when no explicit source is given.
pub(crate) const ADMIN_PASSWORD_ENV: &str = "LORICA_ADMIN_PASSWORD";

/// The management password from its documented sources. Explicit
/// arguments win over the ambient environment, in this order:
/// `--password-file`, `--password-stdin`, `--password` (accepted with
/// a warning: argv is readable through `/proc`, lands in shell history
/// and is logged verbatim by CI and configuration-management `command`
/// modules), then `LORICA_ADMIN_PASSWORD`. A trailing newline is
/// stripped from every source (`echo` and heredocs add one).
pub(crate) fn read_admin_password(
    literal: Option<String>,
    file: Option<&Path>,
    from_stdin: bool,
) -> Result<String, String> {
    let mut stdin = std::io::stdin();
    read_admin_password_from(
        literal,
        file,
        from_stdin.then_some(&mut stdin as &mut dyn Read),
        std::env::var(ADMIN_PASSWORD_ENV).ok(),
    )
}

/// [`read_admin_password`] over explicit sources: `stdin` is `Some`
/// when `--password-stdin` was passed, and `from_env` is the variable's
/// value.
fn read_admin_password_from(
    literal: Option<String>,
    file: Option<&Path>,
    stdin: Option<&mut dyn Read>,
    from_env: Option<String>,
) -> Result<String, String> {
    let trimmed = |s: String| s.trim_end_matches(['\r', '\n']).to_string();
    if let Some(path) = file {
        return std::fs::read_to_string(path)
            .map(trimmed)
            .map_err(|e| format!("cannot read the password file {}: {e}", path.display()));
    }
    if let Some(stdin) = stdin {
        let mut buffer = String::new();
        stdin
            .read_to_string(&mut buffer)
            .map_err(|e| format!("cannot read the password from standard input: {e}"))?;
        return Ok(trimmed(buffer));
    }
    if let Some(literal) = literal {
        eprintln!(
            "warning: --password on the command line is visible to every local process and \
             lands in shell history; prefer --password-file, --password-stdin or \
             {ADMIN_PASSWORD_ENV}"
        );
        return Ok(literal);
    }
    if let Some(from_env) = from_env.map(trimmed).filter(|s| !s.is_empty()) {
        return Ok(from_env);
    }
    Err(format!(
        "no password: pass --password-file <path>, --password-stdin, set {ADMIN_PASSWORD_ENV}, \
         or (discouraged) --password"
    ))
}

/// The password for a command whose credentials are optional
/// (`cluster leave`, `cluster status`): `None` when no `--user` is
/// given AND no explicit password source was passed; a password
/// source without `--user` is a mistake worth naming rather than
/// silently ignoring (the command would then run credential-less).
pub(crate) fn optional_admin_password(
    user: Option<&str>,
    literal: Option<String>,
    file: Option<&Path>,
    from_stdin: bool,
) -> Option<String> {
    if user.is_none() {
        if literal.is_some() || file.is_some() || from_stdin {
            fail("a password source was given without --user; pass --user <name> as well");
        }
        return None;
    }
    Some(read_admin_password(literal, file, from_stdin).unwrap_or_else(|e| fail(e)))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    const PASSWORD: &str = "the-superadmin-password-nobody-else-may-read";

    /// A fresh self-signed leaf for 127.0.0.1, as `(cert_pem, key_pem)`.
    fn leaf() -> (String, String) {
        let certified =
            rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).expect("rcgen");
        (certified.cert.pem(), certified.signing_key.serialize_pem())
    }

    /// A TLS server on a free loopback port, serving `leaf` to one
    /// connection. The task answers every byte it decrypted, which is
    /// empty when the handshake never completed.
    async fn one_connection_server(
        (cert_pem, key_pem): (String, String),
    ) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        let cert = CertificateDer::from_pem_slice(cert_pem.as_bytes()).expect("cert");
        let key =
            rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).expect("key");
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                return Vec::new();
            };
            let mut received = Vec::new();
            let mut buffer = [0u8; 4096];
            while !String::from_utf8_lossy(&received).contains(PASSWORD) {
                match tls.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => received.extend_from_slice(&buffer[..n]),
                }
            }
            let _ = tls
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await;
            let _ = tls.shutdown().await;
            received
        });
        (port, task)
    }

    /// A data directory in which the node recorded `cert_pem` as served.
    fn data_dir_serving(cert_pem: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = lorica_api::management_tls::served_certificate_path(dir.path());
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, cert_pem).expect("write");
        dir
    }

    #[tokio::test]
    async fn a_peer_without_the_served_certificate_never_receives_the_password() {
        // The squatter serves a certificate of its own; the node's
        // record names another one.
        let (port, server) = one_connection_server(leaf()).await;
        let (served, _) = leaf();
        let dir = data_dir_serving(&served);
        let pin = Arc::new(PinnedLeaf::load(dir.path()).expect("pin"));

        let refused = open_session(pin, port, "admin", PASSWORD)
            .await
            .expect_err("a foreign certificate must be refused");
        assert!(
            refused.contains("Another process may hold the management port"),
            "{refused}"
        );
        assert!(refused.contains("password was not sent"), "{refused}");
        assert!(!refused.contains(PASSWORD), "{refused}");
        let received = server.await.expect("server task");
        assert!(
            received.is_empty(),
            "the squatter decrypted {} bytes",
            received.len()
        );
    }

    #[tokio::test]
    async fn the_served_certificate_is_accepted_and_carries_the_login() {
        let node = leaf();
        let dir = data_dir_serving(&node.0);
        let (port, server) = one_connection_server(node).await;
        let pin = Arc::new(PinnedLeaf::load(dir.path()).expect("pin"));

        open_session(pin, port, "admin", PASSWORD)
            .await
            .expect("the node's own certificate is accepted");
        let received = String::from_utf8(server.await.expect("server task")).expect("utf-8");
        assert!(
            received.starts_with("POST /api/v1/auth/login"),
            "{received}"
        );
        assert!(received.contains(PASSWORD), "{received}");
    }

    #[test]
    fn a_certificate_the_caller_cannot_read_names_who_can() {
        let path = Path::new("/var/lib/lorica/management/served-cert.pem");
        let denied = unreadable_pin(
            path,
            &std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );
        assert!(denied.contains("permission denied"), "{denied}");
        assert!(denied.contains("as root or as the lorica user"), "{denied}");
        assert!(denied.contains("password was not sent"), "{denied}");

        // Absent: the node never started its listener with this data
        // directory, which is what the operator has to check.
        let empty = tempfile::tempdir().expect("tempdir");
        let missing = PinnedLeaf::load(empty.path()).expect_err("no record");
        assert!(missing.contains("does not exist"), "{missing}");
        assert!(missing.contains("--data-dir"), "{missing}");

        let garbage = PinnedLeaf::from_pem(path.to_path_buf(), b"not a certificate")
            .expect_err("no certificate");
        assert!(garbage.contains("holds no certificate"), "{garbage}");
    }

    #[test]
    fn password_sources_follow_the_documented_precedence() {
        let file = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(file.path(), "from-file\n").expect("write");
        let env = Some("from-env\n".to_string());
        let stdin = || b"from-stdin\n".as_slice();
        // File beats everything.
        assert_eq!(
            read_admin_password_from(
                Some("literal".into()),
                Some(file.path()),
                Some(&mut stdin()),
                env.clone()
            )
            .expect("file"),
            "from-file"
        );
        // Standard input beats a literal and the variable.
        assert_eq!(
            read_admin_password_from(
                Some("literal".into()),
                None,
                Some(&mut stdin()),
                env.clone()
            )
            .expect("stdin"),
            "from-stdin"
        );
        // An explicit --password beats the ambient variable.
        assert_eq!(
            read_admin_password_from(Some("literal".into()), None, None, env.clone())
                .expect("literal"),
            "literal"
        );
        // The variable is the fallback, trimmed.
        assert_eq!(
            read_admin_password_from(None, None, None, env).expect("env"),
            "from-env"
        );
        // An empty variable is no source.
        assert!(read_admin_password_from(None, None, None, Some(String::new())).is_err());
        assert!(read_admin_password_from(None, None, None, None).is_err());
        assert!(
            read_admin_password_from(None, Some(Path::new("/nonexistent/pw")), None, None).is_err()
        );
    }

    /// A data directory holding what a node older than 1.9.0 leaves:
    /// its settings database and `management/cert.pem`, no record.
    /// `override_pem` stores an operator certificate and names it in
    /// the settings.
    fn pre_1_9_data_dir(cert_pem: &str, override_pem: Option<&str>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let management = dir.path().join("management");
        std::fs::create_dir_all(&management).expect("mkdir");
        std::fs::write(management.join("cert.pem"), cert_pem).expect("write");
        let store =
            lorica_config::ConfigStore::open(&dir.path().join("lorica.db"), None).expect("store");
        if let Some(override_pem) = override_pem {
            let cert = dir.path().join("operator-cert.pem");
            std::fs::write(&cert, override_pem).expect("write");
            let mut settings = store.get_global_settings().expect("settings");
            settings.management_cert_pem_path = Some(cert.display().to_string());
            settings.management_key_pem_path =
                Some(dir.path().join("operator-key.pem").display().to_string());
            store
                .update_global_settings(&settings)
                .expect("store settings");
        }
        dir
    }

    #[tokio::test]
    async fn a_node_older_than_1_9_is_pinned_on_the_self_signed_certificate_it_serves() {
        // `lorica upgrade` from the new binary meets a node that never
        // wrote the record. Its own certificate is accepted...
        let node = leaf();
        let dir = pre_1_9_data_dir(&node.0, None);
        assert!(!lorica_api::management_tls::served_certificate_path(dir.path()).exists());
        let (port, server) = one_connection_server(node).await;
        let pin = Arc::new(PinnedLeaf::load(dir.path()).expect("pin"));
        assert_eq!(pin.path, dir.path().join("management").join("cert.pem"));
        open_session(pin, port, "admin", PASSWORD)
            .await
            .expect("the certificate a 1.8.0 node serves is accepted");
        assert!(String::from_utf8(server.await.expect("server task"))
            .expect("utf-8")
            .contains(PASSWORD));

        // ...and a squatter's is not: the fallback is still one pin.
        let (port, server) = one_connection_server(leaf()).await;
        let pin = Arc::new(PinnedLeaf::load(dir.path()).expect("pin"));
        let refused = open_session(pin, port, "admin", PASSWORD)
            .await
            .expect_err("a foreign certificate must be refused");
        assert!(refused.contains("password was not sent"), "{refused}");
        assert!(server.await.expect("server task").is_empty());
    }

    #[test]
    fn a_node_older_than_1_9_with_an_operator_certificate_is_pinned_on_that_one() {
        let (self_signed, _) = leaf();
        let (operator, _) = leaf();
        let dir = pre_1_9_data_dir(&self_signed, Some(&operator));
        let pin = PinnedLeaf::load(dir.path()).expect("pin");
        assert_eq!(pin.path, dir.path().join("operator-cert.pem"));
        let expected = CertificateDer::from_pem_slice(operator.as_bytes()).expect("cert");
        assert_eq!(pin.leaf.as_ref(), expected.as_ref());
    }

    #[test]
    fn with_no_record_and_no_certificate_a_pre_1_9_node_serves_the_command_is_refused() {
        // A settings database but no certificate beside it.
        let dir = tempfile::tempdir().expect("tempdir");
        lorica_config::ConfigStore::open(&dir.path().join("lorica.db"), None).expect("store");
        let refused = PinnedLeaf::load(dir.path()).expect_err("nothing to pin");
        assert!(refused.contains("does not exist"), "{refused}");
        assert!(refused.contains("cert.pem"), "{refused}");
        assert!(refused.contains("password was not sent"), "{refused}");

        // An operator certificate the settings name but nobody wrote is
        // refused rather than replaced by the self-signed one: the node
        // serves the operator's.
        let (self_signed, _) = leaf();
        let dir = pre_1_9_data_dir(&self_signed, Some("placeholder"));
        std::fs::remove_file(dir.path().join("operator-cert.pem")).expect("remove");
        let refused = PinnedLeaf::load(dir.path()).expect_err("the operator's is absent");
        assert!(refused.contains("operator-cert.pem"), "{refused}");
    }

    #[test]
    fn every_command_speaks_to_the_loopback_listener() {
        assert_eq!(
            management_url(9443, "/api/v1/auth/login"),
            "https://127.0.0.1:9443/api/v1/auth/login"
        );
    }
}
