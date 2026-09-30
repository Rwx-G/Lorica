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

    let login_url = format!("https://127.0.0.1:{port}/api/v1/auth/login");
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
        let pem: Vec<u8> = std::fs::read(&path).map_err(|e| unreadable_pin(&path, &e))?;
        Self::from_pem(path, &pem)
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
        std::io::ErrorKind::NotFound => format!(
            "{path} does not exist: lorica writes it when its management listener starts. \
             Is lorica running, and does --data-dir name its data directory? The password \
             was not sent."
        ),
        _ => format!("Cannot read {path}: {error}. The password was not sent."),
    }
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
    let body = response.text().await.unwrap_or_default();
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
    read_admin_password_with_env(
        literal,
        file,
        from_stdin,
        std::env::var(ADMIN_PASSWORD_ENV).ok(),
    )
}

fn read_admin_password_with_env(
    literal: Option<String>,
    file: Option<&Path>,
    from_stdin: bool,
    from_env: Option<String>,
) -> Result<String, String> {
    let trimmed = |s: String| s.trim_end_matches(['\r', '\n']).to_string();
    if let Some(path) = file {
        return std::fs::read_to_string(path)
            .map(trimmed)
            .map_err(|e| format!("cannot read the password file {}: {e}", path.display()));
    }
    if from_stdin {
        let mut buffer = String::new();
        std::io::stdin()
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
        let file = std::env::temp_dir().join(format!("lorica-pw-{}", std::process::id()));
        std::fs::write(&file, "from-file\n").expect("write");
        let env = Some("from-env\n".to_string());
        // File beats everything.
        assert_eq!(
            read_admin_password_with_env(Some("literal".into()), Some(&file), false, env.clone())
                .expect("file"),
            "from-file"
        );
        // An explicit --password beats the ambient variable.
        assert_eq!(
            read_admin_password_with_env(Some("literal".into()), None, false, env.clone())
                .expect("literal"),
            "literal"
        );
        // The variable is the fallback, trimmed.
        assert_eq!(
            read_admin_password_with_env(None, None, false, env).expect("env"),
            "from-env"
        );
        // An empty variable is no source.
        assert!(read_admin_password_with_env(None, None, false, Some(String::new())).is_err());
        assert!(read_admin_password_with_env(None, None, false, None).is_err());
        assert!(read_admin_password_with_env(
            None,
            Some(Path::new("/nonexistent/pw")),
            false,
            None
        )
        .is_err());
        let _ = std::fs::remove_file(&file);
    }
}
