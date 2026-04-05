// Copyright 2026 Cloudflare, Inc.
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

use std::sync::Arc;

use arc_swap::ArcSwap;
use log::debug;
use lorica_error::{
    Error,
    ErrorType::{ConnectTimedout, InvalidCert},
    OrErr, Result,
};
use lorica_tls::{
    load_ca_file_into_store, load_certs_and_key_files, load_crls_from_file,
    load_platform_certs_incl_env_into_store, version, CertificateDer, CertificateError,
    ClientConfig as RusTlsClientConfig, DigitallySignedStruct, KeyLogFile, PrivateKeyDer,
    RootCertStore, RusTlsError, ServerName, SignatureScheme, TlsConnector as RusTlsConnector,
    UnixTime, WebPkiServerVerifier,
};

// Uses custom certificate verification from rustls's 'danger' module.
use lorica_tls::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier as RusTlsServerCertVerifier,
};

use crate::protocols::tls::{client::handshake, TlsStream};
use crate::{connectors::ConnectorOptions, listeners::ALPN, protocols::IO, upstreams::peer::Peer};

use super::replace_leftmost_underscore;

#[derive(Clone)]
pub struct Connector {
    pub ctx: Arc<TlsConnector>,
}

impl Connector {
    /// Create a new connector based on the optional configurations. If no
    /// configurations are provided, no customized certificates or keys will be
    /// used
    pub fn new(config_opt: Option<ConnectorOptions>) -> Self {
        TlsConnector::build_connector(config_opt).unwrap()
    }
}

/// Interval between CRL file change checks (seconds).
const CRL_CHECK_INTERVAL_SECS: u64 = 60;

pub struct TlsConnector {
    config: ArcSwap<RusTlsClientConfig>,
    ca_certs: Arc<RootCertStore>,
    crl_file: Option<String>,
    debug_ssl_keylog: bool,
    /// Last known mtime of the CRL file, used for hot-reload detection.
    crl_mtime: std::sync::Mutex<Option<std::time::SystemTime>>,
    /// Last time we checked the CRL file for changes.
    last_crl_check: std::sync::Mutex<std::time::Instant>,
}

impl TlsConnector {
    pub(crate) fn build_connector(options: Option<ConnectorOptions>) -> Result<Connector>
    where
        Self: Sized,
    {
        // NOTE: Rustls only supports TLS 1.2 & 1.3

        // TODO: currently using Rustls defaults
        // - support SSLKEYLOGFILE
        // - set supported ciphers/algorithms/curves
        // - add options for CRL/OCSP validation

        let (ca_certs, certs_key) = {
            let mut ca_certs = RootCertStore::empty();
            let mut certs_key = None;

            if let Some(conf) = options.as_ref() {
                if let Some(ca_file_path) = conf.ca_file.as_ref() {
                    load_ca_file_into_store(ca_file_path, &mut ca_certs)?;
                } else {
                    load_platform_certs_incl_env_into_store(&mut ca_certs)?;
                }
                if let Some((cert, key)) = conf.cert_key_file.as_ref() {
                    certs_key = load_certs_and_key_files(cert, key)?;
                }
            } else {
                load_platform_certs_incl_env_into_store(&mut ca_certs)?;
            }

            (ca_certs, certs_key)
        };

        // Build TLS client config, optionally with CRL-based revocation checking
        let ca_certs_arc = Arc::new(ca_certs.clone());
        let builder = if let Some(crl_path) = options.as_ref().and_then(|o| o.crl_file.as_ref()) {
            let crls = lorica_tls::load_crls_from_file(crl_path)?;
            debug!("loaded {} CRL(s) from {}", crls.len(), crl_path);
            let verifier = WebPkiServerVerifier::builder(ca_certs_arc)
                .with_crls(crls)
                .build()
                .or_err(InvalidCert, "Failed to build server verifier with CRLs")?;
            RusTlsClientConfig::builder_with_protocol_versions(&[&version::TLS12, &version::TLS13])
                .with_webpki_verifier(verifier)
        } else {
            RusTlsClientConfig::builder_with_protocol_versions(&[&version::TLS12, &version::TLS13])
                .with_root_certificates(ca_certs.clone())
        };

        let mut config = match certs_key {
            Some((certs, key)) => {
                match builder.with_client_auth_cert(certs.clone(), key.clone_key()) {
                    Ok(config) => config,
                    Err(err) => {
                        // TODO: is there a viable alternative to the panic?
                        // falling back to no client auth... does not seem to be reasonable.
                        panic!("Failed to configure client auth cert/key. Error: {}", err);
                    }
                }
            }
            None => builder.with_no_client_auth(),
        };

        // Enable SSLKEYLOGFILE support for debugging TLS traffic
        if let Some(options) = options.as_ref() {
            if options.debug_ssl_keylog {
                config.key_log = Arc::new(KeyLogFile::new());
            }
        }

        let crl_file = options.as_ref().and_then(|o| o.crl_file.clone());
        let debug_ssl_keylog = options.as_ref().is_some_and(|o| o.debug_ssl_keylog);
        let crl_mtime = crl_file.as_ref().and_then(|p| {
            std::fs::metadata(p).ok().and_then(|m| m.modified().ok())
        });

        Ok(Connector {
            ctx: Arc::new(TlsConnector {
                config: ArcSwap::new(Arc::new(config)),
                ca_certs: Arc::new(ca_certs),
                crl_file,
                debug_ssl_keylog,
                crl_mtime: std::sync::Mutex::new(crl_mtime),
                last_crl_check: std::sync::Mutex::new(std::time::Instant::now()),
            }),
        })
    }
}

impl TlsConnector {
    /// Reload the CRL from disk and rebuild the TLS client config.
    /// New connections will use the updated CRL; existing connections are unaffected.
    pub fn reload_crl(&self) -> Result<()> {
        let Some(ref crl_path) = self.crl_file else {
            return Ok(()); // No CRL configured, nothing to reload
        };

        let crls = load_crls_from_file(crl_path)?;
        debug!("reloaded {} CRL(s) from {}", crls.len(), crl_path);

        let verifier = WebPkiServerVerifier::builder(Arc::clone(&self.ca_certs))
            .with_crls(crls)
            .build()
            .or_err(InvalidCert, "Failed to rebuild server verifier with CRLs")?;

        let mut new_config =
            RusTlsClientConfig::builder_with_protocol_versions(&[&version::TLS12, &version::TLS13])
                .with_webpki_verifier(verifier)
                .with_no_client_auth();

        if self.debug_ssl_keylog {
            new_config.key_log = Arc::new(KeyLogFile::new());
        }

        self.config.store(Arc::new(new_config));

        // Update stored mtime
        if let Ok(meta) = std::fs::metadata(crl_path) {
            if let Ok(mtime) = meta.modified() {
                *self.crl_mtime.lock().unwrap() = Some(mtime);
            }
        }

        debug!("CRL hot-reloaded successfully");
        Ok(())
    }

    /// Check if the CRL file has been modified and reload if needed.
    /// Returns true if a reload was performed.
    pub fn check_and_reload_crl(&self) -> Result<bool> {
        let Some(ref crl_path) = self.crl_file else {
            return Ok(false);
        };

        let current_mtime = match std::fs::metadata(crl_path) {
            Ok(meta) => meta.modified().ok(),
            Err(_) => return Ok(false), // File gone, nothing to do
        };

        let stored_mtime = *self.crl_mtime.lock().unwrap();
        if current_mtime != stored_mtime {
            self.reload_crl()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Rate-limited CRL check: only stat() the file every CRL_CHECK_INTERVAL_SECS.
    /// Safe to call on every connection with negligible overhead.
    pub fn maybe_reload_crl(&self) {
        if self.crl_file.is_none() {
            return;
        }
        let mut last_check = self.last_crl_check.lock().unwrap();
        if last_check.elapsed().as_secs() < CRL_CHECK_INTERVAL_SECS {
            return;
        }
        *last_check = std::time::Instant::now();
        drop(last_check); // Release lock before doing I/O

        if let Err(e) = self.check_and_reload_crl() {
            log::warn!("CRL reload failed: {e}");
        }
    }
}

pub async fn connect<T, P>(
    stream: T,
    peer: &P,
    alpn_override: Option<ALPN>,
    tls_ctx: &TlsConnector,
) -> Result<TlsStream<T>>
where
    T: IO,
    P: Peer + Send + Sync,
{
    // Check if CRL file changed on disk (rate-limited to every 60s)
    tls_ctx.maybe_reload_crl();

    let config = tls_ctx.config.load();

    // Build per-peer CA store if provided
    let peer_ca_store: Option<Arc<RootCertStore>> = if let Some(ca_list) = peer.get_ca() {
        if ca_list.is_empty() {
            return Error::e_explain(InvalidCert, "per-peer CA list is empty");
        }
        let mut ca_store = RootCertStore::empty();
        for ca_cert in &**ca_list {
            let cert_der = CertificateDer::from(ca_cert);
            ca_store.add(cert_der).or_err(
                InvalidCert,
                "Failed to add per-peer CA certificate to root store",
            )?;
        }

        Some(Arc::new(ca_store))
    } else {
        None
    };

    // Determine effective CA store for this connection
    let effective_ca_store = peer_ca_store.as_ref().unwrap_or(&tls_ctx.ca_certs);

    let key_pair = peer.get_client_cert_key();
    let mut updated_config_opt: Option<RusTlsClientConfig> = match key_pair {
        None => None,
        Some(key_arc) => {
            debug!("setting client cert and key");

            let mut cert_chain = vec![];
            debug!("adding leaf certificate to mTLS cert chain");
            cert_chain.push(key_arc.leaf());

            debug!("adding intermediate certificates to mTLS cert chain");
            key_arc
                .intermediates()
                .to_owned()
                .iter()
                .copied()
                .for_each(|i| cert_chain.push(i));

            let certs: Vec<CertificateDer> = cert_chain.into_iter().map(|c| c.into()).collect();
            let private_key: PrivateKeyDer = key_arc
                .key()
                .as_slice()
                .to_owned()
                .try_into()
                .or_err(InvalidCert, "Failed to convert private key to PrivateKeyDer")?;

            let builder = RusTlsClientConfig::builder_with_protocol_versions(&[
                &version::TLS12,
                &version::TLS13,
            ])
            .with_root_certificates(Arc::clone(effective_ca_store));
            debug!("added root ca certificates");

            let mut updated_config = builder.with_client_auth_cert(certs, private_key).or_err(
                InvalidCert,
                "Failed to use peer cert/key to update Rustls config",
            )?;
            // Preserve keylog setting from original config
            updated_config.key_log = Arc::clone(&config.key_log);
            Some(updated_config)
        }
    };

    // Ensure config is updated if per-peer CA is set but no client cert
    if peer_ca_store.is_some() && updated_config_opt.is_none() {
        let mut updated_config =
            RusTlsClientConfig::builder_with_protocol_versions(&[&version::TLS12, &version::TLS13])
                .with_root_certificates(Arc::clone(effective_ca_store))
                .with_no_client_auth();

        updated_config.key_log = Arc::clone(&config.key_log);
        updated_config_opt = Some(updated_config);
    }

    if let Some(alpn) = alpn_override.as_ref().or(peer.get_alpn()) {
        let alpn_protocols = alpn.to_wire_protocols();
        if let Some(updated_config) = updated_config_opt.as_mut() {
            updated_config.alpn_protocols = alpn_protocols;
        } else {
            let mut updated_config = RusTlsClientConfig::clone(&config);
            updated_config.alpn_protocols = alpn_protocols;
            updated_config_opt = Some(updated_config);
        }
    }

    let mut domain = peer.sni().to_string();

    if let Some(updated_config) = updated_config_opt.as_mut() {
        let verification_mode = if peer.sni().is_empty() {
            updated_config.enable_sni = false;
            // No SNI: skip hostname check but still validate certificate chain
            // (CA signature, expiration, revocation). A MITM with a self-signed
            // cert is rejected; only certs from trusted CAs are accepted.
            debug!("empty SNI: hostname verification disabled, chain validation active");
            Some(VerificationMode::SkipHostname)
        } else if !peer.verify_cert() {
            Some(VerificationMode::SkipAll)
        } else if !peer.verify_hostname() {
            Some(VerificationMode::SkipHostname)
        } else {
            // if sni had underscores in leftmost label replace and add
            if let Some(sni_s) = replace_leftmost_underscore(peer.sni()) {
                domain = sni_s;
            }
            None
            // to use the custom verifier for the full verify:
            // Some(VerificationMode::Full)
        };

        // Builds the custom_verifier when verification_mode is set.
        if let Some(mode) = verification_mode {
            let delegate = WebPkiServerVerifier::builder(Arc::clone(effective_ca_store))
                .build()
                .or_err(InvalidCert, "Failed to build WebPkiServerVerifier")?;

            let custom_verifier = Arc::new(CustomServerCertVerifier::new(delegate, mode));

            updated_config
                .dangerous()
                .set_certificate_verifier(custom_verifier);
        }
    }

    // TODO: curve setup from peer
    // - second key share from peer, currently only used in boringssl with PQ features

    // Patch config for dangerous verifier if needed, but only in test builds.
    #[cfg(test)]
    if !peer.verify_cert() || !peer.verify_hostname() {
        use crate::connectors::http::rustls_no_verify::apply_no_verify;
        if let Some(cfg) = updated_config_opt.as_mut() {
            apply_no_verify(cfg);
        } else {
            let mut tmp = RusTlsClientConfig::clone(&config);
            apply_no_verify(&mut tmp);
            updated_config_opt = Some(tmp);
        }
    }

    let tls_conn = if let Some(cfg) = updated_config_opt {
        RusTlsConnector::from(Arc::new(cfg))
    } else {
        RusTlsConnector::from(Arc::clone(&config))
    };

    let connect_future = handshake(&tls_conn, &domain, stream);

    match peer.connection_timeout() {
        Some(t) => match lorica_timeout::timeout(t, connect_future).await {
            Ok(res) => res,
            Err(_) => Error::e_explain(
                ConnectTimedout,
                format!("connecting to server {}, timeout {:?}", peer, t),
            ),
        },
        None => connect_future.await,
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum VerificationMode {
    SkipHostname,
    SkipAll,
    Full,
    // Note: "Full" Included for completeness, making this verifier self-contained
    // and explicit about all possible verification modes, not just exceptions.
}

#[derive(Debug)]
pub struct CustomServerCertVerifier {
    delegate: Arc<WebPkiServerVerifier>,
    verification_mode: VerificationMode,
}

impl CustomServerCertVerifier {
    pub fn new(delegate: Arc<WebPkiServerVerifier>, verification_mode: VerificationMode) -> Self {
        Self {
            delegate,
            verification_mode,
        }
    }
}

// CustomServerCertVerifier delegates TLS signature verification and allows 3 VerificationMode:
// Full: delegates all verification to the original WebPkiServerVerifier
// SkipHostname: same as "Full" but ignores "NotValidForName" certificate errors
// SkipAll: all certificate verification checks are skipped.
impl RusTlsServerCertVerifier for CustomServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RusTlsError> {
        match self.verification_mode {
            VerificationMode::Full => self.delegate.verify_server_cert(
                _end_entity,
                _intermediates,
                _server_name,
                _ocsp,
                _now,
            ),
            VerificationMode::SkipHostname => {
                match self.delegate.verify_server_cert(
                    _end_entity,
                    _intermediates,
                    _server_name,
                    _ocsp,
                    _now,
                ) {
                    Ok(scv) => Ok(scv),
                    Err(RusTlsError::InvalidCertificate(cert_error)) => {
                        if let CertificateError::NotValidForNameContext { .. } = cert_error {
                            Ok(ServerCertVerified::assertion())
                        } else {
                            Err(RusTlsError::InvalidCertificate(cert_error))
                        }
                    }
                    Err(e) => Err(e),
                }
            }
            VerificationMode::SkipAll => Ok(ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RusTlsError> {
        self.delegate.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RusTlsError> {
        self.delegate.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.delegate.supported_verify_schemes()
    }
}
