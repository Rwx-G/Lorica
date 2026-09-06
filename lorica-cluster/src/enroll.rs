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

//! Enrollment and session hooks (Story 9.3): the seams through which
//! the transport crate asks the binary to redeem a token, renew a
//! certificate, or record a lifecycle event, without depending on the
//! configuration store. Plus the joining side: one pinned TLS
//! connection carrying one `Enroll` frame.
//!
//! Both hooks are traits returning boxed futures (no `async-trait`
//! dependency): the binary implements them over `ConfigStore`, the
//! CA and the audit log; tests implement stubs.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use crate::dialer::split_host_port;
use crate::messages::{
    cluster_frame, cluster_request, cluster_response, ClusterFrame, ClusterRequest,
    ClusterStatus, Enroll,
};
use crate::tls::{join_client_config, negotiated_cluster_alpn, ClusterTlsError};
use crate::token::ParsedToken;

/// A boxed future, the return type of every hook method.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What a joining node presents on the enrollment listener, after the
/// listener parsed and bounded it.
#[derive(Debug, Clone)]
pub struct EnrollRequest {
    /// The peer's transport address (the source-CIDR binding input
    /// and the audit `ip`).
    pub peer: SocketAddr,
    /// The token's lookup half.
    pub public_id: String,
    /// The token's secret half (verified by the handler, never
    /// stored, never logged).
    pub secret: Vec<u8>,
    /// The node's bare public key, DER `SubjectPublicKeyInfo`
    /// (AC #3: no CSR).
    pub public_key_der: Vec<u8>,
    /// The display name the node asks for (bounded by the listener).
    pub node_name: String,
    /// The node's build version (bounded by the listener).
    pub build_version: String,
    /// The node's database schema version.
    pub schema_version: u32,
}

/// A successful redemption.
#[derive(Debug, Clone)]
pub struct EnrollGrant {
    /// The server-assigned node id.
    pub node_id: String,
    /// The issued `clientAuth` leaf, PEM.
    pub cert_pem: String,
    /// The cluster CA bundle the node verifies the control plane with
    /// from now on.
    pub ca_pem: String,
    /// `pending` or `active` (AC #5).
    pub status: String,
    /// RFC 3339 `notAfter` of the leaf.
    pub cert_not_after: String,
}

/// Why a redemption was refused. The wire never carries this: the
/// listener answers the OPAQUE status for every variant and logs the
/// diagnostic locally (Story 9.2 AC #4).
#[derive(Debug, thiserror::Error)]
pub enum EnrollRefusal {
    /// Token unknown, wrong secret, expired, burned, binding mismatch,
    /// unacceptable key: the local diagnostic names which.
    #[error("enrollment refused: {0}")]
    Refused(&'static str),
    /// The control plane could not complete the redemption (store,
    /// CA); the token is NOT burned when this happens before the
    /// burn.
    #[error("enrollment failed: {0}")]
    Internal(String),
}

/// Redeems join tokens (implemented by the binary over the store and
/// the CA).
pub trait EnrollmentHandler: Send + Sync + 'static {
    /// Verify the token, burn it atomically, issue the leaf, register
    /// the node. Runs under the listener's in-flight enrollment
    /// permit (Story 9.3 AC #1's verification cap).
    fn redeem(&self, request: EnrollRequest) -> BoxFuture<'_, Result<EnrollGrant, EnrollRefusal>>;
}

/// A handler that refuses everything: the control plane before Story
/// 9.3's runtime is wired, and the transport tests.
pub struct RefuseAllEnrollments;

impl EnrollmentHandler for RefuseAllEnrollments {
    fn redeem(&self, _request: EnrollRequest) -> BoxFuture<'_, Result<EnrollGrant, EnrollRefusal>> {
        Box::pin(async { Err(EnrollRefusal::Refused("no redemption handler installed")) })
    }
}

/// A renewal request from an established session (AC #12).
#[derive(Debug, Clone)]
pub struct RenewRequest {
    /// The requesting node (from its certificate, never the payload).
    pub node_id: String,
    /// The node's NEW bare public key, DER SPKI.
    pub public_key_der: Vec<u8>,
}

/// A renewed certificate.
#[derive(Debug, Clone)]
pub struct RenewGrant {
    /// The new `clientAuth` leaf, PEM.
    pub cert_pem: String,
    /// RFC 3339 `notAfter` of the new leaf.
    pub cert_not_after: String,
}

/// Lifecycle hooks for established sessions (implemented by the
/// binary over the store, the CRL and the audit log).
pub trait SessionHandler: Send + Sync + 'static {
    /// A node completed its handshake. `via_previous_certificate`
    /// means it presented the certificate a renewal superseded; when
    /// `false` and a superseded certificate is still on record, the
    /// handler retires it (AC #12's grace window closes).
    fn on_session_established(
        &self,
        node_id: &str,
        via_previous_certificate: bool,
        peer: SocketAddr,
        build_version: &str,
        schema_version: u32,
    ) -> BoxFuture<'_, ()>;

    /// Issue a new certificate for the node's new public key.
    fn on_renew(&self, request: RenewRequest) -> BoxFuture<'_, Result<RenewGrant, String>>;

    /// The node is leaving the fleet (AC #13): revoke it, audit, alert.
    fn on_leave(&self, node_id: &str, peer: SocketAddr) -> BoxFuture<'_, Result<(), String>>;

    /// A valid certificate with no roster entry, or a revoked one that
    /// reached identity resolution: audit it (AC #8).
    fn on_identity_refused(
        &self,
        fingerprint: &str,
        peer: SocketAddr,
        reason: &'static str,
    ) -> BoxFuture<'_, ()>;

    /// An enrolled node spoke out of plane or out of phase (Story 9.2
    /// AC #6): audit it.
    fn on_protocol_violation(&self, node_id: &str, peer: SocketAddr) -> BoxFuture<'_, ()>;
}

/// A session handler that records nothing and refuses renewals and
/// leaves: the transport tests.
pub struct NoopSessionHandler;

impl SessionHandler for NoopSessionHandler {
    fn on_session_established(
        &self,
        _node_id: &str,
        _via_previous_certificate: bool,
        _peer: SocketAddr,
        _build_version: &str,
        _schema_version: u32,
    ) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }

    fn on_renew(&self, _request: RenewRequest) -> BoxFuture<'_, Result<RenewGrant, String>> {
        Box::pin(async { Err("renewals are not served by this handler".to_string()) })
    }

    fn on_leave(&self, _node_id: &str, _peer: SocketAddr) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async { Err("leave is not served by this handler".to_string()) })
    }

    fn on_identity_refused(
        &self,
        _fingerprint: &str,
        _peer: SocketAddr,
        _reason: &'static str,
    ) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }

    fn on_protocol_violation(&self, _node_id: &str, _peer: SocketAddr) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

/// Bound on the enrollment answer a joiner will read.
const JOIN_MAX_RESPONSE_BYTES: u64 = 64 * 1024;

/// Why a join attempt failed, for the operator running
/// `lorica cluster join`.
#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    /// The enrollment address is not a `host:port`.
    #[error("invalid enrollment address {0:?}: expected host:port")]
    Address(String),
    /// Resolution, TCP, TLS (including a pin or name mismatch), or
    /// timeout.
    #[error("cannot reach the control plane's enrollment listener: {0}")]
    Transport(String),
    /// The control plane answered with the opaque refusal: unknown or
    /// burned token, expired window, binding mismatch, unacceptable
    /// key. The control plane's journal has the reason.
    #[error(
        "the control plane refused the enrollment (its journal has the reason: token unknown, \
         expired, already used, bound to another name or network, or the key type is not allowed)"
    )]
    Refused,
    /// The answer was not an enrollment grant.
    #[error("the control plane answered out of protocol")]
    Protocol,
}

/// Inputs for [`join`].
#[derive(Debug, Clone)]
pub struct JoinParams {
    /// The enrollment listener's `host:port`.
    pub enrollment_addr: String,
    /// The name (DNS or IP) the control-plane certificate must carry
    /// in its SAN (the `--control-plane` host).
    pub expected_host: String,
    /// The parsed join token (secret and pin).
    pub token: ParsedToken,
    /// The node's bare public key, DER SPKI.
    pub public_key_der: Vec<u8>,
    /// Requested display name.
    pub node_name: String,
    /// This build's version string.
    pub build_version: String,
    /// This node's schema version.
    pub schema_version: u32,
    /// Bound on the whole exchange.
    pub timeout: Duration,
}

/// The joining side (AC #2/#3): connect to the enrollment listener
/// over TLS pinned to the token's control-plane leaf SPKI, send one
/// `Enroll` frame, read one answer.
pub async fn join(params: JoinParams) -> Result<EnrollGrant, JoinError> {
    split_host_port(&params.enrollment_addr)
        .map_err(|_| JoinError::Address(params.enrollment_addr.clone()))?;
    let tls_config = join_client_config(&params.token.pin, &params.expected_host)
        .map_err(|e: ClusterTlsError| JoinError::Transport(e.to_string()))?;
    let connector = TlsConnector::from(Arc::new(tls_config));
    // rustls needs a ServerName for SNI; the pin verifier does the
    // real name check against `expected_host`.
    let server_name: ServerName<'static> = ServerName::try_from(params.expected_host.clone())
        .map_err(|e| JoinError::Transport(format!("invalid control-plane host: {e}")))?;

    tokio::time::timeout(params.timeout, async move {
        let tcp = connect_first(&params.enrollment_addr).await?;
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| JoinError::Transport(format!("tls: {e}")))?;
        if !negotiated_cluster_alpn(tls.get_ref().1) {
            return Err(JoinError::Transport(
                "the control plane did not negotiate the cluster ALPN".to_string(),
            ));
        }

        let request = ClusterRequest::enroll(Enroll {
            public_id: params.token.public_id.clone(),
            secret: params.token.secret.to_vec(),
            public_key_der: params.public_key_der.clone(),
            node_name: params.node_name.clone(),
            build_version: params.build_version.clone(),
            schema_version: params.schema_version,
        });
        let frame = ClusterFrame {
            kind: Some(cluster_frame::Kind::Request(request)),
        };
        let encoded = frame.encode_to_vec();
        let mut wire = Vec::with_capacity(8 + encoded.len());
        wire.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
        wire.extend_from_slice(&encoded);
        tls.write_all(&wire)
            .await
            .map_err(|e| JoinError::Transport(format!("send: {e}")))?;

        let mut len_buf = [0u8; 8];
        tls.read_exact(&mut len_buf)
            .await
            .map_err(|e| JoinError::Transport(format!("answer: {e}")))?;
        let len = u64::from_le_bytes(len_buf);
        if len > JOIN_MAX_RESPONSE_BYTES {
            return Err(JoinError::Protocol);
        }
        let mut body = vec![0u8; len as usize];
        tls.read_exact(&mut body)
            .await
            .map_err(|e| JoinError::Transport(format!("answer: {e}")))?;
        let frame = ClusterFrame::decode(body.as_slice()).map_err(|_| JoinError::Protocol)?;
        let Some(cluster_frame::Kind::Response(response)) = frame.kind else {
            return Err(JoinError::Protocol);
        };
        match (response.cluster_status(), response.body) {
            (ClusterStatus::Ok, Some(cluster_response::Body::EnrollAck(ack))) => Ok(EnrollGrant {
                node_id: ack.node_id,
                cert_pem: ack.cert_pem,
                ca_pem: ack.ca_pem,
                status: ack.status,
                cert_not_after: ack.cert_not_after,
            }),
            (ClusterStatus::Ok, _) => Err(JoinError::Protocol),
            _ => Err(JoinError::Refused),
        }
    })
    .await
    .map_err(|_| JoinError::Transport("timed out".to_string()))?
}

/// Resolve `host:port` and connect to the first address that answers.
async fn connect_first(addr: &str) -> Result<tokio::net::TcpStream, JoinError> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(addr)
        .await
        .map_err(|e| JoinError::Transport(format!("resolve {addr}: {e}")))?
        .collect();
    let mut last = format!("resolve {addr}: no addresses");
    for candidate in addrs {
        match tokio::net::TcpStream::connect(candidate).await {
            Ok(tcp) => return Ok(tcp),
            Err(e) => last = format!("tcp connect {candidate}: {e}"),
        }
    }
    Err(JoinError::Transport(last))
}

/// Decode the single frame an enrollment connection sends into an
/// [`Enroll`] body, or `None` when it is anything else (the listener
/// answers the opaque status either way).
pub fn decode_enroll_frame(bytes: &[u8]) -> Option<(u64, Enroll)> {
    let frame = ClusterFrame::decode(bytes).ok()?;
    let cluster_frame::Kind::Request(request) = frame.kind? else {
        return None;
    };
    if !request.body_kind_matches() {
        return None;
    }
    match request.body {
        Some(cluster_request::Body::Enroll(enroll)) => Some((request.sequence, enroll)),
        _ => None,
    }
}
