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

//! Lorica: PROXY protocol accept on the listening endpoints.
//!
//! This module does not exist upstream: it is an additive Lorica-only file
//! of the fork (`FORK.md`, "Lorica divergences in forked crates"), built on
//! the sans-IO parser of [`crate::protocols::proxy_protocol`].
//!
//! An endpoint registered with
//! [`Listeners::add_endpoint_with_proxy_protocol`](super::Listeners::add_endpoint_with_proxy_protocol)
//! asks its [`ProxyProtocolPolicy`] for the mode on every accept. With the
//! mode [`ProxyProtocolMode::Off`] the endpoint behaves exactly as one
//! registered without a policy. Otherwise:
//!
//! - a peer the policy trusts skips the connection filter at accept; its
//!   connection task reads the header (bounded by [`MAX_HEADER_LEN`] and by
//!   [`HEADER_READ_TIMEOUT`] from accept), installs the carried addresses
//!   in the socket digest, and only then runs the connection filter, on the
//!   carried client address;
//! - any other peer is filtered at accept as today and served as a direct
//!   client, unless its first bytes are a PROXY signature, which closes
//!   the connection. The sniff is bounded by [`HEADER_READ_TIMEOUT`] from
//!   accept too: a peer whose first bytes have not told it apart by then
//!   is served as a direct client, its bytes rewound, and a signature it
//!   completes later reaches the HTTP parser or the TLS handshake as
//!   bytes, never as a header.
//!
//! Both reads happen in the connection task, before the read buffer is
//! set, so a slow peer never stalls the accept loop and no client byte
//! read past the header is lost. Every outcome is reported to the policy;
//! a refused connection is dropped without an answer.

use std::fmt::Debug;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use log::debug;
use lorica_error::{Error, ErrorType, OrErr, Result};
use tokio::io::AsyncReadExt;
use tokio::time::Instant;

use super::connection_filter::{AcceptVerdict, ConnectionFilter};
use crate::protocols::l4::stream::Stream;
use crate::protocols::proxy_protocol::{
    classify_prefix, parse, Addresses, ParseError, Parsed, Prefix, Version, HEADER_READ_TIMEOUT,
    MAX_HEADER_LEN, V2_SIGNATURE,
};
use crate::protocols::{GetSocketDigest, ProxiedFrom, SocketDigest};

/// Whether a listener accepts a PROXY header, read live on every accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyProtocolMode {
    /// No header is read; the listener behaves as one without a policy.
    #[default]
    Off,
    /// A trusted peer must send a header; one that sends none is closed.
    Required,
    /// A trusted peer may send a header; one that sends none is served on
    /// its socket address (load balancer health checks).
    Optional,
}

/// The outcome of the header read on one connection. Accepted outcomes
/// let the connection through; refused ones close it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum_macros::EnumIter)]
pub enum ProxyHeaderOutcome {
    /// A v1 header carrying the client address.
    V1,
    /// A v2 header carrying the client address.
    V2,
    /// A header carrying no client address (`LOCAL`, `UNKNOWN`,
    /// `AF_UNSPEC`, `AF_UNIX`): the socket addresses apply.
    Local,
    /// No header from a trusted peer under [`ProxyProtocolMode::Optional`].
    Absent,
    /// A PROXY signature from a peer the policy does not trust.
    UntrustedPeer,
    /// No header from a trusted peer under [`ProxyProtocolMode::Required`].
    Missing,
    /// A header that breaks the grammar of its version.
    Malformed,
    /// A header longer than [`MAX_HEADER_LEN`].
    Oversized,
    /// A well-formed header this listener does not accept.
    Unsupported,
    /// No complete header within [`HEADER_READ_TIMEOUT`] of accept.
    Timeout,
}

impl ProxyHeaderOutcome {
    /// Every outcome, in declaration order, derived from the enum so a new
    /// variant is listed without a second edit.
    pub fn all() -> impl Iterator<Item = ProxyHeaderOutcome> {
        <ProxyHeaderOutcome as strum::IntoEnumIterator>::iter()
    }

    /// The stable label of the outcome, for metrics and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            ProxyHeaderOutcome::V1 => "v1",
            ProxyHeaderOutcome::V2 => "v2",
            ProxyHeaderOutcome::Local => "local",
            ProxyHeaderOutcome::Absent => "absent",
            ProxyHeaderOutcome::UntrustedPeer => "untrusted_peer",
            ProxyHeaderOutcome::Missing => "missing",
            ProxyHeaderOutcome::Malformed => "malformed",
            ProxyHeaderOutcome::Oversized => "oversized",
            ProxyHeaderOutcome::Unsupported => "unsupported",
            ProxyHeaderOutcome::Timeout => "timeout",
        }
    }

    /// Whether the connection goes on after this outcome.
    pub fn is_accepted(self) -> bool {
        matches!(
            self,
            ProxyHeaderOutcome::V1
                | ProxyHeaderOutcome::V2
                | ProxyHeaderOutcome::Local
                | ProxyHeaderOutcome::Absent
        )
    }

    fn of_parse_error(error: &ParseError) -> ProxyHeaderOutcome {
        match error {
            ParseError::Malformed(_) => ProxyHeaderOutcome::Malformed,
            ParseError::Oversized(_) => ProxyHeaderOutcome::Oversized,
            ParseError::Unsupported(_) => ProxyHeaderOutcome::Unsupported,
        }
    }
}

/// The PROXY protocol policy of one listening endpoint, implemented by the
/// application. Every method runs on the accept path, so each must be cheap
/// and must not block.
pub trait ProxyProtocolPolicy: Debug + Send + Sync {
    /// The listener's mode, asked once per accepted connection.
    fn mode(&self) -> ProxyProtocolMode;

    /// Whether `peer`, a socket peer, may send a header.
    fn is_trusted(&self, peer: &SocketAddr) -> bool;

    /// Reports the outcome of the header read on one connection. `peer` is
    /// the socket peer (`None` on a Unix socket). `detail` says why a
    /// refused outcome was refused and is `None` for an accepted one.
    fn record(
        &self,
        outcome: ProxyHeaderOutcome,
        peer: Option<&SocketAddr>,
        detail: Option<&'static str>,
    );
}

/// The error type of a connection closed before its handshake by a PROXY
/// refusal or by the connection filter run after the header. The policy
/// or the filter has already reported it, so the listener service logs it
/// at debug level only (`services/listening.rs`).
pub(crate) const REFUSED_BEFORE_HANDSHAKE: ErrorType = ErrorType::new("RefusedBeforeHandshake");

/// What the connection task still owes a connection accepted on an endpoint
/// whose mode was not [`ProxyProtocolMode::Off`].
pub(crate) struct PendingProxyHeader {
    stage: Stage,
    policy: Arc<dyn ProxyProtocolPolicy>,
    filter: Arc<dyn ConnectionFilter>,
}

enum Stage {
    /// A trusted peer: the connection filter was skipped at accept.
    AwaitingHeader {
        peer: SocketAddr,
        accepted_at: Instant,
    },
    /// Any other peer, filtered at accept on its socket address.
    Direct { accepted_at: Instant },
}

/// What the header read found, before the connection filter runs.
enum HeaderRead {
    Carried {
        version: Version,
        source: SocketAddr,
        destination: SocketAddr,
        consumed: usize,
    },
    NoAddress {
        consumed: usize,
    },
    Absent,
}

struct Refusal {
    outcome: ProxyHeaderOutcome,
    detail: &'static str,
}

impl Refusal {
    fn new(outcome: ProxyHeaderOutcome, detail: &'static str) -> Refusal {
        Refusal { outcome, detail }
    }
}

impl PendingProxyHeader {
    pub(crate) fn awaiting_header(
        policy: Arc<dyn ProxyProtocolPolicy>,
        filter: Arc<dyn ConnectionFilter>,
        peer: SocketAddr,
        accepted_at: Instant,
    ) -> PendingProxyHeader {
        PendingProxyHeader {
            stage: Stage::AwaitingHeader { peer, accepted_at },
            policy,
            filter,
        }
    }

    pub(crate) fn direct(
        policy: Arc<dyn ProxyProtocolPolicy>,
        filter: Arc<dyn ConnectionFilter>,
        accepted_at: Instant,
    ) -> PendingProxyHeader {
        PendingProxyHeader {
            stage: Stage::Direct { accepted_at },
            policy,
            filter,
        }
    }

    /// Reads the header or sniffs for a signature on `stream`, which must
    /// not have its read buffer set yet. On `Ok` the stream is ready for
    /// the handshake, every byte read past a header rewound onto it.
    pub(crate) async fn resolve(self, stream: &mut Stream) -> Result<()> {
        match self.stage {
            Stage::Direct { accepted_at } => {
                refuse_signature(&*self.policy, stream, accepted_at).await
            }
            Stage::AwaitingHeader { peer, accepted_at } => {
                self.read_header(stream, peer, accepted_at).await
            }
        }
    }

    async fn read_header(
        &self,
        stream: &mut Stream,
        peer: SocketAddr,
        accepted_at: Instant,
    ) -> Result<()> {
        let mode = self.policy.mode();
        let mut buf: Vec<u8> = Vec::with_capacity(MAX_HEADER_LEN);
        let read = tokio::time::timeout_at(
            accepted_at + HEADER_READ_TIMEOUT,
            read_until_parsed(stream, &mut buf, mode),
        )
        .await
        .unwrap_or_else(|_| {
            Ok(Err(Refusal::new(
                ProxyHeaderOutcome::Timeout,
                "no complete header within the read timeout",
            )))
        })?;
        let read = match read {
            Ok(read) => read,
            Err(refusal) => {
                self.policy
                    .record(refusal.outcome, Some(&peer), Some(refusal.detail));
                return refused(refusal.outcome.as_str());
            }
        };

        let client = match read {
            HeaderRead::Carried {
                version,
                source,
                destination,
                consumed,
            } => {
                let local = stream
                    .get_socket_digest()
                    .and_then(|digest| digest.local_addr().and_then(|a| a.as_inet()).copied());
                let proxied_from = ProxiedFrom {
                    peer,
                    local,
                    version,
                };
                let digest =
                    SocketDigest::proxied(stream.as_raw_fd(), source, destination, proxied_from);
                stream.set_socket_digest(digest);
                stream.rewind(&buf[consumed..]);
                let outcome = match version {
                    Version::V1 => ProxyHeaderOutcome::V1,
                    Version::V2 => ProxyHeaderOutcome::V2,
                };
                self.policy.record(outcome, Some(&peer), None);
                source
            }
            HeaderRead::NoAddress { consumed } => {
                stream.rewind(&buf[consumed..]);
                self.policy
                    .record(ProxyHeaderOutcome::Local, Some(&peer), None);
                peer
            }
            HeaderRead::Absent => {
                stream.rewind(&buf);
                self.policy
                    .record(ProxyHeaderOutcome::Absent, Some(&peer), None);
                peer
            }
        };

        // The filter skipped at accept runs now, on the client address the
        // connection turned out to have; its permit rides on the stream as
        // it would have from the accept loop.
        if admit(&*self.filter, stream, Some(&client)).await {
            Ok(())
        } else {
            refused("connection filter")
        }
    }
}

/// Attaches the permit of an accepting verdict to `stream`, or answers
/// `false` for a rejecting one.
pub(super) fn apply_verdict(stream: &mut Stream, verdict: AcceptVerdict) -> bool {
    match verdict {
        AcceptVerdict::Reject => {
            debug!("Connection rejected by filter");
            false
        }
        AcceptVerdict::Accept(permit) => {
            // The permit rides on the stream so counting filters decrement
            // exactly when the connection closes (RAII, Story 8.9 AC #5).
            if let Some(permit) = permit {
                stream.set_accept_permit(permit);
            }
            true
        }
    }
}

/// Runs `filter` on `addr` for `stream`.
async fn admit(
    filter: &dyn ConnectionFilter,
    stream: &mut Stream,
    addr: Option<&SocketAddr>,
) -> bool {
    let verdict = filter.try_accept(addr).await;
    apply_verdict(stream, verdict)
}

fn refused(reason: &'static str) -> Result<()> {
    Error::e_explain(REFUSED_BEFORE_HANDSHAKE, reason)
}

/// Whether `error` is a refusal already reported by the policy or the
/// connection filter.
pub(crate) fn is_refusal(error: &Error) -> bool {
    error.etype() == &REFUSED_BEFORE_HANDSHAKE
}

/// Reads from a trusted peer until the buffer holds a complete header, or
/// a refusal, or (under [`ProxyProtocolMode::Optional`]) bytes that open
/// with no PROXY signature.
async fn read_until_parsed(
    stream: &mut Stream,
    buf: &mut Vec<u8>,
    mode: ProxyProtocolMode,
) -> Result<std::result::Result<HeaderRead, Refusal>> {
    loop {
        if classify_prefix(buf) == Prefix::NotProxy {
            return Ok(if mode == ProxyProtocolMode::Optional {
                Ok(HeaderRead::Absent)
            } else {
                Err(Refusal::new(
                    ProxyHeaderOutcome::Missing,
                    "no PROXY header from a trusted peer",
                ))
            });
        }
        match parse(buf) {
            Ok(Parsed::Complete { header, consumed }) => {
                return Ok(match header.addresses {
                    Addresses::Tcp {
                        source,
                        destination,
                    } => Ok(HeaderRead::Carried {
                        version: header.version,
                        source,
                        destination,
                        consumed,
                    }),
                    Addresses::Unspecified | Addresses::Unix => {
                        Ok(HeaderRead::NoAddress { consumed })
                    }
                    Addresses::Udp { .. } => Err(Refusal::new(
                        ProxyHeaderOutcome::Unsupported,
                        "DGRAM transport on an HTTP listener",
                    )),
                });
            }
            Ok(Parsed::Incomplete) => {}
            Err(error) => {
                return Ok(Err(Refusal::new(
                    ProxyHeaderOutcome::of_parse_error(&error),
                    error.detail(),
                )))
            }
        }
        // The parser refuses an oversized header from its fixed part, so a
        // full buffer still incomplete cannot happen; bounding the read
        // keeps that a guarantee rather than an assumption.
        if buf.len() >= MAX_HEADER_LEN {
            return Ok(Err(Refusal::new(
                ProxyHeaderOutcome::Oversized,
                "header longer than the maximum",
            )));
        }
        let filled = buf.len();
        buf.resize(MAX_HEADER_LEN, 0);
        let read = stream.read(&mut buf[filled..]).await;
        let n = read.or_err(ErrorType::ReadError, "while reading the PROXY header")?;
        buf.truncate(filled + n);
        if n == 0 {
            return Ok(match (filled, mode) {
                (0, ProxyProtocolMode::Optional) => Ok(HeaderRead::Absent),
                (0, _) => Err(Refusal::new(
                    ProxyHeaderOutcome::Missing,
                    "connection closed before any byte",
                )),
                _ => Err(Refusal::new(
                    ProxyHeaderOutcome::Malformed,
                    "connection closed inside the header",
                )),
            });
        }
    }
}

/// Reads the first bytes of a direct client until they tell a PROXY
/// signature apart, closes the connection on one, and rewinds them
/// otherwise.
///
/// Bounded by [`HEADER_READ_TIMEOUT`] from `accepted_at`, as the trusted
/// read is. Without that bound a client that sends nothing would wait
/// out the 60 s handshake timeout and end in an unthrottled error line,
/// where a plaintext listener without PROXY hands it to the HTTP read at
/// once. On expiry the bytes read so far are rewound and the connection
/// goes on as a direct client: whatever it sends later is the HTTP
/// parser's or the TLS handshake's to judge, and is never read as a
/// header.
async fn refuse_signature(
    policy: &dyn ProxyProtocolPolicy,
    stream: &mut Stream,
    accepted_at: Instant,
) -> Result<()> {
    let mut prefix = [0u8; V2_SIGNATURE.len()];
    let mut filled = 0;
    let sniff = tokio::time::timeout_at(
        accepted_at + HEADER_READ_TIMEOUT,
        read_prefix(stream, &mut prefix, &mut filled),
    )
    .await;
    let verdict = match sniff {
        Ok(verdict) => verdict?,
        Err(_) => {
            debug!("No PROXY signature decided within the read timeout: served as a direct client");
            Prefix::NotProxy
        }
    };
    match verdict {
        Prefix::V1 | Prefix::V2 => {
            let peer = stream
                .get_socket_digest()
                .and_then(|digest| digest.peer_addr().and_then(|a| a.as_inet()).copied());
            policy.record(
                ProxyHeaderOutcome::UntrustedPeer,
                peer.as_ref(),
                Some("PROXY signature from a peer outside the trust list"),
            );
            refused(ProxyHeaderOutcome::UntrustedPeer.as_str())
        }
        Prefix::NotProxy | Prefix::NeedMore => {
            stream.rewind(&prefix[..filled]);
            Ok(())
        }
    }
}

/// Reads into `prefix` until [`classify_prefix`] decides, `filled` kept
/// current so a caller that stops waiting still holds every byte read.
async fn read_prefix(stream: &mut Stream, prefix: &mut [u8], filled: &mut usize) -> Result<Prefix> {
    loop {
        let verdict = classify_prefix(&prefix[..*filled]);
        if verdict != Prefix::NeedMore {
            return Ok(verdict);
        }
        let n = stream
            .read(&mut prefix[*filled..])
            .await
            .or_err(ErrorType::ReadError, "while reading the first bytes")?;
        if n == 0 {
            // Closed mid-prefix: what was sent goes on, and the handshake
            // sees the end of stream as it would have.
            return Ok(Prefix::NotProxy);
        }
        *filled += n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;

    use tokio::io::AsyncWriteExt;

    use crate::listeners::AcceptAllFilter;
    use crate::protocols::proxy_protocol::accept_vectors::{
        vectors, AcceptVector, Outcome, Peer, Refusal, Then,
    };

    /// A policy in `required` mode that keeps every outcome it is told.
    /// It trusts nobody: the tests pick each connection's stage
    /// themselves, as the accept loop would from the trust list.
    #[derive(Debug, Default)]
    struct Recorder(Mutex<Vec<ProxyHeaderOutcome>>);

    impl ProxyProtocolPolicy for Recorder {
        fn mode(&self) -> ProxyProtocolMode {
            ProxyProtocolMode::Required
        }

        fn is_trusted(&self, _peer: &SocketAddr) -> bool {
            false
        }

        fn record(
            &self,
            outcome: ProxyHeaderOutcome,
            _peer: Option<&SocketAddr>,
            _detail: Option<&'static str>,
        ) {
            self.0.lock().expect("records lock").push(outcome);
        }
    }

    /// The server side of a loopback connection, with the socket digest
    /// the listener gives it, and its client.
    async fn accepted() -> (Stream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let client = tokio::net::TcpStream::connect(listener.local_addr().expect("address"))
            .await
            .expect("connect");
        let (server, _) = listener.accept().await.expect("accept");
        let mut server = Stream::from(server);
        let digest = SocketDigest::from_raw_fd(server.as_raw_fd());
        server.set_socket_digest(digest);
        (server, client)
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_direct_client_is_served_once_the_read_timeout_passes() {
        let policy = Arc::new(Recorder::default());
        let (mut server, _client) = accepted().await;
        let accepted_at = Instant::now();
        let pending =
            PendingProxyHeader::direct(policy.clone(), Arc::new(AcceptAllFilter), accepted_at);

        // The 60 s handshake timeout of `services::listening`.
        let resolved =
            tokio::time::timeout(Duration::from_secs(60), pending.resolve(&mut server)).await;

        assert!(
            matches!(resolved, Ok(Ok(()))),
            "the sniff gives up at the read timeout and serves the client: {resolved:?}"
        );
        let waited = accepted_at.elapsed();
        assert!(waited >= HEADER_READ_TIMEOUT, "{waited:?}");
        assert!(
            waited < HEADER_READ_TIMEOUT + Duration::from_secs(1),
            "{waited:?}"
        );
        assert!(policy.0.lock().expect("records lock").is_empty());
    }

    /// The shared vocabulary's name for a refused outcome of this path.
    fn refusal_of(outcome: ProxyHeaderOutcome) -> Refusal {
        match outcome {
            ProxyHeaderOutcome::Missing => Refusal::Missing,
            ProxyHeaderOutcome::Malformed => Refusal::Malformed,
            ProxyHeaderOutcome::Oversized => Refusal::Oversized,
            ProxyHeaderOutcome::Unsupported => Refusal::Unsupported,
            ProxyHeaderOutcome::Timeout => Refusal::Timeout,
            ProxyHeaderOutcome::UntrustedPeer => Refusal::UntrustedPeer,
            accepted @ (ProxyHeaderOutcome::V1
            | ProxyHeaderOutcome::V2
            | ProxyHeaderOutcome::Local
            | ProxyHeaderOutcome::Absent) => panic!("{accepted:?} is not a refusal"),
        }
    }

    /// Runs `vector` through this path, from the stage the accept loop
    /// hands on to the end of `resolve`, and answers the outcome, read
    /// from the policy's records and the socket digest, with the bytes
    /// the handshake would go on with.
    async fn replay(vector: &AcceptVector) -> (Outcome, Vec<u8>) {
        let policy = Arc::new(Recorder::default());
        let (mut server, mut client) = accepted().await;
        let accepted_at = Instant::now();
        let filter: Arc<dyn ConnectionFilter> = Arc::new(AcceptAllFilter);
        let pending = match vector.peer {
            Peer::Trusted => {
                let peer = client.local_addr().expect("address");
                PendingProxyHeader::awaiting_header(policy.clone(), filter, peer, accepted_at)
            }
            Peer::Untrusted => PendingProxyHeader::direct(policy.clone(), filter, accepted_at),
        };
        let (writes, then) = (vector.writes.clone(), vector.then);
        let writer = tokio::spawn(async move {
            for write in writes {
                tokio::time::sleep(write.pause).await;
                if client.write_all(&write.bytes).await.is_err() {
                    return client;
                }
            }
            if then == Then::Close {
                let _ = client.shutdown().await;
            }
            client
        });

        // The 60 s handshake timeout of `services::listening`.
        let resolved = tokio::time::timeout(Duration::from_secs(60), pending.resolve(&mut server))
            .await
            .unwrap_or_else(|_| panic!("{}: undecided at the handshake timeout", vector.name));
        let recorded = policy.0.lock().expect("records lock").clone();
        let outcome = match (resolved, &recorded[..]) {
            (Err(error), [refused]) if is_refusal(&error) => Outcome::Refused(refusal_of(*refused)),
            (Ok(()), []) => Outcome::Direct,
            (Ok(()), [ProxyHeaderOutcome::Local]) => Outcome::NoAddress,
            (Ok(()), [carried @ (ProxyHeaderOutcome::V1 | ProxyHeaderOutcome::V2)]) => {
                let digest = server.get_socket_digest().expect("a digest");
                Outcome::Carried {
                    version: if *carried == ProxyHeaderOutcome::V1 {
                        Version::V1
                    } else {
                        Version::V2
                    },
                    source: *digest
                        .peer_addr()
                        .and_then(|a| a.as_inet())
                        .expect("the carried source"),
                    destination: *digest
                        .local_addr()
                        .and_then(|a| a.as_inet())
                        .expect("the carried destination"),
                }
            }
            (resolved, recorded) => panic!("{}: {resolved:?} with {recorded:?}", vector.name),
        };
        let mut delivered = Vec::new();
        if !matches!(outcome, Outcome::Refused(_)) {
            tokio::time::timeout(Duration::from_secs(60), server.read_to_end(&mut delivered))
                .await
                .unwrap_or_else(|_| panic!("{}: no end of stream", vector.name))
                .expect("read");
        }
        writer.abort();
        (outcome, delivered)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn every_accept_vector_reaches_its_outcome_on_the_http_path() {
        let replays: Vec<_> = vectors()
            .into_iter()
            .map(|vector| {
                tokio::spawn(async move {
                    let observed = replay(&vector).await;
                    (vector, observed)
                })
            })
            .collect();
        for replay in replays {
            let (vector, (outcome, delivered)) = replay.await.expect("replay task");
            assert_eq!(outcome, vector.expected, "{}", vector.name);
            assert_eq!(
                String::from_utf8_lossy(&delivered),
                String::from_utf8_lossy(&vector.delivered),
                "{}",
                vector.name
            );
        }
    }

    #[test]
    fn labels_are_unique_and_split_accepted_from_refused() {
        let labels: std::collections::HashSet<&str> = ProxyHeaderOutcome::all()
            .map(|outcome| outcome.as_str())
            .collect();
        assert_eq!(labels.len(), ProxyHeaderOutcome::all().count());
        let accepted: Vec<&str> = ProxyHeaderOutcome::all()
            .filter(|outcome| outcome.is_accepted())
            .map(|outcome| outcome.as_str())
            .collect();
        assert_eq!(accepted, ["v1", "v2", "local", "absent"]);
    }

    #[test]
    fn the_default_mode_is_off() {
        assert_eq!(ProxyProtocolMode::default(), ProxyProtocolMode::Off);
    }
}
