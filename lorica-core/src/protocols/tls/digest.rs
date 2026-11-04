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

//! TLS information from the TLS connection

use std::any::Any;
use std::borrow::Cow;
use std::collections::VecDeque;
use std::sync::Arc;

use parking_lot::Mutex;

/// The TLS connection information
#[derive(Clone, Debug)]
pub struct SslDigest {
    /// The cipher used
    pub cipher: Cow<'static, str>,
    /// The TLS version of this connection
    pub version: Cow<'static, str>,
    /// The organization of the peer's certificate
    pub organization: Option<String>,
    /// Lorica: every `O=` value of the peer's end-entity subject, each
    /// whole, in subject order. `organization` joins them with no
    /// separator, so `O=Ac, O=me` reads as `Acme` there; a policy that
    /// matches organizations compares these. Empty when the peer sent no
    /// certificate or its subject has no `O=`.
    pub peer_organizations: Vec<String>,
    /// The serial number of the peer's certificate
    pub serial_number: Option<String>,
    /// The digest of the peer's certificate
    pub cert_digest: Vec<u8>,
    /// The user-defined TLS data
    pub extension: SslDigestExtension,
    /// Lorica: the certificate chain a client presented to a listener.
    /// Empty when the client presented none, and always empty on a
    /// connection Lorica opened, so an upstream leg does not carry its
    /// server's chain around.
    ///
    /// The listener's verifier accepted this chain, but an application that
    /// trusts different roots for different requests on one listener must
    /// verify it again against the roots that apply; `organization`,
    /// `serial_number` and `cert_digest` describe the same end-entity and
    /// are no more trustworthy than it.
    pub peer_cert_chain: PeerCertChain,
    /// Lorica: the application's verdicts on `peer_cert_chain`, kept for the
    /// life of the connection.
    pub peer_chain_verdicts: PeerChainVerdicts,
}

impl SslDigest {
    /// Create a new SslDigest
    pub fn new<S>(
        cipher: S,
        version: S,
        organization: Option<String>,
        serial_number: Option<String>,
        cert_digest: Vec<u8>,
    ) -> Self
    where
        S: Into<Cow<'static, str>>,
    {
        SslDigest {
            cipher: cipher.into(),
            version: version.into(),
            organization,
            peer_organizations: Vec::new(),
            serial_number,
            cert_digest,
            extension: SslDigestExtension::default(),
            peer_cert_chain: PeerCertChain::default(),
            peer_chain_verdicts: PeerChainVerdicts::default(),
        }
    }
}

/// Lorica: a client's certificate chain as a connection keeps it, DER,
/// end-entity first, in the order it was sent.
///
/// rustls keeps its own copy for the life of the connection, so this
/// one is bounded: at most [`PeerCertChain::MAX_CERTIFICATES`]
/// certificates and [`PeerCertChain::MAX_BYTES`] of DER. A chain past
/// either bound is kept truncated and marked so; it still counts as
/// presented, and [`PeerCertChain::verifiable`] withholds it, so a
/// verification reached through that method refuses it rather than
/// judging a prefix that might verify on its own. A legitimate client
/// chain is an end-entity and a few intermediates, far inside both.
///
/// `Debug` prints the shape, never the certificates: they are client
/// identities, and a digest logged with `?` must not dump them.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct PeerCertChain {
    certificates: Vec<Vec<u8>>,
    truncated: bool,
}

impl PeerCertChain {
    /// How many certificates a connection keeps.
    pub const MAX_CERTIFICATES: usize = 10;
    /// How many bytes of DER a connection keeps, all certificates together.
    pub const MAX_BYTES: usize = 32 * 1024;

    /// Keep `presented` (DER, end-entity first) within the bounds,
    /// truncating and marking a chain that exceeds them.
    pub fn new<'c>(presented: impl IntoIterator<Item = &'c [u8]>) -> Self {
        let mut chain = PeerCertChain::default();
        let mut kept_bytes = 0usize;
        for der in presented {
            if chain.certificates.len() == Self::MAX_CERTIFICATES
                || kept_bytes + der.len() > Self::MAX_BYTES
            {
                chain.truncated = true;
                break;
            }
            kept_bytes += der.len();
            chain.certificates.push(der.to_vec());
        }
        chain
    }

    /// Whether the client presented a certificate at all, a chain over
    /// the bounds included.
    pub fn is_presented(&self) -> bool {
        self.truncated || !self.certificates.is_empty()
    }

    /// Whether the presented chain exceeded the bounds.
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// The chain to verify: `None` when none was presented or when it was
    /// truncated, which a verifier must read as a chain that does not
    /// verify.
    pub fn verifiable(&self) -> Option<&[Vec<u8>]> {
        (!self.truncated && !self.certificates.is_empty()).then_some(self.certificates.as_slice())
    }
}

impl std::fmt::Debug for PeerCertChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerCertChain")
            .field("certificates", &self.certificates.len())
            .field(
                "bytes",
                &self.certificates.iter().map(Vec::len).sum::<usize>(),
            )
            .field("truncated", &self.truncated)
            .finish()
    }
}

/// Lorica: verdicts an application reached on a connection's
/// [`SslDigest::peer_cert_chain`], keyed by an id the application chooses
/// (Lorica uses one per route verifier), so a keep-alive or HTTP/2
/// connection verifies its chain once per key rather than once per request.
///
/// Sound because the chain cannot change for the life of a connection:
/// rustls supports neither renegotiation nor TLS 1.3 post-handshake
/// authentication. Holds at most [`PeerChainVerdicts::CAPACITY`] keys and
/// forgets the oldest past that, so a connection kept open across many
/// reloads does not grow it without bound; a forgotten key is simply
/// computed again.
#[derive(Debug, Default)]
pub struct PeerChainVerdicts {
    entries: Mutex<VecDeque<(u64, bool)>>,
}

impl PeerChainVerdicts {
    /// How many keys one connection remembers.
    pub const CAPACITY: usize = 16;

    /// The verdict recorded under `key`, if any.
    pub fn get(&self, key: u64) -> Option<bool> {
        self.entries
            .lock()
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, verdict)| *verdict)
    }

    /// Record `verdict` under `key`, replacing an earlier one.
    pub fn record(&self, key: u64, verdict: bool) {
        let mut entries = self.entries.lock();
        entries.retain(|(k, _)| *k != key);
        if entries.len() >= Self::CAPACITY {
            entries.pop_front();
        }
        entries.push_back((key, verdict));
    }

    /// The verdict under `key`, running `compute` and recording its result
    /// when there is none. `compute` runs without the lock held, so two
    /// requests racing on a fresh key may both run it; they reach the same
    /// verdict.
    pub fn get_or_compute(&self, key: u64, compute: impl FnOnce() -> bool) -> bool {
        if let Some(verdict) = self.get(key) {
            return verdict;
        }
        let verdict = compute();
        self.record(key, verdict);
        verdict
    }
}

impl Clone for PeerChainVerdicts {
    fn clone(&self) -> Self {
        PeerChainVerdicts {
            entries: Mutex::new(self.entries.lock().clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdicts_are_computed_once_per_key() {
        let verdicts = PeerChainVerdicts::default();
        let mut runs = 0;
        assert!(verdicts.get_or_compute(1, || {
            runs += 1;
            true
        }));
        assert!(verdicts.get_or_compute(1, || {
            runs += 1;
            false
        }));
        assert_eq!(runs, 1);
    }

    #[test]
    fn verdicts_are_kept_apart_by_key() {
        let verdicts = PeerChainVerdicts::default();
        assert!(verdicts.get_or_compute(1, || true));
        assert!(!verdicts.get_or_compute(2, || false));
        assert_eq!(verdicts.get(1), Some(true));
        assert_eq!(verdicts.get(2), Some(false));
    }

    #[test]
    fn verdicts_forget_the_oldest_key_past_capacity() {
        let verdicts = PeerChainVerdicts::default();
        let capacity = u64::try_from(PeerChainVerdicts::CAPACITY).unwrap();
        for key in 0..=capacity {
            verdicts.record(key, true);
        }
        assert_eq!(verdicts.get(0), None);
        assert_eq!(verdicts.get(1), Some(true));
        assert_eq!(verdicts.get(capacity), Some(true));
    }

    #[test]
    fn a_new_digest_carries_no_chain_and_no_verdict() {
        let digest = SslDigest::new("cipher", "TLSv1.3", None, None, Vec::new());
        assert!(!digest.peer_cert_chain.is_presented());
        assert_eq!(digest.peer_cert_chain.verifiable(), None);
        assert_eq!(digest.peer_chain_verdicts.get(0), None);
    }

    fn chain_of(sizes: &[usize]) -> Vec<Vec<u8>> {
        sizes.iter().map(|size| vec![0x30; *size]).collect()
    }

    fn kept(presented: &[Vec<u8>]) -> PeerCertChain {
        PeerCertChain::new(presented.iter().map(Vec::as_slice))
    }

    #[test]
    fn a_chain_within_the_bounds_is_kept_whole_and_verifiable() {
        let presented = chain_of(&[1_000; PeerCertChain::MAX_CERTIFICATES]);
        let chain = kept(&presented);
        assert!(chain.is_presented());
        assert!(!chain.is_truncated());
        assert_eq!(chain.verifiable(), Some(presented.as_slice()));
    }

    #[test]
    fn a_chain_with_one_certificate_too_many_is_presented_but_not_verifiable() {
        let presented = chain_of(&[100; PeerCertChain::MAX_CERTIFICATES + 1]);
        let chain = kept(&presented);
        assert!(chain.is_presented());
        assert!(chain.is_truncated());
        assert_eq!(chain.verifiable(), None);
        assert_eq!(chain.certificates.len(), PeerCertChain::MAX_CERTIFICATES);
    }

    #[test]
    fn a_chain_past_the_byte_bound_is_presented_but_not_verifiable() {
        let half = PeerCertChain::MAX_BYTES / 2;
        let chain = kept(&chain_of(&[half, half, 1]));
        assert!(chain.is_truncated());
        assert_eq!(chain.verifiable(), None);
        assert_eq!(chain.certificates.len(), 2);
        assert!(kept(&chain_of(&[half, half])).verifiable().is_some());
    }

    #[test]
    fn an_end_entity_alone_past_the_byte_bound_still_counts_as_presented() {
        let chain = kept(&chain_of(&[PeerCertChain::MAX_BYTES + 1]));
        assert!(chain.is_presented());
        assert_eq!(chain.verifiable(), None);
    }

    #[test]
    fn the_chain_debug_output_carries_no_certificate_bytes() {
        let chain = kept(&[b"CLIENT-IDENTITY".to_vec()]);
        assert_eq!(
            format!("{chain:?}"),
            "PeerCertChain { certificates: 1, bytes: 15, truncated: false }"
        );
    }
}

/// The user-defined TLS data
#[derive(Clone, Debug, Default)]
pub struct SslDigestExtension {
    value: Option<Arc<dyn Any + Send + Sync>>,
}

impl SslDigestExtension {
    /// Retrieves a reference to the user-defined TLS data if it matches the specified type.
    ///
    /// Returns `None` if no data has been set or if the data is not of type `T`.
    pub fn get<T>(&self) -> Option<&T>
    where
        T: Send + Sync + 'static,
    {
        self.value.as_ref().and_then(|v| v.downcast_ref::<T>())
    }

    #[allow(dead_code)]
    pub(crate) fn set(&mut self, value: Arc<dyn Any + Send + Sync>) {
        self.value = Some(value);
    }
}
