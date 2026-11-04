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
    /// The serial number of the peer's certificate
    pub serial_number: Option<String>,
    /// The digest of the peer's certificate
    pub cert_digest: Vec<u8>,
    /// The user-defined TLS data
    pub extension: SslDigestExtension,
    /// Lorica: the certificate chain a client presented to a listener, DER,
    /// end-entity first, in the order it was sent. Empty when the client
    /// presented none, and always empty on a connection Lorica opened, so
    /// an upstream leg does not carry its server's chain around.
    ///
    /// The listener's verifier accepted this chain, but an application that
    /// trusts different roots for different requests on one listener must
    /// verify it again against the roots that apply; `organization`,
    /// `serial_number` and `cert_digest` describe the same end-entity and
    /// are no more trustworthy than it.
    pub peer_cert_chain: Vec<Vec<u8>>,
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
            serial_number,
            cert_digest,
            extension: SslDigestExtension::default(),
            peer_cert_chain: Vec::new(),
            peer_chain_verdicts: PeerChainVerdicts::default(),
        }
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
        assert!(digest.peer_cert_chain.is_empty());
        assert_eq!(digest.peer_chain_verdicts.get(0), None);
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
