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

//! The stream table a worker accepts against.
//!
//! New accepts read the current table; `refresh` swaps it whole. A live
//! connection holds the `Arc<Stream>` it was accepted with, so an edit
//! never reaches it (Story 12.2 AC #8, D-g).
//!
//! Since Story 12.3 (D-i) the table also carries the [`Backend`] rows
//! linked to its streams, with each link's backup flag: an engine reads
//! addresses, weights, health and lifecycle from the table its
//! connection was accepted against, never from the store.
//!
//! Since Story 12.4 each link carries the rule of its TLS stream it
//! serves (D-d), and the table carries the client identities the
//! streams' upstream TLS presents (D-i), loaded by the binary from the
//! certificate store, so a renewal reaches new connections through the
//! same `refresh` as any other edit.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, PoisonError, RwLock};

use lorica_config::models::{Backend, Stream, StreamBackend};
use lorica_tls::{CertificateDer, NoDebug, PemObject, PrivateKeyDer};

/// One backend linked to a stream, as an engine selects among them.
#[derive(Debug, Clone)]
pub struct LinkedBackend {
    /// The backend row.
    pub backend: Arc<Backend>,
    /// Whether the link makes it a backup of the stream (D-f).
    pub backup: bool,
    /// The rule of a TLS stream the link serves (Story 12.4 D-d); `None`
    /// on a stream that reads no ClientHello.
    pub rule: Option<String>,
}

/// A stored certificate and its private key, which a stream's upstream
/// TLS presents to its backends (Story 12.4 D-i). It has no `Debug`, and
/// the table holds it behind [`NoDebug`], so no print of a table ever
/// shows a key.
pub struct ClientIdentity {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl ClientIdentity {
    /// The identity of `chain` (leaf first) and `key`.
    pub fn new(chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> ClientIdentity {
        ClientIdentity { chain, key }
    }

    /// The identity of a stored certificate's PEM chain and PEM key, as
    /// the certificate store decodes them.
    ///
    /// # Errors
    ///
    /// A sentence naming what is missing: no certificate in `cert_pem`,
    /// or no private key `key_pem` loads. It never quotes either PEM.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<ClientIdentity, String> {
        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                .map(|certificate| certificate.map(CertificateDer::into_owned))
                .collect::<Result<_, _>>()
                .map_err(|_| "a certificate of the chain does not decode".to_string())?;
        if chain.is_empty() {
            return Err("the certificate PEM holds no certificate".into());
        }
        let key = lorica_tls::load_first_private_key(key_pem.as_bytes())
            .map_err(|_| "the key PEM holds no supported private key".to_string())?;
        Ok(ClientIdentity { chain, key })
    }

    /// The certificate chain, leaf first.
    pub fn chain(&self) -> &[CertificateDer<'static>] {
        &self.chain
    }

    /// A copy of the private key, for one TLS client configuration.
    pub(crate) fn key(&self) -> PrivateKeyDer<'static> {
        self.key.clone_key()
    }
}

/// The streams and their backend links, as one snapshot of the store.
#[derive(Debug, Clone, Default)]
pub struct StreamTable {
    streams: HashMap<String, Arc<Stream>>,
    links: HashMap<String, BTreeSet<String>>,
    linked: HashMap<String, Vec<LinkedBackend>>,
    backends: HashMap<String, Arc<Backend>>,
    identities: HashMap<String, NoDebug<Arc<ClientIdentity>>>,
}

impl StreamTable {
    /// A table of `streams` with the backend `links` that name them, and
    /// no backend row: the shape of Story 12.2, enough for the drain
    /// test. [`StreamTable::with_backends`] is what an engine needs.
    pub fn new(streams: Vec<Stream>, links: &[StreamBackend]) -> Self {
        Self::with_backends(streams, links, Vec::new())
    }

    /// A table of `streams`, their `links`, and the `backends` rows. A
    /// link naming a backend absent from `backends` still counts for
    /// [`StreamTable::holds`] and is left out of
    /// [`StreamTable::linked_backends`]; a row no link names is dropped.
    pub fn with_backends(
        streams: Vec<Stream>,
        links: &[StreamBackend],
        backends: Vec<Backend>,
    ) -> Self {
        let rows: HashMap<String, Arc<Backend>> = backends
            .into_iter()
            .map(|b| (b.id.clone(), Arc::new(b)))
            .collect();
        let mut link_sets: HashMap<String, BTreeSet<String>> = HashMap::new();
        let mut linked: HashMap<String, Vec<LinkedBackend>> = HashMap::new();
        let mut kept: HashMap<String, Arc<Backend>> = HashMap::new();
        let mut ordered: Vec<&StreamBackend> = links.iter().collect();
        ordered.sort();
        for link in ordered {
            if !link_sets
                .entry(link.stream_id.clone())
                .or_default()
                .insert(link.backend_id.clone())
            {
                continue;
            }
            if let Some(row) = rows.get(&link.backend_id) {
                kept.insert(link.backend_id.clone(), Arc::clone(row));
                linked
                    .entry(link.stream_id.clone())
                    .or_default()
                    .push(LinkedBackend {
                        backend: Arc::clone(row),
                        backup: link.backup,
                        rule: link.rule.clone(),
                    });
            }
        }
        StreamTable {
            streams: streams
                .into_iter()
                .map(|s| (s.id.clone(), Arc::new(s)))
                .collect(),
            links: link_sets,
            linked,
            backends: kept,
            identities: HashMap::new(),
        }
    }

    /// The table with the client `identities` its streams' upstream TLS
    /// may present, by certificate id (Story 12.4 D-i). An id a stream
    /// names and this list lacks (its key never reached the node) leaves
    /// that stream's upstream TLS unconfigured.
    pub fn with_client_identities(
        mut self,
        identities: impl IntoIterator<Item = (String, ClientIdentity)>,
    ) -> Self {
        self.identities = identities
            .into_iter()
            .map(|(id, identity)| (id, NoDebug(Arc::new(identity))))
            .collect();
        self
    }

    /// The client identity of certificate `certificate_id`.
    pub fn client_identity(&self, certificate_id: &str) -> Option<&Arc<ClientIdentity>> {
        self.identities
            .get(certificate_id)
            .map(|identity| &identity.0)
    }

    /// The rule of `stream_id` that `backend_id` serves, if the link
    /// names one. A backend serves at most one rule of a stream (Story
    /// 12.4 Resolved 3), so a selector keyed per (stream, rule) reads it
    /// from any candidate.
    pub fn rule_of(&self, stream_id: &str, backend_id: &str) -> Option<&str> {
        self.linked_backends(stream_id)
            .iter()
            .find(|link| link.backend.id == backend_id)
            .and_then(|link| link.rule.as_deref())
    }

    /// The snapshot of `stream_id` new connections are accepted with.
    pub fn stream(&self, stream_id: &str) -> Option<Arc<Stream>> {
        self.streams.get(stream_id).cloned()
    }

    /// Every stream of the table, in no particular order.
    pub fn streams(&self) -> impl Iterator<Item = &Arc<Stream>> {
        self.streams.values()
    }

    /// The backends linked to `stream_id` whose row the table holds, in
    /// a stable order (by backend id), primaries and backups together.
    pub fn linked_backends(&self, stream_id: &str) -> &[LinkedBackend] {
        self.linked.get(stream_id).map_or(&[], Vec::as_slice)
    }

    /// The row of a backend linked to any stream of the table.
    pub fn backend(&self, backend_id: &str) -> Option<&Arc<Backend>> {
        self.backends.get(backend_id)
    }

    /// Every backend row linked to a stream of the table.
    pub fn backends(&self) -> impl Iterator<Item = &Arc<Backend>> {
        self.backends.values()
    }

    /// Whether a connection of `stream_id` on `backend_id` (if the engine
    /// chose one) still has a place in this table: the stream exists and
    /// is enabled, and the backend is still linked to it. A backend that
    /// was deleted has no link left, so it fails the same test.
    pub fn holds(&self, stream_id: &str, backend_id: Option<&str>) -> bool {
        let Some(stream) = self.streams.get(stream_id) else {
            return false;
        };
        if !stream.enabled {
            return false;
        }
        match backend_id {
            None => true,
            Some(b) => self.links.get(stream_id).is_some_and(|set| set.contains(b)),
        }
    }
}

/// Where a worker loads its stream table from: the configuration store
/// in the binary, a fixed table in tests.
pub trait StreamTableSource: Send + Sync + 'static {
    /// Read the current table.
    ///
    /// # Errors
    ///
    /// Whatever kept the source from being read; the runtime keeps its
    /// previous table and logs it.
    fn load(&self) -> Result<StreamTable, Box<dyn std::error::Error + Send + Sync>>;
}

/// The table every loop of a runtime reads, swapped whole on refresh.
#[derive(Debug, Clone, Default)]
pub(crate) struct SharedTable(Arc<RwLock<Arc<StreamTable>>>);

impl SharedTable {
    pub(crate) fn current(&self) -> Arc<StreamTable> {
        Arc::clone(&self.0.read().unwrap_or_else(PoisonError::into_inner))
    }

    pub(crate) fn replace(&self, table: StreamTable) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(table);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use lorica_config::models::StreamProtocol;

    fn stream(id: &str, enabled: bool) -> Stream {
        Stream {
            enabled,
            ..Stream::new(
                id.into(),
                id.into(),
                StreamProtocol::Tcp,
                "127.0.0.1".parse().unwrap(),
                5432,
                5432,
                Utc::now(),
            )
        }
    }

    #[test]
    fn holds_reads_presence_enabled_and_links() {
        let table = StreamTable::new(
            vec![stream("on", true), stream("off", false)],
            &[StreamBackend {
                stream_id: "on".into(),
                backend_id: "b1".into(),
                backup: false,
                rule: None,
                max_active: None,
            }],
        );
        assert!(table.holds("on", None));
        assert!(table.holds("on", Some("b1")));
        assert!(!table.holds("on", Some("b2")));
        assert!(!table.holds("off", None));
        assert!(!table.holds("gone", None));
    }

    #[test]
    fn links_carry_their_rule_and_identities_never_print() {
        let mut link = StreamBackend::primary("tls", "b1");
        link.rule = Some("app".into());
        let row = Backend {
            id: "b1".into(),
            address: "192.0.2.10:443".into(),
            name: "b1".into(),
            group_name: String::new(),
            weight: 1,
            health_status: lorica_config::models::HealthStatus::Healthy,
            health_check_enabled: false,
            health_check_interval_s: 10,
            health_check_path: None,
            health_check: lorica_config::models::HealthCheck::default(),
            lifecycle_state: lorica_config::models::LifecycleState::Normal,
            active_connections: 0,
            tls_upstream: false,
            tls_skip_verify: false,
            tls_sni: None,
            h2_upstream: false,
            managed_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["client".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let table = StreamTable::with_backends(vec![stream("tls", true)], &[link], vec![row])
            .with_client_identities([(
                "c1".to_string(),
                ClientIdentity::from_pem(&cert.pem(), &key.serialize_pem()).unwrap(),
            )]);
        assert_eq!(table.rule_of("tls", "b1"), Some("app"));
        assert_eq!(table.rule_of("tls", "b2"), None);
        assert_eq!(table.linked_backends("tls")[0].rule.as_deref(), Some("app"));
        assert!(table.client_identity("c1").is_some());
        assert!(table.client_identity("c2").is_none());
        let printed = format!("{table:?}");
        assert!(printed.contains(r#""c1": ..."#), "{printed}");
        assert!(ClientIdentity::from_pem("", &key.serialize_pem()).is_err());
        assert!(ClientIdentity::from_pem(&cert.pem(), "").is_err());
    }

    #[test]
    fn replacing_the_table_leaves_a_held_snapshot_alone() {
        let shared = SharedTable::default();
        shared.replace(StreamTable::new(vec![stream("s", true)], &[]));
        let held = shared.current().stream("s").unwrap();
        let mut edited = stream("s", true);
        edited.name = "edited".into();
        shared.replace(StreamTable::new(vec![edited], &[]));
        let fresh = shared.current().stream("s").unwrap();
        assert!(!Arc::ptr_eq(&held, &fresh));
        assert_eq!(held.name, "s");
        assert_eq!(fresh.name, "edited");
    }
}
