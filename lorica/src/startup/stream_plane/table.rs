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

//! The stream table a stream runtime loads, read from the store.

use std::sync::Arc;
use std::time::Duration;

use lorica_config::ConfigStore;

/// The stream table a stream runtime accepts against, read from the
/// configuration store.
///
/// It holds a connection of its own: the runtime loads the table
/// synchronously from inside its tokio runtime, where the blocking lock
/// of the process's shared `tokio::sync::Mutex` store would panic.
///
/// The table holds every stream, not only the ones this node binds:
/// which bindings a worker serves is the driver's decision, made with
/// `binds_here` over the node's role and carried by `attach` and
/// `detach`, so a stream this node stops binding is drained by its
/// `detach`. A worker cannot make that decision itself, since it does
/// not know whether it runs on the control plane (`--cluster-listen`).
/// What the table answers is whether an attached binding still has its
/// stream, enabled, with the backend a connection uses, which a
/// `refresh` drains on, and the linked backend rows the engines select
/// from, with their health as stored (Story 12.3 D-i), and the client
/// certificates the streams' upstream TLS presents (Story 12.4 D-i).
pub(crate) struct StoreStreamTable {
    store: Arc<std::sync::Mutex<ConfigStore>>,
}

impl StoreStreamTable {
    /// Open a connection of its own to the database at `db_path`.
    pub(crate) fn open(
        db_path: &std::path::Path,
        key: Option<lorica_config::crypto::EncryptionKey>,
    ) -> lorica_config::Result<Self> {
        Ok(StoreStreamTable {
            store: Arc::new(std::sync::Mutex::new(ConfigStore::open(db_path, key)?)),
        })
    }

    /// The stored drain setting, for a stop that arrives without a
    /// `quiesce` message.
    pub(crate) fn drain_timeout(&self) -> Duration {
        let store = self
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::startup::drain::stored_drain_timeout(&store)
    }
}

impl lorica_stream::StreamTableSource for StoreStreamTable {
    fn load(&self) -> Result<lorica_stream::StreamTable, Box<dyn std::error::Error + Send + Sync>> {
        // A panic while holding the lock leaves nothing half-written: the
        // connection only reads here.
        let store = self
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let streams = store.list_streams()?;
        let links = store.list_stream_backends()?;
        let backends = store.list_backends()?;
        // Read with the table, so a renewed client certificate reaches
        // new connections through the same `refresh` as any edit (Story
        // 12.4 D-i).
        let identities = lorica::stream_engine::stream_client_identities(&streams, |id| {
            store.get_certificate(id)
        })?;
        Ok(
            lorica_stream::StreamTable::with_backends(streams, &links, backends)
                .with_client_identities(identities),
        )
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use lorica_config::models::{GlobalSettings, HealthStatus};
    use lorica_stream::{FdBudget, StreamBindStates};
    use tokio::sync::Mutex;

    use super::*;
    use crate::startup::stream_plane::test_support::{reserved, tcp};
    use crate::startup::stream_plane::{
        InProcessLink, PlaneRole, StreamPlane, StreamPlaneHandle, STREAM_CTL_ACK_TIMEOUT,
    };

    #[test]
    fn the_store_table_reads_what_another_connection_wrote() {
        use lorica_stream::StreamTableSource;
        let dir = tempfile::tempdir().expect("test setup: tempdir");
        let db = dir.path().join("lorica.db");
        // The store holds stream ids to the canonical UUID form.
        let id = "6f1c1a52-5b0e-4f7e-9a51-1a7c5a1b2c3d";
        let writer = ConfigStore::open(&db, None).expect("test setup: store");
        writer
            .create_stream(&tcp(id, 5432))
            .expect("test setup: stream");

        let source = StoreStreamTable::open(&db, None).expect("a second connection opens");
        let table = source.load().expect("the table loads");

        assert!(table.stream(id).is_some());
        assert!(table.holds(id, None));
        assert_eq!(
            source.drain_timeout(),
            Duration::from_secs(u64::from(GlobalSettings::DEFAULT_WORKER_DRAIN_TIMEOUT_S))
        );
    }

    /// A TCP engine that serves nothing and reports the health of every
    /// backend each table it is given holds.
    struct HealthSeen(tokio::sync::mpsc::UnboundedSender<Vec<(String, HealthStatus)>>);

    impl lorica_stream::StreamHandler for HealthSeen {
        fn handle(
            &self,
            _conn: lorica_stream::AcceptedConnection,
        ) -> lorica_stream::handler::HandlerFuture {
            Box::pin(async {})
        }

        fn table_changed(&self, table: &lorica_stream::StreamTable) {
            let mut seen: Vec<(String, HealthStatus)> = table
                .backends()
                .map(|b| (b.id.clone(), b.health_status.clone()))
                .collect();
            seen.sort_by(|a, b| a.0.cmp(&b.0));
            let _ = self.0.send(seen);
        }
    }

    fn stored_backend(id: &str, health_status: HealthStatus) -> lorica_config::models::Backend {
        lorica_config::models::Backend {
            id: id.into(),
            address: "192.0.2.10:5432".into(),
            name: id.into(),
            group_name: String::new(),
            weight: 1,
            health_status,
            health_check_enabled: true,
            health_check_interval_s: 10,
            health_check_path: None,
            health_check: lorica_config::models::HealthCheck::TcpConnect,
            lifecycle_state: lorica_config::models::LifecycleState::Normal,
            active_connections: 0,
            tls_upstream: false,
            tls_skip_verify: false,
            tls_sni: None,
            h2_upstream: false,
            managed_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    async fn next(
        seen: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<(String, HealthStatus)>>,
    ) -> Vec<(String, HealthStatus)> {
        tokio::time::timeout(Duration::from_secs(10), seen.recv())
            .await
            .expect("the worker reloads its table")
            .expect("the engine is alive")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_health_flip_reaches_the_workers_stream_table_through_refresh_tables() {
        let dir = tempfile::tempdir().expect("test setup: tempdir");
        let db = dir.path().join("lorica.db");
        let stream_id = "6f1c1a52-5b0e-4f7e-9a51-1a7c5a1b2c3d";
        let backend_id = "0b7e3c2a-1d4f-4e5a-8b6c-7d8e9f0a1b2c";
        let store = ConfigStore::open(&db, None).expect("test setup: store");
        store
            .create_backend(&stored_backend(backend_id, HealthStatus::Healthy))
            .expect("test setup: backend");
        store
            .create_stream(&tcp(stream_id, 5432))
            .expect("test setup: stream");
        store
            .set_stream_backends(stream_id, &[backend_id.to_string()])
            .expect("test setup: link");

        let (seen_tx, mut seen) = tokio::sync::mpsc::unbounded_channel();
        let (peer, transport) = lorica_stream::ControlTransport::in_process_pair(8);
        let runtime = lorica_stream::StreamRuntime::spawn(
            transport,
            lorica_stream::Engines {
                tcp: Some(Arc::new(HealthSeen(seen_tx))),
                ..lorica_stream::Engines::default()
            },
            Arc::new(StoreStreamTable::open(&db, None).expect("a second connection opens")),
        )
        .unwrap();
        assert_eq!(
            next(&mut seen).await,
            vec![(backend_id.to_string(), HealthStatus::Healthy)],
            "the first load carries the linked backend and its health"
        );

        let store = Arc::new(Mutex::new(store));
        let handle = StreamPlaneHandle::new(
            StreamPlane::new(
                vec![(0, InProcessLink(peer))],
                1,
                FdBudget::from_limit(65536),
                reserved(),
                StreamBindStates::new(),
                STREAM_CTL_ACK_TIMEOUT,
            ),
            Arc::clone(&store),
            PlaneRole::Standalone,
            None,
            lorica_notify::AlertSender::new(16),
        );
        // What the health loop persists on a confirmed flip.
        store
            .lock()
            .await
            .update_backend(&stored_backend(backend_id, HealthStatus::Down))
            .expect("the flip is written");
        let hook = handle.refresh_hook();
        hook();

        assert_eq!(
            next(&mut seen).await,
            vec![(backend_id.to_string(), HealthStatus::Down)]
        );
        runtime.stop();
    }

    /// A TCP engine that serves nothing and reports the leaf of client
    /// identity `CLIENT_CERT_ID` in each table it is given.
    struct IdentitySeen(tokio::sync::mpsc::UnboundedSender<Option<Vec<u8>>>);

    const CLIENT_CERT_ID: &str = "3c9d2f4e-8a1b-4c5d-9e6f-0a1b2c3d4e5f";

    impl lorica_stream::StreamHandler for IdentitySeen {
        fn handle(
            &self,
            _conn: lorica_stream::AcceptedConnection,
        ) -> lorica_stream::handler::HandlerFuture {
            Box::pin(async {})
        }

        fn table_changed(&self, table: &lorica_stream::StreamTable) {
            let leaf = table
                .client_identity(CLIENT_CERT_ID)
                .map(|identity| identity.chain()[0].to_vec());
            let _ = self.0.send(leaf);
        }
    }

    async fn next_leaf(
        seen: &mut tokio::sync::mpsc::UnboundedReceiver<Option<Vec<u8>>>,
    ) -> Option<Vec<u8>> {
        tokio::time::timeout(Duration::from_secs(10), seen.recv())
            .await
            .expect("the worker reloads its table")
            .expect("the engine is alive")
    }

    /// A stored client certificate `CLIENT_CERT_ID`, and its leaf's DER.
    fn client_certificate() -> (lorica_config::models::Certificate, Vec<u8>) {
        let key = rcgen::KeyPair::generate().expect("test setup: key");
        let cert = rcgen::CertificateParams::new(vec!["client.example.test".to_string()])
            .expect("test setup: params")
            .self_signed(&key)
            .expect("test setup: certificate");
        let now = Utc::now();
        let row = lorica_config::models::Certificate {
            id: CLIENT_CERT_ID.into(),
            domain: "client.example.test".into(),
            san_domains: vec!["client.example.test".into()],
            fingerprint: String::new(),
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            issuer: "test".into(),
            not_before: now,
            not_after: now + chrono::Duration::days(30),
            is_acme: false,
            acme_auto_renew: false,
            created_at: now,
            acme_method: None,
            acme_dns_provider_id: None,
            adcs_authority_id: None,
            adcs_template: None,
            adcs_template_oid: None,
            adcs_request_id: None,
        };
        (row, cert.der().to_vec())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_renewed_client_certificate_reaches_the_workers_stream_table_through_refresh() {
        let dir = tempfile::tempdir().expect("test setup: tempdir");
        let db = dir.path().join("lorica.db");
        let stream_id = "6f1c1a52-5b0e-4f7e-9a51-1a7c5a1b2c3d";
        let store = ConfigStore::open(&db, None).expect("test setup: store");
        let (first, first_leaf) = client_certificate();
        store
            .create_certificate(&first)
            .expect("test setup: certificate");
        let mut s = tcp(stream_id, 5432);
        s.upstream_tls = Some(lorica_config::models::StreamUpstreamTls {
            client_certificate_id: Some(CLIENT_CERT_ID.into()),
            ..lorica_config::models::StreamUpstreamTls::default()
        });
        store.create_stream(&s).expect("test setup: stream");

        let (seen_tx, mut seen) = tokio::sync::mpsc::unbounded_channel();
        let (peer, transport) = lorica_stream::ControlTransport::in_process_pair(8);
        let runtime = lorica_stream::StreamRuntime::spawn(
            transport,
            lorica_stream::Engines {
                tcp: Some(Arc::new(IdentitySeen(seen_tx))),
                ..lorica_stream::Engines::default()
            },
            Arc::new(StoreStreamTable::open(&db, None).expect("a second connection opens")),
        )
        .unwrap();
        assert_eq!(
            next_leaf(&mut seen).await,
            Some(first_leaf),
            "the first load carries the identity the stream names"
        );

        let store = Arc::new(Mutex::new(store));
        let handle = StreamPlaneHandle::new(
            StreamPlane::new(
                vec![(0, InProcessLink(peer))],
                1,
                FdBudget::from_limit(65536),
                reserved(),
                StreamBindStates::new(),
                STREAM_CTL_ACK_TIMEOUT,
            ),
            Arc::clone(&store),
            PlaneRole::Standalone,
            None,
            lorica_notify::AlertSender::new(16),
        );
        // What a renewal writes: the same row, a new certificate and key.
        let (mut renewed, renewed_leaf) = client_certificate();
        renewed.id = CLIENT_CERT_ID.into();
        store
            .lock()
            .await
            .update_certificate(&renewed)
            .expect("the renewal is written");
        handle.refresh_tables().await;

        assert_eq!(next_leaf(&mut seen).await, Some(renewed_leaf));

        // A follower that holds the row without its key yet: the
        // identity is held back, not loaded half.
        renewed.key_pem.clear();
        store
            .lock()
            .await
            .update_certificate(&renewed)
            .expect("the keyless row is written");
        handle.refresh_tables().await;
        assert_eq!(next_leaf(&mut seen).await, None);
        runtime.stop();
    }
}
