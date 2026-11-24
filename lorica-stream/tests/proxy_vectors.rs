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

//! The PROXY accept vectors of `lorica-core`
//! (`protocols::proxy_protocol::accept_vectors`) replayed through the TCP
//! engine, against real sockets (Linux). The HTTP listeners replay the
//! same vectors in `lorica-core`'s `listeners::proxy_protocol` tests, so
//! the two accept paths are held to one set of outcomes.
//!
//! Each vector runs on a harness of its own: a stream accepting PROXY
//! that trusts the client's loopback address or not, sending a v2 header
//! to a backend that collects what it receives. The outcome is read from
//! the stream's counters, its connection record and the header the
//! backend received, which names the client and the destination the
//! engine went on with.

#![cfg(target_os = "linux")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use lorica_config::models::{
    Stream, StreamBackend, StreamEndReason, StreamProtocol, StreamProxyProtocol,
};
use lorica_core::protocols::proxy_protocol::accept_vectors::{
    vectors, AcceptVector, Outcome, Peer, Refusal, Then,
};
use lorica_core::protocols::proxy_protocol::{parse, Addresses, Parsed, Version};
use lorica_stream::counters::ProxyHeaderOutcome;
use lorica_stream::{
    AcceptedConnection, BoundPorts, CapsRegistry, ConnectionRecord, ConnectionTracker,
    NodeCapsRegions, ResolverCache, StreamCounters, StreamHandler, StreamTable, TcpEngine,
    TcpEngineParts,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const STREAM_ID: &str = "s";
/// Bounds a hang, never a duration: every vector decides within the
/// header read timeout plus its own pauses.
const WAIT: Duration = Duration::from_secs(60);

mod common;

use common::{backend, Breaker, Dns, Gate, Selector};

// ---- the harness ---------------------------------------------------------

struct Harness {
    counters: Arc<StreamCounters>,
    records: mpsc::UnboundedReceiver<ConnectionRecord>,
    listen: SocketAddr,
}

impl Harness {
    /// An engine serving one stream that accepts PROXY from `trusted`
    /// and sends a v2 header to the backend at `backend_address`, behind
    /// a listener of its own.
    async fn serving(trusted: &str, backend_address: SocketAddr) -> Harness {
        let counters = Arc::new(StreamCounters::new());
        let (observer, observed) = common::observer();
        let engine = TcpEngine::new(TcpEngineParts {
            selector: Arc::new(Selector::first()),
            breaker: Arc::new(Breaker::default()),
            resolver: ResolverCache::new(Arc::new(Dns::default()), Arc::clone(&counters)),
            counters: Arc::clone(&counters),
            observer,
            reserved_ports: None,
            source_gate: Arc::new(Gate::default()),
        });

        let mut stream = Stream::new(
            STREAM_ID.into(),
            "vectors".into(),
            StreamProtocol::Tcp,
            "127.0.0.1".parse().unwrap(),
            1,
            1,
            Utc::now(),
        );
        // The fixture backend is on loopback.
        stream.allow_local_backend = true;
        stream.proxy_protocol_accept = true;
        stream.proxy_protocol_trusted_cidrs = vec![trusted.to_string()];
        stream.proxy_protocol_send = StreamProxyProtocol::V2;

        let caps = CapsRegistry::new();
        let mut node = NodeCapsRegions::new(1);
        common::adopt_region(&mut node, &caps, &stream);

        let link = StreamBackend::primary(&stream.id, "b1");
        let table = Arc::new(StreamTable::with_backends(
            vec![stream],
            &[link],
            vec![backend("b1", backend_address)],
        ));
        engine.table_changed(&table);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = listener.local_addr().unwrap();
        let tracker = ConnectionTracker::new();
        let bound = BoundPorts::new();
        tokio::spawn(async move {
            // Keeps the supervisor's side of the region alive.
            let _node = node;
            loop {
                let (stream, peer) = listener.accept().await.unwrap();
                let snapshot = table.stream(STREAM_ID).expect("test setup: the stream");
                tokio::spawn(engine.handle(AcceptedConnection {
                    stream,
                    peer,
                    bind_gen: 1,
                    tracked: tracker.register(1, snapshot),
                    table: Arc::clone(&table),
                    bound_ports: bound.clone(),
                    caps: caps.clone(),
                }));
            }
        });
        Harness {
            counters,
            records: observed.records,
            listen,
        }
    }

    async fn record(&mut self) -> ConnectionRecord {
        common::next(&mut self.records, "a connection record").await
    }

    /// The PROXY header outcomes the stream counted, each once.
    fn counted(&self) -> Vec<ProxyHeaderOutcome> {
        let snapshot = self.counters.snapshot();
        let Some(stats) = snapshot.streams.get(STREAM_ID) else {
            return Vec::new();
        };
        let mut counted = Vec::new();
        for (outcome, count) in &stats.proxy_header {
            for _ in 0..*count {
                counted.push(*outcome);
            }
        }
        counted
    }
}

/// Collects each connection's bytes until EOF and hands them over.
async fn sink() -> (SocketAddr, mpsc::UnboundedReceiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut all = Vec::new();
                let _ = socket.read_to_end(&mut all).await;
                let _ = tx.send(all);
            });
        }
    });
    (addr, rx)
}

// ---- the replay ----------------------------------------------------------

/// The shared vocabulary's name for a refused outcome of the stream
/// plane.
fn refusal_of(outcome: ProxyHeaderOutcome) -> Refusal {
    match outcome {
        ProxyHeaderOutcome::RefusedMissing => Refusal::Missing,
        ProxyHeaderOutcome::RefusedMalformed => Refusal::Malformed,
        ProxyHeaderOutcome::RefusedOversized => Refusal::Oversized,
        ProxyHeaderOutcome::RefusedUnsupported => Refusal::Unsupported,
        ProxyHeaderOutcome::RefusedTimeout => Refusal::Timeout,
        ProxyHeaderOutcome::RefusedUntrustedPeer => Refusal::UntrustedPeer,
        accepted @ (ProxyHeaderOutcome::AcceptedV1
        | ProxyHeaderOutcome::AcceptedV2
        | ProxyHeaderOutcome::AcceptedLocal) => panic!("{accepted:?} is not a refusal"),
    }
}

/// Runs `vector` through the TCP engine and answers the outcome with the
/// bytes the backend received past the engine's own header.
async fn replay(vector: &AcceptVector) -> (Outcome, Vec<u8>) {
    let (backend, mut received) = sink().await;
    let trusted = match vector.peer {
        Peer::Trusted => "127.0.0.1",
        Peer::Untrusted => "192.0.2.0/24",
    };
    let mut h = Harness::serving(trusted, backend).await;
    let mut client = TcpStream::connect(h.listen).await.unwrap();
    let peer = client.local_addr().unwrap();
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

    let record = h.record().await;
    let counted = h.counted();
    let observed = if record.end_reason == StreamEndReason::ProxyHeaderInvalid {
        let [refused] = counted[..] else {
            panic!("{}: one refusal counted, got {counted:?}", vector.name);
        };
        (Outcome::Refused(refusal_of(refused)), Vec::new())
    } else {
        let wire = tokio::time::timeout(WAIT, received.recv())
            .await
            .expect("the backend's bytes in time")
            .expect("the backend is alive");
        let Ok(Parsed::Complete { header, consumed }) = parse(&wire) else {
            panic!("{}: the backend got no PROXY header: {wire:?}", vector.name);
        };
        let Addresses::Tcp {
            source,
            destination,
        } = header.addresses
        else {
            panic!("{}: TCP addresses: {:?}", vector.name, header.addresses);
        };
        assert_eq!(record.client, source, "{}", vector.name);
        let socket_addresses = (source, destination) == (peer, h.listen);
        let outcome = match counted[..] {
            [] if socket_addresses => Outcome::Direct,
            [ProxyHeaderOutcome::AcceptedLocal] if socket_addresses => Outcome::NoAddress,
            [ProxyHeaderOutcome::AcceptedV1] => Outcome::Carried {
                version: Version::V1,
                source,
                destination,
            },
            [ProxyHeaderOutcome::AcceptedV2] => Outcome::Carried {
                version: Version::V2,
                source,
                destination,
            },
            _ => panic!(
                "{}: {counted:?} sending {source} to {destination}",
                vector.name
            ),
        };
        (outcome, wire[consumed..].to_vec())
    };
    writer.abort();
    observed
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_accept_vector_reaches_its_outcome_on_the_stream_plane() {
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
