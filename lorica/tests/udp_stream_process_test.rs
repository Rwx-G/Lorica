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

//! The real binary carries UDP stream traffic (Story 12.5 Lot F): a UDP
//! stream written to the store before the node starts is bound at
//! startup with its caps region, and datagrams sent to its port are
//! answered by a loopback echo backend, in single-process mode and in
//! worker mode. A worker killed while it holds a session has that
//! session released from the stream's caps region before its
//! replacement is sent anything, so the stream's cap is free again.

#![cfg(target_os = "linux")]

use std::io::Read;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use lorica_config::crypto::EncryptionKey;
use lorica_config::models::{
    Backend, HealthCheck, HealthStatus, LifecycleState, Stream, StreamProtocol,
};
use lorica_config::ConfigStore;

/// Longer than the startup of an empty node, which runs its migrations
/// and generates the management certificate before it binds.
const START_DEADLINE: Duration = Duration::from_secs(90);
const STOP_DEADLINE: Duration = Duration::from_secs(30);
/// How long a respawn may take: the monitor's poll, the restart backoff
/// and the replay.
const RESPAWN_DEADLINE: Duration = Duration::from_secs(60);
const REPLY_TIMEOUT: Duration = Duration::from_millis(500);
/// Small enough for the fd budget of any test container.
const TEST_MAX_SESSIONS: u32 = 16;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("test setup: a free port")
        .port()
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .and_then(|socket| socket.local_addr())
        .expect("test setup: a free UDP port")
        .port()
}

/// A UDP echo backend on loopback. The returned slot holds the source of
/// the last datagram it received: the session's upstream socket.
fn echo_backend() -> (SocketAddr, Arc<Mutex<Option<SocketAddr>>>) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("test setup: echo bind");
    let addr = socket.local_addr().expect("test setup: echo addr");
    let last_peer = Arc::new(Mutex::new(None));
    let seen = Arc::clone(&last_peer);
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            *seen.lock().expect("test setup: peer slot") = Some(peer);
            if socket.send_to(&buf[..n], peer).is_err() {
                break;
            }
        }
    });
    (addr, last_peer)
}

/// Write a UDP stream on `port` forwarding to `backend` into the store
/// of `data_dir`, keyed as the node will open it, with `configure`
/// applied over the defaults.
fn seed_stream(
    data_dir: &Path,
    port: u16,
    backend: SocketAddr,
    configure: impl FnOnce(&mut Stream),
) {
    let key = EncryptionKey::load_or_create(&data_dir.join("encryption.key"))
        .expect("test setup: encryption key");
    let store =
        ConfigStore::open(&data_dir.join("lorica.db"), Some(key)).expect("test setup: store");
    let backend_id = "0b7e3c2a-1d4f-4e5a-8b6c-7d8e9f0a1b2c";
    store
        .create_backend(&Backend {
            id: backend_id.into(),
            address: backend.to_string(),
            name: "echo".into(),
            group_name: String::new(),
            weight: 1,
            health_status: HealthStatus::Unknown,
            health_check_enabled: false,
            health_check_interval_s: 10,
            health_check_path: None,
            health_check: HealthCheck::TcpConnect,
            lifecycle_state: LifecycleState::Normal,
            active_connections: 0,
            tls_upstream: false,
            tls_skip_verify: false,
            tls_sni: None,
            h2_upstream: false,
            managed_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
        .expect("test setup: backend");
    let stream_id = "6f1c1a52-5b0e-4f7e-9a51-1a7c5a1b2c3d";
    let mut stream = Stream::new(
        stream_id.into(),
        "echo".into(),
        StreamProtocol::Udp,
        "127.0.0.1".parse().expect("an address"),
        port,
        port,
        Utc::now(),
    );
    // The echo backend is on loopback, on no port of this node.
    stream.allow_local_backend = true;
    if let Some(udp) = stream.udp.as_mut() {
        udp.max_sessions = TEST_MAX_SESSIONS;
    }
    configure(&mut stream);
    store.create_stream(&stream).expect("test setup: stream");
    store
        .set_stream_backends(stream_id, &[backend_id.to_string()])
        .expect("test setup: link");
}

fn start_node(data_dir: &Path, workers: &str) -> (Child, PathBuf) {
    let log_path = data_dir.join("node.log");
    let log = std::fs::File::create(&log_path).expect("test setup: log file");
    let node = Command::new(env!("CARGO_BIN_EXE_lorica"))
        .arg("--data-dir")
        .arg(data_dir)
        .args(["--workers", workers])
        .args(["--management-port", &free_port().to_string()])
        .args(["--http-port", &free_port().to_string()])
        .args(["--https-port", &free_port().to_string()])
        .args(["--log-format", "text"])
        .stdin(Stdio::null())
        .stdout(log.try_clone().expect("test setup: log handle"))
        .stderr(log)
        .spawn()
        .expect("test setup: the node starts");
    (node, log_path)
}

fn read_log(path: &Path) -> String {
    let mut output = String::new();
    let _ = std::fs::File::open(path).and_then(|mut f| f.read_to_string(&mut output));
    output
}

/// A client socket of its own: a new source port, so a new session.
fn client() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("test setup: client bind");
    socket
        .set_read_timeout(Some(REPLY_TIMEOUT))
        .expect("test setup: client timeout");
    socket
}

/// One datagram to the stream port and its answer, or why none came.
fn exchange(socket: &UdpSocket, port: u16, payload: &[u8]) -> Result<Vec<u8>, String> {
    socket
        .send_to(payload, ("127.0.0.1", port))
        .map_err(|e| e.to_string())?;
    let mut buf = [0u8; 2048];
    let (n, from) = socket.recv_from(&mut buf).map_err(|e| e.to_string())?;
    if from != SocketAddr::from(([127, 0, 0, 1], port)) {
        return Err(format!("an answer from {from}, not from the stream port"));
    }
    Ok(buf[..n].to_vec())
}

/// Retry `exchange` from one client socket until an answer comes or
/// `deadline` passes, failing early if the node exits. One socket, so a
/// datagram that waited in a slot socket for its worker opens the same
/// session as the next one, and its late answer still lands here.
fn first_answer(
    node: &mut Child,
    port: u16,
    payload: &[u8],
    deadline: Duration,
) -> Result<Vec<u8>, String> {
    let socket = client();
    let started = Instant::now();
    loop {
        if let Ok(Some(status)) = node.try_wait() {
            return Err(format!("the node exited: {status}"));
        }
        match exchange(&socket, port, payload) {
            Ok(got) => return Ok(got),
            Err(e) if started.elapsed() > deadline => return Err(e),
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

fn stop(node: &mut Child) {
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!("kill -TERM {}", node.id()))
        .status();
    let started = Instant::now();
    while started.elapsed() < STOP_DEADLINE {
        if let Ok(Some(_)) = node.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = node.kill();
    let _ = node.wait();
}

/// A port the backend does not hold, so an answer can only come through
/// the node.
fn stream_port(backend: SocketAddr) -> u16 {
    std::iter::repeat_with(free_udp_port)
        .find(|port| *port != backend.port())
        .expect("a free port")
}

fn a_node_forwards_udp_datagrams(workers: &str) {
    let data_dir = tempfile::tempdir().expect("test setup: data dir");
    let (backend, _) = echo_backend();
    let port = stream_port(backend);
    seed_stream(data_dir.path(), port, backend, |_| {});
    let (mut node, log_path) = start_node(data_dir.path(), workers);

    let first = first_answer(&mut node, port, b"through the udp engine", START_DEADLINE);
    // Each a session of its own, closed on its answer (one response per
    // request by default), from source ports the group spreads over the
    // workers; then two datagrams from one more socket, the second
    // opening a new session once the first has closed on its answer.
    let more: Vec<Result<Vec<u8>, String>> = first
        .as_ref()
        .map(|_| {
            let again = client();
            let mut results: Vec<Result<Vec<u8>, String>> = (0..8)
                .map(|n| exchange(&client(), port, format!("client {n}").as_bytes()))
                .collect();
            results.push(exchange(&again, port, b"once"));
            results.push(exchange(&again, port, b"twice"));
            results
        })
        .unwrap_or_default();
    stop(&mut node);

    let output = read_log(&log_path);
    let got = first.unwrap_or_else(|e| panic!("no answer through the stream ({e}):\n{output}"));
    assert_eq!(got, b"through the udp engine", "{output}");
    let mut expected: Vec<Vec<u8>> = (0..8).map(|n| format!("client {n}").into_bytes()).collect();
    expected.push(b"once".to_vec());
    expected.push(b"twice".to_vec());
    assert_eq!(
        more,
        expected.into_iter().map(Ok).collect::<Vec<_>>(),
        "{output}"
    );
}

#[test]
fn a_single_process_node_forwards_a_udp_stream_to_its_backend() {
    a_node_forwards_udp_datagrams("0");
}

#[test]
fn a_worker_mode_node_forwards_a_udp_stream_to_its_backend() {
    a_node_forwards_udp_datagrams("2");
}

/// The process holding the UDP socket bound to 127.0.0.1:`local_port`,
/// read from `/proc`.
fn udp_socket_owner(local_port: u16) -> Option<u32> {
    // `sl local_address rem_address st queues tr retrnsmt uid timeout
    // inode ...`, the address as hex `0100007F:PORT`.
    let local = format!("0100007F:{local_port:04X}");
    let table = std::fs::read_to_string("/proc/net/udp").ok()?;
    let inode = table.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        (fields.get(1) == Some(&local.as_str()))
            .then(|| fields.get(9).map(|inode| inode.to_string()))
            .flatten()
    })?;
    let target = format!("socket:[{inode}]");
    std::fs::read_dir("/proc")
        .ok()?
        .flatten()
        .find_map(|entry| {
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            let fds = std::fs::read_dir(entry.path().join("fd")).ok()?;
            fds.flatten()
                .any(|fd| {
                    std::fs::read_link(fd.path()).is_ok_and(|link| link.to_str() == Some(&target))
                })
                .then_some(pid)
        })
}

#[test]
fn a_dead_workers_session_is_released_before_its_replacement_serves() {
    let data_dir = tempfile::tempdir().expect("test setup: data dir");
    let (backend, last_peer) = echo_backend();
    let port = stream_port(backend);
    // One session on the node, kept open: it ends only on idle, after an
    // hour, so the stream stays at its cap until something releases it.
    seed_stream(data_dir.path(), port, backend, |stream| {
        stream.idle_timeout_s = 3600;
        if let Some(udp) = stream.udp.as_mut() {
            udp.max_sessions = 1;
            udp.unbounded_responses = true;
            udp.requests_per_session = None;
        }
    });
    let (mut node, log_path) = start_node(data_dir.path(), "2");

    let held = first_answer(&mut node, port, b"held", START_DEADLINE);
    let upstream = *last_peer.lock().expect("test setup: peer slot");
    let owner = upstream.and_then(|peer| udp_socket_owner(peer.port()));
    // At its cap: another client is refused, whichever worker it reaches.
    let refused = exchange(&client(), port, b"refused");
    let killed = owner.filter(|pid| *pid != node.id()).is_some_and(|pid| {
        Command::new("sh")
            .arg("-c")
            .arg(format!("kill -KILL {pid}"))
            .status()
            .is_ok_and(|status| status.success())
    });
    let after = killed.then(|| first_answer(&mut node, port, b"after", RESPAWN_DEADLINE));
    // The respawn replay is done once the supervisor says so.
    let started = Instant::now();
    while started.elapsed() < RESPAWN_DEADLINE
        && !read_log(&log_path).contains("worker restarted, reconnecting channel")
    {
        std::thread::sleep(Duration::from_millis(200));
    }
    stop(&mut node);

    let output = read_log(&log_path);
    assert_eq!(
        held.unwrap_or_else(|e| panic!("no answer through the stream ({e}):\n{output}")),
        b"held",
        "{output}"
    );
    let owner = owner.unwrap_or_else(|| panic!("no process holds the session socket:\n{output}"));
    assert_ne!(owner, node.id(), "a worker, not the supervisor, holds it");
    assert!(
        refused.is_err(),
        "the cap of one holds: {refused:?}\n{output}"
    );
    assert!(killed, "worker {owner} not killed");
    assert_eq!(
        after
            .expect("an answer was awaited after the kill")
            .unwrap_or_else(|e| panic!("the stream stayed at its cap ({e}):\n{output}")),
        b"after",
        "{output}"
    );
    let released = output
        .find("connections and sessions of a dead worker released")
        .unwrap_or_else(|| panic!("no release logged:\n{output}"));
    let replaced = output
        .find("worker restarted, reconnecting channel")
        .unwrap_or_else(|| panic!("no respawn logged:\n{output}"));
    assert!(
        released < replaced,
        "the release comes before the replacement is replayed its bindings:\n{output}"
    );
}
