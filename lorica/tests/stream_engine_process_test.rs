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

//! The real binary carries TCP stream traffic (Story 12.3 Lot D2): a
//! stream written to the store before the node starts is bound at
//! startup, and bytes sent to its port come back from a local echo
//! backend, in single-process mode and in worker mode.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
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
const IO_TIMEOUT: Duration = Duration::from_secs(5);

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("test setup: a free port")
        .port()
}

/// An echo server on loopback, one thread per connection.
fn echo_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("test setup: echo bind");
    let addr = listener.local_addr().expect("test setup: echo addr");
    std::thread::spawn(move || {
        for mut socket in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                while let Ok(n) = socket.read(&mut buf) {
                    if n == 0 || socket.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// Write a TCP stream on `port` forwarding to `backend` into the store
/// of `data_dir`, keyed as the node will open it.
fn seed_stream(data_dir: &Path, port: u16, backend: SocketAddr) {
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
        StreamProtocol::Tcp,
        "127.0.0.1".parse().expect("an address"),
        port,
        port,
        Utc::now(),
    );
    // The echo backend is on loopback, on no port of this node.
    stream.allow_local_backend = true;
    // Small enough for the fd budget of any test container.
    stream.max_connections = 16;
    store.create_stream(&stream).expect("test setup: stream");
    store
        .set_stream_backends(stream_id, &[backend_id.to_string()])
        .expect("test setup: link");
}

/// One round trip through the stream port, or why not.
fn echo_through(port: u16, payload: &[u8]) -> Result<Vec<u8>, String> {
    let mut client = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    client
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|e| e.to_string())?;
    client.write_all(payload).map_err(|e| e.to_string())?;
    let mut got = vec![0u8; payload.len()];
    client.read_exact(&mut got).map_err(|e| e.to_string())?;
    Ok(got)
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

fn a_node_forwards_stream_bytes(workers: &str) {
    let data_dir = tempfile::tempdir().expect("test setup: data dir");
    let backend = echo_backend();
    // A port the backend does not hold, so an echo can only come
    // through the node.
    let stream_port = std::iter::repeat_with(free_port)
        .find(|port| *port != backend.port())
        .expect("a free port");
    seed_stream(data_dir.path(), stream_port, backend);
    let log_path = data_dir.path().join("node.log");
    let log = std::fs::File::create(&log_path).expect("test setup: log file");

    let mut node = Command::new(env!("CARGO_BIN_EXE_lorica"))
        .arg("--data-dir")
        .arg(data_dir.path())
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

    let started = Instant::now();
    let outcome = loop {
        if let Ok(Some(status)) = node.try_wait() {
            break Err(format!("the node exited: {status}"));
        }
        match echo_through(stream_port, b"through the stream engine") {
            Ok(got) => break Ok(got),
            Err(e) if started.elapsed() > START_DEADLINE => break Err(e),
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    };
    let second = outcome
        .as_ref()
        .ok()
        .map(|_| echo_through(stream_port, b"and again"));
    stop(&mut node);

    let mut output = String::new();
    let _ = std::fs::File::open(&log_path).and_then(|mut f| f.read_to_string(&mut output));
    let got = outcome.unwrap_or_else(|e| panic!("no echo through the stream ({e}):\n{output}"));
    assert_eq!(got, b"through the stream engine", "{output}");
    assert_eq!(
        second.expect("a second connection was made"),
        Ok(b"and again".to_vec()),
        "{output}"
    );
    // In worker mode the supervisor hands each worker its node's
    // reserved ports for the connect-time local check.
    assert!(
        !output.contains("started without --reserved-ports"),
        "{output}"
    );
}

#[test]
fn a_single_process_node_forwards_a_tcp_stream_to_its_backend() {
    a_node_forwards_stream_bytes("0");
}

#[test]
fn a_worker_mode_node_forwards_a_tcp_stream_to_its_backend() {
    a_node_forwards_stream_bytes("2");
}
