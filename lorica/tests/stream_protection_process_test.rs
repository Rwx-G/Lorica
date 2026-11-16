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

//! The real binary applies the node's source controls to a stream
//! (Story 12.6 Lot D): the global connection filter and the GeoIP
//! database the HTTP listeners read judge every stream client, in
//! single-process mode and in worker mode.
//!
//! The clients all connect over loopback. A client from a denied
//! network or country is a client a trusted PROXY header carries (Story
//! 12.6 D-b: the carried client is the address judged), so the GeoIP
//! fixture's US range can be reached without leaving the host. A client
//! judged on its socket address binds a loopback source of its own
//! before connecting.
//!
//! The global IP blocklist is not driven here: it loads only from its
//! remote feed. Its refusal and the WAF whitelist exemption are tested
//! on the gate itself, in `lorica::stream_engine`.

#![cfg(target_os = "linux")]

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use chrono::Utc;
use lorica_config::crypto::EncryptionKey;
use lorica_config::models::{Backend, GeoIpConfig, Stream, StreamProtocol};
use lorica_config::ConfigStore;
use serde_json::json;

mod common;

use common::reserve_port;

/// Longer than the startup of an empty node, which runs its migrations
/// and generates the management certificate before it binds.
const START_DEADLINE: Duration = Duration::from_secs(90);
const STOP_DEADLINE: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// The MaxMind country test database the e2e GeoIP profile mounts.
const GEOIP_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests-e2e-docker/fixtures/GeoIP2-Country-Test.mmdb"
);

/// The PROXY peer the stream trusts, which every carried client comes
/// through.
const BALANCER: &str = "127.0.0.1";
/// A carried client in the fixture's US range, which the stream denies.
const US_CLIENT: &str = "214.78.120.5";
/// A carried client in the network the global connection filter denies.
const DENIED_NETWORK_CLIENT: &str = "203.0.113.9";
/// A carried client no control refuses (and no country the fixture
/// knows: an unknown country passes).
const ALLOWED_CLIENT: &str = "198.51.100.7";
/// A loopback source the global connection filter denies, judged on its
/// socket address (the stream does not trust it to speak PROXY).
const DENIED_PEER: &str = "127.0.0.2";
/// A loopback source no control refuses, judged on its socket address.
const ALLOWED_PEER: &str = "127.0.0.3";

fn ip(s: &str) -> IpAddr {
    s.parse().expect("an address")
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

/// A backend row for `address`, through the stored form so the fields
/// left out take their defaults.
fn backend(id: &str, address: SocketAddr) -> Backend {
    let now = Utc::now();
    serde_json::from_value(json!({
        "id": id,
        "address": address.to_string(),
        "name": "echo",
        "weight": 1,
        "health_status": "unknown",
        "health_check_enabled": false,
        "health_check_interval_s": 10,
        "lifecycle_state": "normal",
        "active_connections": 0,
        "tls_upstream": false,
        "created_at": now,
        "updated_at": now,
    }))
    .expect("test setup: a backend row")
}

/// A country denylist, through the stored form.
fn denying(countries: &[&str]) -> GeoIpConfig {
    serde_json::from_value(json!({ "mode": "denylist", "countries": countries }))
        .expect("test setup: a GeoIP list")
}

/// Write into the store of `data_dir`, keyed as the node will open it:
/// the global connection filter denying [`DENIED_NETWORK_CLIENT`]'s
/// network and [`DENIED_PEER`], the GeoIP fixture as the node's
/// database, and a TCP stream on `port` forwarding to `backend` that
/// trusts PROXY headers from [`BALANCER`] and denies the US.
fn seed(data_dir: &Path, port: u16, backend_addr: SocketAddr) {
    let key = EncryptionKey::load_or_create(&data_dir.join("encryption.key"))
        .expect("test setup: encryption key");
    let store =
        ConfigStore::open(&data_dir.join("lorica.db"), Some(key)).expect("test setup: store");

    let mut settings = store.get_global_settings().expect("test setup: settings");
    settings.connection_deny_cidrs = vec!["203.0.113.0/24".into(), format!("{DENIED_PEER}/32")];
    settings.geoip_db_path = Some(GEOIP_FIXTURE.into());
    store
        .update_global_settings(&settings)
        .expect("test setup: settings saved");

    let backend_id = "0b7e3c2a-1d4f-4e5a-8b6c-7d8e9f0a1b2c";
    store
        .create_backend(&backend(backend_id, backend_addr))
        .expect("test setup: backend");
    let stream_id = "6f1c1a52-5b0e-4f7e-9a51-1a7c5a1b2c3d";
    let mut stream = Stream::new(
        stream_id.into(),
        "protected".into(),
        StreamProtocol::Tcp,
        ip("127.0.0.1"),
        port,
        port,
        Utc::now(),
    );
    // The echo backend is on loopback, on no port of this node.
    stream.allow_local_backend = true;
    // Small enough for the fd budget of any test container.
    stream.max_connections = 16;
    stream.proxy_protocol_accept = true;
    stream.proxy_protocol_trusted_cidrs = vec![format!("{BALANCER}/32")];
    stream.geoip = Some(denying(&["US"]));
    store.create_stream(&stream).expect("test setup: stream");
    store
        .set_stream_backends(stream_id, &[backend_id.to_string()])
        .expect("test setup: link");
}

/// What became of one exchange through the stream port.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The payload came back from the backend.
    Echoed,
    /// The node closed the connection without forwarding a byte back.
    Closed,
}

/// Send `header` then `payload` on `client`, and read the echo of
/// `payload`.
fn exchange(mut client: TcpStream, header: &[u8], payload: &[u8]) -> Result<Outcome, String> {
    let closed = |kind: ErrorKind| {
        matches!(
            kind,
            ErrorKind::ConnectionReset | ErrorKind::BrokenPipe | ErrorKind::ConnectionAborted
        )
    };
    client
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|e| e.to_string())?;
    let mut sent = header.to_vec();
    sent.extend_from_slice(payload);
    match client.write_all(&sent) {
        Ok(()) => {}
        Err(e) if closed(e.kind()) => return Ok(Outcome::Closed),
        Err(e) => return Err(e.to_string()),
    }
    let mut got = vec![0u8; payload.len()];
    let mut filled = 0;
    while filled < got.len() {
        match client.read(&mut got[filled..]) {
            Ok(0) => return Ok(Outcome::Closed),
            Ok(n) => filled += n,
            Err(e) if closed(e.kind()) => return Ok(Outcome::Closed),
            Err(e) => return Err(e.to_string()),
        }
    }
    if got == payload {
        Ok(Outcome::Echoed)
    } else {
        Err(format!("an echo that is not the payload: {got:?}"))
    }
}

/// One exchange from the balancer, carrying `client` in a PROXY v1
/// header.
fn carried(port: u16, client: &str) -> Result<Outcome, String> {
    let socket = TcpStream::connect((BALANCER, port)).map_err(|e| e.to_string())?;
    let header = format!("PROXY TCP4 {client} 127.0.0.1 40000 {port}\r\n");
    exchange(socket, header.as_bytes(), b"carried through the stream")
}

/// One exchange from the loopback source `source`, judged on its socket
/// address.
fn direct(port: u16, source: &str) -> Result<Outcome, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .map_err(|e| e.to_string())?;
    let socket = runtime
        .block_on(async {
            let socket = tokio::net::TcpSocket::new_v4()?;
            socket.bind(SocketAddr::new(ip(source), 0))?;
            let stream = socket
                .connect(SocketAddr::new(ip("127.0.0.1"), port))
                .await?;
            stream.into_std()
        })
        .map_err(|e| e.to_string())?;
    socket.set_nonblocking(false).map_err(|e| e.to_string())?;
    exchange(socket, b"", b"straight to the stream")
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

/// The refusal rows the node wrote, one reason word each.
fn refusal_reasons(output: &str) -> Vec<&'static str> {
    ["connection_filter", "geoip", "ip_blocklist"]
        .into_iter()
        .filter(|reason| {
            output
                .lines()
                .any(|line| line.contains("stream connection refused") && line.contains(reason))
        })
        .collect()
}

fn a_node_applies_its_source_controls_to_a_stream(workers: &str) {
    let data_dir = tempfile::tempdir().expect("test setup: data dir");
    let backend = echo_backend();
    // Never the backend's port (an ephemeral one), so an echo can only
    // come through the node.
    let port = reserve_port();
    seed(data_dir.path(), port, backend);
    let log_path = data_dir.path().join("node.log");
    let log = std::fs::File::create(&log_path).expect("test setup: log file");

    let mut node = Command::new(env!("CARGO_BIN_EXE_lorica"))
        .arg("--data-dir")
        .arg(data_dir.path())
        .args(["--workers", workers])
        .args(["--management-port", &reserve_port().to_string()])
        .args(["--http-port", &reserve_port().to_string()])
        .args(["--https-port", &reserve_port().to_string()])
        .args(["--log-format", "text"])
        // The stream refusal rows are written at debug.
        .env("RUST_LOG", "info,lorica_stream=debug")
        .stdin(Stdio::null())
        .stdout(log.try_clone().expect("test setup: log handle"))
        .stderr(log)
        .spawn()
        .expect("test setup: the node starts");

    let started = Instant::now();
    let served = loop {
        if let Ok(Some(status)) = node.try_wait() {
            break Err(format!("the node exited: {status}"));
        }
        match carried(port, ALLOWED_CLIENT) {
            Ok(Outcome::Echoed) => break Ok(()),
            Ok(Outcome::Closed) | Err(_) if started.elapsed() > START_DEADLINE => {
                break Err("the allowed client was never served".to_string())
            }
            _ => std::thread::sleep(Duration::from_millis(200)),
        }
    };
    let outcomes = served.as_ref().ok().map(|()| {
        [
            (
                "a carried client from a denied network",
                carried(port, DENIED_NETWORK_CLIENT),
            ),
            (
                "a carried client from a denied country",
                carried(port, US_CLIENT),
            ),
            ("a denied socket peer", direct(port, DENIED_PEER)),
            ("an allowed carried client", carried(port, ALLOWED_CLIENT)),
            ("an allowed socket peer", direct(port, ALLOWED_PEER)),
        ]
    });
    stop(&mut node);

    let mut output = String::new();
    let _ = std::fs::File::open(&log_path).and_then(|mut f| f.read_to_string(&mut output));
    if let Err(e) = served {
        panic!("{e}:\n{output}");
    }
    let outcomes = outcomes.expect("the exchanges ran once the stream served");
    let expected = [
        Outcome::Closed,
        Outcome::Closed,
        Outcome::Closed,
        Outcome::Echoed,
        Outcome::Echoed,
    ];
    for ((what, got), want) in outcomes.into_iter().zip(expected) {
        assert_eq!(got, Ok(want), "{what}:\n{output}");
    }
    // Refused for the reasons the controls give, not for any other.
    assert_eq!(
        refusal_reasons(&output),
        ["connection_filter", "geoip"],
        "{output}"
    );
}

#[test]
fn a_single_process_node_refuses_stream_clients_its_controls_deny() {
    a_node_applies_its_source_controls_to_a_stream("0");
}

#[test]
fn a_worker_mode_node_refuses_stream_clients_its_controls_deny() {
    a_node_applies_its_source_controls_to_a_stream("2");
}
