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

//! The real binary writes stream access-log rows and stream metrics
//! (Story 12.9 Lot F): a refused connection, an idle-timeout close and a
//! `config_removed` drain each produce a row with their end reason in
//! `GET /api/v1/stream-logs`, the end counters reach `/metrics`, and a
//! stop leaves its `node_shutdown` row in the store, in single-process
//! mode and in worker mode, where the rows and the counters come from
//! the workers.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use chrono::Utc;
use lorica_config::crypto::EncryptionKey;
use lorica_config::models::{Backend, Stream, StreamProtocol, StreamRefusal};
use lorica_config::ConfigStore;
use serde_json::{json, Value};

mod common;

use common::reserve_port;

const START_DEADLINE: Duration = Duration::from_secs(90);
const STOP_DEADLINE: Duration = Duration::from_secs(30);
/// Long enough for a drain, a metrics pull and a writer round.
const ROW_DEADLINE: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// The node's drain: a `config_removed` row comes at most this long
/// after the removal.
const DRAIN_S: u32 = 2;

const BACKEND_ID: &str = "0b7e3c2a-1d4f-4e5a-8b6c-7d8e9f0a1b2c";
const IDLE_STREAM: &str = "6f1c1a52-5b0e-4f7e-9a51-1a7c5a1b2c31";
const DENIED_STREAM: &str = "6f1c1a52-5b0e-4f7e-9a51-1a7c5a1b2c32";
const REMOVED_STREAM: &str = "6f1c1a52-5b0e-4f7e-9a51-1a7c5a1b2c33";
const HELD_STREAM: &str = "6f1c1a52-5b0e-4f7e-9a51-1a7c5a1b2c34";

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

/// A backend row from its required fields only: `Backend` has no
/// constructor, and its serialised form fills every defaulted field.
fn backend_row(address: SocketAddr) -> Backend {
    serde_json::from_value(json!({
        "id": BACKEND_ID,
        "address": address.to_string(),
        "name": "echo",
        "weight": 1,
        "health_status": "unknown",
        "health_check_enabled": false,
        "health_check_interval_s": 10,
        "lifecycle_state": "normal",
        "active_connections": 0,
        "tls_upstream": false,
        "created_at": Utc::now(),
        "updated_at": Utc::now(),
    }))
    .expect("test setup: a backend row")
}

fn tcp_stream(id: &str, port: u16) -> Stream {
    let mut stream = Stream::new(
        id.into(),
        id.into(),
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
    stream
}

struct Ports {
    idle: u16,
    denied: u16,
    removed: u16,
    held: u16,
}

/// The node's store: the admin account (its password returned), a
/// two-second drain, and four streams over one echo backend: one that
/// closes idle connections after a second, one that denies loopback,
/// one the test deletes and one that holds a connection over the stop.
fn seed(data_dir: &Path, ports: &Ports, backend: SocketAddr) -> String {
    let key = EncryptionKey::load_or_create(&data_dir.join("encryption.key"))
        .expect("test setup: encryption key");
    let store =
        ConfigStore::open(&data_dir.join("lorica.db"), Some(key)).expect("test setup: store");
    let password = lorica_api::auth::ensure_admin_user(&store)
        .expect("test setup: admin")
        .expect("test setup: a fresh store has no admin yet");
    let mut settings = store.get_global_settings().expect("test setup: settings");
    settings.worker_drain_timeout_s = DRAIN_S;
    store
        .update_global_settings(&settings)
        .expect("test setup: drain");
    store
        .create_backend(&backend_row(backend))
        .expect("test setup: backend");

    let mut idle = tcp_stream(IDLE_STREAM, ports.idle);
    idle.idle_timeout_s = 1;
    let mut denied = tcp_stream(DENIED_STREAM, ports.denied);
    denied.source_deny_cidrs = vec!["127.0.0.0/8".into()];
    let removed = tcp_stream(REMOVED_STREAM, ports.removed);
    let held = tcp_stream(HELD_STREAM, ports.held);
    for stream in [idle, denied, removed, held] {
        store.create_stream(&stream).expect("test setup: stream");
        store
            .set_stream_backends(&stream.id, &[BACKEND_ID.to_string()])
            .expect("test setup: link");
    }
    password
}

/// One round trip through `port`, keeping the connection open.
fn connect_echoing(port: u16) -> Result<TcpStream, String> {
    let mut client = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    client
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|e| e.to_string())?;
    client.write_all(b"ping").map_err(|e| e.to_string())?;
    let mut got = [0u8; 4];
    client.read_exact(&mut got).map_err(|e| e.to_string())?;
    if &got != b"ping" {
        return Err(format!("echo returned {got:?}"));
    }
    Ok(client)
}

/// Wait for the node to close `client`: a read returns end of file or an
/// error.
fn closed_by_node(mut client: TcpStream, within: Duration) -> bool {
    let _ = client.set_read_timeout(Some(within));
    let mut buf = [0u8; 16];
    matches!(client.read(&mut buf), Ok(0) | Err(_))
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

/// A management API session over the node's self-signed certificate.
struct Api {
    client: reqwest::blocking::Client,
    base: String,
}

impl Api {
    fn login(port: u16, password: &str) -> Result<Api, String> {
        let client =
            lorica_tls::http_client::blocking_client_builder(lorica_tls::http_client::unverified())
                .cookie_store(true)
                .timeout(IO_TIMEOUT)
                .build()
                .map_err(|e| e.to_string())?;
        let base = format!("https://127.0.0.1:{port}");
        let response = client
            .post(format!("{base}/api/v1/auth/login"))
            .json(&json!({"username": "admin", "password": password}))
            .send()
            .map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(format!("login answered {}", response.status()));
        }
        Ok(Api { client, base })
    }

    fn get(&self, path: &str) -> Result<String, String> {
        let response = self
            .client
            .get(format!("{}{path}", self.base))
            .send()
            .map_err(|e| e.to_string())?;
        let status = response.status();
        let body = response.text().map_err(|e| e.to_string())?;
        if status.is_success() {
            Ok(body)
        } else {
            Err(format!("GET {path} answered {status}: {body}"))
        }
    }

    fn delete(&self, path: &str) -> Result<(), String> {
        let response = self
            .client
            .delete(format!("{}{path}", self.base))
            .send()
            .map_err(|e| e.to_string())?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("DELETE {path} answered {}", response.status()))
        }
    }

    /// The rows of `stream_id`, newest first.
    fn stream_rows(&self, stream_id: &str) -> Vec<Value> {
        self.get(&format!("/api/v1/stream-logs?stream_id={stream_id}"))
            .ok()
            .and_then(|body| serde_json::from_str::<Value>(&body).ok())
            .and_then(|body| body["data"]["entries"].as_array().cloned())
            .unwrap_or_default()
    }

    /// Wait for a row of `stream_id` that ended `end_reason`.
    fn row_ending(&self, stream_id: &str, end_reason: &str) -> Option<Value> {
        let started = Instant::now();
        while started.elapsed() < ROW_DEADLINE {
            if let Some(row) = self
                .stream_rows(stream_id)
                .into_iter()
                .find(|row| row["end_reason"] == end_reason)
            {
                return Some(row);
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        None
    }

    /// Wait until the refusal rows of `stream_id` account for `refusals`
    /// refusals: one per `ended` row plus every `refusals_suppressed`
    /// row's count, with at most `processes` `ended` rows, one per
    /// refusing process in the window.
    fn bounded_refusals(
        &self,
        stream_id: &str,
        refusals: u64,
        processes: usize,
    ) -> Result<(), String> {
        let started = Instant::now();
        let mut rows = Vec::new();
        while started.elapsed() < ROW_DEADLINE {
            rows = self.stream_rows(stream_id);
            let ended = rows.iter().filter(|row| row["entry"] == "ended").count();
            let suppressed: u64 = rows
                .iter()
                .filter(|row| row["entry"] == "refusals_suppressed")
                .filter_map(|row| row["suppressed"].as_u64())
                .sum();
            if ended > processes {
                return Err(format!("{ended} refused rows for one window: {rows:?}"));
            }
            if ended as u64 + suppressed == refusals {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Err(format!(
            "the refusal rows never added up to {refusals}: {rows:?}"
        ))
    }

    /// Wait for a sample of `series` (name and labels, as `/metrics`
    /// prints them) above zero; the stream lines of the last scrape when
    /// none came.
    fn metric_above_zero(&self, series: &str) -> Result<(), String> {
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < ROW_DEADLINE {
            match self.get("/api/v1/metrics") {
                Ok(body) => {
                    let value = body.lines().find_map(|line| {
                        line.strip_prefix(series)
                            .and_then(|rest| rest.trim().parse::<f64>().ok())
                    });
                    if value.is_some_and(|v| v > 0.0) {
                        return Ok(());
                    }
                    last = body
                        .lines()
                        .filter(|line| line.starts_with("lorica_stream"))
                        .collect::<Vec<_>>()
                        .join("\n");
                }
                Err(e) => last = e,
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Err(format!("no sample of {series} in:\n{last}"))
    }
}

fn start(data_dir: &Path, workers: &str, management_port: u16) -> Child {
    let log = std::fs::File::create(data_dir.join("node.log")).expect("test setup: log file");
    Command::new(env!("CARGO_BIN_EXE_lorica"))
        .arg("--data-dir")
        .arg(data_dir)
        .args(["--workers", workers])
        .args(["--management-port", &management_port.to_string()])
        .args(["--http-port", &reserve_port().to_string()])
        .args(["--https-port", &reserve_port().to_string()])
        .args(["--log-format", "text"])
        .stdin(Stdio::null())
        .stdout(log.try_clone().expect("test setup: log handle"))
        .stderr(log)
        .spawn()
        .expect("test setup: the node starts")
}

fn node_log(data_dir: &Path) -> String {
    let mut output = String::new();
    let _ = std::fs::File::open(data_dir.join("node.log"))
        .and_then(|mut f| f.read_to_string(&mut output));
    output
}

/// The rows of the store `data_dir` holds, read after the node stopped.
fn stored_end_reasons(data_dir: &Path, stream_id: &str) -> Vec<String> {
    let store = lorica_api::log_store::LogStore::open(data_dir).expect("the log store opens");
    let filter = lorica_api::stream_logs::StreamLogFilter {
        stream_id: Some(stream_id.to_string()),
        ..Default::default()
    };
    store
        .query_stream_logs(&filter)
        .expect("the stream rows read")
        .0
        .into_iter()
        .map(|row| row.end_reason)
        .collect()
}

fn a_node_logs_and_counts_stream_ends(workers: &str) {
    let data_dir = tempfile::tempdir().expect("test setup: data dir");
    let ports = Ports {
        idle: reserve_port(),
        denied: reserve_port(),
        removed: reserve_port(),
        held: reserve_port(),
    };
    let backend = echo_backend();
    let password = seed(data_dir.path(), &ports, backend);
    let workers_count: usize = workers.parse().expect("a worker count");
    let management_port = reserve_port();
    let mut node = start(data_dir.path(), workers, management_port);

    let outcome = (|| -> Result<(), String> {
        // Up once the removed stream echoes and the API answers.
        let started = Instant::now();
        let draining = loop {
            if let Ok(Some(status)) = node.try_wait() {
                return Err(format!("the node exited: {status}"));
            }
            match connect_echoing(ports.removed) {
                Ok(client) => break client,
                Err(e) if started.elapsed() > START_DEADLINE => return Err(e),
                Err(_) => std::thread::sleep(Duration::from_millis(200)),
            }
        };
        let api = loop {
            match Api::login(management_port, &password) {
                Ok(api) => break api,
                Err(e) if started.elapsed() > START_DEADLINE => return Err(e),
                Err(_) => std::thread::sleep(Duration::from_millis(200)),
            }
        };

        // Refused: loopback is denied.
        let _ = TcpStream::connect(("127.0.0.1", ports.denied));
        let refused = api
            .row_ending(DENIED_STREAM, "refused")
            .ok_or("no refused row")?;
        let denied_word: &str = StreamRefusal::SourceDenied.into();
        if refused["refusal_reason"] != denied_word {
            return Err(format!("refused row: {refused}"));
        }
        if refused["client_ip"] != "127.0.0.1" || refused["listen_port"] != ports.denied {
            return Err(format!("refused row: {refused}"));
        }

        // A burst is bounded by the refusal log: at most one row per
        // window in each process that refused, the rest counted in
        // `refusals_suppressed` rows at the window's end.
        const BURST: u64 = 20;
        for _ in 0..BURST {
            let _ = TcpStream::connect(("127.0.0.1", ports.denied));
        }
        api.bounded_refusals(DENIED_STREAM, BURST + 1, workers_count.max(1))?;

        // Idle: a connection that sends nothing more is closed, and its
        // row carries every field of the connection.
        let idle = connect_echoing(ports.idle)?;
        let local_port = idle.local_addr().map_err(|e| e.to_string())?.port();
        if !closed_by_node(idle, Duration::from_secs(10)) {
            return Err("the idle connection was not closed".into());
        }
        let row = api
            .row_ending(IDLE_STREAM, "idle_timeout")
            .ok_or("no idle_timeout row")?;
        let expected = json!({
            "entry": "ended",
            "stream_id": IDLE_STREAM,
            "stream_name": IDLE_STREAM,
            "protocol": "tcp",
            "listen_port": ports.idle,
            "client_ip": "127.0.0.1",
            "client_port": local_port,
            "proxied_from": "",
            "backend_id": BACKEND_ID,
            "backend_address": backend.to_string(),
            "attempts": 1,
            "bytes_upload": 4,
            "bytes_download": 4,
            "datagrams_upload": null,
            "datagrams_download": null,
            "tls_mode": "none",
            "sni": "",
            "alpn": "",
            "client_cert": null,
            "detected_protocol": null,
            "end_reason": "idle_timeout",
            "refusal_reason": "",
            "suppressed": 0,
        });
        for (field, value) in expected.as_object().expect("an object") {
            if &row[field] != value {
                return Err(format!("idle row field {field}: {row}"));
            }
        }
        // Accepted to end spans the one-second idle timeout; something
        // connected, quickly, on loopback.
        if row["duration_ms"].as_u64().is_none_or(|ms| ms < 1_000)
            || row["connect_ms"].as_u64().is_none_or(|ms| ms > 1_000)
        {
            return Err(format!("idle row timings: {row}"));
        }

        // config_removed: the stream goes while a connection is open.
        api.delete(&format!("/api/v1/streams/{REMOVED_STREAM}"))?;
        if !closed_by_node(draining, Duration::from_secs(u64::from(DRAIN_S) + 10)) {
            return Err("the removed stream's connection was not drained".into());
        }
        api.row_ending(REMOVED_STREAM, "config_removed")
            .ok_or("no config_removed row")?;

        // The workers' counters reach the node's /metrics, labels in
        // their declared order.
        for series in [
            format!(
                r#"lorica_stream_ended_total{{stream_id="{IDLE_STREAM}",reason="idle_timeout"}}"#
            ),
            format!(
                r#"lorica_stream_refused_total{{stream_id="{DENIED_STREAM}",reason="{denied_word}"}}"#
            ),
            format!(r#"lorica_stream_bytes_total{{stream_id="{IDLE_STREAM}",direction="upload"}}"#),
        ] {
            api.metric_above_zero(&series)?;
        }

        // A connection open at the stop ends `node_shutdown`, written
        // before the process exits.
        let _open = connect_echoing(ports.held)?;
        stop(&mut node);
        let reasons = stored_end_reasons(data_dir.path(), HELD_STREAM);
        if !reasons.iter().any(|r| r == "node_shutdown") {
            return Err(format!("no node_shutdown row among {reasons:?}"));
        }
        Ok(())
    })();
    stop(&mut node);
    if let Err(e) = outcome {
        panic!("{e}\n{}", node_log(data_dir.path()));
    }
}

#[test]
fn a_single_process_node_logs_and_counts_stream_ends() {
    a_node_logs_and_counts_stream_ends("0");
}

#[test]
fn a_worker_mode_node_logs_and_counts_stream_ends() {
    a_node_logs_and_counts_stream_ends("2");
}
