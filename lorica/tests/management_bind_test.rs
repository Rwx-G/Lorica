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

//! A single-process node whose management port is taken exits instead
//! of serving traffic with no management plane.
//!
//! The management port is unprivileged, so a local process can hold it
//! while Lorica restarts. A node that logged the failed bind and kept
//! proxying was not restarted by systemd, and the process holding the
//! port kept it, receiving every dashboard login meant for the node.
//! Supervisor mode already exited; this runs the real binary in
//! single-process mode against a port somebody else holds.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Longer than the startup of an empty node, which runs its migrations
/// and generates the management certificate before it binds.
const EXIT_DEADLINE: Duration = Duration::from_secs(60);

/// A loopback port nothing listens on at the time of the call.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("test setup: a free port")
        .port()
}

#[test]
fn a_single_process_node_exits_when_its_management_port_is_taken() {
    let squatter = std::net::TcpListener::bind("127.0.0.1:0").expect("test setup: bind");
    let management_port = squatter.local_addr().expect("test setup: addr").port();
    let data_dir = tempfile::tempdir().expect("test setup: data dir");
    let log_path = data_dir.path().join("node.log");
    let log = std::fs::File::create(&log_path).expect("test setup: log file");

    let mut node = Command::new(env!("CARGO_BIN_EXE_lorica"))
        .arg("--data-dir")
        .arg(data_dir.path())
        .args(["--workers", "0"])
        .args(["--management-port", &management_port.to_string()])
        .args(["--http-port", &free_port().to_string()])
        .args(["--https-port", &free_port().to_string()])
        .stdin(Stdio::null())
        .stdout(log.try_clone().expect("test setup: log handle"))
        .stderr(log)
        .spawn()
        .expect("test setup: the node starts");

    let started = Instant::now();
    let status = loop {
        if let Some(status) = node.try_wait().expect("the node can be waited on") {
            break Some(status);
        }
        if started.elapsed() > EXIT_DEADLINE {
            let _ = node.kill();
            let _ = node.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    let mut output = String::new();
    std::fs::File::open(&log_path)
        .and_then(|mut file| file.read_to_string(&mut output))
        .expect("the node's output is readable");
    let status = status
        .unwrap_or_else(|| panic!("the node kept running without its management API:\n{output}"));
    assert_eq!(status.code(), Some(1), "{output}");
    // The exit is the management listener's, not an earlier failure
    // that would make this test pass for the wrong reason.
    assert!(
        output.contains("management API failed to start; exiting"),
        "{output}"
    );
    drop(squatter);
}
