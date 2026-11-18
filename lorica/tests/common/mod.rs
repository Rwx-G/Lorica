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

//! Helpers shared by the end-to-end proxy tests and the tests that start
//! the real binary, and, through `#[path]`, by the `lorica-stream` UDP
//! tests, whose `SO_REUSEPORT` slots need the same cross-process ports.
//!
//! Cargo compiles every top-level file under `tests/` as its own crate,
//! so code cannot be shared by `use`. A subdirectory is not a test
//! target, which makes `tests/common/mod.rs` the standard place for
//! helpers and lets each test file pull it in with `mod common;`.

use std::fs::{File, TryLockError};
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::sync::Mutex;

/// The lowest port [`reserve_port`] hands out: above the registered
/// ports most services listen on.
const FIRST_TEST_PORT: u16 = 10_000;

/// The kernel's ephemeral range starts here when
/// `/proc/sys/net/ipv4/ip_local_port_range` cannot be read (its Linux
/// default).
const DEFAULT_EPHEMERAL_START: u16 = 32_768;

/// The ports this process reserved, each with the open lock file that
/// holds it for as long as the process lives.
static RESERVED: Mutex<Vec<(u16, File)>> = Mutex::new(Vec::new());

/// A port no other test can be handed while this process runs, and that
/// nothing on the host holds at the time of the call, for TCP or UDP on
/// any address.
///
/// The obvious "bind `127.0.0.1:0`, read the port, close the socket" is
/// not enough, and each step below closes one way it failed:
///
/// - **Outside the ephemeral range.** A port the kernel handed out for
///   `:0` goes back to the ephemeral pool when the probe closes, and the
///   next `bind(:0)` or outgoing `connect` anywhere on the host (another
///   test's probe or backend, the node's own upstream connections, a
///   test client) can take it before the node binds it: the node then
///   dies on `Address already in use` (seen on
///   `a_worker_mode_node_forwards_a_udp_stream_to_its_backend`). The
///   kernel never picks a port below `ip_local_port_range` by itself, so
///   a port drawn there can only be taken by someone who chose it.
/// - **A lock file per port, across processes.** Tests that chose ports
///   are the remaining risk: every test thread of this binary, and any
///   other test binary run at the same time. Each reservation takes an
///   exclusive `flock` on `<tmp>/lorica-test-ports/<port>.lock` and keeps
///   the file open: a second reservation of the port, from this process
///   or another, finds it locked and moves on. The kernel releases the
///   lock when the process exits, however it exits, so nothing is ever
///   left to clean up. The proxy binds its listeners with `SO_REUSEPORT`,
///   so two harnesses on one port would both bind and silently split
///   each other's connections: the lock is what rules that out.
/// - **A bind check.** A port some other program on the host already
///   listens on (TCP or UDP, wildcard or loopback) is skipped.
///
/// Each process starts its walk at an offset of its own, so concurrent
/// binaries rarely contend for the same lock.
///
/// # Panics
///
/// Panics when no port of the range can be reserved, or when a lock file
/// cannot be opened: a test setup failure either way.
pub fn reserve_port() -> u16 {
    let end = ephemeral_start();
    assert!(
        end > FIRST_TEST_PORT,
        "test setup: the ephemeral range starts at {end}, leaving no test port below it"
    );
    let span = u32::from(end - FIRST_TEST_PORT);
    let dir = std::env::temp_dir().join("lorica-test-ports");
    std::fs::create_dir_all(&dir).expect("test setup: the port lock directory");

    let mut reserved = RESERVED.lock().unwrap_or_else(|e| e.into_inner());
    let offset = std::process::id().wrapping_mul(7_919) % span;
    for step in 0..span {
        let port = FIRST_TEST_PORT + u16::try_from((offset + step) % span).expect("within u16");
        if reserved.iter().any(|(held, _)| *held == port) {
            continue;
        }
        let lock = File::options()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join(format!("{port}.lock")))
            .expect("test setup: a port lock file");
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => continue,
            Err(TryLockError::Error(e)) => panic!("test setup: port lock {port}: {e}"),
        }
        if !unbound(port) {
            continue;
        }
        reserved.push((port, lock));
        return port;
    }
    panic!("test setup: every port from {FIRST_TEST_PORT} to {end} is taken");
}

/// Whether nothing holds `port`, for TCP or UDP, on any address. The
/// probes close at once and leave no state behind.
fn unbound(port: u16) -> bool {
    TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).is_ok()
        && UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).is_ok()
}

/// The first port of the kernel's ephemeral range.
fn ephemeral_start() -> u16 {
    std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|range| range.split_whitespace().next()?.parse().ok())
        .unwrap_or(DEFAULT_EPHEMERAL_START)
}
