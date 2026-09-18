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

//! Helpers shared by the end-to-end proxy tests.
//!
//! Cargo compiles every top-level file under `tests/` as its own crate,
//! so code cannot be shared by `use`. A subdirectory is not a test
//! target, which makes `tests/common/mod.rs` the standard place for
//! helpers and lets each test file pull it in with `mod common;`.

use std::collections::HashSet;
use std::net::TcpListener;
use std::sync::Mutex;

/// Draw a TCP port no other harness in this process has drawn.
///
/// Binding `127.0.0.1:0`, reading the assigned port and closing the
/// socket is not enough on its own, and the obvious "simplification"
/// back to that one-liner reintroduces a real flake. The proxy binds
/// its listener with `SO_REUSEPORT`, so when the kernel hands the same
/// ephemeral port to two harnesses they both bind it successfully:
/// there is no `EADDRINUSE` to notice. The kernel then splits incoming
/// connections between the two listeners, and one test's request is
/// answered by another test's origin server. The failure surfaces as a
/// wrong status code or byte count, never as a port clash, which is why
/// it took so long to diagnose.
///
/// The process-wide record below removes the intra-binary case: within
/// one test binary a port is handed out at most once, however many
/// tests run concurrently.
///
/// Known limit, stated plainly: the record is per process. Two test
/// binaries running at the same time (`cargo test` runs the targets in
/// parallel) each keep their own set and can still draw the same port.
/// That window is much narrower than the original one, and it has not
/// been observed. Closing it would need a cross-process reservation,
/// for instance a lock file in a shared directory recording the drawn
/// ports, or giving each test binary a disjoint port block from a
/// file-locked counter. Neither is worth the machinery until the
/// cross-binary collision actually shows up.
///
/// # Panics
///
/// Panics when 64 consecutive draws all return a port already taken,
/// which means the ephemeral range is exhausted or the host is not
/// handing out fresh ports.
pub fn reserve_port() -> u16 {
    static TAKEN: Mutex<Option<HashSet<u16>>> = Mutex::new(None);

    for _ in 0..64 {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut taken = TAKEN.lock().unwrap();
        if taken.get_or_insert_with(HashSet::new).insert(port) {
            return port;
        }
    }
    panic!("no free port after 64 attempts");
}
