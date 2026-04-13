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

//! Multi-process crash-safety and concurrency tests for
//! `lorica-shmem::SharedRegion`.
//!
//! These tests exercise the production path: a parent process
//! creates the memfd, forks children, each child adopts the same fd
//! and performs concurrent increments. We then verify:
//!
//! - no torn reads or lost updates across processes;
//! - commutative sums add up under concurrent writers on the same key;
//! - keys isolated across workers do not cross-contaminate;
//! - killing a child mid-flight does not corrupt state seen by the
//!   survivor;
//! - the siphash key populated by the parent is observed identically
//!   by every child (so they probe the same chain for the same key).

#![cfg(target_os = "linux")]

use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

use lorica_shmem::{SharedRegion, SATURATED};

use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};

/// Fork a child that runs `body` against the shared region. Returns the
/// child PID to the parent.
///
/// # Safety
/// The parent must not rely on any async runtime before calling this —
/// forking a process with tokio threads active is undefined behaviour.
/// These tests deliberately avoid tokio.
fn fork_child<F: FnOnce(&'static SharedRegion)>(fd: RawFd, body: F) -> Pid {
    match unsafe { fork() }.expect("fork") {
        ForkResult::Parent { child } => child,
        ForkResult::Child => {
            let dup_fd = nix::unistd::dup(fd).expect("dup in child");
            let region = unsafe { SharedRegion::open_worker(dup_fd) }.expect("open_worker");
            body(region);
            std::process::exit(0);
        }
    }
}

fn wait_all(pids: &[Pid]) {
    for &pid in pids {
        match waitpid(pid, None).expect("waitpid") {
            WaitStatus::Exited(_, 0) => {}
            other => panic!("child {pid} bad status: {other:?}"),
        }
    }
}

#[test]
fn two_children_increment_same_key_sum_correct() {
    let (region, fd) = SharedRegion::create_supervisor().expect("create");
    let fd_raw = fd.as_raw_fd();
    let h = region.tagged(0xdead_beef);
    let now = 1_000u64;

    const PER_CHILD: u64 = 5_000;

    let pids = [
        fork_child(fd_raw, move |r| {
            for _ in 0..PER_CHILD {
                r.waf_flood.increment(h, 1, now);
            }
        }),
        fork_child(fd_raw, move |r| {
            for _ in 0..PER_CHILD {
                r.waf_flood.increment(h, 1, now);
            }
        }),
    ];

    wait_all(&pids);
    // Parent observes the aggregate. 10 000 increments total.
    assert_eq!(region.waf_flood.read(h), Some(2 * PER_CHILD));
    drop(fd);
}

#[test]
fn children_increment_disjoint_keys_no_crosstalk() {
    let (region, fd) = SharedRegion::create_supervisor().expect("create");
    let fd_raw = fd.as_raw_fd();

    // Each child increments its own set of keys.
    const PER_CHILD: u64 = 1_000;
    const KEYS_PER_CHILD: u64 = 16;

    let mut pids = Vec::new();
    for child_id in 0..4 {
        let pid = fork_child(fd_raw, move |r| {
            for k in 0..KEYS_PER_CHILD {
                let raw = (child_id as u64) * 1_000_000 + k;
                let h = r.tagged(raw);
                for _ in 0..PER_CHILD {
                    r.waf_auto_ban.increment(h, 1, 1);
                }
            }
        });
        pids.push(pid);
    }
    wait_all(&pids);

    for child_id in 0..4u64 {
        for k in 0..KEYS_PER_CHILD {
            let raw = child_id * 1_000_000 + k;
            let h = region.tagged(raw);
            assert_eq!(
                region.waf_auto_ban.read(h),
                Some(PER_CHILD),
                "child {child_id} key {k}"
            );
        }
    }
    drop(fd);
}

#[test]
fn siphash_key_is_shared_across_children() {
    let (region, fd) = SharedRegion::create_supervisor().expect("create");
    let parent_key = region.hash_key;
    let fd_raw = fd.as_raw_fd();

    // Child: write a marker value into waf_flood under a known raw key
    // using its own tagged(), then exit. Parent verifies it sees the
    // same tag — which means both hashed the same raw to the same h.
    let pid = fork_child(fd_raw, move |r| {
        assert_eq!(r.hash_key, parent_key, "child must see same key");
        let h = r.tagged(0xabcd_1234);
        r.waf_flood.increment(h, 777, 1);
    });
    wait_all(&[pid]);

    let h_parent = region.tagged(0xabcd_1234);
    assert_eq!(region.waf_flood.read(h_parent), Some(777));
    drop(fd);
}

#[test]
fn killed_child_does_not_corrupt_state() {
    let (region, fd) = SharedRegion::create_supervisor().expect("create");
    let fd_raw = fd.as_raw_fd();
    let h = region.tagged(42);

    // Survivor child: increments 1_000 times quickly, exits cleanly.
    let survivor = fork_child(fd_raw, move |r| {
        for _ in 0..1_000 {
            r.waf_flood.increment(h, 1, 1);
        }
    });

    // Victim child: loops increments forever; parent will SIGKILL.
    let victim = fork_child(fd_raw, move |r| loop {
        r.waf_flood.increment(h, 1, 1);
        std::thread::yield_now();
    });

    // Give them time to interleave, then kill the victim.
    std::thread::sleep(Duration::from_millis(50));
    kill(victim, Signal::SIGKILL).expect("kill");

    // Reap both (SIGKILL status != Exited(0), so handle manually).
    let _ = waitpid(survivor, None).expect("wait survivor");
    let _ = waitpid(victim, None).expect("wait victim");

    // Parent can still read a sane value (at least 1_000 from the
    // survivor plus whatever the victim managed before SIGKILL).
    let v = region.waf_flood.read(h).expect("some value");
    assert!(v >= 1_000, "survivor contributions must be visible: {v}");
    // And the parent can still write without issue.
    region.waf_flood.increment(h, 1, 2);
    assert!(region.waf_flood.read(h).unwrap() > v);
    drop(fd);
}

#[test]
fn probe_chain_saturation_returns_sentinel_across_processes() {
    // Force collision at a single slot start by picking tagged hashes
    // that all map to the same index in a production-size table. With
    // 128 Ki slots, MAX_PROBE = 16 consecutive forced collisions
    // exhausts the chain. We synthesize 16 + 1 tagged hashes with
    // identical low bits but distinct high bits and have a child write
    // all 16 then the parent try the 17th.
    let (region, fd) = SharedRegion::create_supervisor().expect("create");
    let fd_raw = fd.as_raw_fd();
    const SLOTS_MASK: u64 = (lorica_shmem::WAF_SLOTS as u64) - 1;

    // Hashes sharing the low bits => same start index.
    let start_bits: u64 = 0x3333 & SLOTS_MASK;

    let pid = fork_child(fd_raw, move |r| {
        for i in 0..lorica_shmem::MAX_PROBE as u64 {
            // Build raw tagged hash directly, bypassing siphash, so we
            // can control the bits. Then increment under that tag.
            let h = (i << 20) | start_bits | 1;
            r.waf_flood.increment(h, 1, 1);
        }
    });
    wait_all(&[pid]);

    // 17th distinct hash on the same start -> saturation.
    let h_extra = ((lorica_shmem::MAX_PROBE as u64) << 20) | start_bits | 1;
    // Silence the warn log via env. Not critical if it fires.
    let got = region.waf_flood.increment(h_extra, 1, 1);
    assert_eq!(got, SATURATED);
    drop(fd);
}
