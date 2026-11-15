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

//! The stream-caps region across processes (Story 12.5 Lot B): a forked
//! worker adopts the creator's memfd through `open` and both see the same
//! counts, a dead worker's sessions are released by its slot, and a
//! region this binary cannot read is refused.

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::sync::Arc;

use lorica_shmem::{
    RateLimits, RateVerdict, SourceKey, StreamCapsError, StreamCapsRegion,
    STREAM_CAPS_LAYOUT_VERSION,
};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult};

fn source(n: u8) -> SourceKey {
    SourceKey::of(IpAddr::V4(Ipv4Addr::new(192, 0, 2, n)))
}

fn dup(fd: &OwnedFd) -> OwnedFd {
    nix::unistd::dup(fd.as_fd()).expect("dup")
}

/// Fork a child that adopts a copy of `fd` and runs `body` on it, then
/// exits without dropping anything, as a worker that dies would.
fn in_child(fd: &OwnedFd, body: impl FnOnce(Arc<StreamCapsRegion>)) {
    match unsafe { fork() }.expect("fork") {
        ForkResult::Parent { child } => match waitpid(child, None).expect("waitpid") {
            WaitStatus::Exited(_, 0) => {}
            other => panic!("child {child}: {other:?}"),
        },
        ForkResult::Child => {
            // A failed assertion must end the child, never unwind into the
            // copy of the test harness it was forked from.
            let code = match StreamCapsRegion::open(dup(fd)) {
                Ok(region) => {
                    let run = std::panic::AssertUnwindSafe(|| body(Arc::new(region)));
                    match std::panic::catch_unwind(run) {
                        Ok(()) => 0,
                        Err(_) => 2,
                    }
                }
                Err(_) => 3,
            };
            std::process::exit(code);
        }
    }
}

#[test]
fn a_forked_worker_counts_in_the_creators_region() {
    let (region, fd) = StreamCapsRegion::create(64, 4, 1).expect("create");
    let region = Arc::new(region);
    let mine = region
        .worker(0)
        .unwrap()
        .admit_session(source(1), 8, 64)
        .unwrap();

    in_child(&fd, |child| {
        assert_eq!(child.total(), 1, "the creator's session is seen");
        let caps = child.worker(2).unwrap();
        for _ in 0..3 {
            std::mem::forget(caps.admit_session(source(1), 8, 64).unwrap());
        }
        std::mem::forget(caps.admit_session(source(2), 8, 64).unwrap());
    });

    assert_eq!(region.total(), 5);
    assert_eq!(region.worker_sessions(2), Some(4));
    assert_eq!(region.source_sessions(source(1)), 4);
    assert_eq!(region.source_sessions(source(2)), 1);

    // The child is gone with its sessions: its slot is released before
    // a replacement would start.
    assert_eq!(region.release_worker(2), Some(4));
    assert_eq!(region.total(), 1);
    assert_eq!(region.source_sessions(source(1)), 1);
    drop(mine);
    assert_eq!(region.total(), 0);
}

#[test]
fn a_forked_worker_shares_the_source_rates() {
    let (region, fd) = StreamCapsRegion::create(16, 2, 1).expect("create");
    let limits = RateLimits {
        datagrams_per_s: 5,
        bytes_per_s: 1_000_000,
    };
    let now = 10_000_000_000;
    in_child(&fd, move |child| {
        for _ in 0..5 {
            assert_eq!(
                child.charge_rate(source(9), 1, limits, now),
                RateVerdict::Allowed
            );
        }
    });
    // The child spent the source's whole burst.
    assert_eq!(
        region.charge_rate(source(9), 1, limits, now),
        RateVerdict::DatagramRate
    );
    assert_eq!(
        region.charge_rate(source(10), 1, limits, now),
        RateVerdict::Allowed
    );
}

#[test]
fn a_region_with_another_layout_version_is_refused() {
    let (_region, fd) = StreamCapsRegion::create(16, 2, 1).expect("create");
    let file = std::fs::File::from(dup(&fd));
    file.write_at(&(STREAM_CAPS_LAYOUT_VERSION + 1).to_le_bytes(), 8)
        .unwrap();
    match StreamCapsRegion::open(fd) {
        Err(StreamCapsError::BadVersion { got }) => {
            assert_eq!(got, STREAM_CAPS_LAYOUT_VERSION + 1)
        }
        other => panic!("expected BadVersion, got {other:?}"),
    }
}

#[test]
fn a_region_whose_size_disagrees_with_its_header_is_refused() {
    let (region, fd) = StreamCapsRegion::create(16, 2, 1).expect("create");
    let size = region.layout().size as i64;
    for wrong in [size + 4096, size - 64] {
        nix::unistd::ftruncate(&fd, wrong).unwrap();
        assert!(
            matches!(
                StreamCapsRegion::open(dup(&fd)),
                Err(StreamCapsError::BadSize { .. })
            ),
            "{wrong} bytes accepted"
        );
    }
    nix::unistd::ftruncate(&fd, size).unwrap();
    assert!(StreamCapsRegion::open(dup(&fd)).is_ok());
    nix::unistd::ftruncate(&fd, 16).unwrap();
    assert!(matches!(
        StreamCapsRegion::open(fd),
        Err(StreamCapsError::BadSize { .. })
    ));
}

#[test]
fn a_region_with_a_bad_magic_or_shape_is_refused() {
    let (_region, fd) = StreamCapsRegion::create(16, 2, 1).expect("create");
    let file = std::fs::File::from(dup(&fd));
    // Workers = 0: no shard to count in.
    file.write_at(&0u32.to_le_bytes(), 12).unwrap();
    assert!(matches!(
        StreamCapsRegion::open(dup(&fd)),
        Err(StreamCapsError::BadShape { .. })
    ));
    file.write_at(&0u64.to_le_bytes(), 0).unwrap();
    assert!(matches!(
        StreamCapsRegion::open(fd),
        Err(StreamCapsError::BadMagic { got: 0 })
    ));
}
