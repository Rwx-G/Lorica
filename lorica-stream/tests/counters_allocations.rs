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

//! What the stream counters allocate on the paths the engines take per
//! connection, session and dropped datagram (Phase 1 audit C24, C25).
//! A binary of its own: it installs a global allocator that counts the
//! allocations of the thread asking.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use lorica_config::models::{DatagramDropReason, StreamEndKind, StreamRefusal};
use lorica_stream::counters::{
    ClientHelloOutcome, ConnectFailureKind, HandshakeOutcome, ProxyHeaderOutcome,
    UpstreamTlsFailure,
};
use lorica_stream::StreamCounters;

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

fn counted() {
    // `try_with`: an allocation during thread teardown has no counter.
    let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
}

/// The system allocator, counting each allocation of the calling thread.
struct Counting;

// SAFETY: every call is forwarded unchanged to `System`, which upholds
// the `GlobalAlloc` contract; counting touches only a const-initialised
// thread-local `Cell`, which never allocates.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        counted();
        // SAFETY: the caller's contract for `alloc`, passed on.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        counted();
        // SAFETY: the caller's contract for `alloc_zeroed`, passed on.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        counted();
        // SAFETY: the caller's contract for `realloc`, passed on.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract for `dealloc`, passed on.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// The allocations `work` makes on this thread.
fn allocations_of(work: impl FnOnce()) -> usize {
    let before = ALLOCATIONS.with(Cell::get);
    work();
    ALLOCATIONS.with(Cell::get) - before
}

/// A flood of refusals or dropped datagrams counts on counters that
/// exist: no key, first seen or not, may allocate there.
#[test]
fn counting_on_existing_counters_allocates_nothing() {
    let counters = StreamCounters::new();
    let stream = counters.stream("s");
    let link = counters.link("s", "b");
    let allocations = allocations_of(|| {
        for outcome in ProxyHeaderOutcome::ALL {
            stream.proxy_header(outcome);
        }
        for outcome in ClientHelloOutcome::ALL {
            stream.clienthello(outcome);
        }
        for outcome in HandshakeOutcome::ALL {
            stream.handshake(outcome);
        }
        stream.refused(StreamRefusal::SourceOpenRate);
        stream.refused(StreamRefusal::CapsUnavailable);
        stream.dropped(DatagramDropReason::SourceDatagramRate);
        stream.dropped(DatagramDropReason::SendFailed);
        stream.ended(StreamEndKind::ClientClose);
        stream.ended(StreamEndKind::NodeShutdown);
        for kind in ConnectFailureKind::ALL {
            link.connect_failed(kind);
        }
        for kind in UpstreamTlsFailure::ALL {
            link.upstream_tls_failed(kind);
        }
    });
    assert_eq!(allocations, 0);

    let snapshot = counters.snapshot();
    let stream = &snapshot.streams["s"];
    assert_eq!(stream.proxy_header.len(), ProxyHeaderOutcome::ALL.len());
    assert_eq!(stream.clienthello.len(), ClientHelloOutcome::ALL.len());
    assert_eq!(stream.handshakes.len(), HandshakeOutcome::ALL.len());
    assert_eq!(stream.refused[&StreamRefusal::CapsUnavailable], 1);
    assert_eq!(stream.dropped[&DatagramDropReason::SendFailed], 1);
    assert_eq!(stream.ended[&StreamEndKind::NodeShutdown], 1);
    let link = &snapshot.links[&("s".to_string(), "b".to_string())];
    assert_eq!(link.connect_failures.len(), ConnectFailureKind::ALL.len());
    assert_eq!(
        link.upstream_tls_failures.len(),
        UpstreamTlsFailure::ALL.len()
    );
}

/// The engines look their counters up per connection and per session:
/// finding counters that exist allocates nothing.
#[test]
fn finding_existing_counters_allocates_nothing() {
    let counters = StreamCounters::new();
    drop((
        counters.stream("s"),
        counters.link("s", "b"),
        counters.backend("b"),
        counters.rule("s", "r"),
    ));
    let allocations = allocations_of(|| {
        for _ in 0..100 {
            drop(counters.stream("s"));
            drop(counters.link("s", "b"));
            drop(counters.backend("b"));
            drop(counters.rule("s", "r"));
        }
    });
    assert_eq!(allocations, 0);
}
