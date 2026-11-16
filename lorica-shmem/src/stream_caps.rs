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

//! The stream-caps region: per-node caps and rates of one stream, TCP or
//! UDP, shared by every worker (Story 12.5 D-d, Story 12.6 D-e).
//!
//! One anonymous memfd per stream, created by the supervisor (or the
//! single-process driver) and mapped `MAP_SHARED` by every worker. Unlike
//! [`SharedRegion`](crate::SharedRegion), it is sized at runtime from the
//! stream's cap (`max_sessions` on UDP, `max_connections` on TCP), its
//! backend link count and the node's worker count, and a flood that fills
//! one stream's tables cannot touch another's.
//!
//! Layout (little-endian, every part 64-byte aligned):
//!
//! ```text
//!   part             content                                      size
//!   ----             -------                                      ----
//!   header           magic, layout version, workers W, hash key,  64
//!                    rate_slots, shard_slots, caps_gen,
//!                    backend_slots
//!   totals           total, then per_worker[W]                    8 (W + 1), padded
//!   pending          pending, then pending_per_worker[W]          8 (W + 1), padded
//!   stream rate      open_tat                                     64
//!   rate table       rate_slots cells: key, datagram_tat,         rate_slots x 64
//!                    byte_tat, last_seen_ns, open_tat
//!   source shards    W shards of shard_slots cells: key,          W x shard_slots x 32
//!                    active, pending
//!   backend shards   W shards of backend_slots cells: key,        W x backend_slots x 16
//!                    active
//! ```
//!
//! What each part counts:
//!
//! - **The stream total and the pending total** are exact: an admission
//!   adds 1 and backs off when the result passes the cap.
//!   `per_worker[i]` and `pending_per_worker[i]` attribute them, so the
//!   supervisor can subtract a dead worker's share.
//! - **Per-source and per-backend counts** live in per-worker shards. A
//!   worker claims and counts only in its own shard; a check sums the
//!   key over every shard. Only the release that brings a cell's count to
//!   0 frees it, and [`StreamCapsRegion::release_worker`] for a dead
//!   worker's shards: nothing else, eviction included, ever frees a shard
//!   cell, so a held slot is never evicted. Two workers admitting the
//!   same key at once can both pass the check, so a key holds at most
//!   `cap + (W - 1)` on the node; one worker alone never passes `cap`.
//! - **Rates** are GCRA theoretical arrival times, shared by every
//!   worker: one per stream (openings), three per source (openings,
//!   datagrams, bytes). Burst is one second of rate.
//!   [`StreamCapsRegion::evict_rates`] frees a source's cell once its
//!   three buckets are full again and no shard holds its source.
//!
//! A full probe window refuses the admission or the new source on this
//! stream only ([`AdmitRefusal::TableFull`], [`RateVerdict::TableFull`],
//! [`OpenVerdict::TableFull`]).
//!
//! **Cells changing hands.** A free shard cell is claimed by moving its
//! key from `0` to the source's and *setting* its count; a count is never
//! adjusted from a value read before the claim, which is what went wrong
//! in the WAF tables (see [`crate::table`]). What remains is
//! the join of a cell already holding a key: a worker that read the key,
//! then lost the cell to a release and a claim for another key before
//! its add, would add to that key. Every join re-reads the key after its
//! add and takes the add back when the cell changed hands; a rate charge
//! does the same against eviction.
//!
//! The layout carries its own [`STREAM_CAPS_LAYOUT_VERSION`]; the WAF
//! region's [`LAYOUT_VERSION`](crate::LAYOUT_VERSION) is unrelated.
//! Regions are never shared across process generations, so a version
//! change has no upgrade consequence.

use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::os::fd::OwnedFd;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use nix::errno::Errno;
use nix::sys::mman::{mmap, munmap, MapFlags, ProtFlags};

use crate::hash::{random_key, siphash13_u64};
use crate::table::{holding, tagged_hash, window, window_indices, Keyed, MAX_PROBE};

/// Magic number at the start of a stream-caps region: ASCII "LORICASC"
/// read as a big-endian `u64`, as the WAF region's
/// [`MAGIC`](crate::MAGIC) is.
pub const STREAM_CAPS_MAGIC: u64 = u64::from_be_bytes(*b"LORICASC");

/// Layout version of the stream-caps region, checked by every process
/// that maps one. Bumped on any change to the header, the parts, their
/// order or the cells' ABI, and listed in `docs/BUMP-CHECKLIST.md`.
/// Version 2 (Story 12.6) added the pending totals, the stream and
/// per-source open rates, the 32-byte source cells and the backend
/// shards, so one region serves TCP as well as UDP.
pub const STREAM_CAPS_LAYOUT_VERSION: u32 = 2;

/// Rate cells per session (UDP) or connection (TCP) of the stream's cap:
/// sources outnumber admissions (a source is charged before it is
/// admitted, and a refused source may still have a cell), so the table
/// holds four sources per admission at most a quarter full.
pub const RATE_SLOTS_PER_SESSION: u64 = 4;

/// Fewest rate cells a region holds.
pub const MIN_RATE_SLOTS: u64 = 1024;

/// Source cells per session or connection of the stream's cap: one
/// worker never holds more sources than the cap, so its shard is at most
/// half full.
pub const SHARD_SLOTS_PER_SESSION: u64 = 2;

/// Fewest cells a worker's source shard holds.
pub const MIN_SHARD_SLOTS: u64 = 256;

/// Backend cells per backend link of the stream: a worker's backend
/// shard is at most half full. A link count that outgrows it is a new
/// region (`caps_gen`), not a fuller table.
pub const BACKEND_SLOTS_PER_LINK: u64 = 2;

/// Fewest cells a worker's backend shard holds: one probe window, the
/// least a table may have (a window never visits a cell twice).
pub const MIN_BACKEND_SLOTS: u64 = MAX_PROBE as u64;

/// Largest table the layout accepts, in cells: past it the arithmetic of
/// the sizes leaves the range a mapping can have on any host.
const MAX_TABLE_SLOTS: u64 = 1 << 32;

/// Most workers the layout accepts, the same sanity bound.
const MAX_WORKERS: u32 = 1 << 16;

/// GCRA burst tolerance: a source with a full bucket may send one second
/// of its rate at once.
pub const RATE_BURST_NS: u64 = 1_000_000_000;

/// A rate cell claimed less than this long ago is never evicted: its
/// first charge may still be on its way, between the claim and the
/// arrival times it moves.
pub const RATE_CELL_GRACE_NS: u64 = 1_000_000_000;

/// How many times a rate charge looks its source's cell up again after
/// finding that eviction gave the cell to another source mid-charge.
/// Eviction only frees a cell idle for [`RATE_CELL_GRACE_NS`], so a
/// second lookup practically always settles it; past the bound the
/// charge is refused as a full table, with nothing charged.
const RATE_CELL_ATTEMPTS: usize = 4;

/// Header of the region, one cache line. Written once by the creator
/// before the fd leaves it, read-only afterwards.
#[repr(C, align(64))]
struct Header {
    magic: u64,
    layout_version: u32,
    workers: u32,
    hash_key: [u64; 2],
    rate_slots: u64,
    shard_slots: u64,
    caps_gen: u64,
    backend_slots: u64,
}

const _: () = assert!(std::mem::size_of::<Header>() == 64);

/// The stream's own rate state, alone on its cache line: every worker
/// charges it on every opening.
#[repr(C, align(64))]
struct StreamRate {
    /// GCRA theoretical arrival time of the stream's next opening.
    open_tat: AtomicU64,
    _pad: [u64; 7],
}

const _: () = assert!(std::mem::size_of::<StreamRate>() == 64);

/// One source's rate state. One cache line, so two sources never share
/// one under contention.
#[repr(C, align(64))]
struct RateCell {
    /// Tagged hash of the source key, `0` when free.
    key: AtomicU64,
    /// GCRA theoretical arrival time of the next datagram, in
    /// [`now_ns`](crate::now_ns) nanoseconds.
    datagram_tat: AtomicU64,
    /// GCRA theoretical arrival time of the next byte.
    byte_tat: AtomicU64,
    /// When a worker last charged this cell or claimed it.
    last_seen_ns: AtomicU64,
    /// GCRA theoretical arrival time of the source's next opening (a TCP
    /// connection admitted, a UDP session created).
    open_tat: AtomicU64,
    _pad: [u64; 3],
}

const _: () = assert!(std::mem::size_of::<RateCell>() == 64);

/// One source's admissions in one worker's shard.
#[repr(C, align(32))]
struct SourceCell {
    /// Tagged hash of the source key, `0` when free.
    key: AtomicU64,
    /// Connections or sessions of the source this worker holds through
    /// this cell, pending ones included.
    active: AtomicU64,
    /// Those of `active` still in phase 2 (TCP pre-forwarding reads).
    /// Never above `active`: a pending count is given back before its
    /// active one.
    pending: AtomicU64,
    _pad: u64,
}

const _: () = assert!(std::mem::size_of::<SourceCell>() == 32);

/// One backend's connections or sessions in one worker's shard.
#[repr(C, align(16))]
struct BackendCell {
    /// Tagged hash of the backend key, `0` when free.
    key: AtomicU64,
    /// Connections or sessions this worker holds to the backend.
    active: AtomicU64,
}

const _: () = assert!(std::mem::size_of::<BackendCell>() == 16);

impl Keyed for RateCell {
    fn key(&self) -> &AtomicU64 {
        &self.key
    }
}

impl Keyed for SourceCell {
    fn key(&self) -> &AtomicU64 {
        &self.key
    }
}

impl Keyed for BackendCell {
    fn key(&self) -> &AtomicU64 {
        &self.key
    }
}

/// A shard cell: a key and the count of what holds it.
trait Counted: Keyed {
    fn active(&self) -> &AtomicU64;
}

impl Counted for SourceCell {
    fn active(&self) -> &AtomicU64 {
        &self.active
    }
}

impl Counted for BackendCell {
    fn active(&self) -> &AtomicU64 {
        &self.active
    }
}

/// Where each part of a region lies, and its size. A pure function of
/// the stream's cap, its link count and the worker count
/// ([`layout_with_links`]), so the fd budget and the docs compute the
/// same figures the region is built with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamCapsLayout {
    /// Worker count W: one shard of each kind and one attribution
    /// counter of each total each.
    pub workers: u32,
    /// Cells of the rate table.
    pub rate_slots: u64,
    /// Cells of each worker's source shard.
    pub shard_slots: u64,
    /// Cells of each worker's backend shard.
    pub backend_slots: u64,
    /// Offset of the totals part.
    pub totals_offset: usize,
    /// Offset of the pending part.
    pub pending_offset: usize,
    /// Offset of the stream's rate cell.
    pub stream_rate_offset: usize,
    /// Offset of the rate table.
    pub rate_offset: usize,
    /// Offset of the first source shard.
    pub shards_offset: usize,
    /// Offset of the first backend shard.
    pub backends_offset: usize,
    /// Size of the whole region in bytes, the memfd's length. Pages are
    /// only backed once touched.
    pub size: usize,
}

impl StreamCapsLayout {
    /// Bytes of the rate table.
    pub fn rate_table_bytes(&self) -> usize {
        self.shards_offset - self.rate_offset
    }

    /// Bytes of all the source shards together.
    pub fn shard_bytes(&self) -> usize {
        self.backends_offset - self.shards_offset
    }

    /// Bytes of all the backend shards together.
    pub fn backend_bytes(&self) -> usize {
        self.size - self.backends_offset
    }

    fn from_counts(
        workers: u32,
        rate_slots: u64,
        shard_slots: u64,
        backend_slots: u64,
    ) -> Result<Self, StreamCapsError> {
        let table_ok = |slots: u64| {
            slots.is_power_of_two() && slots >= MAX_PROBE as u64 && slots <= MAX_TABLE_SLOTS
        };
        if workers == 0
            || workers > MAX_WORKERS
            || !table_ok(rate_slots)
            || !table_ok(shard_slots)
            || !table_ok(backend_slots)
        {
            return Err(StreamCapsError::BadShape {
                workers,
                rate_slots,
                shard_slots,
                backend_slots,
            });
        }
        let header = std::mem::size_of::<Header>();
        let per_worker_part = (u64::from(workers) + 1)
            .checked_mul(8)
            .and_then(|b| usize::try_from(b).ok())
            .map(|b| b.next_multiple_of(64))
            .ok_or(StreamCapsError::TooLarge)?;
        let table = |slots: u64, cell: usize, copies: usize| {
            usize::try_from(slots)
                .ok()
                .and_then(|n| n.checked_mul(cell))
                .and_then(|b| b.checked_mul(copies))
                .ok_or(StreamCapsError::TooLarge)
        };
        let rate = table(rate_slots, std::mem::size_of::<RateCell>(), 1)?;
        let shards = table(
            shard_slots,
            std::mem::size_of::<SourceCell>(),
            workers as usize,
        )?;
        let backends = table(
            backend_slots,
            std::mem::size_of::<BackendCell>(),
            workers as usize,
        )?;
        let totals_offset = header;
        let pending_offset = totals_offset + per_worker_part;
        let stream_rate_offset = pending_offset + per_worker_part;
        let rate_offset = stream_rate_offset + std::mem::size_of::<StreamRate>();
        let after = |offset: usize, bytes: usize| {
            offset.checked_add(bytes).ok_or(StreamCapsError::TooLarge)
        };
        let shards_offset = after(rate_offset, rate)?;
        let backends_offset = after(shards_offset, shards)?;
        let size = after(backends_offset, backends)?;
        if size > isize::MAX as usize {
            return Err(StreamCapsError::TooLarge);
        }
        Ok(StreamCapsLayout {
            workers,
            rate_slots,
            shard_slots,
            backend_slots,
            totals_offset,
            pending_offset,
            stream_rate_offset,
            rate_offset,
            shards_offset,
            backends_offset,
            size,
        })
    }
}

/// [`layout_with_links`] for a stream with no more links than the
/// smallest backend shard holds, as the UDP path of Story 12.5 sizes its
/// regions.
///
/// # Errors
///
/// As [`layout_with_links`].
pub fn layout_for(max_sessions: u64, workers: u32) -> Result<StreamCapsLayout, StreamCapsError> {
    layout_with_links(max_sessions, workers, 0)
}

/// The layout of a region for a stream whose cap is `max_admitted`
/// (`max_sessions` on UDP, `max_connections` on TCP), with `links`
/// backend links, on a node of `workers` workers:
/// `rate_slots = next_pow2(max(4 x max_admitted, 1,024))`,
/// `shard_slots = next_pow2(max(2 x max_admitted, 256))`,
/// `backend_slots = next_pow2(max(2 x links, 32))`, the factors and
/// floors being [`RATE_SLOTS_PER_SESSION`], [`MIN_RATE_SLOTS`],
/// [`SHARD_SLOTS_PER_SESSION`], [`MIN_SHARD_SLOTS`],
/// [`BACKEND_SLOTS_PER_LINK`] and [`MIN_BACKEND_SLOTS`].
///
/// # Errors
///
/// [`StreamCapsError::BadShape`] for a cap of 0 or no worker,
/// [`StreamCapsError::TooLarge`] past what a mapping can hold.
pub fn layout_with_links(
    max_admitted: u64,
    workers: u32,
    links: u64,
) -> Result<StreamCapsLayout, StreamCapsError> {
    let slots = |count: u64, per: u64, floor: u64| {
        count
            .checked_mul(per)
            .map(|n| n.max(floor))
            .and_then(u64::checked_next_power_of_two)
            .ok_or(StreamCapsError::TooLarge)
    };
    if max_admitted == 0 {
        return Err(StreamCapsError::BadShape {
            workers,
            rate_slots: 0,
            shard_slots: 0,
            backend_slots: 0,
        });
    }
    StreamCapsLayout::from_counts(
        workers,
        slots(max_admitted, RATE_SLOTS_PER_SESSION, MIN_RATE_SLOTS)?,
        slots(max_admitted, SHARD_SLOTS_PER_SESSION, MIN_SHARD_SLOTS)?,
        slots(links, BACKEND_SLOTS_PER_LINK, MIN_BACKEND_SLOTS)?,
    )
}

/// Why a region could not be created or adopted.
#[derive(Debug, thiserror::Error)]
pub enum StreamCapsError {
    #[error("memfd_create failed: {0}")]
    Memfd(Errno),
    #[error("ftruncate failed: {0}")]
    Ftruncate(Errno),
    #[error("fstat failed: {0}")]
    Fstat(Errno),
    #[error("mmap failed: {0}")]
    Mmap(Errno),
    #[error(
        "stream caps region magic mismatch: got {got:#x}, expected {:#x}",
        STREAM_CAPS_MAGIC
    )]
    BadMagic { got: u64 },
    #[error(
        "stream caps layout version mismatch: got {got}, expected {} (supervisor/worker binary skew?)",
        STREAM_CAPS_LAYOUT_VERSION
    )]
    BadVersion { got: u32 },
    #[error(
        "stream caps region shape refused: {workers} workers, {rate_slots} rate cells, {shard_slots} source cells, {backend_slots} backend cells"
    )]
    BadShape {
        workers: u32,
        rate_slots: u64,
        shard_slots: u64,
        backend_slots: u64,
    },
    #[error("stream caps region is {actual} bytes, its header describes {expected}")]
    BadSize { actual: u64, expected: usize },
    #[error("stream caps region too large to map")]
    TooLarge,
}

/// The key the per-source caps and rates count under: an IPv4 address,
/// or the /64 prefix of an IPv6 one, since one host holds a whole /64
/// and per-address keys would let it multiply every per-source control.
/// An IPv4-mapped IPv6 address is its IPv4 address. Balancing does not
/// use this key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceKey {
    /// An IPv4 source.
    V4(u32),
    /// The upper 64 bits of an IPv6 source.
    V6Prefix(u64),
}

impl SourceKey {
    /// The key of a client address.
    pub fn of(ip: IpAddr) -> SourceKey {
        match ip.to_canonical() {
            IpAddr::V4(v4) => SourceKey::V4(u32::from(v4)),
            IpAddr::V6(v6) => SourceKey::V6Prefix((u128::from(v6) >> 64) as u64),
        }
    }
}

impl From<IpAddr> for SourceKey {
    fn from(ip: IpAddr) -> Self {
        SourceKey::of(ip)
    }
}

/// The key a per-backend count is held under: a 64-bit FNV-1a digest of
/// the backend id, the same in every process of the node. The region
/// hashes it again with its own key before placing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BackendKey(u64);

impl BackendKey {
    /// The key of a backend id.
    pub fn of(backend_id: &str) -> BackendKey {
        const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const PRIME: u64 = 0x0000_0100_0000_01b3;
        BackendKey(
            backend_id
                .bytes()
                .fold(OFFSET, |h, b| (h ^ u64::from(b)).wrapping_mul(PRIME)),
        )
    }
}

/// XORed into the first half of the hash key for IPv6 prefixes, so an
/// IPv4 address and an IPv6 prefix of the same numeric value hash apart.
const V6_KEY_DOMAIN: u64 = 0x7636_5f70_7265_6678;

/// Why an admission was refused, by [`WorkerCaps::admit_stream`] or
/// [`StreamPermit::admit_source`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitRefusal {
    /// The stream holds its cap (TCP connections, UDP sessions) on this
    /// node.
    StreamCap,
    /// The stream holds its pending cap on this node.
    PendingCap,
    /// The source holds its per-source cap on this node.
    SourceCap,
    /// The source holds its share of the pending cap on this node.
    SourcePendingCap,
    /// The source's probe window in this worker's shard is full.
    TableFull,
}

/// The outcome of charging one datagram to its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateVerdict {
    /// Within both rates; charged.
    Allowed,
    /// Over the per-source datagram rate; nothing charged.
    DatagramRate,
    /// Over the per-source byte rate; nothing charged.
    ByteRate,
    /// The source has no cell and its probe window is full.
    TableFull,
}

/// The outcome of charging one opening (a TCP connection, a UDP session)
/// to the stream and its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenVerdict {
    /// Within every rate charged; charged.
    Allowed,
    /// Over the stream's open rate; nothing charged.
    OpenRate,
    /// Over the source's open rate; nothing charged.
    SourceOpenRate,
    /// The source has no cell and its probe window is full; nothing
    /// charged.
    TableFull,
}

/// The outcome of charging the first datagram of a new UDP session: its
/// opening and the datagram itself, in one sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewSessionVerdict {
    /// Within every rate; charged.
    Allowed,
    /// Over the stream's open rate; nothing charged.
    OpenRate,
    /// Over the source's open rate; nothing charged.
    SourceOpenRate,
    /// Over the per-source datagram rate; nothing charged.
    DatagramRate,
    /// Over the per-source byte rate; nothing charged.
    ByteRate,
    /// The source has no cell and its probe window is full; nothing
    /// charged.
    TableFull,
}

/// A source's datagram rates, read from the stream's settings at each
/// charge: only sizes live in the region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimits {
    /// Datagrams per second.
    pub datagrams_per_s: u64,
    /// Bytes per second.
    pub bytes_per_s: u64,
}

/// A stream's open rates, read from its settings at each charge; `None`
/// is no limit, and charges nothing.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OpenLimits {
    /// Openings per second on the stream, on this node.
    pub stream_per_s: Option<u64>,
    /// Openings per second from one source, on this node.
    pub source_per_s: Option<u64>,
}

/// What one [`StreamCapsRegion::evict_rates`] pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RateEvictionStats {
    /// Cells holding a source when the pass reached them.
    pub occupied: usize,
    /// Cells released.
    pub evicted: usize,
    /// Cells kept because their source holds a connection or session.
    pub held: usize,
}

/// One stream's caps region, mapped. Every access to the shared pages
/// goes through atomics; the mapping is released on drop, and the pages
/// live as long as any process maps them or holds the memfd.
pub struct StreamCapsRegion {
    base: NonNull<u8>,
    layout: StreamCapsLayout,
    hash_key: [u64; 2],
    caps_gen: u64,
}

// SAFETY: the region's shared memory is only ever read and written
// through atomics (the header is immutable once the fd leaves its
// creator), so it can be used from any thread, as it is from any
// process; `base` is valid until `Drop` unmaps it.
unsafe impl Send for StreamCapsRegion {}
// SAFETY: as above.
unsafe impl Sync for StreamCapsRegion {}

impl std::fmt::Debug for StreamCapsRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamCapsRegion")
            .field("layout", &self.layout)
            .field("caps_gen", &self.caps_gen)
            .field("total", &self.total())
            .field("pending", &self.pending())
            .finish_non_exhaustive()
    }
}

impl Drop for StreamCapsRegion {
    fn drop(&mut self) {
        // SAFETY: `base` and `size` are the mapping `map` made, and no
        // reference into it outlives `self`.
        if let Err(e) = unsafe { munmap(self.base.cast(), self.layout.size) } {
            tracing::warn!(error = %e, "stream caps region: munmap failed");
        }
    }
}

/// Map `len` bytes of `fd`, shared, read and write.
fn map(fd: &OwnedFd, len: usize) -> Result<NonNull<u8>, StreamCapsError> {
    let len = NonZeroUsize::new(len).ok_or(StreamCapsError::TooLarge)?;
    // SAFETY: a fresh shared mapping of a memfd at no fixed address
    // aliases nothing in this process; the caller unmaps it with the
    // same length.
    let ptr = unsafe {
        mmap(
            None,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_SHARED,
            fd,
            0,
        )
    }
    .map_err(StreamCapsError::Mmap)?;
    Ok(ptr.cast())
}

/// Why a charge on a source's rate cell did not complete.
enum Refused {
    /// The stream's own open rate.
    Stream,
    /// The cell's arrival time at this index of [`CELL_TATS`] order:
    /// opening, datagram, byte.
    Cell(usize),
    /// No cell for the source.
    TableFull,
}

/// What charging one rate cell did.
enum CellCharge {
    /// Every increment charged, and the cell still holds the source.
    Charged,
    /// The increment at this index refused; nothing charged.
    Refused(usize),
    /// The cell was given to another source before the charge was
    /// checked; nothing charged.
    Moved,
}

/// The order a source's increments are charged in: opening, datagram,
/// byte.
const CELL_TATS: usize = 3;

impl StreamCapsRegion {
    /// [`StreamCapsRegion::create_with_links`] with no more links than
    /// the smallest backend shard holds ([`layout_for`]).
    ///
    /// # Errors
    ///
    /// As [`StreamCapsRegion::create_with_links`].
    pub fn create(
        max_sessions: u64,
        workers: u32,
        caps_gen: u64,
    ) -> Result<(StreamCapsRegion, OwnedFd), StreamCapsError> {
        Self::create_with_links(max_sessions, workers, 0, caps_gen)
    }

    /// Create the region of a stream whose cap is `max_admitted`, with
    /// `links` backend links, on a node of `workers` workers: a memfd
    /// sized by [`layout_with_links`], mapped, its header written with a
    /// fresh SipHash key. Returns the mapping and the memfd to send to
    /// every worker.
    ///
    /// # Errors
    ///
    /// The layout's refusal, or the failing system call.
    pub fn create_with_links(
        max_admitted: u64,
        workers: u32,
        links: u64,
        caps_gen: u64,
    ) -> Result<(StreamCapsRegion, OwnedFd), StreamCapsError> {
        use nix::sys::memfd::{memfd_create, MFdFlags};
        let layout = layout_with_links(max_admitted, workers, links)?;
        let fd = memfd_create(c"lorica-stream-caps", MFdFlags::MFD_CLOEXEC)
            .map_err(StreamCapsError::Memfd)?;
        let length = i64::try_from(layout.size).map_err(|_| StreamCapsError::TooLarge)?;
        nix::unistd::ftruncate(&fd, length).map_err(StreamCapsError::Ftruncate)?;
        let base = map(&fd, layout.size)?;
        let hash_key = random_key();
        // SAFETY: the mapping is at least one header long, page-aligned,
        // and no other process can see it before the fd leaves here.
        unsafe {
            base.cast::<Header>().as_ptr().write(Header {
                magic: STREAM_CAPS_MAGIC,
                layout_version: STREAM_CAPS_LAYOUT_VERSION,
                workers,
                hash_key,
                rate_slots: layout.rate_slots,
                shard_slots: layout.shard_slots,
                caps_gen,
                backend_slots: layout.backend_slots,
            });
        }
        Ok((
            StreamCapsRegion {
                base,
                layout,
                hash_key,
                caps_gen,
            },
            fd,
        ))
    }

    /// Adopt a region received from its creator: map it, verify the
    /// magic, [`STREAM_CAPS_LAYOUT_VERSION`] and the sizes the header
    /// describes against the file's length. The fd is closed on return;
    /// the mapping keeps the pages.
    ///
    /// # Errors
    ///
    /// A failing system call or a header this binary cannot use.
    pub fn open(fd: OwnedFd) -> Result<StreamCapsRegion, StreamCapsError> {
        let actual = nix::sys::stat::fstat(&fd)
            .map_err(StreamCapsError::Fstat)?
            .st_size;
        let actual = u64::try_from(actual).unwrap_or(0);
        let header_len = std::mem::size_of::<Header>();
        if actual < header_len as u64 {
            return Err(StreamCapsError::BadSize {
                actual,
                expected: header_len,
            });
        }
        let header_map = map(&fd, header_len)?;
        // SAFETY: the mapping is one header long and page-aligned; the
        // creator wrote the header before sending the fd.
        let header = unsafe { header_map.cast::<Header>().as_ptr().read() };
        // SAFETY: `header_map` is the mapping made just above.
        if let Err(e) = unsafe { munmap(header_map.cast(), header_len) } {
            tracing::warn!(error = %e, "stream caps region: munmap of the header failed");
        }
        if header.magic != STREAM_CAPS_MAGIC {
            return Err(StreamCapsError::BadMagic { got: header.magic });
        }
        if header.layout_version != STREAM_CAPS_LAYOUT_VERSION {
            return Err(StreamCapsError::BadVersion {
                got: header.layout_version,
            });
        }
        let layout = StreamCapsLayout::from_counts(
            header.workers,
            header.rate_slots,
            header.shard_slots,
            header.backend_slots,
        )?;
        if actual != layout.size as u64 {
            return Err(StreamCapsError::BadSize {
                actual,
                expected: layout.size,
            });
        }
        Ok(StreamCapsRegion {
            base: map(&fd, layout.size)?,
            layout,
            hash_key: header.hash_key,
            caps_gen: header.caps_gen,
        })
    }

    /// Where each part lies.
    pub fn layout(&self) -> &StreamCapsLayout {
        &self.layout
    }

    /// The region's generation among its stream's successive regions.
    pub fn caps_gen(&self) -> u64 {
        self.caps_gen
    }

    /// The handle through which worker `slot` admits, `None` when the
    /// region has no such slot.
    pub fn worker(self: &Arc<Self>, slot: u32) -> Option<WorkerCaps> {
        (slot < self.layout.workers).then(|| WorkerCaps {
            region: Arc::clone(self),
            slot,
        })
    }

    /// Connections or sessions the stream holds on the node in this
    /// region, exact.
    pub fn total(&self) -> u64 {
        self.totals()[0].load(Ordering::Acquire)
    }

    /// Connections or sessions worker `slot` holds in this region,
    /// `None` for no such slot.
    pub fn worker_sessions(&self, slot: u32) -> Option<u64> {
        (slot < self.layout.workers)
            .then(|| self.totals()[1 + slot as usize].load(Ordering::Acquire))
    }

    /// Connections of the stream in phase 2 on the node in this region,
    /// exact.
    pub fn pending(&self) -> u64 {
        self.pendings()[0].load(Ordering::Acquire)
    }

    /// Connections in phase 2 worker `slot` holds in this region, `None`
    /// for no such slot.
    pub fn worker_pending(&self, slot: u32) -> Option<u64> {
        (slot < self.layout.workers)
            .then(|| self.pendings()[1 + slot as usize].load(Ordering::Acquire))
    }

    /// Connections or sessions `source` holds on the node in this region,
    /// summed over every worker's shard.
    pub fn source_sessions(&self, source: SourceKey) -> u64 {
        let tagged = self.tagged(source);
        self.source_shards()
            .map(|shard| shard_count(shard, tagged, |c| &c.active))
            .sum()
    }

    /// Connections of `source` in phase 2 on the node in this region,
    /// summed over every worker's shard.
    pub fn source_pending(&self, source: SourceKey) -> u64 {
        let tagged = self.tagged(source);
        self.source_shards()
            .map(|shard| shard_count(shard, tagged, |c| &c.pending))
            .sum()
    }

    /// Connections or sessions the stream holds to `backend` on the node
    /// in this region, summed over every worker's shard.
    pub fn backend_active(&self, backend: BackendKey) -> u64 {
        let tagged = self.tagged_backend(backend);
        self.backend_shards()
            .map(|shard| shard_count(shard, tagged, |c| &c.active))
            .sum()
    }

    /// Charge one datagram of `bytes` bytes to `source` at `now_ns`
    /// ([`now_ns`](crate::now_ns), or a test clock): the datagram rate
    /// first, then the byte rate. A datagram refused on either is charged
    /// on neither. The first datagram of a source claims its cell.
    pub fn charge_rate(
        &self,
        source: SourceKey,
        bytes: u64,
        limits: RateLimits,
        now_ns: u64,
    ) -> RateVerdict {
        let increments = [
            None,
            Some(interval_ns(1, limits.datagrams_per_s)),
            Some(interval_ns(bytes, limits.bytes_per_s)),
        ];
        match self.charge(Some(source), None, increments, now_ns) {
            Ok(()) => RateVerdict::Allowed,
            Err(Refused::Cell(1)) => RateVerdict::DatagramRate,
            Err(Refused::Cell(_)) => RateVerdict::ByteRate,
            Err(Refused::Stream | Refused::TableFull) => RateVerdict::TableFull,
        }
    }

    /// Charge one opening (a TCP connection, a UDP session) at `now_ns`:
    /// the stream's open rate first, then `source`'s. An opening refused
    /// on either is charged on neither. `None` for the source charges the
    /// stream alone, as at the accept of a trusted PROXY peer (Story 12.6
    /// D-b); a source is charged, and claims its cell, only when the
    /// stream's rate passed it and `limits` names a source rate.
    pub fn charge_open(
        &self,
        source: Option<SourceKey>,
        limits: OpenLimits,
        now_ns: u64,
    ) -> OpenVerdict {
        let increments = [limits.source_per_s.map(|r| interval_ns(1, r)), None, None];
        let stream = limits.stream_per_s.map(|r| interval_ns(1, r));
        match self.charge(source, stream, increments, now_ns) {
            Ok(()) => OpenVerdict::Allowed,
            Err(Refused::Stream) => OpenVerdict::OpenRate,
            Err(Refused::Cell(_)) => OpenVerdict::SourceOpenRate,
            Err(Refused::TableFull) => OpenVerdict::TableFull,
        }
    }

    /// Charge the first datagram of a new UDP session, `bytes` long, from
    /// `source` at `now_ns`: the stream's open rate, the source's open
    /// rate, then its datagram and byte rates, in one sequence (Story
    /// 12.6 D-g). A datagram refused on any is charged on none.
    pub fn charge_new_session(
        &self,
        source: SourceKey,
        bytes: u64,
        rates: RateLimits,
        open: OpenLimits,
        now_ns: u64,
    ) -> NewSessionVerdict {
        let increments = [
            open.source_per_s.map(|r| interval_ns(1, r)),
            Some(interval_ns(1, rates.datagrams_per_s)),
            Some(interval_ns(bytes, rates.bytes_per_s)),
        ];
        let stream = open.stream_per_s.map(|r| interval_ns(1, r));
        match self.charge(Some(source), stream, increments, now_ns) {
            Ok(()) => NewSessionVerdict::Allowed,
            Err(Refused::Stream) => NewSessionVerdict::OpenRate,
            Err(Refused::Cell(0)) => NewSessionVerdict::SourceOpenRate,
            Err(Refused::Cell(1)) => NewSessionVerdict::DatagramRate,
            Err(Refused::Cell(_)) => NewSessionVerdict::ByteRate,
            Err(Refused::TableFull) => NewSessionVerdict::TableFull,
        }
    }

    /// Release everything a dead worker held: its source and backend
    /// shards are emptied, and its attributions are subtracted from the
    /// stream total and the pending total. Only for a slot whose worker
    /// is gone and not yet replaced: nobody else ever writes those
    /// shards. Returns the connections or sessions released, pending ones
    /// included, `None` for no such slot.
    pub fn release_worker(&self, slot: u32) -> Option<u64> {
        let shard = self.source_shard(slot)?;
        for cell in shard {
            cell.pending.store(0, Ordering::Release);
            cell.active.store(0, Ordering::Release);
            cell.key.store(0, Ordering::Release);
        }
        for cell in self.backend_shard(slot)? {
            cell.active.store(0, Ordering::Release);
            cell.key.store(0, Ordering::Release);
        }
        let pendings = self.pendings();
        let pending = pendings[1 + slot as usize].swap(0, Ordering::AcqRel);
        saturating_sub(&pendings[0], pending);
        let totals = self.totals();
        let released = totals[1 + slot as usize].swap(0, Ordering::AcqRel);
        saturating_sub(&totals[0], released);
        Some(released)
    }

    /// Release every rate cell whose three arrival times are past (its
    /// buckets are full again, nothing to remember), not claimed or
    /// charged in the last [`RATE_CELL_GRACE_NS`], and whose source holds
    /// nothing in any shard. Shard cells are never touched.
    pub fn evict_rates(&self, now_ns: u64) -> RateEvictionStats {
        let mut stats = RateEvictionStats::default();
        for cell in self.rate_cells() {
            let key = cell.key.load(Ordering::Acquire);
            if key == 0 {
                continue;
            }
            stats.occupied += 1;
            let refilled = [&cell.datagram_tat, &cell.byte_tat, &cell.open_tat]
                .iter()
                .all(|tat| tat.load(Ordering::Acquire) <= now_ns);
            let settled = now_ns.saturating_sub(cell.last_seen_ns.load(Ordering::Acquire))
                >= RATE_CELL_GRACE_NS;
            if !refilled || !settled {
                continue;
            }
            if self.is_held(key) {
                stats.held += 1;
                continue;
            }
            if cell
                .key
                .compare_exchange(key, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                stats.evicted += 1;
            }
        }
        stats
    }

    /// The stream increment first, then the source cell's increments in
    /// [`CELL_TATS`] order; the first refusal takes back everything
    /// charged before it. The cell is looked up (and claimed) only once
    /// the stream increment passed and at least one cell increment is
    /// asked for.
    fn charge(
        &self,
        source: Option<SourceKey>,
        stream: Option<u64>,
        increments: [Option<u64>; CELL_TATS],
        now_ns: u64,
    ) -> Result<(), Refused> {
        let stream_tat = &self.stream_rate().open_tat;
        if let Some(increment) = stream {
            if !advance(stream_tat, now_ns, increment) {
                return Err(Refused::Stream);
            }
        }
        let take_back_stream = || {
            if let Some(increment) = stream {
                saturating_sub(stream_tat, increment);
            }
        };
        let Some(source) = source.filter(|_| increments.iter().any(Option::is_some)) else {
            return Ok(());
        };
        let tagged = self.tagged(source);
        for _ in 0..RATE_CELL_ATTEMPTS {
            let Some(cell) = self.rate_cell(tagged, now_ns) else {
                break;
            };
            match charge_cell(cell, tagged, increments, now_ns) {
                CellCharge::Charged => return Ok(()),
                CellCharge::Refused(index) => {
                    take_back_stream();
                    return Err(Refused::Cell(index));
                }
                CellCharge::Moved => continue,
            }
        }
        take_back_stream();
        Err(Refused::TableFull)
    }

    fn tagged(&self, source: SourceKey) -> u64 {
        tagged_hash(match source {
            SourceKey::V4(v4) => siphash13_u64(self.hash_key, u64::from(v4)),
            SourceKey::V6Prefix(prefix) => {
                siphash13_u64([self.hash_key[0] ^ V6_KEY_DOMAIN, self.hash_key[1]], prefix)
            }
        })
    }

    fn tagged_backend(&self, backend: BackendKey) -> u64 {
        tagged_hash(siphash13_u64(self.hash_key, backend.0))
    }

    fn totals(&self) -> &[AtomicU64] {
        // SAFETY: the totals part lies inside the mapping at a 64-byte
        // aligned offset and holds `workers + 1` counters; zeroed bytes
        // are valid atomics.
        unsafe {
            std::slice::from_raw_parts(
                self.base
                    .as_ptr()
                    .add(self.layout.totals_offset)
                    .cast::<AtomicU64>(),
                self.layout.workers as usize + 1,
            )
        }
    }

    fn pendings(&self) -> &[AtomicU64] {
        // SAFETY: as `totals`, for the pending part at `pending_offset`.
        unsafe {
            std::slice::from_raw_parts(
                self.base
                    .as_ptr()
                    .add(self.layout.pending_offset)
                    .cast::<AtomicU64>(),
                self.layout.workers as usize + 1,
            )
        }
    }

    fn stream_rate(&self) -> &StreamRate {
        // SAFETY: the stream rate part is one 64-byte aligned
        // `StreamRate` inside the mapping; zeroed bytes are valid atomics.
        unsafe {
            &*self
                .base
                .as_ptr()
                .add(self.layout.stream_rate_offset)
                .cast::<StreamRate>()
        }
    }

    fn rate_cells(&self) -> &[RateCell] {
        // SAFETY: `rate_slots` cells at the 64-byte aligned `rate_offset`,
        // inside the mapping; zeroed bytes are valid atomics.
        unsafe {
            std::slice::from_raw_parts(
                self.base
                    .as_ptr()
                    .add(self.layout.rate_offset)
                    .cast::<RateCell>(),
                self.layout.rate_slots as usize,
            )
        }
    }

    fn source_shard(&self, slot: u32) -> Option<&[SourceCell]> {
        if slot >= self.layout.workers {
            return None;
        }
        let cells = self.layout.shard_slots as usize;
        let offset =
            self.layout.shards_offset + slot as usize * cells * std::mem::size_of::<SourceCell>();
        // SAFETY: the `slot`-th of `workers` shards of `shard_slots`
        // cells from the 64-byte aligned `shards_offset`, `slot` checked
        // above; zeroed bytes are valid atomics.
        Some(unsafe {
            std::slice::from_raw_parts(self.base.as_ptr().add(offset).cast::<SourceCell>(), cells)
        })
    }

    fn backend_shard(&self, slot: u32) -> Option<&[BackendCell]> {
        if slot >= self.layout.workers {
            return None;
        }
        let cells = self.layout.backend_slots as usize;
        let offset = self.layout.backends_offset
            + slot as usize * cells * std::mem::size_of::<BackendCell>();
        // SAFETY: as `source_shard`, for the backend shards from
        // `backends_offset`.
        Some(unsafe {
            std::slice::from_raw_parts(self.base.as_ptr().add(offset).cast::<BackendCell>(), cells)
        })
    }

    fn source_shards(&self) -> impl Iterator<Item = &[SourceCell]> {
        (0..self.layout.workers).filter_map(|slot| self.source_shard(slot))
    }

    fn backend_shards(&self) -> impl Iterator<Item = &[BackendCell]> {
        (0..self.layout.workers).filter_map(|slot| self.backend_shard(slot))
    }

    fn is_held(&self, tagged: u64) -> bool {
        self.source_shards()
            .any(|shard| holding(shard, tagged).next().is_some())
    }

    /// The source's rate cell, claimed on first use; `None` when its
    /// window is full of other sources.
    fn rate_cell(&self, tagged: u64, now_ns: u64) -> Option<&RateCell> {
        let cells = self.rate_cells();
        if let Some(cell) = holding(cells, tagged).next() {
            return Some(cell);
        }
        for cell in window(cells, tagged) {
            let mut current = cell.key.load(Ordering::Acquire);
            if current == 0 {
                // Stamped before the claim so an eviction pass that sees
                // the new key also sees a fresh stamp. A released cell
                // keeps arrival times in the past, which reads as a full
                // bucket: the state a new source starts in.
                cell.last_seen_ns.store(now_ns, Ordering::Release);
                match cell
                    .key
                    .compare_exchange(0, tagged, Ordering::AcqRel, Ordering::Acquire)
                {
                    Ok(_) => return Some(cell),
                    Err(claimed) => current = claimed,
                }
            }
            if current == tagged {
                return Some(cell);
            }
        }
        None
    }
}

/// Charge `increments` to `cell`, found holding `tagged`, in
/// [`CELL_TATS`] order. The first refusal takes back what was charged
/// before it. Once everything is charged, the key is read again: eviction
/// may have freed the cell after it was found and another source claimed
/// it, in which case the charges landed on that source and are taken
/// back.
fn charge_cell(
    cell: &RateCell,
    tagged: u64,
    increments: [Option<u64>; CELL_TATS],
    now_ns: u64,
) -> CellCharge {
    let tats = [&cell.open_tat, &cell.datagram_tat, &cell.byte_tat];
    cell.last_seen_ns.store(now_ns, Ordering::Release);
    let take_back = |upto: usize| {
        for (tat, increment) in tats.iter().zip(increments).take(upto) {
            if let Some(increment) = increment {
                // Our own advance put the arrival time at least
                // `increment` past `now_ns`, and every other charge only
                // moves it further before taking its own share back.
                saturating_sub(tat, increment);
            }
        }
    };
    for (index, (tat, increment)) in tats.iter().zip(increments).enumerate() {
        if let Some(increment) = increment {
            if !advance(tat, now_ns, increment) {
                take_back(index);
                return CellCharge::Refused(index);
            }
        }
    }
    if cell.key.load(Ordering::Acquire) != tagged {
        take_back(CELL_TATS);
        return CellCharge::Moved;
    }
    CellCharge::Charged
}

/// Worker `slot`'s access to a region: the one through which it admits,
/// into its own shards.
#[derive(Debug, Clone)]
pub struct WorkerCaps {
    region: Arc<StreamCapsRegion>,
    slot: u32,
}

impl WorkerCaps {
    /// The region.
    pub fn region(&self) -> &Arc<StreamCapsRegion> {
        &self.region
    }

    /// The worker's slot.
    pub fn slot(&self) -> u32 {
        self.slot
    }

    /// The stream part of an admission (Story 12.6 D-e): the stream total,
    /// exact against `stream_cap`, then, when the connection starts with
    /// phase 2 work (`pending`), the pending total, exact against
    /// `pending_cap`. A pending refusal undoes the stream count. The
    /// source part follows through [`StreamPermit::admit_source`] once
    /// the source is known. The permit gives everything back when
    /// dropped.
    ///
    /// # Errors
    ///
    /// [`AdmitRefusal::StreamCap`] or [`AdmitRefusal::PendingCap`],
    /// with nothing counted.
    pub fn admit_stream(
        &self,
        stream_cap: u64,
        pending: bool,
        pending_cap: u64,
    ) -> Result<StreamPermit, AdmitRefusal> {
        let region = &self.region;
        let slot = 1 + self.slot as usize;
        let totals = region.totals();
        if !add_within(&totals[0], stream_cap) {
            return Err(AdmitRefusal::StreamCap);
        }
        // Attributed after the total: a worker that dies in between
        // leaves the total one too high, never too low.
        totals[slot].fetch_add(1, Ordering::AcqRel);
        if pending {
            let pendings = region.pendings();
            if !add_within(&pendings[0], pending_cap) {
                saturating_sub(&totals[slot], 1);
                saturating_sub(&totals[0], 1);
                return Err(AdmitRefusal::PendingCap);
            }
            pendings[slot].fetch_add(1, Ordering::AcqRel);
        }
        Ok(StreamPermit {
            region: Arc::clone(region),
            slot: self.slot,
            pending,
            source_cell: None,
        })
    }

    /// Claim one connection or session to `backend` against `cap`, the
    /// link's `max_active`: the backend's count summed over every shard,
    /// then a cell in this worker's backend shard. `None` when the
    /// backend holds its cap, or, past half load (which a link count
    /// sized region never reaches), when its window in this worker's
    /// shard is full. The slot gives the count back when dropped.
    pub fn claim_backend(&self, backend: BackendKey, cap: u64) -> Option<BackendSlot> {
        let region = &self.region;
        if region.backend_active(backend) >= cap {
            return None;
        }
        let shard = region.backend_shard(self.slot)?;
        let cell = shard_claim(shard, region.tagged_backend(backend), |_| {})?;
        Some(BackendSlot {
            region: Arc::clone(region),
            slot: self.slot,
            cell,
        })
    }
}

/// One admitted connection's or session's counts, released when dropped:
/// its source cell (the cell is freed when its count reaches 0), its
/// pending attribution and pending total if still pending, then its
/// attribution and the stream total. An owned value, so a session can be
/// re-admitted in another region before this one is dropped.
#[derive(Debug)]
pub struct StreamPermit {
    region: Arc<StreamCapsRegion>,
    slot: u32,
    pending: bool,
    source_cell: Option<usize>,
}

impl StreamPermit {
    /// The region the admission is counted in.
    pub fn region(&self) -> &Arc<StreamCapsRegion> {
        &self.region
    }

    /// The worker slot it is counted under.
    pub fn slot(&self) -> u32 {
        self.slot
    }

    /// Whether the admission still holds a pending slot.
    pub fn is_pending(&self) -> bool {
        self.pending
    }

    /// Whether the source part was admitted.
    pub fn has_source(&self) -> bool {
        self.source_cell.is_some()
    }

    /// The source part of an admission (Story 12.6 D-e), once per permit:
    /// `source`'s count summed over every shard against `source_cap`,
    /// then, while the permit is pending, its pending count against
    /// `source_pending_cap`, then a cell in this worker's shard. On a
    /// trusted PROXY path it runs on the carried client once the header
    /// is read; otherwise right after [`WorkerCaps::admit_stream`].
    ///
    /// # Errors
    ///
    /// [`AdmitRefusal::SourceCap`], [`AdmitRefusal::SourcePendingCap`]
    /// or [`AdmitRefusal::TableFull`]. The permit is consumed, so the
    /// stream part it counted is given back with it: a refusal leaves
    /// nothing counted.
    pub fn admit_source(
        mut self,
        source: SourceKey,
        source_cap: u64,
        source_pending_cap: u64,
    ) -> Result<StreamPermit, AdmitRefusal> {
        debug_assert!(self.source_cell.is_none(), "a source is admitted once");
        let region = &self.region;
        let tagged = region.tagged(source);
        let Some(shard) = region.source_shard(self.slot) else {
            return Err(AdmitRefusal::TableFull);
        };
        let held = |field: fn(&SourceCell) -> &AtomicU64| -> u64 {
            region
                .source_shards()
                .map(|shard| shard_count(shard, tagged, field))
                .sum()
        };
        if held(|c| &c.active) >= source_cap {
            return Err(AdmitRefusal::SourceCap);
        }
        if self.pending && held(|c| &c.pending) >= source_pending_cap {
            return Err(AdmitRefusal::SourcePendingCap);
        }
        let pending = self.pending;
        let fresh = |cell: &SourceCell| cell.pending.store(u64::from(pending), Ordering::Release);
        let Some((cell, joined)) = shard_claim_with(shard, tagged, fresh) else {
            return Err(AdmitRefusal::TableFull);
        };
        if joined && pending {
            // The cell is ours while our active count is in it, so this
            // add cannot land on another source.
            shard[cell].pending.fetch_add(1, Ordering::AcqRel);
        }
        self.source_cell = Some(cell);
        Ok(self)
    }

    /// Phase 2 is over (the backend is chosen): give back the pending
    /// slot, on the stream and on the source. A no-op on a permit that
    /// holds none, so a drain or a timeout may call it after the success
    /// path did.
    pub fn end_pending(&mut self) {
        if !std::mem::take(&mut self.pending) {
            return;
        }
        if let Some(cell) = self.source_cell_ref() {
            saturating_sub(&cell.pending, 1);
        }
        let pendings = self.region.pendings();
        // Attribution before the total, as for the stream total.
        saturating_sub(&pendings[1 + self.slot as usize], 1);
        saturating_sub(&pendings[0], 1);
    }

    fn source_cell_ref(&self) -> Option<&SourceCell> {
        let index = self.source_cell?;
        self.region
            .source_shard(self.slot)
            .and_then(|shard| shard.get(index))
    }
}

impl Drop for StreamPermit {
    fn drop(&mut self) {
        // Pending first: a source cell's pending count is never above its
        // active one, and the active release may free the cell.
        self.end_pending();
        if let Some(cell) = self.source_cell_ref() {
            shard_release(cell);
        }
        let totals = self.region.totals();
        // Attribution before the total: a worker that dies in between
        // leaves the total one too high, never too low.
        saturating_sub(&totals[1 + self.slot as usize], 1);
        saturating_sub(&totals[0], 1);
    }
}

/// One connection's or session's claim on a backend, released when
/// dropped.
#[derive(Debug)]
pub struct BackendSlot {
    region: Arc<StreamCapsRegion>,
    slot: u32,
    cell: usize,
}

impl BackendSlot {
    /// The region the claim is counted in.
    pub fn region(&self) -> &Arc<StreamCapsRegion> {
        &self.region
    }
}

impl Drop for BackendSlot {
    fn drop(&mut self) {
        if let Some(cell) = self
            .region
            .backend_shard(self.slot)
            .and_then(|shard| shard.get(self.cell))
        {
            shard_release(cell);
        }
    }
}

/// Add 1 to `counter` unless that passes `cap`; exact under any number
/// of writers, since an add that passes is taken back before it is seen
/// as admitted.
fn add_within(counter: &AtomicU64, cap: u64) -> bool {
    if counter.fetch_add(1, Ordering::AcqRel) >= cap {
        saturating_sub(counter, 1);
        return false;
    }
    true
}

/// Subtract without wrapping: a counter a dead worker's release already
/// lowered never goes below zero.
fn saturating_sub(counter: &AtomicU64, by: u64) {
    let _ = counter.try_update(Ordering::AcqRel, Ordering::Acquire, |v| {
        Some(v.saturating_sub(by))
    });
}

/// Nanoseconds `units` take at `per_second`, rounded up, so a rate is
/// never exceeded by rounding. A rate of 0 is read as 1.
fn interval_ns(units: u64, per_second: u64) -> u64 {
    let per_second = u128::from(per_second.max(1));
    let ns = (u128::from(units) * 1_000_000_000).div_ceil(per_second);
    u64::try_from(ns).unwrap_or(u64::MAX)
}

/// GCRA: move the theoretical arrival time `tat` by `increment` from
/// `max(tat, now)` if the result stays within [`RATE_BURST_NS`] of
/// `now`; otherwise leave it and refuse.
fn advance(tat: &AtomicU64, now_ns: u64, increment: u64) -> bool {
    let mut current = tat.load(Ordering::Acquire);
    loop {
        let next = current.max(now_ns).saturating_add(increment);
        if next > now_ns.saturating_add(RATE_BURST_NS) {
            return false;
        }
        match tat.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

/// A key's count in one shard, read through `field`. A cell is counted
/// only if it still holds the key after its count is read, so a cell
/// released and reclaimed for another key in between is not counted for
/// this one.
fn shard_count<C: Keyed>(shard: &[C], tagged: u64, field: fn(&C) -> &AtomicU64) -> u64 {
    holding(shard, tagged)
        .map(|cell| {
            let count = field(cell).load(Ordering::Acquire);
            if cell.key().load(Ordering::Acquire) == tagged {
                count
            } else {
                0
            }
        })
        .sum()
}

/// [`shard_claim_with`], the index alone.
fn shard_claim<C: Counted>(shard: &[C], tagged: u64, fresh: impl Fn(&C)) -> Option<usize> {
    shard_claim_with(shard, tagged, fresh).map(|(index, _)| index)
}

/// Count one more of `tagged` in `shard`: join a cell already holding it,
/// else claim a free one, setting its count to 1 and calling `fresh` on
/// it before its key is published. Returns the cell's index and whether
/// it was joined; `None` when the window is full of other keys.
///
/// A cell's count only rises from a non-zero value, and only its claimer
/// sets it from 0, before the key names it: so a cell whose count a
/// release brought to 0 is never revived, and the release that did it
/// owns the cell until it clears the key. A claim sets the count rather
/// than adjusting it, so no value read before the claim is trusted (the
/// ABA [`crate::table`] describes cannot occur). A join can still lose
/// the cell between reading its key and adding to its count, if the cell
/// is released and claimed for another key in between; [`shard_join`]
/// detects it and takes the add back. Safe with any number of writers on
/// the shard, though only its worker writes it.
fn shard_claim_with<C: Counted>(
    shard: &[C],
    tagged: u64,
    fresh: impl Fn(&C),
) -> Option<(usize, bool)> {
    for i in window_indices(shard.len(), tagged) {
        let cell = &shard[i];
        if cell.key().load(Ordering::Acquire) == tagged && shard_join(cell, tagged) {
            return Some((i, true));
        }
    }
    for i in window_indices(shard.len(), tagged) {
        let cell = &shard[i];
        if cell.key().load(Ordering::Acquire) == 0
            && cell
                .key()
                .compare_exchange(0, CLAIMING, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            cell.active().store(1, Ordering::Release);
            fresh(cell);
            // Nobody but this claimer writes a key that reads CLAIMING
            // (a dead worker's shard is cleared only once it is gone), so
            // the publish is a store.
            cell.key().store(tagged, Ordering::Release);
            return Some((i, false));
        }
    }
    None
}

/// The key word of a shard cell being claimed: even, so no tagged hash
/// equals it, and readers, joiners and claimers of every key skip the
/// cell until its counts are set and its key published. The WAF tables
/// use the same marker for the same reason ([`crate::table`]).
const CLAIMING: u64 = 2;

/// Add one to `cell`, read as holding `tagged`. `false`, with nothing
/// added, when its count is 0 (released, or being claimed) or when the
/// cell changed hands before the add: the add then sits in another key's
/// count and is taken back. An add that succeeds synchronises with the
/// store that set the count it moved, so the key read after it is the
/// one that count belongs to: while our add is in a count, that count
/// cannot reach 0, so the key cannot change before it is read.
fn shard_join<C: Counted>(cell: &C, tagged: u64) -> bool {
    let mut count = cell.active().load(Ordering::Acquire);
    while count > 0 {
        match cell.active().compare_exchange_weak(
            count,
            count + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                if cell.key().load(Ordering::Acquire) == tagged {
                    return true;
                }
                shard_release(cell);
                return false;
            }
            Err(actual) => count = actual,
        }
    }
    false
}

/// Count one less on a shard cell; the release that brings it to 0 frees
/// the cell. A cell [`StreamCapsRegion::release_worker`] already emptied
/// is left alone.
fn shard_release<C: Counted>(cell: &C) {
    let mut count = cell.active().load(Ordering::Acquire);
    loop {
        if count == 0 {
            return;
        }
        match cell.active().compare_exchange_weak(
            count,
            count - 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(actual) => count = actual,
        }
    }
    if count == 1 {
        cell.key().store(0, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A UDP session's admission: the stream part, then the source part
    /// with no pending share.
    fn session(
        caps: &WorkerCaps,
        source: SourceKey,
        source_cap: u64,
        stream_cap: u64,
    ) -> Result<StreamPermit, AdmitRefusal> {
        caps.admit_stream(stream_cap, false, 0)?
            .admit_source(source, source_cap, u64::MAX)
    }
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::AtomicBool;
    use std::sync::Barrier;
    use std::thread;

    fn region(max_admitted: u64, workers: u32) -> Arc<StreamCapsRegion> {
        Arc::new(
            StreamCapsRegion::create(max_admitted, workers, 1)
                .expect("create")
                .0,
        )
    }

    fn v4(n: u32) -> SourceKey {
        SourceKey::of(IpAddr::V4(Ipv4Addr::from(n)))
    }

    fn source_cells(n: usize) -> Vec<SourceCell> {
        (0..n)
            .map(|_| SourceCell {
                key: AtomicU64::new(0),
                active: AtomicU64::new(0),
                pending: AtomicU64::new(0),
                _pad: 0,
            })
            .collect()
    }

    const SECOND: u64 = 1_000_000_000;

    #[test]
    fn layout_matches_the_documented_figures() {
        let kib = 1024;
        let mib = 1024 * kib;
        // UDP at its default: 4,096 sessions, 8 workers.
        let udp = layout_for(4096, 8).unwrap();
        assert_eq!(udp.rate_table_bytes(), mib);
        assert_eq!(udp.shard_bytes(), 2 * mib);
        // TCP at its default (Story 12.6 D-e): 1,024 connections, 8
        // workers.
        let tcp = layout_with_links(1024, 8, 4).unwrap();
        assert_eq!(tcp.rate_table_bytes(), 256 * kib);
        assert_eq!(tcp.shard_bytes(), 512 * kib);
        assert_eq!(tcp.backend_slots, MIN_BACKEND_SLOTS);
        assert_eq!(tcp.backend_bytes(), 8 * 32 * 16);
        let large = layout_for(28_000, 64).unwrap();
        assert_eq!(large.rate_table_bytes(), 8 * mib);
        assert_eq!(large.shard_bytes(), 128 * mib);
        let tiny = layout_for(1, 1).unwrap();
        assert_eq!(tiny.rate_slots, MIN_RATE_SLOTS);
        assert_eq!(tiny.shard_slots, MIN_SHARD_SLOTS);
        assert_eq!(tiny.backend_slots, MIN_BACKEND_SLOTS);
        // A link count past half the floor doubles the backend shards.
        assert_eq!(layout_with_links(1, 1, 17).unwrap().backend_slots, 64);
        assert_eq!(layout_with_links(1, 1, 16).unwrap().backend_slots, 32);
        for layout in [udp, tcp, large, tiny] {
            let part = (8 * (layout.workers as usize + 1)).next_multiple_of(64);
            assert_eq!(layout.totals_offset, 64);
            assert_eq!(layout.pending_offset, layout.totals_offset + part);
            assert_eq!(layout.stream_rate_offset, layout.pending_offset + part);
            assert_eq!(layout.rate_offset, layout.stream_rate_offset + 64);
            for offset in [layout.shards_offset, layout.backends_offset] {
                assert_eq!(offset % 64, 0);
            }
        }
        assert!(matches!(
            layout_for(0, 8),
            Err(StreamCapsError::BadShape { .. })
        ));
        assert!(matches!(
            layout_for(16, 0),
            Err(StreamCapsError::BadShape { .. })
        ));
        assert!(matches!(
            layout_for(u64::MAX, 8),
            Err(StreamCapsError::TooLarge)
        ));
        assert!(matches!(
            layout_with_links(16, 8, u64::MAX),
            Err(StreamCapsError::TooLarge)
        ));
    }

    #[test]
    fn a_created_region_reopens_with_its_header() {
        let (created, fd) = StreamCapsRegion::create_with_links(4096, 4, 40, 7).unwrap();
        let opened = StreamCapsRegion::open(fd).unwrap();
        assert_eq!(opened.layout(), created.layout());
        assert_eq!(opened.layout().backend_slots, 128);
        assert_eq!(opened.caps_gen(), 7);
        assert_eq!(opened.hash_key, created.hash_key);
        assert_ne!(created.hash_key, [0, 0]);
    }

    #[test]
    fn source_keys_canonicalise_and_key_ipv6_on_its_64() {
        let mapped: IpAddr = "::ffff:192.0.2.10".parse().unwrap();
        assert_eq!(
            SourceKey::of(mapped),
            SourceKey::of("192.0.2.10".parse().unwrap())
        );
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(SourceKey::of(a), SourceKey::of(b));
        assert_ne!(SourceKey::of(a), SourceKey::of(other));
        // An IPv4 address and an IPv6 prefix of the same value hash apart.
        let r = region(16, 1);
        let same_value = SourceKey::V6Prefix(u64::from(u32::from(Ipv4Addr::new(192, 0, 2, 10))));
        assert_ne!(
            r.tagged(SourceKey::of("192.0.2.10".parse().unwrap())),
            r.tagged(same_value)
        );
        assert_eq!(
            SourceKey::of(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            SourceKey::V6Prefix(0)
        );
    }

    #[test]
    fn backend_keys_are_stable_and_distinct() {
        assert_eq!(BackendKey::of("backend-a"), BackendKey::of("backend-a"));
        assert_ne!(BackendKey::of("backend-a"), BackendKey::of("backend-b"));
        // FNV-1a's published value for the empty input and for "a".
        assert_eq!(BackendKey::of(""), BackendKey(0xcbf2_9ce4_8422_2325));
        assert_eq!(BackendKey::of("a"), BackendKey(0xaf63_dc4c_8601_ec8c));
    }

    #[test]
    fn the_stream_and_pending_totals_are_exact_under_eight_threads() {
        const WORKERS: u32 = 8;
        const CAP: u64 = 1000;
        const PENDING_CAP: u64 = 300;
        let r = region(CAP, WORKERS);
        let start = Arc::new(Barrier::new(WORKERS as usize));
        let threads: Vec<_> = (0..WORKERS)
            .map(|slot| {
                let caps = r.worker(slot).unwrap();
                let start = Arc::clone(&start);
                thread::spawn(move || {
                    start.wait();
                    let mut permits = Vec::new();
                    // Distinct sources, so only the stream caps bind;
                    // every other admission asks for a pending slot.
                    for n in 0..CAP as u32 {
                        let pending = n % 2 == 0;
                        match caps.admit_stream(CAP, pending, PENDING_CAP) {
                            Ok(p) => {
                                let p = p
                                    .admit_source(v4(slot * 100_000 + n), u64::MAX, u64::MAX)
                                    .unwrap();
                                permits.push(p);
                            }
                            Err(AdmitRefusal::PendingCap | AdmitRefusal::StreamCap) => {}
                            Err(other) => panic!("{other:?}"),
                        }
                    }
                    permits
                })
            })
            .collect();
        let held: Vec<Vec<StreamPermit>> = threads.into_iter().map(|h| h.join().unwrap()).collect();
        let admitted: u64 = held.iter().map(|p| p.len() as u64).sum();
        let pending: u64 = held
            .iter()
            .map(|p| p.iter().filter(|p| p.is_pending()).count() as u64)
            .sum();
        assert_eq!(pending, PENDING_CAP, "the pending cap is reached exactly");
        assert_eq!(r.pending(), PENDING_CAP);
        assert_eq!(admitted, CAP);
        assert_eq!(r.total(), CAP);
        for (slot, permits) in held.iter().enumerate() {
            let slot = slot as u32;
            assert_eq!(r.worker_sessions(slot), Some(permits.len() as u64));
            let mine = permits.iter().filter(|p| p.is_pending()).count() as u64;
            assert_eq!(r.worker_pending(slot), Some(mine));
        }
        drop(held);
        assert_eq!((r.total(), r.pending()), (0, 0));
        assert!((0..WORKERS)
            .all(|slot| r.worker_sessions(slot) == Some(0) && r.worker_pending(slot) == Some(0)));
    }

    /// W threads, one per worker slot, admit one key until refused; the
    /// node may hold at most `cap + (W - 1)`, one worker never more than
    /// `cap`.
    fn overshoot_rounds(
        admit: impl Fn(&WorkerCaps) -> Option<Box<dyn Send>> + Send + Sync + 'static,
    ) {
        const WORKERS: u32 = 8;
        let admit = Arc::new(admit);
        for _round in 0..50 {
            let r = region(4096, WORKERS);
            let start = Arc::new(Barrier::new(WORKERS as usize));
            let threads: Vec<_> = (0..WORKERS)
                .map(|slot| {
                    let caps = r.worker(slot).unwrap();
                    let start = Arc::clone(&start);
                    let admit = Arc::clone(&admit);
                    thread::spawn(move || {
                        start.wait();
                        let mut held = Vec::new();
                        while let Some(p) = admit(&caps) {
                            held.push(p);
                        }
                        held
                    })
                })
                .collect();
            let held: Vec<_> = threads.into_iter().map(|h| h.join().unwrap()).collect();
            let total: u64 = held.iter().map(|p| p.len() as u64).sum();
            assert!(total >= CAP_UNDER_TEST, "{total}");
            assert!(total < CAP_UNDER_TEST + u64::from(WORKERS), "{total}");
            assert!(held.iter().all(|p| p.len() as u64 <= CAP_UNDER_TEST));
        }
    }

    const CAP_UNDER_TEST: u64 = 4;

    #[test]
    fn one_source_overshoots_its_cap_by_at_most_workers_minus_one() {
        let source = v4(0xC000_0201);
        overshoot_rounds(move |caps| {
            let permit = caps
                .admit_stream(4096, false, 0)
                .ok()?
                .admit_source(source, CAP_UNDER_TEST, u64::MAX)
                .ok()?;
            Some(Box::new(permit))
        });
    }

    #[test]
    fn one_source_overshoots_its_pending_share_by_at_most_workers_minus_one() {
        let source = v4(0xC000_0202);
        overshoot_rounds(move |caps| {
            let permit = caps
                .admit_stream(4096, true, 4096)
                .ok()?
                .admit_source(source, u64::MAX, CAP_UNDER_TEST)
                .ok()?;
            Some(Box::new(permit))
        });
    }

    #[test]
    fn one_backend_overshoots_its_cap_by_at_most_workers_minus_one() {
        let backend = BackendKey::of("backend-1");
        overshoot_rounds(move |caps| {
            let slot = caps.claim_backend(backend, CAP_UNDER_TEST)?;
            Some(Box::new(slot))
        });
    }

    #[test]
    fn each_refusal_undoes_everything_counted_before_it() {
        let r = region(4, 1);
        let caps = r.worker(0).unwrap();
        let a = caps
            .admit_stream(3, true, 2)
            .unwrap()
            .admit_source(v4(1), 2, 1)
            .unwrap();
        // The source's pending share is 1 and it holds it.
        assert_eq!(
            caps.admit_stream(3, true, 2)
                .unwrap()
                .admit_source(v4(1), 2, 1)
                .unwrap_err(),
            AdmitRefusal::SourcePendingCap
        );
        assert_eq!((r.total(), r.pending()), (1, 1));
        // Not pending, it may hold a second connection, not a third.
        let b = caps
            .admit_stream(3, false, 2)
            .unwrap()
            .admit_source(v4(1), 2, 1)
            .unwrap();
        assert_eq!(
            caps.admit_stream(3, false, 2)
                .unwrap()
                .admit_source(v4(1), 2, 1)
                .unwrap_err(),
            AdmitRefusal::SourceCap
        );
        assert_eq!((r.total(), r.pending()), (2, 1));
        assert_eq!((r.source_sessions(v4(1)), r.source_pending(v4(1))), (2, 1));
        let c = caps
            .admit_stream(3, true, 2)
            .unwrap()
            .admit_source(v4(2), 2, 1)
            .unwrap();
        assert_eq!(
            caps.admit_stream(3, true, 2).unwrap_err(),
            AdmitRefusal::StreamCap
        );
        drop(b);
        assert_eq!(
            caps.admit_stream(3, true, 2).unwrap_err(),
            AdmitRefusal::PendingCap,
            "the pending total is at its cap of 2"
        );
        assert_eq!((r.total(), r.pending()), (2, 2));
        assert_eq!(r.worker_sessions(0), Some(2));
        assert_eq!(r.worker_pending(0), Some(2));
        drop((a, c));
        assert_eq!((r.total(), r.pending()), (0, 0));
        assert_eq!(r.source_sessions(v4(1)), 0);
        assert!(r.worker(1).is_none());
    }

    #[test]
    fn end_pending_gives_back_the_stream_and_source_pending_once() {
        let r = region(16, 2);
        let caps = r.worker(1).unwrap();
        let mut permit = caps
            .admit_stream(16, true, 1)
            .unwrap()
            .admit_source(v4(3), 8, 1)
            .unwrap();
        assert!(permit.is_pending() && permit.has_source());
        assert_eq!((r.pending(), r.source_pending(v4(3))), (1, 1));
        assert_eq!(
            caps.admit_stream(16, true, 1).unwrap_err(),
            AdmitRefusal::PendingCap
        );
        permit.end_pending();
        permit.end_pending();
        assert!(!permit.is_pending());
        assert_eq!((r.pending(), r.source_pending(v4(3))), (0, 0));
        assert_eq!(r.worker_pending(1), Some(0));
        assert_eq!((r.total(), r.source_sessions(v4(3))), (1, 1));
        // The pending slot is free for another connection.
        let other = caps.admit_stream(16, true, 1).unwrap();
        drop(permit);
        assert_eq!((r.total(), r.pending()), (1, 1));
        drop(other);
        assert_eq!((r.total(), r.pending()), (0, 0));
    }

    #[test]
    fn a_trusted_peer_is_admitted_on_the_stream_then_judged_on_its_client() {
        let r = region(16, 1);
        let caps = r.worker(0).unwrap();
        // Accept of a trusted PROXY peer: stream part only, the peer is
        // not a source.
        let first = caps.admit_stream(16, true, 16).unwrap();
        let second = caps.admit_stream(16, true, 16).unwrap();
        let peer = v4(0x0A00_0001);
        assert_eq!(r.source_sessions(peer), 0);
        assert_eq!((r.total(), r.pending()), (2, 2));
        // The headers carry two clients; the second is the first's source
        // again and finds it at its cap of 1.
        let client = v4(0xC633_6401);
        let first = first.admit_source(client, 1, 1).unwrap();
        assert_eq!(
            second.admit_source(client, 1, 1).unwrap_err(),
            AdmitRefusal::SourceCap
        );
        assert_eq!((r.total(), r.pending()), (1, 1));
        assert_eq!(
            (r.source_sessions(client), r.source_pending(client)),
            (1, 1)
        );
        drop(first);
        assert_eq!((r.total(), r.pending()), (0, 0));
    }

    #[test]
    fn backend_claims_count_per_backend_and_free_on_drop() {
        let r = region(16, 2);
        let a = BackendKey::of("a");
        let b = BackendKey::of("b");
        let w0 = r.worker(0).unwrap();
        let w1 = r.worker(1).unwrap();
        let first = w0.claim_backend(a, 2).unwrap();
        let second = w1.claim_backend(a, 2).unwrap();
        assert!(w0.claim_backend(a, 2).is_none(), "a is at its cap");
        let other = w0.claim_backend(b, 2).unwrap();
        assert_eq!((r.backend_active(a), r.backend_active(b)), (2, 1));
        drop(second);
        let again = w0.claim_backend(a, 2).unwrap();
        assert_eq!(r.backend_active(a), 2);
        drop((first, again, other));
        assert_eq!((r.backend_active(a), r.backend_active(b)), (0, 0));
        assert!(r
            .backend_shards()
            .flatten()
            .all(|c| c.key.load(Ordering::Acquire) == 0));
    }

    #[test]
    fn a_held_source_keeps_its_rate_cell_however_old() {
        let r = region(16, 2);
        let limits = RateLimits {
            datagrams_per_s: 10,
            bytes_per_s: 1_000_000,
        };
        let source = v4(7);
        assert_eq!(
            r.charge_rate(source, 100, limits, SECOND),
            RateVerdict::Allowed
        );
        let permit = session(&r.worker(1).unwrap(), source, 8, 16).unwrap();
        for now in [10 * SECOND, u64::MAX / 2, u64::MAX] {
            let stats = r.evict_rates(now);
            assert_eq!((stats.evicted, stats.held), (0, 1), "at {now}");
        }
        drop(permit);
        assert_eq!(r.evict_rates(10 * SECOND).evicted, 1);
        assert_eq!(r.evict_rates(10 * SECOND).occupied, 0);
    }

    #[test]
    fn eviction_waits_for_a_full_bucket_and_the_grace() {
        let r = region(16, 1);
        let limits = RateLimits {
            datagrams_per_s: 1,
            bytes_per_s: 1_000_000,
        };
        let source = v4(9);
        assert_eq!(
            r.charge_rate(source, 10, limits, SECOND),
            RateVerdict::Allowed
        );
        // The datagram arrival time is one interval ahead: not refilled.
        assert_eq!(r.evict_rates(SECOND + SECOND / 2).evicted, 0);
        assert_eq!(r.evict_rates(2 * SECOND).evicted, 1);
    }

    #[test]
    fn eviction_keeps_a_cell_whose_open_bucket_is_not_full() {
        let r = region(16, 1);
        let open = OpenLimits {
            stream_per_s: None,
            source_per_s: Some(1),
        };
        let source = v4(10);
        assert_eq!(
            r.charge_open(Some(source), open, SECOND),
            OpenVerdict::Allowed
        );
        // Past the grace, but the opening arrival time is still ahead.
        let later = SECOND + RATE_CELL_GRACE_NS;
        assert!(holding(r.rate_cells(), r.tagged(source)).next().is_some());
        assert_eq!(r.evict_rates(later - 1).evicted, 0);
        assert_eq!(r.evict_rates(later).evicted, 1);
    }

    #[test]
    fn release_worker_restores_the_totals_and_empties_its_shards() {
        let r = region(64, 3);
        let dead = r.worker(1).unwrap();
        let alive = r.worker(2).unwrap();
        let kept = session(&alive, v4(5), 8, 64).unwrap();
        let kept_backend = alive.claim_backend(BackendKey::of("x"), 8).unwrap();
        for _ in 0..3 {
            // The worker dies holding its admissions: nothing drops them.
            std::mem::forget(session(&dead, v4(5), 8, 64).unwrap());
        }
        std::mem::forget(
            dead.admit_stream(64, true, 64)
                .unwrap()
                .admit_source(v4(6), 8, 8)
                .unwrap(),
        );
        std::mem::forget(dead.admit_stream(64, true, 64).unwrap());
        std::mem::forget(dead.claim_backend(BackendKey::of("x"), 8).unwrap());
        assert_eq!((r.total(), r.pending()), (6, 2));
        assert_eq!(r.source_sessions(v4(5)), 4);
        assert_eq!(r.backend_active(BackendKey::of("x")), 2);
        assert_eq!(r.release_worker(1), Some(5));
        assert_eq!((r.total(), r.pending()), (1, 0));
        assert_eq!(r.worker_sessions(1), Some(0));
        assert_eq!(r.worker_pending(1), Some(0));
        assert_eq!(r.source_sessions(v4(5)), 1);
        assert_eq!(r.source_sessions(v4(6)), 0);
        assert_eq!(r.source_pending(v4(6)), 0);
        assert_eq!(r.backend_active(BackendKey::of("x")), 1);
        assert!(r.source_shard(1).unwrap().iter().all(|c| {
            c.key.load(Ordering::Acquire) == 0
                && c.active.load(Ordering::Acquire) == 0
                && c.pending.load(Ordering::Acquire) == 0
        }));
        assert!(r
            .backend_shard(1)
            .unwrap()
            .iter()
            .all(|c| c.key.load(Ordering::Acquire) == 0));
        drop((kept, kept_backend));
        assert_eq!(r.total(), 0);
        assert_eq!(r.backend_active(BackendKey::of("x")), 0);
        assert_eq!(r.release_worker(3), None);
    }

    #[test]
    fn gcra_admits_one_second_of_burst_then_the_rate() {
        let r = region(16, 1);
        let limits = RateLimits {
            datagrams_per_s: 10,
            bytes_per_s: 1_000_000,
        };
        let source = v4(11);
        let t0 = 5 * SECOND;
        for i in 0..10 {
            assert_eq!(
                r.charge_rate(source, 1, limits, t0),
                RateVerdict::Allowed,
                "burst datagram {i}"
            );
        }
        assert_eq!(
            r.charge_rate(source, 1, limits, t0),
            RateVerdict::DatagramRate
        );
        // One interval later, exactly one more.
        let t1 = t0 + SECOND / 10;
        assert_eq!(r.charge_rate(source, 1, limits, t1), RateVerdict::Allowed);
        assert_eq!(
            r.charge_rate(source, 1, limits, t1),
            RateVerdict::DatagramRate
        );
        // Over a further second at the rate, ten more and no eleventh.
        let mut allowed = 0;
        for step in 1..=100 {
            let now = t1 + step * SECOND / 100;
            if r.charge_rate(source, 1, limits, now) == RateVerdict::Allowed {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 10);
    }

    #[test]
    fn the_byte_rate_refuses_without_spending_a_datagram() {
        let r = region(16, 1);
        let limits = RateLimits {
            datagrams_per_s: 2,
            bytes_per_s: 1_000,
        };
        let source = v4(12);
        let t0 = SECOND;
        assert_eq!(
            r.charge_rate(source, 1_000, limits, t0),
            RateVerdict::Allowed
        );
        assert_eq!(r.charge_rate(source, 1, limits, t0), RateVerdict::ByteRate);
        // The refused datagram did not spend the second datagram token.
        let later = t0 + SECOND;
        assert_eq!(
            r.charge_rate(source, 1_000, limits, later),
            RateVerdict::Allowed
        );
        assert_eq!(
            r.charge_rate(source, 1, limits, later),
            RateVerdict::ByteRate
        );
        assert_eq!(
            r.charge_rate(source, 0, limits, later),
            RateVerdict::Allowed,
            "the datagram budget still holds one"
        );
        assert_eq!(
            r.charge_rate(source, 0, limits, later),
            RateVerdict::DatagramRate
        );
    }

    #[test]
    fn open_rates_charge_the_stream_then_the_source_and_refund_on_refusal() {
        let r = region(16, 1);
        let t0 = 3 * SECOND;
        let limits = OpenLimits {
            stream_per_s: Some(4),
            source_per_s: Some(2),
        };
        let (a, b, c) = (v4(21), v4(22), v4(23));
        assert_eq!(r.charge_open(Some(a), limits, t0), OpenVerdict::Allowed);
        assert_eq!(r.charge_open(Some(a), limits, t0), OpenVerdict::Allowed);
        // a is at its source rate; the refusal gives the stream token back.
        assert_eq!(
            r.charge_open(Some(a), limits, t0),
            OpenVerdict::SourceOpenRate
        );
        assert_eq!(r.charge_open(Some(b), limits, t0), OpenVerdict::Allowed);
        // A trusted peer's accept charges the stream alone.
        assert_eq!(r.charge_open(None, limits, t0), OpenVerdict::Allowed);
        // The stream's burst of 4 is spent: c is refused before it claims
        // a rate cell.
        assert_eq!(r.charge_open(Some(c), limits, t0), OpenVerdict::OpenRate);
        assert!(holding(r.rate_cells(), r.tagged(c)).next().is_none());
        // No rate configured charges nothing and claims nothing.
        assert_eq!(
            r.charge_open(Some(c), OpenLimits::default(), t0),
            OpenVerdict::Allowed
        );
        assert!(holding(r.rate_cells(), r.tagged(c)).next().is_none());
        // A quarter of a second later the stream admits one more.
        let t1 = t0 + SECOND / 4;
        assert_eq!(r.charge_open(Some(c), limits, t1), OpenVerdict::Allowed);
        assert_eq!(r.charge_open(Some(b), limits, t1), OpenVerdict::OpenRate);
    }

    #[test]
    fn a_new_session_charges_its_opening_and_its_datagram_together() {
        let r = region(16, 1);
        let t0 = 2 * SECOND;
        let rates = RateLimits {
            datagrams_per_s: 100,
            bytes_per_s: 1_000,
        };
        let open = OpenLimits {
            stream_per_s: None,
            source_per_s: Some(1),
        };
        let s = v4(31);
        // Over the byte rate: neither the opening nor the datagram stays
        // charged.
        assert_eq!(
            r.charge_new_session(s, 2_000, rates, open, t0),
            NewSessionVerdict::ByteRate
        );
        assert_eq!(
            r.charge_new_session(s, 10, rates, open, t0),
            NewSessionVerdict::Allowed
        );
        assert_eq!(
            r.charge_new_session(s, 10, rates, open, t0),
            NewSessionVerdict::SourceOpenRate
        );
        // The refused opening left the datagram budget whole: 99 more.
        for i in 0..99 {
            assert_eq!(
                r.charge_rate(s, 0, rates, t0),
                RateVerdict::Allowed,
                "datagram {i}"
            );
        }
        assert_eq!(r.charge_rate(s, 0, rates, t0), RateVerdict::DatagramRate);
        let stream_only = OpenLimits {
            stream_per_s: Some(1),
            source_per_s: None,
        };
        assert_eq!(
            r.charge_new_session(v4(32), 1, rates, stream_only, t0),
            NewSessionVerdict::Allowed
        );
        assert_eq!(
            r.charge_new_session(v4(33), 1, rates, stream_only, t0),
            NewSessionVerdict::OpenRate
        );
    }

    #[test]
    fn a_charge_on_a_cell_that_changed_hands_is_taken_back() {
        let r = region(16, 1);
        let a = r.tagged(v4(41));
        let b = r.tagged(v4(42));
        let cell = r.rate_cell(a, SECOND).unwrap();
        // Eviction freed the cell and b claimed it between the lookup and
        // the charge.
        cell.key.store(b, Ordering::Release);
        let before =
            [&cell.open_tat, &cell.datagram_tat, &cell.byte_tat].map(|t| t.load(Ordering::Acquire));
        let increments = [Some(SECOND / 2), Some(SECOND / 4), Some(SECOND / 8)];
        assert!(matches!(
            charge_cell(cell, a, increments, 10 * SECOND),
            CellCharge::Moved
        ));
        let after =
            [&cell.open_tat, &cell.datagram_tat, &cell.byte_tat].map(|t| t.load(Ordering::Acquire));
        // Each arrival time is back where the charge started from, the
        // `max(tat, now)` of GCRA: never ahead of where b left it.
        for (before, after) in before.iter().zip(after) {
            assert!(after <= (*before).max(10 * SECOND), "{after}");
        }
        assert!(after.iter().all(|t| *t <= 10 * SECOND));
        cell.key.store(a, Ordering::Release);
        assert!(matches!(
            charge_cell(cell, a, increments, 10 * SECOND),
            CellCharge::Charged
        ));
    }

    #[test]
    fn a_full_rate_table_refuses_new_sources_and_keeps_serving_known_ones() {
        let r = region(1, 1);
        let limits = RateLimits {
            datagrams_per_s: 1_000,
            bytes_per_s: 1_000_000,
        };
        let mut known = Vec::new();
        let mut n = 0u32;
        let first_refused = loop {
            let source = v4(n);
            match r.charge_rate(source, 1, limits, SECOND) {
                RateVerdict::Allowed => known.push(source),
                RateVerdict::TableFull => break n,
                other => panic!("{other:?}"),
            }
            n += 1;
            assert!(u64::from(n) <= MIN_RATE_SLOTS + 1, "never refused");
        };
        assert!(u64::from(first_refused) >= MAX_PROBE as u64);
        // Fill whatever windows are left, then every new source is refused.
        for m in first_refused..first_refused + 4 * MIN_RATE_SLOTS as u32 {
            if r.charge_rate(v4(m), 1, limits, SECOND) == RateVerdict::Allowed {
                known.push(v4(m));
            }
        }
        assert_eq!(known.len() as u64, MIN_RATE_SLOTS);
        assert_eq!(
            r.charge_rate(v4(u32::MAX), 1, limits, SECOND),
            RateVerdict::TableFull
        );
        let open = OpenLimits {
            stream_per_s: Some(1_000_000),
            source_per_s: Some(1_000),
        };
        assert_eq!(
            r.charge_open(Some(v4(u32::MAX)), open, SECOND),
            OpenVerdict::TableFull
        );
        for source in &known {
            assert_eq!(
                r.charge_rate(*source, 1, limits, SECOND),
                RateVerdict::Allowed
            );
        }
    }

    #[test]
    fn a_full_shard_window_is_table_full() {
        // Thirty-two keys starting at the same cell fill its window.
        let shard = source_cells(64);
        let key = |n: u64| tagged_hash((n << 6) | 0x10);
        for n in 0..MAX_PROBE as u64 {
            assert!(shard_claim(&shard, key(n), |_| {}).is_some());
        }
        assert_eq!(shard_claim(&shard, key(MAX_PROBE as u64), |_| {}), None);
        // A key already placed still counts more.
        let i = shard_claim(&shard, key(3), |_| {}).unwrap();
        assert_eq!(shard[i].active.load(Ordering::Acquire), 2);
        assert_eq!(shard_count(&shard, key(3), |c| &c.active), 2);
    }

    #[test]
    fn a_full_shard_refuses_the_admission_and_undoes_the_total() {
        let r = region(1, 1);
        let caps = r.worker(0).unwrap();
        let mut held = Vec::new();
        let refusal = loop {
            let admitted = caps
                .admit_stream(u64::MAX, true, u64::MAX)
                .unwrap()
                .admit_source(v4(held.len() as u32), 1, 1);
            match admitted {
                Ok(p) => held.push(p),
                Err(e) => break e,
            }
            assert!(held.len() as u64 <= MIN_SHARD_SLOTS, "never refused");
        };
        assert_eq!(refusal, AdmitRefusal::TableFull);
        assert_eq!(r.total(), held.len() as u64);
        assert_eq!(r.pending(), held.len() as u64);
    }

    #[test]
    fn a_released_cell_is_never_revived_and_a_count_survives_its_neighbours() {
        let r = region(16, 1);
        let caps = r.worker(0).unwrap();
        let first = session(&caps, v4(1), 8, 16).unwrap();
        let second = session(&caps, v4(1), 8, 16).unwrap();
        assert_eq!(first.source_cell, second.source_cell);
        drop(first);
        assert_eq!(r.source_sessions(v4(1)), 1);
        drop(second);
        assert_eq!(r.source_sessions(v4(1)), 0);
        assert!(!r.is_held(r.tagged(v4(1))));
    }

    #[test]
    fn a_join_that_lost_its_cell_takes_its_add_back() {
        let shard = source_cells(MAX_PROBE);
        let (k1, k2) = (tagged_hash(0x40), tagged_hash(0x80));
        let i = shard_claim(&shard, k1, |_| {}).unwrap();
        // k1's holder releases and k2 claims the same cell between a
        // joiner's key read and its add: the joiner's add lands on k2's
        // count, and it must not count it as k1's.
        shard_release(&shard[i]);
        assert_eq!(shard_claim(&shard, k2, |_| {}), Some(i));
        assert!(!shard_join(&shard[i], k1));
        assert_eq!(shard[i].active.load(Ordering::Acquire), 1);
        assert_eq!(shard[i].key.load(Ordering::Acquire), k2);
        // Whichever release brings a count to 0 frees the cell, a
        // joiner's take-back included.
        shard[i].active.fetch_add(1, Ordering::AcqRel);
        shard_release(&shard[i]);
        shard_release(&shard[i]);
        assert_eq!(shard[i].key.load(Ordering::Acquire), 0);
    }

    /// The interleaving the WAF tables lost counts to (9fc991f6), run on
    /// a shard: several writers claim and release the same few keys,
    /// whose windows all start at the same cell, so a cell one writer
    /// frees is claimed again at once for another key while a second
    /// writer is between reading its key and adding to its count. A
    /// claim must return a cell holding its own key, every key must end
    /// with exactly the claims still held on it, and the shard must end
    /// empty. Only the stream engines' tests share a shard between
    /// threads; a worker writes its own shard alone, so this is the
    /// stronger case.
    #[test]
    fn churned_shard_cells_never_count_one_key_for_another() {
        const WRITERS: usize = 4;
        const ROUNDS: usize = 20_000;
        let keys: Vec<u64> = (1..=6u64).map(|k| tagged_hash((k << 7) | 0x40)).collect();
        let shard = Arc::new(source_cells(MAX_PROBE * 2));
        let start = Arc::new(Barrier::new(WRITERS));
        let misplaced = Arc::new(AtomicBool::new(false));
        let threads: Vec<_> = (0..WRITERS)
            .map(|w| {
                let shard = Arc::clone(&shard);
                let start = Arc::clone(&start);
                let misplaced = Arc::clone(&misplaced);
                let keys = keys.clone();
                thread::spawn(move || {
                    let mut held: Vec<(u64, usize)> = Vec::new();
                    start.wait();
                    for round in 0..ROUNDS {
                        let key = keys[(round + w) % keys.len()];
                        if let Some(i) = shard_claim(&shard, key, |_| {}) {
                            // Our count is in the cell, so its key cannot
                            // change under this read.
                            if shard[i].key.load(Ordering::Acquire) != key {
                                misplaced.store(true, Ordering::Release);
                            }
                            held.push((key, i));
                        }
                        if held.len() > 2 || round % 3 == 0 {
                            let (_, i) = held.remove(0);
                            shard_release(&shard[i]);
                        }
                    }
                    held
                })
            })
            .collect();
        let held: Vec<(u64, usize)> = threads
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();
        assert!(
            !misplaced.load(Ordering::Acquire),
            "a claim returned another key's cell"
        );
        for key in &keys {
            let claims = held.iter().filter(|(k, _)| k == key).count() as u64;
            assert_eq!(shard_count(&shard, *key, |c| &c.active), claims);
        }
        for (key, i) in held {
            assert_eq!(shard[i].key.load(Ordering::Acquire), key);
            shard_release(&shard[i]);
        }
        assert!(shard.iter().all(|c| {
            c.key.load(Ordering::Acquire) == 0 && c.active.load(Ordering::Acquire) == 0
        }));
    }
}
