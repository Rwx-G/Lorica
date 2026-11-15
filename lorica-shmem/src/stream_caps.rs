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

//! The stream-caps region: per-node session caps and per-source rates of
//! one UDP stream, shared by every worker (Story 12.5 D-d).
//!
//! One anonymous memfd per stream, created by the supervisor (or the
//! single-process driver) and mapped `MAP_SHARED` by every worker. Unlike
//! [`SharedRegion`](crate::SharedRegion), it is sized at runtime from the
//! stream's `max_sessions` and the node's worker count, and a flood that
//! fills one stream's tables cannot touch another's.
//!
//! Layout (little-endian, every part 64-byte aligned):
//!
//! ```text
//!   part            content                                       size
//!   ----            -------                                       ----
//!   header          magic, layout version, workers W, hash key,   64
//!                   rate_slots, shard_slots, caps_gen
//!   totals          total, then per_worker[W]                     8 (W + 1), padded
//!   rate table      rate_slots cells: key, datagram_tat,          rate_slots x 64
//!                   byte_tat, last_seen_ns
//!   session shards  W shards of shard_slots cells: key, sessions  W x shard_slots x 16
//! ```
//!
//! What each part counts:
//!
//! - **The stream total** is exact: a session adds 1 and backs off when
//!   the result passes the cap. `per_worker[i]` attributes it, so the
//!   supervisor can subtract a dead worker's sessions.
//! - **Per-source sessions** live in per-worker shards. A worker claims
//!   and counts only in its own shard; the per-source check sums the
//!   source over every shard. Only the session that brings a cell's
//!   count to 0 releases it, and [`StreamCapsRegion::release_worker`]
//!   for a dead worker's shard: nothing else, eviction included, ever
//!   releases a shard cell, so a held concurrency slot is never evicted.
//!   Two workers admitting the same source at once can both pass the
//!   check, so a source holds at most `source_cap + (W - 1)` sessions on
//!   the node; one worker alone never passes `source_cap`.
//! - **Per-source rates** are two GCRA theoretical arrival times per
//!   source (datagrams, bytes), shared by every worker. Burst is one
//!   second of rate. [`StreamCapsRegion::evict_rates`] releases a cell
//!   whose bucket is full again and whose source holds no session.
//!
//! A full probe window refuses the new session or the new source on this
//! stream only ([`CapRefusal::TableFull`], [`RateVerdict::TableFull`]).
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
pub const STREAM_CAPS_LAYOUT_VERSION: u32 = 1;

/// Rate cells per session of `max_sessions`: sources outnumber sessions
/// (a source sends before it holds one, and a refused source still has a
/// cell), so the table holds four sources per session at most a quarter
/// full.
pub const RATE_SLOTS_PER_SESSION: u64 = 4;

/// Fewest rate cells a region holds.
pub const MIN_RATE_SLOTS: u64 = 1024;

/// Shard cells per session of `max_sessions`: one worker never holds
/// more than `max_sessions` sources, so its shard is at most half full.
pub const SHARD_SLOTS_PER_SESSION: u64 = 2;

/// Fewest cells a worker's shard holds.
pub const MIN_SHARD_SLOTS: u64 = 256;

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
}

const _: () = assert!(std::mem::size_of::<Header>() == 64);

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
    _pad: [u64; 4],
}

const _: () = assert!(std::mem::size_of::<RateCell>() == 64);

/// One source's sessions in one worker's shard.
#[repr(C, align(16))]
struct ShardCell {
    /// Tagged hash of the source key, `0` when free.
    key: AtomicU64,
    /// Sessions of the source this worker holds through this cell.
    sessions: AtomicU64,
}

const _: () = assert!(std::mem::size_of::<ShardCell>() == 16);

impl Keyed for RateCell {
    fn key(&self) -> &AtomicU64 {
        &self.key
    }
}

impl Keyed for ShardCell {
    fn key(&self) -> &AtomicU64 {
        &self.key
    }
}

/// Where each part of a region lies, and its size. A pure function of
/// `max_sessions` and the worker count ([`layout_for`]), so the fd budget
/// and the docs compute the same figures the region is built with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamCapsLayout {
    /// Worker count W: one shard and one attribution counter each.
    pub workers: u32,
    /// Cells of the rate table.
    pub rate_slots: u64,
    /// Cells of each worker's shard.
    pub shard_slots: u64,
    /// Offset of the totals part.
    pub totals_offset: usize,
    /// Offset of the rate table.
    pub rate_offset: usize,
    /// Offset of the first shard.
    pub shards_offset: usize,
    /// Size of the whole region in bytes, the memfd's length. Pages are
    /// only backed once touched.
    pub size: usize,
}

impl StreamCapsLayout {
    /// Bytes of the rate table.
    pub fn rate_table_bytes(&self) -> usize {
        self.shards_offset - self.rate_offset
    }

    /// Bytes of all the shards together.
    pub fn shard_bytes(&self) -> usize {
        self.size - self.shards_offset
    }

    fn from_counts(
        workers: u32,
        rate_slots: u64,
        shard_slots: u64,
    ) -> Result<Self, StreamCapsError> {
        let table_ok = |slots: u64| {
            slots.is_power_of_two() && slots >= MAX_PROBE as u64 && slots <= MAX_TABLE_SLOTS
        };
        if workers == 0 || workers > MAX_WORKERS || !table_ok(rate_slots) || !table_ok(shard_slots)
        {
            return Err(StreamCapsError::BadShape {
                workers,
                rate_slots,
                shard_slots,
            });
        }
        let header = std::mem::size_of::<Header>();
        let totals = (u64::from(workers) + 1)
            .checked_mul(8)
            .and_then(|b| usize::try_from(b).ok())
            .map(|b| b.next_multiple_of(64))
            .ok_or(StreamCapsError::TooLarge)?;
        let rate = usize::try_from(rate_slots)
            .ok()
            .and_then(|n| n.checked_mul(std::mem::size_of::<RateCell>()))
            .ok_or(StreamCapsError::TooLarge)?;
        let shards = usize::try_from(shard_slots)
            .ok()
            .and_then(|n| n.checked_mul(std::mem::size_of::<ShardCell>()))
            .and_then(|b| b.checked_mul(workers as usize))
            .ok_or(StreamCapsError::TooLarge)?;
        let rate_offset = header + totals;
        let shards_offset = rate_offset
            .checked_add(rate)
            .ok_or(StreamCapsError::TooLarge)?;
        let size = shards_offset
            .checked_add(shards)
            .ok_or(StreamCapsError::TooLarge)?;
        if size > isize::MAX as usize {
            return Err(StreamCapsError::TooLarge);
        }
        Ok(StreamCapsLayout {
            workers,
            rate_slots,
            shard_slots,
            totals_offset: header,
            rate_offset,
            shards_offset,
            size,
        })
    }
}

/// The layout of a region for a stream of `max_sessions` on a node of
/// `workers` workers: `rate_slots = next_pow2(max(4 x max_sessions,
/// 1,024))`, `shard_slots = next_pow2(max(2 x max_sessions, 256))`, the
/// factors and floors being [`RATE_SLOTS_PER_SESSION`],
/// [`MIN_RATE_SLOTS`], [`SHARD_SLOTS_PER_SESSION`] and
/// [`MIN_SHARD_SLOTS`].
///
/// # Errors
///
/// [`StreamCapsError::BadShape`] for no session or no worker,
/// [`StreamCapsError::TooLarge`] past what a mapping can hold.
pub fn layout_for(max_sessions: u64, workers: u32) -> Result<StreamCapsLayout, StreamCapsError> {
    let slots = |per_session: u64, floor: u64| {
        max_sessions
            .checked_mul(per_session)
            .map(|n| n.max(floor))
            .and_then(u64::checked_next_power_of_two)
            .ok_or(StreamCapsError::TooLarge)
    };
    if max_sessions == 0 {
        return Err(StreamCapsError::BadShape {
            workers,
            rate_slots: 0,
            shard_slots: 0,
        });
    }
    StreamCapsLayout::from_counts(
        workers,
        slots(RATE_SLOTS_PER_SESSION, MIN_RATE_SLOTS)?,
        slots(SHARD_SLOTS_PER_SESSION, MIN_SHARD_SLOTS)?,
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
        "stream caps region shape refused: {workers} workers, {rate_slots} rate cells, {shard_slots} shard cells"
    )]
    BadShape {
        workers: u32,
        rate_slots: u64,
        shard_slots: u64,
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

/// XORed into the first half of the hash key for IPv6 prefixes, so an
/// IPv4 address and an IPv6 prefix of the same numeric value hash apart.
const V6_KEY_DOMAIN: u64 = 0x7636_5f70_7265_6678;

/// Why a session was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapRefusal {
    /// The stream holds its `max_sessions` on this node.
    SessionCap,
    /// The source holds its per-source cap on this node.
    SourceSessionCap,
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

/// A source's rates, read from the stream's settings at each charge:
/// only sizes live in the region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimits {
    /// Datagrams per second.
    pub datagrams_per_s: u64,
    /// Bytes per second.
    pub bytes_per_s: u64,
}

/// What one [`StreamCapsRegion::evict_rates`] pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RateEvictionStats {
    /// Cells holding a source when the pass reached them.
    pub occupied: usize,
    /// Cells released.
    pub evicted: usize,
    /// Cells kept because their source holds a session.
    pub held: usize,
}

/// One UDP stream's caps region, mapped. Every access to the shared
/// pages goes through atomics; the mapping is released on drop, and the
/// pages live as long as any process maps them or holds the memfd.
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

impl StreamCapsRegion {
    /// Create the region of a stream of `max_sessions` on a node of
    /// `workers` workers: a memfd sized by [`layout_for`], mapped, its
    /// header written with a fresh SipHash key. Returns the mapping and
    /// the memfd to send to every worker.
    ///
    /// # Errors
    ///
    /// The layout's refusal, or the failing system call.
    pub fn create(
        max_sessions: u64,
        workers: u32,
        caps_gen: u64,
    ) -> Result<(StreamCapsRegion, OwnedFd), StreamCapsError> {
        use nix::sys::memfd::{memfd_create, MFdFlags};
        let layout = layout_for(max_sessions, workers)?;
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
        let layout =
            StreamCapsLayout::from_counts(header.workers, header.rate_slots, header.shard_slots)?;
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

    /// The handle through which worker `slot` admits sessions, `None`
    /// when the region has no such slot.
    pub fn worker(self: &Arc<Self>, slot: u32) -> Option<WorkerCaps> {
        (slot < self.layout.workers).then(|| WorkerCaps {
            region: Arc::clone(self),
            slot,
        })
    }

    /// Sessions the stream holds on the node in this region, exact.
    pub fn total(&self) -> u64 {
        self.totals()[0].load(Ordering::Acquire)
    }

    /// Sessions worker `slot` holds in this region, `None` for no such
    /// slot.
    pub fn worker_sessions(&self, slot: u32) -> Option<u64> {
        (slot < self.layout.workers)
            .then(|| self.totals()[1 + slot as usize].load(Ordering::Acquire))
    }

    /// Sessions `source` holds on the node in this region, summed over
    /// every worker's shard.
    pub fn source_sessions(&self, source: SourceKey) -> u64 {
        self.sessions_of(self.tagged(source))
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
        let Some(cell) = self.rate_cell(self.tagged(source), now_ns) else {
            return RateVerdict::TableFull;
        };
        cell.last_seen_ns.store(now_ns, Ordering::Release);
        let one = interval_ns(1, limits.datagrams_per_s);
        if !advance(&cell.datagram_tat, now_ns, one) {
            return RateVerdict::DatagramRate;
        }
        if !advance(
            &cell.byte_tat,
            now_ns,
            interval_ns(bytes, limits.bytes_per_s),
        ) {
            // Our own advance put the arrival time at least `one` past
            // `now_ns`, and others only move it further, so this never
            // goes below zero.
            cell.datagram_tat.fetch_sub(one, Ordering::AcqRel);
            return RateVerdict::ByteRate;
        }
        RateVerdict::Allowed
    }

    /// Release the shard and the attributed sessions of a dead worker:
    /// its shard is emptied and its attribution is subtracted from the
    /// total. Only for a slot whose worker is gone and not yet replaced:
    /// nobody else ever writes that shard. Returns the sessions released,
    /// `None` for no such slot.
    pub fn release_worker(&self, slot: u32) -> Option<u64> {
        let shard = self.shard(slot)?;
        for cell in shard {
            cell.sessions.store(0, Ordering::Release);
            cell.key.store(0, Ordering::Release);
        }
        let totals = self.totals();
        let released = totals[1 + slot as usize].swap(0, Ordering::AcqRel);
        saturating_sub(&totals[0], released);
        Some(released)
    }

    /// Release every rate cell whose two arrival times are past (its
    /// bucket is full again, nothing to remember), not claimed in the
    /// last [`RATE_CELL_GRACE_NS`], and whose source holds no session in
    /// any shard. Shard cells are never touched.
    pub fn evict_rates(&self, now_ns: u64) -> RateEvictionStats {
        let mut stats = RateEvictionStats::default();
        for cell in self.rate_cells() {
            let key = cell.key.load(Ordering::Acquire);
            if key == 0 {
                continue;
            }
            stats.occupied += 1;
            let refilled = cell.datagram_tat.load(Ordering::Acquire) <= now_ns
                && cell.byte_tat.load(Ordering::Acquire) <= now_ns;
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

    fn tagged(&self, source: SourceKey) -> u64 {
        tagged_hash(match source {
            SourceKey::V4(v4) => siphash13_u64(self.hash_key, u64::from(v4)),
            SourceKey::V6Prefix(prefix) => {
                siphash13_u64([self.hash_key[0] ^ V6_KEY_DOMAIN, self.hash_key[1]], prefix)
            }
        })
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

    fn rate_cells(&self) -> &[RateCell] {
        // SAFETY: as `totals`, for `rate_slots` cells at `rate_offset`.
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

    fn shard(&self, slot: u32) -> Option<&[ShardCell]> {
        if slot >= self.layout.workers {
            return None;
        }
        let cells = self.layout.shard_slots as usize;
        let offset = self.layout.shards_offset + slot as usize * cells * 16;
        // SAFETY: as `totals`, for the `slot`-th of `workers` shards of
        // `shard_slots` cells from `shards_offset`, `slot` checked above.
        Some(unsafe {
            std::slice::from_raw_parts(self.base.as_ptr().add(offset).cast::<ShardCell>(), cells)
        })
    }

    fn shards(&self) -> impl Iterator<Item = &[ShardCell]> {
        (0..self.layout.workers).filter_map(|slot| self.shard(slot))
    }

    fn sessions_of(&self, tagged: u64) -> u64 {
        self.shards().map(|shard| shard_count(shard, tagged)).sum()
    }

    fn is_held(&self, tagged: u64) -> bool {
        self.shards()
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

/// Worker `slot`'s access to a region: the one through which it admits
/// sessions, into its own shard.
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

    /// Admit one session of `source`: the stream total first, exact
    /// against `stream_cap`, then the source's sessions summed over every
    /// shard against `source_cap`, then a cell in this worker's shard.
    /// Each refusal undoes what was counted before it. The permit gives
    /// everything back when dropped.
    ///
    /// # Errors
    ///
    /// The cap that refused, or a full window in this worker's shard.
    pub fn admit_session(
        &self,
        source: SourceKey,
        source_cap: u64,
        stream_cap: u64,
    ) -> Result<SessionPermit, CapRefusal> {
        let region = &self.region;
        let totals = region.totals();
        if totals[0].fetch_add(1, Ordering::AcqRel) >= stream_cap {
            saturating_sub(&totals[0], 1);
            return Err(CapRefusal::SessionCap);
        }
        let tagged = region.tagged(source);
        if region.sessions_of(tagged) >= source_cap {
            saturating_sub(&totals[0], 1);
            return Err(CapRefusal::SourceSessionCap);
        }
        let claimed = region
            .shard(self.slot)
            .and_then(|shard| shard_claim(shard, tagged));
        let Some(cell) = claimed else {
            saturating_sub(&totals[0], 1);
            return Err(CapRefusal::TableFull);
        };
        // Attributed after the total: a worker that dies in between
        // leaves the total one too high, never too low.
        totals[1 + self.slot as usize].fetch_add(1, Ordering::AcqRel);
        Ok(SessionPermit {
            region: Arc::clone(region),
            slot: self.slot,
            cell,
        })
    }
}

/// One admitted session's counts, released when dropped: its shard cell
/// (the cell is freed when its count reaches 0), its attribution, then
/// the total. An owned value, so a session can be re-admitted in another
/// region before this one is dropped.
#[derive(Debug)]
pub struct SessionPermit {
    region: Arc<StreamCapsRegion>,
    slot: u32,
    cell: usize,
}

impl SessionPermit {
    /// The region the session is counted in.
    pub fn region(&self) -> &Arc<StreamCapsRegion> {
        &self.region
    }

    /// The worker slot it is counted under.
    pub fn slot(&self) -> u32 {
        self.slot
    }
}

impl Drop for SessionPermit {
    fn drop(&mut self) {
        if let Some(cell) = self
            .region
            .shard(self.slot)
            .and_then(|shard| shard.get(self.cell))
        {
            shard_release(cell);
        }
        let totals = self.region.totals();
        // Attribution before the total: a worker that dies in between
        // leaves the total one too high, never too low.
        saturating_sub(&totals[1 + self.slot as usize], 1);
        saturating_sub(&totals[0], 1);
    }
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

/// A source's sessions in one shard. A cell is counted only if it still
/// holds the key after its count is read, so a cell released and
/// reclaimed for another source in between is not counted for this one.
fn shard_count(shard: &[ShardCell], tagged: u64) -> u64 {
    holding(shard, tagged)
        .map(|cell| {
            let sessions = cell.sessions.load(Ordering::Acquire);
            if cell.key.load(Ordering::Acquire) == tagged {
                sessions
            } else {
                0
            }
        })
        .sum()
}

/// Count one more session of `tagged` in `shard`, returning the cell's
/// index; `None` when the window is full of other sources.
///
/// A cell's count only rises from a non-zero value, and only its claimer
/// sets it from 0 to 1 right after the claim: so a cell whose count a
/// release brought to 0 can never be revived, and the release that did
/// it owns the cell until it clears the key. Safe with any number of
/// writers on the shard, though only its worker writes it.
fn shard_claim(shard: &[ShardCell], tagged: u64) -> Option<usize> {
    for i in window_indices(shard.len(), tagged) {
        let cell = &shard[i];
        if cell.key.load(Ordering::Acquire) != tagged {
            continue;
        }
        let mut sessions = cell.sessions.load(Ordering::Acquire);
        while sessions > 0 {
            match cell.sessions.compare_exchange_weak(
                sessions,
                sessions + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(i),
                Err(actual) => sessions = actual,
            }
        }
    }
    for i in window_indices(shard.len(), tagged) {
        let cell = &shard[i];
        if cell.key.load(Ordering::Acquire) == 0
            && cell
                .key
                .compare_exchange(0, tagged, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            cell.sessions.store(1, Ordering::Release);
            return Some(i);
        }
    }
    None
}

/// Count one session less on a shard cell; the session that brings it
/// to 0 frees the cell. A cell [`StreamCapsRegion::release_worker`]
/// already emptied is left alone.
fn shard_release(cell: &ShardCell) {
    let mut sessions = cell.sessions.load(Ordering::Acquire);
    loop {
        if sessions == 0 {
            return;
        }
        match cell.sessions.compare_exchange_weak(
            sessions,
            sessions - 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(actual) => sessions = actual,
        }
    }
    if sessions == 1 {
        cell.key.store(0, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Barrier;
    use std::thread;

    fn region(max_sessions: u64, workers: u32) -> Arc<StreamCapsRegion> {
        Arc::new(
            StreamCapsRegion::create(max_sessions, workers, 1)
                .expect("create")
                .0,
        )
    }

    fn v4(n: u32) -> SourceKey {
        SourceKey::of(IpAddr::V4(Ipv4Addr::from(n)))
    }

    const SECOND: u64 = 1_000_000_000;

    #[test]
    fn layout_matches_the_documented_figures() {
        let mib = 1024 * 1024;
        let default = layout_for(4096, 8).unwrap();
        assert_eq!(default.rate_table_bytes(), mib);
        assert_eq!(default.shard_bytes(), mib);
        let large = layout_for(28_000, 64).unwrap();
        assert_eq!(large.rate_table_bytes(), 8 * mib);
        assert_eq!(large.shard_bytes(), 64 * mib);
        let tiny = layout_for(1, 1).unwrap();
        assert_eq!(tiny.rate_slots, MIN_RATE_SLOTS);
        assert_eq!(tiny.shard_slots, MIN_SHARD_SLOTS);
        for layout in [default, large, tiny] {
            assert_eq!(layout.totals_offset, 64);
            assert_eq!(layout.rate_offset % 64, 0);
            assert_eq!(layout.shards_offset % 64, 0);
            assert_eq!(
                layout.rate_offset - layout.totals_offset,
                (8 * (layout.workers as usize + 1)).next_multiple_of(64)
            );
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
    }

    #[test]
    fn a_created_region_reopens_with_its_header() {
        let (created, fd) = StreamCapsRegion::create(4096, 4, 7).unwrap();
        let opened = StreamCapsRegion::open(fd).unwrap();
        assert_eq!(opened.layout(), created.layout());
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
    fn the_total_is_exact_under_eight_threads_at_the_cap() {
        const WORKERS: u32 = 8;
        const CAP: u64 = 1000;
        let r = region(CAP, WORKERS);
        let start = Arc::new(Barrier::new(WORKERS as usize));
        let threads: Vec<_> = (0..WORKERS)
            .map(|slot| {
                let caps = r.worker(slot).unwrap();
                let start = Arc::clone(&start);
                thread::spawn(move || {
                    start.wait();
                    let mut permits = Vec::new();
                    // Distinct sources, so only the stream cap binds.
                    for n in 0..CAP as u32 {
                        if let Ok(p) = caps.admit_session(v4(slot * 100_000 + n), u64::MAX, CAP) {
                            permits.push(p);
                        }
                    }
                    permits
                })
            })
            .collect();
        let held: Vec<Vec<SessionPermit>> =
            threads.into_iter().map(|h| h.join().unwrap()).collect();
        let admitted: usize = held.iter().map(Vec::len).sum();
        assert_eq!(admitted as u64, CAP);
        assert_eq!(r.total(), CAP);
        for slot in 0..WORKERS {
            assert_eq!(
                r.worker_sessions(slot),
                Some(held[slot as usize].len() as u64)
            );
        }
        drop(held);
        assert_eq!(r.total(), 0);
        assert!((0..WORKERS).all(|slot| r.worker_sessions(slot) == Some(0)));
    }

    #[test]
    fn one_source_overshoots_its_cap_by_at_most_workers_minus_one() {
        const WORKERS: u32 = 8;
        const SOURCE_CAP: u64 = 4;
        let source = v4(0xC000_0201);
        for _round in 0..50 {
            let r = region(4096, WORKERS);
            let start = Arc::new(Barrier::new(WORKERS as usize));
            let threads: Vec<_> = (0..WORKERS)
                .map(|slot| {
                    let caps = r.worker(slot).unwrap();
                    let start = Arc::clone(&start);
                    thread::spawn(move || {
                        start.wait();
                        let mut permits = Vec::new();
                        while let Ok(p) = caps.admit_session(source, SOURCE_CAP, 4096) {
                            permits.push(p);
                        }
                        permits
                    })
                })
                .collect();
            let held: Vec<Vec<SessionPermit>> =
                threads.into_iter().map(|h| h.join().unwrap()).collect();
            let total: u64 = held.iter().map(|p| p.len() as u64).sum();
            assert!(total >= SOURCE_CAP, "{total}");
            assert!(total < SOURCE_CAP + u64::from(WORKERS), "{total}");
            assert!(held.iter().all(|p| p.len() as u64 <= SOURCE_CAP));
            assert_eq!(r.source_sessions(source), total);
            assert_eq!(r.total(), total);
            drop(held);
            assert_eq!(r.source_sessions(source), 0);
        }
    }

    #[test]
    fn a_refusal_counts_nothing_and_names_its_cap() {
        let r = region(2, 1);
        let caps = r.worker(0).unwrap();
        let a = caps.admit_session(v4(1), 1, 2).unwrap();
        assert_eq!(
            caps.admit_session(v4(1), 1, 2).unwrap_err(),
            CapRefusal::SourceSessionCap
        );
        let b = caps.admit_session(v4(2), 1, 2).unwrap();
        assert_eq!(
            caps.admit_session(v4(3), 1, 2).unwrap_err(),
            CapRefusal::SessionCap
        );
        assert_eq!(r.total(), 2);
        assert_eq!(r.worker_sessions(0), Some(2));
        drop((a, b));
        assert_eq!(r.total(), 0);
        assert!(r.worker(1).is_none());
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
        let permit = r.worker(1).unwrap().admit_session(source, 8, 16).unwrap();
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
    fn release_worker_restores_the_total_and_empties_its_shard() {
        let r = region(64, 3);
        let dead = r.worker(1).unwrap();
        let alive = r.worker(2).unwrap();
        let kept = alive.admit_session(v4(5), 8, 64).unwrap();
        for _ in 0..3 {
            // The worker dies holding its sessions: nothing drops them.
            std::mem::forget(dead.admit_session(v4(5), 8, 64).unwrap());
        }
        std::mem::forget(dead.admit_session(v4(6), 8, 64).unwrap());
        assert_eq!(r.total(), 5);
        assert_eq!(r.source_sessions(v4(5)), 4);
        assert_eq!(r.release_worker(1), Some(4));
        assert_eq!(r.total(), 1);
        assert_eq!(r.worker_sessions(1), Some(0));
        assert_eq!(r.source_sessions(v4(5)), 1);
        assert_eq!(r.source_sessions(v4(6)), 0);
        assert!(r.shard(1).unwrap().iter().all(|c| {
            c.key.load(Ordering::Acquire) == 0 && c.sessions.load(Ordering::Acquire) == 0
        }));
        drop(kept);
        assert_eq!(r.total(), 0);
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
        let shard: Vec<ShardCell> = (0..64)
            .map(|_| ShardCell {
                key: AtomicU64::new(0),
                sessions: AtomicU64::new(0),
            })
            .collect();
        let key = |n: u64| tagged_hash((n << 6) | 0x10);
        for n in 0..MAX_PROBE as u64 {
            assert!(shard_claim(&shard, key(n)).is_some());
        }
        assert_eq!(shard_claim(&shard, key(MAX_PROBE as u64)), None);
        // A key already placed still counts more.
        let i = shard_claim(&shard, key(3)).unwrap();
        assert_eq!(shard[i].sessions.load(Ordering::Acquire), 2);
        assert_eq!(shard_count(&shard, key(3)), 2);
    }

    #[test]
    fn a_full_shard_refuses_the_session_and_undoes_the_total() {
        let r = region(1, 1);
        let caps = r.worker(0).unwrap();
        let mut held = Vec::new();
        let refusal = loop {
            match caps.admit_session(v4(held.len() as u32), 1, u64::MAX) {
                Ok(p) => held.push(p),
                Err(e) => break e,
            }
            assert!(held.len() as u64 <= MIN_SHARD_SLOTS, "never refused");
        };
        assert_eq!(refusal, CapRefusal::TableFull);
        assert_eq!(r.total(), held.len() as u64);
    }

    #[test]
    fn a_released_cell_is_never_revived_and_a_count_survives_its_neighbours() {
        let r = region(16, 1);
        let caps = r.worker(0).unwrap();
        let first = caps.admit_session(v4(1), 8, 16).unwrap();
        let second = caps.admit_session(v4(1), 8, 16).unwrap();
        assert_eq!(first.cell, second.cell);
        drop(first);
        assert_eq!(r.source_sessions(v4(1)), 1);
        drop(second);
        assert_eq!(r.source_sessions(v4(1)), 0);
        assert!(!r.is_held(r.tagged(v4(1))));
    }
}
