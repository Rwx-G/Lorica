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

//! Anonymous shared-memory region used by supervisor and workers.
//!
//! Layout (all little-endian, Linux amd64):
//!
//! ```text
//!   offset    field              type                   size
//!   ------    -----              ----                   ----
//!        0    magic              u64 (LORICASHM)           8
//!        8    layout_version     u32                       4
//!       12    _reserved          u32                       4
//!       16    hash_key[0]        u64                       8
//!       24    hash_key[1]        u64                       8
//!       32    _pad0              [u8; 32]                 32
//!       64    waf_flood          AtomicHashTable<N>   N * 64
//!      ...    waf_auto_ban       AtomicHashTable<N>   N * 64
//! ```
//!
//! The padding to offset 64 is enforced by `#[repr(C, align(64))]` on
//! both this struct and `AtomicHashTable`. N is fixed at compile time
//! to [`WAF_SLOTS`]; any change to N, to the struct layout, or to the
//! ABI of `Slot` must bump [`LAYOUT_VERSION`] and be documented in
//! `docs/BUMP-CHECKLIST.md`.

use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use nix::errno::Errno;
use nix::sys::mman::{mmap, MapFlags, ProtFlags};
use std::num::NonZeroUsize;

use crate::hash::random_key;
use crate::table::AtomicHashTable;

/// Magic number written at the start of the region so workers can fail
/// fast on a layout mismatch. ASCII "LORICASHM".
pub const MAGIC: u64 = 0x4c4f_5249_4341_5348;

/// Current layout version. Bumped on any change to the binary ABI of
/// [`SharedRegion`] or its tables.
pub const LAYOUT_VERSION: u32 = 1;

/// Number of slots per WAF table. Must be a power of two. 128 Ki slots
/// ≈ 8 MiB per table, 16 MiB for both. At 50 % load factor this covers
/// ~64 Ki concurrent live IPs per table, more than any single-node
/// Lorica deployment expects.
pub const WAF_SLOTS: usize = 128 * 1024;
const _: () = {
    assert!(WAF_SLOTS.is_power_of_two());
};

/// The full shared region. Layout is frozen and ABI-stable across
/// supervisor and worker processes.
#[repr(C, align(64))]
pub struct SharedRegion {
    pub magic: u64,
    pub layout_version: u32,
    pub _reserved: u32,
    /// SipHash-1-3 key, written once by the supervisor at
    /// [`SharedRegion::create_supervisor`] from OS-backed entropy and
    /// read-only thereafter. Workers inherit it by mapping the same
    /// pages. Prevents HashDoS on the probe chain.
    pub hash_key: [u64; 2],
    /// Explicit pad so `waf_flood` starts at a fresh 64-byte cache line.
    _pad0: [u8; 32],
    pub waf_flood: AtomicHashTable<WAF_SLOTS>,
    pub waf_auto_ban: AtomicHashTable<WAF_SLOTS>,
}

// Sanity-check layout at compile time so accidental reordering is caught.
const _: () = {
    assert!(std::mem::align_of::<SharedRegion>() == 64);
    // Header (offsets 0..64) must be exactly one cache line wide.
    assert!(std::mem::offset_of!(SharedRegion, waf_flood) == 64);
};

/// Error returned when opening or creating the region.
#[derive(Debug, thiserror::Error)]
pub enum SharedRegionError {
    #[error("memfd_create failed: {0}")]
    Memfd(Errno),
    #[error("ftruncate failed: {0}")]
    Ftruncate(Errno),
    #[error("mmap failed: {0}")]
    Mmap(Errno),
    #[error("region magic mismatch: got {got:#x}, expected {expected:#x}")]
    BadMagic { got: u64, expected: u64 },
    #[error(
        "layout version mismatch: got {got}, expected {expected} (supervisor/worker binary skew?)"
    )]
    BadVersion { got: u32, expected: u32 },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Total region size in bytes. Fixed at compile time.
pub const REGION_SIZE: usize = std::mem::size_of::<SharedRegion>();

impl SharedRegion {
    /// Create the anonymous memfd, size it to [`REGION_SIZE`], mmap it
    /// with `MAP_SHARED`, initialise the header (magic, version,
    /// random hash key), and return the mapped reference plus the fd
    /// that should be passed to each worker at fork.
    ///
    /// Called once by the supervisor at startup before any worker is
    /// spawned. The returned `&'static SharedRegion` has the lifetime
    /// of the process — the supervisor must not unmap it.
    pub fn create_supervisor() -> Result<(&'static SharedRegion, OwnedFd), SharedRegionError> {
        use nix::sys::memfd::{memfd_create, MemFdCreateFlag};

        // `MFD_CLOEXEC`: the supervisor never exec()s, but this is the
        // defensive default. We explicitly dup / pass the fd to workers
        // via SCM_RIGHTS so CLOEXEC on the supervisor side is harmless.
        let fd: OwnedFd = memfd_create(c"lorica-shmem", MemFdCreateFlag::MFD_CLOEXEC)
            .map_err(SharedRegionError::Memfd)?;

        // Size the region.
        nix::unistd::ftruncate(&fd, REGION_SIZE as i64).map_err(SharedRegionError::Ftruncate)?;

        let region = unsafe { map_region(&fd)? };

        // Initialise the header. We only ever write these fields here,
        // before any worker gets a chance to read.
        region.magic = MAGIC;
        region.layout_version = LAYOUT_VERSION;
        region._reserved = 0;
        region.hash_key = random_key();
        // Tables are already zeroed by ftruncate (fresh memfd).

        Ok((region as &'static SharedRegion, fd))
    }

    /// Adopt a memfd received from the supervisor (typically via
    /// SCM_RIGHTS), mmap it, and verify the header.
    ///
    /// # Safety
    /// `fd` must be a valid memfd with the exact same layout the
    /// supervisor created. The caller takes ownership of the fd.
    pub unsafe fn open_worker(fd: RawFd) -> Result<&'static SharedRegion, SharedRegionError> {
        // Turn the raw fd into an OwnedFd so we drop it cleanly on
        // error paths.
        let owned = OwnedFd::from_raw_fd(fd);
        let region = map_region(&owned)?;
        // Header verification.
        if region.magic != MAGIC {
            return Err(SharedRegionError::BadMagic {
                got: region.magic,
                expected: MAGIC,
            });
        }
        if region.layout_version != LAYOUT_VERSION {
            return Err(SharedRegionError::BadVersion {
                got: region.layout_version,
                expected: LAYOUT_VERSION,
            });
        }
        // Leak the fd: we want the mapping to survive for the process
        // lifetime. Forgetting here is deliberate (the kernel keeps the
        // pages alive as long as any process holds the fd or a mapping).
        std::mem::forget(owned);
        Ok(region as &'static SharedRegion)
    }

    /// Compute the tagged siphash for a raw u64 key using this region's
    /// hash_key. Convenience wrapper so call sites don't reach into
    /// both `hash` and `table` modules.
    #[inline]
    pub fn tagged(&self, raw: u64) -> u64 {
        crate::table::tagged_hash(crate::hash::siphash13_u64(self.hash_key, raw))
    }
}

/// # Safety
/// `fd` must refer to a memfd sized to at least [`REGION_SIZE`]. The
/// returned mutable reference is alive for the process lifetime. The
/// caller ensures single-initialisation semantics for header fields on
/// the supervisor side.
unsafe fn map_region(fd: &OwnedFd) -> Result<&'static mut SharedRegion, SharedRegionError> {
    let len = NonZeroUsize::new(REGION_SIZE).expect("REGION_SIZE > 0");
    // nix 0.29: mmap takes an AsFd and returns NonNull<c_void>.
    let nn = mmap(
        None,
        len,
        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
        MapFlags::MAP_SHARED,
        fd,
        0,
    )
    .map_err(SharedRegionError::Mmap)?;
    let region_ptr = nn.as_ptr().cast::<SharedRegion>();
    // Enforce alignment assumption at runtime too.
    assert!(
        region_ptr.align_offset(std::mem::align_of::<SharedRegion>()) == 0,
        "mmap returned misaligned pointer (kernel gave us {:p}, need align {})",
        region_ptr,
        std::mem::align_of::<SharedRegion>()
    );
    Ok(&mut *region_ptr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table::tagged_hash;
    use std::os::fd::AsRawFd;

    #[test]
    fn create_and_read_header() {
        let (region, fd) = SharedRegion::create_supervisor().expect("create");
        assert_eq!(region.magic, MAGIC);
        assert_eq!(region.layout_version, LAYOUT_VERSION);
        assert_ne!(region.hash_key, [0u64, 0u64]);
        drop(fd);
    }

    #[test]
    fn supervisor_and_worker_see_same_hash_key() {
        let (sup, fd) = SharedRegion::create_supervisor().expect("create");

        // Duplicate the fd so both sides hold their own OwnedFd.
        let dup_fd = nix::unistd::dup(fd.as_raw_fd()).expect("dup");
        // The test "worker" shares the same process — in production
        // this fd travels via SCM_RIGHTS to a forked child.
        let worker = unsafe { SharedRegion::open_worker(dup_fd) }.expect("worker open");
        assert_eq!(worker.hash_key, sup.hash_key);
        assert_eq!(worker.magic, MAGIC);
    }

    #[test]
    fn increment_via_region_propagates() {
        let (region, _fd) = SharedRegion::create_supervisor().expect("create");
        let h = region.tagged(0x10_20_30_40);
        assert_eq!(region.waf_flood.increment(h, 1, 100), 1);
        assert_eq!(region.waf_flood.increment(h, 4, 200), 5);
        assert_eq!(region.waf_flood.read(h), Some(5));
    }

    #[test]
    fn flood_and_auto_ban_are_independent() {
        let (region, _fd) = SharedRegion::create_supervisor().expect("create");
        let h = region.tagged(42);
        region.waf_flood.increment(h, 10, 1);
        assert_eq!(region.waf_auto_ban.read(h), None);
        region.waf_auto_ban.increment(h, 1, 2);
        assert_eq!(region.waf_auto_ban.read(h), Some(1));
        assert_eq!(region.waf_flood.read(h), Some(10));
    }

    #[test]
    fn bad_magic_rejected() {
        use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
        let fd = memfd_create(c"lorica-bad", MemFdCreateFlag::MFD_CLOEXEC).expect("memfd");
        nix::unistd::ftruncate(&fd, REGION_SIZE as i64).expect("ftruncate");
        // Leave magic = 0.
        let raw = fd.as_raw_fd();
        std::mem::forget(fd); // open_worker adopts ownership
                              // Match pattern instead of unwrap_err: SharedRegion does not
                              // implement Debug (it is a 16 MiB struct) so unwrap_err cannot
                              // format the Ok variant.
        match unsafe { SharedRegion::open_worker(raw) } {
            Err(SharedRegionError::BadMagic { .. }) => {}
            Err(other) => panic!("expected BadMagic, got {other:?}"),
            Ok(_) => panic!("expected BadMagic, got Ok"),
        }
    }

    #[test]
    fn layout_is_exactly_16_mib_plus_header() {
        // Two tables × 128 Ki slots × 64 B = 16 MiB. Plus the 64 B
        // header cache line. Repr enforces; assert at runtime anyway.
        let expected = 64 + 2 * WAF_SLOTS * 64;
        assert_eq!(REGION_SIZE, expected);
    }

    #[test]
    fn tagged_lsb_set() {
        let (region, _fd) = SharedRegion::create_supervisor().expect("create");
        let h = region.tagged(0);
        assert_eq!(h & 1, 1);
        let h = region.tagged(0xffff_ffff_ffff_ffff);
        assert_eq!(h & 1, 1);
        let _ = tagged_hash; // silence unused import when features shift
    }
}
