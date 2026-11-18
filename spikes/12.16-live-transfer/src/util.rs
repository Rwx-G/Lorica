//! Clock, deterministic byte streams and the raw socket calls the spike
//! needs.

use std::collections::HashMap;
use std::os::fd::RawFd;

/// `CLOCK_MONOTONIC` in nanoseconds. One clock for every process of the
/// same time namespace, so an absolute value can cross a handover.
pub fn mono_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid out-pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// A deterministic byte stream (xorshift64*), so each end can generate
/// what the other must receive and compare byte for byte.
pub struct ByteStream {
    state: u64,
    pending: [u8; 8],
    pending_len: usize,
}

impl ByteStream {
    pub fn new(seed: u64) -> Self {
        ByteStream {
            state: seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1,
            pending: [0; 8],
            pending_len: 0,
        }
    }

    fn next_word(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            if self.pending_len == 0 {
                self.pending = self.next_word().to_le_bytes();
                self.pending_len = 8;
            }
            *b = self.pending[8 - self.pending_len];
            self.pending_len -= 1;
        }
    }
}

/// FNV-1a over a whole direction, for the report.
#[derive(Clone, Copy)]
pub struct Fnv(pub u64);

impl Fnv {
    pub fn new() -> Self {
        Fnv(0xcbf2_9ce4_8422_2325)
    }
    pub fn update(&mut self, data: &[u8]) {
        for b in data {
            self.0 ^= u64::from(*b);
            self.0 = self.0.wrapping_mul(0x0100_0000_01b3);
        }
    }
}

/// Checks a received direction against the stream its sender generated.
pub struct Verifier {
    expected: ByteStream,
    scratch: Vec<u8>,
    pub offset: u64,
    pub first_mismatch: Option<u64>,
    pub hash: Fnv,
}

impl Verifier {
    pub fn new(seed: u64) -> Self {
        Verifier {
            expected: ByteStream::new(seed),
            scratch: Vec::new(),
            offset: 0,
            first_mismatch: None,
            hash: Fnv::new(),
        }
    }

    pub fn check(&mut self, data: &[u8]) {
        self.scratch.resize(data.len(), 0);
        self.expected.fill(&mut self.scratch);
        if self.first_mismatch.is_none() {
            if let Some(i) = data.iter().zip(&self.scratch).position(|(a, b)| a != b) {
                self.first_mismatch = Some(self.offset + i as u64);
            }
        }
        self.hash.update(data);
        self.offset += data.len() as u64;
    }
}

/// Bytes in the socket's kernel receive queue (`SIOCINQ`).
pub fn inq(fd: RawFd) -> i64 {
    let mut v: libc::c_int = 0;
    // SAFETY: FIONREAD writes one int.
    unsafe { libc::ioctl(fd, libc::FIONREAD, &mut v) };
    i64::from(v)
}

/// Bytes in the socket's kernel send queue, unacknowledged or unsent
/// (`SIOCOUTQ`).
pub fn outq(fd: RawFd) -> i64 {
    let mut v: libc::c_int = 0;
    // SAFETY: TIOCOUTQ (SIOCOUTQ) writes one int.
    unsafe { libc::ioctl(fd, libc::TIOCOUTQ, &mut v) };
    i64::from(v)
}

pub fn shutdown_write(fd: RawFd) {
    // SAFETY: plain syscall on a descriptor the caller owns.
    unsafe { libc::shutdown(fd, libc::SHUT_WR) };
}

pub fn shutdown_both(fd: RawFd) {
    // SAFETY: plain syscall on a descriptor the caller owns.
    unsafe { libc::shutdown(fd, libc::SHUT_RDWR) };
}

pub fn set_linger_zero(fd: RawFd) {
    let l = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: `l` outlives the call and its size is passed.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&l as *const libc::linger).cast(),
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };
}

/// `--key value` arguments, in order, for the spike's own CLI.
pub fn parse_args(args: &[String]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut it = args.iter();
    while let Some(k) = it.next() {
        if let Some(key) = k.strip_prefix("--") {
            let v = it.next().cloned().unwrap_or_default();
            map.insert(key.to_string(), v);
        }
    }
    map
}

pub fn arg<T: std::str::FromStr>(map: &HashMap<String, String>, key: &str, default: T) -> T {
    map.get(key).and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Percentile over a sorted slice.
pub fn pct(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let i = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[i]
}
