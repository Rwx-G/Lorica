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

//! SCM_RIGHTS-based file descriptor passing between supervisor and worker processes.
//!
//! The supervisor creates listening sockets, then passes their FDs to workers
//! over a unix socketpair using the SCM_RIGHTS ancillary message.
//!
//! Each FD carries a typed tag ([`FdKind`]) so callers can distinguish a
//! listening TCP socket from e.g. the shared-memory memfd used by
//! `lorica-shmem`. On the wire, the tags are serialised as a space-
//! separated list alongside the SCM_RIGHTS payload:
//!
//! - `listener:0.0.0.0:8080`: a TCP listener
//! - `shmem`: the anonymous memfd holding the `SharedRegion`
//! - `rpc`: the worker end of the pipelined RPC socketpair
//! - `stream-ctl`: the worker end of the stream control channel
//!   ([`crate::stream_ctl`])
//! - `stream:<tcp|udp>:<bind_gen>:<addr>`: a stream socket, sent only
//!   over the stream control channel, never in the fork bundle
//! - `stream-caps:<caps_gen>`: the memfd of one stream's caps region
//!   (`lorica_shmem::StreamCapsRegion`), sent only over the stream control
//!   channel, never in the fork bundle

use std::io::{IoSlice, IoSliceMut};
use std::net::SocketAddr;
use std::os::fd::{BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::sys::socket::{
    self, AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType,
    UnixAddr,
};

use crate::stream_ctl::ATTACH_HEADER_MAX_LEN;
use crate::WorkerError;

/// Maximum number of FDs that can be passed in a single message, on the
/// fork bundle and on one stream control `attach` alike. The kernel's own
/// ceiling (`SCM_MAX_FD`, 253) is far above; keeping it at 32 also bounds
/// the fds in flight per worker on the stream control channel, which the
/// kernel charges to the sender's `RLIMIT_NOFILE` (`ETOOMANYREFS`).
pub const MAX_FDS: usize = 32;

/// Upper bound on one wire token's encoded size. The longest token is a
/// stream socket token, bounded by [`STREAM_SOCKET_TOKEN_MAX_LEN`]; the
/// rest is headroom for future schemes.
pub(crate) const MAX_TOKEN_LEN: usize = 128;

/// Maximum size of the tag payload buffer, on the fork bundle and on the
/// stream control channel. It must hold the longest `attach` header plus
/// `MAX_FDS` space-separated tokens of up to `MAX_TOKEN_LEN` bytes each.
/// The compile-time assertion below enforces that invariant so future
/// `FdKind` variants with longer tokens trip the build instead of
/// producing silent `MSG_TRUNC` on the wire (audit L-2).
pub(crate) const PAYLOAD_BUF_SIZE: usize = 8192;

/// Longest decimal rendering of a `u64`.
pub(crate) const U64_MAX_DIGITS: usize = 20;

/// Longest text form of a `SocketAddr`: an IPv6 address of eight full
/// groups (39 bytes), a scope id of up to ten digits after `%`, the
/// brackets and a five-digit port.
const SOCKET_ADDR_MAX_LEN: usize = 1 + 39 + 1 + 10 + 2 + 5;

/// Longest stream socket token: `stream:udp:<u64>:<addr>`.
pub(crate) const STREAM_SOCKET_TOKEN_MAX_LEN: usize =
    "stream:udp:".len() + U64_MAX_DIGITS + 1 + SOCKET_ADDR_MAX_LEN;

const _: () = assert!(
    STREAM_SOCKET_TOKEN_MAX_LEN <= MAX_TOKEN_LEN,
    "a stream socket token must fit MAX_TOKEN_LEN"
);

const _: () = assert!(
    ATTACH_HEADER_MAX_LEN + MAX_FDS * (1 + MAX_TOKEN_LEN) <= PAYLOAD_BUF_SIZE,
    "PAYLOAD_BUF_SIZE must fit the attach header plus MAX_FDS separated tokens of MAX_TOKEN_LEN"
);

/// Transport protocol of a stream socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamProto {
    /// A listening TCP socket, shared by every worker.
    Tcp,
    /// A UDP socket, one per worker slot in a `SO_REUSEPORT` group.
    Udp,
}

impl StreamProto {
    /// The wire and API spelling: `tcp` or `udp`.
    pub fn as_str(self) -> &'static str {
        match self {
            StreamProto::Tcp => "tcp",
            StreamProto::Udp => "udp",
        }
    }

    /// Parse the spelling produced by [`Self::as_str`].
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "tcp" => Some(StreamProto::Tcp),
            "udp" => Some(StreamProto::Udp),
            _ => None,
        }
    }
}

impl std::fmt::Display for StreamProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a passed file descriptor is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FdKind {
    /// A listening TCP socket. `addr` is the bind address (e.g. "0.0.0.0:8080").
    Listener { addr: String },
    /// The anonymous memfd backing the `lorica_shmem::SharedRegion`.
    Shmem,
    /// The worker's end of the dedicated pipelined-RPC socketpair
    /// (separate from the legacy command channel). Used by the
    /// `lorica_command::RpcEndpoint` to sync per-route token buckets,
    /// verdict caches, and breaker state with the supervisor. See
    /// `docs/architecture/worker-shared-state.md` § 4.
    Rpc,
    /// The worker's end of the `SOCK_SEQPACKET` stream control channel
    /// ([`crate::stream_ctl`]), over which the supervisor attaches and
    /// detaches stream sockets at runtime.
    StreamCtl,
    /// One socket of a stream binding, sent in a stream control `attach`.
    /// `bind_gen` names the binding (all its sockets); `addr` is the
    /// socket's bind address.
    StreamSocket {
        proto: StreamProto,
        bind_gen: u64,
        addr: SocketAddr,
    },
    /// The memfd of one UDP stream's caps region, sent in a stream
    /// control `caps`. `caps_gen` names the region among the stream's
    /// successive ones (a size change replaces it).
    StreamCaps { caps_gen: u64 },
}

impl FdKind {
    /// Serialise as a wire token (one space-separated item in the payload).
    pub(crate) fn to_token(&self) -> String {
        match self {
            FdKind::Listener { addr } => format!("listener:{addr}"),
            FdKind::Shmem => "shmem".to_string(),
            FdKind::Rpc => "rpc".to_string(),
            FdKind::StreamCtl => "stream-ctl".to_string(),
            FdKind::StreamSocket {
                proto,
                bind_gen,
                addr,
            } => format!("stream:{proto}:{bind_gen}:{addr}"),
            FdKind::StreamCaps { caps_gen } => format!("stream-caps:{caps_gen}"),
        }
    }

    /// Parse a wire token produced by [`Self::to_token`].
    pub(crate) fn from_token(tok: &str) -> Result<Self, WorkerError> {
        if tok == "shmem" {
            Ok(FdKind::Shmem)
        } else if tok == "rpc" {
            Ok(FdKind::Rpc)
        } else if tok == "stream-ctl" {
            Ok(FdKind::StreamCtl)
        } else if let Some(caps_gen) = tok.strip_prefix("stream-caps:") {
            Ok(FdKind::StreamCaps {
                caps_gen: parse_decimal_u64(caps_gen)?,
            })
        } else if let Some(addr) = tok.strip_prefix("listener:") {
            Ok(FdKind::Listener {
                addr: addr.to_string(),
            })
        } else if let Some(rest) = tok.strip_prefix("stream:") {
            let (proto, rest) = rest.split_once(':').ok_or(WorkerError::InvalidPayload)?;
            let (bind_gen, addr) = rest.split_once(':').ok_or(WorkerError::InvalidPayload)?;
            Ok(FdKind::StreamSocket {
                proto: StreamProto::from_wire(proto).ok_or(WorkerError::InvalidPayload)?,
                bind_gen: bind_gen.parse().map_err(|_| WorkerError::InvalidPayload)?,
                addr: addr.parse().map_err(|_| WorkerError::InvalidPayload)?,
            })
        } else {
            Err(WorkerError::InvalidPayload)
        }
    }
}

/// A decimal `u64` of digits only: `str::parse` would also take a sign.
fn parse_decimal_u64(tok: &str) -> Result<u64, WorkerError> {
    if tok.is_empty() || !tok.bytes().all(|b| b.is_ascii_digit()) {
        return Err(WorkerError::InvalidPayload);
    }
    tok.parse().map_err(|_| WorkerError::InvalidPayload)
}

/// A typed FD entry sent over the command channel at worker fork.
#[derive(Debug, Clone)]
pub struct FdEntry {
    pub fd: RawFd,
    pub kind: FdKind,
}

/// Create a Unix socketpair for supervisor-worker communication.
///
/// Both ends are created with `SOCK_CLOEXEC` so they are closed on exec by default.
/// The worker end must have CLOEXEC cleared before exec via [`clear_cloexec`].
///
/// Returns `(supervisor_fd, worker_fd)`.
pub fn create_socketpair() -> Result<(OwnedFd, OwnedFd), WorkerError> {
    let (fd1, fd2) = socket::socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .map_err(WorkerError::SocketPair)?;
    Ok((fd1, fd2))
}

/// Send typed FD entries to a worker.
///
/// The tags are serialised as a space-separated payload; the FDs travel
/// in the SCM_RIGHTS ancillary message. The `i`-th tag pairs with the
/// `i`-th FD. Order is preserved; callers match by `kind`, not by index.
pub fn send_worker_fds(sock: RawFd, entries: &[FdEntry]) -> Result<(), WorkerError> {
    let fds: Vec<RawFd> = entries.iter().map(|e| e.fd).collect();
    let tokens: Vec<String> = entries.iter().map(|e| e.kind.to_token()).collect();
    let payload = tokens.join(" ");
    let iov = [IoSlice::new(payload.as_bytes())];
    let cmsg = [ControlMessage::ScmRights(&fds)];

    socket::sendmsg::<UnixAddr>(sock, &iov, &cmsg, MsgFlags::empty(), None)
        .map_err(WorkerError::SendFds)?;

    Ok(())
}

/// Receive typed FD entries from the supervisor.
///
/// Wraps every received `RawFd` into an [`OwnedFd`] immediately after
/// `recvmsg` so any subsequent error path (UTF-8 validation, fds/tokens
/// mismatch, bad `FdKind` token) correctly `close(2)`s the FDs via
/// `OwnedFd::drop`. On success, ownership is transferred back to the
/// caller via `IntoRawFd` so callers remain free to `mem::forget` or
/// re-own as they see fit. This closes audit finding H-2 (kernel FD
/// leak on error paths) and M-6 (silent `MSG_TRUNC` truncation).
pub fn recv_worker_fds(sock: RawFd) -> Result<Vec<FdEntry>, WorkerError> {
    let mut buf = [0u8; PAYLOAD_BUF_SIZE];

    // Collect OwnedFds up front. If the function returns Err anywhere
    // below, `drop` closes each FD. If it returns Ok we `into_raw_fd`
    // to hand ownership to the caller.
    let received =
        recv_with_rights(sock, &mut buf, MsgFlags::empty()).map_err(WorkerError::RecvFds)?;
    let (owned_fds, bytes) = (received.fds, received.bytes);

    if received.truncated {
        // Payload or cmsg buffer was too small: the kernel silently
        // dropped bytes / FDs. Returning Err here also drops `owned_fds`
        // via `OwnedFd::drop` so no FD leak (audit H-2 / M-6).
        return Err(WorkerError::InvalidPayload);
    }

    let payload = std::str::from_utf8(&buf[..bytes]).map_err(|_| WorkerError::InvalidPayload)?;
    let tokens: Vec<&str> = payload.split_ascii_whitespace().collect();

    if owned_fds.len() != tokens.len() {
        return Err(WorkerError::FdAddrMismatch {
            fds: owned_fds.len(),
            addrs: tokens.len(),
        });
    }

    // Validate every token before transferring ownership. Any parse
    // failure here still drops `owned_fds` via the RAII path.
    let mut kinds = Vec::with_capacity(tokens.len());
    for tok in &tokens {
        kinds.push(FdKind::from_token(tok)?);
    }

    // All validations passed - hand the raw FDs to the caller.
    Ok(owned_fds
        .into_iter()
        .zip(kinds)
        .map(|(owned, kind)| FdEntry {
            fd: owned.into_raw_fd(),
            kind,
        })
        .collect())
}

/// One `recvmsg` with its `SCM_RIGHTS` fds already owned.
pub struct ReceivedRights {
    /// Payload bytes written into the caller's buffer.
    pub bytes: usize,
    /// `MSG_TRUNC` or `MSG_CTRUNC`: payload or fds were lost.
    pub truncated: bool,
    /// Every fd the kernel installed, owned so any error path closes it.
    pub fds: Vec<OwnedFd>,
}

/// Send `payload` with `fds` attached as one `SCM_RIGHTS` message on a
/// connected unix socket, and return how many payload bytes the kernel
/// took.
///
/// On a stream socket the kernel may take less than the whole payload;
/// the descriptors travel with the bytes it took, so the caller sends the
/// rest without any.
pub fn send_with_rights(sock: RawFd, payload: &[u8], fds: &[RawFd]) -> Result<usize, WorkerError> {
    let iov = [IoSlice::new(payload)];
    let rights = [ControlMessage::ScmRights(fds)];
    let cmsg: &[ControlMessage<'_>] = if fds.is_empty() { &[] } else { &rights };
    socket::sendmsg::<UnixAddr>(sock, &iov, cmsg, MsgFlags::empty(), None)
        .map_err(WorkerError::SendFds)
}

/// [`recv_with_rights`] for a receiver outside this crate, always with
/// `MSG_CMSG_CLOEXEC`: descriptors received from another process must not
/// leak into the processes this one forks and execs.
pub fn recv_with_rights_cloexec(
    sock: RawFd,
    buf: &mut [u8],
) -> Result<ReceivedRights, WorkerError> {
    recv_with_rights(sock, buf, MsgFlags::MSG_CMSG_CLOEXEC).map_err(WorkerError::RecvFds)
}

/// `recvmsg` into `buf` with room for [`MAX_FDS`] passed fds, owning every
/// fd the kernel installed, including on `MSG_CTRUNC`.
///
/// nix refuses to iterate a control buffer flagged `MSG_CTRUNC`
/// (`ENOBUFS`), yet the kernel has installed the fds that fit into it
/// (and, when the receiver runs out of descriptors, those it managed to
/// install). Propagating that refusal would leak them, so a truncated
/// buffer is read by [`salvage_rights`] instead.
pub(crate) fn recv_with_rights(
    sock: RawFd,
    buf: &mut [u8],
    flags: MsgFlags,
) -> nix::Result<ReceivedRights> {
    let mut cmsg_buf = nix::cmsg_space!([RawFd; MAX_FDS]);
    let (bytes, msg_flags, mut fds) = {
        let mut iov = [IoSliceMut::new(buf)];
        let msg = socket::recvmsg::<UnixAddr>(sock, &mut iov, Some(&mut cmsg_buf), flags)?;
        let mut owned = Vec::<OwnedFd>::new();
        if !msg.flags.contains(MsgFlags::MSG_CTRUNC) {
            for cmsg in msg.cmsgs()? {
                if let ControlMessageOwned::ScmRights(received) = cmsg {
                    for raw in received {
                        // SAFETY: `ScmRights` yields fresh kernel FDs that the
                        // kernel passed with exclusive ownership; wrapping them
                        // in `OwnedFd` is the canonical close-on-drop idiom.
                        owned.push(unsafe { OwnedFd::from_raw_fd(raw) });
                    }
                }
            }
        }
        (msg.bytes, msg.flags, owned)
    };
    if msg_flags.contains(MsgFlags::MSG_CTRUNC) {
        fds = salvage_rights(&cmsg_buf);
    }
    Ok(ReceivedRights {
        bytes,
        truncated: msg_flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC),
        fds,
    })
}

/// Own the fds of every `SCM_RIGHTS` header in a control buffer the
/// kernel flagged `MSG_CTRUNC`. Linux writes only whole headers whose
/// `cmsg_len` covers the fds it installed; the rest of the buffer is
/// still zeroed, and a zero `cmsg_len` ends the walk.
fn salvage_rights(control: &[u8]) -> Vec<OwnedFd> {
    use nix::libc::{cmsghdr, CMSG_LEN, CMSG_SPACE, SCM_RIGHTS, SOL_SOCKET};

    // SAFETY: `CMSG_LEN` is pure arithmetic on its argument.
    let data_offset = unsafe { CMSG_LEN(0) } as usize;
    let fd_size = std::mem::size_of::<RawFd>();
    let mut fds = Vec::new();
    let mut offset = 0usize;
    while offset + std::mem::size_of::<cmsghdr>() <= control.len() {
        // SAFETY: the bounds check above keeps the read inside `control`,
        // and `read_unaligned` places no alignment requirement on it.
        let header: cmsghdr =
            unsafe { std::ptr::read_unaligned(control[offset..].as_ptr().cast::<cmsghdr>()) };
        // `cmsg_len` is `size_t` on glibc and `socklen_t` on musl.
        #[allow(clippy::unnecessary_cast)]
        let len = header.cmsg_len as usize;
        if len < data_offset || offset + len > control.len() {
            break;
        }
        if header.cmsg_level == SOL_SOCKET && header.cmsg_type == SCM_RIGHTS {
            for raw in control[offset + data_offset..offset + len].chunks_exact(fd_size) {
                let mut bytes = [0u8; std::mem::size_of::<RawFd>()];
                bytes.copy_from_slice(raw);
                // SAFETY: the kernel installed this descriptor for this
                // process alone while filling the header; nothing else
                // owns it.
                fds.push(unsafe { OwnedFd::from_raw_fd(RawFd::from_ne_bytes(bytes)) });
            }
        }
        // SAFETY: `CMSG_SPACE` is pure arithmetic on its argument.
        offset += unsafe { CMSG_SPACE((len - data_offset) as u32) } as usize;
    }
    fds
}

/// Backwards-compatible wrapper used by tests that only care about
/// listener FDs. The on-wire tokens are still the typed form so
/// [`send_listener_fds`] interoperates with [`recv_worker_fds`].
pub fn send_listener_fds(sock: RawFd, fds: &[RawFd], addrs: &[String]) -> Result<(), WorkerError> {
    if fds.len() != addrs.len() {
        return Err(WorkerError::FdAddrMismatch {
            fds: fds.len(),
            addrs: addrs.len(),
        });
    }
    let entries: Vec<FdEntry> = fds
        .iter()
        .zip(addrs)
        .map(|(&fd, addr)| FdEntry {
            fd,
            kind: FdKind::Listener { addr: addr.clone() },
        })
        .collect();
    send_worker_fds(sock, &entries)
}

/// Backwards-compatible wrapper: drops non-listener entries so callers
/// that only need listeners stay simple. A dropped entry's FD is closed.
pub fn recv_listener_fds(sock: RawFd) -> Result<Vec<(RawFd, String)>, WorkerError> {
    let entries = recv_worker_fds(sock)?;
    Ok(entries
        .into_iter()
        .filter_map(|e| match e.kind {
            FdKind::Listener { addr } => Some((e.fd, addr)),
            FdKind::Shmem
            | FdKind::Rpc
            | FdKind::StreamCtl
            | FdKind::StreamSocket { .. }
            | FdKind::StreamCaps { .. } => {
                // SAFETY: `recv_worker_fds` handed this FD over with
                // exclusive ownership and nothing else refers to it.
                unsafe { close_fd(e.fd) };
                None
            }
        })
        .collect())
}

/// Clear the CLOEXEC flag on a file descriptor so it survives `execv`.
pub fn clear_cloexec(fd: RawFd) -> Result<(), WorkerError> {
    // SAFETY: the caller hands an open descriptor it keeps open for the
    // duration of this call; the borrow does not outlive it.
    let fd: BorrowedFd<'_> = unsafe { BorrowedFd::borrow_raw(fd) };
    fcntl(fd, FcntlArg::F_SETFD(FdFlag::empty())).map_err(WorkerError::ClearCloexec)?;
    Ok(())
}

/// Duplicate `fd` into a fresh CLOEXEC descriptor owned by the returned
/// [`OwnedFd`].
///
/// Used by the hot-upgrade handoff (Story 8.4) to keep a long-lived copy
/// of each proxy listening socket alive in the supervisor after the
/// originals are closed post-fork. The dup refers to the SAME open file
/// description (shared accept queue), so it can later be re-passed to a
/// new supervisor via SCM_RIGHTS. CLOEXEC is set because the dup is never
/// meant to leak across an `execv`; the SCM_RIGHTS transfer dups it again
/// in the receiver regardless of this flag.
pub fn dup_cloexec(fd: RawFd) -> Result<OwnedFd, WorkerError> {
    // SAFETY: the caller hands an open descriptor it keeps open for the
    // duration of this call; the borrow does not outlive it.
    let fd: BorrowedFd<'_> = unsafe { BorrowedFd::borrow_raw(fd) };
    let raw: RawFd = fcntl(fd, FcntlArg::F_DUPFD_CLOEXEC(0)).map_err(WorkerError::DupFd)?;
    // SAFETY: `F_DUPFD_CLOEXEC` returns a fresh, exclusively-owned FD;
    // wrapping it in `OwnedFd` is the canonical close-on-drop idiom.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Create a TCP listening socket bound to the given address.
///
/// The socket has `SO_REUSEADDR` set and a backlog of 65535.
/// It is created with CLOEXEC (default on Linux), which is appropriate
/// since it will be sent to workers via SCM_RIGHTS rather than inherited.
pub fn create_tcp_listener(addr: &str) -> Result<(RawFd, String), WorkerError> {
    let sock_addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|e| WorkerError::BadAddress(addr.to_string(), e))?;

    let domain = if sock_addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };

    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
        .map_err(WorkerError::CreateSocket)?;

    socket
        .set_reuse_address(true)
        .map_err(WorkerError::CreateSocket)?;

    // Enable SO_REUSEPORT so multiple workers can share the socket efficiently.
    // The kernel distributes incoming connections across workers.
    socket
        .set_reuse_port(true)
        .map_err(WorkerError::CreateSocket)?;

    socket
        .bind(&sock_addr.into())
        .map_err(WorkerError::CreateSocket)?;

    socket.listen(65535).map_err(WorkerError::CreateSocket)?;

    let fd = socket.into_raw_fd();
    Ok((fd, addr.to_string()))
}

/// Close a raw file descriptor by wrapping it in OwnedFd (which drops it).
///
/// # Safety
/// The fd must be a valid open file descriptor not owned by anything else.
pub unsafe fn close_fd(fd: RawFd) {
    drop(OwnedFd::from_raw_fd(fd));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    #[allow(unused_imports)]
    use std::os::fd::IntoRawFd;

    #[test]
    fn test_create_socketpair() {
        let (fd1, fd2) = create_socketpair().expect("socketpair failed");
        assert!(fd1.as_raw_fd() >= 0);
        assert!(fd2.as_raw_fd() >= 0);
        assert_ne!(fd1.as_raw_fd(), fd2.as_raw_fd());
    }

    #[test]
    fn test_send_recv_fds_roundtrip() {
        let (parent_fd, child_fd) = create_socketpair().expect("socketpair failed");

        // Create a dummy socket to pass as a listener FD
        let dummy = socket::socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .expect("dummy socket failed");
        let dummy_raw = dummy.as_raw_fd();

        let addrs = vec!["0.0.0.0:8080".to_string()];

        // Send from parent side
        send_listener_fds(parent_fd.as_raw_fd(), &[dummy_raw], &addrs)
            .expect("send_listener_fds failed");

        // Receive on child side
        let received = recv_listener_fds(child_fd.as_raw_fd()).expect("recv_listener_fds failed");

        assert_eq!(received.len(), 1);
        assert_eq!(received[0].1, "0.0.0.0:8080");
        // The received FD is a new descriptor (dup'd by kernel)
        assert!(received[0].0 >= 0);
    }

    #[test]
    fn test_send_recv_multiple_fds() {
        let (parent_fd, child_fd) = create_socketpair().expect("socketpair failed");

        let dummy1 = socket::socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        let dummy2 = socket::socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap();

        let fds = [dummy1.as_raw_fd(), dummy2.as_raw_fd()];
        let addrs = vec!["0.0.0.0:8080".to_string(), "0.0.0.0:8443".to_string()];

        send_listener_fds(parent_fd.as_raw_fd(), &fds, &addrs).expect("send failed");
        let received = recv_listener_fds(child_fd.as_raw_fd()).expect("recv failed");

        assert_eq!(received.len(), 2);
        assert_eq!(received[0].1, "0.0.0.0:8080");
        assert_eq!(received[1].1, "0.0.0.0:8443");
    }

    #[test]
    fn test_clear_cloexec() {
        let (fd, _) = create_socketpair().expect("socketpair failed");
        let raw = fd.as_raw_fd();

        // Initially CLOEXEC should be set (due to SOCK_CLOEXEC)
        let flags = fcntl(&fd, FcntlArg::F_GETFD).expect("F_GETFD failed");
        assert!(FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC));

        // Clear it
        clear_cloexec(raw).expect("clear_cloexec failed");

        let flags = fcntl(&fd, FcntlArg::F_GETFD).expect("F_GETFD failed");
        assert!(!FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC));
    }

    #[test]
    fn test_create_tcp_listener() {
        // Use port 0 for OS-assigned port
        let (fd, addr) = create_tcp_listener("127.0.0.1:0").expect("create_tcp_listener failed");
        assert!(fd >= 0);
        assert_eq!(addr, "127.0.0.1:0");

        // Clean up
        unsafe { close_fd(fd) };
    }

    #[test]
    fn test_send_recv_typed_shmem_plus_listener() {
        use nix::sys::memfd::{memfd_create, MFdFlags};
        let (parent_fd, child_fd) = create_socketpair().expect("socketpair failed");

        let memfd =
            memfd_create(c"lorica-shmem-test", MFdFlags::MFD_CLOEXEC).expect("memfd_create");
        let dummy = socket::socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .expect("dummy");

        let entries = [
            FdEntry {
                fd: memfd.as_raw_fd(),
                kind: FdKind::Shmem,
            },
            FdEntry {
                fd: dummy.as_raw_fd(),
                kind: FdKind::Listener {
                    addr: "0.0.0.0:8080".to_string(),
                },
            },
        ];
        send_worker_fds(parent_fd.as_raw_fd(), &entries).expect("send");

        let received = recv_worker_fds(child_fd.as_raw_fd()).expect("recv");
        assert_eq!(received.len(), 2);
        assert_eq!(received[0].kind, FdKind::Shmem);
        match &received[1].kind {
            FdKind::Listener { addr } => assert_eq!(addr, "0.0.0.0:8080"),
            _ => panic!("expected Listener"),
        }
    }

    #[test]
    fn test_legacy_listener_wrapper_filters_out_shmem() {
        // Sender mixes shmem + listener; legacy receiver keeps only listeners.
        use nix::sys::memfd::{memfd_create, MFdFlags};
        let (parent_fd, child_fd) = create_socketpair().expect("socketpair failed");

        let memfd = memfd_create(c"lorica-shmem-test2", MFdFlags::MFD_CLOEXEC).unwrap();
        let dummy = socket::socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        let entries = [
            FdEntry {
                fd: memfd.as_raw_fd(),
                kind: FdKind::Shmem,
            },
            FdEntry {
                fd: dummy.as_raw_fd(),
                kind: FdKind::Listener {
                    addr: "127.0.0.1:9000".to_string(),
                },
            },
        ];
        send_worker_fds(parent_fd.as_raw_fd(), &entries).unwrap();
        let pairs = recv_listener_fds(child_fd.as_raw_fd()).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].1, "127.0.0.1:9000");
    }

    #[test]
    fn test_fd_kind_token_roundtrip() {
        let cases = [
            FdKind::Shmem,
            FdKind::Rpc,
            FdKind::Listener {
                addr: "0.0.0.0:8080".to_string(),
            },
            FdKind::Listener {
                addr: "[::]:443".to_string(),
            },
            FdKind::StreamCtl,
            FdKind::StreamSocket {
                proto: StreamProto::Tcp,
                bind_gen: 0,
                addr: "0.0.0.0:5432".parse().unwrap(),
            },
            FdKind::StreamSocket {
                proto: StreamProto::Udp,
                bind_gen: 7,
                addr: "[::]:53".parse().unwrap(),
            },
            FdKind::StreamSocket {
                proto: StreamProto::Udp,
                bind_gen: u64::MAX,
                addr: "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"
                    .parse()
                    .unwrap(),
            },
            FdKind::StreamCaps { caps_gen: 0 },
            FdKind::StreamCaps { caps_gen: u64::MAX },
        ];
        for k in cases {
            let t = k.to_token();
            assert!(t.len() <= MAX_TOKEN_LEN, "{t} exceeds MAX_TOKEN_LEN");
            let back = FdKind::from_token(&t).unwrap();
            assert_eq!(back, k);
        }
        // Unknown tag is an error.
        assert!(FdKind::from_token("wat:garbage").is_err());
    }

    #[test]
    fn test_recv_worker_fds_closes_what_arrived_on_ctrunc() {
        // One fd more than the control buffer holds: the kernel installs
        // MAX_FDS of them and flags MSG_CTRUNC, which nix refuses to
        // iterate. Every installed copy must still be closed.
        let (parent_fd, child_fd) = create_socketpair().expect("socketpair failed");
        let passed: Vec<OwnedFd> = (0..=MAX_FDS)
            .map(|_| {
                socket::socket(
                    AddressFamily::Unix,
                    SockType::Stream,
                    SockFlag::empty(),
                    None,
                )
                .unwrap()
            })
            .collect();
        let entries: Vec<FdEntry> = passed
            .iter()
            .map(|fd| FdEntry {
                fd: fd.as_raw_fd(),
                kind: FdKind::Rpc,
            })
            .collect();
        send_worker_fds(parent_fd.as_raw_fd(), &entries).unwrap();
        assert!(matches!(
            recv_worker_fds(child_fd.as_raw_fd()),
            Err(WorkerError::InvalidPayload)
        ));
        for fd in &passed {
            let ino = nix::sys::stat::fstat(fd).unwrap().st_ino;
            let target = format!("socket:[{ino}]");
            let open = std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| {
                    std::fs::read_link(e.path())
                        .map(|l| l.to_string_lossy() == target)
                        .unwrap_or(false)
                })
                .count();
            assert_eq!(open, 1, "a received copy of {target} leaked");
        }
    }

    #[test]
    fn test_stream_ctl_and_stream_socket_tokens() {
        assert_eq!(FdKind::StreamCtl.to_token(), "stream-ctl");
        let longest = FdKind::StreamSocket {
            proto: StreamProto::Udp,
            bind_gen: u64::MAX,
            addr: "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"
                .parse()
                .unwrap(),
        };
        assert_eq!(
            longest.to_token(),
            "stream:udp:18446744073709551615:[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"
        );
    }

    #[test]
    fn test_stream_socket_token_bound_matches_the_worst_case() {
        // The constant is arithmetic; this pins it to what `Display`
        // really renders for the longest address, scope id included.
        let worst = FdKind::StreamSocket {
            proto: StreamProto::Udp,
            bind_gen: u64::MAX,
            addr: SocketAddr::V6(std::net::SocketAddrV6::new(
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap(),
                65535,
                0,
                u32::MAX,
            )),
        };
        let token = worst.to_token();
        assert_eq!(token.len(), STREAM_SOCKET_TOKEN_MAX_LEN, "{token}");
        assert_eq!(FdKind::from_token(&token).unwrap(), worst);
    }

    #[test]
    fn test_stream_socket_token_rejects_malformed_forms() {
        for bad in [
            "stream:",
            "stream:tcp",
            "stream:tcp:1",
            "stream:sctp:1:127.0.0.1:80",
            "stream:tcp:x:127.0.0.1:80",
            "stream:tcp:-1:127.0.0.1:80",
            "stream:tcp:1:127.0.0.1",
            "stream:tcp:1:localhost:80",
            "stream:udp:1:[::1]:70000",
        ] {
            assert!(FdKind::from_token(bad).is_err(), "{bad} was accepted");
        }
    }

    #[test]
    fn test_stream_caps_token_is_documented_and_strict() {
        assert_eq!(
            FdKind::StreamCaps { caps_gen: 12 }.to_token(),
            "stream-caps:12"
        );
        for bad in [
            "stream-caps:",
            "stream-caps:+1",
            "stream-caps:-1",
            "stream-caps:x",
            "stream-caps:18446744073709551616",
            "stream-caps:1:2",
        ] {
            assert!(FdKind::from_token(bad).is_err(), "{bad} was accepted");
        }
    }

    #[test]
    fn test_legacy_listener_wrapper_filters_out_stream_kinds() {
        let (parent_fd, child_fd) = create_socketpair().expect("socketpair failed");
        let ctl = socket::socket(
            AddressFamily::Unix,
            SockType::SeqPacket,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        let stream_sock = socket::socket(
            AddressFamily::Inet,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        let listener = socket::socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        let caps = nix::sys::memfd::memfd_create(
            c"lorica-stream-caps-test",
            nix::sys::memfd::MFdFlags::MFD_CLOEXEC,
        )
        .unwrap();
        let entries = [
            FdEntry {
                fd: ctl.as_raw_fd(),
                kind: FdKind::StreamCtl,
            },
            FdEntry {
                fd: caps.as_raw_fd(),
                kind: FdKind::StreamCaps { caps_gen: 1 },
            },
            FdEntry {
                fd: stream_sock.as_raw_fd(),
                kind: FdKind::StreamSocket {
                    proto: StreamProto::Tcp,
                    bind_gen: 3,
                    addr: "127.0.0.1:5432".parse().unwrap(),
                },
            },
            FdEntry {
                fd: listener.as_raw_fd(),
                kind: FdKind::Listener {
                    addr: "127.0.0.1:9000".to_string(),
                },
            },
        ];
        send_worker_fds(parent_fd.as_raw_fd(), &entries).unwrap();
        let pairs = recv_listener_fds(child_fd.as_raw_fd()).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].1, "127.0.0.1:9000");
    }
}
