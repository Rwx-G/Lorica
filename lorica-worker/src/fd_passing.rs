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
//! - `listener:0.0.0.0:8080` — a TCP listener
//! - `shmem` — the anonymous memfd holding the `SharedRegion`

use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd, RawFd};

use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::sys::socket::{
    self, AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType,
    UnixAddr,
};

use crate::WorkerError;

/// Maximum number of FDs that can be passed in a single message. Covers
/// the worst case: one HTTP listener + one HTTPS listener + one shmem
/// memfd + headroom for future RPC / shared-state descriptors.
const MAX_FDS: usize = 32;

/// Upper bound on one wire token's encoded size. The longest token today
/// is `listener:[2001:db8:ffff:ffff:ffff:ffff:ffff:ffff]:65535` which is
/// under 60 bytes; we give it 128 B of headroom for future schemes.
const MAX_TOKEN_LEN: usize = 128;

/// Maximum size of the tag payload buffer. Must be large enough to hold
/// `MAX_FDS` space-separated tokens (each up to `MAX_TOKEN_LEN`). The
/// compile-time assertion below enforces that invariant so future
/// `FdKind` variants with longer tokens trip the build instead of
/// producing silent `MSG_TRUNC` on the wire (audit L-2).
const PAYLOAD_BUF_SIZE: usize = 4096;

const _: () = assert!(
    MAX_FDS * MAX_TOKEN_LEN <= PAYLOAD_BUF_SIZE,
    "PAYLOAD_BUF_SIZE must fit MAX_FDS tokens of MAX_TOKEN_LEN bytes each"
);

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
}

impl FdKind {
    /// Serialise as a wire token (one space-separated item in the payload).
    fn to_token(&self) -> String {
        match self {
            FdKind::Listener { addr } => format!("listener:{addr}"),
            FdKind::Shmem => "shmem".to_string(),
            FdKind::Rpc => "rpc".to_string(),
        }
    }

    /// Parse a wire token produced by [`Self::to_token`].
    fn from_token(tok: &str) -> Result<Self, WorkerError> {
        if tok == "shmem" {
            Ok(FdKind::Shmem)
        } else if tok == "rpc" {
            Ok(FdKind::Rpc)
        } else if let Some(addr) = tok.strip_prefix("listener:") {
            Ok(FdKind::Listener {
                addr: addr.to_string(),
            })
        } else {
            Err(WorkerError::InvalidPayload)
        }
    }
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
    let mut cmsg_buf = nix::cmsg_space!([RawFd; MAX_FDS]);

    // Collect OwnedFds up front. If the function returns Err anywhere
    // below, `drop` closes each FD. If it returns Ok we `into_raw_fd`
    // to hand ownership to the caller.
    let (owned_fds, bytes, truncated) = {
        let mut iov = [IoSliceMut::new(&mut buf)];
        let msg =
            socket::recvmsg::<UnixAddr>(sock, &mut iov, Some(&mut cmsg_buf), MsgFlags::empty())
                .map_err(WorkerError::RecvFds)?;

        let mut owned = Vec::<OwnedFd>::new();
        for cmsg in msg.cmsgs().map_err(WorkerError::RecvFds)? {
            if let ControlMessageOwned::ScmRights(received) = cmsg {
                for raw in received {
                    // SAFETY: `ScmRights` yields fresh kernel FDs that the
                    // kernel passed with exclusive ownership; wrapping them
                    // in `OwnedFd` is the canonical close-on-drop idiom.
                    owned.push(unsafe { OwnedFd::from_raw_fd(raw) });
                }
            }
        }
        let truncated =
            msg.flags.contains(MsgFlags::MSG_TRUNC) || msg.flags.contains(MsgFlags::MSG_CTRUNC);
        (owned, msg.bytes, truncated)
    };

    if truncated {
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
/// that only need listeners stay simple.
pub fn recv_listener_fds(sock: RawFd) -> Result<Vec<(RawFd, String)>, WorkerError> {
    let entries = recv_worker_fds(sock)?;
    Ok(entries
        .into_iter()
        .filter_map(|e| match e.kind {
            FdKind::Listener { addr } => Some((e.fd, addr)),
            FdKind::Shmem | FdKind::Rpc => None,
        })
        .collect())
}

/// Clear the CLOEXEC flag on a file descriptor so it survives `execv`.
pub fn clear_cloexec(fd: RawFd) -> Result<(), WorkerError> {
    fcntl(fd, FcntlArg::F_SETFD(FdFlag::empty())).map_err(WorkerError::ClearCloexec)?;
    Ok(())
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
        let flags = fcntl(raw, FcntlArg::F_GETFD).expect("F_GETFD failed");
        assert!(FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC));

        // Clear it
        clear_cloexec(raw).expect("clear_cloexec failed");

        let flags = fcntl(raw, FcntlArg::F_GETFD).expect("F_GETFD failed");
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
        use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
        let (parent_fd, child_fd) = create_socketpair().expect("socketpair failed");

        let memfd =
            memfd_create(c"lorica-shmem-test", MemFdCreateFlag::MFD_CLOEXEC).expect("memfd_create");
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
        use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
        let (parent_fd, child_fd) = create_socketpair().expect("socketpair failed");

        let memfd = memfd_create(c"lorica-shmem-test2", MemFdCreateFlag::MFD_CLOEXEC).unwrap();
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
        ];
        for k in cases {
            let t = k.to_token();
            let back = FdKind::from_token(&t).unwrap();
            assert_eq!(back, k);
        }
        // Unknown tag is an error.
        assert!(FdKind::from_token("wat:garbage").is_err());
    }
}
