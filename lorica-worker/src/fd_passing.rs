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

use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd, RawFd};

use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::sys::socket::{
    self, AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType,
    UnixAddr,
};

use crate::WorkerError;

/// Maximum number of listener FDs that can be passed in a single message.
const MAX_FDS: usize = 32;

/// Maximum size of the address payload buffer.
const PAYLOAD_BUF_SIZE: usize = 2048;

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

/// Send listening socket FDs and their bind addresses to a worker.
///
/// The addresses are serialized as space-separated strings in the message payload.
/// The FDs are sent via SCM_RIGHTS ancillary data.
pub fn send_listener_fds(sock: RawFd, fds: &[RawFd], addrs: &[String]) -> Result<(), WorkerError> {
    if fds.len() != addrs.len() {
        return Err(WorkerError::FdAddrMismatch {
            fds: fds.len(),
            addrs: addrs.len(),
        });
    }

    let payload = addrs.join(" ");
    let iov = [IoSlice::new(payload.as_bytes())];
    let cmsg = [ControlMessage::ScmRights(fds)];

    socket::sendmsg::<UnixAddr>(sock, &iov, &cmsg, MsgFlags::empty(), None)
        .map_err(WorkerError::SendFds)?;

    Ok(())
}

/// Receive listening socket FDs and their bind addresses from the supervisor.
///
/// Returns a list of `(raw_fd, bind_address)` pairs.
pub fn recv_listener_fds(sock: RawFd) -> Result<Vec<(RawFd, String)>, WorkerError> {
    let mut buf = [0u8; PAYLOAD_BUF_SIZE];
    let mut cmsg_buf = nix::cmsg_space!([RawFd; MAX_FDS]);

    let (fds, bytes) = {
        let mut iov = [IoSliceMut::new(&mut buf)];
        let msg =
            socket::recvmsg::<UnixAddr>(sock, &mut iov, Some(&mut cmsg_buf), MsgFlags::empty())
                .map_err(WorkerError::RecvFds)?;

        let mut fds = Vec::new();
        for cmsg in msg.cmsgs().map_err(WorkerError::RecvFds)? {
            if let ControlMessageOwned::ScmRights(received) = cmsg {
                fds.extend_from_slice(&received);
            }
        }
        (fds, msg.bytes)
    };

    let payload = std::str::from_utf8(&buf[..bytes]).map_err(|_| WorkerError::InvalidPayload)?;
    let addrs: Vec<String> = payload.split_ascii_whitespace().map(String::from).collect();

    if fds.len() != addrs.len() {
        return Err(WorkerError::FdAddrMismatch {
            fds: fds.len(),
            addrs: addrs.len(),
        });
    }

    Ok(fds.into_iter().zip(addrs).collect())
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
}
