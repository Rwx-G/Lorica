//! The handover channel: a `SOCK_SEQPACKET` unix socketpair, created by
//! the old generation before it execs the new one, so each message keeps
//! its boundary and carries its own `SCM_RIGHTS` descriptors. Blocking,
//! with an optional receive timeout through `poll(2)`.

use std::io::{self, IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags, UnixAddr};

/// At most this many descriptors per message. Two per TCP connection,
/// one per UDP session, two for the listeners.
pub const MAX_FDS_PER_MSG: usize = 8;

pub struct Chan {
    fd: OwnedFd,
}

pub enum Recv {
    Msg(String, Vec<OwnedFd>),
    Eof,
    TimedOut,
}

impl Chan {
    pub fn new(fd: OwnedFd) -> Self {
        Chan { fd }
    }

    pub fn send(&self, msg: &str, fds: &[RawFd]) -> io::Result<()> {
        assert!(fds.len() <= MAX_FDS_PER_MSG);
        let iov = [IoSlice::new(msg.as_bytes())];
        let rights = [ControlMessage::ScmRights(fds)];
        let cmsg: &[ControlMessage<'_>] = if fds.is_empty() { &[] } else { &rights };
        sendmsg::<UnixAddr>(
            self.fd.as_raw_fd(),
            &iov,
            cmsg,
            MsgFlags::MSG_NOSIGNAL,
            None,
        )
        .map_err(io::Error::from)?;
        Ok(())
    }

    /// `timeout_ms` < 0 waits forever.
    pub fn recv(&self, timeout_ms: i32) -> io::Result<Recv> {
        let mut pfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            // SAFETY: one valid pollfd.
            let r = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if r < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if r == 0 {
                return Ok(Recv::TimedOut);
            }
            break;
        }
        let mut buf = vec![0u8; 128 * 1024];
        let mut cmsg_buf = nix::cmsg_space!([RawFd; MAX_FDS_PER_MSG]);
        let mut iov = [IoSliceMut::new(&mut buf)];
        let msg = recvmsg::<UnixAddr>(
            self.fd.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_buf),
            MsgFlags::MSG_CMSG_CLOEXEC,
        )
        .map_err(io::Error::from)?;
        if msg
            .flags
            .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
        {
            return Err(io::Error::other("handover message truncated"));
        }
        let mut fds = Vec::new();
        for c in msg.cmsgs().map_err(io::Error::from)? {
            if let ControlMessageOwned::ScmRights(raw) = c {
                for r in raw {
                    // SAFETY: the kernel installed this descriptor for us.
                    fds.push(unsafe { OwnedFd::from_raw_fd(r) });
                }
            }
        }
        let n = msg.bytes;
        if n == 0 && fds.is_empty() {
            return Ok(Recv::Eof);
        }
        Ok(Recv::Msg(
            String::from_utf8_lossy(&buf[..n]).into_owned(),
            fds,
        ))
    }

    /// Everything already queued, without waiting; stops at EOF.
    pub fn drain_queued(&self) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(Recv::Msg(m, _)) = self.recv(0) {
            out.push(m);
        }
        out
    }
}

/// `key=value` fields of a message.
pub fn field<'a>(msg: &'a str, key: &str) -> Option<&'a str> {
    msg.split(' ')
        .find_map(|kv| kv.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
}

pub fn field_u64(msg: &str, key: &str) -> u64 {
    field(msg, key).and_then(|v| v.parse().ok()).unwrap_or(0)
}
