// Copyright 2026 Romain G. (Lorica)
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

//! Async command channel over a Unix stream socket with length-prefixed framing.
//!
//! Wire format: `[8 bytes LE: message length][N bytes: prost-encoded message]`
//!
//! This custom framing ensures forward compatibility regardless of prost's
//! internal delimiter format changes.

use std::io;
use std::os::fd::{FromRawFd, RawFd};
use std::time::Duration;

use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

use crate::ChannelError;

/// Maximum allowed message size (1 MB). Prevents OOM from corrupt framing.
const MAX_MESSAGE_SIZE: u64 = 1024 * 1024;

/// Default timeout for send/recv operations.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// An async command channel over a Unix stream socket.
///
/// Used for bidirectional communication between the supervisor and a worker.
/// Messages are framed with an 8-byte little-endian size prefix followed
/// by prost-encoded protobuf bytes.
pub struct CommandChannel {
    stream: UnixStream,
    timeout: Duration,
}

impl CommandChannel {
    /// Create a CommandChannel from a raw file descriptor.
    ///
    /// # Safety
    /// The fd must be a valid, open Unix stream socket not owned by anything else.
    /// After this call, the CommandChannel owns the fd and will close it on drop.
    pub unsafe fn from_raw_fd(fd: RawFd) -> Result<Self, ChannelError> {
        let std_stream = std::os::unix::net::UnixStream::from_raw_fd(fd);
        std_stream
            .set_nonblocking(true)
            .map_err(ChannelError::Io)?;
        let stream = UnixStream::from_std(std_stream).map_err(ChannelError::Io)?;
        Ok(Self {
            stream,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Set the timeout for send/recv operations.
    pub fn set_timeout(&mut self, duration: Duration) {
        self.timeout = duration;
    }

    /// Send a protobuf message with length-prefix framing.
    pub async fn send<T: Message>(&mut self, msg: &T) -> Result<(), ChannelError> {
        let encoded = msg.encode_to_vec();
        let len = encoded.len() as u64;

        let write_fut = async {
            self.stream
                .write_all(&len.to_le_bytes())
                .await
                .map_err(ChannelError::Io)?;
            self.stream
                .write_all(&encoded)
                .await
                .map_err(ChannelError::Io)?;
            self.stream.flush().await.map_err(ChannelError::Io)?;
            Ok(())
        };

        timeout(self.timeout, write_fut)
            .await
            .map_err(|_| ChannelError::Timeout)?
    }

    /// Receive a protobuf message with length-prefix framing.
    pub async fn recv<T: Message + Default>(&mut self) -> Result<T, ChannelError> {
        let read_fut = async {
            let mut len_buf = [0u8; 8];
            self.stream
                .read_exact(&mut len_buf)
                .await
                .map_err(ChannelError::Io)?;
            let len = u64::from_le_bytes(len_buf);

            if len > MAX_MESSAGE_SIZE {
                return Err(ChannelError::MessageTooLarge(len));
            }

            let mut msg_buf = vec![0u8; len as usize];
            self.stream
                .read_exact(&mut msg_buf)
                .await
                .map_err(ChannelError::Io)?;

            T::decode(&msg_buf[..]).map_err(ChannelError::Decode)
        };

        timeout(self.timeout, read_fut)
            .await
            .map_err(|_| ChannelError::Timeout)?
    }

    /// Try to receive a message without blocking. Returns None if no data is available.
    pub async fn try_recv<T: Message + Default>(&mut self) -> Result<Option<T>, ChannelError> {
        let mut len_buf = [0u8; 8];
        match self.stream.try_read(&mut len_buf) {
            Ok(8) => {}
            Ok(0) => return Err(ChannelError::Io(io::Error::from(io::ErrorKind::UnexpectedEof))),
            Ok(_) => {
                // Partial read of length header - read the rest
                let read = self
                    .stream
                    .read_exact(&mut len_buf[..])
                    .await
                    .map_err(ChannelError::Io);
                if read.is_err() {
                    return Err(ChannelError::Io(io::Error::from(
                        io::ErrorKind::UnexpectedEof,
                    )));
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(ChannelError::Io(e)),
        }

        let len = u64::from_le_bytes(len_buf);
        if len > MAX_MESSAGE_SIZE {
            return Err(ChannelError::MessageTooLarge(len));
        }

        let mut msg_buf = vec![0u8; len as usize];
        self.stream
            .read_exact(&mut msg_buf)
            .await
            .map_err(ChannelError::Io)?;

        let msg = T::decode(&msg_buf[..]).map_err(ChannelError::Decode)?;
        Ok(Some(msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{Command, CommandType, Response};
    use std::os::fd::IntoRawFd;

    fn make_socketpair() -> (RawFd, RawFd) {
        use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
        let (fd1, fd2) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .expect("socketpair failed");
        (fd1.into_raw_fd(), fd2.into_raw_fd())
    }

    #[tokio::test]
    async fn test_send_recv_command() {
        let (fd1, fd2) = make_socketpair();
        let mut sender = unsafe { CommandChannel::from_raw_fd(fd1).unwrap() };
        let mut receiver = unsafe { CommandChannel::from_raw_fd(fd2).unwrap() };

        let cmd = Command::new(CommandType::ConfigReload, 1);
        sender.send(&cmd).await.expect("send failed");

        let received: Command = receiver.recv().await.expect("recv failed");
        assert_eq!(received.typed_command(), CommandType::ConfigReload);
        assert_eq!(received.sequence, 1);
    }

    #[tokio::test]
    async fn test_send_recv_response() {
        let (fd1, fd2) = make_socketpair();
        let mut sender = unsafe { CommandChannel::from_raw_fd(fd1).unwrap() };
        let mut receiver = unsafe { CommandChannel::from_raw_fd(fd2).unwrap() };

        let resp = Response::error(42, "test error");
        sender.send(&resp).await.expect("send failed");

        let received: Response = receiver.recv().await.expect("recv failed");
        assert_eq!(received.sequence, 42);
        assert_eq!(received.message, "test error");
    }

    #[tokio::test]
    async fn test_bidirectional_communication() {
        let (fd1, fd2) = make_socketpair();
        let mut supervisor = unsafe { CommandChannel::from_raw_fd(fd1).unwrap() };
        let mut worker = unsafe { CommandChannel::from_raw_fd(fd2).unwrap() };

        // Supervisor sends command
        let cmd = Command::new(CommandType::Heartbeat, 10);
        supervisor.send(&cmd).await.expect("send cmd failed");

        // Worker receives and responds
        let received: Command = worker.recv().await.expect("recv cmd failed");
        assert_eq!(received.sequence, 10);

        let resp = Response::ok(received.sequence);
        worker.send(&resp).await.expect("send resp failed");

        // Supervisor receives response
        let received_resp: Response = supervisor.recv().await.expect("recv resp failed");
        assert_eq!(received_resp.sequence, 10);
    }

    #[tokio::test]
    async fn test_multiple_messages() {
        let (fd1, fd2) = make_socketpair();
        let mut sender = unsafe { CommandChannel::from_raw_fd(fd1).unwrap() };
        let mut receiver = unsafe { CommandChannel::from_raw_fd(fd2).unwrap() };

        for i in 0..10 {
            let cmd = Command::new(CommandType::Heartbeat, i);
            sender.send(&cmd).await.expect("send failed");
        }

        for i in 0..10 {
            let received: Command = receiver.recv().await.expect("recv failed");
            assert_eq!(received.sequence, i);
        }
    }

    #[tokio::test]
    async fn test_recv_timeout() {
        let (fd1, _fd2) = make_socketpair();
        let mut receiver = unsafe { CommandChannel::from_raw_fd(fd1).unwrap() };
        receiver.set_timeout(Duration::from_millis(50));

        let result: Result<Command, _> = receiver.recv().await;
        assert!(matches!(result, Err(ChannelError::Timeout)));
    }
}
