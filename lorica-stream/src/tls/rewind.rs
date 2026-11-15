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

//! The preamble replay adapter of a terminating stream (Story 12.4 D-f).
//!
//! The ClientHello reader has already taken the client's first bytes off
//! the socket. [`Rewind`] serves them again before the socket's own, so
//! rustls reads the exact hello the parser read, and whatever the client
//! sent after it, in order. Writes go straight to the socket.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A stream that reads `preamble` first, then `inner`.
#[derive(Debug)]
pub struct Rewind<S> {
    preamble: Vec<u8>,
    served: usize,
    inner: S,
}

impl<S> Rewind<S> {
    /// `inner`, with `preamble` read before anything it holds.
    pub fn new(preamble: Vec<u8>, inner: S) -> Rewind<S> {
        Rewind {
            preamble,
            served: 0,
            inner,
        }
    }

    /// Bytes of the preamble not read yet.
    pub fn pending(&self) -> usize {
        self.preamble.len() - self.served
    }

    /// The wrapped stream.
    pub fn get_ref(&self) -> &S {
        &self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Rewind<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.served < this.preamble.len() {
            let n = (this.preamble.len() - this.served).min(buf.remaining());
            buf.put_slice(&this.preamble[this.served..this.served + n]);
            this.served += n;
            if this.served == this.preamble.len() {
                // The ClientHello buffer is the pending phase's: once
                // replayed, it is released rather than held for the
                // connection's life.
                this.preamble = Vec::new();
                this.served = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Rewind<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn the_preamble_comes_first_then_the_stream_and_writes_pass_through() {
        let (mut peer, inner) = tokio::io::duplex(64);
        let mut rewind = Rewind::new(b"hello ".to_vec(), inner);
        assert_eq!(rewind.pending(), 6);
        peer.write_all(b"world").await.unwrap();
        peer.shutdown().await.unwrap();

        let mut small = [0u8; 4];
        rewind.read_exact(&mut small).await.unwrap();
        assert_eq!(&small, b"hell");
        assert_eq!(rewind.pending(), 2);
        let mut rest = Vec::new();
        rewind.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"o world");
        assert_eq!(rewind.pending(), 0);

        rewind.write_all(b"back").await.unwrap();
        rewind.shutdown().await.unwrap();
        let mut back = Vec::new();
        peer.read_to_end(&mut back).await.unwrap();
        assert_eq!(back, b"back");
    }
}
