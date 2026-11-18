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

//! The process's shutdown signal, for its periodic background loops.
//!
//! The exit path closes the shared task tracker and waits for it, so
//! that work in flight (a backend drain, a load test, a session write)
//! finishes before the process exits. A periodic loop (the blocklist
//! refresh, the certificate checks, the prunes) is not work in flight:
//! it never ends by itself, and while it was tracked every exit waited
//! out the whole drain timeout for it. Each such loop waits on [`tick`]
//! or [`sleep`] instead of the bare timer, so it ends as soon as
//! [`begin`] is called.
//!
//! One signal per process, because a process stops once: the stop and
//! upgrade paths call [`begin`], nothing else does.
//!
//! The same signal ends the API servers' connections ([`serve_until`],
//! [`going_away`]): once a hot upgrade's old generation has begun its
//! shutdown, no client keeps talking to the outgoing binary through a
//! keep-alive connection or a WebSocket (Story 12.11 D-b).

use std::future::Future;
use std::pin::Pin;
use std::sync::LazyLock;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

static SHUTDOWN: LazyLock<CancellationToken> = LazyLock::new(CancellationToken::new);

/// Start the process's shutdown: every loop waiting on [`tick`],
/// [`sleep`] or [`token`] ends.
pub fn begin() {
    SHUTDOWN.cancel();
}

/// A handle on the shutdown signal, for a loop that selects on it.
pub fn token() -> CancellationToken {
    SHUTDOWN.clone()
}

/// Wait for the next tick of `ticker`. Returns `false` instead once the
/// shutdown has begun, so a loop reads `while shutdown::tick(&mut t).await`.
pub async fn tick(ticker: &mut tokio::time::Interval) -> bool {
    tick_on(ticker, &SHUTDOWN).await
}

/// [`tick`] on `shutdown` instead of the process's signal, for a loop
/// its caller hands the token to: the process passes [`token`], a test
/// its own.
pub async fn tick_on(ticker: &mut tokio::time::Interval, shutdown: &CancellationToken) -> bool {
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => false,
        _ = ticker.tick() => true,
    }
}

/// Sleep for `duration`. Returns `false` instead once the shutdown has
/// begun.
pub async fn sleep(duration: Duration) -> bool {
    tokio::select! {
        biased;
        _ = SHUTDOWN.cancelled() => false,
        _ = tokio::time::sleep(duration) => true,
    }
}

/// Drive the served connection `conn` to its end. Once `shutdown` is
/// cancelled, `graceful` asks it to end (an HTTP/1 connection finishes
/// the response in flight then closes, an idle keep-alive one closes at
/// once, HTTP/2 sends `GOAWAY`) and its end is awaited. The API servers
/// pass [`token`]; a test passes its own.
pub async fn serve_until<F: Future>(
    mut conn: Pin<&mut F>,
    shutdown: &CancellationToken,
    graceful: impl FnOnce(Pin<&mut F>),
) -> F::Output {
    tokio::select! {
        served = conn.as_mut() => served,
        _ = shutdown.cancelled() => {
            graceful(conn.as_mut());
            conn.await
        }
    }
}

/// The close frame a WebSocket is sent when the process stops serving
/// it: 1001, going away.
pub fn going_away() -> axum::extract::ws::Message {
    axum::extract::ws::Message::Close(Some(axum::extract::ws::CloseFrame {
        code: axum::extract::ws::close_code::AWAY,
        reason: "server shutting down".into(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::ws::WebSocketUpgrade;
    use axum::routing::get;
    use axum::Router;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as HyperAutoBuilder;
    use hyper_util::service::TowerToHyperService;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const READ_BOUND: Duration = Duration::from_secs(5);

    /// Serve `router` on a local port the way the API servers serve each
    /// connection, ending them on `shutdown`.
    async fn serve(router: Router, shutdown: CancellationToken) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a local port");
        let addr = listener.local_addr().expect("its address");
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let service = TowerToHyperService::new(router.clone());
                let shutdown = shutdown.clone();
                tokio::spawn(async move {
                    let builder = HyperAutoBuilder::new(TokioExecutor::new());
                    let connection =
                        builder.serve_connection_with_upgrades(TokioIo::new(tcp), service);
                    tokio::pin!(connection);
                    let _ = serve_until(connection, &shutdown, |c| c.graceful_shutdown()).await;
                });
            }
        });
        addr
    }

    /// Read until the peer closes, within [`READ_BOUND`].
    async fn read_to_close(stream: &mut TcpStream) -> String {
        let mut out = Vec::new();
        tokio::time::timeout(READ_BOUND, stream.read_to_end(&mut out))
            .await
            .expect("the server closes the connection")
            .expect("a clean close");
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Read until what arrived holds `marker`, within [`READ_BOUND`] per
    /// read.
    async fn read_until(stream: &mut TcpStream, marker: &str) -> String {
        let mut out = Vec::new();
        let mut buf = [0u8; 1024];
        while !String::from_utf8_lossy(&out).contains(marker) {
            let n = tokio::time::timeout(READ_BOUND, stream.read(&mut buf))
                .await
                .expect("the server answers")
                .expect("a read");
            assert!(n > 0, "closed before `{marker}`");
            out.extend_from_slice(&buf[..n]);
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn router(shutdown: CancellationToken) -> Router {
        let (logs, _) = tokio::sync::broadcast::channel::<crate::logs::LogEntry>(4);
        Router::new()
            .route("/fast", get(|| async { "fast-body" }))
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    "slow-body"
                }),
            )
            .route(
                "/ws",
                get(move |ws: WebSocketUpgrade| {
                    let rx = logs.subscribe();
                    let shutdown = shutdown.clone();
                    async move {
                        ws.on_upgrade(move |socket| {
                            crate::logs::handle_log_stream(socket, rx, shutdown)
                        })
                    }
                }),
            )
    }

    #[tokio::test]
    async fn the_shutdown_closes_an_idle_keep_alive_and_lets_an_in_flight_request_finish() {
        let shutdown = CancellationToken::new();
        let addr = serve(router(shutdown.clone()), shutdown.clone()).await;

        let mut idle = TcpStream::connect(addr).await.unwrap();
        idle.write_all(b"GET /fast HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
        read_until(&mut idle, "fast-body").await;
        let mut busy = TcpStream::connect(addr).await.unwrap();
        busy.write_all(b"GET /slow HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        shutdown.cancel();

        assert_eq!(read_to_close(&mut idle).await, "", "the keep-alive closes");
        let answer = read_to_close(&mut busy).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(
            answer.ends_with("slow-body"),
            "the request in flight completes: {answer}"
        );
    }

    #[tokio::test]
    async fn the_shutdown_sends_a_websocket_its_going_away_close_frame() {
        let shutdown = CancellationToken::new();
        let addr = serve(router(shutdown.clone()), shutdown.clone()).await;
        let mut ws = TcpStream::connect(addr).await.unwrap();
        ws.write_all(
            b"GET /ws HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .await
        .unwrap();
        let head = read_until(&mut ws, "\r\n\r\n").await;
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");

        shutdown.cancel();

        let mut frame = [0u8; 4];
        tokio::time::timeout(READ_BOUND, ws.read_exact(&mut frame))
            .await
            .expect("a frame arrives")
            .expect("a whole frame head");
        assert_eq!(frame[0], 0x88, "a final close frame");
        let code = u16::from_be_bytes([frame[2], frame[3]]);
        assert_eq!(code, axum::extract::ws::close_code::AWAY);
    }
}
