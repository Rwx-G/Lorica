// Copyright 2026 Cloudflare, Inc.
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

//! The abstraction and implementation interface for service application logic

pub mod http_app;
#[cfg(feature = "prometheus")]
pub mod prometheus_http_app;

use crate::server::ShutdownWatch;
use async_trait::async_trait;
use log::{debug, error};
use std::any::Any;
use std::sync::Arc;
use std::time::Duration;

use crate::protocols::http::v2::server;
use crate::protocols::http::ServerSession;
use crate::protocols::Digest;
use crate::protocols::Stream;
use crate::protocols::ALPN;

// https://datatracker.ietf.org/doc/html/rfc9113#section-3.4
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// HTTP/1.x keepalive takes whole seconds and reads `0` as "no bound",
/// so a sub-second idle timeout must round up rather than truncate.
fn keepalive_seconds(idle: Duration) -> u64 {
    let whole = idle.as_secs();
    if idle.subsec_nanos() > 0 {
        whole + 1
    } else {
        whole.max(1)
    }
}

#[async_trait]
/// This trait defines the interface of a transport layer (TCP or TLS) application.
pub trait ServerApp {
    /// Whenever a new connection is established, this function will be called with the established
    /// [`Stream`] object provided.
    ///
    /// The application can do whatever it wants with the `session`.
    ///
    /// After processing the `session`, if the `session`'s connection is reusable, This function
    /// can return it to the service by returning `Some(session)`. The returned `session` will be
    /// fed to another [`Self::process_new()`] for another round of processing.
    /// If not reusable, `None` should be returned.
    ///
    /// The `shutdown` argument will change from `false` to `true` when the server receives a
    /// signal to shutdown. This argument allows the application to react accordingly.
    async fn process_new(
        self: &Arc<Self>,
        mut session: Stream,
        // TODO: make this ShutdownWatch so that all task can await on this event
        shutdown: &ShutdownWatch,
    ) -> Option<Stream>;

    /// This callback will be called once after the service stops listening to its endpoints.
    async fn cleanup(&self) {}
}
#[non_exhaustive]
#[derive(Default)]
/// HTTP Server options that control how the server handles some transport types.
pub struct HttpServerOptions {
    /// Allow HTTP/2 for plaintext.
    pub h2c: bool,

    /// Allow proxying CONNECT requests when handling HTTP traffic.
    ///
    /// When disabled, CONNECT requests are rejected with 405 by proxy services.
    pub allow_connect_method_proxying: bool,

    #[doc(hidden)]
    pub force_custom: bool,

    /// Maximum number of requests that this connection will handle. This is
    /// equivalent to [Nginx's keepalive requests](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#keepalive_requests)
    /// which says:
    ///
    /// > Closing connections periodically is necessary to free per-connection
    /// > memory allocations. Therefore, using too high maximum number of
    /// > requests could result in excessive memory usage and not recommended.
    ///
    /// Unlike nginx, the default behavior here is _no limit_.
    pub keepalive_request_limit: Option<u32>,

    /// If set, close a downstream HTTP/2 connection that has been idle
    /// for this duration.
    ///
    /// Default: `None`
    pub h2_idle_timeout: Option<Duration>,
}

/// Settings persisted across HTTP/1.x keepalive requests on the same downstream connection.
///
/// In addition to framework-managed keepalive parameters, this struct can carry an optional
/// user-defined context via [`set_user_context`](Self::set_user_context). The proxy layer
/// populates this through `ProxyHttp::persist_connection_context`
/// and delivers it to the next request through `ProxyHttp::on_connection_reuse`.
#[derive(Debug)]
pub struct HttpPersistentSettings {
    keepalive_timeout: Option<u64>,
    keepalive_reuses_remaining: Option<u32>,
    /// User-defined context to carry to the next request on this connection.
    user_context: Option<Box<dyn Any + Send + Sync>>,
}

impl HttpPersistentSettings {
    pub fn for_session(session: &ServerSession) -> Self {
        HttpPersistentSettings {
            keepalive_timeout: session.get_keepalive(),
            keepalive_reuses_remaining: session.get_keepalive_reuses_remaining(),
            user_context: None,
        }
    }

    /// Set a user-defined context to be carried to the next request on this connection.
    pub fn set_user_context(&mut self, ctx: Box<dyn Any + Send + Sync>) {
        self.user_context = Some(ctx);
    }

    /// Take the user-defined context, if any.
    pub fn take_user_context(&mut self) -> Option<Box<dyn Any + Send + Sync>> {
        self.user_context.take()
    }

    pub fn apply_to_session(self, session: &mut ServerSession) {
        let Self {
            keepalive_timeout,
            mut keepalive_reuses_remaining,
            user_context,
        } = self;

        // Reduce the number of times the connection for this session can be
        // reused by one. A session with reuse count of zero won't be reused
        if let Some(reuses) = keepalive_reuses_remaining.as_mut() {
            *reuses = reuses.saturating_sub(1);
        }

        session.set_keepalive(keepalive_timeout);
        session.set_keepalive_reuses_remaining(keepalive_reuses_remaining);

        // Carry user context into the session for the proxy layer to consume
        session.set_connection_user_context(user_context);
    }
}

#[derive(Debug)]
pub struct ReusedHttpStream {
    stream: Stream,
    persistent_settings: Option<HttpPersistentSettings>,
}

impl ReusedHttpStream {
    pub fn new(stream: Stream, persistent_settings: Option<HttpPersistentSettings>) -> Self {
        ReusedHttpStream {
            stream,
            persistent_settings,
        }
    }

    pub fn consume(self) -> (Stream, Option<HttpPersistentSettings>) {
        (self.stream, self.persistent_settings)
    }
}

/// This trait defines the interface of an HTTP application.
#[async_trait]
pub trait HttpServerApp {
    /// Similar to the [`ServerApp`], this function is called whenever a new HTTP session is established.
    ///
    /// After successful processing, [`ServerSession::finish()`] can be called to return an optionally reusable
    /// connection back to the service. The caller needs to make sure that the connection is in a reusable state
    /// i.e., no error or incomplete read or write headers or bodies. Otherwise a `None` should be returned.
    async fn process_new_http(
        self: &Arc<Self>,
        mut session: ServerSession,
        // TODO: make this ShutdownWatch so that all task can await on this event
        shutdown: &ShutdownWatch,
    ) -> Option<ReusedHttpStream>;

    /// Provide options on how HTTP/2 connection should be established. This function will be called
    /// every time a new HTTP/2 **connection** needs to be established.
    ///
    /// A `None` means to use the built-in default options. See [`server::H2Options`] for more details.
    fn h2_options(&self) -> Option<server::H2Options> {
        None
    }

    /// Provide HTTP server options used to override default behavior. This function will be called
    /// every time a new connection is processed.
    ///
    /// A `None` means no server options will be applied.
    fn server_options(&self) -> Option<&HttpServerOptions> {
        None
    }

    /// How long a downstream connection may sit idle: an HTTP/1.x
    /// connection waiting for its next request, an HTTP/2 connection
    /// with no stream in flight. Called every time a new connection is
    /// processed and before every HTTP/1.x keepalive reuse, so a value
    /// read from live configuration reaches the next wait without a
    /// restart.
    ///
    /// `None` keeps the built-in behaviour: 60 s before the first
    /// HTTP/1.x request, no bound between later ones unless the
    /// application sets one per request, and
    /// [`HttpServerOptions::h2_idle_timeout`] for HTTP/2. HTTP/1.x
    /// keepalive counts in whole seconds, so a `Some` value is rounded
    /// up to at least one second there.
    ///
    /// The bound applies only while waiting for a request. A response
    /// in progress, including a long poll or an event stream, and an
    /// upgraded connection (`101 Switching Protocols`, which is never
    /// reused) are not idle in this sense and are not cut by it.
    fn downstream_idle_timeout(&self) -> Option<Duration> {
        None
    }

    /// How long an HTTP/1.x client may take to send a whole request
    /// header, from its first byte to the end of the header block. Past
    /// it, [`ServerSession::read_request()`] fails with `ReadTimedout`.
    /// Called before every HTTP/1.x request, the first one and every
    /// keepalive reuse, so a value read from live configuration reaches
    /// the next request without a restart.
    ///
    /// `None` keeps the built-in behaviour: only each gap between bytes is
    /// bounded (by the keepalive or read timeout), so a client sending one
    /// byte per gap holds the read indefinitely.
    ///
    /// The wait before the first byte is not part of the header: it stays
    /// bounded by [`Self::downstream_idle_timeout`]. HTTP/2 is not
    /// affected: a stream reaches the application only once its header
    /// block is complete, and a connection with no complete stream is
    /// bounded by its idle timeout.
    fn downstream_header_timeout(&self) -> Option<Duration> {
        None
    }

    async fn http_cleanup(&self) {}

    #[doc(hidden)]
    async fn process_custom_session(
        self: Arc<Self>,
        _stream: Stream,
        _shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        None
    }
}

#[async_trait]
impl<T> ServerApp for T
where
    T: HttpServerApp + Send + Sync + 'static,
{
    async fn process_new(
        self: &Arc<Self>,
        mut stream: Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        let mut h2c = self.server_options().as_ref().map_or(false, |o| o.h2c);
        let custom = self
            .server_options()
            .as_ref()
            .map_or(false, |o| o.force_custom);

        // h2c is for cleartext connections; on TLS, ALPN handles protocol negotiation.
        // Otherwise, h2c stays true on TLS streams, forcing HTTP/1.1 clients into HTTP/2
        if stream.get_ssl_digest().is_some() {
            h2c = false;
        }
        // try to read h2 preface
        else if h2c && !custom {
            let mut buf = [0u8; H2_PREFACE.len()];
            let peeked = stream
                .try_peek(&mut buf)
                .await
                .map_err(|e| {
                    // this error is normal when h1 reuse and close the connection
                    debug!("Read error while peeking h2c preface {e}");
                    e
                })
                .ok()?;
            // not all streams support peeking
            if peeked {
                // turn off h2c (use h1) if h2 preface doesn't exist
                h2c = buf == H2_PREFACE;
            }
        }
        if h2c || matches!(stream.selected_alpn_proto(), Some(ALPN::H2)) {
            // create a shared connection digest
            let digest = Arc::new(Digest {
                ssl_digest: stream.get_ssl_digest(),
                // TODO: log h2 handshake time
                timing_digest: stream.get_timing_digest(),
                proxy_digest: stream.get_proxy_digest(),
                socket_digest: stream.get_socket_digest(),
            });

            // Lorica: the app's idle timeout, read per connection, wins
            // over the static option.
            let h2_idle_timeout = self
                .downstream_idle_timeout()
                .or_else(|| self.server_options().and_then(|o| o.h2_idle_timeout));
            let h2_options = self.h2_options();
            // Lorica: the handshake completes only once the client has sent
            // its connection preface, so a client that goes silent after TLS
            // would hold the connection here before the accept loop's idle
            // timeout could start. The same bound applies; with none set this
            // waits as upstream does.
            let handshake = server::handshake(stream, h2_options);
            let handshaken = match h2_idle_timeout {
                Some(idle) => match lorica_timeout::timeout(idle, handshake).await {
                    Ok(handshaken) => handshaken,
                    Err(_) => {
                        debug!("H2 connection preface not received within {idle:?}");
                        return None;
                    }
                },
                None => handshake.await,
            };
            let h2_conn = match handshaken {
                Err(e) => {
                    error!("H2 handshake error {e}");
                    return None;
                }
                Ok(c) => c,
            };

            // The accept-loop body - including the graceful-shutdown state
            // machine - lives in `server::accept_downstream_sessions` so that
            // the same code path is exercised by tests in `protocols::http::v2`.
            let app = self.clone();
            let shutdown_for_session = shutdown.clone();
            server::accept_downstream_sessions(
                h2_conn,
                digest,
                shutdown.clone(),
                h2_idle_timeout,
                |h2_stream, guard| {
                    let app = app.clone();
                    let shutdown = shutdown_for_session.clone();
                    lorica_runtime::current_handle().spawn(async move {
                        // hold `guard` for the session's lifetime so the accept
                        // loop's idle timeout sees this connection as busy.
                        let _guard = guard;
                        // Note, `PersistentSettings` not currently relevant for h2
                        app.process_new_http(ServerSession::new_http2(h2_stream), &shutdown)
                            .await;
                    });
                },
            )
            .await;
        } else if custom || matches!(stream.selected_alpn_proto(), Some(ALPN::Custom(_))) {
            return self.clone().process_custom_session(stream, shutdown).await;
        } else {
            // No ALPN or ALPN::H1 and h2c was not configured, fallback to HTTP/1.1
            let mut session = ServerSession::new_http1(stream);
            if *shutdown.borrow() {
                // stop downstream from reusing if this service is shutting down soon
                session.set_keepalive(None);
            } else {
                // Lorica: the app's idle timeout replaces the fixed 60 s.
                let first_wait = self.downstream_idle_timeout().map_or(60, keepalive_seconds);
                session.set_keepalive(Some(first_wait));
            }
            session.set_keepalive_reuses_remaining(
                self.server_options()
                    .and_then(|opts| opts.keepalive_request_limit),
            );
            // Lorica: asked per request, so a reload reaches the next one.
            session.set_header_timeout(self.downstream_header_timeout());

            let mut result = self.process_new_http(session, shutdown).await;
            while let Some((stream, persistent_settings)) = result.map(|r| r.consume()) {
                let mut session = ServerSession::new_http1(stream);
                if let Some(persistent_settings) = persistent_settings {
                    persistent_settings.apply_to_session(&mut session);
                }
                // Lorica: `read_request` turns every HTTP/1.1 request without
                // `Connection: close` into an unbounded keepalive
                // (`Some(0)`), and that is what the persistent settings
                // carry here. Only that case is replaced: a bound the
                // application chose for this connection is kept.
                if session.get_keepalive() == Some(0) {
                    if let Some(idle) = self.downstream_idle_timeout() {
                        session.set_keepalive(Some(keepalive_seconds(idle)));
                    }
                }
                session.set_header_timeout(self.downstream_header_timeout());

                result = self.process_new_http(session, shutdown).await;
            }
        }
        None
    }

    async fn cleanup(&self) {
        self.http_cleanup().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test::io::Builder;

    #[test]
    fn test_persistent_settings_user_context_roundtrip() {
        // Create a mock H1 session
        let mock_io = Builder::new().build();
        let mut session = ServerSession::new_http1(Box::new(mock_io));
        session.set_keepalive(Some(60));

        // Snapshot settings (no user context yet)
        let mut settings = HttpPersistentSettings::for_session(&session);
        assert!(settings.take_user_context().is_none());

        // Set user context
        settings.set_user_context(Box::new(123u64));

        // Apply to a fresh session -- user context should transfer
        let mock_io2 = Builder::new().build();
        let mut session2 = ServerSession::new_http1(Box::new(mock_io2));
        settings.apply_to_session(&mut session2);

        // The user context should now be on the session
        let ctx = session2.take_connection_user_context();
        assert!(ctx.is_some());
        let val = ctx.unwrap().downcast::<u64>().unwrap();
        assert_eq!(*val, 123u64);

        // Keepalive should also have been applied
        assert_eq!(session2.get_keepalive(), Some(60));
    }

    #[test]
    fn test_persistent_settings_no_user_context_by_default() {
        let mock_io = Builder::new().build();
        let mut session = ServerSession::new_http1(Box::new(mock_io));
        session.set_keepalive(Some(30));

        let settings = HttpPersistentSettings::for_session(&session);

        let mock_io2 = Builder::new().build();
        let mut session2 = ServerSession::new_http1(Box::new(mock_io2));
        settings.apply_to_session(&mut session2);

        // No user context should be present
        assert!(session2.take_connection_user_context().is_none());
        // Keepalive should still work
        assert_eq!(session2.get_keepalive(), Some(30));
    }

    #[test]
    fn keepalive_seconds_rounds_up_and_never_reaches_zero() {
        assert_eq!(keepalive_seconds(Duration::from_secs(75)), 75);
        assert_eq!(keepalive_seconds(Duration::from_millis(1500)), 2);
        assert_eq!(keepalive_seconds(Duration::from_millis(100)), 1);
        // `0` would mean "no bound" to the HTTP/1.x session.
        assert_eq!(keepalive_seconds(Duration::ZERO), 1);
    }

    mod idle_timeout {
        use super::super::*;
        use bytes::Bytes;
        use lorica_http::ResponseHeader;
        use std::time::Instant;
        use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
        use tokio::sync::watch;

        /// Answers every HTTP/1.x request `200 ok` and hands the
        /// connection back for reuse, the way `lorica-proxy` does.
        struct IdleApp {
            idle: Option<Duration>,
            options: HttpServerOptions,
        }

        #[async_trait]
        impl HttpServerApp for IdleApp {
            async fn process_new_http(
                self: &Arc<Self>,
                mut session: ServerSession,
                _shutdown: &ShutdownWatch,
            ) -> Option<ReusedHttpStream> {
                if !session.read_request().await.ok()? {
                    return None;
                }
                let mut resp = ResponseHeader::build(200, None).ok()?;
                resp.insert_header("Content-Length", "2").ok()?;
                session.write_response_header(Box::new(resp)).await.ok()?;
                session
                    .write_response_body(Bytes::from_static(b"ok"), true)
                    .await
                    .ok()?;
                let settings = HttpPersistentSettings::for_session(&session);
                session
                    .finish()
                    .await
                    .ok()
                    .flatten()
                    .map(|s| ReusedHttpStream::new(s, Some(settings)))
            }

            fn server_options(&self) -> Option<&HttpServerOptions> {
                Some(&self.options)
            }

            fn downstream_idle_timeout(&self) -> Option<Duration> {
                self.idle
            }
        }

        fn http1_app(idle: Option<Duration>) -> Arc<IdleApp> {
            Arc::new(IdleApp {
                idle,
                options: HttpServerOptions::default(),
            })
        }

        async fn read_one_response(client: &mut tokio::io::DuplexStream) {
            let mut buf = Vec::new();
            let mut scratch = [0u8; 1024];
            while !buf.ends_with(b"\r\n\r\nok") {
                let n = client.read(&mut scratch).await.expect("read response");
                assert!(n > 0, "server closed before answering");
                buf.extend_from_slice(&scratch[..n]);
            }
        }

        #[tokio::test]
        async fn an_idle_http1_keepalive_connection_is_closed_after_the_timeout() {
            let (mut client, server) = duplex(65536);
            let (_shutdown_tx, shutdown) = watch::channel(false);
            let app = http1_app(Some(Duration::from_secs(1)));
            let started = Instant::now();
            let serving =
                tokio::spawn(async move { app.process_new(Box::new(server), &shutdown).await });

            client
                .write_all(b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")
                .await
                .unwrap();
            read_one_response(&mut client).await;

            let result = lorica_timeout::timeout(Duration::from_secs(5), serving).await;
            assert!(result.is_ok(), "an idle keepalive connection stayed open");
            assert!(
                started.elapsed() >= Duration::from_secs(1),
                "closed before the idle timeout"
            );
            let mut rest = [0u8; 16];
            assert_eq!(client.read(&mut rest).await.unwrap(), 0, "EOF after close");
        }

        #[tokio::test]
        async fn requests_inside_the_window_keep_the_http1_connection_open() {
            let (mut client, server) = duplex(65536);
            let (_shutdown_tx, shutdown) = watch::channel(false);
            let app = http1_app(Some(Duration::from_secs(1)));
            let serving =
                tokio::spawn(async move { app.process_new(Box::new(server), &shutdown).await });

            // Three requests half a timeout apart span three timeouts in
            // total; the wait restarts at every request.
            for _ in 0..3 {
                client
                    .write_all(b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")
                    .await
                    .unwrap();
                read_one_response(&mut client).await;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            assert!(!serving.is_finished(), "an active connection was closed");
            drop(client);
            let _ = lorica_timeout::timeout(Duration::from_secs(5), serving).await;
        }

        #[tokio::test]
        async fn without_an_idle_timeout_reuse_keeps_the_unbounded_default() {
            let (mut client, server) = duplex(65536);
            let (_shutdown_tx, shutdown) = watch::channel(false);
            let app = http1_app(None);
            let serving =
                tokio::spawn(async move { app.process_new(Box::new(server), &shutdown).await });

            client
                .write_all(b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")
                .await
                .unwrap();
            read_one_response(&mut client).await;
            tokio::time::sleep(Duration::from_millis(1500)).await;
            assert!(!serving.is_finished(), "the fork default changed");
            drop(client);
            let _ = lorica_timeout::timeout(Duration::from_secs(5), serving).await;
        }

        #[tokio::test]
        async fn an_idle_http2_connection_takes_the_app_timeout_over_the_options() {
            let (mut client, server) = duplex(65536);
            let (_shutdown_tx, shutdown) = watch::channel(false);
            // h2c over a stream that cannot peek: the preface decides. The
            // options' own timeout would hold the connection for a minute.
            let app = Arc::new(IdleApp {
                idle: Some(Duration::from_millis(200)),
                options: HttpServerOptions {
                    h2c: true,
                    h2_idle_timeout: Some(Duration::from_secs(60)),
                    ..Default::default()
                },
            });
            let serving =
                tokio::spawn(async move { app.process_new(Box::new(server), &shutdown).await });

            client.write_all(H2_PREFACE).await.unwrap();
            // An empty SETTINGS frame (length 0, type 0x4, stream 0), then
            // the ACK of the server's (flag 0x1). No stream is opened.
            client
                .write_all(&[0, 0, 0, 0x4, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            client
                .write_all(&[0, 0, 0, 0x4, 0x1, 0, 0, 0, 0])
                .await
                .unwrap();
            let drain = tokio::spawn(async move {
                let mut scratch = [0u8; 1024];
                while matches!(client.read(&mut scratch).await, Ok(n) if n > 0) {}
            });

            let result = lorica_timeout::timeout(Duration::from_secs(5), serving).await;
            assert!(result.is_ok(), "an idle HTTP/2 connection stayed open");
            drain.abort();
        }

        /// The h2c branch over a stream that cannot peek is the same
        /// handshake a TLS connection that negotiated `h2` reaches, minus
        /// the TLS, so a client that sends no preface stands in for one
        /// that went silent after its TLS handshake.
        fn h2c_app(idle: Option<Duration>) -> Arc<IdleApp> {
            Arc::new(IdleApp {
                idle,
                options: HttpServerOptions {
                    h2c: true,
                    ..Default::default()
                },
            })
        }

        #[tokio::test]
        async fn an_http2_client_that_never_sends_its_preface_is_closed() {
            let (mut client, server) = duplex(65536);
            let (_shutdown_tx, shutdown) = watch::channel(false);
            let app = h2c_app(Some(Duration::from_millis(300)));
            let started = Instant::now();
            let serving =
                tokio::spawn(async move { app.process_new(Box::new(server), &shutdown).await });

            let result = lorica_timeout::timeout(Duration::from_secs(5), serving).await;
            assert!(result.is_ok(), "a silent HTTP/2 client held the connection");
            assert!(
                started.elapsed() >= Duration::from_millis(300),
                "closed before the idle timeout"
            );
            // Whatever the server queued (its SETTINGS) drains, then EOF.
            let eof = lorica_timeout::timeout(Duration::from_secs(2), async {
                let mut scratch = [0u8; 1024];
                while matches!(client.read(&mut scratch).await, Ok(n) if n > 0) {}
            })
            .await;
            assert!(eof.is_ok(), "the connection was not closed");
        }

        #[tokio::test]
        async fn without_an_idle_timeout_the_preface_wait_keeps_the_upstream_default() {
            let (client, server) = duplex(65536);
            let (_shutdown_tx, shutdown) = watch::channel(false);
            let app = h2c_app(None);
            let serving =
                tokio::spawn(async move { app.process_new(Box::new(server), &shutdown).await });

            tokio::time::sleep(Duration::from_millis(500)).await;
            assert!(!serving.is_finished(), "the fork default changed");
            drop(client);
            let _ = lorica_timeout::timeout(Duration::from_secs(5), serving).await;
        }
    }
}
