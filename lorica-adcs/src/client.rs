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

//! The calls the rest of Lorica makes: a [`CesSession`], which
//! authenticates once and then enrolls or tests as often as one API
//! operation or one renewal tick needs, and the one-shot [`enroll`] and
//! [`test_connection`] over a session of one request.
//!
//! Each request is one authenticated exchange with CES:
//!
//! 1. on the session's first request only, an unauthenticated `GET`, to
//!    obtain the 401 `Negotiate` challenge and the server certificate
//!    the channel binding is computed from; from then on every
//!    connection of the session must present that same certificate (see
//!    [`crate::tls`]);
//! 2. the initial SPNEGO token, bound to that certificate (RFC 5929
//!    `tls-server-end-point`), on a blocking task; the session's first
//!    request acquires the ticket there, and every later one reuses it;
//! 3. the request with `Authorization: Negotiate <token>`;
//! 4. the server's `WWW-Authenticate: Negotiate <token>`, whatever the
//!    status, fed back to the context, which must then be complete, with
//!    Kerberos as its mechanism and mutual authentication in its flags,
//!    and have nothing left to send: that token is the only proof the
//!    server holds the service key (Epic 13 D2, Story 13.1 AC #5).

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use reqwest::header::{HeaderMap, AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use reqwest::{Client, Response, StatusCode};

use crate::binding::channel_binding;
use crate::gss::{GssBackend, GssContext, GssFailure, LibGssapi, Negotiated, TicketFailure};
use crate::krb5conf::Realm;
use crate::secret::Secret;
use crate::target::{CesEndpoint, Principal};
use crate::tls::{client_config, CertificatePin};
use crate::wstep::request::{build_request, new_message_id, SOAP_CONTENT_TYPE};
use crate::wstep::response::{parse_response, EnrollmentResponse};
use crate::AdcsError;

/// What an enrollment returns: the authority's answer, issued, pending,
/// denied or another fault. The same type the response parser gives, so
/// the two cannot drift apart.
pub type EnrollOutcome = EnrollmentResponse;

/// The step names of the two HTTP legs, as errors display them.
const PROBE: &str = "unauthenticated request";
const AUTHENTICATED: &str = "authenticated request";

/// A CES answer is a leaf and a CMC set of a few certificates, tens of
/// kilobytes; a body past this is not one and is refused before it costs
/// memory.
const MAX_BODY_BYTES: usize = 256 * 1024;

/// The bounds of one request (Epic 13 D8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CesTimeouts {
    /// TCP and TLS connection establishment, per connection.
    pub connect: Duration,
    /// The longest wait for the next bytes of a response.
    pub read: Duration,
    /// One whole request of a session, ticket acquisition included when
    /// it is the session's first.
    ///
    /// It bounds the HTTP legs, and it is checked after each GSS-API
    /// step, but it never interrupts one: a step is synchronous FFI on a
    /// blocking thread, which tokio cannot stop, and abandoning its task
    /// would leave the thread spending KDC attempts after the operation
    /// had returned, beside the next one (Epic 13 D8, D15). So a request
    /// whose deadline passes during a step returns [`AdcsError::Timeout`]
    /// only once that step has returned, and may therefore outlast this
    /// bound by one step. What bounds a step is MIT krb5's own schedule:
    /// on MIT before 1.22 nothing in the generated `krb5.conf` bounds a
    /// KDC exchange (a silent KDC was measured to hold one for about
    /// 27 s); from 1.22 its `request_timeout` does (see
    /// [`crate::KdcTiming`]).
    ///
    /// The default sits well above one silent-KDC cycle, so a single
    /// unreachable KDC is reported as such rather than as a timeout.
    pub operation: Duration,
}

impl Default for CesTimeouts {
    fn default() -> CesTimeouts {
        CesTimeouts {
            connect: Duration::from_secs(10),
            read: Duration::from_secs(30),
            operation: Duration::from_secs(120),
        }
    }
}

/// How to reach and authenticate to one authority's CES.
///
/// The KDCs are not here: MIT krb5 reads them from the generated
/// `krb5.conf` that `KRB5_CONFIG` points at (see
/// [`crate::krb5_config_path`]), and GSS-API offers no way to pass them
/// per call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CesParams {
    /// The CES endpoint, under the rules of [`CesEndpoint::new`], for
    /// example
    /// `https://ces.corp.example.org/<CAName>_CES_Kerberos/service.svc/CES`.
    pub endpoint: String,
    /// The service account's realm.
    pub realm: Realm,
    /// The service account, under the rules of [`Principal::new`].
    pub principal: String,
    /// When set, the PEM certificates that alone are trusted for the
    /// endpoint's TLS certificate, in place of the system and webpki
    /// roots (Epic 13 D12).
    pub trust_bundle_pem: Option<String>,
    /// The bounds of each request.
    pub timeouts: CesTimeouts,
}

/// An authenticated conversation with one authority's CES: one ticket,
/// one HTTPS client, one pinned server certificate, for as many requests
/// as one API operation or one renewal tick makes (Epic 13 D15: one
/// ticket per tick).
///
/// A session must not outlive that operation or that tick (Epic 13 D3:
/// no ticket outlives an operation): it holds the service account's
/// ticket in memory and, until the ticket is acquired, a copy of the
/// password. Dropping the session releases both.
///
/// A session acquires at most one ticket. When acquisition fails, every
/// later request of the session fails with the same error without
/// contacting the KDC again, so a session can spend at most one failed
/// pre-authentication against the account.
///
/// Requests take `&mut self`, so they run one at a time. When a request
/// resolves, no GSS-API call of it is still running, a timeout included
/// (see [`CesTimeouts::operation`]). That holds only for a future driven
/// to completion: dropping it while a step runs detaches the step's
/// thread, so a caller that must not start another operation beside it
/// runs the session in a task it never cancels.
pub struct CesSession {
    inner: Session<LibGssapi>,
}

impl CesSession {
    /// Validates `params` and builds the session's HTTPS client. Nothing
    /// is sent and no ticket is asked for until the first request, so an
    /// endpoint that cannot be reached costs the account nothing.
    ///
    /// Reads the system trust store when `params` carries no bundle, on a
    /// blocking thread.
    pub async fn open(params: &CesParams, password: &Secret) -> Result<CesSession, AdcsError> {
        let inner: Session<LibGssapi> =
            Session::open(Arc::new(LibGssapi), params, password).await?;
        Ok(CesSession { inner })
    }

    /// Requests a certificate for the DER PKCS#10 `csr_der`.
    ///
    /// The request is an issuance at the authority: it is logged there
    /// and undone only by revocation. Errors name the step that failed;
    /// a pending, denied or failed request is an [`EnrollOutcome`], not
    /// an error.
    pub async fn enroll(&mut self, csr_der: &[u8]) -> Result<EnrollOutcome, AdcsError> {
        self.inner.enroll(csr_der).await
    }

    /// Checks that the session authenticates: the endpoint accepts the
    /// bound token and proves itself with its response token. Nothing is
    /// requested from the authority.
    ///
    /// MS-WSTEP has no operation that issues nothing, so the
    /// authenticated request is a `GET` of the endpoint. IIS
    /// authenticates every request before the service sees it, and the
    /// service then refuses the `GET` (400 or 405) with the response
    /// token already in the answer: the whole authentication is
    /// exercised while the WS-Trust layer, which only acts on a `POST`ed
    /// `RequestSecurityToken`, never is. Posting an envelope with an
    /// empty or invalid CSR would reach the authority and leave a failed
    /// request in its database.
    pub async fn test(&mut self) -> Result<(), AdcsError> {
        self.inner.test().await
    }
}

/// [`CesSession::enroll`] on a session of its own, for a caller that
/// makes one request.
pub async fn enroll(
    params: &CesParams,
    password: &Secret,
    csr_der: &[u8],
) -> Result<EnrollOutcome, AdcsError> {
    CesSession::open(params, password)
        .await?
        .enroll(csr_der)
        .await
}

/// [`CesSession::test`] on a session of its own: authenticates to the
/// CES described by `params` with `password` without requesting
/// anything.
pub async fn test_connection(params: &CesParams, password: &Secret) -> Result<(), AdcsError> {
    CesSession::open(params, password).await?.test().await
}

#[cfg(test)]
pub(crate) async fn enroll_with<B: GssBackend>(
    backend: Arc<B>,
    params: &CesParams,
    password: &Secret,
    csr_der: &[u8],
) -> Result<EnrollOutcome, AdcsError> {
    Session::open(backend, params, password)
        .await?
        .enroll(csr_der)
        .await
}

#[cfg(test)]
pub(crate) async fn test_connection_with<B: GssBackend>(
    backend: Arc<B>,
    params: &CesParams,
    password: &Secret,
) -> Result<(), AdcsError> {
    Session::open(backend, params, password).await?.test().await
}

/// The deadline of one request, as the instant every leg is measured
/// against (see [`CesTimeouts::operation`] for why a GSS-API step is
/// checked after it returns instead of being cut short).
struct Deadline {
    at: tokio::time::Instant,
    after: Duration,
}

impl Deadline {
    fn after(after: Duration) -> Deadline {
        Deadline {
            at: tokio::time::Instant::now() + after,
            after,
        }
    }

    /// An async leg, cancelled when the deadline passes. Only legs that
    /// own no blocking thread may go through here.
    async fn bound<T>(
        &self,
        leg: impl Future<Output = Result<T, AdcsError>>,
    ) -> Result<T, AdcsError> {
        tokio::time::timeout_at(self.at, leg)
            .await
            .map_err(|_| AdcsError::Timeout { after: self.after })?
    }

    /// The deadline, checked once a blocking step has returned. The
    /// step's own error is looked at first by the caller: a credential
    /// the KDC rejected must reach the breaker as such, not as a
    /// timeout, or the next operation would spend another attempt
    /// against the account.
    fn check(&self) -> Result<(), AdcsError> {
        if tokio::time::Instant::now() >= self.at {
            return Err(AdcsError::Timeout { after: self.after });
        }
        Ok(())
    }
}

/// Runs `task` on a blocking thread and always awaits its end.
async fn blocking<T: Send + 'static>(
    step: &'static str,
    task: impl FnOnce() -> T + Send + 'static,
) -> Result<T, AdcsError> {
    tokio::task::spawn_blocking(task)
        .await
        .map_err(|err: tokio::task::JoinError| AdcsError::GssTask {
            step,
            reason: err.to_string(),
        })
}

/// What is sent: the enrollment envelope, or a `GET` that IIS
/// authenticates (the probe, and the connection test's request).
enum Request {
    Enroll(String),
    Get,
}

/// The authenticated answer, after mutual authentication succeeded.
struct Answer {
    status: StatusCode,
    body: Vec<u8>,
}

/// A failed ticket acquisition, kept so every later request of the
/// session reports it again without asking the KDC.
struct Refusal {
    failure: TicketFailure,
    kdc_error_code: Option<u32>,
    minor_status: u32,
    message: String,
}

enum Credential<C> {
    /// No ticket yet: the password it will be acquired with.
    Pending(Secret),
    Acquired(C),
    Refused(Refusal),
}

/// The ticket the next initial token is built with.
enum TicketSource<C> {
    Held(C),
    Acquire(Secret),
}

/// [`CesSession`] over any GSS-API backend, so the exchange is tested
/// against a scripted one.
pub(crate) struct Session<B: GssBackend> {
    backend: Arc<B>,
    endpoint: CesEndpoint,
    principal: Principal,
    operation_timeout: Duration,
    http: Client,
    pin: Arc<CertificatePin>,
    /// The binding of the pinned certificate, once the probe met it.
    binding: Option<Vec<u8>>,
    credential: Credential<B::Credential>,
}

impl<B: GssBackend> Session<B> {
    pub(crate) async fn open(
        backend: Arc<B>,
        params: &CesParams,
        password: &Secret,
    ) -> Result<Session<B>, AdcsError> {
        let endpoint: CesEndpoint = CesEndpoint::new(&params.endpoint)?;
        let principal: Principal = Principal::new(&params.principal, &params.realm)?;
        let timeouts: CesTimeouts = params.timeouts;
        if timeouts.connect.is_zero() || timeouts.read.is_zero() || timeouts.operation.is_zero() {
            return Err(AdcsError::InvalidParams {
                reason: "every timeout must be above zero".to_owned(),
            });
        }
        let pin: Arc<CertificatePin> = Arc::new(CertificatePin::default());
        let bundle: Option<String> = params.trust_bundle_pem.clone();
        let verifier_pin: Arc<CertificatePin> = Arc::clone(&pin);
        let tls: rustls::ClientConfig = blocking("TLS configuration", move || {
            client_config(bundle.as_deref(), verifier_pin)
        })
        .await??;
        let http: Client = Client::builder()
            .use_preconfigured_tls(tls)
            .https_only(true)
            .tls_info(true)
            // A redirect would send the next request, and its token, to a
            // host the token was not bound to.
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(timeouts.connect)
            .read_timeout(timeouts.read)
            .build()
            .map_err(|err: reqwest::Error| AdcsError::Tls {
                reason: format!("the HTTPS client cannot be built: {err}"),
            })?;
        Ok(Session {
            backend,
            endpoint,
            principal,
            operation_timeout: timeouts.operation,
            http,
            pin,
            binding: None,
            credential: Credential::Pending(password.clone()),
        })
    }

    pub(crate) async fn enroll(&mut self, csr_der: &[u8]) -> Result<EnrollOutcome, AdcsError> {
        let envelope: String =
            build_request(self.endpoint.url().as_str(), &new_message_id(), csr_der)?;
        let deadline: Deadline = Deadline::after(self.operation_timeout);
        let answer: Answer = self.exchange(&Request::Enroll(envelope), &deadline).await?;
        if answer.status != StatusCode::OK && answer.status != StatusCode::INTERNAL_SERVER_ERROR {
            return Err(AdcsError::Http {
                stage: AUTHENTICATED,
                reason: format!(
                    "unexpected status {}; a CES answers 200 or a SOAP fault with 500",
                    answer.status
                ),
            });
        }
        let body: String = String::from_utf8(answer.body).map_err(|_| AdcsError::Http {
            stage: AUTHENTICATED,
            reason: "the response body is not UTF-8".to_owned(),
        })?;
        // Building the tree and walking the chain are CPU work bounded by
        // the body cap; they stay off the async workers.
        blocking("SOAP response", move || parse_response(&body)).await?
    }

    pub(crate) async fn test(&mut self) -> Result<(), AdcsError> {
        let deadline: Deadline = Deadline::after(self.operation_timeout);
        self.exchange(&Request::Get, &deadline).await?;
        Ok(())
    }

    async fn exchange(
        &mut self,
        request: &Request,
        deadline: &Deadline,
    ) -> Result<Answer, AdcsError> {
        let binding: Vec<u8> = match &self.binding {
            Some(binding) => binding.clone(),
            None => self.probe(deadline).await?,
        };
        let (context, token): (B::Context, Vec<u8>) =
            self.initial_token(&binding, deadline).await?;

        let response: Response = deadline
            .bound(self.send(request, Some(&token), AUTHENTICATED))
            .await?;
        let status: StatusCode = response.status();
        let server_token: Option<String> = negotiate_challenges(response.headers())
            .into_iter()
            .flatten()
            .next();
        let body: Vec<u8> = deadline.bound(read_body(AUTHENTICATED, response)).await?;
        if status == StatusCode::UNAUTHORIZED {
            return Err(AdcsError::Spnego {
                reason: "the endpoint refused the token with 401 (check the channel binding / \
                         Extended Protection, the SPN HTTP/<host>, the ticket)"
                    .to_owned(),
            });
        }
        let server_token: Vec<u8> = server_token
            .ok_or_else(|| AdcsError::MutualAuth {
                reason: format!(
                    "the endpoint answered {status} without a Negotiate response token"
                ),
            })
            .and_then(|encoded: String| {
                base64::engine::general_purpose::STANDARD
                    .decode(encoded.as_bytes())
                    .map_err(|err: base64::DecodeError| AdcsError::MutualAuth {
                        reason: format!("the response token is not base64: {err}"),
                    })
            })?;
        blocking("SPNEGO mutual authentication", move || {
            authenticate_server(context, &server_token, &binding)
        })
        .await??;
        deadline.check()?;
        Ok(Answer { status, body })
    }

    /// The unauthenticated `GET`: checks the endpoint asks for Negotiate,
    /// computes the binding of the certificate it presented, and pins
    /// that certificate for the rest of the session.
    async fn probe(&mut self, deadline: &Deadline) -> Result<Vec<u8>, AdcsError> {
        let probe: Response = deadline
            .bound(self.send(&Request::Get, None, PROBE))
            .await?;
        let server_certificate: Vec<u8> = probe
            .extensions()
            .get::<reqwest::tls::TlsInfo>()
            .and_then(reqwest::tls::TlsInfo::peer_certificate)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| AdcsError::Tls {
                reason: "the endpoint presented no certificate to bind the token to".to_owned(),
            })?;
        let probe_status: StatusCode = probe.status();
        let offers_negotiate: bool = !negotiate_challenges(probe.headers()).is_empty();
        let offered: String = offered_schemes(probe.headers());
        deadline.bound(read_body(PROBE, probe)).await?;
        if probe_status != StatusCode::UNAUTHORIZED {
            return Err(AdcsError::Spnego {
                reason: format!(
                    "the endpoint answered {probe_status} without credentials; a CES in Kerberos \
                     mode answers 401 Negotiate"
                ),
            });
        }
        if !offers_negotiate {
            return Err(AdcsError::Spnego {
                reason: format!("the endpoint does not offer Negotiate ({offered})"),
            });
        }
        let binding: Vec<u8> = channel_binding(&server_certificate)?;
        self.pin.pin(server_certificate);
        self.binding = Some(binding.clone());
        Ok(binding)
    }

    /// A new context and its initial token, bound to `binding`; the
    /// session's ticket is acquired first when it has none yet.
    async fn initial_token(
        &mut self,
        binding: &[u8],
        deadline: &Deadline,
    ) -> Result<(B::Context, Vec<u8>), AdcsError> {
        let source: TicketSource<B::Credential> = match &self.credential {
            Credential::Acquired(credential) => TicketSource::Held(credential.clone()),
            Credential::Pending(password) => TicketSource::Acquire(password.clone()),
            Credential::Refused(refusal) => return Err(self.refusal_error(refusal)),
        };
        let backend: Arc<B> = Arc::clone(&self.backend);
        let principal: String = self.principal.as_str().to_owned();
        let host: String = self.endpoint.host().to_owned();
        let binding: Vec<u8> = binding.to_vec();
        let (acquired, outcome) = blocking("SPNEGO initial token", move || {
            let credential: B::Credential = match source {
                TicketSource::Held(credential) => credential,
                TicketSource::Acquire(password) => {
                    match backend.acquire_credential(&principal, &password) {
                        Ok(credential) => credential,
                        Err(err) => return (None, Err(err)),
                    }
                }
            };
            let outcome: Result<(B::Context, Vec<u8>), AdcsError> =
                first_token(backend.as_ref(), credential.clone(), &host, &binding);
            (Some(credential), outcome)
        })
        .await?;
        if let Some(credential) = acquired {
            self.credential = Credential::Acquired(credential);
        }
        let (context, token): (B::Context, Vec<u8>) = outcome.inspect_err(|err: &AdcsError| {
            if let AdcsError::Ticket {
                failure,
                kdc_error_code,
                minor_status,
                message,
                ..
            } = err
            {
                self.credential = Credential::Refused(Refusal {
                    failure: *failure,
                    kdc_error_code: *kdc_error_code,
                    minor_status: *minor_status,
                    message: message.clone(),
                });
            }
        })?;
        deadline.check()?;
        Ok((context, token))
    }

    fn refusal_error(&self, refusal: &Refusal) -> AdcsError {
        AdcsError::Ticket {
            principal: self.principal.as_str().to_owned(),
            failure: refusal.failure,
            kdc_error_code: refusal.kdc_error_code,
            minor_status: refusal.minor_status,
            message: refusal.message.clone(),
        }
    }

    async fn send(
        &self,
        request: &Request,
        token: Option<&[u8]>,
        stage: &'static str,
    ) -> Result<Response, AdcsError> {
        let url: reqwest::Url = self.endpoint.url().clone();
        let mut builder: reqwest::RequestBuilder = match request {
            Request::Enroll(envelope) => self
                .http
                .post(url)
                .header(CONTENT_TYPE, SOAP_CONTENT_TYPE)
                .body(envelope.clone()),
            Request::Get => self.http.get(url),
        };
        if let Some(token) = token {
            let encoded: String = base64::engine::general_purpose::STANDARD.encode(token);
            builder = builder.header(AUTHORIZATION, format!("Negotiate {encoded}"));
        }
        builder.send().await.map_err(|err: reqwest::Error| {
            if self.pin.take_refusal() {
                AdcsError::ServerCertificateChanged
            } else {
                transport_error(stage, &err)
            }
        })
    }
}

/// A context for `HTTP@<host>` with `credential`, and its first token.
fn first_token<B: GssBackend>(
    backend: &B,
    credential: B::Credential,
    host: &str,
    binding: &[u8],
) -> Result<(B::Context, Vec<u8>), AdcsError> {
    let mut context: B::Context = backend.client_context(credential, host)?;
    let token: Vec<u8> = context
        .step(None, binding)
        .map_err(|failure: GssFailure| AdcsError::Spnego {
            reason: format!(
                "cannot build the initial token for HTTP/{host}: {}",
                failure.message
            ),
        })?
        .ok_or_else(|| AdcsError::Spnego {
            reason: "the GSS-API library produced no initial token".to_owned(),
        })?;
    Ok((context, token))
}

/// Feeds the server's token to `context` and requires what proves the
/// server: an established context, with nothing left to send (a token
/// the two-leg exchange could not deliver), Kerberos as the mechanism
/// SPNEGO settled on (Epic 13 D2: never NTLM or another mechanism the
/// host registered), and mutual authentication in its flags.
fn authenticate_server<C: GssContext>(
    mut context: C,
    server_token: &[u8],
    binding: &[u8],
) -> Result<(), AdcsError> {
    let mutual = |reason: String| AdcsError::MutualAuth { reason };
    let further: Option<Vec<u8>> =
        context
            .step(Some(server_token), binding)
            .map_err(|failure: GssFailure| {
                mutual(format!(
                    "the response token was rejected: {}",
                    failure.message
                ))
            })?;
    if !context.is_complete() {
        return Err(mutual(
            "the security context is still incomplete after the response token".to_owned(),
        ));
    }
    if further.is_some() {
        return Err(mutual(
            "the security context completed with a further token for the endpoint, which a \
             two-leg exchange cannot deliver"
                .to_owned(),
        ));
    }
    let negotiated: Negotiated = context.negotiated().map_err(|failure: GssFailure| {
        mutual(format!(
            "the established context cannot be inspected: {}",
            failure.message
        ))
    })?;
    if !negotiated.is_kerberos() {
        return Err(AdcsError::Spnego {
            reason: format!(
                "SPNEGO settled on the mechanism {}, not Kerberos",
                negotiated.mechanism_name()
            ),
        });
    }
    if !negotiated.mutual {
        return Err(mutual(
            "the established context does not carry mutual authentication".to_owned(),
        ));
    }
    Ok(())
}

/// The error of a failed HTTP leg. reqwest reports a TLS failure as a
/// connection error; the cause chain, which carries rustls' message, is
/// what tells it from a TCP or DNS one. Only the causes are read, never
/// the top-level message: it repeats the URL, which says nothing the
/// operator does not know, and the causes say what failed.
fn transport_error(stage: &'static str, err: &reqwest::Error) -> AdcsError {
    let mut causes: Vec<String> = Vec::new();
    let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(err);
    while let Some(cause) = source {
        causes.push(cause.to_string());
        source = cause.source();
    }
    let chain: String = if causes.is_empty() {
        "the HTTP client gave no cause".to_owned()
    } else {
        causes.join(": ")
    };
    if err.is_timeout() {
        return AdcsError::Http {
            stage,
            reason: format!("timed out: {chain}"),
        };
    }
    let tls_failure: bool = err.is_connect()
        && causes.iter().any(|cause: &String| {
            let cause: String = cause.to_ascii_lowercase();
            ["certificate", "tls", "handshake"]
                .iter()
                .any(|marker: &&str| cause.contains(marker))
        });
    if tls_failure {
        AdcsError::Tls {
            reason: format!("{stage}: {chain}"),
        }
    } else {
        AdcsError::Http {
            stage,
            reason: chain,
        }
    }
}

async fn read_body(stage: &'static str, mut response: Response) -> Result<Vec<u8>, AdcsError> {
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err: reqwest::Error| transport_error(stage, &err))?
    {
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(AdcsError::Http {
                stage,
                reason: format!("the response body exceeds {MAX_BODY_BYTES} bytes"),
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The parameter of every `Negotiate` challenge in `headers`, `None`
/// for a bare `Negotiate`. A header value may list several challenges
/// separated by commas; a Negotiate token is base64 and has none.
fn negotiate_challenges(headers: &HeaderMap) -> Vec<Option<String>> {
    headers
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value: &str| value.split(','))
        .filter_map(|challenge: &str| {
            let challenge: &str = challenge.trim();
            let (scheme, parameter): (&str, &str) =
                challenge.split_once(' ').unwrap_or((challenge, ""));
            if !scheme.eq_ignore_ascii_case("Negotiate") {
                return None;
            }
            let parameter: &str = parameter.trim();
            Some((!parameter.is_empty()).then(|| parameter.to_owned()))
        })
        .collect()
}

fn offered_schemes(headers: &HeaderMap) -> String {
    let values: Vec<&str> = headers
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    if values.is_empty() {
        "no WWW-Authenticate header".to_owned()
    } else {
        format!("WWW-Authenticate: {}", values.join(", "))
    }
}

#[cfg(test)]
mod tests;
