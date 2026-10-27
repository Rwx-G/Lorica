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

//! The machinery every AD CS operation runs on: the seam to the client,
//! the session one operation or one renewal tick shares, the
//! single-flight guard, and the runtime the API state carries.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use lorica_adcs::{AdcsError, CesParams, CesTimeouts, EnrollOutcome, Secret};

use super::{AdcsRenewalMemory, AdoptionVerdicts};

/// How long the renewal loop waits for a busy guard before trying its
/// AD CS batch again. A tick that gave up at the first refusal could be
/// skipped, for 12 hours, by anyone keeping the guard busy with
/// connection tests or issuances at the right moment.
const BUSY_RETRY_DELAY: Duration = Duration::from_secs(30);

/// What a handler waits for its operation beyond the client's own
/// operation timeout, for the audit and breaker writes that follow it.
/// An operation that ends on that timeout is then reported by the
/// handler as it ended; only one whose GSS-API step outlived it (MIT's
/// own schedule, see [`CesTimeouts::operation`]) is answered 504.
const HANDLER_GRACE: Duration = Duration::from_secs(15);

/// How long a handler waits for its AD CS operation before answering
/// 504: [`CesTimeouts::default`]'s operation timeout, the one every
/// operation runs with, plus [`HANDLER_GRACE`].
fn handler_deadline() -> Duration {
    CesTimeouts::default().operation + HANDLER_GRACE
}

/// One authenticated conversation with the authority: one ticket for
/// every request of one API operation or one renewal tick (Epic 13 D3,
/// D15). It holds the service account's ticket, so it never outlives
/// the operation or the tick that opened it.
#[async_trait::async_trait]
pub(crate) trait AdcsSession: Send {
    /// Authenticate without requesting anything.
    async fn test(&mut self) -> Result<(), AdcsError>;

    /// Request a certificate for the DER PKCS#10 `csr_der`: an issuance
    /// at the authority.
    async fn enroll(&mut self, csr_der: &[u8]) -> Result<EnrollOutcome, AdcsError>;
}

/// The calls into the authority the API makes, behind a seam so tests
/// drive the handlers without a KDC. Production opens a
/// [`lorica_adcs::CesSession`].
#[async_trait::async_trait]
pub(crate) trait AdcsClient: Send + Sync {
    /// Authenticate to the CES described by `params` without
    /// requesting anything, on a session of its own.
    async fn test_connection(&self, params: &CesParams, password: &Secret)
        -> Result<(), AdcsError>;

    /// Request a certificate for `csr_der` on a session of its own.
    async fn enroll(
        &self,
        params: &CesParams,
        password: &Secret,
        csr_der: &[u8],
    ) -> Result<EnrollOutcome, AdcsError>;

    /// Open a session. The default makes every request of it a call of
    /// its own, which is what a stand-in authority needs; the real
    /// client acquires one ticket for the whole session.
    async fn open<'a>(
        &'a self,
        params: &CesParams,
        password: Secret,
    ) -> Result<Box<dyn AdcsSession + 'a>, AdcsError> {
        Ok(per_request_session(self, params, password))
    }
}

/// A session on `client` whose requests each go through its one-shot
/// calls.
pub(crate) fn per_request_session<'a, C: AdcsClient + ?Sized>(
    client: &'a C,
    params: &CesParams,
    password: Secret,
) -> Box<dyn AdcsSession + 'a> {
    Box::new(PerRequest {
        client,
        params: params.clone(),
        password,
    })
}

/// See [`per_request_session`].
struct PerRequest<'a, C: ?Sized> {
    client: &'a C,
    params: CesParams,
    password: Secret,
}

#[async_trait::async_trait]
impl<C: AdcsClient + ?Sized> AdcsSession for PerRequest<'_, C> {
    async fn test(&mut self) -> Result<(), AdcsError> {
        self.client
            .test_connection(&self.params, &self.password)
            .await
    }

    async fn enroll(&mut self, csr_der: &[u8]) -> Result<EnrollOutcome, AdcsError> {
        self.client
            .enroll(&self.params, &self.password, csr_der)
            .await
    }
}

/// The real client: the `lorica-adcs` crate.
struct LibAdcsClient;

/// A [`lorica_adcs::CesSession`] behind the seam.
struct LibSession(lorica_adcs::CesSession);

#[async_trait::async_trait]
impl AdcsSession for LibSession {
    async fn test(&mut self) -> Result<(), AdcsError> {
        self.0.test().await
    }

    async fn enroll(&mut self, csr_der: &[u8]) -> Result<EnrollOutcome, AdcsError> {
        self.0.enroll(csr_der).await
    }
}

#[async_trait::async_trait]
impl AdcsClient for LibAdcsClient {
    async fn test_connection(
        &self,
        params: &CesParams,
        password: &Secret,
    ) -> Result<(), AdcsError> {
        lorica_adcs::test_connection(params, password).await
    }

    async fn enroll(
        &self,
        params: &CesParams,
        password: &Secret,
        csr_der: &[u8],
    ) -> Result<EnrollOutcome, AdcsError> {
        lorica_adcs::enroll(params, password, csr_der).await
    }

    async fn open<'a>(
        &'a self,
        params: &CesParams,
        password: Secret,
    ) -> Result<Box<dyn AdcsSession + 'a>, AdcsError> {
        let session = lorica_adcs::CesSession::open(params, &password).await?;
        Ok(Box::new(LibSession(session)))
    }
}

/// A session opened on its first request, so an operation refused
/// before it reaches the authority (a name, a template) builds nothing,
/// and a renewal tick shares one session across its certificates.
///
/// Opening contacts nothing (see [`lorica_adcs::CesSession::open`]), so
/// a failed open is retried on the next request at no cost to the
/// account.
pub(crate) struct LazySession<'a> {
    client: &'a dyn AdcsClient,
    params: CesParams,
    password: Secret,
    session: Option<Box<dyn AdcsSession + 'a>>,
}

impl<'a> LazySession<'a> {
    /// A session on `client` for the authority `params` describes.
    pub(crate) fn new(client: &'a dyn AdcsClient, params: CesParams, password: Secret) -> Self {
        LazySession {
            client,
            params,
            password,
            session: None,
        }
    }

    async fn opened(&mut self) -> Result<&mut Box<dyn AdcsSession + 'a>, AdcsError> {
        let session: Box<dyn AdcsSession + 'a> = match self.session.take() {
            Some(session) => session,
            None => {
                self.client
                    .open(&self.params, self.password.clone())
                    .await?
            }
        };
        Ok(self.session.insert(session))
    }

    /// See [`AdcsSession::test`].
    pub(crate) async fn test(&mut self) -> Result<(), AdcsError> {
        self.opened().await?.test().await
    }

    /// See [`AdcsSession::enroll`].
    pub(crate) async fn enroll(&mut self, csr_der: &[u8]) -> Result<EnrollOutcome, AdcsError> {
        self.opened().await?.enroll(csr_der).await
    }
}

/// The single-flight guard of every AD CS operation (Epic 13 D15).
///
/// One per process, shared by every clone of [`AppState`]. A second
/// operation is refused at once instead of waiting its turn: the
/// GSS-API calls behind an operation are blocking FFI on the blocking
/// pool, and an operation blocked on a silent KDC holds its thread
/// until MIT krb5 gives up, so a queue of callers would turn one silent
/// KDC into a pile of blocked threads, each about to spend another
/// pre-authentication attempt against the service account.
///
/// The permit lives in the task [`run_exclusive`] spawns, not in the
/// handler, and `lorica-adcs` resolves an operation only once its
/// blocking GSS-API calls have returned: so the guard is held until no
/// thread of the operation is left, even when the handler has already
/// answered 504 or its client has gone.
///
/// Authority writes take it too, so a password saved while a test is
/// in flight cannot be followed by that test's verdict on the old one.
#[derive(Clone, Default)]
pub(crate) struct AdcsGuard {
    slot: Arc<tokio::sync::Mutex<()>>,
}

/// Proof that the holder is the one AD CS operation running; the guard
/// is released when it is dropped.
pub(crate) struct AdcsPermit {
    _held: tokio::sync::OwnedMutexGuard<()>,
}

impl AdcsGuard {
    /// The permit, or `None` while another operation holds it.
    pub(crate) fn try_acquire(&self) -> Option<AdcsPermit> {
        Arc::clone(&self.slot)
            .try_lock_owned()
            .ok()
            .map(|held| AdcsPermit { _held: held })
    }
}

/// Why [`run_exclusive`] returned no output.
#[derive(Debug)]
pub(crate) enum NotRun {
    /// Another AD CS operation is running; this one never started.
    Busy,
    /// The operation started and outlived the handler's deadline. It
    /// keeps running, and the guard, until it ends.
    StillRunning,
    /// The operation's task panicked or was cancelled by the runtime.
    Lost(String),
}

/// The process's AD CS runtime: the [`AdcsGuard`], the client the
/// handlers call, where `adcs_authority_failed` alerts go, how long a
/// handler waits for its operation, what the renewal paths remember
/// about each certificate's failures, and the adoption listing's
/// signature verdicts.
#[derive(Clone)]
pub struct AdcsRuntime {
    guard: AdcsGuard,
    pub(in crate::adcs) client: Arc<dyn AdcsClient>,
    pub(in crate::adcs) alerts: Option<lorica_notify::AlertSender>,
    handler_deadline: Duration,
    /// How long the renewal loop waits before trying again when another
    /// AD CS operation holds the guard.
    busy_retry_delay: Duration,
    pub(crate) renewals: Arc<AdcsRenewalMemory>,
    pub(crate) adoption: Arc<AdoptionVerdicts>,
    /// [`lorica_adcs::krb5_config_is_honoured`], read once: it is fixed
    /// at exec.
    pub(crate) krb5_config_honoured: bool,
}

impl AdcsRuntime {
    /// The production runtime. `alerts` is the process's alert channel;
    /// `None` raises nothing (tests and one-shot commands).
    pub fn new(alerts: Option<lorica_notify::AlertSender>) -> AdcsRuntime {
        AdcsRuntime {
            guard: AdcsGuard::default(),
            client: Arc::new(LibAdcsClient),
            alerts,
            handler_deadline: handler_deadline(),
            busy_retry_delay: BUSY_RETRY_DELAY,
            renewals: Arc::default(),
            adoption: Arc::default(),
            krb5_config_honoured: lorica_adcs::krb5_config_is_honoured(),
        }
    }

    /// A runtime calling `client` instead of the authority.
    #[cfg(test)]
    pub(crate) fn with_client(
        client: Arc<dyn AdcsClient>,
        alerts: Option<lorica_notify::AlertSender>,
    ) -> AdcsRuntime {
        AdcsRuntime {
            guard: AdcsGuard::default(),
            client,
            alerts,
            handler_deadline: handler_deadline(),
            busy_retry_delay: BUSY_RETRY_DELAY,
            renewals: Arc::default(),
            adoption: Arc::default(),
            krb5_config_honoured: lorica_adcs::krb5_config_is_honoured(),
        }
    }

    /// The same runtime with a handler deadline short enough for a test.
    #[cfg(test)]
    pub(crate) fn with_handler_deadline(mut self, deadline: Duration) -> AdcsRuntime {
        self.handler_deadline = deadline;
        self
    }

    /// The same runtime as in a process started setuid or with file
    /// capabilities, where MIT krb5 ignores `KRB5_CONFIG`.
    #[cfg(test)]
    pub(crate) fn with_krb5_config_ignored(mut self) -> AdcsRuntime {
        self.krb5_config_honoured = false;
        self
    }

    /// The same runtime with a renewal-loop busy retry short enough for
    /// a test.
    #[cfg(test)]
    pub(crate) fn with_busy_retry_delay(mut self, delay: Duration) -> AdcsRuntime {
        self.busy_retry_delay = delay;
        self
    }

    /// How long the renewal loop waits before retrying a busy guard.
    pub(crate) fn busy_retry_delay(&self) -> Duration {
        self.busy_retry_delay
    }

    /// The single-flight guard, for a test to hold it.
    #[cfg(test)]
    pub(crate) fn guard(&self) -> &AdcsGuard {
        &self.guard
    }
}

/// Run `operation` as the one AD CS operation of the process, or return
/// [`NotRun::Busy`] at once when another one is running (see
/// [`AdcsGuard`]).
///
/// The operation runs in a task of its own that holds the permit for
/// its whole life, so neither the handler's deadline nor a client that
/// disconnects can release the guard while it runs. When the deadline
/// passes first the handler gets [`NotRun::StillRunning`] and the task
/// carries on: whatever the operation records on completion (its audit
/// row, the D15 breaker) is therefore written by the task, never lost.
pub(crate) async fn run_exclusive<T, F>(runtime: &AdcsRuntime, operation: F) -> Result<T, NotRun>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let permit: AdcsPermit = runtime.guard.try_acquire().ok_or(NotRun::Busy)?;
    let task: tokio::task::JoinHandle<T> = tokio::spawn(async move {
        let _permit: AdcsPermit = permit;
        operation.await
    });
    match tokio::time::timeout(runtime.handler_deadline, task).await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(err)) => Err(NotRun::Lost(err.to_string())),
        Err(_) => Err(NotRun::StillRunning),
    }
}

/// Run `operation` as the one AD CS operation of the process and wait
/// for its end, or return [`NotRun::Busy`] at once when another one is
/// running. For the renewal loop, which has no client to answer: the
/// operation is a whole tick's batch, bounded per request by the
/// client's operation timeout rather than by a handler's deadline.
pub(crate) async fn run_exclusive_to_end<T, F>(
    runtime: &AdcsRuntime,
    operation: F,
) -> Result<T, NotRun>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let permit: AdcsPermit = runtime.guard.try_acquire().ok_or(NotRun::Busy)?;
    tokio::spawn(async move {
        let _permit: AdcsPermit = permit;
        operation.await
    })
    .await
    .map_err(|err| NotRun::Lost(err.to_string()))
}
