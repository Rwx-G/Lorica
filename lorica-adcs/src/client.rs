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

//! The two calls the rest of Lorica makes: [`enroll`] and
//! [`test_connection`]. Each runs one authenticated exchange with CES:
//!
//! 1. the request, unauthenticated, to obtain the 401 `Negotiate`
//!    challenge and, from that TLS connection, the server certificate
//!    the channel binding is computed from (it depends on the
//!    certificate only, so the next request needs no connection
//!    affinity);
//! 2. ticket acquisition and the initial SPNEGO token, bound to that
//!    certificate (RFC 5929 `tls-server-end-point`), on a blocking task;
//! 3. the request again with `Authorization: Negotiate <token>`;
//! 4. the server's `WWW-Authenticate: Negotiate <token>`, whatever the
//!    status, fed back to the context, which must then be complete:
//!    that token is the only proof the server holds the service key
//!    (Epic 13 D2, Story 13.1 AC #5).

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use reqwest::header::{HeaderMap, AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use reqwest::{Client, Response, StatusCode, Url};

use crate::binding::channel_binding;
use crate::gss::{GssBackend, GssContext, GssFailure, LibGssapi};
use crate::krb5conf::Realm;
use crate::secret::Secret;
use crate::wstep::request::{build_request, new_message_id, SOAP_CONTENT_TYPE};
use crate::wstep::response::{parse_response, EnrollmentResponse};
use crate::AdcsError;

/// What an enrollment returns: the authority's answer, issued, pending,
/// denied or another fault. The same type as [`parse_response`] gives,
/// so the two cannot drift apart.
pub type EnrollOutcome = EnrollmentResponse;

/// The step names of the two HTTP legs, as errors display them.
const PROBE: &str = "unauthenticated request";
const AUTHENTICATED: &str = "authenticated request";

/// A CES answer is a few kilobytes; a body past this is not one and is
/// refused before it costs memory.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// The bounds of one operation (Epic 13 D8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CesTimeouts {
    /// TCP and TLS connection establishment, per connection.
    pub connect: Duration,
    /// The longest wait for the next bytes of a response.
    pub read: Duration,
    /// The whole operation, ticket acquisition included. It is the outer
    /// guard: a GSS-API call already running on a blocking thread is not
    /// stopped by it, which is why the `krb5.conf` `kdc_timeout` and
    /// `max_retries` must fit inside it.
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
    /// The CES endpoint, `https://` only, for example
    /// `https://ces.corp.example.org/<CAName>_CES_Kerberos/service.svc/CES`.
    /// Its host must be a DNS name: the service ticket is for
    /// `HTTP/<host>`.
    pub endpoint: String,
    /// The service account's realm.
    pub realm: Realm,
    /// The service account, `user` or `user@REALM` with the same realm
    /// as [`Self::realm`].
    pub principal: String,
    /// When set, the PEM certificates that alone are trusted for the
    /// endpoint's TLS certificate, in place of the system and webpki
    /// roots (Epic 13 D12).
    pub trust_bundle_pem: Option<String>,
    /// The bounds of the operation.
    pub timeouts: CesTimeouts,
}

/// Requests a certificate for the DER PKCS#10 `csr_der` from the CES
/// described by `params`, authenticating as its service account with
/// `password`.
///
/// The request is an issuance at the authority: it is logged there and
/// undone only by revocation. Errors name the step that failed;
/// a pending, denied or failed request is an [`EnrollOutcome`], not an
/// error.
pub async fn enroll(
    params: &CesParams,
    password: &Secret,
    csr_der: &[u8],
) -> Result<EnrollOutcome, AdcsError> {
    enroll_with(Arc::new(LibGssapi), params, password, csr_der).await
}

/// Checks that Lorica can authenticate to the CES described by `params`
/// with `password`: a ticket is acquired, the endpoint accepts the bound
/// token, and it proves itself with its response token. Nothing is
/// requested from the authority.
///
/// MS-WSTEP has no operation that issues nothing, so the authenticated
/// request is a `GET` of the endpoint. IIS authenticates every request
/// before the service sees it, and the service then refuses the `GET`
/// (400 or 405) with the response token already in the answer: the
/// whole authentication is exercised while the WS-Trust layer, which
/// only acts on a `POST`ed `RequestSecurityToken`, never is. Posting an
/// envelope with an empty or invalid CSR would reach the authority and
/// leave a failed request in its database.
pub async fn test_connection(params: &CesParams, password: &Secret) -> Result<(), AdcsError> {
    test_connection_with(Arc::new(LibGssapi), params, password).await
}

pub(crate) async fn enroll_with<B: GssBackend>(
    backend: Arc<B>,
    params: &CesParams,
    password: &Secret,
    csr_der: &[u8],
) -> Result<EnrollOutcome, AdcsError> {
    let target: Target = Target::from_params(params)?;
    let envelope: String = build_request(target.url.as_str(), &new_message_id(), csr_der)?;
    let request: Request = Request::Enroll(envelope);
    bounded(params.timeouts.operation, async {
        let answer: Answer = exchange(backend, params, &target, password, &request).await?;
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
        parse_response(&body)
    })
    .await
}

pub(crate) async fn test_connection_with<B: GssBackend>(
    backend: Arc<B>,
    params: &CesParams,
    password: &Secret,
) -> Result<(), AdcsError> {
    let target: Target = Target::from_params(params)?;
    bounded(params.timeouts.operation, async {
        exchange(backend, params, &target, password, &Request::Probe).await?;
        Ok(())
    })
    .await
}

async fn bounded<T>(
    after: Duration,
    operation: impl Future<Output = Result<T, AdcsError>>,
) -> Result<T, AdcsError> {
    tokio::time::timeout(after, operation)
        .await
        .map_err(|_| AdcsError::Timeout { after })?
}

/// The validated endpoint and principal.
struct Target {
    url: Url,
    host: String,
    principal: String,
}

impl Target {
    fn from_params(params: &CesParams) -> Result<Target, AdcsError> {
        let invalid = |reason: String| AdcsError::InvalidParams { reason };
        let url: Url = Url::parse(&params.endpoint).map_err(|err| {
            invalid(format!(
                "the endpoint {:?} is not a URL: {err}",
                params.endpoint
            ))
        })?;
        if url.scheme() != "https" {
            return Err(invalid(format!(
                "the endpoint must be https://, not {}://",
                url.scheme()
            )));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(invalid(
                "the endpoint must not carry credentials in the URL".to_owned(),
            ));
        }
        let host: String = url
            .domain()
            .ok_or_else(|| {
                invalid(format!(
                    "the endpoint host of {:?} must be a DNS name: the service ticket is for HTTP/<host>",
                    params.endpoint
                ))
            })?
            .to_owned();
        let principal: String = principal_name(&params.principal, &params.realm)?;
        let timeouts: CesTimeouts = params.timeouts;
        if timeouts.connect.is_zero() || timeouts.read.is_zero() || timeouts.operation.is_zero() {
            return Err(invalid("every timeout must be above zero".to_owned()));
        }
        Ok(Target {
            url,
            host,
            principal,
        })
    }
}

/// `user@REALM` from `principal` and `realm`.
fn principal_name(principal: &str, realm: &Realm) -> Result<String, AdcsError> {
    let invalid = |reason: String| AdcsError::InvalidParams { reason };
    if principal.is_empty()
        || principal
            .chars()
            .any(|c: char| c.is_control() || c.is_whitespace())
    {
        return Err(invalid(format!(
            "the principal {principal:?} is empty or contains spaces or control characters"
        )));
    }
    match principal.split_once('@') {
        None => Ok(format!("{principal}@{realm}")),
        Some((user, principal_realm)) if !user.is_empty() && principal_realm == realm.as_str() => {
            Ok(principal.to_owned())
        }
        Some(_) => Err(invalid(format!(
            "the principal {principal:?} must be a user name or user@{realm}"
        ))),
    }
}

/// What is sent: the enrollment envelope, or for the connection test a
/// `GET` that IIS authenticates and the service then refuses.
enum Request {
    Enroll(String),
    Probe,
}

/// The authenticated answer, after mutual authentication succeeded.
struct Answer {
    status: StatusCode,
    body: Vec<u8>,
}

fn http_client(params: &CesParams) -> Result<Client, AdcsError> {
    let mut builder: reqwest::ClientBuilder = Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .tls_info(true)
        // A redirect would send the next request, and its token, to a
        // host the token was not bound to.
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(params.timeouts.connect)
        .read_timeout(params.timeouts.read);
    if let Some(pem) = &params.trust_bundle_pem {
        let roots: Vec<reqwest::Certificate> = reqwest::Certificate::from_pem_bundle(
            pem.as_bytes(),
        )
        .map_err(|err: reqwest::Error| AdcsError::Tls {
            reason: format!("the endpoint trust bundle cannot be read: {err}"),
        })?;
        if roots.is_empty() {
            return Err(AdcsError::Tls {
                reason: "the endpoint trust bundle holds no PEM certificate".to_owned(),
            });
        }
        builder = builder.tls_built_in_root_certs(false);
        for root in roots {
            builder = builder.add_root_certificate(root);
        }
    }
    builder
        .build()
        .map_err(|err: reqwest::Error| AdcsError::Tls {
            reason: format!("the HTTPS client cannot be built: {err}"),
        })
}

async fn send(
    client: &Client,
    url: &Url,
    request: &Request,
    token: Option<&[u8]>,
    stage: &'static str,
) -> Result<Response, AdcsError> {
    let mut builder: reqwest::RequestBuilder = match request {
        Request::Enroll(envelope) => client
            .post(url.clone())
            .header(CONTENT_TYPE, SOAP_CONTENT_TYPE)
            .body(envelope.clone()),
        Request::Probe => client.get(url.clone()),
    };
    if let Some(token) = token {
        let encoded: String = base64::engine::general_purpose::STANDARD.encode(token);
        builder = builder.header(AUTHORIZATION, format!("Negotiate {encoded}"));
    }
    builder
        .send()
        .await
        .map_err(|err: reqwest::Error| transport_error(stage, &err))
}

/// The error of a failed HTTP leg. reqwest reports a TLS failure as a
/// connection error; the cause chain, which carries rustls' message, is
/// what tells it from a TCP or DNS one. Only the causes are read, never
/// the top-level message, which holds the URL.
fn transport_error(stage: &'static str, err: &reqwest::Error) -> AdcsError {
    let mut causes: Vec<String> = Vec::new();
    let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(err);
    while let Some(cause) = source {
        causes.push(cause.to_string());
        source = cause.source();
    }
    let chain: String = std::iter::once(err.to_string())
        .chain(causes.iter().cloned())
        .collect::<Vec<String>>()
        .join(": ");
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

async fn blocking<T: Send + 'static>(
    step: &'static str,
    task: impl FnOnce() -> Result<T, AdcsError> + Send + 'static,
) -> Result<T, AdcsError> {
    tokio::task::spawn_blocking(task)
        .await
        .map_err(|err: tokio::task::JoinError| AdcsError::GssTask {
            step,
            reason: err.to_string(),
        })?
}

async fn exchange<B: GssBackend>(
    backend: Arc<B>,
    params: &CesParams,
    target: &Target,
    password: &Secret,
    request: &Request,
) -> Result<Answer, AdcsError> {
    let client: Client = http_client(params)?;

    let probe: Response = send(&client, &target.url, request, None, PROBE).await?;
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
    read_body(PROBE, probe).await?;
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

    let principal: String = target.principal.clone();
    let host: String = target.host.clone();
    let password: Secret = password.clone();
    let initial_binding: Vec<u8> = binding.clone();
    let (context, token): (B::Context, Vec<u8>) = blocking("SPNEGO initial token", move || {
        let credential: B::Credential = backend.acquire_credential(&principal, &password)?;
        drop(password);
        let mut context: B::Context = backend.client_context(credential, &host)?;
        let token: Vec<u8> = context
            .step(None, &initial_binding)
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
    })
    .await?;

    let response: Response =
        send(&client, &target.url, request, Some(&token), AUTHENTICATED).await?;
    let status: StatusCode = response.status();
    let server_token: Option<String> = negotiate_challenges(response.headers())
        .into_iter()
        .flatten()
        .next();
    let body: Vec<u8> = read_body(AUTHENTICATED, response).await?;
    if status == StatusCode::UNAUTHORIZED {
        return Err(AdcsError::Spnego {
            reason: "the endpoint refused the token with 401 (check the channel binding / \
                     Extended Protection, the SPN HTTP/<host>, the ticket)"
                .to_owned(),
        });
    }
    let server_token: Vec<u8> = server_token
        .ok_or_else(|| AdcsError::MutualAuth {
            reason: format!("the endpoint answered {status} without a Negotiate response token"),
        })
        .and_then(|encoded: String| {
            base64::engine::general_purpose::STANDARD
                .decode(encoded.as_bytes())
                .map_err(|err: base64::DecodeError| AdcsError::MutualAuth {
                    reason: format!("the response token is not base64: {err}"),
                })
        })?;
    blocking("SPNEGO mutual authentication", move || {
        let mut context: B::Context = context;
        context
            .step(Some(&server_token), &binding)
            .map_err(|failure: GssFailure| AdcsError::MutualAuth {
                reason: format!("the response token was rejected: {}", failure.message),
            })?;
        if context.is_complete() {
            Ok(())
        } else {
            Err(AdcsError::MutualAuth {
                reason: "the security context is still incomplete after the response token"
                    .to_owned(),
            })
        }
    })
    .await?;
    Ok(Answer { status, body })
}

#[cfg(test)]
mod tests;
