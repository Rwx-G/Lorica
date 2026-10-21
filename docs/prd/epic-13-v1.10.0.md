# Epic 13: AD CS Certificate Enrollment over CES (v1.10.0)

**Author:** Romain G.
**Target version:** 1.10.0. It ships before Epic 12, which moves to 1.11.0 and 1.12.0 (maintainer decision, 2026-10-21).
**Status:** Draft (2026-10-21). Written against `main` at `e78d923a` (v1.9.3); cite function and type names, since line numbers may drift. Authentication with a TLS channel binding was demonstrated against an AD CS deployment with Extended Protection Required (see "Evidence"). Dependencies approved by the maintainer on 2026-10-21 (D7). Revised the same day after a requirement challenge (scope cut to one authority and password-only credentials, the authority made a SuperAdmin control-plane object) and after an architecture review against the code (enforcement points placed, the authority kept out of replication, schema and alert ownership moved to Story 13.2). Revised again on 2026-10-21 after a verification against the Microsoft specifications, which replaced the planned spike extension: the template travels in the CSR, the chain is a CMC response, pending is not a fault, and the ticket is acquired in-process.

**Epic Goal:** Let an operator obtain, renew and take over internal certificates from an Active Directory Certificate Services authority the way Lorica already does it for Let's Encrypt: configured once, issued in one confirmed click from the route or the certificate page, renewed without anyone thinking about it. The workflow it replaces is manual: generate a key and a CSR in a desktop tool, submit it to the authority, download the certificate, upload it into Lorica, and do it again before expiry.

**Why this is its own epic:** ACME covers public names. Internal names served by Lorica in a company network are issued by the company's own authority, which in a Windows estate is AD CS, and AD CS does not speak ACME. A gateway in front of AD CS (an ACME server translating to it) was considered and refused by the maintainer: the requirement is a client inside Lorica, with no extra service to operate.

**What doing nothing costs:** nothing breaks. Manual certificates are already covered by expiry alerting (`check_cert_expiry`, `lorica-api/src/acme/expiry.rs`), so an unnoticed expiry is already mitigated. What the epic buys is the operator time spent per internal certificate per renewal, and the removal of private keys handled on desktops.

## The authority is the whole problem

An AD CS authority is a domain-wide trust anchor. A certificate it issues is trusted by every machine in the forest, and its common misconfigurations are documented attack paths (the ESC1 to ESC8 family). Lorica becomes one of its clients, holding a credential that can request certificates. It follows that:

- **Lorica must not be the weak link of the authority.** No cleartext transport, no relayable authentication, no request shape that only works on a misconfigured authority. Where the authority is misconfigured, Lorica fails and says why, rather than adapting.
- **Lorica must not become a way to mint arbitrary names.** The authority signs whatever its template allows the service account to request. Lorica bounds that with its own allowlist of DNS suffixes, enforced server-side, and editable only by a role that does not issue (D11).
- **Lorica must not become a way to steal the credential it holds.** Whoever can redirect where the credential is sent (endpoint, realm, KDC) could harvest material derived from it, so changing any of those clears the stored secret (D11); and no derivative of the secret leaves the control plane (D13).
- **Issuance is a human decision.** It is logged by the authority and undone only by revocation, which Lorica cannot perform. Every new certificate goes through a confirmation that shows exactly what will be requested.
- **The private key never leaves Lorica.** Only the CSR crosses the wire.

## Evidence: the authentication spike (2026-10-21)

A standalone Rust binary (`libgssapi` 0.11.0 over MIT krb5, `reqwest` 0.12.28 with rustls) was run from a Debian 13 host, with a TGT obtained by `kinit` for a service account, against a CES instance whose IIS application has Extended Protection set to **Required** and NTLM refused.

| Request | Result |
|---|---|
| GET on the CES endpoint, no `Authorization` | 401, `WWW-Authenticate: Negotiate` |
| SPNEGO token **with** the `tls-server-end-point` channel binding | **400** from the SOAP layer: IIS accepted the authentication and returned a response token |
| Same ticket, SPNEGO token **without** channel binding | **401**: Extended Protection enforces the binding |

Findings that shape the stories:

- The CES endpoint's TLS certificate was signed with SHA-512. RFC 5929 hashes the certificate with its signature hash, upgrading only MD5 and SHA-1 to SHA-256; a client that always uses SHA-256 would have been refused. The rule must be implemented, not assumed.
- An account in a child domain reached an authority in its parent domain: MIT krb5 followed the AD KDC's cross-realm referral with no configuration beyond DNS SRV discovery.
- `reqwest` exposes the server's leaf certificate after the handshake (`ClientBuilder::tls_info(true)`, `TlsInfo::peer_certificate()`), so the binding is computed from the 401 response of a first unauthenticated request. The binding depends on the certificate only, not on the connection, so the authenticated request needs no connection affinity.
- A common Windows HTTP client (`curl.exe --negotiate`) sends no channel binding and is refused: the binding is not optional in practice.

**What the spike did not prove**: the server's response token was received but never fed back to GSS-API, so mutual authentication was not verified; the ticket came from a host `kinit` with the host's own Kerberos configuration, so neither in-process password acquisition nor a Lorica-generated `krb5.conf` was exercised; and a GET was sent, so no WS-Trust request was ever accepted. The maintainer chose not to extend the spike against a real authority before development (2026-10-21). These points were instead checked against the specifications (next section), and the first exchange with a real authority is the release check of Story 13.6 AC #5.

## Verification against the specifications (2026-10-21)

Checked against the current Microsoft Open Specifications ([MS-WSTEP] v20240423, [MS-WCCE] v20260824, [MS-XCEP] v20260309, [MS-CRTD]), the MS-WSTEP response example decoded with OpenSSL, RFC 5929, the MIT krb5 documentation and sources, and the `libgssapi` 0.11.0 and `libgssapi-sys` sources. Points marked *unconfirmed* are covered by the harness and by the release check, not by a primary source.

- **Request** (MS-WSTEP 2.1, 3.1.4.1.2, 4.1.1.1): SOAP 1.2 over HTTPS, POST, `Content-Type: application/soap+xml; charset=utf-8`; WS-Addressing `Action` `http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep` with `mustUnderstand="1"`, a `urn:uuid:` `MessageID`, the anonymous `ReplyTo`, and `To` (sent by other clients, harmless; whether CES requires it is *unconfirmed*). Body: `RequestSecurityToken` with `TokenType` `...x509-token-profile-1.0#X509v3`, `RequestType` `.../ws-trust/200512/Issue`, the DER PKCS#10 as a `BinarySecurityToken` whose `ValueType` and `EncodingType` URIs are copied byte for byte from the specification's example, and `RequestID` nil. No WS-Security header: in Kerberos mode authentication is at the transport layer (MS-WSTEP 3.1.1.1.1; MS-XCEP 3.1.4.1.3.5).
- **Template** (MS-WCCE 3.2.2.6.2.1.4.1, 2.2.2.7.10): MS-WSTEP has no template element and defines no `AdditionalContext` item for it. The CA reads the template from the request itself, so it travels **inside the CSR**, as the `CertificateTemplate` name-value pair attribute (1.3.6.1.4.1.311.13.2.1, BMPString values). The CA matches the template's common name (`cn`); a display name fails with `CERTSRV_E_UNSUPPORTED_CERT_TYPE` (0x80094800).
- **Subject and SANs** (MS-WCCE 3.2.2.6.2.1.4.5.9): with *Supply in the request*, the CA uses the subject and the SAN extension of the CSR, and rejects a request with an empty subject. `EDITF_ATTRIBUTESUBJECTALTNAME2` only governs the separate `san:` attribute (3.2.1.4.2.1.2).
- **Issued response** (MS-WSTEP 3.1.4.1.3.2, 3.1.4.1.3.5, 4.1.1.2): a `RequestSecurityTokenResponseCollection` with one response; the leaf in `RequestedSecurityToken` (`#X509v3`); the chain in a sibling `BinarySecurityToken` (`#PKCS7`) that is a CA-signed CMC Full PKI Response (CMS SignedData, `id-cct-PKIResponse`), not a certs-only bundle, whose `certificates` set is unordered and includes the root; plus `DispositionMessage` and `RequestID`. Base64 text may carry CR and LF.
- **Pending** (MS-WSTEP 3.1.4.2.1.1): a normal response, not a fault, with a `SecurityTokenReference` and a `RequestID` (exact shape *unconfirmed*: the specification has no example).
- **Denial and errors** (MS-WSTEP 3.1.4.1.2.1, 3.1.4.1.3.7): a SOAP 1.2 fault whose optional detail is `CertificateEnrollmentWSDetail` (`ErrorCode` as a signed `int` HRESULT, `InvalidRequest` true for a denial, `RequestID`). Known codes: 0x80094012 (no Enroll permission on the template), 0x80094800 (template unknown or not configured), 0x80094802 (identifiers map to two templates). The detail may be absent.
- **Template extension in issued certificates** (MS-WCCE 2.2.2.7.7): version 2 and later templates are identified by 1.3.6.1.4.1.311.21.7 (template OID and version), version 1 templates by 1.3.6.1.4.1.311.20.2 (name, BMPString in practice).
- **Credentials** (`libgssapi` 0.11.0; MIT `acquire_cred.c`): `Cred::acquire_with_password` exists in the safe API, and MIT implements it into a fresh, unique `MEMORY:` credential cache per call. `ClientCtx` is `Send` and not `Sync`, and `step` takes the channel binding directly. `gss_krb5_ccache_name` is not exposed by `libgssapi-sys` and is process-global; it is not used.
- **`KRB5_CONFIG`** (MIT `init_os_ctx.c`): read with `secure_getenv` at every context creation, so a value set once at startup applies to every later acquisition. `secure_getenv` ignores it in a process started with elevated privileges (setuid or file capabilities); the shipped unit grants capabilities through `AmbientCapabilities` with `NoNewPrivileges`, which is believed not to trigger this (*unconfirmed*, covered by the release check).
- **Channel binding** (RFC 5929 4.1): MD5 and SHA-1 signatures upgrade to SHA-256, otherwise the signature's hash; undefined for signatures with no single hash. Microsoft's handling of RSASSA-PSS server certificates is *unconfirmed*.

## Supported templates

v1.10.0 supports templates that **issue immediately**. A `pending` response (a template requiring CA certificate manager approval) is a typed outcome that stores nothing, shows the authority's request identifier, is audited and raises `cert_issuance_failed` (Story 13.2 AC #9). `docs/adcs.md` states that templates requiring manager approval are not supported. Supporting them later would need a pending-request table (request identifier, SANs, subject, template, encrypted private key, target certificate id or none) registered in `ENCRYPTED_COLUMNS`, a poll interval separate from the 12 h renewal tick, a "Check now" action, and a guarantee that a pending row never reaches `list_certificates`.

## Decisions taken up front

**D1 - CES (MS-WSTEP), and only CES.** The Certificate Enrollment Web Service is the machine-facing enrollment API of AD CS: SOAP over HTTPS, structured responses, typed faults, a request identifier for pending requests. The browser-facing web enrollment pages (`/certsrv`) were the first candidate and are refused: they are HTML forms meant for a person, an integration would parse pages that change with the server's version and language, and they are the target of ESC8. The Certificate Enrollment Policy service (CEP, MS-XCEP) is not used: the operator configures the template name, which is all CEP would have provided.

**D2 - Kerberos SPNEGO with a mandatory TLS channel binding.** The only authentication mode. No NTLM (relayable, deprecated by Microsoft, and refused by hardened deployments), no HTTP Basic, no CES `UsernamePassword` instance. The channel binding is `tls-server-end-point` per RFC 5929, with the hash chosen from the certificate's signature algorithm, passed as GSS-API `application_data` with empty addresses. A server certificate whose signature algorithm has no hash Lorica can determine (RSASSA-PSS whose parameters it cannot read, unknown OIDs) fails the request with an error naming the algorithm. There is no setting to disable the binding, and `lorica-adcs` has no cargo feature or `cfg` that removes it. The server's response token is verified: an exchange that does not complete mutual authentication is a failure.

**D3 - Lorica owns the Kerberos exchange. Nothing Kerberos is configured on the host.** Paths below are relative to the data directory passed with `--data-dir` (`/var/lib/lorica` in the shipped unit and image).

- **Credential**: the SuperAdmin enters the service principal and its password in the dashboard. The password is stored encrypted in its own column, registered in `ENCRYPTED_COLUMNS` (`lorica-config/src/store/mod.rs`) so key rotation covers it, never inside a JSON blob. Writing it is refused when the store has no encryption key loaded (a new `ConfigStore::has_encryption_key()`): the API store always opens with a key today, so this is a guard for future code paths, not a reachable case. Password only: a keytab requires a domain administrator to run `ktpass` and silently stops working when the account's password changes; it is deferred.
- **Ticket**: acquired for each enrollment operation (one dashboard action, or one loop tick across all its AD CS certificates) and discarded after it. Acquisition is in-process with `Cred::acquire_with_password`, which MIT implements into a fresh, unique `MEMORY:` credential cache per call. No child process, no `kinit`, no Kerberos client tools in the packages, and no ticket outlives the operation, so no bearer credential ever sits on disk.
- **Configuration**: Lorica generates one `krb5.conf` at `<data-dir>/adcs/krb5.conf` from the authority (realm, `rdns = false`, TCP preferred, KDC discovery through DNS SRV or an explicit KDC list, AES encryption types only, `kdc_timeout` and `max_retries` sized so their worst case fits inside the operation timeout of D8), regenerated atomically when the authority changes. It is produced by a typed renderer from validated fields (Story 13.2 AC #1), never by templating free text: a realm or KDC value carrying a newline or a profile delimiter could otherwise inject relations, weaken the encryption types, or load a plugin module into the process that holds the master key. The process sets `KRB5_CONFIG` to that file in `main` immediately after `Cli::parse` and before `init_logging`, the first call that may spawn a thread, so every launch mode (systemd, Docker, development runs, an operator's `ExecStart=` override, `execv`ed workers and hot-upgrade successors) gets it; the systemd unit is not changed. MIT reads it with `secure_getenv`, which ignores it in a process started with elevated privileges, so Lorica must never be given capabilities through file capabilities (`setcap`) or setuid; the unit's `AmbientCapabilities` is the supported way, and `docs/adcs.md` says so. The host's `/etc/krb5.conf` is **not** chained: Lorica's Kerberos behaviour is deterministic and independent of the host, and pinning AES-only encryption types is at least as strict as a host crypto policy.

**D4 - A new key for every issuance and every renewal, SANs in the CSR only.** Lorica generates the key (ECDSA P-256 by default, RSA 2048 or 3072 selectable) and the CSR with `rcgen`, already a workspace dependency. The subject alternative names travel in the CSR's extension request, the subject is never empty (the CA rejects an empty subject under *Supply in the request*), and the template travels in the CSR as the `CertificateTemplate` name-value pair attribute (see "Verification against the specifications"). Story 13.1 checks whether `rcgen` can emit that attribute; if it cannot, the attribute is DER-encoded by Lorica and appended before signing, with no new dependency. Lorica never sends the `san:` request attribute, which only works on an authority with `EDITF_ATTRIBUTESUBJECTALTNAME2` set (ESC6); supporting it would reward a misconfiguration authorities are told to remove. Keys are never reused across renewals.

**D5 - The subject is split between the authority and the certificate, and names are bounded.** The authority carries the fixed part of the subject (`C`, `ST`, `L`, `O`, `OU`, optional email), the default template and key type, and the **allowed DNS suffixes**. The certificate carries what identifies the service: the SANs, taken from the route's hostname and aliases or typed on the certificate page, and the `CN`, which is the first SAN. The allowlist semantics: an entry `corp.example.org` permits that name and every name under it at any depth; matching is on DNS labels, case-insensitive, never on a string suffix (`evilcorp.example.org` does not match `corp.example.org`). The existing `matches_one_label` (`lorica-config/src/models/certificate.rs`) has single-label semantics and is not reused. **Wildcard SANs are refused** in v1.10.0. A request with a name outside the allowlist is refused by the API before anything reaches the authority. The authority may rewrite or drop subject fields; Lorica displays the subject it received, never the one it asked for.

**D6 - Issuance and renewal stay on the management plane, and the refusal is keyed on the caller.** New certificates are issued from the dashboard or the management API, after a summary of the full request (subject, SANs, template, key type) is confirmed. AD CS certificates are renewed by the background loop and by the dashboard's "Renew now". The automation listener and the MCP config tier neither issue nor renew them: widening what already-minted `certificates:write` tokens can do against a domain-wide authority would be a decision of its own, and the token renewal budget (`MIN_TOKEN_RENEWAL_INTERVAL_HOURS`, `renewal.rs`) is reasoned for Let's Encrypt, not for a domain authority. The dashboard handler `renew_certificate` and the automation handler both call `renew_certificate_as`, so the refusal cannot be keyed on the certificate alone: `renew_certificate_as` refuses an AD CS certificate whenever it runs for a token (`RenewalBudget::PerCertificate`), after `guard.check` so a token outside its grant learns nothing, with the named error `adcs_renewal_not_on_automation_plane`. Tests cover the three planes: the automation route and the MCP tool both get that error for an in-grant AD CS certificate, and the dashboard route renews it.

**D7 - Dependencies, approved 2026-10-21.**

- `libgssapi` (MIT licence, version pinned). It links the system GSS-API library, and its `libgssapi-sys` dependency generates bindings with `bindgen`, so **`libclang` is required at build time** (verified in the spike's lockfile). Build requirements `libkrb5-dev` and `libclang-dev` apply to every CI job that compiles the workspace (they run on bare `ubuntu-latest` runners, not only in containers), to the builder stage of every Dockerfile that compiles it, and to `ci-check.Dockerfile`'s own package list. Runtime: `libgssapi-krb5-2` on Debian, `krb5-libs` on RHEL, declared explicitly in both packages and installed explicitly in the runtime stage of `Dockerfile` and `tests-e2e-docker/Dockerfile`, never inherited through another package. Both halves land with the first commit that links the library (Story 13.1 AC #1). Every install of Lorica then links the GSS-API library, including installs that never configure an authority; the changelog states it as a new runtime requirement.
- `quick-xml` (MIT) for the SOAP envelope and response. No SOAP framework: the WS-Trust surface this epic needs is one request shape and one response shape.
- The issued chain arrives as a CMC Full PKI Response (CMS SignedData). Lorica reads only its `certificates` set with `der-parser`, already in the tree through `x509-parser`, builds the path from the leaf by issuer and subject, and drops the root; it does not verify the CMC signature, since the chain it keeps is verified as a certificate path. No new dependency.

**D8 - A new crate, `lorica-adcs`.** It holds the protocol client and nothing else: ticket acquisition, the channel binding, the SPNEGO exchange, the WS-Trust envelope, response and fault parsing, chain extraction, CSR construction, the `krb5.conf` renderer. It depends on no first-party crate and knows nothing about the store, routes or the dashboard. Orchestration (when to issue, when to renew, where to store) lives in `lorica-api` beside the ACME orchestration. The crate keeps the FFI surface in one place; every `lorica-api` test binary and the `lorica` binary still link the library. GSS-API calls are synchronous FFI that perform DNS and KDC network I/O, so they run on `spawn_blocking`. A tokio timeout around a blocking call stops the caller from waiting but does not stop the thread, so the operation bound comes from the profile values of D3; the tokio timeout is an outer guard, and the HTTP legs carry explicit connect and read timeouts. `ClientCtx` is `Send`, so a context moves between the blocking GSS-API steps and the async HTTP legs of one operation; it is never shared between tasks. The decrypted password exists only in the process that runs the management API (the supervisor, or the single process); workers never run the API and never see it. The new-crate checklist of `.claude/rules/lorica-rust.md` applies in full.

**D9 - Existing certificates are never changed by the upgrade. Adoption is offered, and confirmed.** The migration is additive and leaves every existing certificate manual. Once the authority knows its **issuing CA certificate** (D12), Lorica identifies the manual certificates that certificate signed, by signature verification and authority key identifier, never by issuer name and never against a root (every issuing CA under the same root would match), and offers to adopt them. Adoption keeps the certificate in place and changes what happens at its next renewal; it issues nothing by itself. The CSR an operator kept from a manual issuance is not needed: a renewal generates a new key and a new CSR.

**D10 - One authority in v1.10.0.** The maintainer's requirement names one authority. A single authority removes an authority picker on two forms, multi-realm Kerberos configuration and cross-authority adoption ambiguity. It is stored in a dedicated table with a stable `id` (the `dns_providers` and `cluster_ca` precedents), not in `global_settings`, whose replicate-or-local routing and scalar KvText rows do not fit a suffix list, two PEM bundles and a subject; the API enforces at most one row. Certificates reference it through `adcs_authority_id` (D14), so supporting several later is a UI and API change, not a data migration.

**D11 - The authority is SuperAdmin; issuing is Operator.** `Role::Operator` has full CRUD on certificates (`lorica-config/src/models/enums.rs`). If the same role could edit the allowed suffixes, the allowlist would bound nothing against the people it is meant to bound; if it could edit the realm or the KDC list, a connection test would send pre-authentication derived from the service account's password to a KDC of its choosing. So, in `required_role` (`lorica-api/src/middleware/authorize.rs`):

- `/api/v1/adcs/authority` writes (create, update, delete), covering suffixes, endpoint, realm, KDC list, principal, CA certificates and subject defaults, are **SuperAdmin**. Reads stay at the Viewer default and report the password as set or unset only.
- `POST /api/v1/adcs/authority/test` is carved out at **Operator** by an explicit rule ahead of the SuperAdmin overlay, as capture `disable` is today.
- Issuance (`POST /api/v1/certificates/adcs`), adoption (`POST /api/v1/certificates/{id}/adcs/adopt`), reverting to manual and "Renew now" are **Operator**, the certificate default.
- Any change to the endpoint, realm, KDC list or principal **clears the stored password**, and the same request must supply it again.
- The threat model states the limit: the allowlist bounds API callers, not anyone who can read the data directory, where the encryption key sits beside the database.

**D12 - What the authority knows about its chains.** Two distinct trust objects, never conflated:

- the **endpoint trust bundle**, used only to verify the CES web server's TLS certificate. When it is set, the CES client trusts it alone (`tls_built_in_root_certs(false)`), not in addition to the system and webpki roots that `lorica-api`'s HTTP client enables;
- the **issuing CA certificate**, learned from the chain of the first successful issuance or pasted by the SuperAdmin, used for adoption (D9) and to display which CA issued a certificate.

**D13 - A control-plane object that never leaves the control plane.** The authority is **not** part of the canonical blob. `lorica-config/src/store/replica.rs` carries `dns_providers` and `notification_configs` to every follower with their secret as an unsalted SHA-256 digest (`secret_digest`, `canonical.rs`), which is acceptable for a high-entropy API token and not for a password a person chose: a follower would hold an offline-crackable hash of the service account's password, and the endpoint, realm, KDC list, principal and suffixes in clear. A follower never applies the authority and nothing it serves depends on it, so the digest would buy no drift detection the fleet uses. Issuance and renewal run on the control plane only, which is already where certificate renewal runs (the follower guard in `run_api_server`, `lorica/src/startup/mod.rs`). Issued certificates, which carry the `adcs_*` columns, reach followers through the canonical blob and the Story 9.5 key pull path, which is keyed on certificate rows and indifferent to their source. A follower's dashboard shows "managed on the control plane" instead of the authority settings.

**D14 - The data model derives the source; it does not store it.**

- Certificates gain nullable `adcs_authority_id`, `adcs_template` (the name used at issuance), `adcs_template_oid` (as observed in the issued certificate) and `adcs_request_id`. `adcs_authority_id` is plain nullable `TEXT`, **not a foreign key**, like `acme_dns_provider_id`: followers hold AD CS certificates without the authority row, and a `REFERENCES` constraint under `PRAGMA foreign_keys=ON` would fail every replica apply. Integrity is the API's job (the delete guard of Story 13.2).
- The source is derived: ACME when `is_acme`, AD CS when `adcs_authority_id` is set, manual otherwise. A stored source enum beside `is_acme` would be two truths that can disagree. `CertificateResponse` (`lorica-api/src/certificates.rs`, `api.ts`) carries the derived `source` and the `adcs_*` fields, so the dashboard never re-derives it.
- Auto-renew reuses `acme_auto_renew` for both sources; its doc comment is updated to say so, and the derived source disambiguates it. "Auto-renew off" keeps a certificate AD CS managed with no renewal; "revert to manual" clears `adcs_authority_id`.
- Canonical format: **no version bump**. `CANONICAL_FORMAT_VERSION` is compared by equality (`decode_canonical`), so a bump would stop replication for the whole upgrade window. The new fields carry `#[serde(default)]` on `Certificate` (a `deny_unknown_fields` struct, where `acme_method` and `acme_dns_provider_id` already do the same), `CANONICAL_SHAPE_DIGEST` is updated with the compatibility argument of the backlog #82 precedent, and the fleet is upgraded followers first, control plane last, per `docs/cluster.md`. A test pins that a blob produced by the previous release decodes.
- The authority is not part of the configuration export, like DNS providers today; importing an AD CS certificate whose authority is absent makes it manual, with a warning.

**D15 - A failing credential stops everything at once, and stays stopped.** The renewal loop iterates certificates one by one (`renewal.rs`), and its only back-off is the in-memory `RenewalLedger`, keyed by certificate and triggered by an ACME rate-limit message. Repeated for AD CS, a stale password would cost one failed pre-authentication per certificate per tick, plus every connection test and "Renew now", and lock the service account in the directory. So:

- a pre-authentication failure (`KDC_ERR_PREAUTH_FAILED`, `KDC_ERR_CLIENT_REVOKED`, `KDC_ERR_KEY_EXPIRED`) puts the **authority** in a failed state that stops every further attempt against it, with one `adcs_authority_failed` notification;
- the failed state (since, step, KDC code) is **persisted on the authority row**, so a restart, a crash loop or a hot upgrade does not spend another attempt; only a password write clears it;
- ticket acquisition is **single-flight per authority** across the loop, "Renew now", issuance and the connection test, through one guard on the API state beside `RenewalLedger`; a loop tick acquires at most one ticket for all its AD CS certificates;
- the connection test is rate-limited like ACME provisioning (`RL_ACME_PROVISION`);
- the failed state and the learned issuing CA certificate never enter a replicated payload (D13).

**Integration Requirements:** All work lands on a single `feat/v1.10.0` branch with one final PR to `main`. Nothing in this epic touches `request_filter` or the data plane's hot path: certificates reach the proxy through the existing store and hot-swap path (`notify_config_changed`, `reload_cert_resolver`), as ACME ones do. `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo audit`, `cargo fmt --all -- --check` and the frontend gates stay green at every commit.

**Cross-cutting deliverables** (release-blocking, owned by no single story):

- `docs/adcs.md`, the operator guide, including the **authority-side prerequisites** Lorica cannot check: a dedicated template with *Supply in the request* subject mode, the *Server Authentication* EKU only and enrollment restricted to the service account; `EDITF_ATTRIBUTESUBJECTALTNAME2` cleared on the authority; Extended Protection set to Required on the CES application; the CES instance in Kerberos mode; the template published on the authority; the `HTTP/<ces-host>` SPN registered on the CES application pool identity; AES encryption types enabled on the service account and the pool identity; a service account password that does not expire, or a documented rotation procedure; the network flows (HTTPS to the authority, Kerberos to the KDCs over TCP and UDP 88, DNS) and time synchronisation. It also states that every certificate event rotates the bot-protection HMAC (`rotate_bot_hmac_on_cert_event`), so an issuance invalidates visitors' verdict cookies, as an ACME issuance does today; and that unbound AD CS certificates are neither renewed nor purged.
- `docs/security/threat-model.md` gains the authority as an asset and the service account credential as a secret, with D5, D11, D13 and D15 as mitigations and D11's stated limit.
- `lorica-api/openapi.yaml` for every new endpoint, field and alert type, kept green against the contract test.
- `CHANGELOG.md` under Added and Security, including the new runtime library requirement (D7).
- Every example, fixture and test uses placeholder names (`corp.example.org`, `CORP.EXAMPLE.ORG`, `<CAName>`). No name, hostname, topology or configuration detail of any real deployment appears anywhere in the repository, and neither does the spike's source tree.

---

## Story 13.1: The `lorica-adcs` client

As a developer of the orchestration stories,
I want a tested client that turns a CSR into an issued certificate through CES,
so that every later story calls one function and none of them touches Kerberos, TLS bindings or XML.

### Acceptance Criteria

1. **New workspace member `lorica-adcs`**, a library crate, product version line, with every item of the new-crate checklist done in the same commit series (Dockerfiles, CI lists, both bump checklists, crate tables). In the same commit series, both halves of D7: the build requirements in every CI job, builder stage and `ci-check.Dockerfile`, and the runtime library in `dist/rpm/lorica.spec` (`Requires: krb5-libs`), `dist/build-deb.sh` (`Depends: libgssapi-krb5-2`) and the runtime stage of `Dockerfile` and `tests-e2e-docker/Dockerfile`.
2. **Ticket acquisition from a password** per D3, with `Cred::acquire_with_password` into the per-call `MEMORY:` cache. No child process is spawned. The password never appears in a log line, and the buffer holding it is zeroed after use.
3. **Generated `krb5.conf`** per D3 at `<data-dir>/adcs/krb5.conf`, written atomically by a typed renderer, and `KRB5_CONFIG` set in `main` after `Cli::parse` and before `init_logging`. A source-scan test (the pattern of `lorica/src/startup/mod.rs`'s ordering tests) asserts that the assignment precedes `init_logging` and every runtime construction in `main.rs`, and the call carries a `// SAFETY:` note for the edition 2024 migration, where `set_var` becomes `unsafe`.
4. **Channel binding per RFC 5929**, with a unit test per supported algorithm family (RSA PKCS#1 v1.5 and ECDSA with SHA-1, SHA-256, SHA-384, SHA-512) and a test that an unsupported algorithm is refused with its OID in the error.
5. **SPNEGO exchange** with the binding, and verification of the server's response token. A response without a valid mutual-authentication token is a failure.
6. **WS-Trust request and response** exactly as in "Verification against the specifications": the envelope, headers and URIs of the MS-WSTEP request, the template carried in the CSR, no WS-Security header. The response is parsed into one of four typed outcomes: **issued** (leaf from `RequestedSecurityToken`, chain from the sibling CMC response per D7), **pending** (a response with no certificate, keeping the `RequestID`), **denied** (a fault whose `CertificateEnrollmentWSDetail` has `InvalidRequest` true), **error** (any other fault, classified by `ErrorCode` into permission, template and other, with a missing detail handled as a generic error). Base64 decoding tolerates CR and LF. Retrieving a pending request (`QueryTokenStatus`) is out of scope ("Supported templates").
7. **CSR construction** with `rcgen`: key type per D4, SANs in the extension request, a non-empty subject per D5, and the `CertificateTemplate` name-value pair attribute carrying the template's common name. No `san:` attribute is ever produced, and a test asserts it; another decodes the CSR and checks the template attribute's encoding.
8. **Errors name the step that failed**: ticket acquisition (with the KDC's error code, so D15 can classify it), KDC discovery, TLS, channel binding, SPNEGO (401, missing or invalid mutual token), SOAP fault, denial. Story 13.2's connection test displays them as they are.
9. **Bounded operations** per D8: GSS-API calls on `spawn_blocking`, the profile's `kdc_timeout` and `max_retries` bounding the Kerberos legs, an outer tokio timeout, explicit HTTP connect and read timeouts. Checked against a harness KDC that never answers.
10. **Endpoint trust** per D12: when a bundle is configured, the client trusts it alone.
11. **Fixtures**: synthetic responses for each outcome, built to the structure of the MS-WSTEP examples (including a CMC response whose `certificates` set is unordered and contains the root) and generated by the test suite from its own throwaway CA rather than copied from the specification, and the GSS-API layer behind a trait so the SOAP, chain and binding logic are unit-tested without a KDC.
12. **A Kerberos test harness in Docker, owned by this story**: one MIT KDC realm and a CES fixture that authenticates with GSS-API, **refuses a context whose returned flags lack `GSS_C_CHANNEL_BOUND_FLAG`** (an MIT acceptor otherwise accepts a token that carries no binding at all), answers WS-Trust with each outcome on demand, and returns a mutual-authentication token. The harness ships its own probe client (test code outside `lorica-adcs`) able to present a token without a binding. Story 13.6 builds its end-to-end profile on this harness.

### Integration Verification

- IV1: Against the harness, the spike's observations are reproduced: 401 without credentials, success with the binding, and 401 for the harness probe client presenting a token without one.
- IV2: A server certificate signed under SHA-512 and one under SHA-256 both authenticate.
- IV3: A harness that returns no mutual-authentication token, or a forged one, fails the exchange.
- IV4: The production `Dockerfile` image built from the branch starts, and `ldd` on its `lorica` resolves every library.

---

## Story 13.2: The AD CS authority

As a SuperAdmin,
I want to declare my organisation's authority once and see immediately whether Lorica can reach it,
so that issuing a certificate later is one click for an operator and not a debugging session.

### Acceptance Criteria

1. **Schema, in one additive migration** at the next free version in `MIGRATIONS` (`lorica-config/src/store/mod.rs`): the authority table per D10, and the certificate columns of D14. The authority holds: CES endpoint (`https://` only), realm (`^[A-Z0-9][A-Z0-9.-]*$`), optional explicit KDC list (each `host[:port]` with RFC 1123 labels), service principal, password (own column, registered in `ENCRYPTED_COLUMNS` in the same commit, which the existing source-scan test enforces; write refused without a loaded key per D3), endpoint trust bundle and issuing CA certificate (D12), default template name (the template's common name, not its display name), default key type, subject defaults (`C`, `ST`, `L`, `O`, `OU`, email), allowed DNS suffixes (at least one, D5 semantics, wildcards refused), and the D15 failed state. Any other character in realm or KDC values is refused at the API, with injection test vectors for the `krb5.conf` renderer. The canonical-format change of D14 lands here, with its compatibility test.
2. **Management API** at the paths and roles of D11, with a `required_role` table test for each path. The password is write-only. A change to the endpoint, realm, KDC list or principal clears the password and is refused unless the same request supplies a new one. Deleting the authority while any certificate has `adcs_authority_id` set is refused with the list of those certificates.
3. **Connection test**: acquires a ticket, authenticates to the endpoint with the binding and mutual authentication, and reports success or the failing step from Story 13.1 AC #8. It requests no certificate. Rate-limited per D15, single-flight per D15, refused while the authority is in the failed state, and every test is audited.
4. **Failure state** per D15, persisted, visible on the settings page (since when, which step, KDC code), cleared only by a password write. Entry and exit are audited.
5. **Dashboard settings tab** `AdcsAuthorityTab.svelte` under `components/settings-tabs/`, editable when `$isSuperAdminRole`, read-only for other roles, with the authority-side prerequisites of `docs/adcs.md` linked from the tab. On a follower the tab shows "managed on the control plane" and offers no test button, so `every_path_the_dashboard_offers_on_a_follower_is_still_admitted` stays green.
6. **Cluster** per D13: the authority, its failed state and its issuing CA certificate are absent from the canonical blob and from every follower-facing payload, and a test asserts it.
7. **Export and import** per D14: the authority is not exported.
8. **Audit**: create, update (naming the fields changed, never their values when secret), delete, connection test.
9. **Alert types** `adcs_authority_failed` (one per entry into the failed state) and `cert_issuance_failed` (denial, fault, pending answer, renewal failure; carrying `cert_id` when there is one, the failing step and the authority's message) are added to `AlertType` (`lorica-notify/src/events.rs`), the dashboard's notification settings and history, and `openapi.yaml`. A migration subscribes channels saved with an explicit type list, as migration 63 (`migrate_subscribe_log_store_alerts`) does.

### Integration Verification

- IV1: An Operator token is refused on every authority write, including the suffix list, and admitted on the connection test; a SuperAdmin update of the realm without a password is refused and leaves the stored password unchanged.
- IV2: A connection test with a wrong password, an unreachable KDC, an untrusted endpoint certificate and a missing binding each report a distinct, named failure; the wrong password puts the authority in the failed state after one attempt, and the state survives a restart.

---

## Story 13.3: Issuing a new certificate

As an operator putting a service behind Lorica,
I want to obtain its certificate from my authority from the place I am already working,
so that I stop generating CSRs by hand and uploading what comes back.

### Acceptance Criteria

1. **Response shape** per D14: `CertificateResponse` gains the derived `source` (`acme`, `adcs`, `manual`) and the `adcs_*` fields, in `lorica-api` and `api.ts`.
2. **Issuance endpoint** `POST /api/v1/certificates/adcs`, Operator and above, taking SANs and optionally a template, key type and subject overrides. It checks every SAN against the allowlist **before** contacting the authority, and refuses the request naming the offending names. It refuses while the authority is in the failed state. It is rate-limited under a new `adcs_issue` bucket the size of `RL_ACME_PROVISION`, and it is single-flight with the other AD CS operations (D15).
3. **Certificate page**: an "AD CS" issuance form beside `CertificateAcmeForm.svelte`, SANs typed by the operator, defaults from the authority. A certificate issued here is not bound to a route; the renewal loop only renews bound certificates (`is_bound`), so it renews it once a route uses it. The form says so.
4. **Route form**: a new derived value, the route's hostname and aliases covered by **no stored certificate**, computed with `findUncoveredHostnames` (`lib/cert-san-match.ts`) over every certificate's `domain` plus `san_domains` (today `RoutingTab.svelte` only checks the selected certificate's `san_domains`), drives an "Issue from AD CS" action with those names pre-filled, wildcard aliases dropped (D5). A successful issuance sets the form's certificate selection; the binding persists when the route is saved. A route whose creation is cancelled leaves an unbound certificate, visible on the certificate page.
5. **Confirmation before every issuance**: a summary of the full request (template, key type, complete subject, every SAN) that the operator confirms. The confirmation is the dashboard's; the API documents that a call is an issuance.
6. **Outcomes**: issued, the certificate is stored with its chain, the subject **as issued** is displayed, the template OID observed in it is recorded, the issuing CA certificate is recorded on the authority if not yet known (D12), and the hot-swap path serves it; pending, nothing is stored and the request identifier is shown and audited ("Supported templates"); denied or fault, nothing is stored and the authority's message is shown.
7. **Audit and notification**: every issuance attempt is audited with SANs and outcome; a pending answer, a denial or a fault raises `cert_issuance_failed`.
8. **Automation plane and MCP**: no issuance path (D6). A test asserts that no automation route reaches the issuance endpoint.

### Integration Verification

- IV1: Issuing from the route form produces a certificate covering every hostname of the route and binds it, with no action besides saving the route.
- IV2: A SAN outside the allowlist, a wildcard SAN and a label-suffix lookalike (`evilcorp.example.org` against `corp.example.org`) are each refused with no request reaching the harness.

---

## Story 13.4: Renewal

As an operator,
I want AD CS certificates renewed the way ACME ones are,
so that an internal certificate never expires because someone forgot it.

### Acceptance Criteria

1. **A source-dispatched renewal loop.** The loop in `lorica-api/src/acme/renewal.rs` gains an AD CS arm and a dispatch by derived source (D14), with the same renewal window and the same `is_bound` rule for both sources. The ACME predicates (`should_auto_renew`, `is_bound`, `cooldown_from_error`, `superseded_orphans`) stay in `acme/renewal.rs`, so ACME behaviour is unchanged and the existing tests in `acme/tests.rs` stay green unmodified.
2. **Renewal is in place**: same certificate id, route bindings kept, new key and new CSR, the SANs and subject of the current certificate reused, **the certificate's recorded template** used (the authority's template is only the default at issuance). It takes the `RenewalLedger` in-flight mark shared by the loop and the dashboard; a second concurrent request answers 409.
3. **D15 in the loop**: one ticket per authority per tick, single-flight with every other AD CS operation; a pre-authentication failure stops every AD CS renewal for the tick and puts the authority in the failed state.
4. **Pending**: a renewal answered as pending keeps the current certificate in service, stores nothing, and is handled as a failure under AC #5, naming the request identifier.
5. **Failures** keep the current certificate in service, back off per certificate for non-credential failures, and raise `cert_issuance_failed` naming the failing step, once per failure state rather than once per tick.
6. **Expiry alerts**: `check_cert_expiry` alerts on every certificate in its window and the loop sends its own `CertExpiring` for eligible ones. The story decides which one speaks for an AD CS certificate and asserts that an operator receives one alert per certificate per state, not two.
7. **Audit**: every renewal attempt, loop included, writes an audit row, the loop's with `AuditContext::node("adcs-renewal")`. Today only the manual path audits (`certificate.renew`); an AD CS loop renewal is an issuance at the authority and is audited as one.
8. **"Renew now"** on the dashboard for an AD CS certificate, Operator and above, under the D15 breaker. The automation plane and MCP get `adcs_renewal_not_on_automation_plane` per D6, with the three-plane tests.

### Integration Verification

- IV1: A bound certificate whose expiry falls inside the window is renewed by the loop against the harness, keeps its id and route bindings, carries a different public key and was requested with its recorded template.
- IV2: With a wrong password and five AD CS certificates in the window, one tick makes exactly one ticket attempt and produces one `adcs_authority_failed` notification; a "Renew now" during the failed state makes none.

---

## Story 13.5: Adopting certificates issued before Lorica could

As an operator who has been issuing certificates by hand,
I want Lorica to recognise the ones my authority issued and take them over,
so that upgrading Lorica ends the manual work instead of adding a second process next to it.

### Acceptance Criteria

1. **Candidates** per D9: every manual certificate whose leaf is signed by the authority's **issuing CA certificate** (signature and authority key identifier) and whose SANs satisfy the allowlist. Detection runs when the issuing CA certificate is set or changes, and on demand. With no issuing CA certificate known yet, the page says how to provide one.
2. **The certificate page shows the candidates**, with individual and bulk adoption (`POST /api/v1/certificates/{id}/adcs/adopt`), Operator and above.
3. **The adoption summary** shows, per certificate, the SANs and subject that renewal will request (from the certificate, not from the authority's defaults), the template it was issued with (the OID of extension 1.3.6.1.4.1.311.21.7, or the name of 1.3.6.1.4.1.311.20.2 for a version 1 template, decoded as BMPString or UTF8String) next to the one observed on certificates Lorica issued with the authority's template ("unknown" when Lorica has issued none yet), with a warning when they differ, and the auto-renew setting.
4. **Adoption issues nothing.** It sets the `adcs_*` references. Renewal happens in the normal window, or immediately on "Renew now".
5. **Reverting to manual** is available on any AD CS certificate: it clears `adcs_authority_id`, Lorica stops renewing it and keeps the current certificate in service (distinct from auto-renew off, D14).
6. Audit for adoption and reversion, naming the certificates.

### Integration Verification

- IV1: A certificate signed by the issuing CA is offered; one signed by a sibling issuing CA under the same root is not; one signed by another chain with a forged identical issuer name is not.
- IV2: An adopted, bound certificate renews in place at its next window with its route bindings intact.

---

## Story 13.6: Packaging, end-to-end and the operator guide

As an operator installing or upgrading Lorica,
I want the AD CS support to install like the rest of Lorica and to be proven against a real Kerberos exchange,
so that the first time it meets my authority is not the first time it meets Kerberos.

### Acceptance Criteria

1. **Package install checks.** The packages already declare the runtime library (Story 13.1 AC #1). The install and upgrade scripts (`dist/tests/deb-upgrade.sh`, `dist/tests/rpm-upgrade.sh`, the `test-rpm-install` job) install the new package through `apt-get install ./<deb>` and `dnf install ./<rpm>`, so the dependency is resolved the way an operator's install resolves it; legs that install the previous release keep `dpkg -i` and `rpm -ivh`. Each job checks that `ldd /usr/bin/lorica` resolves and that the binary starts.
2. **The e2e Docker suite gains an `adcs` profile** built on the Story 13.1 harness: it drives the management API through authority creation, connection test, issuance from a route, renewal, adoption, reversion and the D15 breaker.
3. **`docs/adcs.md`** complete, with the authority-side prerequisites, the network flows, troubleshooting by failing step (Story 13.1 AC #8), the supported-templates statement, and what Lorica refuses to support and why (NTLM, Basic, `/certsrv`, the `san:` attribute, wildcards). The cross-realm case is documented as observed in the spike and not covered by the e2e profile, whose single MIT realm does not reproduce an AD KDC's referral.
4. The threat model, OpenAPI and changelog deliverables of the epic are complete.
5. **Release check against a real authority**, run by the maintainer from the release candidate's `.deb` before the PR to `main`: connection test, one issuance of a test name, one "Renew now", one adoption. It confirms what the specifications left *unconfirmed* (the `To` header, the response shapes, the `KRB5_CONFIG` behaviour under the shipped unit) and the profile timeouts. The outcome is recorded in the story with every name replaced by a placeholder, and the test certificates are revoked by the authority's administrators afterwards. A failure here reopens the story that owns the failing step.

### Integration Verification

- IV1: The `adcs` profile passes, including the harness probe client being refused without a binding.
- IV2: A fresh install on Debian 13 and on the RHEL target, through `apt-get install` and `dnf install`, starts Lorica with no Kerberos package installed by hand.
- IV3: The release check of AC #5 passes.

---

## Out of Scope (deferred)

- **The `/certsrv` web enrollment pages.** D1. Refused, not deferred.
- **CEP template discovery.** The template name is configured.
- **NTLM, HTTP Basic, and CES `UsernamePassword` instances.** D2. Refused.
- **Several authorities.** D10. The data model keeps the reference so a later release can add them without a migration.
- **Keytab credentials.** D3. A candidate if an estate only hands out keytabs.
- **Issuance and renewal through the automation plane or MCP.** D6.
- **Wildcard SANs.** D5.
- **CES `Certificate` authentication (renewal signed by the current certificate).** It would remove the password from renewals; it needs an authority-side CES instance in that mode.
- **Templates requiring manager approval.** "Supported templates".
- **Revocation from Lorica.** CES does not revoke; revocation stays with the authority's administrators. Deleting an AD CS certificate in Lorica says so.
- **One-click issuance from the route form for ACME.** The same affordance would serve ACME; this epic ships it for AD CS only.
- **Key reuse across renewals**, and the `san:` request attribute. D4. Refused.
- **Cross-realm Kerberos in the e2e suite.** Story 13.6 AC #3.
- **An ACME gateway in front of AD CS.** Considered and refused by the maintainer.
