# Story 13.1: The `lorica-adcs` Client

**Epic:** [Epic 13 - AD CS Certificate Enrollment over CES (v1.10.0)](../prd/epic-13-v1.10.0.md)
**Status:** Done
**Priority:** P0
**Author:** Romain G.
**Depends on:** nothing in this epic. It builds on `main` at `0245ab20`
(v1.9.3 plus the Epic 13 PRD).
**Blocks:** Stories 13.2 to 13.6. Every one of them calls the client
this story builds, and Story 13.6's end-to-end profile runs on the
harness this story owns.

---

As a developer of the orchestration stories,
I want a tested client that turns a CSR into an issued certificate through CES,
so that every later story calls one function and none of them touches
Kerberos, TLS bindings or XML.

## Problem

Lorica has no way to talk to an AD CS authority. The authority's
machine-facing enrollment API, CES, speaks SOAP 1.2 over HTTPS and, in
the deployments this epic targets, authenticates only with Kerberos
SPNEGO under IIS Extended Protection: a token without a TLS channel
binding is refused with a 401 even when the ticket is valid. A spike
outside the repository proved the binding works from Rust with
`libgssapi`; nothing of it is reusable code, and it never sent a real
enrollment request.

What this story produces is a leaf crate with one job: given an
authority's connection parameters, a password and a CSR, return an
issued certificate and its chain, or a typed reason why not. It knows
nothing about the store, routes, roles or the dashboard.

## Decisions taken in this story

**The CSR is built with `rcgen`'s `serialize_request_with_attributes`.**
Checked on docs.rs for rcgen 0.14: it takes `Vec<Attribute>`, where
`Attribute { oid: &'static [u64], values: Vec<u8> }` and `values` is the
DER of the attribute's `SET OF` values. The `CertificateTemplate`
name-value pair attribute (MS-WCCE 2.2.2.7.10, OID
1.3.6.1.4.1.311.13.2.1) is therefore DER-encoded by this crate and
handed to rcgen, which still emits the SAN `extensionRequest` from the
`CertificateParams`. No hand-built PKCS#10.

**No new direct dependency beyond the two approved ones.** Digests for
the channel binding use `ring` (already the workspace's TLS crypto
provider) rather than `sha2`; DER parsing uses the `der_parser`
re-exported by `x509-parser` 0.18; the WS-Addressing `MessageID` uses
`uuid` v4 as `lorica-api` does. `libgssapi` and `quick-xml` are the
only additions (PRD D7).

**The password buffer is wiped without `zeroize`.** AC #2 asks that
the buffer holding the password be zeroed after use. A plain loop of
zero writes can be removed by the optimiser; `zeroize` exists for that
reason but would be a new direct dependency, which the maintainer did
not approve. Decided 2026-10-21: the crate holds the password in a
`Secret` type whose `Drop` overwrites its bytes with
`core::ptr::write_volatile` followed by a `compiler_fence(SeqCst)`,
the same technique `zeroize` uses, in one function carrying
`#[allow(unsafe_code)]` and a `// SAFETY:` comment (the writes stay
inside a slice the type owns). Copies made by `libgssapi` and MIT krb5
during acquisition are outside Lorica's reach and are not claimed to be
wiped.

**The CES fixture of the harness is Python, not Rust.** The fixture
must refuse a context whose returned flags lack
`GSS_C_CHANNEL_BOUND_FLAG` (MIT 1.19+, value 0x800). Whether
`libgssapi`'s `ServerCtx::flags()` preserves a bit its `CtxFlags`
bitflags type does not declare is not established, and a fixture that
silently drops the bit would accept unbound tokens and prove nothing
(the challenge report's M9). `python3-gssapi` on Debian exposes the raw
flags and the channel-binding API directly, and the fixture is test
infrastructure, not shipped code. If Lot 4 finds that `libgssapi`
preserves the bit, a Rust fixture is acceptable; the refusal test is
what matters, not the language.

## Acceptance Criteria

These are the PRD's, unchanged. They are the contract.

1. **New workspace member `lorica-adcs`**, a library crate, product version line, with every item of the new-crate checklist done in the same commit series (Dockerfiles, CI lists, both bump checklists, crate tables). In the same commit series, both halves of D7: the build requirements in every CI job, builder stage and `ci-check.Dockerfile`, and the runtime library in `dist/rpm/lorica.spec` (`Requires: krb5-libs`), `dist/build-deb.sh` (`Depends: libgssapi-krb5-2`) and the runtime stage of `Dockerfile` and `tests-e2e-docker/Dockerfile`.
2. **Ticket acquisition from a password** per D3, with `Cred::acquire_with_password` into the per-call `MEMORY:` cache. No child process is spawned. The password never appears in a log line, and the buffer holding it is zeroed after use.
3. **Generated `krb5.conf`** per D3 at `<data-dir>/adcs/krb5.conf`, written atomically by a typed renderer, and `KRB5_CONFIG` set in `main` after `Cli::parse` and before `init_logging`. A source-scan test (the pattern of `lorica/src/startup/mod.rs`'s ordering tests) asserts that the assignment precedes `init_logging` and every runtime construction in `main.rs`, and the call carries a `// SAFETY:` note for the edition 2024 migration, where `set_var` becomes `unsafe`.
4. **Channel binding per RFC 5929**, with a unit test per supported algorithm family (RSA PKCS#1 v1.5 and ECDSA with SHA-1, SHA-256, SHA-384, SHA-512) and a test that an unsupported algorithm is refused with its OID in the error.
5. **SPNEGO exchange** with the binding, and verification of the server's response token. A response without a valid mutual-authentication token is a failure.
6. **WS-Trust request and response** exactly as in "Verification against the specifications": the envelope, headers and URIs of the MS-WSTEP request, the template carried in the CSR, no WS-Security header. The response is parsed into one of four typed outcomes: **issued** (leaf from `RequestedSecurityToken`, chain from the sibling CMC response per D7), **pending** (a response with no certificate, keeping the `RequestID`), **denied** (a fault whose `CertificateEnrollmentWSDetail` has `InvalidRequest` true), **error** (any other fault, classified by `ErrorCode` into permission, template and other, with a missing detail handled as a generic error). Base64 decoding tolerates CR and LF. Retrieving a pending request (`QueryTokenStatus`) is out of scope ("Supported templates").
7. **CSR construction** with `rcgen`: key type per D4, SANs in the extension request, a non-empty subject per D5, and the `CertificateTemplate` name-value pair attribute carrying the template's common name. No `san:` attribute is ever produced, and a test asserts it; another decodes the CSR and checks the template attribute's encoding.
8. **Errors name the step that failed**: ticket acquisition (with the KDC's error code, so D15 can classify it), KDC discovery, TLS, channel binding, SPNEGO (401, missing or invalid mutual token), SOAP fault, denial. Story 13.2's connection test displays them as they are.
9. **Bounded operations** per D8: GSS-API calls on `spawn_blocking`, the profile's `request_timeout` bounding the Kerberos legs where MIT supports it (1.22+), an outer tokio timeout, explicit HTTP connect and read timeouts. Checked against a harness KDC that never answers.
10. **Endpoint trust** per D12: when a bundle is configured, the client trusts it alone.
11. **Fixtures**: synthetic responses for each outcome, built to the structure of the MS-WSTEP examples (including a CMC response whose `certificates` set is unordered and contains the root) and generated by the test suite from its own throwaway CA rather than copied from the specification, and the GSS-API layer behind a trait so the SOAP, chain and binding logic are unit-tested without a KDC.
12. **A Kerberos test harness in Docker, owned by this story**: one MIT KDC realm and a CES fixture that authenticates with GSS-API, **refuses a context whose returned flags lack `GSS_C_CHANNEL_BOUND_FLAG`** (an MIT acceptor otherwise accepts a token that carries no binding at all), answers WS-Trust with each outcome on demand, and returns a mutual-authentication token. The harness ships its own probe client (test code outside `lorica-adcs`) able to present a token without a binding. Story 13.6 builds its end-to-end profile on this harness.

## Integration Verification

- IV1: Against the harness, the spike's observations are reproduced: 401 without credentials, success with the binding, and 401 for the harness probe client presenting a token without one.
- IV2: A server certificate signed under SHA-512 and one under SHA-256 both authenticate.
- IV3: A harness that returns no mutual-authentication token, or a forged one, fails the exchange.
- IV4: The production `Dockerfile` image built from the branch starts, and `ldd` on its `lorica` resolves every library.

## Tasks

Four lots. Each ends on a tree that builds and passes the full gate
chain (`cargo fmt --all -- --check`, the three clippy invocations of
`ci.yml` under `RUSTFLAGS=-D warnings`, `cargo test --workspace`,
`cargo audit`), so none of them is a skeleton waiting for the next.

### Lot 1: a crate that builds everywhere it has to

- [x] Workspace member `lorica-adcs`, `#![deny(unsafe_code)]`,
      `#![warn(missing_docs)]`, product version line, `thiserror` error
      type. Depends on `libgssapi` (pinned `=0.11.0`) and nothing
      first-party; a test in the crate links it so the build proves
      the system library is found.
- [x] The new-crate checklist of `.claude/rules/lorica-rust.md` in
      full: workspace `members`; `COPY lorica-adcs/ lorica-adcs/` in
      `Dockerfile`, `Dockerfile.dev`, `tests-e2e-docker/Dockerfile`
      (before the `tinyufo` line); the three crate lists of `ci.yml`
      (clippy, `cargo test -p`, coverage `-p`); both bump checklists
      (`docs/BUMP-CHECKLIST.md` and
      `.claude/skills/bump-version/bump-checklist.md`); the crate tables
      of `README.md`, `FORK.md`, `CONTRIBUTING.md`,
      `docs/architecture/source-tree.md`,
      `docs/architecture/component-architecture.md`; the crate lists of
      the `run-tests` and `build-deb` skills.
- [x] Build requirements `libkrb5-dev libclang-dev`: every `ci.yml` job
      that compiles the workspace (`lint`, `test`, `coverage`,
      `build-and-package`, and any other `cargo` job on a bare runner),
      the builder stage of the three Dockerfiles, and
      `ci-check.Dockerfile`'s own list.
- [x] Runtime library: `Requires: krb5-libs` in `dist/rpm/lorica.spec`,
      `libgssapi-krb5-2` in the `Depends:` of `dist/build-deb.sh`, and
      an explicit `libgssapi-krb5-2` in the runtime stage of
      `Dockerfile` and `tests-e2e-docker/Dockerfile` (not inherited
      through `curl`).
- [x] IV4 checked by hand: the production image builds, starts, and
      `ldd /usr/bin/lorica` inside it resolves.

### Lot 2: the pure logic, tested without a network

- [x] `channel_binding(cert_der) -> Result<Vec<u8>, AdcsError>`: RFC
      5929 hash selection, `tls-server-end-point:` prefix, `ring`
      digests. AC #4's test per family, generated certificates.
- [x] `krb5.conf` renderer from typed values (`Realm`, `KdcAddress`,
      constructors that validate the grammar of Story 13.2 AC #1 and
      are the only way to build them), with `rdns = false`, TCP
      preferred, AES-only enctypes, `request_timeout`, DNS
      SRV discovery or the explicit KDC list. Atomic write
      (sibling file, `fsync`, rename). Injection vectors (newline,
      `[`, `]`, `{`, `}`, `=`) refused at construction.
- [x] CSR builder: key generation per D4, subject with `CN` = first
      SAN plus the authority's fixed fields, SAN extension, and the
      `CertificateTemplate` attribute DER-encoded per MS-WCCE
      2.2.2.7.10. Tests: decode the CSR, assert the template
      attribute's OID and BMPString encoding, assert no `san:`
      attribute, assert the subject is never empty.
- [x] Envelope builder (`quick-xml` writer): the MS-WSTEP request with
      the exact URIs listed in Dev Notes. A golden-file test on the
      produced XML, with `MessageID` injected.
- [x] Response parser (`quick-xml` reader): the four outcomes of AC #6,
      namespace-aware, tolerant of CR/LF in base64, refusing a response
      with no `RequestSecurityTokenResponse`.
- [x] CMC chain extraction: walk `ContentInfo` -> `SignedData` ->
      `certificates` with `x509_parser::der_parser`, build the path
      from the leaf by issuer and subject (and AKI/SKI when present),
      drop the self-signed root, refuse a set that does not chain to
      the leaf.
- [x] Test fixtures (AC #11), generated at test time from a throwaway
      `rcgen` CA: an issued response with an unordered certificate set
      including the root, a pending response, a denial fault, an error
      fault with and without detail.

### Lot 3: Kerberos, HTTP, and the one public call

- [x] `Secret` type per the decision above: volatile wipe on `Drop`,
      no `Debug`/`Display` that prints the value, a test that the
      buffer reads zero after the wipe.
- [x] `GssBackend` trait (acquire with password, init step with
      binding, verify response token) with the `libgssapi`
      implementation and a test double. `Cred::acquire_with_password`
      with `GSS_MECH_SPNEGO` alone in the desired mechs (see Debug Log);
      target name `HTTP@<host>` as `GSS_NT_HOSTBASED_SERVICE`.
- [x] HTTP client: `reqwest` with `tls_info(true)`; when a trust bundle
      is set, `tls_built_in_root_certs(false)` plus that bundle only;
      connect and read timeouts. First POST unauthenticated to read the
      server certificate from the 401, then the authenticated POST with
      `Authorization: Negotiate <token>`, then the response token from
      `WWW-Authenticate` fed back to the context; anything short of a
      complete context is AC #5's failure.
- [x] `enroll(params, password, csr) -> Result<EnrollOutcome,
      AdcsError>` and `test_connection(params, password) ->
      Result<(), AdcsError>` (authentication only, no certificate), GSS
      calls on `spawn_blocking`, outer `tokio::time::timeout`. Every
      `AdcsError` variant names its step (AC #8); the ticket variant
      carries the KDC error code.
- [x] `KRB5_CONFIG` in `lorica/src/main.rs`, after `Cli::parse` and
      before the first `init_logging`, from `cli.data_dir`, with the
      `// SAFETY:` note; the source-scan test of AC #3. The `worker`
      subcommand arm needs nothing: workers never run the API (see Dev
      Notes).

### Lot 4: the harness

- [x] `tests-e2e-docker/adcs/`: an MIT KDC container (one realm,
      `CORP.EXAMPLE.ORG`, a service principal `HTTP/ces.corp.example.org`
      and a user principal with a password), and the CES fixture
      (Python, `python3-gssapi`, HTTPS with a certificate from a
      throwaway CA), which:
      - answers 401 `Negotiate` without credentials;
      - accepts a context only when the returned flags carry
        `GSS_C_CHANNEL_BOUND_FLAG` and the binding matches its own
        certificate;
      - returns a mutual-authentication token, or none, or a corrupted
        one, on demand;
      - answers the WS-Trust request with issued, pending, denied or
        error on demand, signing issued certificates with its CA;
      - can be switched to a KDC address that never answers.
- [x] The probe client (Python, in the harness) that sends a token
      without a binding.
- [x] A test entry point (a `#[ignore]`d integration test in
      `lorica-adcs/tests/`, run by the harness script) driving IV1 to
      IV3 and AC #9 against the containers.
- [x] Shell scripts under the harness LF-only (`.gitattributes`
      already covers `*.sh`, but a tool-written file can still carry
      CRLF: check with `file`).

## Dev Notes

### The request, byte for byte

From MS-WSTEP 4.1.1.1 and 3.1.4.1.2. Copy these strings, do not
retype them from memory:

- SOAP 1.2 envelope `http://www.w3.org/2003/05/soap-envelope`;
  WS-Addressing `http://www.w3.org/2005/08/addressing`.
- `a:Action` (`s:mustUnderstand="1"`):
  `http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep`.
- `a:MessageID` `urn:uuid:<v4>`; `a:ReplyTo/a:Address`
  `http://www.w3.org/2005/08/addressing/anonymous`; `a:To` the endpoint
  URL (not in the specification's example, sent by other clients,
  harmless).
- `RequestSecurityToken` in `http://docs.oasis-open.org/ws-sx/ws-trust/200512`:
  - `TokenType`
    `http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3`;
  - `RequestType` `http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue`;
  - `BinarySecurityToken` in
    `http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd`,
    `EncodingType` `...wssecurity-secext-1.0.xsd#base64binary` (lower
    case `b`, as in the example), `ValueType`
    `...wssecurity-secext-1.0.xsd#PKCS7` (the example's value, even
    though the payload is a bare PKCS#10);
  - `RequestID` in `http://schemas.microsoft.com/windows/pki/2009/01/enrollment`,
    `xsi:nil="true"`.
- `Content-Type: application/soap+xml; charset=utf-8`. POST.

### The response

- `RequestSecurityTokenResponseCollection` with one
  `RequestSecurityTokenResponse`; action `.../enrollment/RSTRC/wstep`.
- Issued: leaf in `RequestedSecurityToken/BinarySecurityToken`
  (`#X509v3`); chain in a sibling `BinarySecurityToken` (`#PKCS7`), a
  CA-signed CMC Full PKI Response (`id-cct-PKIResponse`,
  1.3.6.1.5.5.7.12.3). Its `certificates` set is unordered and contains
  the root. `DispositionMessage` and `RequestID` beside them.
- Pending: no certificate in `RequestedSecurityToken` (a
  `SecurityTokenReference` instead) and a `RequestID`. The specification
  has no example: key the outcome on "no X509v3 token and a RequestID",
  not on the exact shape of the reference.
- Fault: SOAP 1.2 `s:Fault`, optional detail
  `CertificateEnrollmentWSDetail` in the enrollment namespace with
  `BinaryResponse`, `ErrorCode` (signed `int`; compare as `u32`),
  `InvalidRequest`, `RequestID`. Known codes: 0x80094012 (no Enroll
  permission), 0x80094800 (template unknown, including a display name
  given instead of the common name), 0x80094802 (template conflict).
  The HTTP status of a fault is not specified; expect 500 and do not
  key on it.

### Why the template is not in `AdditionalContext`

MS-WSTEP defines no `ContextItem` name for it, and the CA reads the
template from the request itself (MS-WCCE 3.2.2.6.2.1.4.1): the
1.3.6.1.4.1.311.20.2 extension, the 1.3.6.1.4.1.311.13.2.1 name-value
pair, or a 1.3.6.1.4.1.311.21.7 OID extension. The name-value pair is
chosen because its encoding is unambiguous (the specification's own
example carries 20.2 in a form that contradicts its ASN.1 definition).
A 21.7 version higher than the template's revision is rejected; with no
21.7 the version is assumed (0,0), which passes.

### Credentials and `KRB5_CONFIG`

- `Cred::acquire_with_password(name, password, time_req, usage,
  desired_mechs)` is in the safe API of `libgssapi` 0.11.0, ungated.
  MIT implements it with `krb5_cc_new_unique(context, "MEMORY", ...)`,
  so each call gets its own cache and nothing touches the default
  ccache. Do not use `gss_krb5_ccache_name`: it is not in
  `libgssapi-sys` and it is process-global.
- `ClientCtx` is `Send`, not `Sync`. `step(tok, channel_bindings)`
  takes the binding as `application_data`; `libgssapi` zero-fills the
  addresses, which is what Windows expects.
- MIT reads `KRB5_CONFIG` with `secure_getenv` at every
  `krb5_init_context`. Setting it once in `main` covers every later
  acquisition. `secure_getenv` ignores it in an AT_SECURE process
  (setuid, file capabilities); the shipped unit's
  `AmbientCapabilities` with `NoNewPrivileges` is believed not to set
  AT_SECURE, and the release check of Story 13.6 confirms it.
- `main` runs `init_logging` inside the `match` arms (the `worker` arm
  at the top, the default path later); `--log-file` makes it spawn the
  `tracing_appender` thread, which is why the assignment goes before
  it. Workers are `fork` + `execv` with the `worker` subcommand, never
  run the API and never acquire a ticket, so the variable is set from
  the top-level `cli.data_dir` only.

### What a passing harness must not hide

An MIT acceptor given channel bindings still accepts a token that
carries none, unless the application checks
`GSS_C_CHANNEL_BOUND_FLAG` in the returned flags. A fixture that skips
the check turns IV1's third leg green while enforcing nothing, which
is exactly the failure Extended Protection exists to prevent. The
fixture's refusal of the probe client is the test of the test.

### The thing most likely to go wrong

The `WWW-Authenticate` response token on a 200/400/500 answer is easy
to ignore, and ignoring it still yields a working enrollment against a
real authority. It is the only proof that the server holds the
service key, and AC #5 makes it a failure condition. IV3 exists so this
cannot regress silently.

## Code Map

- `lorica/src/main.rs`: `Cli::parse` at the top of `main`, then the
  `match cli.command`; `init_logging` in the `worker` arm and in the
  default path.
- `lorica/src/startup/mod.rs`: the ordering source-scan tests to copy
  for AC #3.
- `lorica-api/Cargo.toml`: `reqwest` 0.12 with
  `rustls-tls-native-roots` and `rustls-tls-webpki-roots`; `rcgen`
  0.14; `x509-parser` 0.18; `uuid` v4. Match these versions in
  `lorica-adcs`.
- `.github/workflows/ci.yml`: clippy at lines starting
  `run: cargo clippy`, tests at `run: cargo test`, coverage `-p` list;
  print them with `grep -E '^\s+run: cargo' .github/workflows/ci.yml`.
- Dockerfiles: builder `apt-get install` lines and the `COPY` blocks
  ending with `lorica-mcp/` and `lorica-automation-policy/`.
- `dist/rpm/lorica.spec` (`Requires:`), `dist/build-deb.sh`
  (`Depends:`).

### Do not touch

- `lorica-api`, `lorica-config`, the dashboard: no orchestration, no
  schema, no endpoint in this story. Story 13.2 starts there.
- `dist/lorica.service`: unchanged by design (PRD D3).

## Dev Agent Record

### Debug Log

- 2026-10-21, Lot 1: the Docker data disk filled during the gates (a
  dedicated target volume had been created, against the project's disk
  rule); the volume was removed and later runs use `lorica-target` with
  `CARGO_INCREMENTAL=0`. `cargo audit` failed on four advisories
  already present on `main`; fixed in their own commit (`b88f3f3b`).
- 2026-10-21, Lot 2: `rcgen` 0.14 on the `ring` backend cannot generate
  RSA keys. RSA became the default key type (PRD D4 revised: a v2
  template with a legacy CSP only handles RSA), so Lot 3 enabled
  `rcgen`'s `aws_lc_rs` feature, already in the lockfile.
- 2026-10-21, Lot 2: the `CertificateTemplate` attribute is encoded as
  `SET { SEQUENCE { BMPString name, BMPString value } }`, the form
  `certreq` produces; MS-WCCE 2.2.2.7.10 reads as a `SEQUENCE OF`
  inside the set. To be confirmed by the release check of Story 13.6.
- 2026-10-21, Lot 4: acquiring with SPNEGO and KRB5 as desired
  mechanisms sent two AS-REQs per acquisition (MIT 1.20 and 1.21), so a
  wrong password cost two pre-authentication failures against the
  account lockout. Acquisition now asks for SPNEGO only; the harness
  asserts exactly one AS-REQ and one `PREAUTH_FAILED`. SPNEGO renumbers
  the Kerberos minor status, so the KDC error code is recovered from
  the message MIT wraps it in.
- 2026-10-21, Lot 4: `kdc_timeout` and `max_retries` are Heimdal
  relations MIT ignores; a silent KDC costs about 27 s on MIT 1.20/1.21.
  The renderer now emits `request_timeout` (MIT 1.22+, ignored before),
  and the PRD and AC #9 say the outer timeout plus Story 13.2's
  single-flight guard are the real bound.
- 2026-10-21, IV4: the `lorica` binary runs on `debian:bookworm-slim`
  with the runtime packages of the production `Dockerfile`, but it does
  not link `libgssapi_krb5` yet: `lorica` only calls
  `krb5_config_path`, and the linker drops a library none of whose
  symbols are used. IV4 is meaningful once Story 13.2 calls the client
  from `lorica-api`, and is checked at the end of that story.

### Completion Notes

- AC #1 to #12 met. IV1 to IV3 pass in the harness
  (`tests-e2e-docker/adcs/run.sh`, ten tests plus the probe client).
  IV4 carried to the end of Story 13.2 (Debug Log).
- `test_connection` is an authenticated GET of the endpoint: IIS
  authenticates before WCF refuses the method, so no request reaches
  the CA's database.
- The password is held in `Secret`, wiped with volatile writes over its
  whole allocation on drop; copies inside `libgssapi` and MIT are out of
  reach and not claimed.

## File List

- `lorica-adcs/Cargo.toml`, `lorica-adcs/src/{lib,error,binding,krb5conf,csr,der,chain,secret,gss,client,test_support}.rs`,
  `lorica-adcs/src/client/tests.rs`, `lorica-adcs/src/wstep/{mod,request,response}.rs`,
  `lorica-adcs/src/wstep/request.golden.xml`, `lorica-adcs/tests/harness.rs`
- `tests-e2e-docker/adcs/` (KDC, CES fixture, probe, black hole, compose, `run.sh`)
- `lorica/Cargo.toml`, `lorica/src/main.rs`
- `Cargo.toml`, `Cargo.lock`, `.github/workflows/ci.yml`, `Dockerfile`,
  `Dockerfile.dev`, `tests-e2e-docker/Dockerfile`, `ci-check.Dockerfile`,
  `dist/rpm/lorica.spec`, `dist/build-deb.sh`
- `README.md`, `FORK.md`, `CONTRIBUTING.md`, `docs/BUMP-CHECKLIST.md`,
  `docs/architecture/source-tree.md`, `docs/architecture/component-architecture.md`

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-10-21 | 0.1 | Story drafted from the Epic 13 PRD after the specification check. Status Draft. | Romain G. |
| 2026-10-21 | 0.2 | Password wipe decided without `zeroize` (volatile writes). Status Approved. | Romain G. |
| 2026-10-21 | 0.3 | Lots 1 to 4 implemented; SPNEGO-only acquisition and request_timeout after the harness findings; IV4 carried to Story 13.2. Status Review. | Romain G. |
| 2026-10-21 | 0.4 | IV4 verified after Story 13.2 Lot 3: `lorica` links `libgssapi_krb5.so.2`, resolved on `debian:bookworm-slim` with the production runtime packages. Status Done. | Romain G. |
