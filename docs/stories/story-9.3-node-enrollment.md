# Story 9.3: Node Enrollment, Registry and Revocation

**Epic:** 9 (v1.7.0)
**Status:** Review
**Author:** Romain G.

**Depends on:** Stories 9.1, 9.2.

## Story

As an operator,
I want to enroll a new node with a single short-lived token and revoke
it just as easily,
so that adding an edge is a one-command operation and a decommissioned
node loses fleet access immediately.

## Acceptance Criteria

1. Token shape is `<public_id>.<secret>`. The database indexes
   `public_id` and stores a hash of the secret only, so exactly one
   verification runs per attempt. Verification uses HMAC-SHA256 with a
   server-side key, not a memory-hard KDF, and runs under a global
   semaphore capping concurrent verifications. Comparison is
   constant-time; error and timing are identical whether `public_id`
   exists or not.
2. The token pins the SHA-256 of the **control-plane leaf SPKI**, not
   the CA. The joiner also verifies the presented SAN against the
   `--control-plane` host. Node certificates are issued `clientAuth`-only
   and the control-plane certificate `serverAuth`-only.
3. **No CSR.** The follower sends a bare public key; the control plane
   assigns subject, SANs, EKU, basic constraints (`CA:FALSE`) and
   validity itself, and validates the key type against an allowlist
   (Ed25519, P-256, RSA-2048+). The private key never leaves the node.
4. Single use is atomic and precedes issuance: one conditional update
   (`UPDATE ... SET state='burned' WHERE id=? AND state='unused'`) must
   report exactly one affected row **before** any certificate is signed;
   zero rows aborts.
5. Enrollment lands in `Pending`. The node receives no configuration and
   no certificates until a SuperAdmin activates it, unless an explicit
   auto-activate opt-in is set. A token may be bound at mint time to an
   expected node name and optionally a source CIDR, both enforced at
   redemption.
6. The token never appears in argv: `--token-file`, `--token-stdin` and
   `LORICA_JOIN_TOKEN` are the documented paths; a literal
   `--token <value>` either does not exist or emits a loud warning.
7. Revocation is enforced during the handshake: the fingerprint enters a
   CRL, the cluster `ServerConfig` is rebuilt with `with_crls()` and the
   acceptor arc-swapped. Revocation also tears down in-flight sessions
   synchronously.
8. Node identity comes from the peer certificate fingerprint recorded at
   enrollment, never from the message body. A `node_id` in a payload is
   ignored; a mismatch drops the connection and audits. The fingerprint
   is SHA-256.
9. `cluster_nodes` table: `node_id`, `name`, `cert_fingerprint`,
   `address`, `version`, `schema_version`, `status`
   (`Pending`/`Active`/`Revoked`), `enrolled_at`, `last_seen_at`,
   `applied_config_generation`, `applied_config_hash`.
10. `GET /api/v1/cluster/nodes` (Viewer+, secrets scrubbed),
    `GET /api/v1/cluster/nodes/{id}` (Viewer+),
    `POST /api/v1/cluster/nodes/{id}/activate` (SuperAdmin),
    `DELETE /api/v1/cluster/nodes/{id}` (SuperAdmin, revokes).
11. Rate limiting is listener-level: per-IP **and** global
    concurrent-enrollment caps, a hard map size cap with LRU eviction, a
    sliding window, IPv6 keyed by /64.
12. Node certificates valid 90 days, auto-renewing at two thirds of
    lifetime over the established channel.
13. `lorica cluster leave` requires control-plane deregistration or a
    SuperAdmin credential on the local management API; wipes the node
    key, the CA bundle **and every replicated certificate private key**;
    audits on both sides and alerts immediately on the control plane.
14. `lorica cluster status` prints role, node id, connection state,
    applied generation, and the fleet roster on a control plane.

## Tasks / Subtasks

- [x] AC #1: token mint/format, indexed `public_id`, HMAC verification,
      semaphore, constant-time compare, uniform error and timing.
- [x] AC #2: leaf-SPKI pinning, SAN check, EKU separation.
- [x] AC #3: bare-public-key flow, server-assigned params, key-type
      allowlist.
- [x] AC #4: atomic burn ahead of signing.
- [x] AC #5: `Pending` lifecycle, activation endpoint, name/CIDR binding.
- [x] AC #6: `--token-file` / `--token-stdin` / env; warn or remove the
      literal form.
- [x] AC #7: CRL minting, `ServerConfig` rebuild, acceptor arc-swap,
      synchronous session teardown.
- [x] AC #8: identity derived from certificate fingerprint; payload
      `node_id` ignored; mismatch drops and audits.
- [x] AC #9: migration for `cluster_nodes`.
- [x] AC #10: four endpoints + OpenAPI entries.
- [x] AC #11: listener-level limiter.
- [x] AC #12: 90-day certs + auto-renew.
- [x] AC #13: authorised `leave` with full wipe and dual audit.
- [x] AC #14: `cluster status`.

## Dev Notes

Almost every AC here exists because the adversarial review broke the
first draft's version. Read the rationale before simplifying anything.

**AC #1: the first draft turned enrollment into a DoS primitive.** It
stored only an argon2id hash with no lookup key, which forces one
verification per live token per attempt. The existing parameters are
`Params::new(19456, 2, 1)`, i.e. 19 MiB per verify
(`lorica-api/src/auth.rs:24-29`). Two hundred concurrent attempts
against five live tokens is roughly 19 GB of transient allocation and
full CPU saturation, on a node also terminating production TLS, which
breaks the epic's "data plane is sacred" invariant. A join token is 256
bits of machine-generated entropy, not a human password, so a memory-hard
KDF buys nothing and costs the attack.

**AC #2: CA-fingerprint pinning is not control-plane identity pinning.**
Pinning the CA admits any certificate the cluster CA ever issued, so a
compromised follower could stand up a rogue control plane, redirect the
joiner by DNS or ARP, present its own valid node certificate and harvest
the token. That is precisely the attack the pin exists to prevent. EKU
separation closes the same hole from the other side.

**AC #3: dropping the CSR solves two problems at once.** Security: an
unconstrained CSR lets a leaked token request `CA:TRUE` and receive a
subordinate CA, which node revocation cannot touch, granting permanent
unrevocable fleet membership. Practicality: rcgen 0.14's
`CertificateSigningRequestParams::from_der` / `from_pem` are
`#[cfg(feature = "x509-parser")]` (`rcgen-0.14.9/src/csr.rs:86`, `:109`)
and that feature is off by default, so parsing a CSR would need a
feature flip requiring sign-off. Signing from a bare public key works
with today's defaults: `CertificateParams::signed_by` is already used at
`lorica-api/src/certificates.rs:543-547` and
`lorica-api/src/management_tls.rs:174-212`.

**AC #4**: if the burn is a separate write after signing, N simultaneous
joins with one token all read `state=unused` and all succeed. Note the
first draft's IV tested replay *after* a completed join, which a
vulnerable implementation passes, so the race would have shipped
untested. IV1 below fixes that.

**AC #5**: without it, a one-hour token converts into a 90-day
self-renewing identity (AC #12) holding fleet configuration and, via
Story 9.5, private keys. The TTL cap would protect nothing past the
first hour. Note the first draft defined a `Pending` status in the schema
and then never used it.

**AC #6**: argv is readable through `/proc/*/cmdline`, lands in shell
history, and is logged verbatim by CI and Ansible `command:` modules
unless `no_log` is set. Story 9.7 AC #2 must match this: the dashboard
must not display a ready-to-paste `--token <value>` command.

**AC #7 is new machinery, not a line item.** rustls 0.23.43 does support
it: `ClientCertVerifierBuilder::with_crls()` exists
(`rustls-0.23.43/src/webpki/client_verifier.rs:99`, plus
`only_check_end_entity_revocation` `:116` and
`allow_unknown_revocation_status` `:138`), `CertificateRevocationListDer`
is already re-exported (`lorica-tls/src/lib.rs:53`), and rcgen can mint
the CRL (`rcgen-0.14.9/src/crl.rs:163`, `:187`). But nothing in Lorica
uses `with_crls` today (the only `crl` hits are the unrelated
`--upstream-crl-file` connector option, `cli.rs:113`), and because a
`ServerConfig` is immutable every revocation means rebuilding it and
swapping the acceptor. Budget CRL minting, rebuild and swap as their own
task.

**AC #8**: `WebPkiClientVerifier` proves "signed by the cluster CA" and
nothing more. Trusting a body-supplied `node_id` lets follower C claim to
be follower B: poisoning B's telemetry and audit stream, forging B's
applied generation to hide drift, and receiving configuration scoped to B
under Story 9.4's `node_selector`. Do **not** reuse
`compute_ca_fingerprint` (`mtls.rs:132-152`): it is a non-cryptographic
`DefaultHasher`, unstable across Rust versions, and is only a drift
warning today.

**AC #11**: the existing per-endpoint limiter is axum middleware and
does not exist on a raw TLS listener, so "reuse" is not implementable.
Where it does apply it is documented as loopback-scale
(`middleware/rate_limit.rs:52-62`), is a fixed window (2x burst across
the boundary), only evicts entries older than 300 s (`:132-135`), and
falls back to the key `"127.0.0.1"` when `ConnectInfo` is absent
(`:197-199`). An attacker rotating addresses from an IPv6 /64 keeps every
entry fresh and grows the map without bound under a single global mutex.

**AC #13**: the first draft let any local shell run `leave`, regain
local write access, and keep every fleet hostname's private key on disk,
with the control plane learning about it only through drift.

## Dev Agent Record

### Debug Log

- 2026-09-06: Phase 1 pre-implementation review against the 9.2
  transport as shipped (listener.rs, dialer.rs, tls.rs, ca.rs,
  messages.rs), rustls 0.23.43 `with_crls` /
  `only_check_end_entity_revocation`, rcgen 0.14.9
  (`SubjectPublicKeyInfo::from_der`, `CertificateParams::signed_by`
  taking any `PublicKeyData`, `CertificateRevocationListParams`).
  Everything the story needs exists in the pinned versions; no
  feature flip and no new workspace dependency.

### Completion Notes

- **Phase 1 decisions** (each one is a place where the ACs left a
  gap or two ACs pulled against each other):
  - **D1 - token minting has a surface the AC list forgot.** AC #10
    names only node endpoints, but 9.7 AC #2 mints tokens from the
    dashboard and AC #6 forbids the token in argv. Added:
    `POST /api/v1/cluster/tokens` (SuperAdmin; returns the token
    exactly once), `GET /api/v1/cluster/tokens` (SuperAdmin; never
    the secret), `DELETE /api/v1/cluster/tokens/{public_id}`
    (SuperAdmin; revokes an unused token, closes the window). The
    CLI form `lorica cluster token` calls the local management API
    with SuperAdmin credentials, the `run_unban` precedent.
  - **D2 - token shape satisfies AC #1 and AC #2 literally.**
    `<public_id>.<payload>` with `public_id` = 12 random bytes hex
    (the indexed lookup key) and `payload` = base64url of
    `secret[32] || control_plane_leaf_spki_sha256[32]`. The HMAC
    covers the 32-byte secret only. The server-side HMAC key is a
    dedicated encrypted row in a new `cluster_secrets` table,
    registered in the rotation registry (Story 9.1 gate). Redemption
    order: SELECT by `public_id` -> `ring::hmac::verify` (constant
    time; an unknown id verifies against a fixed dummy so timing and
    error are identical) -> the conditional burn UPDATE must report
    one row -> only then sign. A token is not burned by a wrong
    secret.
  - **D3 - redemption logic lives in the binary, behind a trait.**
    The transport crate stays free of `ConfigStore` (the 9.2
    deferral). `lorica-cluster` defines `EnrollmentHandler`
    (boxed-future methods, no `async-trait`); the binary implements
    it with the store, the CA, the HMAC key and `ipnet` for the CIDR
    binding. The listener's existing `max_inflight_enrollments`
    semaphore IS the AC #1 global verification cap.
  - **D4 - the joiner has no CA yet, so it pins.** A custom
    `ServerCertVerifier` (`tls::join_client_config`) accepts the
    control plane iff the leaf SPKI SHA-256 equals the token's pin,
    the SAN matches the `--control-plane` host, the validity window
    holds and EKU carries `serverAuth`. Parsing uses `x509-parser`
    (already in the tree at 0.18 through lorica-api and rcgen's
    feature). The verifier is the one `dangerous()` use in the crate
    and is confined to the enrollment dial.
  - **D5 - server-assigned node certificates.** CN = `node_id`
    (UUID v4), `clientAuth` only, `CA:FALSE`, 90 days, serial = 16
    random bytes (top bit cleared) recorded in the registry because
    CRLs revoke by serial, not by fingerprint. Key-type allowlist
    checked on the bare SPKI: Ed25519, P-256, RSA with a modulus of
    at least 2048 bits.
  - **D6 - roster in memory, store as the source of truth.**
    `cluster_nodes` gets AC #9's columns plus `cert_serial`,
    `prev_cert_fingerprint`, `prev_cert_serial`. The crate keeps an
    `ArcSwap<HashMap<fingerprint, NodeIdentity>>` the binary reloads
    after every registry mutation, so a connection never touches
    SQLite. An unknown fingerprint (valid certificate, no row) or a
    `Revoked` row is dropped and audited; a `Pending` node is
    admitted to a session (heartbeats, visibility) and Story 9.4
    gates configuration on `Active`.
  - **D7 - session registry with a kill switch.** Sessions register
    by `node_id` after identity resolution; a newer session for the
    same node supersedes the older one; revocation flips the
    session's watch and the loop exits synchronously (AC #7 second
    half). Live facts (connected, last seen, peer address, build
    version, schema) live in the registry and a 30 s flush persists
    `last_seen_at` / `address` / `version` / `schema_version`. Hello
    gains `build_version` (tag 5, bounded like `node_name`).
  - **D8 - CRL.** rcgen mints one CRL over every `Revoked` (and
    superseded) serial; the acceptor is rebuilt with
    `with_crls(...).only_check_end_entity_revocation()` and swapped;
    the same rebuild runs at boot. With nothing revoked the verifier
    carries no CRL at all (no phantom "unknown status" failures).
  - **D9 - one handle for the API.** `lorica_cluster::ControlPlane`
    owns roster, session registry, acceptor, CA, CRL state, fleet
    size and the token-liveness sender; `AppState` carries it as
    `cluster_control: Option<Arc<ControlPlane>>` and every mutating
    endpoint writes the store first, then calls the handle.
  - **D10 - listener-level limiter, no `lru`.** `EnrollmentLimiter`
    runs at accept, before TLS: sliding window per key (IPv4 /32,
    IPv6 /64), per-key concurrent cap, the existing global semaphore,
    a hard map cap (4096) with oldest-entry eviction implemented in
    place (a bounded scan at the cap beats a new dependency).
  - **D11 - follower runtime.** New single-row `cluster_identity`
    (node id, name, certificate, encrypted key in the registry, CA
    PEM, control-plane address and server name, enrolled_at).
    Startup spawns the dialer in both modes when the row exists.
    `lorica cluster join` writes the row and asks for a restart; it
    refuses on a control plane (CA row present) or an enrolled node.
    Renewal is follower-initiated (`Renew{public_key_der}` at two
    thirds of lifetime over the session); the control plane keeps
    the previous certificate valid until the first session on the
    new one, then revokes it as superseded (a crash between issuance
    and persistence does not brick the node).
    `DialerHandle::update_identity` swaps the connector for the next
    reconnect.
  - **D12 - `leave` is two paths, both authorised.** With SuperAdmin
    credentials: `POST /api/v1/cluster/leave` on the local API sends
    `Leave` over the session (the control plane revokes, audits,
    alerts), then wipes and audits locally. Without credentials: the
    CLI dials the control plane with the node identity; a TLS
    refusal proves control-plane-side deregistration and the CLI
    wipes and writes the local audit row through `LogStore`; an
    admitted session means "still registered" and the command
    refuses. Replicated certificate private keys do not exist before
    Story 9.5; the wipe covers the identity and 9.5 extends it with
    its provenance column (recorded in that story's file list).
  - **D13 - `cluster status`.** Offline facts from the database
    (role, node id, enrolled_at); live facts through
    `GET /api/v1/cluster/status` (Viewer+) when credentials are
    passed: connection state, applied generation (0 until 9.4), and
    the roster on a control plane.
  - **D14 - `--cluster-auto-activate`** is the explicit opt-in of
    AC #5, inherited across hot upgrades and logged at WARN.
  - **D15 - audit and alerts.** Every lifecycle operation goes
    through `audit::record` on the control plane (`cluster.token.mint`,
    `cluster.token.revoke`, `cluster.node.enroll`,
    `cluster.node.activate`, `cluster.node.revoke`,
    `cluster.node.renew`, `cluster.node.leave`). Operations that
    arrive on the cluster plane rather than a session use an
    `AuditContext` with operator `cluster`, role `node` and the
    peer address. A node leaving raises a `ClusterNodeLeft` alert.
- **Implementation notes (2026-09-06)**:
  - The transport crate still has no store dependency: redemption and
    lifecycle run behind `EnrollmentHandler` / `SessionHandler` in the
    binary (`startup/cluster_plane.rs`), which owns the store, the CA
    (through the `ControlPlane` handle), the audit log
    (`audit::record_with_store`, the `AppState`-free variant) and the
    alert dispatcher. The API acts on the same handle
    (`AppState.cluster`), so every mutation is store first, then
    roster reload + CRL rebuild, then session kill, then audit.
  - AC #1's constant-time property: the handler verifies against a
    fixed dummy digest when the `public_id` is unknown, so unknown-id
    and wrong-secret attempts cost the same HMAC and answer the same
    opaque status; the listener's in-flight enrollment permit (8) is
    the global verification cap.
  - AC #4: the key allowlist and the mint-time bindings are checked
    BEFORE the burn (a bad key or a wrong CIDR must not consume a good
    token); the burn is `UPDATE ... WHERE state='unused' AND
    expires_at > now`; a signing failure after the burn leaves a
    burned token and a loud error (the operator mints another).
  - AC #7: `operational_server_config_with_crl` uses
    `with_crls(...).only_check_end_entity_revocation()`; the CRL is
    minted from `cluster_revoked_serials` (operator revocations AND
    superseded renewals) at boot and after every change. With nothing
    revoked the verifier carries no CRL at all.
  - AC #12: the previous certificate stays resolvable (roster entry
    flagged `via_previous_certificate`) until the node's first session
    on the new one; `on_session_established` retires it. Two renewals
    without a session in between retire the older one first.
  - AC #13 `leave` without credentials proves deregistration by
    probing: a TLS refusal, or a connection closed right after mTLS
    (how TLS 1.3 surfaces a rejected client certificate), counts;
    "unreachable" and "admitted" both refuse. Replicated certificate
    keys do not exist before 9.5.
  - `cluster status` never needs the service running for the
    persisted facts; live facts come from `GET /api/v1/cluster/status`.
  - Not done here, by design: the dashboard (9.7); a per-fingerprint
    connection cap (the registry counts sessions per node, so a
    per-identity cap is a 9.4 follow-up alongside the dispatcher).
- **QA iteration 1 (2026-09-06)**: four auditors (security,
  architecture, quality, performance) returned 1 Critical, 6 High
  after aggregation and about seventeen Mediums; every Critical, High
  and Medium fixed, most Lows too:
  - Critical (performance): redemption and renewal held the store's
    async mutex across rcgen signing, serializing the reload path and
    every management handler behind cluster-plane crypto. Both are now
    three phases: verify + bindings + allowlist + atomic burn (or the
    renewal eligibility check) under a short lock, signing on the
    blocking pool with NO lock, then a second short lock to persist.
  - High: `Renew` was served to any session without an eligibility
    check, so a `Pending` node self-renewed forever (AC #5 defeated)
    and any node could loop the signing path at line rate. A renewal
    now requires `Active`, at most 35 days of remaining validity, one
    grant per node per hour, and at most three requests per session
    (more is a protocol violation that drops the session); the store
    guard mirrors the `Active` rule in its UPDATE.
  - High: revocation was a non-atomic, non-retryable sequence (store
    write, refresh, kill) whose refresh error skipped the session
    kill and whose retry hit 404. `revoke_node_fully` in the runtime
    layer kills the session even when the refresh fails and is
    idempotent: a repeated DELETE re-runs the CRL rebuild and the kill.
  - High: two concurrent refreshes could land out of order and undo a
    revocation; `refresh_control_plane` now holds the control plane's
    refresh lock across the read AND the swaps, rebuilds the acceptor
    BEFORE swapping the roster, and skips the mint + rustls rebuild
    when the revoked-serial set is unchanged.
  - High: followers renewed at a fixed 30-day lead with no jitter (a
    batch enrolled together renewed together); the lead is drawn per
    process in 25..30 days. A successful renewal now drops the session
    and reconnects on the new certificate immediately, so the
    superseded one is retired within seconds instead of "whenever the
    old session ends".
  - High: the renewal audit row carried a fabricated `0.0.0.0:0`;
    `RenewRequest` carries the session peer.
  - Medium (security): the RSA allowlist could be inflated with a
    zero-padded modulus and never looked at the exponent (`e = 1`
    forgeable); significant bytes are counted and `e` must be odd and
    at least 65537. The credential-less `leave` treated any transport
    failure as proof of deregistration; only a certificate-level TLS
    alert from the control plane counts now, a reset, an EOF or a
    timeout refuses the wipe. The cluster CLI took the SuperAdmin
    password on argv: `--password-file`, `--password-stdin` and
    `LORICA_ADMIN_PASSWORD` are the documented sources (`--password`
    stays with a warning).
  - Medium (architecture): the fleet runtime rule moved out of the
    HTTP handlers into `lorica-api/src/cluster/runtime.rs`; both
    startup modes call one `startup::spawn_cluster_runtime`; the
    cluster CLI lives in the binary (`cli_cluster.rs`, `cluster init`
    included) with one shared management-API client (`cli_client.rs`,
    `unban` rewritten on it); `ControlPlane.ca` is private (signing
    only through `issue_node_leaf`); `issue_client_leaf` (control
    plane generating node keys) is gone; the `public_id` shape is
    checked at the unauthenticated boundary; the credential-less
    leave audits through `record_with_store`; the redemption pipeline
    is a free function unit-tested against a real store (allowlist
    and bindings before the burn, replay, concurrency, auto-activate).
  - Medium (performance): revoked serials carry the certificate's
    expiry, expired ones are pruned every flush and excluded from the
    CRL; the session flush is one transaction.
  - AC #11 completed: a per-source sliding-window attempt limiter on
    the enrollment listener (20 per 60 s per source, 4096 sources
    tracked, oldest evicted at the cap), counted as
    `attempt_window`.
  - Lows fixed: leftover statement in a test, INSERT lists derived
    from the SELECT constants, `token::mint` typed error,
    `LiveSession` re-exported, doc wording, admission constants no
    longer duplicated in the binary, no-empty node name at the
    boundary.

## File List

- `lorica-cluster/src/token.rs` (new): token shape, mint, parse,
  keyed constant-time verification, local base64url.
- `lorica-cluster/src/enroll.rs` (new): `EnrollmentHandler` and
  `SessionHandler` traits (boxed futures), the pinned joiner `join()`,
  `decode_enroll_frame`, test stubs.
- `lorica-cluster/src/roster.rs` (new): `Roster`, `SessionRegistry`
  with kill switches, `ControlPlane` handle (CRL rebuild, liveness).
- `lorica-cluster/src/ca.rs`: bare-public-key issuance with the
  allowlist and random serials, CRL minting, `generate_node_keypair`.
- `lorica-cluster/src/tls.rs`: `SpkiPinVerifier` /
  `join_client_config`, `operational_server_config_with_crl`,
  `leaf_spki_sha256`.
- `lorica-cluster/src/messages.rs`, `proto/cluster.proto`: `Enroll`,
  `Renew`, `Leave` bodies (tags 12-14) and acks, `Hello.build_version`.
- `lorica-cluster/src/bridge.rs`, `handshake.rs`, `session.rs`,
  `dialer.rs` (`update_identity`), `listener/enrollment.rs`
  (redemption), `listener/operational.rs` (identity, registry, kill
  switch, renew/leave), `lib.rs`, `Cargo.toml` (`x509-parser`).
- `lorica-cluster/tests/enrollment.rs` (new): IV1 concurrency shape,
  IV2 revocation, IV3 identity, grace window, renew/leave.
- `lorica-config/src/models/cluster.rs` (new),
  `store/cluster_nodes.rs`, `store/cluster_tokens.rs`,
  `store/cluster_identity.rs` (new), `store/mod.rs` (migration 50,
  rotation registry, `encrypt_bytes`), `models/mod.rs`, `tests.rs`.
- `lorica-api/src/cluster.rs` (new): `ClusterRuntime`, token and node
  endpoints, status, leave, roster/CRL refresh; `server.rs`,
  `lib.rs`, `middleware/authorize.rs`, `audit.rs`
  (`record_with_store`), `metrics.rs`, `openapi.yaml`, `tests.rs`.
- `lorica-notify/src/events.rs`, `channels/slack.rs`:
  `AlertType::ClusterNodeLeft`.
- `lorica/src/startup/cluster_plane.rs` (fleet runtime, redemption
  and lifecycle hooks, liveness publisher, session flush),
  `startup/cluster_follower.rs` (new), `startup/mod.rs`,
  `startup/single.rs`, `startup/supervisor.rs`, `cli.rs`
  (`--cluster-auto-activate`, subcommands), `cli_cluster.rs` (new),
  `lib.rs`, `main.rs`.
- `docs/cluster.md`, `docs/security/threat-model.md`,
  `docs/security/hardening-guide.md`.

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-08-23 | 0.1 | Story drafted from the revised Epic 9 PRD. CSR dropped for a bare public key; token reshaped to avoid an argon2id amplification path; revocation moved to a real CRL + acceptor swap. Status Draft. | Romain G. |
| 2026-09-06 | 0.2 | Phase 1 review: fifteen decisions recorded (token mint surface, two-segment token with embedded pin, redemption behind a trait, SPKI-pinning joiner verifier, in-memory roster, session kill switch, CRL rebuild, follower identity row, two-path leave). Status InProgress. | Romain G. |
| 2026-09-06 | 0.3 | Implementation: token mint/parse/verify, pinned joiner, bare-key issuance + CRL, roster + session registry with kill switches, redemption/lifecycle hooks in the binary, registry endpoints + status + leave, `cluster join/leave/status/token`, follower runtime with renewal, docs. All ACs implemented; integration tests for IV1-IV3. Status Review. | Romain G. |
| 2026-09-06 | 0.4 | QA iteration 1: store lock released around signing (Critical), renewal eligibility/cooldown/per-session cap, idempotent revocation with the kill before the error, serialized refresh, jittered renewals with immediate reconnect, RSA allowlist hardened, leave probe requires a certificate alert, password sources for the CLI, runtime layer split, shared startup helper, AC #11 sliding window. | Romain G. |
