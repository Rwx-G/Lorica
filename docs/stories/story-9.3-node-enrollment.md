# Story 9.3: Node Enrollment, Registry and Revocation

**Epic:** 9 (v1.7.0)
**Status:** Draft
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

- [ ] AC #1: token mint/format, indexed `public_id`, HMAC verification,
      semaphore, constant-time compare, uniform error and timing.
- [ ] AC #2: leaf-SPKI pinning, SAN check, EKU separation.
- [ ] AC #3: bare-public-key flow, server-assigned params, key-type
      allowlist.
- [ ] AC #4: atomic burn ahead of signing.
- [ ] AC #5: `Pending` lifecycle, activation endpoint, name/CIDR binding.
- [ ] AC #6: `--token-file` / `--token-stdin` / env; warn or remove the
      literal form.
- [ ] AC #7: CRL minting, `ServerConfig` rebuild, acceptor arc-swap,
      synchronous session teardown.
- [ ] AC #8: identity derived from certificate fingerprint; payload
      `node_id` ignored; mismatch drops and audits.
- [ ] AC #9: migration for `cluster_nodes`.
- [ ] AC #10: four endpoints + OpenAPI entries.
- [ ] AC #11: listener-level limiter.
- [ ] AC #12: 90-day certs + auto-renew.
- [ ] AC #13: authorised `leave` with full wipe and dual audit.
- [ ] AC #14: `cluster status`.

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

(empty)

### Completion Notes

(empty)

## File List

Anticipated:

- `lorica-cluster/src/enroll.rs`, `ca.rs`, `registry.rs`, `revocation.rs`
- `lorica-config/src/migrations/` (`cluster_nodes`, join tokens)
- `lorica-api/src/cluster.rs` (endpoints), `lorica-api/openapi.yaml`
- `lorica/src/cli.rs` (`cluster join` / `leave` / `status`)

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-08-23 | 0.1 | Story drafted from the revised Epic 9 PRD. CSR dropped for a bare public key; token reshaped to avoid an argon2id amplification path; revocation moved to a real CRL + acceptor swap. Status Draft. | Romain G. |
