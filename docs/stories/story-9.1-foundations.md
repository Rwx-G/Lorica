# Story 9.1: Foundations

**Epic:** 9 (v1.7.0)
**Status:** Review
**Author:** Romain G.

## Story

As a maintainer,
I want the reusable primitives this epic depends on to actually be
reusable before any cluster code is written,
so that the cluster stories build on verified seams instead of on
assumptions that fail at integration time.

Every item here was verified as missing or unsuitable during the
pre-implementation review of the Epic 9 PRD. None is cluster-specific;
all are prerequisites. Nothing in Stories 9.2 through 9.7 can start
before this lands.

## Acceptance Criteria

1. `RpcEndpoint` generalised over transport: accepts any
   `AsyncRead + AsyncWrite + Unpin + Send + 'static` via
   `tokio::io::split`. `from_raw_fd` stays a `UnixStream`-only
   constructor. Existing call sites infer unchanged; UDS tests stay
   green unmodified.
2. `RpcEndpoint` generalised over frame type: a `Frame` trait exposing
   `sequence()` so the cluster message set lives in a separate proto
   package and versions independently of the worker command set.
3. `MAX_MESSAGE_SIZE`, `OUTBOUND_QUEUE_CAP`, `SLOW_ENQUEUE_WARN` and
   `DEFAULT_REQUEST_TIMEOUT` become per-endpoint parameters instead of
   crate constants.
4. Oversize outbound frames return a typed size error instead of being
   silently dropped; the in-flight map gains a bound.
5. A canonical configuration encoder producing byte-stable output for a
   given logical configuration: every map serialised through a sorted
   view, a total order on every collection with a non-unique sort key,
   secrets included, node-local fields excluded. Not the TOML export
   path.
6. A `cluster_config_generation` counter persisted in the config DB,
   distinct from the supervisor's in-memory `reload_generation`.
7. Hot upgrade hands off the cluster listener FD, with an interlock so
   that during the old/new supervisor overlap a follower never holds two
   live sessions for one `node_id`.
8. `rotate_encryption_key` converted from a hardcoded two-table loop to
   a table-driven enumeration of every encrypted column, with a test
   that fails when a new encrypted column is added without updating the
   rotation table.
9. `Http01ChallengeSolver::present` becomes fallible (breaking change to
   a public trait in `lorica-acme`).
10. `acme_challenges` folded into the `MIGRATIONS` table-driven system.
11. `ConfigStore::schema_version()` exposed beyond tests so the cluster
    handshake can compare it.
12. Types used to decode a replicated configuration blob carry
    `#[serde(deny_unknown_fields)]`.
13. A Pebble ACME fixture in `tests-e2e-docker/` with CA-root trust
    injection into the Lorica image, plus a mock DNS provider for
    DNS-01.

## Tasks / Subtasks

- [x] AC #1: generic `new()`, swap `UnixStream::into_split` for
      `tokio::io::split`, add bounds; keep `from_raw_fd` concrete.
- [x] AC #2: define `Frame` trait, parameterise the reader/writer tasks
      and the demux over it; keep `Envelope` as the worker-plane impl.
- [x] AC #3: move the four constants into a per-endpoint config struct
      with the current values as defaults.
- [x] AC #4: replace the `continue` at the oversize branch with a typed
      error path; bound the in-flight map and define the over-limit
      behaviour.
- [x] AC #5: canonical encoder + sorted-view serialisation for every
      `HashMap` field; unit tests across differing `RandomState` seeds.
- [x] AC #6: migration for the persisted counter; wire it distinctly
      from `reload_generation`.
- [x] AC #7: extend the hot-upgrade FD set; add the double-session
      interlock and a test for the overlap window. (Seam-only in 9.1;
      see Completion Notes.)
- [x] AC #8: table-driven rotation + coverage test.
- [x] AC #9: `present -> Result`, update the driver call site so a
      failure aborts before `set_ready()`.
- [x] AC #10: move `acme_challenges` DDL into `MIGRATIONS`.
- [x] AC #11: expose `schema_version()`. (Already `pub`; see
      Completion Notes.)
- [x] AC #12: `deny_unknown_fields` on replica decode types.
- [x] AC #13: Pebble compose service, CA trust injection, mock DNS
      provider, wiring into the `cluster` profile. (Shipped as its
      own `acme` profile, run.sh Phase 9; 15/15 asserts green.)

## Dev Notes

Evidence gathered during the PRD verification pass. Read this before
touching `lorica-command`.

**AC #1 is smaller than it looks, AC #2 is bigger.** `RpcEndpoint`'s
struct carries no transport type at all (`lorica-command/src/rpc.rs:99-121`);
`Inner` holds only `next_seq`, `inflight`, `tx_out`, `_tasks`. The only
concrete bindings are `rpc.rs:233` (`new(stream: UnixStream)` using
`into_split`) and the task signatures at `rpc.rs:380` / `rpc.rs:407`. So
no type parameter on the public type is needed. The real work is AC #2:
the endpoint hard-codes `Envelope`, `envelope::Kind`, `Command`,
`Response` and `cmd.sequence` / `resp.sequence` (imports `rpc.rs:53`,
dispatch `rpc.rs:439-471`).

**Framing is already transport-agnostic**: `[8-byte LE length][prost
Envelope]` over a byte stream (`rpc.rs:380-405`, `:407-434`). No
SEQPACKET, no datagram boundaries, and no SCM_RIGHTS inside
`RpcEndpoint` (fd passing happens only at channel establishment,
`startup/worker.rs:652`, `supervisor.rs:1761`). Demux is sequence-keyed
(`rpc.rs:90`, `:441-457`), so reordering is a non-issue.

**Why AC #3 matters**: every one of those constants is tuned for a
same-host UDS. `MAX_MESSAGE_SIZE = 1 MiB` (`rpc.rs:57`),
`OUTBOUND_QUEUE_CAP = 256` (`:67`), `SLOW_ENQUEUE_WARN = 10 ms` (`:74`),
`DEFAULT_REQUEST_TIMEOUT = 5 s` (`:77`). Left as-is over a WAN, the 10 ms
warn threshold alone turns into a log flood.

**Why AC #4 matters**: `rpc.rs:384-390` logs and `continue`s on an
oversize outbound frame, so the caller sees `ChannelError::Timeout`
after its full timeout with no indication of the cause. On the cluster
Prepare path that is indistinguishable from a dead follower. Inbound
oversize kills the connection instead (`:422-428`). The in-flight map is
a `std::sync::Mutex<HashMap>` whose own comment (`rpc.rs:79-89`) says it
is sized for reload-frequency volume and is "the first structure to
revisit".

**AC #5 is the one that silently breaks drift detection.** These fields
are `HashMap`s: `Route.response_headers` (`models/route.rs:35`),
`HeaderRule.proxy_headers` / `response_headers` (`:565`, `:568`),
`SecurityHeaderPreset.headers` (`models/settings.rs:19`). Serde emits
them in iteration order, which is `RandomState`-seeded **per process**,
so the same logical config hashes differently on two nodes and on the
same node after a restart. Do not try to reuse the TOML export: it
blanks `key_pem` (`export.rs:100`), password hashes (`:52-56`), webhook
/ Slack / SMTP secrets (`:59-94`) and `bot_hmac_secret_hex` (`:113-116`),
and the import rejects those placeholders (`import.rs:244-301`). Row
ordering also has ties: `certificates ORDER BY domain`
(`store/certs.rs:66`) and `notification_configs ORDER BY channel`
(`store/notifications.rs:58`) are not unique keys. Timestamps are safe
(bound from the model, not `datetime('now')`).

**AC #6 prevents a fleet-wide false-drift storm.** The supervisor's
reload generation is an in-memory `AtomicU64` reset to 0 on every start
(`startup/supervisor.rs:473-474`), and `GenerationGate` refuses any
non-increasing value (`lorica-command/src/generation.rs:46-48`). After a
control-plane restart the counter would be 0 while followers hold
`applied_config_generation = 17`: every node reports drift and every
follower gate rejects the first post-restart Prepare.

**AC #7**: `hot_upgrade.rs:199-216` transfers proxy listeners and the
management listener only. The new supervisor starts accepting while the
old drains (`hot_upgrade.rs:32-50`), so without an interlock a follower
briefly has two supervisors applying config and both eligible to renew
its node certificate.

**AC #8 is a silent-bricking guard.** `store/mod.rs:645-700` enumerates
`certificates.key_pem` and `notification_configs.config` by hand. A
cluster CA key in a third table is skipped, rotation prints success, the
operator swaps the key file, and the CA is undecryptable. Discovered at
the next enrollment. Rotation also runs on `unchecked_transaction`
against a DB the daemon may have open, and the key-file swap is manual;
do not widen that behaviour here, just fix the coverage.

**AC #9**: `Http01ChallengeSolver::present` returns `()`
(`lorica-acme/src/driver.rs:53-57`) and `driver.rs:144-151` calls
`set_ready()` on the next line inside the per-authz loop. Cleanup is
already correct on both paths (`driver.rs:165-170`).

**AC #13 does not exist today.** Grep confirms: the only "pebble"
occurrences in the tree are the Epic 9 PRD itself and
`docs/audits/v1.5.2-audit.md:308`, an unimplemented recommendation
(audit item M-22). There is **zero** end-to-end ACME coverage; the 11
existing profile scripts do not touch it, and `lorica-acme/src/tests.rs`
only stubs DNS provider APIs with wiremock. Budget this as real work,
including CA-root trust injection into every node image.

Migration numbering hazard worth knowing: `MIGRATION_V18` has no file
and version 18 is an inline entry (`store/mod.rs:280-286`), while
`019_sessions.sql` is registered as version **21** (`store/mod.rs:83`,
`:133`). Current head is 46.

`lorica-command` cannot take `#![deny(unsafe_code)]`; it needs unsafe for
`from_raw_fd` (`lorica-command/src/lib.rs:21-22`).

## Dev Agent Record

### Debug Log

- 2026-09-01: `lorica-command` tests green after the transport+frame
  generalisation on the first full run; the bare-`RpcEndpoint` call
  sites in `lorica` inferred unchanged thanks to the default type
  parameter (`RpcEndpoint<F: Frame = Envelope>`) plus keeping
  `new`/`from_raw_fd`/`request_rpc` on the `Envelope` impl.
- 2026-09-01: the AC #8 source-scan gate initially keyed on literal
  `INTO <table>` / `UPDATE <table>` strings and broke itself: the
  table-driven rotation builds its SQL with `format!`. Relaxed to
  "module must mention a registry table name".
- 2026-09-01: standalone `cargo clippy -p lorica-command` failed on
  `tokio::select!` while `cargo test` passed: the `macros` feature
  was dev-deps-only and test builds unify features. Added `macros`
  to the lib dependency.
- 2026-09-01: first acme e2e run failed at provisioning: Lorica hit
  the aliased Pebble at `/directory` (Let's Encrypt convention) but
  Pebble serves `/dir`. Resolved with the `LORICA_ACME_DIRECTORY_URL`
  override (also useful for private CAs); the TLS trust chain via
  `SSL_CERT_FILE` was proven working by that very failure (Pebble's
  404 body was received over a verified handshake).
- 2026-09-01: smoke script assumed `GET /api/v1/certificates`
  returns `{data: [...]}`; the API wraps as
  `{data: {certificates: [...]}}`. Fixed the jq paths. Final run:
  15/15 asserts, both HTTP-01 and manual DNS-01 certificates issued
  by Pebble.

### Completion Notes

- **QA iteration 1 (2026-09-02)**: five-auditor sweep (quality,
  security, performance, architecture + AC traceability) returned
  1 Critical, 5 High (after my aggregation), and a set of cheap
  Mediums; all fixed in one pass:
  - Critical: the canonical blob embedded secret MATERIAL while
    doubling as the future replication payload. Secrets now encode
    as `sha256:<hex>` digests (drift-visible, nothing to steal);
    actual key/credential transfer stays on Story 9.5's node-scoped
    path. Free today (zero production callers), a wire break after
    9.4.
  - Rotation: row read failures now abort the transaction instead of
    silently under-rotating; every re-encrypted value is
    decrypt-verified under the new key before the UPDATE; the UPDATE
    is prepared once per column; the drift-gate test now extracts
    the actual INSERT/UPDATE target tables (recursive scan, mod.rs
    exempt, reviewed non-encrypted targets listed) instead of a
    substring match.
  - Cluster counters: increment via single-statement
    `UPDATE .. RETURNING` (two concurrent mutators could both read
    the other's post-increment value and stamp two configs with one
    generation).
  - Takeover epoch: the old supervisor re-takes the epoch on the
    Rollback branch, otherwise a FAILED upgrade would fence the
    surviving supervisor's sessions under 9.2's fencing rule.
  - FD handoff: cluster slot widened to role-qualified entries
    (`cluster:op:<bind>` / `cluster:enroll:<bind>`) because 9.2
    mandates two listeners and the table is a cross-version wire
    contract; duplicate/malformed/unknown-role keys now fail the
    pull (rollback) instead of silently dropping a descriptor.
  - RpcEndpoint: `try_send` fast path (no timer armed unless
    backpressured - request() sits on the per-HTTP-request
    breaker/verdict path); `is_closed()`; `inbound_queue_cap` and
    `frame_read_timeout` in RpcLimits (body-read bounded, idle wait
    not - the worker plane has no heartbeat); incremental body
    buffer (64 KiB initial cap) so a length prefix alone cannot
    commit max_message_size; single-buffer frame writes; module doc
    states the one-endpoint-one-FIFO contract for 9.2.
  - Canonical decode: version peeked tolerantly BEFORE the strict
    pass (a v2 blob now fails as "version not supported", not on its
    first unknown field); decode errors carry position only, never
    field values.
  - GlobalSettings replication drift gate: exhaustive destructuring
    test (no `..`) forces every future field through an explicit
    replicate-or-node-local decision at compile time.
  - present() carries the authorization's hostname (9.5's fleet
    solver input; folded into this cycle's one breaking trait
    change); tokens are recorded before presenting so a partial
    publish is retracted; NoopHttp01Solver now fails closed;
    challenge-store cache entry removed when persist fails; DELETE
    failures logged (token only).
  - LORICA_ACME_DIRECTORY_URL: https-only (non-https override is
    ignored with an error log), and use of the override is WARN'd at
    issuance.
  - e2e: wait_for_backend/wait_for_api helpers wired into the acme
    smoke (wait_for_api itself fixed: it curl -f'd an
    auth-required endpoint, so it could never succeed - why it had
    zero callers); stale fixture comment refreshed.
- **QA findings deliberately NOT fixed this story** (logged for
  backlog / handoffs): RpcObserver event hook (9.2 designs the
  vocabulary with its consumer; is_closed() landed now),
  DashMap/sharded inflight map (self-flagged threshold not reached),
  encoded_len double computation (measure first),
  canonical_bytes double serialize/sort (cold until 9.4 wires drift
  checks), rpc.rs file split (9.2), acme_challenges TTL + prune
  (9.5 adds expires_at), CLI programmatic key-file swap on rotation,
  transfer_fd bind-then-chmod TOCTOU + SO_PEERCRED (forked crate),
  challenge-path INFO token logging downgrade, driver account/order
  bootstrap dedup, TableName newtype for rotation SQL.

- **AC #5 (canonical encoder) - the Dev Notes' determinism premise
  was WRONG**: serde serializes a `HashMap` field in the map's own
  iteration order; the BTreeMap-backed `serde_json::Map` only kicks
  in when encoding via `serde_json::Value`. A direct
  `serde_json::to_vec(&struct)` is therefore NOT deterministic
  across processes (per-instance SipHash seeds). Caught by the
  cross-insertion-order test. Fix: `canonical_bytes()` encodes
  through `Value` plus a recursive key-sort rewrite, deterministic
  even if `preserve_order` gets enabled somewhere later. Top-level
  entity Vecs are sorted by their canonical JSON string (total
  order, immune to SQL tie-ordering); inner rule arrays keep their
  semantic first-match-wins order. Hash = `ring` SHA-256 (existing
  dep), `CANONICAL_FORMAT_VERSION = 1`.
- **AC #12**: `deny_unknown_fields` on 23 model structs.
  `GlobalSettings` deliberately NOT strict (tolerant KV projection
  used by the settings table); the strict fleet-policy replica is
  `CanonicalGlobalSettings` (34 fields, node-local fields excluded
  by construction: cert_export_*, management, geoip paths, secrets
  for local sinks, all syslog_*/otlp_* - Story 9.4 revisits the
  sink split). `CustomVerification` (internally-tagged enum) cannot
  take the attribute per serde limitation; documented in code.
- **AC #7 scope decision**: the cluster listener only exists from
  Story 9.2 (`--cluster-listen`), so 9.1 lands the SEAM: the FD
  transfer gains an optional `cluster:<bind>` slot (serve, pull,
  partition all handle it; `HandoffArgs.cluster_fd` is `None` until
  9.2 wires it), and the double-session interlock primitive is a
  persisted `takeover_epoch` in `cluster_state` that a `--hot-upgrade`
  NEW supervisor bumps before serving anything. Story 9.2's session
  registry tags sessions with their accept epoch and fences older
  epochs.
- **AC #8 found its motivating bug live**: the pre-9.1 hardcoded
  rotation loop skipped `dns_providers.config`, so a key rotation
  left every DNS provider credential undecryptable while reporting
  success. The table-driven `ENCRYPTED_COLUMNS` registry now covers
  certificates, notification_configs, dns_providers and the two
  Story 9.8 sink secrets; the drift gate is a runtime source scan of
  `src/store/` asserting every encrypting module mentions a
  registered table.
- **AC #9** also closes a pre-existing leak: an in-loop `?` on a
  challenge/authz error used to return without retracting
  already-presented tokens; the restructured setup loop cleans up on
  every failure path before returning. `AcmeChallengeStore::set` is
  now fallible (SQLite persist failure = the workers would 404 the
  CA's validation request); memory-only degraded mode still succeeds
  (single-process serves from memory).
- **AC #10**: schema ownership moved to migration v47; the ad-hoc
  DDL in `AcmeChallengeStore` is deleted (production order is safe:
  every process opens `ConfigStore` - which migrates - before the
  challenge store attaches; the store's own tests now mirror that).
- **AC #11 was already satisfied**: `ConfigStore::schema_version()`
  has been `pub` since the migration-table rework; the story's
  "referenced only from tests" observation predates it. No change
  needed beyond this note.
- **AC #6**: `cluster_state` table (migration v48) with
  `config_generation` and `takeover_epoch` rows;
  `increment_cluster_config_generation()` /
  `increment_cluster_takeover_epoch()` are atomic single-statement
  UPDATEs; persistence proven across a reopen in tests.
- **AC #3/#4**: `RpcLimits` per endpoint (defaults = the historical
  constants); oversize outbound frames fail with the existing typed
  `ChannelError::MessageTooLarge` at enqueue (size measured via
  `encoded_len()` before any state is installed); new
  `ChannelError::InflightFull` bounds the in-flight map (default
  1024).

## File List

- `lorica-command/src/rpc.rs` (Frame trait, RpcLimits, generic
  transport via `tokio::io::split`, typed oversize error, bounded
  in-flight map, tests)
- `lorica-command/src/lib.rs` (Frame/FrameKind/IncomingRequest(s)/
  RpcLimits exports, `ChannelError::InflightFull`)
- `lorica-command/Cargo.toml` (tokio `macros` feature: lib code now
  uses `select!`/`pin!`; previously dev-only)
- `lorica-config/src/canonical.rs` (new: canonical encoder, hash,
  strict decode, tests)
- `lorica-config/src/lib.rs` (canonical module + re-exports)
- `lorica-config/src/models/*.rs` (`deny_unknown_fields` on 23
  structs: route, backend, certificate, notification,
  cert_export_acl, ai_crawler, probes, sla, settings)
- `lorica-config/src/store/mod.rs` (migrations 47+48,
  ENCRYPTED_COLUMNS registry, table-driven rotation, cluster
  generation/takeover-epoch accessors)
- `lorica-config/src/tests.rs` (schema head 48, migration ownership,
  cluster counters, rotation coverage incl. registry drift gate)
- `lorica-acme/src/error.rs` (`AcmeError::Solver`)
- `lorica-acme/src/config.rs` (`LORICA_ACME_DIRECTORY_URL` override,
  `directory_url()` returns `String`)
- `lorica-acme/src/driver.rs` (fallible `present`, setup loop aborts
  before `set_ready()` and retracts presented tokens on failure)
- `lorica-api/src/acme/store.rs` (ad-hoc DDL removed, fallible
  `set`)
- `lorica-api/src/acme/http01.rs` + `tests.rs` (call-site updates)
- `lorica/src/startup/hot_upgrade.rs` (cluster FD slot, pure
  `partition_inherited_fds` + test)
- `lorica/src/startup/supervisor.rs` (cluster_fd handoff arg,
  takeover-epoch bump under `--hot-upgrade`)
- `tests-e2e-docker/` (acme profile: Pebble + challtestsrv services,
  CA init, `run-acme-smoke.sh`, run.sh Phase 9, Dockerfile entries)

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-08-23 | 0.1 | Story drafted from the revised Epic 9 PRD, after a five-pass verification of the first draft's reuse assumptions. Status Draft. | Romain G. |
| 2026-09-01 | 0.2 | Slices A-E implemented: RpcEndpoint generalisation (Frame + RpcLimits + typed oversize/inflight errors), canonical encoder + deny_unknown_fields, migrations 47/48 + table-driven key rotation (fixes pre-existing dns_providers rotation gap), fallible present with pre-set_ready abort, cluster FD seam + takeover-epoch interlock. Status InProgress. | Romain G. |
| 2026-09-01 | 0.3 | Pebble ACME e2e profile authored (tests-e2e-docker acme profile, Phase 9). | Romain G. |
| 2026-09-01 | 0.4 | acme e2e proven 15/15 (HTTP-01 + manual DNS-01 issued by Pebble) after LORICA_ACME_DIRECTORY_URL override and smoke jq fixes. All ACs implemented; full test/clippy/audit chain green. Status Review. | Romain G. |
