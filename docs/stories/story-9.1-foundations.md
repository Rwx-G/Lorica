# Story 9.1: Foundations

**Epic:** 9 (v1.7.0)
**Status:** Draft
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

- [ ] AC #1: generic `new()`, swap `UnixStream::into_split` for
      `tokio::io::split`, add bounds; keep `from_raw_fd` concrete.
- [ ] AC #2: define `Frame` trait, parameterise the reader/writer tasks
      and the demux over it; keep `Envelope` as the worker-plane impl.
- [ ] AC #3: move the four constants into a per-endpoint config struct
      with the current values as defaults.
- [ ] AC #4: replace the `continue` at the oversize branch with a typed
      error path; bound the in-flight map and define the over-limit
      behaviour.
- [ ] AC #5: canonical encoder + sorted-view serialisation for every
      `HashMap` field; unit tests across differing `RandomState` seeds.
- [ ] AC #6: migration for the persisted counter; wire it distinctly
      from `reload_generation`.
- [ ] AC #7: extend the hot-upgrade FD set; add the double-session
      interlock and a test for the overlap window.
- [ ] AC #8: table-driven rotation + coverage test.
- [ ] AC #9: `present -> Result`, update the driver call site so a
      failure aborts before `set_ready()`.
- [ ] AC #10: move `acme_challenges` DDL into `MIGRATIONS`.
- [ ] AC #11: expose `schema_version()`.
- [ ] AC #12: `deny_unknown_fields` on replica decode types.
- [ ] AC #13: Pebble compose service, CA trust injection, mock DNS
      provider, wiring into the `cluster` profile.

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

(empty)

### Completion Notes

(empty)

## File List

Anticipated:

- `lorica-command/src/rpc.rs` (transport + frame generalisation, limits,
  oversize error path, bounded in-flight map)
- `lorica-command/src/lib.rs` (Frame trait export)
- `lorica-config/src/canonical.rs` (new)
- `lorica-config/src/store/mod.rs` (rotation table, schema_version
  exposure, cluster generation migration)
- `lorica-config/src/migrations/` (new migration)
- `lorica/src/hot_upgrade.rs` (cluster FD handoff + interlock)
- `lorica-acme/src/driver.rs` (fallible present)
- `lorica-api/src/acme/store.rs` (DDL moved to MIGRATIONS)
- `tests-e2e-docker/docker-compose.yml`, `Dockerfile`, Pebble fixture

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-08-23 | 0.1 | Story drafted from the revised Epic 9 PRD, after a five-pass verification of the first draft's reuse assumptions. Status Draft. | Romain G. |
