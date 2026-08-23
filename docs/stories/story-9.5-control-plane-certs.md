# Story 9.5: Control-Plane Certificate Issuance

**Epic:** 9 (v1.7.0)
**Status:** Draft
**Author:** Romain G.

**Depends on:** Stories 9.1 (fallible `present`, Pebble fixture), 9.2,
9.3, 9.4 (`node_selector`).

## Story

As an operator,
I want ACME issuance and renewal to happen once for the fleet,
so that three edges serving the same hostname do not produce three
different certificates and do not burn the Let's Encrypt rate limit.

## Acceptance Criteria

1. Need-to-know key distribution, on by default: a follower receives
   private keys only for hostnames bound to routes it is selected for,
   reusing the `node_selector` predicate from Story 9.4. Pushing every
   key to every node is an explicit opt-in.
2. The key handling is stated, not implied: distribution means
   decrypting on the control plane, shipping the key material over the
   mutual-TLS channel, and re-encrypting under the follower's own key.
   The control plane therefore holds every distributed private key in
   usable form, and `docs/cluster.md` says so.
3. Only the renewal task and the certificate-expiry notifier are
   disabled on followers, via the single shared call site.
4. OCSP refresh keeps running on every node.
5. DNS-01 is unchanged: the control plane holds the provider secrets and
   completes the challenge itself.
6. HTTP-01 is fleet-aware and fails safe: the control plane distributes
   the token and key authorization to the followers plausibly serving
   that hostname, using the fallible `present` from Story 9.1, so a
   partial distribution aborts the challenge instead of racing
   `set_ready()`. Challenge entries carry their own TTL.
7. Issued chain and key are pushed over the mutual-TLS channel and
   installed through the existing arc-swap hot-swap. **Certificate
   distribution uses a path independent of the configuration commit.**
8. A follower offline during a renewal receives its certificates as part
   of reconnect convergence, before it is asked to serve that hostname.
9. The filesystem certificate export zone and its per-pattern ACL keep
   working on every node, driven by node-local settings per Story 9.4
   AC #1.
10. Prometheus: `lorica_cluster_cert_push_total{node_id, outcome}` and a
    per-hostname gauge of the fleet-wide minimum remaining validity.

## Tasks / Subtasks

- [ ] AC #1: selector-scoped key distribution, opt-in override.
- [ ] AC #2: decrypt/ship/re-encrypt path + threat-model paragraph.
- [ ] AC #3: follower guard in `startup::run_api_server`.
- [ ] AC #4: confirm OCSP stays spawned on followers; add a regression
      test so a future change does not silently disable it.
- [ ] AC #5: no change; add a cluster-mode test.
- [ ] AC #6: fleet token distribution, plausibility scoping, TTL on
      challenge entries, abort-on-partial.
- [ ] AC #7: independent distribution path + arc-swap install.
- [ ] AC #8: certificates in the reconnect convergence set.
- [ ] AC #9: verify export zone is untouched by replication.
- [ ] AC #10: metrics.

## Dev Notes

**AC #1 is the single highest-leverage change in the epic, and it costs
one predicate.** At-rest encryption protects a stolen database file or a
backup; it does not protect against root or the service user on the
node, because the master key is 32 raw bytes in a `0600` file beside the
database (`lorica-config/src/crypto.rs:34-70`). Without need-to-know,
one compromised DMZ edge yields the private key of every hostname in the
fleet, including hostnames that edge never serves. Story 9.4 AC #13
already provides the selector.

**AC #3: there is exactly one clean seam, and it exists for a reason.**
`startup::run_api_server` (`lorica/src/startup/mod.rs:162-190`) is the
single shared call site for `spawn_renewal_task` (`:178`) and
`spawn_cert_expiry_check_task` (`:184`), used by both modes
(`single.rs:395`, `supervisor.rs:985`). Its doc comment (`:150-153`)
says the dedup exists precisely because the modes drifted and caused the
v1.5.2 cert-hotswap bug. One `if !is_follower` guard here covers both
modes.

**AC #4 corrects a design error in the first draft.** It disabled OCSP
refresh on followers. OCSP stapling is a *serving* concern, not an
issuance concern: the loop reads route-referenced certs and attaches
staples to the resolver the node actually serves from
(`startup/mod.rs:332-343`, `worker.rs:640-643`). Disabling it on
followers would strip stapling from exactly the nodes terminating client
TLS, with no push path to replace it.

There is also a plumbing trap if anyone later tries to gate it:
`spawn_ocsp_refresh_loop` has two call sites in **different processes**,
`single.rs:407` and `worker.rs:643` (inside each forked worker, "each
worker owns its own resolver"), and `supervisor.rs` never calls it. So a
follower flag would have to reach the worker process via argv
reconstruction (see `upstream_crl_file` at `cli.rs:242-244` for the
existing pattern) or via the DB, not just live in the supervisor. This is
the same supervisor/worker asymmetry class that produced the v1.5.2 bug.

**There is no component called an "ACME scheduler".** The three real
tasks are the renewal task, the certificate-expiry notifier and the OCSP
loop. The first draft named a non-existent scheduler and omitted the
expiry notifier, which left running on followers would fire one
duplicate fleet-wide alert per node.

**AC #6: the premise everyone assumes is stale, and the real blocker is
elsewhere.** `AcmeChallengeStore` is **not** in-memory per process: it is
SQLite-backed (`lorica-api/src/acme/store.rs:22-59`, table
`acme_challenges (token TEXT PRIMARY KEY, key_auth TEXT)` at `:87-91`)
with an in-memory `RwLock<HashMap>` as a supervisor-local read cache
only, and `get()` falls back to SQLite on a miss (`:143-159`, documented
at `:43-47`). Workers serve the endpoint from the data plane
(`lorica/src/proxy_wiring.rs:748-768`). So **one write per node covers
every worker of that node** and worker mode is already solved.

The actual blocker is the trait: `Http01ChallengeSolver::present`
returns `()` (`lorica-acme/src/driver.rs:53-57`) and `driver.rs:144-151`
calls `set_ready()` on the very next line inside the per-authz loop. A
fleet distribution that partially fails has no channel to report it, so
the CA is told to validate while some nodes have no token, surfacing as
an opaque `AcmeError::NotReady` with no indication of which node broke.
Story 9.1 AC #9 makes it fallible. Cleanup is already correct on both
paths and runs regardless of outcome (`driver.rs:165-170`), so AC #6's
removal requirement maps onto it cleanly; the TTL is belt-and-braces for
a node that goes offline mid-validation.

Note also that `acme_challenges` is created ad hoc from a second
rusqlite connection rather than through `MIGRATIONS`; Story 9.1 AC #10
folds it in **before** this story adds a network writer to it.

**AC #7 exists because of the Story 9.4 veto problem.** If certificate
distribution rides the configuration commit path, one slow or drifted
follower can block renewals for the whole fleet until expiry.

**Verification depends on Story 9.1 AC #13.** There is no Pebble fixture
and no end-to-end ACME coverage in the repo at all: the 11 existing
profile scripts do not touch ACME, and unit tests only stub DNS provider
APIs with wiremock (`lorica-acme/src/tests.rs`). Without the fixture,
this story ships on unit tests only, which for the most protocol-
sensitive story in the epic is not acceptable.

## Dev Agent Record

### Debug Log

(empty)

### Completion Notes

(empty)

## File List

Anticipated:

- `lorica-cluster/src/certs.rs` (distribution, selector scoping)
- `lorica-acme/src/driver.rs` (call-site update for fallible `present`)
- `lorica-api/src/acme/store.rs` (network writer path)
- `lorica/src/startup/mod.rs` (follower guard on renewal + expiry
  notifier)
- `docs/cluster.md`

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-08-23 | 0.1 | Story drafted from the revised Epic 9 PRD. Need-to-know key distribution added; OCSP kept running on followers (first draft disabled it, which was wrong); certificate path decoupled from the config commit. Status Draft. | Romain G. |
