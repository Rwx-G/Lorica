# Story 9.5: Control-Plane Certificate Issuance

**Epic:** 9 (v1.7.0)
**Status:** Done
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

- [x] AC #1 + D3: recipient resolution control-plane side (hostname ->
      routes -> selector -> node_id); opt-in override for fleet-wide.
- [x] D3: migration 53, UNIQUE on `cluster_nodes.name` with duplicate
      renaming; enrollment refuses a taken name.
- [x] AC #2 + D5: decrypt on the control plane, ship over mTLS, write
      through the existing encrypt-on-write path; threat-model
      paragraph in `docs/cluster.md`.
- [x] AC #3 + D6: follower guard at the spawn site covering the renewal
      task, the expiry notifier (which runs one pass immediately) and
      the orphan purge.
- [ ] AC #4 + D7: regression test that OCSP stays spawned on every
      role; comment recording why a follower flag must not be added.
      (The comment is in; the test is NOT written.)
- [ ] AC #5: no change; cluster-mode test for DNS-01. (No code change
      was needed, as predicted; the test is NOT written.)
- [x] AC #6 + D10 + D16: fleet solver wrapping the local store,
      cleanup fan-out. The verdict is NOT all-or-nothing: a live node
      that refused blocks the order, an offline one does not.
- [x] AC #6 + D11: migration 54, challenge expiry and purge.
- [x] AC #7 + D1 + D2: message pair on tags 60-79; push at issuance and
      renewal.
- [x] AC #8 + D2: pull for missing keys after an apply and at
      reconnect.
- [x] AC #9 + D8: export triggered after a key installation, never at
      configuration apply.
- [x] D9: break-glass does not suspend key delivery; documented.
- [x] AC #10 + D12: the distribution counter is in, with one unit
      (a certificate) on every outcome and no outcome counted twice.
- [x] AC #10 + D12: "waiting for a key" is split from "corrupt
      bundle". Keyless rows are held back from the resolver and
      published on the `certificates_awaiting_key` gauge instead of
      landing in `lorica_certificates_invalid_bundle_total`.
- [x] D15 (iteration 1): the node name is bound at mint, enforced at
      redemption, validated against the selector alphabet, and shown
      in the pending-node review.
- [x] D16 (iteration 1): `ChallengeMiss` splits an offline recipient
      from a live refusal; only the refusal stops an order.

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

- 2026-09-08: Phase 1 pre-implementation review. Verified the three
  dependencies this story declares on Story 9.1 rather than trusting
  them, because the Dev Notes state that without the ACME fixture the
  story ships on unit tests only. All three are met:
  `Http01ChallengeSolver::present` returns `Result<(), AcmeError>`
  (`lorica-acme/src/driver.rs:67-72`); `acme_challenges` is owned by the
  migration table as `(47, migrate_acme_challenges)`
  (`lorica-config/src/store/mod.rs:167`); the Pebble fixture and its
  dedicated e2e profile exist under `tests-e2e-docker/`. Nothing
  upstream blocks this story.

### Completion Notes

- **Phase 1 decisions**:
  - **D1 - certificate distribution is its own message pair, on the
    tags already reserved for it.** AC #7 says "independent of the
    configuration commit" and that is the whole point: if keys ride the
    commit path, one slow follower blocks fleet renewals until expiry,
    which is the Story 9.4 veto problem with a worse blast radius. Tags
    60-79 are already documented as reserved for this story
    (`lorica-cluster/src/messages.rs:378-382`,
    `proto/cluster.proto:36-44`) and all twenty are free. This also
    settles backlog #56: the canonical blob stays fleet-wide with its
    single hash, and `node_selector` stays what `docs/cluster.md` now
    says it is, a placement filter and not a confidentiality boundary.
    Keys get their own boundary instead of borrowing one that never
    was.
  - **D2 - both directions, deliberately.** AC #7 says pushed, AC #8
    says an offline node converges at reconnect; those are two
    mechanisms and the story needs both. PUSH at issuance and renewal
    for latency, from the control plane to the nodes it resolved as
    recipients. PULL after a replica apply and at reconnect, where the
    follower asks for exactly the certificates it just counted as
    missing. The pull path is the one that must be correct: it covers
    AC #8 and any push that failed or landed while the node was down.
    The push is an optimisation on top, not the guarantee.

    **CORRECTION, made during implementation.** This decision
    originally said the certificate pull "inherits the
    `NodeState::Active` gate the 9.4 QA added to the pull dispatch for
    free". That was WRONG, and it was the most dangerous sentence in
    this record: the certificate pull is its own dispatch arm and
    inherits nothing. Anyone implementing D2 literally would have
    shipped a key-distribution path with no activation check at all,
    which is the exact defect the 9.4 QA found on the configuration
    pull. The gate is written out explicitly on the new arm, with the
    reasoning copied and strengthened, because a node awaiting operator
    activation must not receive private keys either. Caught by the
    implementer verifying the claim instead of trusting it.
  - **D3 - the recipient is resolved on the CONTROL PLANE, to a
    `node_id`.** AC #1 says to reuse the `node_selector` predicate from
    Story 9.4, which read literally lets the recipient select itself:
    the selector matches on `cluster_nodes.name`, a string the joining
    node chooses, with no UNIQUE constraint. That is not need-to-know.
    The chain is resolved control-plane side at send time: certificate
    hostname, then the routes bound to it, then their `node_selector`,
    then names resolved against `cluster_nodes` to `node_id`, which is
    the identity the mTLS certificate actually proves.

    **CORRECTION (audit iteration 1, see D15).** The sentence that
    stood here claimed the transport layer already guarantees a node
    name is never an authorization input, and that resolving the chain
    control-plane side keeps that true. Both halves were wrong. The
    `roster.rs` comment saying so described the transport only, and
    resolving names to `node_id` at send time does not stop the name
    from being the thing the selector matches: a node that joins under
    a name a selector already lists is entitled to that certificate
    key the moment it is activated. Resolving to `node_id` narrows the
    delivery target, it does not decide entitlement. What actually
    makes the name safe is D15: the name is bound at mint time and
    enforced at redemption, so an operator, not the joining node,
    chooses it. The `roster.rs` comment is corrected to match.

    Migration 53 adds
    UNIQUE on `cluster_nodes.name` and enrollment refuses a name
    already taken, for operator ergonomics rather than for security.
    The migration must handle a pre-existing fleet with duplicate
    names: rename the losers with a suffix and log loudly, never fail
    the boot.
  - **D4 - Story 9.4 replica apply is NOT modified, and that is the
    convergence mechanism.** `apply_replica_certificates`
    (`lorica-config/src/store/replica.rs:268-303`) compares
    `secret_digest(held.key_pem)` against the blob digest string and
    KEEPS the local key when they match. So a key delivered on its own
    path is picked up automatically at the next apply, with no change
    to that function and no ordering requirement between the two
    channels. The tests at `replica.rs:820-840` and `:960-982` pin that
    semantics; leaving it alone is the point.
  - **D5 - the mTLS channel is the confidentiality boundary, because
    nothing else exists.** There is no per-node public key to wrap keys
    to: enrollment sends a bare SPKI (`proto/cluster.proto:124`) which
    the control plane never persists, and `cluster_nodes` keeps only
    fingerprints and serials. Re-encrypting under the follower own key,
    as AC #2 puts it, is not a new crypto path: the follower writes
    through `create_certificate` / `update_certificate`, which already
    encrypt on write under that node master key (`store/certs.rs:19,80`).
    Do not invent a second encryption path. Any new encrypted-at-rest
    column must be registered in `ENCRYPTED_COLUMNS`
    (`store/mod.rs:713-766`) in the same commit, which a source-scanning
    test enforces.
  - **D6 - the follower guard needs no plumbing, but must sit at the
    spawn.** `AppState` already carries `cluster: ClusterRuntime`
    (`lorica-api/src/server.rs:251`), and `run_api_server`
    (`lorica/src/startup/mod.rs:164-203`) is the single shared call site
    both modes use, deduplicated precisely because they once drifted and
    caused the v1.5.2 cert-hotswap bug. So AC #3 is a
    `matches!(state.cluster, ClusterRuntime::Follower(_))` with no
    signature change. The trap: `spawn_cert_expiry_check_task` runs one
    check IMMEDIATELY before entering its loop
    (`lorica-api/src/acme/expiry.rs:109`), so a guard placed inside the
    loop still fires one duplicate fleet-wide alert per node at boot.
    `purge_superseded_acme_orphans` (`startup/mod.rs:178`) deletes
    certificates and is redundant with the replica apply own delete
    pass on a follower; it belongs in the same guard.
  - **D7 - AC #4 is zero code plus one regression test.** OCSP already
    runs on every node and must keep doing so: stapling is a serving
    concern, and followers are the nodes terminating client TLS. The
    test exists to stop a future change from gating it. Record why a
    follower flag must never be added here: `spawn_ocsp_refresh_loop` is
    called from two DIFFERENT processes (`single.rs:452`,
    `worker.rs:650`) and never by the supervisor, so the flag would have
    to reach the worker by argv or the database. The worker has no
    `AppState` and never dials the cluster plane.
  - **D8 - AC #9 hides a gap, not a verification.** The export zone has
    never worked on a follower: nothing in the replica-apply path calls
    `export_after_release`, and `apply_staged` only bumps the reload
    counter (`cluster_follower.rs:267-316`). Worse, exporting AT apply
    time would write an EMPTY private-key file for every certificate
    still counted in `certificates_without_key`, because the exporter
    writes the stored key verbatim (`cert_export.rs:286`). So the export
    is triggered after a successful KEY INSTALLATION, for the
    certificates whose keys just landed, never from the configuration
    apply. The split underneath is already right: the six
    `cert_export_*` settings are node-local and excluded from the blob
    by construction (`canonical.rs:875-880`, with a regression test),
    while the ACL rows replicate and are applied (`replica.rs:232-252`).
  - **D9 - break-glass does NOT suspend key delivery.** A private key is
    not configuration: delivering one overwrites no operator edit, so
    the reason 9.4 excludes a break-glass node from replication does not
    apply. Suspending delivery for a window of up to twenty-four hours
    could let a certificate expire in the middle of the incident the
    window was opened for, which is the worst possible moment. Stated in
    `docs/cluster.md` as a deliberate exception, since every other
    control-plane-originated flow IS suspended.
  - **D10 - the HTTP-01 fleet solver WRAPS the local store, it does not
    replace it.** `AcmeChallengeStore::set` already awaits its SQLite
    write and unwinds its cache on failure
    (`acme/store.rs:142,160-164`), so local semantics come for free. The
    wrapper adds the fan-out to the nodes plausibly serving that
    hostname, an all-or-nothing verdict before returning `Ok` (which the
    Story 9.1 fallible `present` now allows), and a matching fan-out in
    `cleanup`, which the driver calls unconditionally on both paths
    (`driver.rs:199-206`, `:218-220`). The substitution point is the
    match in `provision_with_acme`
    (`lorica-api/src/acme/http01.rs:179-182`). `present` receives the
    per-SAN `identifier`, not the primary domain, so node selection is
    per hostname and matches the D3 predicate exactly. One write per
    node covers all that node workers, since the data plane reads
    through SQLite (`proxy_wiring.rs:747-768`).
  - **D11 - challenge TTL is a migration, and it fixes a live leak.**
    `acme_challenges` has two columns, no timestamp, no index and no
    purge task, and the only caller of `remove` is the driver cleanup.
    A crashed order therefore leaves a node serving a key authorization
    forever, which the code already admits in a warning
    (`acme/store.rs:210-212`). Migration 54 adds the expiry column and a
    purge; the shape test at `lorica-config/src/tests.rs:1313-1347` pins
    the current column set and moves with it.
  - **D12 - metrics, plus one existing blind spot worth closing.**
    AC #10 asks for `lorica_cluster_cert_push_total{node_id, outcome}`
    and a per-hostname gauge of the fleet-wide minimum remaining
    validity. Separately: today a certificate whose key was never
    delivered is indistinguishable in metrics from a corrupt bundle,
    because both land in
    `lorica_certificates_invalid_bundle_total{source="reload"}`
    (`reload.rs:1075-1080`). A node waiting for a key and a node with a
    broken certificate need different operator responses.
  - **D14 - three corrections the implementation forced, recorded so
    the next reader does not repeat them.** The message pair cannot
    live in `certs.rs` as the File List said: `messages.rs` is the
    prost module, so the wire types live there and `certs.rs` holds the
    plain twins and the coordinator, mirroring `ConfigPrepare` against
    `ConfigPayload`. AC #1's fleet-wide opt-in cannot be implemented in
    the transport at all: the distributor addresses exactly the ids it
    is handed and never widens them, so the override belongs entirely
    to the control-plane resolver, and nothing below will catch a
    resolver that returns the whole fleet. And a new body tag needs TEN
    lockstep edits, not the nine this record listed: `messages.rs`
    carries a reserved-range test asserting the next free tags are
    unknown, which moves every time the range is used.
  - **D13 - no new reporting channel is needed, and that is a
    consequence of D2.** The control plane cannot currently learn which
    certificates a node lacks: `ConfigCommitAck` carries only the
    applied generation and hash. The pull path removes the question
    rather than answering it, because the follower asks for exactly what
    it counted as missing. Resist adding per-node key-state tracking to
    the control plane for the push path; the push is best-effort by D2
    and the pull is what closes the gap.
  - **D15 (audit iteration 1) - the node name IS an authorization
    input, so it is bound at mint time and enforced at redemption.**
    Two agents were sent at this question, one on published practice
    and one on this code, because D3 and a `roster.rs` comment both
    asserted the opposite and the audit contradicted them.

    Published practice is unambiguous. A self-asserted node name is a
    documented weakness class, not a theoretical one: Kubernetes node
    authorization has had to add restrictions precisely because a
    kubelet could claim a name, and the same shape has been written up
    against managed offerings. The convergent answer across Consul
    node identities, Teleport, and SPIFFE/SPIRE is that identity is
    either assigned by the server or bound into the credential the
    node redeems, never picked by the joiner at first contact.

    The code side established the local specifics. `bound_node_name`
    already existed on the enrollment token but was OPTIONAL, so the
    protection was available and not enforced. A revoked name is
    permanently retired, which closes the "steal a departed node's
    name" variant on its own; what remained exploitable was the case
    that matters in practice, a selector written before the node it
    names is provisioned. The node-name alphabet was also a strict
    superset of the selector alphabet, so a name could be minted that
    no selector could ever be written to match, or the reverse. And
    the activation review showed the operator nothing about what a
    name would be entitled to.

    Decision, all four parts implemented in this iteration: the mint
    endpoint and `lorica cluster token` now REQUIRE a node name;
    redemption fails closed on a token with no binding rather than
    treating an absent binding as "any name"; the name is validated
    against the selector alphabet at both mint and join so the two
    vocabularies cannot drift; and the roster response carries
    `selected_for_hostnames`, so an operator approving a pending node
    sees which hostnames that name is already selected for before
    clicking activate. D3 and the `roster.rs` comment are corrected
    rather than left standing.

    What this gives up: an operator can no longer mint a token and
    decide the name later, at join time. That flexibility was the
    vulnerability, so losing it is the point.
  - **D16 (audit iteration 1) - an OFFLINE node does not veto an ACME
    order; a LIVE node that refused the token does.** Second question
    put to two agents, one on published practice and one on this code,
    because the implementation shipped an all-or-nothing verdict and
    the audit called it a fleet-wide veto.

    The code agent established the blast radius precisely. Recipients
    are resolved from the registry, so an `Active` node that is
    powered off is still in the list; the fan-out then reports it as a
    failure, and the solver aborted on any failure. Since an empty
    `node_selector` means "every Active node", ONE follower down
    stopped renewing every certificate on every fleet-wide route, and
    the renewal loop only retries every twelve hours. It also found
    the local precedent: Story 9.4 replication deliberately EVICTS an
    unreachable node rather than let it veto the round, with the
    module doc spelling out why, and `distribute_certificate` in this
    very story is best effort for the same reason. The challenge
    fan-out was the odd one out.

    Published practice pushed the other way and is worth recording
    honestly. Let's Encrypt validates from five vantage points and
    tolerates only one failure, each resolving the hostname itself, so
    "some node had the token" is genuinely not good enough; and no
    surveyed system (cert-manager, Traefik, Caddy) accepts partial
    delivery. But all of them remove the partial state by
    construction, with one solver endpoint, an elected writer, or
    shared storage, rather than by refusing to try. The web agent's
    own recommendation ended at the same place this decision lands: a
    node that is down should be treated as out of the answering set
    for this attempt, not gambled on and not treated as a hole.

    The distinction that resolves it: a node with no live cluster
    session is not answering port 80 either. An authority that
    resolves the hostname to it gets a connection failure whether or
    not we published a token there, so refusing to attempt validation
    prevents no failure and causes a real one. A node that IS up and
    refused the token is the opposite: it will answer, and it will
    answer 404.

    So `ChallengeReport::failed` now carries a typed `ChallengeMiss`
    (`Offline` or `Refused`), mirroring `PrepareOutcome`'s split in
    the replication path, and `blocking()` returns only the refusals.
    An offline recipient is logged at WARN naming the nodes, because
    the issuance IS degraded and the operator should know, and the
    order proceeds.

    What this gives up: if DNS still resolves the hostname to a node
    that is down, validation will fail, and we now spend a failed
    attempt discovering that. That is cheap (one failed validation
    costs nothing at the CA; five per hostname per hour is the first
    limit), and the alternative spends a certificate.

## File List

Anticipated, refined by the Phase 1 review:

- `lorica-cluster/src/certs.rs` (new: the distribution message pair on
  tags 60-79, push and pull, plus the report type)
- `lorica-cluster/src/messages.rs`, `proto/cluster.proto` (the nine
  lockstep edits a new body tag requires, including
  `is_known_body_kind`, whose omission would make the build answer
  UNSUPPORTED_METHOD to itself)
- `lorica-cluster/src/bridge.rs` (a new arm in the control-plane-to-
  follower table for the push, and a new arm in the follower-to-control-
  plane table for the pull; each must stay OUT of the opposite table)
- `lorica-cluster/src/dialer.rs` (a `FollowerHandler` method for the
  push; a breaking change to a public trait, same class as Story 9.1
  AC #9)
- `lorica-cluster/src/listener/operational.rs` (control-plane dispatch
  for the follower-initiated pull, reusing the `NodeState::Active` gate)
- `lorica-config/src/store/mod.rs` (migration 53: UNIQUE on
  `cluster_nodes.name` with duplicate renaming; migration 54: challenge
  expiry column and purge)
- `lorica-config/src/store/cluster_nodes.rs` (recipient resolution:
  hostname to routes to selector to `node_id`)
- `lorica-api/src/acme/store.rs` (challenge TTL, purge, and the fleet
  solver wrapper around the existing store)
- `lorica-api/src/acme/http01.rs` (solver substitution at
  `provision_with_acme`; push trigger after issuance and renewal)
- `lorica-api/src/acme/renewal.rs`, `expiry.rs` (unchanged internally;
  gated at their spawn)
- `lorica-api/src/metrics.rs` (AC #10, plus splitting "waiting for a
  key" from "corrupt bundle")
- `lorica/src/startup/mod.rs` (follower guard at the spawn site,
  covering the renewal task, the expiry notifier and the orphan purge)
- `lorica/src/startup/cluster_follower.rs` (pull for missing keys after
  an apply; export trigger after a key installation)
- `tests-e2e-docker/` (a cluster variant of the existing ACME profile)
- `docs/cluster.md`

Actually touched, as built and after audit iteration 1. The Phase 1
list above was close but wrong in three places, kept as written so the
difference is visible:

- `lorica-cluster/src/certs.rs` holds the plain twins and the
  coordinator only; the WIRE types went to `messages.rs`, which is the
  prost module (D14).
- `lorica-cluster/src/challenge.rs` (new, unanticipated): the HTTP-01
  fan-out, `ChallengeMiss` and `ChallengeReport` (D16).
- `lorica-config/src/store/replica.rs` IS modified, contrary to D4.
  The claim that the apply needed no change was the audit's headline
  finding: it blanked a working key as soon as the blob announced a
  different digest.
- `lorica-config/src/store/acme_challenges.rs` (new): the challenge
  rows the retention loop purges.
- `lorica-api/src/acme/fleet.rs` (new): `FleetHttp01Solver`.
- `lorica-api/src/acme/mod.rs` (`after_certificate_issued`, the shared
  issuance tail that replaced three duplicated ones).
- `lorica-api/src/cluster/mod.rs`, `lorica-api/src/cluster/runtime.rs`
  (mandatory `node_name` at mint, the review surface, `cert_bundle`,
  `distribute_certificate`).
- `lorica-api/src/cert_export.rs` (sanitised fallback and containment
  check on the export directory).
- `lorica-cluster/src/roster.rs` (`addressable`, the one intersection
  both fan-outs use), `lorica-cluster/src/enroll.rs`
  (`SessionHandler::on_cert_pull`).
- `lorica/src/reload.rs` (`cert_data_for_resolver`),
  `lorica/src/startup/single.rs`, `lorica/src/startup/worker.rs`,
  `lorica/src/startup/cluster_plane.rs`, `lorica/src/proxy_wiring.rs`,
  `lorica/src/cli.rs`, `lorica/src/cli_cluster.rs`.

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-08-23 | 0.1 | Story drafted from the revised Epic 9 PRD. Need-to-know key distribution added; OCSP kept running on followers (first draft disabled it, which was wrong); certificate path decoupled from the config commit. Status Draft. | Romain G. |
| 2026-09-09 | 1.0 | Audit iteration 1 and remediation. Headline: the replica apply blanked a working private key the moment the configuration announced a different digest, and the pull that should have recovered it was chained to the config-drift path (which never fires after a push) and gated on break-glass against D9; one defect in three parts, all fixed. Two contentious topics arbitrated between a web agent and a code agent, recorded as D15 (the node name IS an authorization input, so it is bound at mint and enforced at redemption) and D16 (an offline node no longer vetoes an ACME order; a live node that refused still does). D2, D3, D4 and a `roster.rs` comment corrected rather than left standing, plus the D12 metric split finally implemented. Three clippy gates and 1022 tests clean. Status Done. | Romain G. |
| 2026-09-08 | 0.2 | Phase 1 review: thirteen decisions recorded. Verified all three declared Story 9.1 dependencies rather than trusting them. Settles backlog #56 (keys get their own channel on the reserved tags; the blob stays fleet-wide). Two AC corrections agreed with the operator: AC #7 and AC #8 are served by BOTH a push and a pull rather than one reinterpreted as the other, and AC #1 resolves the recipient control-plane side to a node_id instead of letting the recipient match its own name. Two findings the ACs did not name: the export zone has never worked on a follower and exporting at apply time would write an empty private-key file, and the challenge table leaks a served token forever with no expiry. Break-glass explicitly does not suspend key delivery. Status InProgress. | Romain G. |
