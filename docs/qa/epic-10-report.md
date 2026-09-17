# Epic 10 QA Report - v1.8.0

**Epic:** Conditional Request Capture & CI Automation API
**Target version:** 1.8.0
**Date:** 2026-09-17
**Author:** Romain G.

## 1. Executive summary

Epic 10 lands two operator features and one piece of debt that had to
close before the second of them could be built. Per-recipient
replication (10.0) ends the fleet-wide configuration blob, so a
follower holds only what it serves. Conditional request capture (10.1,
10.2) gives an operator a per-route rule that keeps the full request and
response for a subset of traffic, with a request-side phase deciding
whether to buffer and a response-side phase deciding whether to emit,
under caps, budgets and a clock. The automation plane (10.3, 10.4, 10.5)
adds a second listener on its own socket, bearer-only and source-filtered
before the TLS handshake, serving one idempotent `environment` resource
that a GitLab pipeline creates, re-runs and tears down, authenticated by
a scoped static token or by the job's own OIDC ID token.

Overall gate: **PASS** for the epic as its PRD defines it. Stories
10.0 to 10.5 are Done, every acceptance criterion is met, each story
was audited as part of one epic-wide pass, and every Critical, High
and Medium finding plus every Low with operational impact was fixed on
the branch rather than filed. Two qualifications, both stated in the
story records rather than discovered here:

- **Story 10.6 (content-type-aware WAF body inspection) is not part of
  this delivery.** It carries an Epic 10 header but has no section in
  `docs/prd/epic-10-v1.8.0.md`. Its AC #1 to #4 shipped in the v1.7.2
  patch; AC #5, #7, #8, #9 and the rest of #10 are unshipped and the
  story is still `InProgress`. Nothing on this branch depends on it.
- **The version bump to 1.8.0 is deliberately not in this epic's
  work.** `CHANGELOG.md` sits under `[Unreleased]` and the README
  roadmap row reads `In progress`, as in previous cycles. The bump is
  its own commit on request.

Story status:

| Story | Title | Status |
|-------|-------|--------|
| 10.0 | Per-recipient replication payload | Done (AC #3 met by derivation, section 3) |
| 10.1 | Capture rules, two-phase matching and budgets | Done (AC #5 expiry, section 7) |
| 10.2 | Capture records, redaction, sinks and dashboard | Done |
| 10.3 | Automation listener and scoped API tokens | Done |
| 10.4 | The environment resource | Done (ownership deviates from the PRD, section 3) |
| 10.5 | GitLab OIDC ID tokens | Done |
| 10.6 | Content-type-aware WAF body inspection | InProgress, out of this delivery |

Top findings across the epic, ranked by what they would have cost:

1. **An empty `allowed_backend_cidrs` meant every address (10.4,
   High).** A token minted without the field could point a public
   hostname at `127.0.0.1:9443`, the loopback management API, or at a
   cloud metadata address. Both credential models now refuse an empty
   grant at write time and `validate_backends` refuses one again at use
   time for rows written before the rule. Section 5 says why a green
   unit suite could not see it.
2. **An OIDC issuer entry bound to nothing granted a whole GitLab
   instance (10.5, High).** `aud` is a string a job writes into its own
   `id_tokens:` block, not a secret, so an entry with no `project_path`
   and no `namespace_path` accepted a token from every project on that
   instance that guessed the audience. `OidcIssuer::validate` refuses
   one now. Section 5, again, on why nothing in the verifier was wrong.
3. **The `shared` label was a takeover primitive, and the PRD's
   ownership rule crossed tenants (10.4, 10.5).** A `PUT` rebuilt the
   row with the request's owner and labels after the access check
   passed, so a caller who reached a shared environment could lock its
   real owner out. Separately, "same name prefix" made `ci-acme` and
   `ci-globex` one owner, and the OIDC projects `acme/web` and
   `acme/web-docs` likewise. Ownership is exact principal equality of
   the same kind now, a deliberate deviation from the PRD's wording.
4. **A capture rule watching `4xx` could not capture what the proxy
   itself refused (10.1, 10.2).** `logging` looked its rules up through
   `ctx.route_id`, which only `upstream_peer` sets, so a WAF block, a
   403 from an IP list, a 429, a redirect, a maintenance page or a
   `return_status` produced no record however exactly the rule matched.
   The buffers had been filled and the node reservation spent for
   nothing. The admitting route and its compiled rule set now travel on
   `CaptureState`.
5. **Code that was built, unit-tested and wired to nothing.** One
   commit closed four of these; the audit found two more. Section 6
   treats it as a pattern rather than as six incidents.

## 2. Test coverage

| Suite | Gate | Result |
|-------|------|--------|
| The three CI clippy commands, `RUSTFLAGS="-D warnings"` | CI-matching Docker | clean |
| Rust unit and integration, product crates, `--features otel` | Docker | 2632 tests, zero failures |
| Rust unit and integration, Pingora-forked crates | Docker | 748 tests, zero failures |
| `cargo audit` | Docker | two pre-existing allowed advisories, nothing new |
| Frontend `npm run check` (svelte-check + tsc) | node:22 Docker | 0 errors |
| Frontend `npm run lint` | node:22 Docker | clean |
| Frontend Vitest | node:22 Docker | 480 cases across 25 files, green |
| Docker e2e, base and workers | `tests-e2e-docker/run.sh --build` | 361 and 90 |
| Docker e2e, existing profiles | same run | cert-export 39, ai-bot 52 and 49, rbac 37 and 37, audit 17, hot-upgrade 29, log-sinks 23, acme 15 |
| Docker e2e, `capture` profile (new, Stories 10.1 and 10.2) | same run | 163 |
| Docker e2e, `cluster` profile and its automation phase (new, Stories 10.0 and 10.3 to 10.5) | same run | cluster 64, automation 104, restart 6 and 9, revocation 7 |

Every phase passed on the final tree with no product defect. Two
suites, `waf_body_inspection_e2e_test` and `lorica-memory-cache`,
flaked only under fourteen concurrent `cargo test` runs; each passed
twenty consecutive solo runs on the quiet tree, and one of them
(`stale-while-update`) was made deterministic rather than left to
timing.

Schema head moves from 55 to 60: capture rules (56), automation tokens
with their own HMAC key row (57), environments and `managed_by` (58),
OIDC issuers (59), the per-issuer pinned CA (60).
`CANONICAL_FORMAT_VERSION` moves from 1 to 2 exactly once, in Story
10.1, and a guard test asserts it does not move again inside this
release; a digest of the canonical field set now pins the number to a
shape so the two cannot drift. One new dependency, `jsonwebtoken`,
approved by the maintainer on 2026-09-16 for Story 10.5, on the
`aws_lc_rs` backend because `rust_crypto` pulls the `rsa` crate and
RUSTSEC-2023-0071 with it.

## 3. Per-story results

### 10.0 Per-recipient replication payload - Done

The control plane cuts one payload per recipient, resolving
`node_selector` to the `node_id` the certificate proves rather than to
the display name the selector carries. Routes, their links, the backends
those links reference, the certificates those routes bind, and from 10.1
and 10.4 the capture rules and environments, are cut with the route;
fleet policy stays fleet-wide, because a node that cannot see the policy
it is judged against cannot tell whether it is behind. The consequence
that made this a story is that two nodes correctly converged on one
generation legitimately hold different bytes, so the fleet-wide hash the
convergence design rested on becomes per-node, including in what the
control plane advertises: the handshake ack, the heartbeat ack and the
up-to-date pull ack carry that node's expected version, without which
every follower would read as permanently behind.

AC #3 asked for the expectation to be persisted; it is derived, and the
story says why rather than treating it as a shortcut. The architecture
review then found the derivation's premise wrong: a cut is a function of
the canonical configuration *and* the roster that resolves a selector
name, and the roster could move under a generation. The fleet identity
hash folds in the sorted `(name, node_id)` rows now, so an enrolment
advances the generation, and the boot seed repairs a change that landed
without a round behind it. Two of the story's own premises were
corrected in its Debug Log.

Cost at AC #8's request (release, dev container, 20 pinned routes per
node plus 10 fleet-wide): 1.10 ms per round at 2 nodes, 7.82 ms at 10,
96.13 ms at 50 against 25.28 ms for one fleet-wide encode. Quadratic and
knowingly so; each recipient's blob stays flat at about 71 KB while the
fleet's grows to 2.6 MB, which is the opposite of the old shape. The
frozen wire corpus passes unmodified.

### 10.1 Capture rules, two-phase matching and budgets - Done

Model, migration 56, store CRUD, the replication allowlist entry, the
`CanonicalConfig` field and the format-version bump. Predicates compile
into a set keyed by route at snapshot build time, never per request; a
request no rule wants costs one `Option` check per hook and allocates
nothing. Overflow follows the mirror: keep the prefix, set `truncated`,
leave the stream alone, with tests asserting the upstream receives every
byte of a body the buffer kept 64 KiB of. The node-wide ceiling is a
process static released by `Drop`, not a snapshot field, because a
reservation outlives the snapshot it was taken under, and the buffers
are released at `logging` by ownership, so there is no call to forget.
Budgets are one critical section, the rate window a 60-slot ring rather
than a list of timestamps, and a spent rule disables itself once through
a ticker off the request path, audited and never deleted.

Two deliberate asymmetries are documented at their site: an on-call
Operator may stop a capture without being able to start one, and a
malformed `source_cidrs` entry fails the whole rule where the connection
filter skips and warns, because skipping can empty the list and an empty
list means every client. That second one produced backlog #88.

### 10.2 Capture records, redaction, sinks and dashboard - Done

One JSON document per capture joined to its access-log row on
`request_id`, headers as an ordered list so duplicates survive, `utf8`
or `base64` by content type. Redaction is a constant set a rule can only
extend, and the test asserts the negative. Four outputs: the
`lorica::capture` tracing target, a bounded ring of the last fifty
records, the syslog and OTLP lanes through `SinkKind::Capture` with
per-kind toggles, and a directory writer that publishes with `hard_link`
so a partial write never leaves a half document. A sink failure drops
and counts; the request is never touched.

Under `--workers` the supervisor holds an empty ring and answers 503
with a message naming the three places the records actually are, and
the Debug Log states exactly what shipping the workers' rings would
cost. The two capture gauges do aggregate, as typed fields on
`MetricsReport`: `lorica_capture_rules_active` as the maximum across
workers (every worker compiles the same snapshot) and
`lorica_capture_inflight_bytes` as the sum, with the rule documented on
each setter.

### 10.3 Automation listener and scoped API tokens - Done

A second axum server on its own socket with its own TLS, its own router
and none of the session middleware. The source allowlist is checked on
the accepted `TcpStream` before the TLS acceptor sees it, which is the
first axum listener in this project to filter by source; to avoid a
second copy of the predicate the pure `ConnectionFilterPolicy` moved
into `lorica-config` and the runtime stayed in the binary. Bearer only,
so there is no ambient credential and no CSRF question. A path with no
declared scope is refused for every token and logged at ERROR: the
tempting default, the widest scope, reads as fail-closed and is not.
Scopes are a closed enum with no `routes:write`, no `certificates:write`
and no `settings:*`, so the automation surface is the environment
resource and not the management API behind a different door.

The story corrected three PRD statements before implementation rather
than during it: there is no settings file to put an `[automation]` block
in, so the bind is a clap flag and the allowlist a `GlobalSettings`
column with hot reload for free; `validate_cluster_listen` is not
reusable as written, so its two primitives became one
`validate_listen_bind` serving all three listener families and
`ReservedPorts` learned about the cluster and automation ports it could
not previously refuse; and the listener belongs in `lorica-api` rather
than widening a `pub(crate)` function's visibility.

### 10.4 The environment resource - Done

`PUT /automation/v1/environments/{name}` writes a route, its backends,
the joins and the environment row in one transaction, on a
`ConfigStore::in_transaction` that commits on `Ok` and rolls back on
drop. `certificate: "auto"` is a stored mode re-resolved at every
snapshot build, so replacing a wildcard certificate moves every
environment over without a pipeline re-run; when no certificate covers
the hostname any more the route keeps its last id and a WARN names the
environment, because an environment that served yesterday must not stop
serving silently over a certificate change it had no part in.

Three findings here changed the contract rather than the code alone.
Ownership is exact principal equality, not the PRD's name prefix.
Foreign and unknown answer alike, because a 403 on someone else's
environment confirms the name is taken and by whom, which is the one
fact a neighbour on a shared node must not be able to enumerate. And
`applied_generation` is a floor rather than a target: the PRD said
"poll until every node reports it", which is off by one, since the
write itself starts the round that publishes the next generation.

### 10.5 GitLab OIDC ID tokens - Done

RS256 pinned on the verifier and never read from the token header, with
the refusal test written before the verifier existed and failing
against a stub first. `kid` lookups hit a JWKS cache refreshed every
six hours and at most once a minute on an unknown key, so a caller
sending random `kid` values cannot drive an outbound fetch per request.
The replay set is bounded and its evictions are counted, because a
silent eviction turns a full set into a replay window.

Three audit findings are the story's own: the unbound issuer entry
(section 5), an unanchored `project_path` glob where `acme*` covered
`acme-evil/pwn` (a glob must now pin a namespace segment before its
star, and a star no longer crosses `/`), and an unauthenticated `aud`
fan-out where `peek_audiences` drove one store read each under the
global mutex. The e2e author found the fourth and most practical one:
the JWKS client trusted webpki roots only, which makes the mode
unusable for its main audience, a self-hosted GitLab under an internal
PKI. It trusts the platform store now and an entry may pin its own CA,
replacing rather than extending the trust for that issuer. The claim
that `lorica-acme` had the same gap was checked and is false.

## 4. The epic-wide audit

Five read-only reviewers (security, offensive, architecture, quality,
performance) read the epic as one system after the last story and
before the MR, on Opus. Everything a story had already recorded was
excluded from their scope. Every Critical, High and Medium finding, and
every Low with operational impact, is fixed on the branch; nothing was
carried into the backlog as a known defect.

| Area | What the pass changed |
|---|---|
| Security | empty backend grant is deny-all; an issuer must bind a project or a namespace; the `shared` label stops being a takeover; ownership is exact principal equality; a foreign environment is indistinguishable from an unknown one; the protected-environment binding runs on every verb; an explicit certificate must cover the hostname; `tls_sni` validated and `weight` capped; an issuer may pin its own CA |
| Offensive | an oversized bearer or a wide audience list is refused before any store read (8 KiB, 8 audiences); quotas on environments per principal (100) and backends per environment (32); a symlinked capture output directory is refused; six holes in `CaptureRule::validate`, the worst a malformed redaction entry that redacted nothing while appearing in the rule |
| Architecture | the roster joins the fleet identity hash and the boot seed repairs a generation a crash left behind; a canonical shape digest guards the format version; one JSON column decoder replaces four; one follower check replaces four; the 400 versus 422 rule written on `ApiError` rather than swept across call sites; stored columns that do not decode are `Corrupt` and answer 500 |
| Quality | the refusal reason rides the stored action and a structured tracing field from one published vocabulary a new variant cannot escape; a handler that panics still lands its audit row, through a panic net inside the audit layer; the management API refuses to edit or delete rows the automation plane owns, which the dashboard alone had been guarding; `managed_by` is serialised at all |
| Performance | the commit phase reads a version rather than a per-node blob (at fifty nodes that was a hundred megabytes copied per generation, and again on every dashboard render); audit rows from both planes go through one bounded single-consumer queue, so a request no longer pays a chained-hash SQLite write inline; `last_used_at` coalesces to one write a minute; the JWKS lock is released across the fetch; the capture buffer grows amortised instead of reserving its cap; the rate ticker uses the expiry index; evicted rules lose their metric series |

The frontend pass is worth naming separately: the Capture page owns a
single poll and passes a refresh key down, reads the ring size and
elision the node reports rather than restating them, drops a read that
lands after unmount, and binds reactive state in its tests, which
removed 270 non-reactive warnings.

## 5. What a green unit suite could not see

Two High findings deserve more than a table row, because both were
invisible to a test suite that was passing and would have stayed
invisible to a larger one of the same kind.

**An empty `allowed_backend_cidrs` read as every address.** Nothing
here behaved incorrectly in isolation. `ConnectionFilterPolicy::from_cidrs`
reads an empty allow list as default-allow, which is the right meaning
for a filter an operator opts into, and its own tests assert exactly
that. The environment validator's tests all handed it a token that
carried CIDRs, because that is the shape every example in the story and
the PRD uses. The defect lives in the seam: a policy type whose empty
case means *allow* was reused to express a grant a credential carries,
where the empty case has to mean *nothing*. A unit test could only have
caught it by asserting the behaviour of a case nobody had decided on,
which is the same act as deciding it. The consequence, a token pointing
a public hostname at the loopback management API or a cloud metadata
address, is visible only when reasoning about the deployment, not about
the function. Both model validators refuse an empty list at write time
now, and `validate_backends` refuses one again at use time, for rows
written before the rule existed. The audit also established that the
"node default backend policy" both model docs described never existed.

**An OIDC issuer entry with no bound project or namespace.** Every
verification step was correct and every test on it passed: RS256 pinned
on the verifier, the signature checked, `iss`, `aud`, `exp`, `nbf` and
`iat` checked with 60 s of skew, every `bound_claims` entry matched
exactly. The hole is that `bound_claims` was allowed to be empty, and
what makes that fatal lives outside the code: on GitLab, `aud` is a
string the job writes into its own `id_tokens:` block, not a secret
Lorica issued. An entry binding neither `project_path` nor
`namespace_path` therefore accepted a token from every project on that
instance that guessed the audience. No test of the verifier could have
failed, because the verifier was not wrong; the missing thing was a
requirement, and a unit suite tests behaviours someone thought of.

The general shape is the same in both: an absent constraint, not a
wrong behaviour. It is also why the end-to-end suite would not have
caught either. An e2e drives the happy path and the refusals its author
already knew about, and in both cases the author would have minted a
credential with the field filled in.

## 6. Two failure patterns worth naming for the next epic

**The same rule implemented twice, drifting apart.** This epic found
and closed it four times over, and the hygiene pass at the head of the
cycle had already closed it twice more.

- Four hand-rolled answers to "is this a CIDR". The pure
  `ConnectionFilterPolicy` moved into `lorica-config` and all four
  delegate to it; validators refuse a bad entry, the data plane skips
  one, and the module doc says which does which.
  `GlobalSettings::cidr_lists` is the single enumeration, guarded by a
  test that serialises the struct and requires every address-named
  field to be in it, so the next CIDR field added without validation
  fails the build. Backlog #88 exists because two copies of this rule
  had resolved the same question two different ways, and the data
  plane's way silently disabled an allowlist on a single typo.
- Three hostname matchers under two names. One function called
  `pattern_matches`, any-depth, was about to serve as a single-label
  authorization grant, where `*.review.example.com` would have covered
  `a.b.review.example.com`. The danger was never having two rules; it
  was having one whose name did not say which rule it was. They are
  `matches_any_depth` and `matches_one_label` now, each documented
  against the other, and the cluster store's `host_pattern_matches` is
  deliberately left as a third with a written reason and a pointer to
  it.
- Four follower checks, and four JSON-column decoders, each collapsed
  to one in the audit fix pass.
- From the hygiene pass: two definitions of drift (backlog #71), where
  the control plane compared generation and hash while the dashboard
  compared generation alone, so a converged node kept its pill for half
  a minute and a hash-only divergence never showed one at all; and
  `DriftTracker`, whose two-method contract lived in a comment until
  `observe` became `pub(crate)` behind a handle claimed once.

The design answer this epic reached for repeatedly is the same one:
derive rather than store a second copy. Story 10.0's per-node
expectation is derived for exactly that reason. What the architecture
review added is the condition that makes derivation safe, which is that
the sources cannot move under the identity being compared.

**Built, unit-tested, wired to nothing.** One commit closed four of
these at once, and its own message names the class: each had a green
test suite and did nothing.

- The automation listener was never started. Its slice said so plainly
  at the time ("nothing starts this listener yet"), and the startup
  wiring was its own slice one commit later.
- `automation_allowed_cidrs` existed in the settings model and in the
  store and had no management API path that could set it. The listener
  refuses to open without it, so until that landed the listener could
  never open at all.
- The socket did not survive a hot upgrade. The producer side had
  deliberately handed over nothing rather than a socket the new side
  could only close, and the consequence, EADDRINUSE during the overlap,
  was stated rather than hidden until the arm was written.
- `spawn_capture_disable_task` was written in Story 10.1 and registered
  in neither startup path. A rule that spent its budget set its flag,
  nothing wrote it back, so it kept recording and no audit row appeared.

The audit found two more of the same shape. Route and backend responses
never serialised `managed_by`, so the dashboard's automation badge was
dead against a real server, and the management API did not refuse to
edit managed rows at all: the dashboard alone had been guarding it.
And `ConfigStore::bump_capture_counters` was built in Story 10.1 with
no producer, so the per-rule counts lived in the process budget and
never reached the row the dashboard reads; Story 10.2 took it because
whoever emits the record is the one who knows an emission happened.

The related variant is wiring that exists but reads the wrong field,
which unit tests pass with the same confidence: the capture emit path
looking rules up through `ctx.route_id`, so the entire class of
requests the proxy refuses itself produced no record.

## 7. Cross-cutting findings

- **Deviations from the PRD, each taken deliberately and written down
  before the code.** No `[automation]` settings block, because there is
  no settings file. `validate_cluster_listen` lifted rather than
  reused. The listener in `lorica-api` rather than the binary.
  Ownership as exact principal equality rather than a name prefix.
  `applied_generation` as a floor rather than a target. AC #3 of Story
  10.0 met by derivation rather than persistence. Every one of these is
  in a story's Debug Log with the reasoning, not in a commit message
  alone.
- **One acceptance criterion is met by documentation rather than by the
  behaviour it describes.** Story 10.1 AC #5 says reaching `expires_at`
  flips `enabled = false` and audits it. The shipped code stops an
  expired rule (it is never a candidate on any node, whatever the flag
  says) and the self-disable task reacts to a spent `max_captures`
  only. `docs/capture.md` states what the code does. Closing the gap is
  a ticker that walks the store for `enabled AND expires_at <= now`;
  it is not in this release, and it is named here rather than left for
  an operator to find.
- **Worker-mode parity was answered per story, not assumed.** The
  capture ring is a 503 under `--workers` with the alternatives in the
  message; `lorica_captures_total` joined `PER_WORKER_COUNTERS`; the
  two gauges travel on `MetricsReport` with the aggregation rule (max,
  then sum) documented on each setter. The one piece of the PRD's e2e
  topology that was not built is the `capture-workers` profile, which
  the PRD asked for on the grounds that body buffering is precisely the
  kind of thing that passes single-process and breaks in a worker. The
  in-process tests and the documented semantics cover it; a profile
  would cover it better.
- **Honest guarantees, stated where an operator reads them.** The
  captured response body is the upstream's, before any rewrite this
  proxy applies, so a capture can disagree with what the client
  received on a rewriting route. Bodies are not redacted, and that is
  said out loud rather than left as an omission. Counters and rate
  windows are per worker, with the absolute `expires_at` as the only
  fleet-consistent bound. A capture rule cannot be disabled on a
  follower without break-glass, because it arrives by replication and a
  local change would be overwritten on the next round. A pipeline
  waiting for the fleet polls until every node exceeds the generation
  its `PUT` returned.
- **Mixed-version safety was designed, not discovered.**
  `CANONICAL_FORMAT_VERSION` moves once, at 56, and the accompanying
  schema migration makes the handshake refuse a 1.7.x follower before a
  version 2 blob is ever offered. The documented upgrade order,
  followers first and control plane last, holds unchanged. The frozen
  wire corpus passes unmodified, because the blob is still opaque bytes
  and no message shape moved.

## 8. The end-to-end suite this cycle

Epic 9's Integration Verification ran for the first time only at the
close and found five defects before its first assertion passed. This
cycle inverted the order: the audit ran first, its findings were fixed,
and the full suite then passed on the final tree with no product defect
at all. That is the outcome the ordering was chosen for, and it should
not be read as the suite having nothing to say.

- The `capture` profile, 163 assertions, drives a real proxy from two
  source addresses with the syslog and OTLP collectors and an output
  directory mounted read-only and then writable, including a WAF block
  captured by a rule watching `4xx`: the audit finding above, pinned by
  a test that could have caught it.
- The automation phase on the cluster topology, 104 assertions, runs
  against an OIDC issuer fixture that mints RS256, HS256 and unsigned
  tokens, rotates its key, counts JWKS fetches and simulates an outage.
- The JWKS trust-store gap in Story 10.5 was found by the e2e author,
  not by a reviewer, and is the only finding in the epic that made a
  feature unusable for its stated audience rather than unsafe.
- Two operational facts are now encoded in the fixtures: Docker's
  embedded DNS answers a bare service name with one address on the first
  shared network, so a service on two networks needs a per-network
  alias; and the capture and automation metric families are forced at
  API start, so they appear on `/metrics` at zero rather than absent.
- Story 10.0 deleted an assertion rather than relaxing it: the cluster
  smoke required every node to report the same configuration hash, which
  is wrong by construction now. Its replacement asserts that `edge-b`
  holds neither the route selected for `edge-a` nor its backend, and the
  backend half carries the weight, because the old recipient-side filter
  deleted the route it was not selected for and kept the backend rows it
  had been sent.

## 9. Backlog movement

The cycle opened by pruning the Open table: nineteen of its forty-one
rows were already resolved, which is what makes a table stop being read,
and this cycle picks its hygiene work from that table.

Resolved during the epic: #49 (`Arc<SinkPayload>` instead of a deep copy
per lane, brought forward because the capture lane is a third consumer
carrying 64 KiB bodies), #50 (per-kind OTLP toggles for all four sink
kinds, since it was the same code), #51 (a sink lane is registered by
its consumer, which is what makes the capture lane cost one call), #56
(per-recipient replication, Story 10.0), #57 (replication tuning stops
advertising a knob nobody has), #59 (`DriftTracker`'s contract enforced
by the type system), #71 (one definition of drift, formed by the
server). Raised and closed in the same cycle: #88, a malformed CIDR
silently disabling the connection allowlist.

**No new open entry was filed by this epic.** That is deliberate: the
audit findings were fixed rather than recorded. The two items a reader
might expect to find there are at section 7 instead, the expiry ticker
and the `capture-workers` profile.

## 10. Recommendations

- **Immediate:** none blocking. Bump to 1.8.0 as its own commit when
  requested.
- **Migration note for the release:** schema head 55 to 60 and
  `CANONICAL_FORMAT_VERSION` 1 to 2. The upgrade order for a fleet is
  unchanged, followers first and control plane last; a 1.7.x follower
  is refused at the handshake by the schema gate before a version 2
  blob is offered.
- **Operator note:** enabling `--automation-listen` opens a network
  port. It refuses to start on a follower, and refuses to start with an
  empty `automation_allowed_cidrs`; an operator who does not run CI
  against Lorica gains nothing and should leave it off.
  `docs/security/hardening-guide.md` carries the firewall stanza and
  the capture-rule hygiene paragraph.
- **Operator spot-checks:** the Capture page against a real node in a
  browser (the e2e drives the API, not the DOM), the automation badge
  and edit refusal on a route an environment owns, and one full
  create-and-tear-down from a real GitLab pipeline under both
  authentication modes.
- **Next cycle, in order:** the expiry ticker that clears `enabled`
  (section 7), the `capture-workers` e2e profile, and a decision on
  Story 10.6's remainder, which is currently an `InProgress` story
  attached to a closed epic and should either be finished in the 1.9.0
  cycle or re-homed.
