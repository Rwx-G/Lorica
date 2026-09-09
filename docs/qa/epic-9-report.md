# Epic 9 QA Report - v1.7.0

**Epic:** Multi-Node Cluster, Unified Control Plane & Log Fan-Out
**Target version:** 1.7.0
**Date:** 2026-09-09
**Author:** Romain G.

## 1. Executive summary

Epic 9 lands the v1.7.0 cycle: a designated control plane and any
number of followers over mutual TLS with a fleet CA, token-based
enrollment with explicit activation, two-phase configuration
replication with per-node route targeting, fleet-wide certificate
issuance with need-to-know key distribution, telemetry and audit-trail
fan-in with one verifiable chain per node, a fleet dashboard, and the
two log sinks (RFC 5424 syslog, OTLP logs) that were the other half of
the PRD.

Overall gate: **PASS.** Every story is Done. One acceptance criterion
is knowingly short and is put to the operator in section 7 rather than
hidden: Story 9.7 AC #5 asks for the node filter on the SLA page too,
and it is deliberately not built (decision D17), because no SLA data
fans in and a fleet percentile cannot be computed from minute buckets.
Everything else in the PRD is implemented, audited per story, audited
again as one system at the close, and verified end to end.

The epic's Integration Verification ran for the first time only at the
close, in a new `cluster` Docker e2e profile (control plane plus two
followers, one in workers mode, with the Pebble ACME fixture). Every
story from 9.2 to 9.9 had shipped on unit and integration tests alone
and said so in its record. That first run found five defects before
its first assertion passed, three of them in the product, one of them
a Critical: a node activated while its session was open stayed
`Pending` in the eyes of every gate until it happened to reconnect
(section 5).

Story status:

| Story | Title | Status |
|-------|-------|--------|
| 9.1 | Foundations (RPC generalisation, canonical encoder, migrations, FD seam, Pebble fixture) | Done |
| 9.2 | `lorica-cluster` crate, transport and listeners | Done |
| 9.3 | Node enrollment, registry and revocation | Done |
| 9.4 | Configuration replication | Done |
| 9.5 | Control-plane certificate issuance | Done |
| 9.6 | Telemetry fan-in | Done |
| 9.7 | Fleet dashboard | Done (AC #5 short on SLA, see section 7) |
| 9.8 | Syslog sink and OTLP logs signal | Done |
| 9.9 | Fleet-wide audit trail | Done |

Top findings across the epic, ranked by what they would have cost:

1. **Activation never reached an open session (Story 9.3, Critical,
   found by the e2e profile).** `LiveSession.state` was captured at
   admission and never updated, so a node approved through the API
   while connected kept being refused configuration, certificates and
   telemetry while the roster and the dashboard both said active.
   Every roster refresh now reconciles live sessions and the three
   listener gates read the live entry. Nine stories of unit tests did
   not see it because none of them held a session open across an
   activation.
2. **The fan-in acknowledgement froze cursors after the first shed
   (Story 9.9, Critical).** The ack returned newly-written rows rather
   than rows durably held, so a re-sent batch answered zero and the
   drain never advanced again. Fixed with the semantics stated in the
   proto; the cursors now also advance per class (close), so a class
   an older control plane does not know blocks only itself.
3. **Revocation cut access and said nothing about possession (close,
   security audit, High).** A revoked node keeps the certificate
   private keys it was entitled to; nothing in the response, the audit
   row, the alert or three documents said so. It now names them as
   `certificates_to_reissue` everywhere, and the e2e asserts it.
4. **The wire contract had no version line and no compatibility
   artefact (close, architecture review, Critical).** `lorica-cluster`
   follows the product version from 1.7.0; `docs/cluster.md` gains the
   mixed-version chapter (schema is the binding gate, followers
   upgrade first); a frozen corpus of every message's v1.7.0 encoding
   is a test.
5. **Comments asserting a safety the code did not have**, the pattern
   this epic kept finding: "one store pass" over an N+1 walk, "three
   heartbeat intervals" over six, "re-applies on its next pull" over a
   path that never ran, "refuses an implausible timestamp" over a
   non-empty check, an e2e header claiming a key-distribution assertion
   that could not fire. Each was corrected in code, not in prose.

## 2. Test coverage

| Suite | Gate | Result |
|-------|------|--------|
| `cargo clippy -p lorica-cluster --all-targets -- -D warnings` | CI-matching Docker | clean |
| `cargo clippy` on the product crates (config, waf, api, notify, bench) | CI-matching Docker | clean |
| `cargo clippy -p lorica --all-targets --features otel` | CI-matching Docker | clean |
| `cargo test -p lorica-cluster` (unit + 5 integration binaries incl. the wire corpus) | Docker | 132 unit + 31 integration, green |
| `cargo test -p lorica-config -p lorica-api` | Docker | 286 + 610, green |
| `cargo test -p lorica --features otel` | Docker | 318 unit + every integration binary, green |
| `cargo audit` | Docker | clean (3 allowed warnings, all in `.cargo/audit.toml`) |
| Frontend `npm run check` (svelte-check + tsc) | node:22 Docker | 0 errors, 0 warnings |
| Frontend `npm run lint` | node:22 Docker | clean |
| Frontend Vitest | node:22 Docker | 420 cases, green |
| Frontend `npm audit` (production) | node:22 Docker | 0 vulnerabilities (vite bumped for the dev-only advisories) |
| Docker e2e, base + workers suites | `tests-e2e-docker/run.sh --build` | 348/348 (single-process) and 90/90 (workers), green |
| Docker e2e, profiles (bot, cert-export, geoip, otel, rdns, ai-bot, rbac, audit, hot-upgrade, log-sinks, acme) | same run | cert-export 39, ai-bot 52 + 49 (workers), rbac 37 + 37 (workers), audit 17, hot-upgrade 29, log-sinks 23, acme 15, all green |
| Docker e2e, `cluster` profile (Epic 9 IV) | same run | 47/47: enrolment, activation, gauges, replication, follower 409, telemetry fan-in, a real HTTP-01 order validated through the selected follower, need-to-know key distribution (installed on edge-a, absent on edge-b), audit fan-in with three verified chains, break-glass open/close, revocation of both followers with `certificates_to_reissue` |

## 3. Per-story results

### 9.1 Foundations - Done
`RpcEndpoint` generalised (frame trait, limits, typed oversize and
in-flight errors, cancel-safe in-flight bookkeeping), canonical
encoder with `deny_unknown_fields` and secret material replaced by
digests, migrations 47/48 with table-driven key rotation (which fixed a
pre-existing `dns_providers` rotation gap), fallible `present` with a
pre-`set_ready` abort, the cluster FD seam with the takeover-epoch
interlock, and the Pebble ACME e2e profile (15/15). Two QA iterations.

### 9.2 `lorica-cluster` crate, transport and listeners - Done
Two listeners (operational mTLS on the fleet CA, enrollment opened only
while a token is live), protocol range negotiation, pre-auth budgets
and per-source gates, TLS 1.3 + ALPN, persisted control-plane leaf,
hot-upgrade FD handoff, `.proto` drift test. Two QA iterations closed
one Critical (FD handoff) and the handshake-pool lockout.

### 9.3 Node enrollment, registry and revocation - Done
Two-segment tokens with an embedded SPKI pin, constant-time
verification with a dummy digest on the unknown-id path, bare public
key issuance (no CSR), a CRL-backed acceptor swapped without dropping
the socket, in-memory roster with a session kill switch, renewal with
jitter and a grace window, two-path leave. Close: activation
reconciliation (Critical, e2e), revocation names the keys to re-issue,
the follower gate admits three cluster paths by exact match rather
than a prefix.

### 9.4 Configuration replication - Done
Canonical blob as payload, transactional replica apply with the applied
marker now inside the same transaction (close), two phases with
slow-node eviction instead of fleet veto, pull-based convergence within
one heartbeat, `node_selector` on routes, follower read-only with an
audited break-glass window, drift detection with per-node suppression.
QA closed two Criticals (an aborted round served by the pull path; a
break-glass edit never reconciled). The e2e exercises replication to
both followers, the 409 on a follower, and break-glass open and close.

### 9.5 Control-plane certificate issuance - Done
Need-to-know key distribution resolved on the control plane, push and
pull on separate tags, HTTP-01 challenges fanned out to the nodes that
serve the hostname with per-node reports, OCSP kept on followers, the
export zone on followers. QA closed a three-part Critical (a replica
apply blanked a working key). Close: the e2e now runs a real HTTP-01
order whose validation Pebble can only complete through the selected
follower, binds the certificate to the selected route, and asserts the
key install on one node and its absence on the other; the roster's
`selected_hostnames` is really one store pass.

### 9.6 Telemetry fan-in - Done
Access rows, WAF events and bans ride tags 40-41 into a separate
`cluster-telemetry.db` with a per-node quota, a storage watermark, a
rowid-cursor drain off the request path, fleet query endpoints and a
fleet-wide ban. QA closed two Criticals (per-node retention on a shared
id space; drain throughput). Close: per-class cursor advancement, a
per-session push rate cap, quota entries swept, retired nodes' rows
reclaimed, `metrics_require_auth` flipped to `true` as v1.6.0 promised.
The fan-in ceiling stays derived rather than measured (backlog #64,
with the instrument now specified).

### 9.7 Fleet dashboard - Done
Cluster page (roster, resource gauges on an optional heartbeat payload,
node drawer with certificate entitlement from the server, join dialog
with `--token-stdin`, break-glass and leave on a follower), node filter
on Access Logs, Security and Audit, header badge, read-only mode made
orthogonal to role with an explicit allow-list cross-checked against
the server's. QA closed a Critical (fleet-wide entitlements omitted)
and the missing break-glass/leave controls. Close: revocation keeps
the re-issue list on screen. AC #5 on SLA: section 7.

### 9.8 Syslog sink and OTLP logs signal - Done
RFC 5424 over UDP, TCP (octet counting) and TCP+TLS with optional
mutual TLS, hand-rolled (no new dependency); OTLP logs by a feature
flip on the already-pinned crates; a bounded queue drained by a
dedicated OS thread in every process mode; secret masking and
at-rest encryption of sink secrets; a `log-sinks` e2e profile (23/23).
Five High closed in QA.

### 9.9 Fleet-wide audit trail - Done
One chain per node in the aggregated table, a separate verbatim insert
path, per-chain retention seals, per-chain verify, the node-scoped
apply recorded on both outcomes, and the security property stated as
it is (the aggregated copy is strictly weaker than each origin's own
stream). QA closed two Criticals (the frozen cursor; no arrival genesis
so verify cried tamper on every healthy fleet). Close: fanned-in rows
are aged by arrival time so an origin's timestamp cannot hold them,
and the push rate is capped.

## 4. The epic-wide audit (close)

Four auditors read the epic as one system after the last story:
security, architecture, quality, performance. Everything a story had
already recorded or filed to the backlog was excluded from their scope.

| Auditor | Critical | High | Medium | Low | Verified and acted on |
|---------|----------|------|--------|-----|-----------------------|
| Security | 0 | 2 | 3 | 4 | revocation names keys; audit retention by arrival + push rate cap; scrape token redacted in the export; follower gate exact; cluster reads rate-limited; break-glass honour-clock reset logged; convergence stated as self-reported; e2e harness follows the product's password rules |
| Architecture | 1 | 3 | 5 | 1 | version line + mixed-version chapter + frozen wire corpus; per-class cursors; Pebble in the cluster profile; failure-modes and control-plane-replacement chapters; retired nodes' fan-in rows reclaimed; applied marker in the apply transaction; taxonomy of fan-in payloads; `lorica-fleet` extraction re-scoped as #52 |
| Quality | 0 | 1 | 1 | 3 | the 9.5 e2e assertion made real; `STALE_AFTER_MS` derived and its label read from it; the `TelemetryPush` paragraph put above `TelemetryPush`; sixteen flattened string literals repaired |
| Performance | 0 | 2 | 3 | 0 | `selected_hostnames` single pass; quota sweep; the load-phase instrument specified on #64; audit fan-in contention filed to measure (#75); `refresh_control_plane` under the store lock filed (#79) |

Every finding was verified against the code before acting. Two of the
security auditor's corrections were to the backlog itself: #72 claimed
two mitigations that did not exist in the tree, and both are now real.
The architecture review's central verdict is worth repeating: the
document reads as one design with two chapters missing rather than
nine seams showing, and the property most worth preserving is that
identity is proved by the channel and never carried in a payload,
applied without exception across nine stories.

## 5. Defects the e2e profile found that no unit test had

| Defect | Story | Class | How the profile surfaced it |
|--------|-------|-------|-----------------------------|
| `--cluster-advertise host:port` accepted silently; the port became the leaf's SAN and every join failed with a TLS error naming neither cause nor flag | 9.2 | product | first join |
| A node activated while its session was open stayed `Pending` for every gate | 9.3 | product, Critical | first configuration assertion after activation |
| The roster response is flat (`serde(flatten)`) and the dashboard's type nested it; the Cluster page rendered no node on a real fleet while its tests passed against fixtures encoding the same fiction | 9.7 | product, Critical | first jq path against the real response |
| The smoke's 9.5 section could not fail: no certificate was bound, so its "nothing to distribute" branch fired unconditionally | e2e | test | quality audit at the close; now a real ACME issuance |
| `--data-dir` after the subcommand, a `tee` pipeline swallowing a failed join, a missing `COPY` in the runner image, shared-volume permissions | e2e | harness | first runs |
| The audit profile read verify's pre-9.9 shape; the cluster smoke bound the certificate to a route id the API ignores; `run.sh`'s readiness probe passed `/shared/...` through Git Bash path conversion and never succeeded on a Windows host | e2e | harness | the close's full runs |
| Cluster reads on the 30-per-minute mutation bucket answered 429 to the dashboard and the smoke within a minute (a regression of the close's own limiter fix) | api | product | cluster smoke, second run |

## 6. Cross-cutting findings

- **Comments as unverified claims.** The recurring defect of this
  epic, in code and in tests: a sentence describing a behaviour the
  code did not have. The remedy applied every time was to change the
  code, then the sentence, and where possible to pin the sentence with
  a test (the follower allow-list cross-check, the wire corpus, the
  far-future timestamp test).
- **Contentious topics arbitrated in pairs.** Per the standing
  instruction, a web-practices agent and a code agent were dispatched
  on each: SLA node filter (D17, not built), the heartbeat as a gauge
  carrier (D18, with the rule written down and, at the close, its
  missing "bounded in size" axis), the four follower-local controls
  (D19), node name as an authorisation input (9.5 D15), offline nodes
  not vetoing an ACME order (9.5 D16).
- **Worker-mode parity.** The cluster plane runs in the supervisor,
  and the profile's second follower runs in workers mode precisely to
  exercise that path; audit rows exist only there, which is the trap
  9.9's notes name and the e2e now walks.
- **Honest guarantees.** All-or-none on Prepare and best-effort on
  Commit; the aggregated audit copy strictly weaker than each origin;
  the fan-in envelope declared derived rather than measured;
  convergence resting on a follower's own claim; revocation cutting
  access and not possession. Each is in `docs/cluster.md` as it holds.

## 7. Decision for the operator: Story 9.7 AC #5 on the SLA page

AC #5 asks for the node filter on Access Logs, Security AND SLA. It is
built on the first two and deliberately not on SLA. Three reasons,
arbitrated between a web-practices agent and a code agent (D17):

1. No SLA data fans in. Buckets are mutable (a minute's row is updated
   until the minute closes), which does not fit the id-cursor drain
   that the sheddable series use; shipping them would need a
   different mechanism.
2. A fleet percentile is not computable from per-node minute buckets:
   p95 of two nodes is not a function of each node's p95, so a "fleet"
   SLA page would show a number that is not one.
3. The arbitration also surfaced two pre-existing SLA defects
   unrelated to this epic (#67: a config apply cascade-deletes a
   follower's SLA history; #68: passive SLA is last-writer-wins across
   workers). Fixing those comes before fanning the data in.

Options, in the order recommended: (a) accept the criterion as short
and record it in the PRD as deferred with #67/#68 as prerequisites;
(b) build a per-node (never aggregated) SLA view in v1.8.0 once the
buckets ship over a snapshot-class channel; (c) insist on v1.7.0
scope, in which case the honest deliverable is a per-node picker that
shows one node's own SLA fetched from that node, which needs a
control-plane-to-follower read proxy that does not exist. The release
does not wait on this decision.

## 8. Backlog raised by the epic

Filed during the stories: #49-#74. Filed at the close: #75 (audit
fan-in on the shared `access-log.db` connection, measure first), #76
(a partition longer than local retention loses rows with no signal),
#77 (`cluster` e2e: a restart phase, then renewal, leave, drift and the
quota), #78 (the drift alert takes a follower's break-glass claim at
its word), #79 (`refresh_control_plane` under the store lock). Resolved
at the close: #62 (version line), #61(f) (rate limiter on the cluster
reads), #66 (the profile, with the Pebble caveat closed). Rewritten:
#52 (`lorica-fleet` before `lorica-obs`), #64 (the instrument), #72
(the two mitigations that did not exist).

## 9. Recommendations

- **Immediate:** none blocking release. Bump to 1.7.0.
- **Migration note for the release:** `/metrics` requires
  authentication by default from 1.7.0 (CHANGELOG, `docs/security.md`);
  the upgrade order for a fleet is followers first, control plane last
  (`docs/cluster.md`, "Running a Mixed-Version Fleet").
- **Operator spot-checks:** the dashboard's Cluster page against a
  real fleet in a browser (the e2e drives the API, not the DOM), and
  the revocation banner after revoking a node that held a key.
- **Next cycle, in order:** the restart phase in the `cluster` profile
  (#77), the `lorica-fleet` extraction at the top of the cycle (#52),
  the load phase that turns the fan-in ceiling from derived into
  measured (#64), then the policy decisions deferred as one set
  (#54/#69/#73).
