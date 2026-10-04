# Epic 11 QA Report - v1.9.0

**Epic:** Management MCP Server with Tiered Access
**Target version:** 1.9.0
**Date:** 2026-10-04
**Author:** Romain G.

## 1. Executive summary

Epic 11 lets an operator drive Lorica from an MCP client without handing
that client more authority than the task needs. It ships `lorica-mcp`, a
server that is exactly one tier, decided by the scopes of the token it
runs with: a **read** tier of nine tools over a new read surface on the
automation plane (11.1), a **config** tier of eight route, backend and
certificate mutations, each with a `_preview` twin (11.2), and an
**admin** tier that changes nine operational settings and nothing else
(11.3). Story 11.4 makes the separation a property of the product rather
than of the operator's discipline: a token whose scopes span two tiers
cannot start a server, `lorica mcp token create --tier` mints exactly one
tier and prints its blast radius, and the binary ships in both packages
and the production image with no service starting it. The server speaks
MCP revision 2026-07-28 over stdio and over one path on the Epic 10
automation listener, so an operator who has not enabled that listener
has no MCP surface at all.

The cycle also found and fixed six defects in versions already released,
two of them serious: every `.deb` from 1.0.0 to 1.8.0 installed its
files owned by the CI runner account, and since 1.7.2 a Blocking-mode
WAF refusal of a chunked request body delivered that body to the backend
as a complete request. Section 2 lists them.

Overall gate: **PASS** for the epic as its PRD defines it, and for the
release defects above. Stories 11.1 to 11.4 are Done, every acceptance
criterion is met (one in part, by the maintainer's decision, section 4),
each story was audited by its own pass, the release was audited as a
whole before the merge and again on everything that landed after that
audit, and every Critical and High finding of those passes was fixed
on the branch, as was every Medium and Low with a security, correctness
or operational consequence. Maintainability findings were taken where
they removed a duplicated source of truth, which is most of them. The full
Docker end-to-end suite passed on HEAD `352c184b` (section 10). Three
qualifications:

- **The version bump to 1.9.0 is deliberately not in this epic's work.**
  Every first-party manifest still reads 1.8.0, `CHANGELOG.md` sits under
  `[Unreleased]` and the README roadmap row reads `In progress`, as in
  previous cycles. The bump is the next commit.
- **The `.deb` ownership defect needs an advisory, and it is not
  published.** A draft exists outside the tracked tree
  (`SECURITY-ADVISORY-DRAFT-deb-ownership.md`, untracked, not part of
  this release's commits). Hosts running a 1.0.0 to 1.8.0 `.deb` that
  also carry a uid 1001 account remain exposed until they upgrade or are
  checked by hand, and only the advisory tells them so.
- **Three residual risks are accepted and named** (section 12): deleting
  a protected route and creating it again (#93), the bytes past the WAF
  scan budget that stream unscanned, and the fifteen open backlog
  entries that predate the cycle.

Story status:

| Story | Title | Status |
|-------|-------|--------|
| 11.1 | The `lorica-mcp` crate and the read tier | Done (AC #4 met in part by decision: status yes, roster no) |
| 11.2 | The config tier | Done (IV3's follower half is the listener's startup refusal; the replication half proven in the cluster e2e profile) |
| 11.3 | The admin tier, and where it stops | Done (allowlist narrowed from eighteen keys to nine, section 4) |
| 11.4 | Tier isolation, packaging and the operator story | Done |

Top findings across the cycle, ranked by what they would have cost:

1. **Every `.deb` from 1.0.0 to 1.8.0 installed its files owned by the
   CI runner account (`3ffabd71`).** On a host with a `runner` or uid
   1001 account, that account owned `/usr/bin/lorica` and
   `/lib/systemd/system/lorica.service` and could reach root through the
   unit. Verified on all 25 published releases; the `.rpm` was never
   affected. Section 6.
2. **A Blocking-mode WAF refusal of a chunked body completed the request
   upstream, since 1.7.2 (`a1b3ed28`, `7c1b57d5`).** The client saw a 403
   while the backend received the whole SQLi payload, or the first,
   unscanned mebibyte past the scan window. Found because a flaky test
   was investigated instead of retried. Sections 6 and 7.
3. **A write grant bounded what a write claimed, never what it targeted
   (Story 11.2, Critical, never released).** A token confined to a review
   namespace could disable the WAF on a production route by id, unbind
   its certificate, drain a production backend or delete another
   owner's environment. The guard now runs inside the store closure, on
   the row it writes (`621e7950`).
4. **A route a token or an environment creates took a host's traffic,
   and its protections, from a wildcard or catch-all route (final audit,
   Medium; the environment half released since 1.8.0).** Hostname
   uniqueness compares exact strings and the proxy picks an exact name
   first, so `app1.review.example.com` created under an operator's
   Basic-auth-protected `*.review.example.com` served that host with no
   protection. Section 6.
5. **The management CLI sent the SuperAdmin password to whatever held
   the loopback management port (backlog #90, `b1a39995`, every release
   with a CLI login).** The port is unprivileged, so a local user who
   bound it during a restart received the password. In single-process
   mode the node even kept serving after losing the port. Section 2.

## 2. Released-version defects found and fixed in this cycle

| Defect | Released in | Found by | Fix |
|---|---|---|---|
| Every `.deb` entry owned by `runner` (uid 1001) instead of root | 1.0.0 to 1.8.0 (all 25 releases) | Story 11.4 penetration audit (High, rated "likely"), verified on the published 1.8.0 asset and then on every release | `3ffabd71`: `dpkg-deb --root-owner-group`, a postinst that resets to `root:root` any package path another owner holds, CI ownership assertions on both packages; `d98b2927` and `352c184b` refined the repair (no reload or start on a repaired host, no recursive `chown` of the data directory) |
| Blocking-mode WAF refusal of a chunked body (body-scan 403, scan-window 413, chunked `max_request_body_bytes` 413) ended the upstream body with a terminating chunk, so the backend got a well-formed request | 1.7.2 to 1.8.0 | A flaky test (one run in fifty), investigated (section 7) | `a1b3ed28` drops the upstream connection mid-body; `7c1b57d5` reads and scans an inspectable body in full before the upstream is dialled, so a refused body reaches no backend at all, mirror included |
| An environment's exact-host route took a protected wildcard or catch-all route's traffic and shed its protections | 1.8.0 | Final targeted audit (security, Medium; environment variant rated "likely") | `352c184b`: the environment route inherits the displaced routes' protections control by control in the safe direction, Basic auth copied server side and never answered |
| The CLI accepted any certificate on `127.0.0.1` and sent the password; single-process mode kept running after a failed management bind | Pre-existing in every management CLI command that logs in, up to 1.8.0 | Story 11.4 security audit (Low, pre-existing), then the pre-merge security audit for the bind | `b1a39995` pins the certificate the listener records as served; `d98b2927` makes a failed management bind fatal in both modes |
| An RPM upgrade left the service stopped and disabled (`%preun` ran unguarded after the new `%post`) | 1.8.0 `.rpm` (pre-existing) | Pre-merge architecture audit (High) | `d98b2927` guards `%preun` and repairs the 1.8.0 hop in `%posttrans`; `352c184b` records the service state before the old scriptlets run, so an upgrade keeps it as the operator left it |
| Six Network-tab settings (`audit_log_retention_days`, `connection_limits_per_ip`, the two bot-stash caps, the two mirror caps) had no request field, so every save dropped the edit | 1.6.0 to 1.8.0 | The backlog #89 pass | `352c184b` |

Two 1.8.0 defects of the environment resource, smaller in reach, were
fixed on the way and are in `CHANGELOG.md` Security: a backend grant
whose stored entries all failed to parse reached the connection filter
empty and admitted every address, and an IPv6 grant covering the mapped
space (`::/0`, `::ffff:0:0/96`) admitted `[::ffff:127.0.0.1]`, which
connects to IPv4 loopback.

## 3. Test coverage

| Suite | Gate | Result |
|-------|------|--------|
| The three CI clippy commands, `-D warnings` | CI-matching Docker | clean (run of 2026-10-04 on the final fix tree) |
| Rust unit and integration, product crates, `--features otel` | Docker | 3073 tests, zero failures (README figure, re-measured on the final tree) |
| Rust unit and integration, Pingora-forked crates | Docker | 766 tests, zero failures |
| `cargo test -p lorica --features otel` in CI | CI | runs for the first time this cycle (section 7) |
| `cargo audit` | Docker | re-run on the final tree (2026-10-04): no vulnerability, three allowed warnings already listed in `.cargo/audit.toml` |
| Frontend `npm run check` (svelte-check + tsc) | node:22 Docker | 0 errors, 0 warnings |
| Frontend `npm run lint` | node:22 Docker | clean |
| Frontend Vitest | node:22 Docker | 522 cases across 26 files, green |
| Package upgrade tests | CI (`dist/tests/deb-upgrade.sh`, `rpm-upgrade.sh`) | the released 1.8.0 `.deb` and `.rpm` upgraded under systemd, ownership and service state asserted |
| Docker e2e, every profile | `tests-e2e-docker/run.sh --build` | section 10 |

Product tests went from 2632 at the 1.8.0 close to 3073: 2814 when Story
11.1 closed, 2881 at 11.2, 2975 at 11.4. Forked tests moved from 748 to
766. Vitest moved from 480
cases across 25 files to 522 across 26.

No schema migration this cycle: the head stays at 61, shipped in 1.8.0,
and `CANONICAL_FORMAT_VERSION` stays at 2. The new scopes are new
spellings in an existing JSON column. Two new workspace members, both on
the product line: `lorica-mcp` and `lorica-automation-policy` (33
members, 16 forked and 17 product). No new external dependency: D5 of
the PRD was resolved as a hand-rolled JSON-RPC loop rather than the
`rmcp` SDK, and every crate `lorica-mcp` uses was already in the
lockfile at its siblings' versions.

## 4. Per-story results

### 11.1 The `lorica-mcp` crate and the read tier - Done

Four lots, each ending on a tree that built and passed its gates. The
discovery that shaped the story is recorded at its head: the automation
plane had no read surface. PRD decision D3 keeps the MCP server off the
management API, so the nine read paths (`/automation/v1/logs`,
`/waf/events`, `/waf/stats`, `/sla/overview`, `/sla/routes/{id}`,
`/cluster/status`, `/backends`, `/routes`, `/certificates`) had to be
built before any tool. Every one wraps the management handler or the
function split out of it, and computes nothing of its own.

| AC | Result |
|---|---|
| #1 crate, stdio, no argv | Met. Endpoint, token and CA bundle from the environment or a named TOML file; any argument refuses the start; a malformed file reports its path, never the parser's message, which may quote the token |
| #2 five read scopes | Met. `AutomationScope::ALL` is the one list every restatement walks, and the Rust-to-TypeScript edge, guarded by nothing before, is diffed both ways |
| #3 ask before offering | Met. `whoami` became reachable by any live token through a third gate state, `ScopeRequirement::AnyLiveToken`, method-guarded, distinct from "undeclared"; the registry is built once from the token's scopes and never re-read |
| #4 read tool surface | **Met in part, by decision.** Cluster status is served, the fleet roster is not: it is the one cluster read the management API gates at `Operator`, and it names each follower's address and which node holds which private key. The maintainer was offered a projection and a dedicated scope on 2026-09-23 and refused both. Paging is capped at 200 rows and 256 KiB whatever the caller asks |
| #5 secrets never cross | Met. The sweep walks every read for credential-shaped names and PEM blocks, a second test pins each answer's field set, and since the pre-merge audit a third walks every read the router mounts against the list the first two walk |
| #6 audit | Met, with an honest split. Over stdio the node cannot observe the tool or the transport, so the row keeps what it established apart from an `asserted[...]` clause; over Streamable HTTP the tool is established |
| #7 injection hygiene | Met structurally. A tool result has two constructors, both taking bytes from outside; the fence marker grows until the payload cannot spell it, in one pass since the audit (11.36 s to 0.03 s on a hostile body) |
| #8 docs | Met: `docs/mcp.md` |
| #9 Streamable HTTP | Met. Every `Origin` refused with 403; `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` compared with the body after Base64-sentinel decoding; `-32020` on mismatch; 405 on `GET` and `DELETE`; authorization per tool call, since the endpoint cannot sit behind one scope |
| #10 one core | Met: both bindings build their server through one constructor |
| #11 revision note | Met: the crate implements 2026-07-28 and no other era, and the maintenance obligation is written down |

IV1 to IV3 are tests. IV2's HTTP half was found lying by the first
audit: every refused tool call was audited as `ok`, because the core
answered with a 200. The row now takes its outcome from the call.

### 11.2 The config tier - Done

The same discovery again: the automation plane had no write surface.
Lot 1 built eight write paths, each running the management handler's own
body (split into a wrapper and an `_as` body) with the token as the
actor. Lot 2 built the tier, after the structural change the 11.1
architecture audit had asked for: the in-process seam stopped being a
second router and became `AutomationPlane::call`, which hands the request
to the plane's own route table under its scope gate, so an MCP call over
HTTP is authorized exactly as a socket call is.

| AC | Result |
|---|---|
| #1 reverse 10.3 AC #5 | Met, with the pointer in the Epic 10 PRD (verified at its line 140) |
| #2 separate token and process | Met, made structural by Story 11.4's tier table |
| #3 diff before apply | Met. `?dry_run=true` on every write path runs the same body and stops before the store, the reload and the audit row; each mutation declared once yields its apply and `_preview` tools. `docs/mcp.md` states that a preview is an affordance, not a control: the protocol cannot make a client look first |
| #4 one named resource | Met. No selector, no bulk verb |
| #5 validation is the API's | Met. IV1 proven byte for byte in the canonical encoding, and failed against a lookalike missing one field |
| #6 no key material | Met. The sweep first walked the published schema, whose body properties are empty, and missed `mtls.ca_cert_pem`; it now walks the Rust request structs into every nested type, with a positive control |
| #7 audit and docs | Met: both rows land, the management one under the token's identity |

IV3 deviates in form. A config-tier server pointed at a follower is
refused because the automation listener refuses to start on a follower
(Epic 10), not by a per-request check, since a node becomes a follower
only through a restart. The replication half was proven nowhere until
backlog #91 added an MCP phase to the cluster profile (`a9f1d72f`).

### 11.3 The admin tier, and where it stops - Done

One scope, `settings:write`, one path, `PUT /automation/v1/settings`, one
mutation and its preview. The tier is defined by what it refuses, and the
refusal is the plane's: a body naming any key outside `SETTINGS_ALLOWLIST`
is a 403 naming the key before any value is read, whoever sends it. The
story was drafted with its central criterion deliberately empty, because
which settings a model may change is a judgement about blast radius that
belongs to the maintainer.

| AC | Result |
|---|---|
| #1 short list by exclusion | Met. Nine keys: the access-log, WAF-event and SLA retentions (raise-only, never 0, under a ceiling of ten times the default), the two certificate alert thresholds, the WAF auto-ban threshold and duration (at most a day), the health-check interval (5 to 60 s) and probe budget |
| #2 cluster mutations out | Met. Users, roles, tokens, OIDC issuers, nodes, enrolment, fleet bans, `leave` and break-glass are declared for no token on any verb, by a test derived from the management route table |
| #3 reversible from the dashboard | Met. Every key is an editable field of the settings form, which a test reads |
| #4 audit, docs, hardening guide | Met. The audit row records `key:old->new` |

IV1 asserts the tool list against the constant; IV2 proves the refusal
happens at the scope gate, so the tool does not exist to be named.

The deviation worth recording is the list itself. Eighteen keys were
decided on 2026-09-23, fifteen on 2026-09-28 (four had no dashboard field,
which made AC #3 false for them), and nine after the story's own audit
showed that "reversible" was too weak a filter: inside the validators'
bounds a steered model could trim the access log to one row within the
hour, switch flood defence or the auto-ban off, or issue a 68-year ban
that outlives the setting's revert. The maintainer's rule became safe
direction plus bounds. Three latent defects surfaced on the way and were
fixed for both planes: the stored `log_level` had never been applied, the
health loop read its interval once at spawn, and neither the interval
nor the ban duration had an upper bound.

### 11.4 Tier isolation, packaging and the operator story - Done

| AC | Result |
|---|---|
| #1 one process, one tier | Met. One tier table names, per tier, the scopes it requires, the reads it tolerates and its default lifetime; every scope is required by exactly one tier. The refusal sits in the constructor both bindings share: stdio exits 78 naming the scopes, Streamable HTTP answers 403 audited as `spans_tiers` |
| #2 packaging | Met in the `.deb`, the `.rpm`, the production image and the release binaries, and in four Dockerfiles, not the three the rule names (`ci-check.Dockerfile` is the one it omits). The unit carries a comment saying why it does not start `lorica-mcp`, and CI fails if it does |
| #3 blast radius at minting | Met. `lorica mcp token create --tier` is a front end over the existing mint route: the token alone on stdout, the tier's tools, scopes, grants and settings bounds on stderr, derived at print time from the tier table |
| #4 `mcp` e2e profile | Met: 51 assertions when it landed, 53 now |
| #5 docs | Met: `docs/mcp.md` rewritten for a first setup, the MCP actor and threat T9, the tier guidance in the hardening guide |

IV1 is tested on both bindings; IV2 is the `mcp` profile, which ends by
verifying the audit chain.

## 5. The audits

### Per-story passes

| Story | Pass | What it found and what changed |
|---|---|---|
| 11.1 | Two five-auditor sweeps (security, architecture, quality, performance, debt), each followed by a fix pass | First sweep: seven High after deduplication, nine Medium, seven Low. The log read never returned the newest row and `has_more` never went false; the fleet roster was a privilege widening and left the plane; `offset` was unclamped. Second sweep: four High, seven Medium. The HTTP binding had no invocation budget although three documents said it did; every refused call was audited `ok`; a caller could rename the tool the audit row named; a test named for a property checked nothing |
| 11.2 | One five-auditor sweep, two fix passes | One Critical (grants bound the claim, not the target, top finding 3) and one High (`forward_auth`, `mirror` and five positions of `backend_ids` aimed traffic the CIDR grant never weighed). The second pass took the Mediums and Lows a first reading had filed as decisions, and four were fixes: `mtls` could install a client-auth trust anchor, `routes:write` alone bound any certificate, `?dryrun=true` was an apply, and `[::ffff:127.0.0.1]` slipped past an IPv4 grant |
| 11.3 | Four auditors (security, architecture, quality, debt) | Security: two High and five Medium, the retention, flood and ban findings that cut the list to nine and an OIDC entry able to carry `settings:write`. Architecture: one High (two settings whose effects outlive their revert, fleet-wide), the inert `log_level` and the missing write budget, and two inputs recorded for 11.4: a typed tier with a fallible constructor, and grants that mean nothing on an admin token |
| 11.4 | Five auditors (security, penetration, quality, debt, architecture) | Pentest High: `proxy_headers` values reached every model; the `.deb` built as the runner account. Architecture High: the admin tier minted for 365 days with no ceiling; the `lorica` crate's tests never ran in CI. Security Low: the CLI password (#90). Three maintainer decisions followed, section 8 |

### The pre-merge release-wide audit

Six reports read the whole release against `main` on 2026-09-30: security, adversarial design review, architecture, quality,
performance and debt. A seventh, the penetration auditor, was blocked and
produced no report; the adversarial review covers the same attacker's
view and is the record of it. None found a way for a model, a stolen
token, a compromised pipeline or a local user to leave its tier or its
grants (the adversarial review's question 2, answered no). What they did
find was fixed in `d98b2927` and `0e489c92`, the remainder in `a9f1d72f`,
`963227a2` and `c98be2df` as backlog #91 to #95.

| Area | What the pass changed |
|---|---|
| Security | the config tier could switch Basic auth, an allowlist, the WAF or upstream TLS verification off; it may now only strengthen a protection (maintainer decision of 2026-09-30); `basic_auth_password` refused by the plane, not only withheld from the tool; a failed management bind is fatal in single-process mode; the self-signed pair is generated once per process; header-rule values masked; foreign environment names withheld from listings; budgets keyed per project |
| Adversarial (High 1, Medium 3) | a committed write whose client hung up landed with no audit row and no reload, so requests now run as tasks the connection does not own; an OIDC ID token was replayable for the minute after `exp`; `environment_protected` did not bound route deletes; a flood of cheap requests could shed a write's audit row, so a quarter of the queue is reserved |
| Architecture (High 1) | the RPM upgrade defect; a CI job upgrading the released 1.8.0 packages under systemd; the policy crate as the top leverage point, taken as #95 |
| Performance (High 3) | the log read ran a discarded `COUNT(*)` under the log-store mutex; the route listing ran one statement per route under the config lock and paged after building every view; the SLA overview computed every route before the window; plus keyset paging, Argon2 off the async worker, certificate keys no longer decrypted to be dropped |
| Quality (Medium 10) | the withheld route fields declared once; `thiserror` in `lorica-mcp`; `[Unreleased]` rewritten as the release's final state rather than a development log |
| Debt (High 3) | the read-surface secret sweep claimed derivation from the matrix and walked a hand-typed list; two Security changelog entries contradicted the code; `ci-check.Dockerfile` and the `run-tests` skill ran six of CI's fourteen product crates and ignored forked-step failures |

### The targeted final audit

Four auditors (security, adversarial, architecture, debt) read
everything that landed after the pre-merge audit, `d98b2927` to
`c98be2df`, on 2026-10-04. No Critical or High from security, adversarial
or architecture; one High from debt. Every finding listed below was
fixed in `352c184b`.

| Area | What the pass changed |
|---|---|
| Security (Medium 2, Low 5) | the wildcard and catch-all shadowing (top finding 4), now refused or inherited through `lorica_config::route_selection`, the proxy's own selection; the mutation reserve went to any authenticated non-GET request and now goes only to writes that happened; a structured `rate_limit` over a legacy `rate_limit_rps` could raise the enforced limit; a preview's `changes` keys were an equality oracle on masked values; the CLI's 1.8.0 fallback pin opened `lorica.db` read-write with migrations as root; the scriptlets ran `chown -R` over the data directory and re-enabled a disabled service |
| Adversarial (Medium 1, Low 4) | the same reserve finding; environment names still readable in `group_name` and backend names; detached request tasks escaping the connection caps |
| Architecture (Medium 4) | detached units bounded per plane, drained at shutdown and counted by `lorica_detached_request_units{plane}`; the cancellation-safe tail extended from four management handler families to every management mutation through one router layer; a masked `health_check_path` written back broke the health check; the read-only CLI fallback |
| Debt (High 1, Medium 8) | the OpenAPI scope enums claimed pinned against `AutomationScope::ALL` and read by nothing, now pinned; the listener router test compared the table with a router folded from the same table, and now drives the real router; README e2e table and binary counts; #89 decided rather than left open |

Two Info findings were left as they are, both rated speculative or
without impact: IPv4-compatible, NAT64 and 6to4 IPv6 prefixes are still
weighed as IPv6 under a `::/0` grant, which reaches IPv4 only on a host
with a tunnel or a NAT64 gateway; and a few pre-existing em dashes and
one emoji outside the range.

## 6. What a green unit suite could not see

**The `.deb` ownership.** No test could fail, because no test looked.
`dpkg-deb --build` records the real owner of every entry, the package was
built by the unprivileged runner account, and dpkg applies the recorded
owner on install, by name and then by uid. Every unit, integration and
e2e test runs against a binary, not against the ownership metadata of the
archive that carries it, and CI asserted nothing about that metadata
until this cycle. It took an auditor asking what the package actually
installs to see it, and it had shipped twenty-five times.

**The chunked WAF refusal.** Every WAF test passed, including the ones
asserting the refusal. The body filter wrote the 403 and cleared the
body; the proxy read a cleared body as end of body and wrote the closing
chunk. Each half was correct in isolation. The test origin could tell
how many bytes it read but not whether the body had ended on its own
framing, so the only test able to see the defect saw it as a race, about
one run in fifty. Once the origin reported both, the defect showed on
every run. The `lorica` crate's tests, where these live, had also never
run in CI, so even the flake could only appear locally.

**The wildcard shadowing.** Store uniqueness is right to compare exact
strings, the proxy is right to prefer an exact host over a wildcard, and
the safe-direction rule was right that a created row carries its own
protections. The defect lived in the seam between the three: a created
row is not at its weakest when another route already serves its host.
The fix makes the write guard and the proxy call one statement of route
selection, so the two can no longer disagree.

The shape is the one Epic 10 named: an absent constraint, not a wrong
behaviour, found by reasoning about the deployment rather than the
function.

## 7. Failure patterns worth naming for the next epic

**A flaky test is a report, not noise.** The cycle's most serious
product defect was found this way, and it was not alone.

- `a1b3ed28`: a refusal test raced the closing chunk one run in fifty.
  Investigating the race, rather than retrying it, found the backend
  receiving refused bodies whole.
- The AI-crawler handle: a test in the `lorica` crate failed about one
  run in three because another test module rebuilt the process-wide
  handle from a store without its row. Fixed at its cause with a
  test-only writer lock, no retry and no sleep.
- `c16db2ae`: the OIDC tamper test failed a quarter of the time because
  it altered the one base64url character of an RS256 signature that
  cannot take an arbitrary value.
- `c98be2df`: the cluster profile wrote its readiness marker before the
  management API listened; compose restarted the follower, so the phase
  passed while `run.sh` waited out its 180 s. Seen in four saved logs.
- `cd12ac16`: the load phase asserted a fixed share of the load requested
  from a generator running on the node under test, so a contended runner
  failed a healthy fleet.

Each of these was green on rerun, which is exactly why each would have
been retried.

**A guard that is claimed is not a guard that runs.** Epic 10 named code
built, unit-tested and wired to nothing. This cycle found its testing
twin.

- The `lorica` crate's tests were compiled by clippy and run by nothing
  in CI. `ci-check.Dockerfile` ran them in a step whose failures were
  ignored, and the local "CI mirrors" ran six of CI's fourteen product
  crates. Two auditors of Story 11.4, architecture and quality, found it
  independently, both at High. CI runs
  `cargo test -p lorica --features otel` now.
- The read-surface secret sweep was documented in three places as derived
  from the scope matrix and walked a hand-typed list; a read path added
  to the router would have reached a model unswept.
- The OpenAPI scope enums were described in two comments as turning red
  on a new variant; no test read them.
- The listener router test compared the route table with a router folded
  from the same table.
- From 11.1: a test named for the property that the HTTP binding asserts
  no header scanned no header.

**Masked on read, written back on write.** A field the plane masks and
the tier may write needs a write-back rule, or a read-modify-write stores
the marker. Header-rule values got one in `0e489c92`; `health_check_path`
did not, and a model copying a listed backend into an update would have
replaced a probe credential with `[redacted]` and taken the backend Down.
Both now keep the stored value when the marker comes back where it was
read, and refuse it anywhere else.

## 8. Cross-cutting findings

**Decisions the maintainer took during the cycle**, each recorded where
the work lives:

- The fleet roster stays off the automation plane; no projection, no
  operator-equivalent scope (2026-09-23).
- D5: a hand-rolled JSON-RPC loop rather than `rmcp` (2026-09-22).
- `lorica mcp token create --tier` is a thin front end over the existing
  mint path (2026-09-23).
- The admin allowlist reshaped twice, ending at nine keys each with a
  bound and a safe direction (2026-09-28), and the health interval bound
  tightened on review to 5 to 60 s.
- Hostname and CIDR grants are typed absence: required, non-empty, for a
  token carrying a scope a grant bounds, refused otherwise; stored rows
  load as they are (2026-09-30).
- Per-tier default lifetimes (90, 7 and 1 days) and a node-side ceiling of
  7 days on any token carrying `settings:write`, whichever surface mints
  it; a mint naming no lifetime is refused rather than silently clamped
  (2026-09-30).
- A grant-bearing token's route, backend and certificate listings answer
  only rows inside its grants (2026-09-30).
- Query-string values masked on the automation log read, although the
  check showed the proxy logs the path alone and the premise was false
  (2026-09-30).
- Safe direction only for the config tier's route and backend
  protections (2026-09-30).
- Deleting a protected route and creating it again accepted as a residual
  and recorded as #93 rather than closed by a rule that would make delete
  close to useless for the tier.
- An environment route inherits the protections of every route it
  displaces, control by control (2026-10-04).
- The policy extracted into `lorica-automation-policy`, a crate of pure
  data whose one dependency is `serde`, so `lorica-mcp` reads the tier
  table, the allowlist and the protection rules without linking SQLite
  (#95).
- #89: the dashboard writes the six settings only an import could set,
  and none joins the admin allowlist (2026-10-04).

**Deviations from the PRD, each written down before or with the code.**
AC #4 of 11.1 served in part. `whoami` stops requiring a scope, the one
change 11.1 makes to the Story 10.3 gate. IV3's follower refusal is the
listener's startup refusal. A preview is an affordance, not a control,
because the protocol cannot make a client look first. Packaging touches
four Dockerfiles, not three. And the config tier reaches further than the
PRD's "routes, backends, certificates" in one respect and less far in
another: the plane refuses `forward_auth`, `mirror`, `mtls`,
`proxy_headers` and the Basic-auth password from any token, because a
model reading attacker text could aim traffic or replace a trust anchor
through each.

**Honest guarantees, stated where an operator reads them.** Tier
isolation is a boundary against a steered model, not against a token
thief who can mint three sessions. A stdio refusal happens in the
client-side binary and leaves no node audit row, so the hardening guide
splits its alerts by binding. A client with Docker access and a shell
tool is outside the tier model, and `docs/mcp.md` puts a version-matched
`lorica-mcp` on the client's own host first. The CLI pin covers the CLI;
a browser that accepts a certificate warning is outside it, and the
hardening guide gives the fingerprint to compare.

**Mixed-version safety.** No migration, so the upgrade touches no
schema. A token minted on 1.9.0 with a
new scope is refused by a 1.8.0 node, which the changelog says. The CLI
reaches a running 1.8.0 node for a hot upgrade by pinning the certificate
that node serves, read through a read-only connection that runs no
migration. Environment writes are budgeted for the first time, 100 a
minute per credential, which a 1.8.0 pipeline could notice; the changelog
says so under Changed.

## 9. Data plane

The PRD said no story in this epic touches `request_filter`, and no
Epic 11 story does. The WAF fixes do, and they are release defects
rather than epic scope: in Blocking mode an inspectable body is now read
and scanned in `request_filter` before the upstream is dialled, the scan
buffer itself holding it, bounded by the route's scan window and the
node-wide scan budget. Measured on loopback, a clean 1 MiB body costs
28.1 ms held against 28.5 ms streamed. `lorica-proxy` gains one
divergence from upstream, recorded in `FORK.md`. Detection mode and
bodies the WAF does not inspect stream as before.

## 10. The end-to-end suite this cycle

The full suite ran on HEAD `352c184b` with `./run.sh --build`, every
profile on, and ended on
`=== ALL E2E TESTS PASSED ===` with zero failures in every phase.

| Phase | Assertions | Failed |
|---|---|---|
| base (single-process) | 361 | 0 |
| workers | 90 | 0 |
| cert-export | 39 | 0 |
| ai-bot, ai-bot-workers | 52, 49 | 0 |
| rbac, rbac-workers | 37, 37 | 0 |
| audit | 17 | 0 |
| hot-upgrade | 29 | 0 |
| log-sinks | 23 | 0 |
| acme | 15 | 0 |
| capture | 163 | 0 |
| capture-workers | 160 + 50 | 0 |
| mcp (new, Story 11.4) | 53 | 0 |
| cluster | 66 | 0 |
| cluster restart | 6 and 9 | 0 |
| automation | 104 | 0 |
| cluster mcp phase (new, backlog #91) | 13 | 0 |
| revocation | 7 | 0 |

`Fleet is ready.` printed before the cluster phase, and the 180 s
`the fleet did not form` error appears nowhere in the log: the readiness
marker fix in `c98be2df` holds, where four earlier logs show the suite
waiting out its timeout while the phase still passed. One `ERROR` line
appears in the automation phase, `automation listener failed to start`
on a follower, and it is the refusal that phase asserts, not a failure.
One cosmetic oddity is pre-existing and recorded rather than hidden: the
workers phase prints `Results: 90 passed, 0 failed (80 total)`, its
total counter disagreeing with its pass counter.

What the run adds over the 1.8.0 close is the first end-to-end exercise
of the MCP surface. Through Story 11.3 the suite passed at the same
count it had before any Epic 11 code existed (553 on the subset run
during 11.1 and 11.2), which proved nothing broke and covered nothing
new. The `mcp` profile drives every tier over stdio through the real
`lorica-mcp` binary and the real `--tier` minting command, and the
cluster MCP phase proves a config-tier write replicates. Outside the
Docker suite, the WAF refusal tests in the `lorica` crate's end-to-end
binaries (`lorica/tests/waf_body_inspection_e2e_test.rs`) now assert the origin was never contacted, for
Content-Length and chunked bodies, at end of stream and at the scan
window; disabling the hold fails ten of them.

## 11. Backlog movement

Raised and resolved in this cycle: #90 (the CLI password), #91 (11.2
IV3's replication half), #92 (the Epic 11 leftovers: the trace span, the
dashboard tier hint, the shared e2e helper, the cheaper MCP answer), #94
(the pre-merge findings on the automation plane, eight items), #95 (the
policy crate). Raised during Story 11.3 and resolved on 2026-10-04: #89.
Raised and left open by decision: #93.

The Open table holds sixteen entries: fifteen that predate the cycle
(#14, 15, 52, 53, 64, 70, 72, 75, 79, 81, 82, 83, 84, 85, 86) and #93.
#52, the `lorica-fleet` extraction, was re-deferred at this close as at
the last one, and its entry says so.

## 12. Residual risks accepted

- **#93, delete then recreate.** A token that may delete a route inside
  its grant may create it again without its protections: two audited
  rows, `route.delete` then `route.create`. `docs/mcp.md` and the threat
  model state it: a hostname whose protections no model may remove
  belongs in no config-tier grant.
- **Bytes past the scan budget stream unscanned.** When the node-wide WAF
  scan budget refuses a body mid-read, the prefix read so far is
  forwarded and the rest streams unscanned, counted as `skipped_budget`.
  Failing closed would let any client turn the shared budget into a 413
  for everyone else; the reasoning is in `docs/security.md` and the
  threat model.
- **The fifteen pre-cycle backlog entries**, none of them a defect this
  cycle introduced: upstream tracking (#14, #15, #81, #83), measurements
  owed (#64, #70, #75, #79), the fleet audit bounds and signed checkpoints
  (#72, #84), CA key protection (#85), multipart inspection (#86), the
  downstream idle timeout (#82), the log-sink follow-ups (#53) and the
  `lorica-fleet` extraction (#52).

## 13. Recommendations

- **Immediate:** bump to 1.9.0 as its own commit, keeping the untracked
  advisory draft out of it. Publish the `.deb` ownership advisory with
  the release, with the `stat` check from the changelog and the instruction
  to inspect `/lib/systemd/system` for foreign units before upgrading.
- **Operator spot-checks:** one session per tier from a real MCP client
  over both transports; the dashboard's tier hint on the token form; an
  RPM and a `.deb` upgrade on a host where the service was deliberately
  stopped; a chunked SQLi body against a Blocking-mode route with a
  packet capture on the backend side.
- **Next cycle:** #52 should be the first extraction of whichever cycle
  takes one, in one move. Keep the local CI mirrors derived from
  `ci.yml` rather than transcribed, since that is the failure that hid
  the `lorica` crate's tests.
