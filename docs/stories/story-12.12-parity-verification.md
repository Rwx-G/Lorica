# Story 12.12: Parity Verification

**Epic:** [Epic 12 - TCP and UDP Stream Proxying (v1.11.0 and v1.12.0)](../prd/epic-12-v1.11.0.md)
**Status:** InProgress
**Priority:** P0
**Author:** Romain G.
**Verified on:** `feat/v1.11.0` at `6e460a61` (2026-11-18). No stream
e2e Lot of Stories 12.2 to 12.11 has landed: `tests-e2e-docker/` holds
no `streams` profile, no `run-streams-*.sh` and none of the approved
runner additions yet.
**Depends on:**
- Stories 12.1 to 12.11, each for the scenarios its Integration
  Verifications name. Each scenario Lot below names the Lots of the
  story it waits for. 12.0, 12.1 and 12.7 are in Review; the others are
  InProgress.
- The released 1.10.7 package (PR #57, `main`), as the NFR1 baseline
  and the rollback target.
- The artefacts of D-p, approved on 2026-11-18 (Resolved 1 to 3); Lot
  A pins them and records every digest and checksum (AC #6).

**Blocks:** the 1.11.0 release (Phase 1 ends when IV1 below passes) and
therefore every Phase 2 story, which starts from the head released here.

---

As the maintainer,
I want parity proven end to end and measured against nginx on the same machine,
so that "on a par" is a measured claim before Phase 2 starts.

## Problem

Eleven stories each wrote Integration Verifications, and nine of them
planned an e2e Lot of their own, all on one `streams` profile, one
compose file and one `run.sh`, each assuming the previous one landed.
Several of those Lots use standard-library stand-ins and hand the real
form to this story (PostgreSQL for 12.3 IV1, a DNS resolver and a DNS
load generator for 12.5 IV2, a frozen Redis for 12.7 IV1, the real
1.10.7 binary for 12.1 AC #3). None has landed. Built separately, they
would be nine sequential edits of shared files, half of them written
twice (stand-in first, real image later), and still no single place that
says which IV passed.

There is also no measurement. The PRD's parity claim and NFR1 and NFR4
are ratios against nginx and against 1.10.7, and nothing in the
repository produces a ratio: `lorica-bench` is Lorica's own SLA and
load-test feature, the `bench/` directory drives one proxy with an
unpinned `oha`, and the CI e2e job (43 minutes on the last green `main`
run, 2026-11-16) has no performance step.

This story builds the L4 phase that runs every IV as a named scenario,
the performance phase that compares Lorica with nginx `stream` and with
1.10.7, and the CI and local procedures that gate the release on them.

## Acceptance Criteria

These are the PRD's, unchanged. They are the contract.

1. **An L4 phase in `tests-e2e-docker/`** with real backends, running every Integration Verification of Stories 12.1 to 12.11 as its own named scenario, plus the fd-reserve scenario (filling UDP sessions to the ceiling leaves HTTP accept unaffected).
2. **A performance phase** runs nginx `stream` (pinned version) and Lorica in the same compose, alternately, against the same backends, comparing **ratios, never absolute numbers**. The load generator, the proxy under test and the backends are pinned to disjoint `cpuset`s, and both proxies get the same core count. Each measurement is repeated at least 5 times per proxy, alternating; the phase reports median and spread, and proxy CPU per GiB forwarded. This harness is separate from `lorica-bench`, which is Lorica's SLA and load-test feature.
   - TCP passthrough: Lorica median throughput at least 0.90 x the nginx median, and Lorica CPU per GiB at most 1.15 x nginx.
   - Connection setup: Lorica p99 accept-to-backend-connect latency at most 1.5 x the nginx p99, for non-TLS streams.
   - UDP: at a fixed session count equal to 80 % of Lorica's derived ceiling, both proxies hold every session with no loss and no premature eviction; Lorica's resident memory per 1,000 sessions is reported.
3. **Inconclusive is not a pass.** A result whose spread exceeds 5 % of its median is re-run, at most 3 times; still inconclusive, it blocks the release pending an owner decision.
4. **NFR1 by the same method**: HTTP throughput and p99 against the 1.10.7 binary in the same run, with and without one idle stream configured, held to the NFR1 thresholds (0.95 x throughput, 1.05 x p99).
5. **Gating.** The performance phase gates the local release run, which has the machine to itself as the e2e suite already requires. In CI it runs and publishes its numbers in the job summary without gating, because shared runners are too noisy for these ratios. That includes the release pipeline, which since 1.10.4 waits for the e2e suite: there the performance phase is a step whose failure does not hold the release, while the L4 phase gates it like every other e2e phase.
6. **New test artefacts are named and approved at the start of this story**: the nginx image and version, a TCP load generator, a DNS load generator, and the PostgreSQL, DNS resolver, SSH and TLS echo backend images.
7. Every existing e2e profile passes unchanged.

## Integration Verification

- IV1: The local release run of the full e2e suite, including the L4 and performance phases, passes on the Phase 1 head, which is released as 1.11.0. Phase 2 starts from that release.

## What the suite does today

Verified on `6e460a61`.

- **`tests-e2e-docker/run.sh`** runs phases in sequence, each guarded by
  `[ "$EXIT_CODE" = "0" ]`, so a failing phase short-circuits every later
  one. Each profile has a `--skip-<name>` flag (default on) and joins
  `ALL_PROFILES`, which `--build` and the final `down -v` pass so that
  profile-gated images are rebuilt and their volumes removed.
  `dump_node_log` prints a node's log when a smoke fails. Phase 1
  (single process) is not skippable.
- **Compose**: one `docker-compose.yml` (1,717 lines), one network
  `e2e`, Lorica images built from `tests-e2e-docker/Dockerfile`
  (`rust:1-bookworm` builder, `debian:bookworm-slim` runtime, `--release`
  with optional `LORICA_FEATURES`). The builder does not copy
  `rust-toolchain.toml`, so the e2e binary is built by whatever stable
  `rust:1-bookworm` carries, not by the pinned 1.99.1 the release uses
  (`build-binaries` on `almalinux:9`).
- **Runner**: `test-runner/Dockerfile`, `alpine:3.20` with `bash curl jq
  openssl python3 socat sqlite`, scripts copied by name. Smokes run as
  `docker compose run --rm <smoke>` inside the compose network; anything
  that needs Docker itself (stop, kill, a throwaway container on a data
  volume) is done by `run.sh` between runner invocations (the cluster
  automation phase is the model).
- **Third-party images** are pinned by tag only (`pebble:2.8.0`,
  `jaegertracing/all-in-one:1.60`,
  `otel/opentelemetry-collector-contrib:0.111.0`), and one is not pinned
  at all (`strm/dnsmasq:latest`, `rdns` profile). The Redis approval of
  Story 12.7 (by digest) is the first digest pin of the suite.
- **Approved this cycle, not yet added**: `iproute2` in the runner
  (12.2 Lot H), `openssh-server` in a new `ssh-backend` image and
  `openssh-client` in the runner (12.11 Resolved 4), the official `redis`
  image by digest (12.7 Resolved 6), Python standard-library tools in the
  runner (12.3, 12.4, 12.5, 12.6 Lots).
- **CI**: `e2e-docker` runs `./run.sh --build` with a 90-minute timeout,
  on pull requests to `main` and on `main` and tag pushes. Since 1.10.4,
  `verify-tag` needs `e2e-docker` and `adcs-harness`, and `release`
  needs `verify-tag`, so a release waits for the suite. The last green
  `main` run took 43 minutes for `E2E (Docker)`, build included.
- **Machine alone**: the suite shares one compose project name and is
  timing-sensitive (cluster formation, load assertions). A leftover run
  or a concurrent cargo build produces failures that look like product
  defects (project memory, 2026-09-22).
- **1.10.7 on Debian 12**: the binaries published for 1.10.1 to 1.10.3
  need glibc 2.38; from 1.10.4 the `run-on-oldest` job proves each
  release starts on `debian:12`, the base of the e2e runtime image.
  Release assets are `lorica_<v>_amd64.deb` with a detached `.asc`,
  verified by `test-deb-upgrade` with `gpgv` against
  `docs/lorica-signing-key.asc`.

## Decisions taken in this story

### D-a. One L4 phase, built here; the stories' e2e Lots move into it

The nine planned e2e Lots (12.2 H, 12.3 G, 12.4 H, 12.5 I, 12.6 I, 12.8
G, 12.9 J, 12.10 H, 12.11 G) are **implemented as Lots of this story**,
in one harness, not separately. Their checklists stay the specification
of their scenarios: each 12.12 scenario Lot below implements the
corresponding story Lot's items, word for word where they still apply,
and replaces a stand-in by the approved real artefact where this story
was handed the real form.

How a story closes: its e2e Lot heading in its own file gains the line
"Delivered by Story 12.12 Lot X" when Lot A lands, and its checkboxes are
ticked when that 12.12 Lot passes. A story moves to Review only once
its scenarios pass, exactly as before; what changes is who writes the
files and that they are written once.

*Why:* the e2e Lots are sequential anyway (each needs the machine alone
and all edit the same compose file), the stand-ins of 12.5 and 12.3 would
otherwise be written and then replaced, and AC #1 needs one registry of
named scenarios that a single report can check.
*Cost:* the e2e proof of a story now depends on this story's Lot A
landing first, so Lot A is the first thing to do, before any other e2e
work of the cycle.

### D-b. Topology: two compose projects of their own, plus stream sections where an IV needs an existing topology

- **`docker-compose.l4.yml`**, compose project `lorica-e2e-l4`, holds the
  profiles `streams` (one node, `--workers 2`) and `streams-single`
  (single process), with their backends, clients and probes. A separate
  file and project keep the L4 Lots from serialising against other
  stories' edits of `docker-compose.yml`, keep teardown independent
  (`down -v --remove-orphans` per project), and keep `ALL_PROFILES`
  unchanged.
- **`docker-compose.perf.yml`**, project `lorica-e2e-perf`, holds the
  performance phase (D-i).
- **Stream sections inside existing profiles**, appended after their
  current assertions, where the IV needs a topology the suite already
  builds: `cluster` (12.1 IV1, IV2; 12.4 key replication), `acme` (12.4
  IV2), `hot-upgrade` (12.11 IV1 and its three scenarios; 12.1 hot
  rollback), `mcp` (12.10 IV1; 12.7 IV2), `geoip` and `workers` (12.8,
  HTTP listeners). Building a second three-node fleet or a second Pebble
  for L4 alone would double the suite's slowest boots for nothing.
- Both new compose files build the Lorica image from the same
  `tests-e2e-docker/Dockerfile` under one image name, so a run builds it
  once.

Inside the `streams` profiles, two runners: **`streams-probe`** shares
the node's network and pid namespaces (`network_mode` and `pid` set to
`service:<node>`, as 12.2 Lot H planned) for `ss`, the squatter process
and killing a worker; **`streams-client`** has its own addresses on the
`l4` network and on `streams-geo` (subnet `214.78.120.0/24`, 12.6 Lot I),
because every source-address scenario breaks if the client shares the
node's namespace (its connections would come from loopback).

### D-c. A host-side driver, in-container tools, one registry, one report

- **Driver**: `tests-e2e-docker/l4/run-l4.sh`, run by `run.sh` on the
  host, owns everything that needs Docker: start, stop, `kill` (12.3
  IV1), `pause` and `unpause` (12.7 IV1), a throwaway container on a data
  volume (12.1 rollback), reading a container's cgroup (D-j). It sources
  one file per story, `tests-e2e-docker/l4/scenarios/12.N.sh`, each
  defining one shell function per scenario.
- **Tools**: everything that sends traffic or measures time runs inside
  a container (`docker compose exec -T streams-client ...`), from Python
  standard-library tools under `tests-e2e-docker/test-runner/l4/` (the
  runner image's build context) or from the approved images. **Every
  timed assertion runs inside one in-container command**, timer
  included: a `docker compose exec` costs 100 to 300 ms on Docker
  Desktop, which would eat a 5 s budget.
- **Scenario contract**: every scenario, wherever it runs (driver,
  in-container smoke of an existing profile), prints exactly one line
  `L4-SCENARIO <name> <PASS|FAIL|PARTIAL> <one-line detail>`. `run.sh`
  tees every phase's output to `tests-e2e-docker/results/e2e-<ts>.log`
  (new directory, git-ignored).
- **Registry**: `tests-e2e-docker/l4/scenarios.tsv`, one row per
  scenario of D-d (name, source IV or AC, story, profile, automation
  level, parity-matrix rows it proves). Lot A writes every row of D-d at
  once, so later Lots never edit it except to correct a row.
- **Report**: `tests-e2e-docker/l4/report.py` (standard library, run in
  the runner image) reads the log and the registry and fails the phase
  when any registry row for a profile that ran has no line, more than
  one line, or `FAIL`. A scenario that silently did not run is a
  failure, not a pass. It prints the scenario table and the parity
  matrix (D-e) and writes them as Markdown for the CI job summary.
- **Naming**: `<story>-<kind>-<slug>`, lowercase, kind one of `iv<n>`
  (a PRD IV), `ac<n>` (an AC check a story's e2e Lot planned), `x` (a
  named scenario a story planned beyond its IVs), `matrix` (D-e). Names
  a story already chose are kept (12.11's four).
- **Flags**: `run.sh` gains `--skip-l4`, `--skip-perf`, `--only-l4`,
  `--only-perf` (skip every pre-existing phase, Phase 1 included) and
  `--perf-advisory` (D-m). The stream sections inside existing profiles
  are skipped with their profile.

### D-d. Every IV mapped to a scenario

"full": the IV is asserted as written. "partial": the part named in the
note is not automated, and the report prints `PARTIAL` with that note,
which counts as a pass for gating and is listed in the release run's
Completion Notes. No IV is left without a scenario.

| Scenario | Source | Profile | Level | Notes |
|---|---|---|---|---|
| `12.1-iv1-targeted-stream-binds-on-one-node` | 12.1 IV1 | `cluster` | full | Selector `["edge-a"]`; each node's own `GET /api/v1/streams`: listed on `edge-a`, absent on `edge-b`, held on the control plane; a TCP connect from the runner succeeds on `edge-a` only (the external truth, no `ss` in the node image). |
| `12.1-iv2-follower-https-port-refused` | 12.1 IV2 | `cluster` | full | 409 naming the follower. |
| `12.1-ac3-rollback-cold-1.10.7` | 12.1 AC #3, handed | `streams-single` | full | D-h. |
| `12.1-ac3-rollback-hot-1.10.7` | 12.1 AC #3 | `hot-upgrade` | full | D-h; gated on a clean, documented result (Resolved 7). |
| `12.2-iv1-bind-and-release-within-5s` | 12.2 IV1 | `streams`, `streams-single` | full | 12.2 Lot H item, HTTP loop zero failures. |
| `12.2-iv2-port-in-use-fails-cleanly` | 12.2 IV2 | `streams`, `streams-single` | full | Squatter in `streams-probe`. |
| `12.2-ac3-privileged-port-853` | 12.2 AC #3 | `streams` | partial | Ambient capability set by `setpriv` as systemd would; the real unit is not booted in e2e (the package jobs boot it, without streams). |
| `12.2-ac1-udp-group-survives-worker-respawn` | 12.2 Lot H | `streams` | full | |
| `12.2-ac1-dual-stack-conflict` | 12.2 Lot H | `streams` | full | Needs IPv6 on the `l4` network (`enable_ipv6`). |
| `12.2-ac7-stop-drains-then-exits` | 12.2 Lot H | `streams`, `streams-single` | full | |
| `12.2-ac5-budget-refuses-range` | 12.2 Lot H | `streams` | full | `ulimits: nofile` 4,096 on a dedicated node service. |
| `12.12-fd-reserve-http-unaffected` | 12.12 AC #1 | `streams` | full | D-f. |
| `12.3-iv1-pg-balance-and-failover` | 12.3 IV1, handed | `streams` | full | Three PostgreSQL backends, `psql` from a `pg-client` service of the same image; per algorithm as 12.3 Lot G planned (peak EWMA reported, not asserted: its choice depends on latencies the test does not control); `docker compose kill` of one backend by the driver. |
| `12.3-iv2-shared-backend-down-both-planes` | 12.3 IV2 | `streams` | full | |
| `12.3-iv3-proxy-v2-send-and-accept` | 12.3 IV3 | `streams` | full | Adds the trusted-accept case 12.3 Lot G left out (the carried address reaches the record and a v2 send). |
| `12.3-iv4-local-backend-refused-and-rebind-excluded` | 12.3 IV4 | `streams` | partial | Second half through the approved DNS image with a reloaded zone; if Docker's embedded DNS does not forward the TTL, the half is proved by 12.3 Lot D2's hickory test, as 12.3 Lot G already allowed. |
| `12.4-iv1-sni-passthrough-two-names` | 12.4 IV1 | `streams` | full | Plus one ALPN-routed name (matrix row "ALPN routing"). |
| `12.4-iv2-acme-renewal-on-terminating-stream` | 12.4 IV2 | `acme` | partial only if renewal cannot be forced | Falls back to the store write the renewal performs (12.4 Lot H). |
| `12.4-ac5-two-cas-two-streams` | 12.4 Lot H | `streams` | full | |
| `12.4-ac4-upstream-mtls` | 12.4 Lot H | `streams` | full | TLS backend: `openssl s_server` from the runner's existing `openssl`, and the Python `ssl` backend of 12.4 Lot H. |
| `12.4-x-key-replication-targeted` | 12.4 Lot H | `cluster` | full | |
| `12.5-iv1-reflection-bounded` | 12.5 IV1 | `streams` | full | Stand-ins are the real thing here: spoofer (`NET_RAW`), victim, amplifying backend (12.5 Lot I). |
| `12.5-ac2-byte-bound` | 12.5 Lot I | `streams` | full | |
| `12.5-ac5-table-isolation` | 12.5 Lot I | `streams` | full | |
| `12.5-iv2-dns-above-capacity-all-answered` | 12.5 IV2, handed | `streams` | full | Two instances of the approved DNS server, `dnsperf` at twice the capacity formula across 64 source ports for 60 s; zero lost queries, zero refusals. |
| `12.5-x-reply-source-address` | 12.5 Lot I | `streams` | full | |
| `12.5-x-worker-death-no-leaked-count` | 12.5 Lot I | `streams` | full | |
| `12.5-ac6-budget-refuses-second-stream` | 12.5 Lot I | `streams` | full | |
| `12.6-iv1-source-rate-refused-other-served` | 12.6 IV1 | `streams` | full | |
| `12.6-iv2-geo-deny-tcp-and-udp` | 12.6 IV2 | `streams` | full | `streams-geo` network, GeoIP test database. |
| `12.6-iv3-10k-silent-pending-cap` | 12.6 IV3 | `streams` | full | 10,000 connections is the IV's scale; there is no separate "security phase" (Resolved 11). |
| `12.7-iv1-redis-paused-marked-down` | 12.7 IV1, handed | `streams` | full | `docker pause` by the driver; also records what Redis and PostgreSQL log per probe. |
| `12.7-x-smtp-banner-template` | 12.7 AC #3 (Resolved 4) | `streams` | full | Standard-library banner server, answering and hanging variants; no Postfix image. |
| `12.7-iv2-template-yes-payload-no` | 12.7 IV2 | `mcp` | full | Automation API and MCP config tier, real binary. |
| `12.8-iv1-proxy-v2-https-real-client` | 12.8 IV1 | `geoip` | full | The Python client stands in for the L4 load balancer (12.8 Lot G, no HAProxy image). |
| `12.8-iv2-untrusted-and-forged-xff` | 12.8 IV2 | `geoip`, `workers` | full | |
| `12.8-iv3-proxy-off-suite-unchanged` | 12.8 IV3, AC #7 | every pre-existing profile | partial | The run is automated; "unchanged" is a review of `git diff v1.10.7 -- tests-e2e-docker/` listing every modified pre-existing assertion with its reason (Lot O). |
| `12.9-iv1-end-reasons-in-api-and-syslog` | 12.9 IV1 | `streams` | partial | Asserted in `GET /api/v1/stream-logs` (what the dashboard reads) and in the syslog collector; the dashboard's rendering is not automated (no browser in the suite). |
| `12.9-x-metrics-and-sink-up` | 12.9 Lot J | `streams` | full | |
| `12.9-x-stream-sla` | 12.9 Lot J | `streams` | full | |
| `12.10-iv1-dashboard-stream-visible-read-only` | 12.10 IV1 | `mcp` | partial | "From the dashboard" is the request body the form sends (12.10 Lot D2 fixture), not a browser click. |
| `12.11-iv1-stream-ssh-drained-by-upgrade` | 12.11 IV1 | `hot-upgrade` | full | Name kept from 12.11 Lot G. |
| `12.11-x-stream-new-connection-after-upgrade` | 12.11 Lot G | `hot-upgrade` | full | |
| `12.11-x-udp-across-upgrade` | 12.11 Lot G | `hot-upgrade` | full | |
| `12.11-x-fd-transfer-past-32` | 12.11 Lot G | `hot-upgrade` | full | |

Story 12.0's IV is a parser behaviour proved by its Vitest suite and is
outside AC #1's range (12.1 to 12.11).

### D-e. The parity matrix, and the rows no IV proves

Stories 12.9 and 12.10 hand "the parity matrix rows" to this story. The
report prints every P1 row of the PRD's coverage matrix with the
scenarios that prove it. Rows no IV covers get a small `matrix` scenario
where an e2e check is cheap (each under a minute), or cite the unit or
integration test that proves them, marked "not e2e":

| Row | Proved by |
|---|---|
| Backup backends | `12.3-matrix-backup-backends` |
| Bandwidth limit | `12.3-matrix-bandwidth` (64 KiB at 16 KiB/s each way) |
| Timeouts connect / idle / total | `12.3-matrix-timeouts`; UDP idle in `12.5-matrix-udp-idle-timeout` |
| Chosen source address | `12.3-matrix-proxy-bind` (second address on the node, backend reports the peer) |
| Port ranges | `12.3-matrix-port-range` (port N to backend port N on a 16-port range) |
| Connection limit per source, per listener, per backend | `12.6-matrix-concurrency-caps` |
| Latency-aware selection | not e2e: 12.3 Lot D1 selection tests |
| Backend TCP keepalive | not e2e: 12.3 Lot C socket-option test |

Every other P1 row maps to a D-d scenario; the registry carries the
mapping. Rows marked P2 are out of scope.

### D-f. The fd-reserve scenario

`12.12-fd-reserve-http-unaffected`, on a dedicated `streams` node with
`ulimits: nofile` 8,192 so the UDP ceiling is bound by the fd budget,
not by ephemeral ports:

1. Read the node's budget view (12.2 AC #5): process fd limit, HTTP
   reserve `R`, derived UDP ceiling `C`.
2. A UDP stream whose session cap is the whole ceiling, per-source caps
   lifted for the test client, a backend that echoes once.
3. `udp_hold.py` (D-j) opens `C + 10 %` sessions from one client address
   and keeps them alive.
4. Throughout, an HTTP loop opens a new TCP connection per request
   (no keep-alive, so accept is exercised) at 50 requests per second,
   and a second client holds `R - 64` concurrent keep-alive HTTP
   connections opened after the fill.
5. Assert: the sessions above `C` are refused with the ceiling's reason
   and counted; every HTTP request succeeds; every held HTTP connection
   was accepted and answers; no `EMFILE` or `accept` error in the node's
   log.

### D-g. The 1.10.7 binary: the released package, verified, on the e2e base image

`tests-e2e-docker/baseline/Dockerfile` (new), `FROM debian:bookworm-slim`
by digest, downloads `lorica_1.10.7_amd64.deb` and its `.asc` from the
v1.10.7 GitHub release, verifies them with `gpgv` against
`docs/lorica-signing-key.asc` exactly as `test-deb-upgrade` does, and
extracts the binary with `dpkg-deb -x` (the path `dpkg-deb -c` lists).
The version is a build argument, `LORICA_BASELINE_VERSION=1.10.7`.

*Why the released package and not a build from the tag:* NFR1 is about
what an operator regresses from, which is the shipped, signed binary;
a build from the tag would add a second full Rust build (15 to 25
minutes per run) and measure a binary nobody runs. Debian 12's glibc is
enough: 1.10.4 onward start on `debian:12` (`run-on-oldest`).
*Cost:* the build needs GitHub reachable; it already needs Docker Hub
and GHCR.

**Build parity for 1.11.0.** The e2e builder stage gains
`COPY rust-toolchain.toml`, so the 1.11.0 binary under test is built by
the pinned toolchain the release uses (1.99.1 today), not by whatever
`rust:1-bookworm` carries. Both binaries then run on the same runtime
glibc of the same image base. What remains different is the C compiler
that built the crypto library (AlmaLinux 9 for the release, Debian 12
for the e2e image), which is why NFR1 gates on the plain HTTP listener
(D-l). The change affects every profile's build, not its assertions.

### D-h. The rollback scenarios

**`12.1-ac3-rollback-cold-1.10.7`** (the scenario Story 12.1 handed,
gating). On the `streams-single` node's data volume, after 1.11.0 has
migrated it and holds a stream, its links, a backend with
`Http{/h}` and a backend with a typed kind 1.10.7 cannot express
(send/expect, from 12.7): the driver stops the node and runs the
baseline image on the same volume. Assert: 1.10.7 starts, applies no
migration (`schema_migrations` unchanged), serves an HTTP route, and its
API lists both backends. Through 1.10.7's API, edit the first backend's
path to `/x` and clear nothing else. Stop, start 1.11.0 on the volume.
Assert the D-2 matrix of Story 12.1: the first backend reads
`Http{/x}`; the send/expect backend reads its typed kind unchanged; the
stream and its links are intact and the stream binds again.

**`12.1-ac3-rollback-hot-1.10.7`** (Resolved 7, gating). In the
`hot-upgrade` profile, after the 12.11 scenarios: upload the 1.10.7
binary as an upgrade (signed with the test key the smoke already uses)
while one TCP stream exists. This is the rollback
`docs/hot-upgrade.md` describes. 1.10.7 knows nothing of stream fds in
the handoff; whether it ignores them, refuses the handoff cleanly, or
fails is not known today. The scenario records which, and `docs/hot-upgrade.md`
states it.

### D-i. The performance phase: topology

Compose project `lorica-e2e-perf`, `docker-compose.perf.yml`:

| Service | Image | cpuset | Role |
|---|---|---|---|
| `perf-lorica` | e2e Lorica image (1.11.0) | proxy | `--workers N` |
| `perf-lorica-baseline` | baseline image (1.10.7) | proxy | `--workers N` |
| `perf-nginx` | approved nginx | proxy | `worker_processes N`, `stream {}` |
| `perf-backend` | `perf-tools` | backends | `iperf3 -s`, connect-latency backend, UDP echo |
| `perf-backend-http` | approved nginx | backends | static 200 with a fixed 1 KiB body, the NFR1 upstream |
| `perf-client` | `perf-tools` | load | `iperf3`, `oha`, Python tools |

- **cpusets** are derived from the CPU count Docker reports
  (`docker info --format '{{.NCPU}}'`): with 8 or more, proxy `2-3`,
  load `4-5`, backends `6-7` (0 and 1 left to the Docker daemon and the
  idle containers); with 4 to 7, proxy `1`, load `2`, backends `3`;
  with fewer than 4 the phase reports `NOT-RUN`. **N is the proxy
  cpuset's size**, for all three proxies. Lorica runs in worker mode:
  its stream runtime has one thread per process (12.3 Pitfalls), so a
  single-process Lorica would get one core against nginx's N.
- **The release machine** reports 24 CPUs to Docker (Resolved 13): the
  8-CPU minimum is met and the release run uses the larger layout
  (proxy `2-3`, load `4-5`, backends `6-7`, `N = 2`). The other 16 CPUs
  stay unassigned, so the layout and its ratios are the same as on any
  8-CPU machine.
- **All proxies stay up; the load alternates.** An idle proxy on the
  shared proxy cpuset costs nothing measurable, and not restarting
  containers between runs removes warm-up from the comparison.
- **Equivalent configuration.** Same backends, round robin over one
  backend, same connect and idle timeouts, 16 KiB buffers on both sides
  (nginx's `proxy_buffer_size` default, Lorica's fixed per-direction
  buffer), no splice on either (nginx `stream` copies too). Both log one
  row per connection with their default mechanism; nginx's `access_log`
  in `stream` goes to a file with `buffer=32k`, since Lorica's writer is
  asynchronous. `ulimits: nofile` 65,536 on every proxy, so the UDP
  ceiling is bound by ephemeral ports, not fds. nginx's configuration
  file is in the repository (`perf/nginx-stream.conf`); Lorica's streams
  and route are created by the driver through the management API.
- **Environment guard.** Before the first measurement the driver records
  `docker info` (CPU count, memory, kernel, Docker version), the image
  digests, the Lorica commit and the cpusets, and checks that no
  container outside the perf project is running. A foreign container
  makes every verdict `INCONCLUSIVE (environment)`.

### D-j. The measurements

Each measurement runs at least 5 repetitions per arm, alternating arms
within a repetition and rotating which arm goes first in each
repetition, after one discarded warm-up run per arm.

1. **TCP throughput and CPU per GiB.** `iperf3 -c <proxy> -P 4 -t 15 -J`
   through a plain TCP stream (no TLS mode), once upload and once
   download (`-R`), each its own series. Throughput is the receiver-side
   sum. CPU is the proxy container's `cpu.stat` `usage_usec` delta over
   the run (cgroup v2, read by the driver with `docker exec`), divided by
   the bytes forwarded in GiB. Thresholds per direction: median
   throughput ratio Lorica/nginx at least 0.90, median CPU per GiB ratio
   at most 1.15.
2. **Connection setup.** `l4_connect_latency.py` opens 10,000
   connections at a fixed 500 per second (open loop, a few threads, so a
   slow connection does not delay the schedule) through a non-TLS
   stream to a backend that records `CLOCK_MONOTONIC` at `accept`; the
   client records it when `connect` returns and sends a 16-byte id.
   Containers share the kernel and Docker creates no time namespace, so
   the two clocks are one, and the difference is the proxy's accept to
   backend connect plus wake-up costs both proxies pay alike. One p99
   per run; the series is the per-run p99s; threshold: median ratio at
   most 1.5. The backend closes first, so TIME_WAIT lands on the
   backend, not on the proxy's ephemeral ports. *Amended 2026-11-24:
   the p99 is pooled over the runs' every latency and judged on a
   bootstrap interval (D-k, amendment); the threshold is unchanged.*
3. **UDP hold.** The driver reads Lorica's derived ceiling `C` from the
   budget view and sets `S = floor(0.8 x C)`. Both proxies get a UDP
   stream with idle timeout 30 s, responses unbounded
   (`unbounded_responses` on Lorica, nginx's default), requests per
   session unbounded, per-source caps and rates lifted for the client,
   and Lorica's `max_sessions` at `S` (12.5's hand-off: the default
   4,096 is not 80 % of anything). `udp_hold.py` opens `S` sockets from
   one address, sends one datagram per socket every 5 s for 30 s, and
   expects every echo within 1 s; the backend counts distinct upstream
   peers. Pass, per run: zero lost echoes and exactly `S` distinct peers
   at the backend (an evicted session comes back on a new upstream
   port). Every Lorica run must pass. An nginx run that fails makes the
   measurement `INCONCLUSIVE` (the harness or its configuration is
   wrong), not a Lorica failure. **Memory**: the summed PSS of the
   Lorica container's processes (`/proc/<pid>/smaps_rollup`) with `S`
   sessions minus before the fill, per 1,000 sessions; PSS splits the
   shared-memory region across workers, which RSS would count once per
   worker. Reported with its median and spread, not gated. nginx's
   figure is reported beside it.
4. **NFR1** (D-l).

### D-k. Statistics and verdicts

- **Spread** of a series is its interquartile range divided by its
  median (with 5 values, the 4th minus the 2nd sorted value). It is
  robust to one outlier run, which (max - min) is not; see Open
  question 5.
- **A measurement is conclusive** when every series it compares has a
  spread of at most 5 % of its median. The ratio is median over median.
- **Re-run**: an inconclusive measurement is run again whole (every
  arm, 5 repetitions), at most 3 times. The verdict is taken on the
  first conclusive attempt; every attempt, conclusive or not, is in the
  report.
- **Verdicts**: `PASS`, `FAIL` (conclusive and over a threshold),
  `INCONCLUSIVE` (still over 5 % after 3 re-runs, or the environment
  guard), `NOT-RUN` (fewer than 4 CPUs). Gated measurements: the two
  throughput series, the two CPU per GiB series, connection setup, the
  UDP hold, NFR1. Reported only: memory per 1,000 sessions, NFR1 over
  HTTPS.
- **Output**: `tests-e2e-docker/results/perf-<ts>.json` (every run's raw
  numbers) and `perf-summary.md` (one table per measurement: medians,
  spreads, ratios, thresholds, attempts, verdict, and the environment
  record). Analysis is `perf/analyse.py`, standard library, run in the
  `perf-tools` container, so the Windows host needs no Python.
- **Amendment, 2026-11-24 (Phase 1 audit, maintainer decision): p99
  checks.** The connection-setup p99 (D-j 2) and the NFR1 p99s (D-l) no
  longer use the spread rule. The larger-layout dry run (Lot M
  Completion Notes) had per-run p99s at 3 to 26 % spread while the p50s
  held 1 to 3 %: a p99 series met 5 % rarely and by luck, so AC #3
  became a re-run lottery and NFR1 HTTP p99 stayed `INCONCLUSIVE` after
  four attempts. AC #3 is read as "an uncertain result is not a pass",
  which an interval states directly. The method:
  - Each p99 run keeps every latency: the connect tool's `--samples`
    file (us), oha 1.16's `--db-url` SQLite (the `duration` column,
    which with `--latency-correction` is the corrected latency oha's own
    percentiles use; ms). `analyse.py record` stores them gzip under
    `results/perf-<ts>.samples/`, named in the run record.
  - Per arm, the latencies of its runs are pooled; the pooled p99 is the
    nearest-rank 99th percentile, and the ratio is pooled p99 over
    pooled p99.
  - A 95 % percentile bootstrap interval brackets the ratio: each
    resample draws whole runs with replacement within each arm,
    independently, so the run-to-run variation the spread rule was
    about stays in the interval. The resample count is
    `BOOTSTRAP_RESAMPLES` in `analyse.py`; the seed is
    `PERF_BOOTSTRAP_SEED` (default `analyse.py`'s `DEFAULT_SEED`),
    recorded in the report, so a report recomputes to the same interval.
  - A p99 series is 10 runs per arm (`PERF_P99_REPS`, at least
    `analyse.py`'s `P99_RUNS`, which `perf/test_analyse.py` pins against
    `run-perf.sh`). An attempt is complete with that many good runs per
    arm; an incomplete one is re-run whole, at most 3 times, as before.
  - Verdict on the first complete attempt: `PASS` when the interval's
    upper bound is within the threshold, `FAIL` when its lower bound
    exceeds it, `INCONCLUSIVE` otherwise, which blocks the release
    pending an owner decision as AC #3 says. A complete attempt is not
    re-run for an inconclusive interval: re-running until an interval
    clears would bring the lottery back.
  - Throughput, CPU per GiB and requests per second keep the 5 % spread
    rule and its re-runs unchanged.

### D-l. NFR1

Three arms on the proxy cpuset: **B**, 1.10.7 (`perf-lorica-baseline`);
**L0**, 1.11.0 with no stream; **L1**, 1.11.0 with one idle TCP stream
bound (created through the API before the arm, deleted after, on the
same `perf-lorica` container). The same route, seeded by the driver
through endpoints both versions accept, to `perf-backend-http`.

- **Throughput**: `oha -z 15s -c 64` with keep-alive, closed loop, on
  the plain HTTP listener. Threshold: median requests per second of L0
  and of L1 each at least 0.95 x B.
- **p99**: `oha -z 20s -c 64 -q R --latency-correction` at a fixed rate
  `R` = 50 % of B's median saturation throughput from the throughput
  series of the same run, so latency is measured below saturation and
  corrected for coordinated omission. Threshold: median p99 of L0 and of
  L1 each at most 1.05 x B. *Amended 2026-11-24: pooled p99 over 10
  runs per arm, judged on a bootstrap interval (D-k, amendment); the
  1.05 threshold is unchanged.*
- **HTTPS** is measured the same way and reported, not gated (D-g, the
  crypto library's C compiler differs between the two builds).
- The p99 threshold is tight against the 5 % spread rule. Twenty
  seconds at a fixed rate gives tens of thousands of samples per run,
  which is what keeps a per-run p99 stable; if it still is not, the
  rule says inconclusive, and that blocks the release by design.
  *Superseded 2026-11-24: the dry run showed it is not stable (3 to
  26 % spread); see D-k's amendment.*

### D-m. Gating and CI

**Local release run**: `./run.sh --build` runs every phase; the L4
phase and the performance phase both gate (`EXIT_CODE` non-zero on any
L4 `FAIL`, any registry row missing, or any perf `FAIL`, `INCONCLUSIVE`
or `NOT-RUN`). An `INCONCLUSIVE` prints "release blocked pending owner
decision"; the decision is recorded in this story before the release
PR. `--skip-perf` exists for iterating during the cycle and is never
used for the release run.

**CI** (`.github/workflows/ci.yml`), three jobs where there is one:

| Job | Runs | Timeout | Gates the release |
|---|---|---|---|
| `e2e-docker` | `./run.sh --build --skip-l4 --skip-perf` (pre-existing profiles, with their new stream sections) | 90 min | yes, as today |
| `e2e-l4` (new) | `./run.sh --build --only-l4` | 90 min | yes: joins `verify-tag`'s `needs` |
| `e2e-perf` (new) | `./run.sh --build --only-perf --perf-advisory` | 120 min | no: job-level `continue-on-error: true`, and in `verify-tag`'s `needs` |

- `--perf-advisory` makes the performance phase write its verdicts and
  exit 0 whatever they are. A step with `if: always()` appends
  `perf-summary.md` to `$GITHUB_STEP_SUMMARY` and uploads `results/` as
  an artifact. `e2e-l4` does the same with the scenario table and the
  parity matrix.
- `e2e-perf` is in `verify-tag`'s `needs` with `continue-on-error`, so
  on a tag push the release waits for the numbers and publishes them in
  the run that released, and still never fails on them. This is AC #5's
  "a step whose failure does not hold the release". I am fairly sure,
  not certain, that a job-level `continue-on-error` also covers a
  timeout; Lot N checks it on a branch run before relying on it.
- Splitting into three jobs is forced by time: today's 43 minutes plus
  the L4 and perf phases exceed the 90-minute timeout of one job, and
  three jobs run in parallel. Each builds its own image; layer cache
  does not cross jobs without a cache backend, and adding one is not
  this story's business.
- On a GitHub runner (4 vCPU) the perf phase uses the small cpuset
  layout and `N = 1`. Its numbers are advisory by AC #5 and the summary
  says which layout ran.

### D-n. The local release-run procedure (Lot O)

1. The machine to itself: no cargo, no other suite, no other Docker
   project running. `docker ps -a` empty, or each project torn down
   with `down -v --remove-orphans` (`lorica`, `lorica-e2e-l4`,
   `lorica-e2e-perf`). Close heavy applications on the host.
2. Docker Desktop's VM has at least 8 CPUs (Resolved 13: the release
   machine reports 24, the larger layout of D-i applies); record
   `docker info`.
3. The working tree is the Phase 1 head, clean; record the commit.
   Every `.sh` under `tests-e2e-docker/` is LF (`file` or
   `grep -c $'\r'`), since a tool-written script keeps CRLF and bash in
   the image dies on it.
4. `cd tests-e2e-docker && ./run.sh --build`, nothing else until it
   ends.
5. Record in this story's Completion Notes: commit, environment, the
   duration of each phase, the scenario table with every `PARTIAL` and
   its note, the parity matrix, the perf summary with attempts, and the
   review of AC #7 (`12.8-iv3-proxy-off-suite-unchanged`).
6. Any `FAIL` is a defect fixed in this cycle, then the whole run is
   repeated: a fix can move a ratio. Any `INCONCLUSIVE` waits for the
   owner's decision, recorded here.
7. A passing run is IV1. The release PR and the bump follow (outside
   this story).

### D-o. Expected runtime

Estimates, to be replaced by measured values in Lot O's notes.

| Part | Estimate |
|---|---|
| Pre-existing profiles (CI, build included) | 43 min today |
| Stream sections in `cluster`, `acme`, `hot-upgrade`, `mcp`, `geoip`, `workers` | about 12 min (12.11 alone adds about 3) |
| L4 phase, `streams` and `streams-single` | about 35 min |
| Perf phase, no re-run | about 30 min (TCP 6, connection setup 4, UDP hold 8, NFR1 10, boots 2) |
| Perf phase, worst case (3 re-runs of every measurement) | about 2 h more |
| Local release run, sequential, no re-run | about 2 h |

### D-p. Artefacts (AC #6), approved

All approved by the maintainer on 2026-11-18 (Resolved 1 to 3), as
test images only. Every new image is pinned by **tag and `@sha256`
digest**, and every downloaded binary by checksum; **Lot A records
every digest and checksum** (`docker buildx imagetools inspect` on the
day it runs) in this story's Resolved list. None has been pulled yet;
the versions below are the lines to pin, and Lot A checks each claim
marked "to verify".

| Artefact | Pinned as | Why | Status |
|---|---|---|---|
| nginx | Official `nginx` image, newest **stable** release (even minor) at Lot A, Debian variant, by digest | AC #2's comparator, and the NFR1 HTTP backend (one artefact, two uses). Stable over mainline: what adopters run, and the PRD's 1.31.6 survey is about features, not speed. The official build includes `stream` (to verify with `nginx -V`). | Approved (new) |
| TCP load generator | `iperf3` from Debian bookworm (3.12) in a new `perf-tools` image `FROM debian:bookworm-slim` by digest | Standard, multi-stream, JSON output, server and client in one package, distribution-signed. | Approved (new) |
| Connection-setup client and backend | `l4_connect_latency.py`, standard library | Measures accept to backend connect directly (D-j); no packaged tool does. | No (stdlib, approved) |
| DNS load generator | `dnsperf` from Debian bookworm in `perf-tools` (to verify the package with `apt-cache policy`; fallback: DNS-OARC's release tarball, checksum pinned) | Reports lost queries and holds a fixed rate across many source ports, which 12.5 IV2 asserts. | Approved (new) |
| HTTP load generator (NFR1) | `oha`, a pinned release binary with its SHA-256 checked in the `perf-tools` Dockerfile | Not in AC #6's list, but NFR1 needs one. The only candidate with a fixed-rate mode and coordinated-omission correction plus JSON percentiles; `bench/` already uses it (unpinned). Chosen over Debian's `wrk`, closed loop only (Resolved 2). | Approved (new) |
| PostgreSQL | Official `postgres`, major 17, Debian bookworm variant, by digest; three backends and a `pg-client` service of the same image for `psql` | 12.3 IV1 with real servers and a real client, with no package added to the runner. | Approved (new) |
| DNS resolver | Official `coredns/coredns`, current 1.12 or later release, by digest, authoritative only (`file` or `hosts` plugin with `reload`, no forwarding) | Two instances for 12.5 IV2, one with a reloaded zone for 12.3 IV4; no outbound queries, so deterministic. | Approved (new) |
| SSH backend | `ssh-backend` image on `debian:bookworm-slim` with `openssh-server`; `openssh-client` in the runner | 12.11 IV1. The runner is Alpine, so its client is Alpine's `openssh-client`, not Debian's as 12.11 Resolved 4 reads; accepted (Resolved 14). | Approved (12.11) |
| TLS echo backend | **No image.** `openssl s_server` from the runner's existing `openssl` package, and 12.4 Lot H's Python `ssl` backend | An image cannot report the raw ClientHello, the SNI and the client certificate it saw, which 12.4's scenarios assert (Resolved 3). | Approved (no image) |
| Redis | Official `redis`, 7.4 line, by digest | 12.7 IV1 (`docker pause`). | Approved (12.7) |
| Runner additions | `iproute2`, `openssh-client` (Alpine) | 12.2 `ss`; 12.11 SSH client. | Approved |
| Base images | `debian:bookworm-slim` by digest for `perf-tools`, `baseline` and `ssh-backend` | Same base as the e2e runtime image. | No (already used, now by digest) |
| 1.10.7 package | `lorica_1.10.7_amd64.deb` and `.asc` from the v1.10.7 release, `gpgv`-verified | D-g. | No (project's own, signed) |
| Test-only privileges | `NET_RAW` on the spoofer (12.5), `NET_ADMIN` on `streams-client` (12.6 `ip addr add`), shared pid namespace for `streams-probe` (12.2) | As the stories planned; test containers only. | Approved in those stories |

Images used by the L4 phase are pulled in CI on every run; nothing is
vendored. The new images add roughly 1.2 GB to the Docker disk.

## Tasks

Lots with hard file allowlists. A Lot touches only its files; two Lots
that share a file are sequential, never parallel, and say so. Every e2e
Lot needs the machine to itself, so e2e Lots are sequential in practice
whatever their files. No Lot runs cargo except through the e2e image
build. Every `.sh` written is LF, checked before the run. No agent runs
`git checkout`, `git restore`, `git stash` or `git reset` in the shared
tree. Scripts are written with the Write tool (heredocs with apostrophes
break the Bash tool).

**Order.** A first, now: nothing else of the cycle's e2e work starts
before it. Then B to L, each after the Lots of its story named in
"Depends on", sequential on `docker-compose.l4.yml` (B, C, E, F, G, I)
or on `docker-compose.yml` (D, H, J, K, L). M after A and after 12.3
Lot D2 and the 12.5 engine (landed) and 12.2's budget view. N after A
and M, its documentation part after every scenario Lot. O last, after
every Phase 1 story is in Review.

### Lot A: the harness, the images, the flags - e2e build only

Allowlist: `tests-e2e-docker/docker-compose.l4.yml` (new: networks
`l4` with IPv6 and `streams-geo`, services `lorica-streams`,
`lorica-streams-single`, `streams-probe`, `streams-client`; backends are
added by later Lots), `tests-e2e-docker/l4/run-l4.sh` (new),
`tests-e2e-docker/l4/lib.sh` (new), `tests-e2e-docker/l4/scenarios.tsv`
(new, every row of D-d and D-e), `tests-e2e-docker/l4/scenarios/12.12.sh`
(new, a harness self-test only), `tests-e2e-docker/test-runner/l4/report.py`
(new), `tests-e2e-docker/entrypoint-streams.sh` (new),
`tests-e2e-docker/entrypoint-streams-single.sh` (new),
`tests-e2e-docker/Dockerfile` (the `rust-toolchain.toml` `COPY` in the
builder; the two entrypoint `COPY` and `chmod` lines),
`tests-e2e-docker/test-runner/Dockerfile` (`iproute2`, `openssh-client`;
the `COPY` of `l4/`), `tests-e2e-docker/baseline/Dockerfile` (new),
`tests-e2e-docker/perf-tools/Dockerfile` (new), `tests-e2e-docker/run.sh`
(the five flags of D-c, the results tee, the L4 call, the teardown of
the two new projects), `.gitignore` (`tests-e2e-docker/results/`),
`tests-e2e-docker/docker-compose.yml` (the `strm/dnsmasq` digest pin
only, Resolved 15), and in
`docs/stories/story-12.{2,3,4,5,6,8,9,10,11}-*.md` the heading of the
e2e Lot plus one line "Delivered by Story 12.12 Lot X" (nothing else in
those files).
Depends on: nothing (artefacts approved, Resolved 1 to 3).

- [x] Pin every approved image by digest; record the digests in
      "Resolved".
- [x] `baseline/Dockerfile` per D-g; `lorica --version` in the built
      image prints 1.10.7.
- [x] `perf-tools/Dockerfile`: `iperf3`, `dnsperf`, `oha` (checksum),
      `python3`.
- [x] Driver, scenario API (`scenario <name>`, `pass`, `fail`,
      `partial <note>`, each printing the D-c line), report with the
      registry check and the Markdown output.
- [x] `run.sh` flags; the L4 phase guarded like every phase; a
      `dump_node_log` equivalent for the L4 project.
- [x] `stop_grace_period` on `lorica-streams` and
      `lorica-streams-single` in `docker-compose.l4.yml`, above the
      drain under test, which Story 12.2 D-f claims the e2e compose sets
      and none does (12.2's note of 2026-11-18). Without it `docker
      stop` SIGKILLs a drain after 10 s.
- [x] Self-test: the self-test scenario passes; a registry row with no
      line fails the phase; a row printed twice fails it.
- [ ] The full pre-existing suite passes with the toolchain pin (AC #7
      for this Lot).

### Lot B: Story 12.2 scenarios and the fd reserve - Docker e2e

Allowlist: `tests-e2e-docker/l4/scenarios/12.2.sh` (new),
`tests-e2e-docker/l4/scenarios/12.12.sh` (the fd-reserve function),
`tests-e2e-docker/test-runner/l4/udp_hold.py` (new; shared with Lot M,
which reuses it unchanged), `tests-e2e-docker/test-runner/l4/http_loop.py`
(new), `tests-e2e-docker/docker-compose.l4.yml` (the budget nodes and
the squatter only), `docs/stories/story-12.2-stream-listeners.md`
(Lot H checkboxes only).
Depends on: A; 12.2 Lots D, E3 and G.

- [x] Every item of 12.2 Lot H as the scenarios of D-d.
- [x] `12.12-fd-reserve-http-unaffected` per D-f.

### Lot C: Story 12.3 scenarios and the TCP matrix rows - Docker e2e

Allowlist: `tests-e2e-docker/l4/scenarios/12.3.sh` (new),
`tests-e2e-docker/test-runner/l4/tcp_backend.py` (new, 12.3 Lot G's
design), `tests-e2e-docker/l4/coredns/` (new: Corefile and zone),
`tests-e2e-docker/docker-compose.l4.yml` (PostgreSQL x3, `pg-client`,
CoreDNS, the Python backends), `docs/stories/story-12.3-tcp-engine.md`
(Lot G checkboxes only).
Depends on: B; 12.3 Lots D2 and E.

- [x] 12.3 IV1 to IV4 per D-d, IV1 with PostgreSQL and `psql`.
- [x] The five `12.3-matrix-*` scenarios of D-e.

### Lot D: Story 12.4 scenarios - Docker e2e

Allowlist: `tests-e2e-docker/l4/scenarios/12.4.sh` (new),
`tests-e2e-docker/test-runner/l4/tls_backend.py` (new, 12.4 Lot H's
design), `tests-e2e-docker/docker-compose.l4.yml` (TLS backends),
`tests-e2e-docker/docker-compose.yml` (the `acme` and `cluster`
profiles' stream additions only), the `acme` and `cluster` smoke scripts
(a stream section appended, nothing above it changed),
`tests-e2e-docker/test-runner/Dockerfile` (`COPY` lines only),
`docs/stories/story-12.4-tls-l4.md` (Lot H checkboxes only).
Depends on: C; 12.4 Lots E and F.

- [x] Every item of 12.4 Lot H, plus the ALPN name in IV1.

### Lot E: Story 12.5 scenarios - Docker e2e

Allowlist: `tests-e2e-docker/l4/scenarios/12.5.sh` (new),
`tests-e2e-docker/test-runner/l4/udp_tools.py` (new: spoofer,
amplifying backend, victim recorder), `tests-e2e-docker/docker-compose.l4.yml`
(spoofer, victim, amplifier, second CoreDNS, `dns-loadgen` on the
`perf-tools` image), `tests-e2e-docker/l4/coredns/` (the IV2 zone),
`docs/stories/story-12.5-udp-engine.md` (Lot I checkboxes only).
Depends on: C (CoreDNS service); 12.5 Lots F, G, H.

- [x] Every item of 12.5 Lot I; IV2 with CoreDNS and `dnsperf` instead
      of the stand-ins (the stand-in DNS responder and load generator of
      12.5 Lot I are not written).
- [x] `12.5-matrix-udp-idle-timeout`.

### Lot F: Story 12.6 scenarios - Docker e2e

Allowlist: `tests-e2e-docker/l4/scenarios/12.6.sh` (new),
`tests-e2e-docker/test-runner/l4/protect_tools.py` (new, 12.6 Lot I's
design), `tests-e2e-docker/docker-compose.l4.yml` (`streams-geo`
attachments, `NET_ADMIN`, the GeoIP database mount),
`docs/stories/story-12.6-stream-protection.md` (Lot I checkboxes only).
Depends on: D, E; 12.6 Lots D, E, F.

- [x] Every item of 12.6 Lot I; `12.6-matrix-concurrency-caps`.

### Lot G: Story 12.7 IV1 - Docker e2e

Allowlist: `tests-e2e-docker/l4/scenarios/12.7.sh` (new),
`tests-e2e-docker/test-runner/l4/smtp_banner.py` (new, standard
library), `tests-e2e-docker/test-runner/Dockerfile` (`COPY` lines only),
`tests-e2e-docker/docker-compose.l4.yml` (Redis, the two banner
servers), `docs/health-checks.md` (the "Backend-side noise"
observations and the SMTP verification only).
Depends on: C (PostgreSQL); 12.7 in Review.

- [x] `12.7-iv1-redis-paused-marked-down` as 12.7 handed it; the
      per-probe log lines of Redis and PostgreSQL recorded in
      `docs/health-checks.md`.
- [x] `12.7-x-smtp-banner-template` (Resolved 4): `smtp_banner.py` in
      two services, one that accepts and writes `220 example.com ESMTP`
      then waits, one that accepts and never writes. A backend on
      `tcp_template{smtp_banner}` is `Up` on the first and marked down on
      the second within `HEALTH_FLIP_THRESHOLD` x the interval plus the
      timeout. `docs/health-checks.md` states that the SMTP template was
      verified against this standard-library banner server, not against
      a real MTA, so what an MTA logs per probe was not observed.

### Lot H: Story 12.8 scenarios - Docker e2e

Allowlist: as 12.8 Lot G's allowlist
(`run-proxy-protocol-smoke.sh`, `proxy_protocol_client.py`, the
runner Dockerfile `COPY` lines, one call each in `run-geoip-smoke.sh`
and `run-tests-workers.sh`, `docker-compose.yml` for the geoip
profile's environment only), plus `docs/stories/story-12.8-proxy-protocol-http.md`
(Lot G checkboxes only).
Depends on: A; 12.8 Lot D.

- [x] Every item of 12.8 Lot G, each printing its scenario line.

### Lot I: Story 12.9 scenarios - Docker e2e

Allowlist: `tests-e2e-docker/l4/scenarios/12.9.sh` (new),
`tests-e2e-docker/docker-compose.l4.yml` (a `syslog-collector` and a
logs-only OTel collector in the `streams` profile, reusing the existing
images and `fixtures/otelcol-logs.yaml`),
`docs/stories/story-12.9-stream-observability.md` (Lot J checkboxes
only).
Depends on: C (Python backend); 12.9 Lots C1, C3, E, H.

- [x] Every item of 12.9 Lot J, in the `streams` profile instead of a
      `stream-observability` profile of its own (same shape: one node,
      two workers; one boot fewer).

### Lot J: Story 12.10 IV1 and Story 12.7 IV2 - Docker e2e

Allowlist: `tests-e2e-docker/test-runner/run-mcp-smoke.sh` (a streams
section appended), `tests-e2e-docker/test-runner/mcp-helpers.sh`,
`docs/stories/story-12.10-stream-surfaces.md` (Lot H checkboxes only).
Depends on: 12.10 Lots B and D2; 12.7 in Review.

- [x] Every item of 12.10 Lot H; `12.7-iv2-template-yes-payload-no` in
      the same section.

### Lot K: Story 12.11 scenarios - Docker e2e

Allowlist: as 12.11 Lot G's allowlist (`docker-compose.yml` for the
`hot-upgrade` profile's services, `tests-e2e-docker/ssh-backend/` new,
`run-hot-upgrade-smoke.sh` with a section appended, the runner
Dockerfile, `entrypoint-hot-upgrade.sh` and `run.sh` only if needed),
plus `docs/stories/story-12.11-upgrade-drain.md` (Lot G checkboxes
only).
Depends on: E (the UDP stand-in), I; 12.11 Lots C and D; 12.2 Lot G.

- [x] Every item of 12.11 Lot G under its four names.

### Lot L: Story 12.1 scenarios and the rollbacks - Docker e2e

Allowlist: `tests-e2e-docker/l4/scenarios/12.1.sh` (new),
`tests-e2e-docker/test-runner/run-cluster-smoke.sh` (a streams section
appended), `tests-e2e-docker/test-runner/run-hot-upgrade-smoke.sh` (the
hot rollback, appended after Lot K's section),
`tests-e2e-docker/docker-compose.yml` (the baseline image service in the
`hot-upgrade` profile only), `tests-e2e-docker/docker-compose.l4.yml`
(the baseline service on the `streams-single` volume),
`docs/hot-upgrade.md` (the rollback statement only).
Depends on: K (same smoke file); 12.1 in Review; 12.2 Lot G; 12.7 (the
send/expect backend of D-h).

- [x] `12.1-iv1-*`, `12.1-iv2-*` in the `cluster` section.
- [x] Both rollback scenarios per D-h; `docs/hot-upgrade.md` states
      what a rollback to 1.10.7 does with streams present, as observed.

### Lot M: the performance phase - Docker perf

Allowlist: `tests-e2e-docker/docker-compose.perf.yml` (new),
`tests-e2e-docker/perf/run-perf.sh` (new), `tests-e2e-docker/perf/nginx-stream.conf`
(new), `tests-e2e-docker/perf/nginx-http-backend.conf` (new),
`tests-e2e-docker/perf/entrypoint-perf.sh` (new: only flags 1.10.7
knows), `tests-e2e-docker/perf/analyse.py` (new),
`tests-e2e-docker/perf-tools/l4_connect_latency.py` (new),
`tests-e2e-docker/perf-tools/udp_echo_peers.py` (new),
`tests-e2e-docker/perf-tools/Dockerfile` (`COPY` lines only),
`tests-e2e-docker/run.sh` (the perf call and the `--perf-advisory`
behaviour only).
Depends on: A, B (`udp_hold.py`); 12.3 Lot D2; the 12.5 engine; 12.2's
budget view.

- [x] Topology, cpusets and environment guard per D-i.
- [x] Measurements 1 to 3 per D-j, NFR1 per D-l.
- [x] Statistics, re-runs, verdicts and output per D-k.
- [x] A dry run on the development machine with both layouts (force the
      small one with an override variable) recorded in the Completion
      Notes, including whether any series reaches 5 % spread at all
      and how long the phase took.
      *Open, 2026-11-22: the larger layout ran and is recorded (Lot M
      Completion Notes, the pre-fix baseline); the small layout
      (`PERF_LAYOUT=small`) is deliberately not run yet, by the
      coordinator's decision, until the p99 method changes and the audit
      fixes land, since both move what it would validate.*
      *2026-11-24: the p99 method changed (D-k, amendment): raw
      latencies per run (`l4_connect_latency.py --samples`, oha
      `--db-url`), pooled p99 per arm, seeded bootstrap interval on
      whole runs, 10 runs per p99 series, unit-tested in
      `perf/test_analyse.py` (stdlib `unittest`, no Docker). The phase
      has not run with it yet: the larger-layout baseline above is the
      old method's, and both layouts' dry runs are owed.*
      *Done 2026-11-24 on `67573484`: both layouts ran with the amended
      method (Lot M Completion Notes, the post-audit run). Larger layout
      64.9 min, small layout 57.9 min; throughput, CPU per GiB and
      req/s series reach 5 % spread in both (0.4 to 3.4 %), the p99
      series are judged on their intervals.*

### Lot N: CI and documentation - no cargo

Allowlist: `.github/workflows/ci.yml` (the `e2e-docker` run line, the
`e2e-l4` and `e2e-perf` jobs, `verify-tag`'s `needs`),
`docs/benchmarks.md` (a section on the parity harness: method, layouts,
statistics, how to run, and the 1.11.0 numbers from Lot O),
`docs/streams.md` (a "Parity verification" section: the matrix with its
scenarios and the ratios measured), `CHANGELOG.md` (`[Unreleased]`,
Added: the L4 and performance phases; Changed: the release waits for
the L4 phase).
Depends on: A, M; the documentation part after every scenario Lot and
the numbers after O.

- [ ] CI per D-m; a branch run proves `e2e-perf` failing or timing out
      does not fail the workflow (Completion Notes say how it was
      forced).
      *2026-11-24: the jobs are written and lint clean (Lot N
      Completion Notes); the branch run happens on the release PR, the
      first push that runs this workflow, forced as the notes say.*
- [ ] Documentation and changelog.
      *2026-11-24: written except the 1.11.0 numbers, which Lot O adds
      as a dated results table at the end of `docs/benchmarks.md`'s
      "Layer-4 parity harness" and of `docs/streams.md`'s "Parity
      verification".*

### Lot O: the release run - IV1

Allowlist: this story's Dev Agent Record and Change Log only.
Depends on: every Lot above; every Phase 1 story in Review.

- [ ] The procedure of D-n; results recorded; owner decision recorded
      for any `INCONCLUSIVE`.
- [ ] The breaker RPC load under a UDP flood (added 2026-11-21, Phase 1
      audit item N1, maintainer decision). Worker mode, a DNS flood with
      a fresh source port per query at about 30,000 queries a second
      through one UDP stream while HTTP is measured, taken after the
      audit's fix that stops awaiting the breaker report (C9) has landed:
      HTTP p99 and the supervisor's breaker RPC rate, recorded with the
      other numbers. Every new session asks the supervisor for one
      breaker admission over the RPC endpoint HTTP shares. A worker-local
      cache of closed circuits is built only if HTTP p99 then moves past
      NFR1; it is not built otherwise, because it would let a circuit
      stay closed on a worker for the cache's lifetime after the
      supervisor opened it, which changes 12.3 D-g's coordination.

## Dev Notes

### Where to extend, verified on `6e460a61`

- `tests-e2e-docker/run.sh`: the flag loop, `ALL_PROFILES`,
  `dump_node_log`, the readiness loop (`curl -skf
  https://127.0.0.1:19443/` through `docker compose exec`), the guarded
  phase pattern, the cluster automation phase as the model for driving
  Docker between runner steps (its `sh -c` wrapper exists for Git
  Bash's path conversion), the final `down -v`.
- `tests-e2e-docker/Dockerfile`: the builder stage's `COPY` list (no
  `rust-toolchain.toml`), the runtime stage's entrypoint `COPY` and
  `chmod` lines, `USER lorica`.
- `tests-e2e-docker/test-runner/Dockerfile`: the `apk add` line and the
  per-script `COPY` and `chmod` lines; `CURL_HOME` makes every curl
  accept the self-signed management certificate.
- `tests-e2e-docker/docker-compose.yml`: `hot-upgrade` (shared volume,
  `NOTIFY_SOCKET`, root runner), `log-sinks` (`syslog-collector` on the
  runner image with socat, logs-only OTel collector), `geoip` (the test
  database and the runner address the smoke relies on), `cluster` (three
  nodes, enrollment), `mcp` (`seed-automation-allowlist.sh`).
- `.github/workflows/ci.yml`: `e2e-docker`, `verify-tag`'s `needs`,
  `test-deb-upgrade` (the download and `gpgv` steps D-g copies),
  `run-on-oldest` (why 1.10.7 starts on Debian 12), `build-binaries`
  (`almalinux:9`, pinned toolchain).
- `bench/`: an earlier HTTP-only harness with an unpinned `oha`; not
  reused, not changed.

### Pitfalls

- **Timed assertions inside one container command** (D-c). The host is
  Windows with Git Bash locally; `docker compose exec` is slow and its
  path arguments are rewritten by MSYS unless `MSYS_NO_PATHCONV=1` is
  set in the driver.
- **CRLF**: a `.sh` written by a tool keeps CRLF despite
  `.gitattributes`; the image copies the working tree and bash fails on
  `\r`. Check before every e2e run.
- **Client fd limits**: 10,000 TCP sockets (12.6 IV3) and up to about
  22,500 UDP sockets (D-j) need `ulimits: nofile` on the client
  services, and one client address offers about 28,000 ephemeral ports.
- **iperf3 serves one test at a time**: the alternation must wait for
  the server to be free; a stray client blocks the next run.
- **nginx UDP across workers** needs `listen ... udp reuseport`, and
  `worker_connections` must cover both sides of every session in each
  worker's share.
- **`docker pause` freezes the cgroup**, and the kernel still completes
  TCP handshakes into the listen backlog: exactly why 12.7 chose it, and
  why a paused backend passes a connect-only check.
- **A container's PID 1 ignores signals from inside its namespace**
  unless it handles them: kill backends from the driver
  (`docker compose kill`), never from inside.
- **Docker's embedded DNS** forwards names it does not own to the
  `dns:` servers; whether it keeps the TTL is not verified (12.3 IV4).
- **cgroup v2**: `cpu.stat` is at `/sys/fs/cgroup/cpu.stat` inside a
  container with a private cgroup namespace (the default on cgroup v2);
  Lot M checks it on Docker Desktop and on the GitHub runner.
- **Entrypoint flags for 1.10.7**: anything added in 1.11.0 (drain
  setting, stream flags) breaks the baseline container at start; the
  perf entrypoint uses only flags both versions know.
- **The whole suite short-circuits on the first failure** (every phase
  checks `EXIT_CODE`), so an L4 failure hides the perf phase. For the
  release run that is correct; for Lot M's dry runs use `--only-perf`.

### Tests per Lot

Listed in each Lot. All of them are e2e runs needing the machine alone.
What no test here proves: the dashboard's rendering of streams (12.10
Lot E's frontend tests are the proof), the behaviour under a real
systemd unit (the package jobs boot one, without streams), kernels older
than the Docker VM's, and performance on hardware other than the
release machine, since every number is a ratio taken on one machine.

### Handed to other stories

- **12.2 to 12.11**: their e2e Lots are delivered here (D-a); each
  story's file gets the pointer line in Lot A and its checkboxes ticked
  by the Lot that delivers them.
- **12.3**: if CPU per GiB misses 1.15 x, the splice decision 12.3
  handed here is taken on Lot O's numbers, in this cycle.
- **12.16 (spike)**: the perf harness is the place to measure what a
  transfer costs; nothing here depends on it.
- **12.18**: Phase 2's verification extends this registry and this
  harness rather than building another.

## Resolved (maintainer, 2026-11-18)

Numbered as the draft's open questions were, so every "Resolved N" in
this file points at the decision it took.

1. **Artefacts approved**, as test images only, each pinned by digest
   or checksum: nginx stable (official), `iperf3` and `dnsperf` from
   Debian in the `perf-tools` image, `postgres` 17 bookworm, `coredns`
   authoritative only. **Lot A records every digest and checksum** here,
   below this list, on the day it pins them.
2. **`oha` over `wrk`** for NFR1, pinned release binary with its SHA-256
   checked in the `perf-tools` Dockerfile.
3. **No TLS echo image**: `openssl s_server` from the runner and 12.4's
   Python `ssl` backend fill AC #6's slot.
4. **SMTP is verified, not left "not checked".** Story 12.7's SMTP
   banner template is checked against a standard-library banner server
   (a socket that writes `220 ...`, and a variant that never writes),
   the same approach as 12.7's fake Redis; no Postfix image. Scenario
   `12.7-x-smtp-banner-template`, Lot G. What a real MTA logs per probe
   is not observed, and `docs/health-checks.md` says so.
5. **Spread is IQR over median** (D-k).
6. **Build parity** as D-g: toolchain pin in the e2e builder, compare
   against the released 1.10.7, gate NFR1 on plain HTTP, report HTTPS.
7. **The hot rollback to 1.10.7 runs and gates** on a clean,
   documented result: the handoff succeeds with HTTP surviving, or
   1.10.7 refuses it and the old generation keeps serving. A crash or a
   lost listener is a defect fixed in this cycle.
8. **The nine story e2e Lots are delivered by this story** (D-a);
   stories reach Review when their 12.12 Lot passes, so Lot A lands
   first.
9. **The extra matrix scenarios are kept** (D-e).
10. **"TCP passthrough" is a plain TCP stream** (no TLS mode).
11. **No separate security phase**: 12.6 IV3 at 10,000 connections is
    the scenario.
12. **CI: three jobs.** `e2e-docker` unchanged in what it gates;
    `e2e-l4` gates the release; `e2e-perf` with `continue-on-error`,
    publishing to the job summary (D-m).
13. **The release machine reports 24 CPUs to Docker**: the 8-CPU
    minimum is met and the release run uses the larger cpuset layout
    (proxy `2-3`, load `4-5`, backends `6-7`, `N = 2`). Fewer than 8 on
    a release run gives `INCONCLUSIVE (environment)`.
14. **Alpine's `openssh-client`** in the runner is accepted.
15. **`strm/dnsmasq` is pinned by digest** in Lot A.
16. **nginx logs per connection** in the perf phase, as Lorica does.
17. **`NET_ADMIN` on `streams-probe`** (approved 2026-11-20, test
    environment only): the probe gives the worker node a second address
    on `l4` for `12.3-matrix-proxy-bind` (D-e's "second address on the
    node"). D-p's privileges row gave it to `streams-client` only.

### Digests and checksums pinned by Lot A (2026-11-18)

Resolved with `docker buildx imagetools inspect` (the index digest, so
every platform resolves through it) and pulled; versions read from the
pulled images.

| Artefact | Pinned as | Checked |
|---|---|---|
| nginx | `nginx:1.30.7@sha256:8a7280c664b1a205092ffea6443299e6d307fe65b6f946b02028fa311c29fd01` | Newest stable (`stable` tag on the day). `nginx -V` lists `--with-stream`, `--with-stream_ssl_module`, `--with-stream_ssl_preread_module`, `--with-stream_realip_module`. Debian 13 (trixie): the official stable line publishes no bookworm variant of 1.30.7, and `stable-bookworm` is frozen on 1.28.0 (built 2025-12-08), so the Debian variant is trixie. |
| PostgreSQL | `postgres:17.12-bookworm@sha256:40865bc877a289da75963d97d72b59633f639fc5af7a4e856bfa3714cae5b536` | `postgres --version`: 17.12 (Debian 17.12-1.pgdg12+1). |
| CoreDNS | `coredns/coredns:1.15.0@sha256:0a9d8c8ddf34347eb59aad9a8784f0710de88d6d112726d11d271f9bc6daca26` | `-version`: CoreDNS-1.15.0 (the `latest` tag on the day). |
| Redis | `redis:7.4.12-bookworm@sha256:2e3eb11462c4e3759e6972678dd051d150ff54b1e60714b3c33b701260172a90` | `redis-server --version`: 7.4.12; same digest as `redis:7.4`. |
| Debian base | `debian:bookworm-20261104-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc` | Same digest as `debian:12.15-slim` and `bookworm-slim` on the day. Used by `perf-tools` and `baseline`; `ssh-backend` (Lot K) uses the same line. |
| `strm/dnsmasq` | `strm/dnsmasq:latest@sha256:dcf4c0aeb69ea6b9bca81314449d732ecd2ea021588d8a34d4be7c2304f89a39` | Resolved 15. A single-platform manifest; the image publishes no versioned tag. |
| iperf3 | Debian bookworm `3.12-1+deb12u2` | `iperf3 --version`: 3.12. From the distribution, signed by its archive; not pinned to the package version, which a point release would remove from the mirror. |
| dnsperf | Debian bookworm `2.10.0-2` | `apt-cache policy dnsperf` in the pinned base: in bookworm main, so the DNS-OARC tarball fallback is not needed. |
| python3 (perf-tools) | Debian bookworm `3.11.2-1+b1` | |
| oha | `v1.16.0`, `oha-linux-amd64`, SHA-256 `620bb9e16fb53eabc9a3fc45f88bdb41fefa3fee5c05e75892011ce320391716` | Checked by `sha256sum -c` in `perf-tools/Dockerfile`; equal to the digest GitHub publishes for the asset. `--latency-correction`, `-q`, `-z` and `--output-format` present. v1.17.0 (2026-11-14) was four days old and is not taken. |
| Lorica 1.10.7 | `lorica_1.10.7_amd64.deb` SHA-256 `8f33d920aac1f6777cb1658b1bf47f4b7c74c5dbbe5adb7c617e4fa25a1e4cf7`, `.asc` SHA-256 `681911643828577c9d01fd24649039adf81aec05d9f723c978d8520ff7d77398` (GitHub asset digests) | `gpgv` in the baseline build: good signature from `B6E37EA916841674`; the built image's `lorica --version` prints `lorica 1.10.7`. |
| Rust toolchain (e2e builder) | `rust-toolchain.toml`, 1.99.1 | The e2e build log shows rustup syncing `1.99.1-x86_64-unknown-linux-gnu` before cargo. |

## Dev Agent Record

### Debug Log

- Lot A, 2026-11-18: the first self-test run failed on the probe's
  process count: busybox `pgrep -x lorica` matches the workers' full
  executable path, not their name, and found the supervisor alone. The
  self-test now counts `ps -o comm`. Kept as the first proof that a
  `FAIL` reaches the report.
- Paused 2026-11-19 (machine shutdown). Lot B committed and passing.
  Lot C written but never run, left uncommitted in the worktree
  (`l4/scenarios/12.3.sh`, `test-runner/l4/tcp_backend.py`,
  `l4/coredns/Corefile`, the Lot C services in
  `docker-compose.l4.yml`); its registry rows are still `pending`. Next:
  mark the Lot C rows `live`, then from `tests-e2e-docker/`
  `./run.sh --only-l4 --build` (runner image rebuild; the Lorica image
  is cached), starting with `12.3-iv1-pg-balance-and-failover`. Lot D
  not started.
- Resumed 2026-11-20 on `feat/v1.11.0` at `4ace5482` (Lot B integrated
  as `7813bbcf`); the Lot C files were carried over unchanged, and
  `docker-compose.l4.yml` had not moved since Lot B.
- 2026-11-20, Lot D in progress when the plan changed to lanes. Its
  cluster key-replication scenario found a product defect, fixed in
  `44d6248b` (`fix(cluster)`): the per-recipient cut of the replicated
  configuration (`restrict_for_recipient`) kept the certificates of the
  recipient's routes only, so a follower bound a terminating stream with
  no certificate row and refused every handshake (TLS alert 49), while
  the roster listed it as entitled. Unreleased (streams are 1.11.0's).
  Regression test `a_streams_certificates_are_cut_with_the_stream`; full
  cargo chain and `cargo audit` clean; the `acme` and `cluster` phases
  then passed with Lot D's sections (12.4 IV2 renewal and key
  replication, PASS). Lot D's files are not committed: they wait in the
  Lot D agent's hands (see its report).
- Lots F and G, lane 2: a first agent wrote them on 2026-11-20 and was
  stopped by a machine shutdown before committing. Its last full-lane
  run (`results/e2e-l4-lane-2-20261120T225341Z.log`) lost the `streams`
  profile's containers in the middle of `12.6-iv1`: the client was no
  longer running and the node's log came back empty, so every later
  row of the profile failed on Docker, not on Lorica; the cause was not
  found, and no run since has repeated it. Resumed 2026-11-21 on
  `c01536bb`: one literal carriage return in `l4/scenarios/12.6.sh`
  (inside a `tr -d` argument) replaced by `\r`, the rest kept as
  written, then both Lots run from scratch.
- 2026-11-21, lane 1 resumed after a machine shutdown, on `8b19f19f`
  (Lots D and E committed by the earlier lane 1 agent, unverified; Lot L
  not started). Every Lot D and Lot E row re-run before being counted.
  Commit `8b19f19f` lacked the 12.5 IV2 zone: it was named
  `iv2.test.db`, which the root `.gitignore` (`*.db`) drops, so the run
  passed on a file no checkout would have. Renamed `iv2.test.zone`
  (Corefile and story follow). `12.5-iv1-reflection-bounded` failed
  once in the first lane run (30,636 datagrams at the victim for 30,635
  requests counted from its key) and passed in the eight runs after; the
  per-key count subtracts the legitimate client's requests from the
  stream's upload total, which is off by one exactly when one of the
  client's requests never reaches the backend, and the client check ran
  last. It now runs first, and a failure prints the node's counters,
  its own count of what it reflected and the tools' records.
- 2026-11-21, Lot M, **D-j deviation: iperf3 runs 8 streams per proxy
  worker, not `-P 4`.** The first `-P 4` series were bimodal for both
  proxies, about 25 or about 52 Gbit/s upload, the low mode at the same
  CPU per GiB. Per-process CPU ticks over each run showed why: in a low
  run one worker carried the whole run (500 of 500 ticks on one nginx
  worker), so one proxy core of the two worked. Both proxies' workers
  share one TCP listening socket (Lorica: `bind_tcp_listener` in
  `lorica-worker/src/stream_sockets.rs`, `SO_REUSEPORT` off, one socket
  the supervisor hands to every worker; nginx: `listen` without
  `reuseport`, kept so for that reason), and a burst of connects is
  mostly accepted whole by the worker that wakes first. In the aborted
  first full run, attempt 1 of `tcp-up` had nginx on one worker in 4
  runs of 5 and Lorica in 1 of 5, for a "ratio" of 1.94 and spreads of
  10.4 % and 3.5 %. That ratio measured the accept spread, not either
  engine. Not taken: nginx `listen ... reuseport` (proposed on the
  premise that Lorica's workers own reuseport sockets, which is true of
  UDP only): it would give nginx a kernel-hashed spread over per-worker
  queues that Lorica's TCP listener does not have, so the configuration
  would no longer be equivalent (D-i). Measured on the shared socket, 6
  runs per value, 5 s each (busiest worker's share of the CPU, 0.50
  being an even split): `-P 4` nginx 4 of 6 on one worker, Lorica 1 of
  6; `-P 8` (4 per worker) nginx 3 of 6, Lorica 0 of 6; `-P 16` (8 per
  worker) 0 of 6 for both, every run at 0.50, Lorica 47.0 to 48.9 and
  nginx 51.5 to 52.4 Gbit/s. So `run-perf.sh` runs
  `-P (8 x N)`, and `analyse.py` also keeps out of its series any run
  with N > 1 in which one process did more than 90 % of the proxy's
  work, with the reason in the run's record, so a ratio never mixes the
  two modes again; the report shows each attempt's count of such runs.
  At N = 1 (the small layout) the question does not arise.

### Completion Notes

- **Lot A, 2026-11-18.** The harness, the images and the flags.
  - **Layout.** `docker-compose.l4.yml` (project `lorica-e2e-l4`):
    `lorica-streams` (`--workers 2`) and `lorica-streams-single`, one
    image `lorica-e2e-l4/lorica:local`, both aliased `l4-node` on `l4`
    (IPv6 on, `fd00:4c34::/64`), `stop_grace_period: 60s` (default drain
    30 s plus the supervisor's 10 s), `net.ipv4.ip_unprivileged_port_start=1024`
    so the 12.2 AC #3 check needs the capability; `streams-probe` in the
    worker node's network and pid namespaces; `streams-client` on `l4`;
    `streams-geo` (`214.78.120.0/24`) defined, attached by Lot F; and a
    non-test `l4-report` service. The entrypoints start as root, run
    Lorica and the socat forwarder through `setpriv` with
    `CAP_NET_BIND_SERVICE` ambient (checked in `/proc/<pid>/status` on
    the supervisor and both workers), and forward SIGTERM so `docker
    stop` drains instead of waiting for SIGKILL.
  - **Driver** `l4/run-l4.sh`, **library** `l4/lib.sh` (`scenario`,
    `pass`, `fail`, `partial`, `l4_client`, `l4_probe`, `l4_node`,
    `l4_api`, `l4_api_status`, `l4_dump_node_log`), **registry**
    `l4/scenarios.tsv` (every row of D-d and D-e, plus the self-test and
    the not-e2e rows), **report** `test-runner/l4/report.py`.
  - **How a Lot adds a scenario.** Set its row's `state` to `live` in
    `l4/scenarios.tsv` (correct the row if it is wrong, nothing else), and
    in `l4/scenarios/<story>.sh` define `scenario_<name>` with every `.`
    and `-` of the name turned into `_`. The driver calls it once per
    profile the row names, after `scenario <name>`, in a subshell under
    `set -euo pipefail` with stdin closed; it drives traffic with
    `l4_client` (timed assertions inside one in-container command, the
    Python tools under `test-runner/l4/`), the node's namespaces with
    `l4_probe`, the API with `l4_api`, Docker itself directly
    (`l4_compose kill|pause|...`), and ends with exactly one `pass`,
    `fail` or `partial <note>`. A scenario in a pre-existing profile's
    smoke echoes `L4-SCENARIO <name> <PASS|FAIL|PARTIAL> <detail>` at the
    start of a line itself. The report fails a live row of a profile that
    ran with no line, two lines, `FAIL`, `PARTIAL` from a `full` row, a
    line under another profile, and a pending row that reports (mark it
    live).
  - **Lanes and image reuse (added 2026-11-20).** Build the images once
    per product or runner change, then iterate without `--build`:
    `L4_IMAGE_TAG=<tag> l4/build-images.sh` (`--runner-only` after a
    change under `test-runner/` alone; scenario files under `l4/` run on
    the host and need no rebuild). To run several L4 phases at once on
    one Docker host, give each `L4_LANE=1..4`:
    `L4_LANE=2 L4_IMAGE_TAG=<tag> ./run.sh --only-l4`. A lane gets its
    own compose project (`lorica-e2e-l4-N`, so its own containers,
    networks and volumes), its own pinned subnets (IPv6 of `l4`,
    `l4-dns`, `streams-geo`, all derived in `l4/lib.sh` and nowhere
    else), its own `results/` files (`e2e-l4-lane-N-*.log`,
    `l4-summary-lane-N.md`, `${L4_RESULTS}-*` for a scenario's own), no
    host port, and it never builds: `run.sh` refuses `L4_LANE` with
    `--build` or without `--only-l4`. `L4_LOTS=B,D` (any run) runs only
    those Lots' rows, and the report reads the other Lots' rows as
    `NOT-RUN` instead of `MISSING`; include `A` to keep the self-test.
    Unset `L4_LANE` is the previous layout, which lane 1 shares a
    `streams-geo` /24 with (the GeoIP test database's US block holds
    four), so run lanes 1 to 4 or the plain layout, not both. A scenario
    drives Docker only through `l4_compose` (never a bare `docker
    compose -f`) and names any file it writes under `results/` with
    `${L4_RESULTS}`. An `--only-l4` run no longer tears down the main
    project, which it never started.
  - **Deviations from the text.** (1) The registry has `lot` and `state`
    columns: without `pending`, every row of the `streams` profile would
    fail Lot A's own run. A run with no `--skip-*` or `--only-*` flag
    (the release run) is strict: every row must report, pending ones
    included, so the full suite fails at the report until Lot L lands;
    iterate with `--skip-perf` or `--skip-l4`. (2) The report attributes
    a line to a profile through `L4-PROFILE <name>` markers: run.sh
    prints one at the start of every phase, the driver one per profile.
    (3) The report derives the P1 rows from the PRD coverage matrix
    (mounted read-only) and fails on a P1 row without a registry row or
    a registry label that is not a P1 Feature cell, so the matrix is not
    transcribed. (4) The report runs after every run except
    `--only-perf`, not only in the L4 phase, so the stream sections of
    pre-existing profiles are checked when the L4 phase is skipped (the
    CI `e2e-docker` job of D-m). (5) `--only-perf` and `--perf-advisory`
    exit 2 until Lot M; `--skip-perf` is accepted and skips nothing yet.
    (6) `12.12-fd-reserve-http-unaffected` keeps D-f's name although it
    has no kind segment; the report enforces the story prefix only.
  - **For later Lots.** The `geoip` profile is not run by `run.sh`
    today, so Lot H must add its phase (with `announce_profile geoip`)
    or 12.8's rows stay `NOT-RUN` outside a strict run. Nothing prints
    `L4-PROFILE suite` yet (12.8 IV3, Lot H). No D-d scenario asserts an
    IP-literal allow/deny entry: the "IP allow/deny" matrix row is mapped
    to `12.6-iv2-geo-deny-tcp-and-udp`, so Lot F adds one to that
    scenario. A budget node of Lot B must not take the `l4-node` alias.
    `--keep` leaves only the `streams-single` containers up.
  - **Proof.** `./run.sh --only-l4`: both profiles, self-test `PASS`
    (client `HTTP/1.1 404` in 3.7 ms timed in the container, API login
    and zero streams, the probe sees 3 `lorica` processes and the :8080
    listener), report `PASSED`, 19.7 s for the phase with the report.
    With four temporary rows (removed): `fail` gave `FAIL`, two `pass`
    gave `DUPLICATE`, a live row with no function gave `MISSING`, a
    failing command before any verdict gave `FAIL ended without a
    verdict (exit 1)`, and the report failed the run. Synthetic logs
    also cover `DOWNGRADED`, `UNMARKED`, an unknown name, a wrong
    profile, strict mode and ANSI/CRLF lines.
  - **Toolchain pin.** Phase 1 alone (every other phase skipped) on the
    pinned-toolchain image: 372 passed, 0 failed, 4 min 29 s. The full
    pre-existing suite was **not** run: another Docker workload shared
    the machine (the suite needs it alone), so that task stays open.
  - **Runner additions**: Alpine 3.20 `iproute2` 6.9.0-r0 and
    `openssh-client` 9.7_p1-r6. Still pinned by tag only and outside Lot
    A's allowlist: `alpine:3.20`, `node:22-slim`, `rust:1-bookworm`,
    `debian:bookworm-slim` in the e2e image, Jaeger, the OTel collector
    and Pebble.

- **Lot A gains a task, 2026-11-18:** `stop_grace_period` on the two Lorica services of `docker-compose.l4.yml`, above the drain under test. Story 12.2 D-f says the e2e compose sets it and no compose file does; 12.2 carries a dated note pointing here. The file is already on Lot A's allowlist.

- **Lot B, 2026-11-19.** Story 12.2's scenarios and the fd reserve.
  - **Verdicts** (`./run.sh --only-l4`, both profiles, 199 s for the
    phase with the report): `12.2-iv1-bind-and-release-within-5s` PASS
    in both profiles (listening about 50 ms after the create, released
    about 50 ms after the delete, both timed in the probe from the API
    call to `ss`; HTTP loop of about 90 requests, zero failures; same
    supervisor pid); `12.2-iv2-port-in-use-fails-cleanly` PASS in both
    (`address_in_use` with `Address already in use (os error 98)`, one
    `stream.bind_failed` audit row, HTTP 200, bound 2.4 to 4.4 s after
    the squatter left); `12.2-ac3-privileged-port-853` PARTIAL with its
    D-d note (bound as uid 999 with `CapAmb` 0x400; an unprivileged
    process in the same namespace is refused 853, so the sysctl is not
    what passes it); `12.2-ac1-udp-group-survives-worker-respawn` PASS;
    `12.2-ac1-dual-stack-conflict` PASS (409 `stream_port_conflict`,
    echoes over IPv4 and IPv6); `12.2-ac7-stop-drains-then-exits` PASS
    in both (idle stop 0.014 to 0.21 s; a request answering after 8 s
    completes, the process exits 0.07 to 0.27 s after it, about 6 s
    after SIGTERM); `12.2-ac5-budget-refuses-range` PASS;
    `12.12-fd-reserve-http-unaffected` PASS (fd limit 8192, `R` 4096,
    `C` 3071: 3071 of 3378 sessions held for 12 rounds, 307 refused,
    every refusal counted as `session_cap`; HTTP loop of about 2,500
    requests with zero failures; 4,032 keep-alive connections answered
    twice; no EMFILE or accept error in the log).
  - **No product defect found.** Three first-run failures were the
    scenarios': (1) the UDP default `responses_per_request` of 1 ends a
    session on its answer (`response_bound_reached`, docs/streams.md
    "How a session ends"), so an echo client never held more than a few
    sessions and the ceiling was never reached. The fd-reserve and
    respawn streams set `unbounded_responses` (D-j already says so for
    the perf UDP hold; D-f did not). (2) 4,032 keep-alive connections
    opened one request at a time took longer than the 75 s
    `downstream_idle_timeout_s`, so the first ones were closed before
    their second request: `http_loop.py hold` now runs its requests 32 at
    a time, which keeps one upstream connection per window rather than
    one per held connection. (3) The idle stop measured 25 s once: the
    respawn scenario's deleted stream still held a session draining with
    `config_removed`, and a stop keeps the earlier deadline (12.2 D-g),
    as designed. The stop scenario now waits until the node holds no
    stream connection or session before its idle stop.
  - **Deviations.** (1) `12.2-ac5-budget-refuses-range`: 12.2 Lot H
    reads "a 1,024-port UDP range refused with the supervisor constraint
    named", written before 12.5 gave a UDP session one fd. At fd limit
    4096 (`S` = 1024), 1,024 ports plus at least one session is 1,025
    fds in one worker, and the worker constraint is checked first, so
    that range is refused `worker_fds`. The scenario asserts that, then a
    600-port range (fits one worker, 1,201 supervisor fds) refused
    `supervisor_fds`, then a 100-port range accepted. (2) A
    `streams-single-probe` service: 12.2 Lot H asks for a runner in each
    profile's namespaces, and IV2 and the stop path need one in
    single-process mode. (3) The probe cannot tell which worker owns a
    socket: it is root without `CAP_SYS_PTRACE`, and the workers, started
    with an ambient capability, are not dumpable. The respawn scenario
    kills workers one at a time, waiting for each respawn, until the
    client's session socket is gone (one kill or two), so the killed set
    always includes the worker that served the client. (4) The stop
    path's exit time is Docker's `FinishedAt` against the SIGTERM time
    the probe prints, both the VM's clock: the probe cannot time the exit
    itself, since it shares the node's pid namespace and dies with it.
  - **Helpers for later Lots** live in `l4/scenarios/12.2.sh` (`l4s_*`):
    a client-side prelude with `api` and `api_try` that wait out a 429
    of the management API's rate limits (stream writes 100 per minute,
    backends 60, settings 30), `l4s_node_api_script` (lib.sh's API
    script aimed at another node), `l4s_wait_bind`,
    `l4s_create_stream`/`backend` (they return the refusal instead of
    calling `fail`: a verdict printed inside a command substitution
    would land in the variable and the report would see no line),
    `l4s_http_ready` (the `l4-http.test` route to `http_loop.py serve`),
    the loop, the echo backends, `l4s_cleanup_streams <prefix>`. A
    deleted UDP stream with live sessions keeps its port for the drain:
    give every scenario its own ports.
    *Amended 2026-11-24 (Phase 1 audit C32): the shared helpers moved
    from `12.2.sh` to `l4/lib.sh`, with the ones 12.3.sh lent to later
    Lots (`l4c_backend`, `l4c_ip`, the reason-count and health waits,
    `l4c_subnet_address`, `l4c_count`, the interface lookup) renamed
    `l4s_*`, and the copies of a `jq` and a tool runner in 12.5.sh and
    12.6.sh merged as `l4s_jq` and `l4s_tool`. A scenario file now runs
    with `lib.sh` and itself alone: its own helpers keep its prefix, and
    `run-l4.sh` refuses to start (exit 2) when a file names an `l4<x>_*`
    or `L4<X>_*` name that neither `lib.sh` nor the file defines
    (`l4_check_scenario_files`).*
  - **The fd-reserve test client**: one address, 3,378 UDP sockets and
    4,032 TCP connections, within Docker's default `nofile`; the budget
    nodes are `lorica-budget-4k` and `lorica-budget-8k`, worker mode,
    their own `/shared`, no `l4-node` alias.

- **Lot C, 2026-11-20.** Story 12.3's IVs and the TCP rows of the parity
  matrix, on `4ace5482` (the e2e images rebuilt for it).
  - **Verdicts** (`./run.sh --only-l4`, Lots A to C, 416 s for the phase
    with the report), all PASS:
    `12.3-iv1-pg-balance-and-failover` (three `postgres:17.12` servers,
    `psql` from `pg-client`: round robin 100/99/101 over 300
    connections, consistent hash 300 on one server, random
    119/102/79, least connections 9/10/11 over 30 overlapping
    sessions, peak EWMA 7/45/48 reported; one server killed, marked down
    in about 16 s, then 100 new connections all on the two survivors; a
    session held on a survivor across the kill finished its queries);
    `12.3-iv2-shared-backend-down-both-planes` (route and stream 20 of
    20 on the other backend once the shared one was marked down, about
    13 s after its listener closed; the stream connection established
    before answered 35 pings, 0 failures);
    `12.3-iv3-proxy-v2-send-and-accept` (v2 carries the client address;
    an untrusted v1 and v2 header are closed and counted
    `proxy_header_invalid`; a trusted header's 203.0.113.7 reaches the
    backend through a v2 send and the access-log row);
    `12.3-iv4-local-backend-refused-and-rebind-excluded` PASS in full,
    not partial: the management port is refused 409
    `stream_local_backend` with the flag and without, and a CoreDNS name
    moved to 127.0.0.1 was excluded within 5 s, ten connections closed
    with nothing forwarded, two exclusions counted in
    `lorica_stream_backend_dns_local_excluded_total` (Docker's embedded
    DNS forwarded the 5 s TTL as is);
    `12.3-matrix-backup-backends`, `-bandwidth` (64 KiB at 16 KiB/s
    each way in about 3.05 s, one second of burst; unlimited 1 ms),
    `-timeouts` (0.501, 2.001 and 3.002 s, with their three end reasons),
    `-proxy-bind`, `-port-range` (16 ports, N to N).
  - **No product defect found.** Corrected in the scenarios: IV4's
    first half expected 422 without `allow_local_backend`; rule B
    answers 409 for a node's own port whatever the flag, as
    docs/streams.md states, and is checked first. A killed backend's
    health flip takes three probes at the loop's 5 s floor, each up to
    the 5 s connect timeout, so the waits allow 45 s (16 s measured).
    Counters are read with a short poll: a connection's end is counted
    when its task finishes, a moment after the client sees the close.
    Observed, not a defect: an untrusted PROXY header on a stream with
    no backend linked ends `no_healthy_backend`, since the backend is
    chosen before the first bytes are inspected; with a backend it ends
    `proxy_header_invalid`, and either way nothing is forwarded.
  - **Deviations.** `NET_ADMIN` on `streams-probe` (Resolved 17) to give
    the node its second address. The client tools are one Python string
    in `l4/scenarios/12.3.sh` (`L4C_TCP_CLIENT`), since the Lot's
    allowlist names no client file. The CoreDNS zone is a hosts file the
    scenario copies into the container (`docker compose cp`, the image
    has no shell); `l4/coredns/` holds the Corefile only. The worker node
    joins a network `l4-dns` (10.89.53.0/24) where CoreDNS has a fixed
    address, which `dns:` needs. `tcp_backend.py` also reports the TCP
    peer (`peer=`), which the proxy-bind row reads.

- **Lot F, 2026-11-21.** Story 12.6's IVs, an IP allow/deny entry and
  the concurrency-caps row, lane 2 on `c01536bb`.
  - **Verdicts**, all PASS in both runs (`L4_LOTS=A,F,G`, 3 min 36 s for
    the phase with the report; `L4_LOTS=A,B,C,F,G`, about 10 min 16 s,
    Lots A to C PASS beside them). Numbers from the first:
    `12.6-iv1-source-rate-refused-other-served` (`source_open_rate` 5:
    30 connects in one second from the US address, 9 served, 21 closed
    before any echo, 21 counted `source_open_rate`; 3 of 3 from the `l4`
    address served in the same second; the access log holds 2 refusal
    rows, one per worker, and 2 suppressed rows counting the other 19);
    `12.6-iv2-geo-deny-tcp-and-udp` (GeoIP denylist `US`: TCP closed with
    no echo and UDP unanswered from the US address, both served from the
    `l4` address, which the test database does not know; both counted
    `geoip` with access-log rows; a TCP stream denying the US /32 and a
    UDP stream allowing the `l4` /32 with no explicit session cap each
    serve one source and refuse the other, counted `source_denied`);
    `12.6-iv3-10k-silent-pending-cap` (10,000 silent connections at
    1,000 a second from one address: at most 32 held at once, the share;
    9,936 closed at once and counted `source_pending_cap`, 64 at their
    5 s ClientHello deadline; 66 of 66 TLS handshakes from `l4` completed
    throughout; 2 refusal rows and 2 suppressed rows counting 9,934.
    Then nine US addresses x 40: at most 256 held, the cap; a TLS
    connection opened before echoed 24 times with no failure; 0 of 10
    new handshakes completed while the cap was full (`pending_cap`), the
    last refused at 4.97 s, 16 of 16 completed from 7 s);
    `12.6-matrix-concurrency-caps` (`max_connections` 5 with
    `source_max_connections` 3: three held from one source, its fourth
    refused `source_connection_cap`, two from another, its third refused
    `connection_cap`; `backend_max_active` 1 and 2 on two backends: one
    and two held, the fourth refused `backend_cap`).
  - **No product defect found.**
  - **Deviations**, recorded in Story 12.6's Dev Agent Record with the
    reason for each: the client is connected to `streams-geo` by each
    Story 12.6 scenario and disconnected when it ends (attached for the
    whole profile, its host name resolved to either address and broke
    `12.3-iv3` once); its US address is the one Docker gives it on the
    lane's /24, not `214.78.120.5`; the node reaches `streams-geo` under
    the alias `l4-node-geo`; the refusal rows are read in
    `GET /api/v1/stream-logs`, where the limiter writes at most one per
    worker per window, so IV1 accepts one row per worker and checks that
    rows plus suppressed counts equal the counter; IV3 counts a silent
    socket as held once it has been open a second, so a refusal not yet
    read as a close is not counted. The IP-literal entries are in
    `12.6-iv2`, as Lot A's note asked.

- **Lot G, 2026-11-21.** Story 12.7 IV1 and the SMTP banner template,
  lane 2 on `c01536bb`, in the same two runs as Lot F.
  - **Verdicts**, both PASS in both runs:
    `12.7-iv1-redis-paused-marked-down` (the pinned `redis:7.4.12`
    behind a TCP stream beside `tcp-backend-2`, its backend on
    `tcp_template{redis_ping}` at a 5 s interval and a 1,000 ms timeout:
    healthy, the stream split 5/5; `docker pause`: marked down in 11.9
    and 15.9 s, 3 `response_timeout` probe failures, then 10 of 10 on
    `tcp-backend-2`; `docker unpause`: healthy again in 13.7 s and
    selected again);
    `12.7-x-smtp-banner-template` (`smtp_banner.py` in two services:
    the backend on the server writing `220 example.com ESMTP` stays
    healthy with no failed probe over 3 probes; the one on the server
    that never writes is marked down 12.9 and 12.2 s after its create,
    3 `response_timeout` failures).
  - **Backend-side noise**, written into `docs/health-checks.md`: Redis
    accepted one connection per probe (3 over 3 intervals) and logged
    no line; `pg-1` logged no line over 3 or more
    `postgresql_ssl_request` probes; the banner server saw each probe
    end as `ConnectionResetError`, since the probe reads only the
    expected prefix and drops the connection with the rest of the
    greeting unread (`read_budget` in `lorica/src/health.rs`).
  - **The flip bound.** The Lot's text bounds a flip by
    `HEALTH_FLIP_THRESHOLD` x the interval plus the timeout, 16 s here.
    The scenarios allow 20 s: one second more per probe for the health
    loop's tick (`HEALTH_LOOP_TICK`, 1 s, ticks delayed by a probe
    waiting out its timeout), and one for the API poll. The flips
    measured in the six lane-2 runs that reached these rows since
    2026-11-20 (the first agent's four, these two) ran from 11.9 to
    17.8 s, so the strict 16 s would fail on timing alone.
  - **No product defect found.** One observation, recorded in Story
    12.7: a probe whose expected answer is shorter than what the server
    writes ends the connection with a reset, not a FIN. Neither the AC
    nor the IV depends on it.
  - **Deviations.** None from the Lot's items. The runner Dockerfile
    needed no change: it already copies `test-runner/l4/` whole.
- **Lot H, 2026-11-20.** Story 12.8's scenarios, in the `geoip` and
  `workers` profiles (L4 lane 3, `feat/v1.11.0` at `c01536bb`).
  - **Verdicts** (`L4_IMAGE_TAG=lane3 L4_LOTS=H ./run.sh --keep` with
    every pre-existing phase but Phase 1, `workers` and `geoip` skipped,
    and `--skip-l4`; 7 min 9 s, Phase 1 included):
    `12.8-iv1-proxy-v2-https-real-client` PASS in `geoip` (v2 headers
    from the runner, HTTPS `required`, the runner's /32 trusted: carried
    US `214.78.120.5` 403 and KR `2001:220::1` 200 by the route's GeoIP
    denylist; access-log rows with those client addresses and `is_xff`
    false; the echo backend got `X-Real-IP 2001:220::1` and it as the
    last `X-Forwarded-For` entry; on a per-IP bucket of 2, one carried
    address answered 200 200 429 and another 200;
    `lorica_proxy_protocol_accepted_total{listener="https",kind="v2"}`
    grew); `12.8-iv2-untrusted-and-forged-xff` PASS in `geoip` and in
    `workers` (a trusted v2 header carrying `198.51.100.20` with a
    forged `X-Forwarded-For: 192.0.2.99`: logged as `198.51.100.20`,
    `is_xff` false, no row with the forged address, the backend got
    `X-Forwarded-For: 192.0.2.99, 198.51.100.20`; with the trust list
    moved to a TEST-NET address, a v1 and a v2 header from the runner
    were disconnected without a byte, `untrusted_peer` counted exactly 2,
    and plain HTTPS requests from the same runner answered 200). The
    `geoip` smoke trusts `0.0.0.0/0` in `trusted_proxies`, so only the
    no-stacking rule kept the forged address out. Report: Lot H rows
    PASS, the others `NOT-RUN`, `=== L4 REPORT PASSED ===`.
  - **`12.8-iv3-proxy-off-suite-unchanged`** is printed by `run.sh`
    after its last pre-existing phase, under `L4-PROFILE suite`, only
    when no pre-existing phase was skipped: `PARTIAL` with D-d's note
    when they all passed, `FAIL` otherwise. Not run here (the full
    pre-existing suite is Lot O's); the block was run on its own with
    the four flag combinations that matter and its line fed to the
    report, which reads it `PARTIAL` from a `partial` row and passes.
    Both sections that turn PROXY accept on put the three settings back
    to off and delete what they created (checked in `geoip`'s store
    after the run), so the profiles after them start as before.
  - **No product defect found.** One first-run failure was the smoke's:
    `helpers.sh` resets `SESSION` when sourced, so the caller's session
    is read before it.
  - **Lot A's note settled.** `run.sh` gains the `geoip` phase (Phase
    2b, after `workers`, `--skip-geoip`, skipped by `--only-l4`): the
    profile existed and no run ever ran it. Its existing smoke passed
    unchanged.
  - **Choices.** The scenarios live in `run-proxy-protocol-smoke.sh`,
    called once at the end of each host smoke with its session, and print
    their own `L4-SCENARIO` lines; a failure there also fails the host
    smoke. IV1 runs in `geoip` only (the GeoIP test database is mounted
    there); IV2 runs in both, as the registry row says. The HTTPS
    listener is the node's `:8443` with a self-signed certificate per
    route: the listener is registered at boot with or without
    certificates (`startup/single.rs`, `startup/worker.rs`), so the
    "no certificates at boot" caveat in `run-tests.sh` does not apply.
    No `docker-compose.yml` change was needed.
  - **Shared-project hygiene.** The run held the main-compose lock, built
    only the services it ran, used `--keep` so `run.sh` would not tear
    down the plain `lorica-e2e-l4` project (the report container is the
    only thing it put there, with no network), then tore the main
    project down itself.
  - **Re-verified 2026-11-21** after the lane was interrupted before its
    report: the main-compose images this run uses rebuilt from the lane
    worktree under the lock, then the same `run.sh` invocation. Phase 1
    passed, `workers` 91 of 91, `geoip` 16 of 16; `12.8-iv1-*` PASS in
    `geoip` (accepted v2 0 to 7, per-IP bucket 200 200 429 then 200 for
    the other address), `12.8-iv2-*` PASS in `geoip` and `workers`
    (`untrusted_peer` 0 to 2 in each), `12.8-iv3-*` `NOT-RUN` as
    expected on a partial run; `=== L4 REPORT PASSED ===`; 7 min 7 s.
    The `suite` block of `run.sh` was exercised alone again: `PARTIAL`
    after a complete passing run, `FAIL` after a failed phase, nothing
    when Phase 1 or any phase is skipped. Nothing changed in the files.

- **Lot I, 2026-11-20.** Story 12.9's scenarios in the `streams` profile
  (L4 lane 3, `feat/v1.11.0` at `c01536bb` plus Lot H).
  - **Verdicts** (`L4_LANE=3 L4_IMAGE_TAG=lane3 L4_LOTS=I ./run.sh
    --only-l4`, 2 min 20 s for the phase with both boots and the report,
    run twice with the same results):
    `12.9-iv1-end-reasons-in-api-and-syslog` PARTIAL with D-d's note
    (refused: a stream whose `source_deny_cidrs` holds the client; the
    first row is `ended`, `refused`, `source_denied`, with the client's
    address; one connect then a burst of 30 gave 2 refused rows and 2
    `refusals_suppressed` rows counting 29, so every one of the 31
    refusals is accounted for and each process wrote at most one row per
    window; idle timeout: the silent connection closed after 2.00 s on a
    2 s timeout, one `idle_timeout` row; `config_removed`: with
    `worker_drain_timeout_s` 3, unlinking the backend under an open
    connection gave the row 3.2 s after the update, the connection closed
    3.1 s after; each row also a syslog frame with MSGID `stream` and the
    same words in its body); `12.9-x-metrics-and-sink-up` PASS
    (`lorica_stream_ended_total{reason="idle_timeout"}` 1 and
    `lorica_stream_bytes_total` 56 for the stream on the supervisor's
    `/metrics`, values only the workers hold;
    `lorica_log_sink_up{sink="syslog"}` 1, then 0 about 1.1 to 1.2 s
    after the collector's `FinishedAt`, then 1 about 1.7 to 2.2 s after
    its `StartedAt`, with no traffic between); `12.9-x-stream-sla` PASS
    (after 5 connections, the `1h` window judged 5, 5 successes, 0
    failures, 100 %).
  - **No product defect found**; every scenario passed on its first run.
  - **Deviations.** (1) No logs-only OTel collector: the L4 image is
    built without the `otel` feature (one image for every L4 node), so an
    OTLP lane cannot run there, and none of 12.9 Lot J's assertions reads
    it; a collector nobody sends to would prove nothing. (2) The burst
    bound is per process: the limiter keeps one window per key in each
    process (`lorica-stream/src/refusal_log.rs`), so with two workers a
    burst gives up to two refused rows and two `refusals_suppressed`
    rows, not "the limiter's rows plus one"; the scenario asserts that
    bound and that the rows account for every refusal. (3) The syslog
    collector writes one file per TCP connection, as the
    `log-sinks-workers` one does, since each worker holds its own
    connection. (4) The gauge's two delays are measured from Docker's
    `FinishedAt` and `StartedAt` to the moment a poll in the client read
    the new value, both on the VM clock; the poll runs every 0.5 s, so
    the figures are upper bounds.
  - **Ports** 7910 to 7914 and names `l4o-*` (streams and backends),
    removed with the settings put back (`worker_drain_timeout_s` 30, no
    syslog endpoint) by each scenario's cleanup.
  - **Re-verified 2026-11-21** after the lane was interrupted before its
    report: `l4/build-images.sh` (every layer cached, so the images are
    the ones the first runs used), then the same lane run, 2 min 18 s.
    Same verdicts: IV1 PARTIAL with D-d's note (2 refused rows and 2
    `refusals_suppressed` rows counting 29 for 31 refusals; idle close
    at 2.00 s; `config_removed` row 3.2 s after the update, connection
    closed 3.1 s after), metrics and gauge PASS (0 at 1.2 s after the
    stop, 1 at 1.8 s after the start), SLA PASS (5 judged, 5 successes);
    `=== L4 REPORT PASSED ===`; the lane project left nothing behind.
    Nothing changed in the files.
- **Lot K, 2026-11-21.** Story 12.11's IV1 and its three handover
  scenarios, a section appended to `run-hot-upgrade-smoke.sh` after the
  Story 8.4 assertions: a second upgrade of the same binary once the
  first one's old generation has left, `worker_drain_timeout_s` 120,
  three streams bound (SSH, a bounded UDP stream, a 64-port TCP range).
  - **Verdicts** (lane 4, the `hot-upgrade` phase alone under the
    main-compose lock, then the report with `--lots J,K`), all PASS:
    `12.11-iv1-stream-ssh-drained-by-upgrade` (preview
    `drain_timeout_s=120`, the SSH stream `established=1`
    `on_upgrade=drain`; the session still printed at T0 + 115 s and
    ended at T0 + 121 s with "closed by remote host", a FIN; one
    stream-log row `drained_by_upgrade`; the new generation's `/metrics`
    then showed `lorica_hot_upgrade_stream_connections_total{outcome="drained"} 1`
    for the stream, `lorica_hot_upgrade_drain_seconds_count` 1 and
    `lorica_hot_upgrade_total{outcome="completed"}` 1);
    `12.11-x-stream-new-connection-after-upgrade` (the API answered from
    the new supervisor 1 s after T0 and, at T0 + 15 s, the preview named
    the old one as `previous_generation`; a session opened at T0 + 10 s
    still printed at T0 + 150 s with the old generation gone);
    `12.11-x-udp-across-upgrade` (700 queries 50 ms apart from T0 - 3 s
    to T0 + 32 s on one socket, every one answered within 1 s, no
    `binding_draining` drop; the stream previewed `relay_in_flight`);
    `12.11-x-fd-transfer-past-32` (64 of 64 range ports and the UDP
    stream answered before and after; upgrade `completed`).
  - **No product defect found.** The first run's four FAILs were the
    scenario's: the UDP stream listened on `0.0.0.0` without a source
    allowlist or an explicit `udp.source_session_cap`, which the
    exposed-address rule refuses (422, docs/streams.md); it now sets
    `udp.source_session_cap` 64, which also makes `udp` present, so its
    upgrade policy is `relay_in_flight` as the scenario expects.
  - **Topology.** `ssh-backend` (new image on the pinned
    `debian:bookworm-20261104-slim` digest with `openssh-server`, host
    and client keys generated at start, the client's private key
    published on `shared-hot-upgrade`, nothing in the image or the
    repository) and `hot-upgrade-l4-backends` (the runner image:
    `udp_hold.py serve` on 5300 and `tcp_backend.py` on 7400 to 7463),
    both in the `hot-upgrade` profile; the smoke depends on them.
  - **Run time.** The section adds about 155 s to the `hot-upgrade`
    phase (173 s for the whole phase in this run), most of it the 120 s
    drain IV1 waits out.
  - **Not done here.** 12.11 Lot G's last box ("the full suite passes
    with the machine to itself") stays open: this run held the
    main-compose lock, not the machine, since L4 lanes 1 and 2 ran their
    own projects at the same time. IV1 is timing-bound and passed
    regardless; the release run (Lot O) is where the machine is alone.

- **Lot J, 2026-11-21.** Story 12.10 IV1 and Story 12.7 IV2, a streams
  section appended to `run-mcp-smoke.sh` after the Story 11.4
  assertions; each scenario prints its line at the section's end.
  - **Verdicts** (lane 4, the `mcp` phase alone under the main-compose
    lock, then the report with `--lots J,K`):
    `12.10-iv1-dashboard-stream-visible-read-only` PARTIAL with its D-d
    note (the Lot D2 fixture body posted by a management session, not a
    browser click): `iv1-tcp` created 201 and listening on 40100 (read
    from `/proc/net/tcp` in the node's namespace, the image has no
    `ss`); a `--tier read` token lists it on `/automation/v1/streams`
    and reads `bind.state` `bound` on `/automation/v1/streams/status`;
    the read-tier MCP session finds it through `lorica_streams` and
    `lorica_stream_status`; the config (19 tools) and admin (2 tools)
    tiers list no stream tool; `lorica_backend_delete` on its backend is
    refused listing the stream's id and the backend stays; a token
    holding all 14 scopes gets 403 on POST, PUT and DELETE of
    `/automation/v1/streams` and `/automation/v1/streams/{id}`, five
    audit rows `automation.request.forbidden:no_declared_scope`; one
    `stream.create` row by the admin session, chain verified.
    `12.7-iv2-template-yes-payload-no` PASS: a `backends:write` config
    token creates a `tcp_template` (`redis_ping`) backend on the
    automation API (201) and moves it to `smtp_banner` through
    `lorica_backend_update`; a raw send/expect payload is refused on
    POST and PUT (403, nothing stored, the template kept) and by the MCP
    tool naming `send`, with no audit row, so no plane call.
  - **No product defect found.** Three runs; the failures were the
    scenario's. (1) The management API admits five logins a minute per
    address and every CLI mint logs in: the smoke's own login and four
    mints use the window up, so the section's mints were refused 429.
    They now retry once the window has rolled. (2) A token carrying
    `settings:write` is refused past a seven-day lifetime: the
    every-scope mint passes `--lifetime-days 1`. (3) 12.10 Lot H reads
    "403 `no_declared_scope`"; the 403 body says the path "declares no
    automation scope and is reachable by no token", and
    `no_declared_scope` is the refusal's reason, in the audit row's
    action, as docs/automation.md's reasons table states. The scenario
    asserts both.
  - **Run time.** The section adds about 50 s to the `mcp` phase (72 s
    for the whole phase), most of it waiting out the login window.
  - **Not done here.** 12.10 Lot H's last box ("run alone on the
    machine") stays open: this run held the main-compose lock while L4
    lanes ran their own projects. 12.7 has no handed-over e2e Lot (its
    IV2 is automated in its Lot 2), so nothing is ticked there.
- **Lot D, 2026-11-20.** Story 12.4's IVs, the two-CA proof, upstream
  mTLS and key replication, on `c01536bb` (lane 1).
  - **Verdicts**, all PASS. In lane 1 (`L4_LANE=1 L4_LOTS=D
    ./run.sh --only-l4`, 41 s for the phase with the report):
    `12.4-iv1-sni-passthrough-two-names` (one.l4d.test and two.l4d.test
    on one passthrough port to `tls-raw-1` and `tls-raw-2`, each
    reporting the SHA-256 of the 517-byte ClientHello the client sent;
    alpn.l4d.test offering `h2` to one backend, `http/1.1` alone to the
    other; three.l4d.test closed, one `no_match` counted);
    `12.4-ac5-two-cas-two-streams` (each client certificate served on its
    own stream and refused on the other, no certificate refused on both);
    `12.4-ac4-upstream-mtls` (the Python `ssl` backend verified the
    stored client identity and saw the fixed name). In the `acme` and
    `cluster` phases of the plain layout on `44d6248b` (the main compose
    project, before lanes; the smoke sections are unchanged since):
    `12.4-iv2-acme-renewal-on-terminating-stream` PASS, not partial: the
    renewal is forced through `POST /api/v1/certificates/{id}/renew` on
    Pebble, in place (same id), new connections present the renewed
    certificate's fingerprint and the connection opened before kept
    echoing (124 pings, 0 failures); `12.4-x-key-replication-targeted`.
  - **Product defect found and fixed**: the per-recipient cut of the
    replicated configuration dropped a stream's certificates (Debug Log,
    `44d6248b`). The first key-replication run failed on it (TLS alert
    49 through edge-a's stream).
  - **Deviations.** (1) Key replication: 12.4 Lot H expected the
    untargeted follower to hold both rows without a key. Since Story
    10.0 a node receives only the certificates of what it serves
    (`restrict_for_recipient`), so it holds neither row nor key, and the
    scenario asserts that. After the retarget, what edge-a keeps is
    asserted as the cluster smoke asserts a retargeted route: the
    roster's entitlement (`certificate_ids` of
    `GET /api/v1/cluster/nodes`) plus what the node's own API holds; it
    is no longer entitled, holds neither row nor key (the apply deletes
    a row the blob dropped), and no longer serves the stream. (2) Files:
    `test-runner/l4/tls_backend.py` and `l4/scenarios/12.4.sh` replace
    12.4 Lot H's `test-runner/tls_backend.py` and `run-streams-tls.sh`;
    the runner Dockerfile's `COPY l4/` already ships the tool, so it is
    unchanged. (3) The renewal waits out a 429: the two issuances of the
    ACME smoke spend the same bucket (3 a minute per address); the first
    run failed on it. (4) The TLS backend's PKI goes from the client to
    `tls-backend` through `${L4_RESULTS}-l4d-*` files on the host, one
    file at a time.

- **Lot E, 2026-11-20.** Story 12.5's IVs, the Lot I items and the UDP
  idle-timeout row, on `3857b24e` (lane 1).
  - **Verdicts** (`L4_LANE=1 L4_LOTS=E ./run.sh --only-l4`, 316 s for
    the phase with the report), all PASS:
    `12.5-iv1-reflection-bounded` (600,000 spoofed datagrams at 20,000/s
    for 30 s; the victim received 30,950 datagrams, a mean of 1,857,000
    B/s against the bound 8,192,000, worst second 3,405,600 B against
    2 x 8,192,000; exactly one 1,800-byte response per request accepted from its
    key, 568,938 `source_datagram_rate` drops; the legitimate client got
    300 of 300 answers); `12.5-ac2-byte-bound` (the victim received
    nothing, 0 response bytes forwarded, 30,993 `response_byte_bound`
    drops, each session ending `response_bound_reached`);
    `12.5-ac5-table-isolation` (300,000 datagrams from random sources:
    145,473 refusals on stream A, all `session_table_full`; stream B's
    client answered 150 of 150, no refusal on B);
    `12.5-iv2-dns-above-capacity-all-answered` (dnsperf, 49,200 queries
    at 820/s for 60 s over 64 source ports, every one answered within
    2 s and NOERROR; no refusal, no drop; 49,200 sessions, every one
    ended `response_bound_reached`; the session gauge peaked at 1);
    `12.5-x-reply-source-address`; `12.5-x-worker-death-no-leaked-count`
    (a stream holding 200 sessions went to 111 after the kill, equal to
    the upstream sockets still open; the DNS stream's total back to 0;
    8,200 of 8,200 queries answered after the respawn);
    `12.5-ac6-budget-refuses-second-stream` ("worker fds: 8194 committed
    exceed the stream budget of 7168 (fd limit 16384, ...)");
    `12.5-matrix-udp-idle-timeout` (closed 2.005 s after the last
    datagram, one session across a datagram at 1.5 s).
  - **No product defect found.** First-run failures were the
    scenarios': the host has no `jq` (every host-side read now runs `jq`
    in the client), and the stream counters are no clock in worker mode,
    since the workers' counters reach the API with the supervisor's
    heartbeat round every 5 s: the idle timeout first measured 4.7 s from
    the counter. It is now timed in the probe on the session's upstream
    socket, and every counter read after a load waits until the counters
    have not moved for 7 s.
  - **Deviations.** (1) 12.5 Lot I's IV1 expects `response_count_bound`
    drops to be non-zero. With `responses_per_request` 1 a session ends
    under the lock of its first forwarded response (D-b), so the other 9
    datagrams of the amplifier reach a closed upstream socket and no
    session counts them; the counter stays 0 and the scenario reports
    it. The count bound is asserted by its effect instead: at most one
    datagram at the victim per request accepted from its key. The
    reflection bound holds either way; `docs/streams.md` ("How a session
    ends") does not say that responses past the count arriving after the
    end go uncounted. (2) The victim binds the spoofer's 2,000 source
    ports rather than reading a raw socket, so it needs no privilege;
    the spoofer alone has `NET_RAW` (D-p). (3) Table isolation spoofs
    sources in 198.18.0.0/15 (RFC 2544) against a backend answering past
    the byte bound, so nothing is ever sent to those addresses and the
    node's neighbour table is not flooded; the table that fills is the
    rate table (4 cells per session of `max_sessions`, evicted every
    second), whose full window refuses `session_table_full`. (4) The
    AC #6 node is a new budget node, `lorica-budget-16k` (fd limit
    16,384, `S` 7,168), the limit at which one default UDP stream fits
    and two do not; Lot B's nodes are too small for one. (5) The second
    resolver is `coredns-2`; both serve `iv2.test` from
    `l4/coredns/iv2.test.zone`, a block added to Lot C's Corefile.
    `dns-loadgen` runs the `perf-tools` image, which
    `l4/build-images.sh` now builds for the lanes. (6) Worker death
    asserts the "no leaked count" on a stream holding 200 sessions
    (`responses_per_request` 0, a 300 s idle timeout) beside IV2's load:
    the DNS load alone holds about one session at a time, too few for a
    leak to show.

- **Lots D and E re-verified, 2026-11-21, lane 1** (Debug Log). In the
  lane (`L4_LANE=1 L4_LOTS=D,E,L ./run.sh --only-l4`, 360 s for the
  phase with the report, report PASSED) every Lot D and Lot E row PASS:
  IV1 the 517-byte ClientHello byte for byte on both names and the ALPN
  pair, one `no_match`; the reflection bound with 30,998 datagrams at
  the victim for 30,998 requests from its key, a mean of 1,859,880 B/s,
  worst second 3,506,400 B, client 300 of 300; byte bound 30,993
  `response_byte_bound` drops and nothing at the victim; table isolation
  145,008 `session_table_full` and nothing else, B 150 of 150; IV2
  49,200 of 49,200 within 2 s; worker death 200 to 102 sessions, equal
  to the sockets alive; the budget refusal; idle close at 2.005 s. IV1
  alone, seven more runs, all PASS after the one failure the Debug Log
  explains. In the main project, from the lane 1 worktree under the
  shared lock (images built from it, the `acme`, `cluster` and
  `hot-upgrade` phases as `run.sh` runs them, nothing else):
  `12.4-iv2-acme-renewal-on-terminating-stream` PASS (renewed in place,
  the new fingerprint served, 124 pings on the held connection, 0
  failures) and `12.4-x-key-replication-targeted` PASS; the whole
  `cluster` phase passed after them (smoke 69 of 69, restart, automation,
  MCP and revocation runners).

- **Lot L, 2026-11-21, lane 1.** Story 12.1's IVs and both rollbacks to
  1.10.7 (D-h), on `8b19f19f` plus this Lot.
  - **Verdicts.** `12.1-iv1-targeted-stream-binds-on-one-node` PASS (a
    TCP stream with selector `["edge-a"]`: listed by edge-a's own API
    and held by the control plane's, absent from edge-b's once edge-b
    had applied edge-a's generation, 11; backend1 answered 200 through
    edge-a:7602; edge-b:7602 and the control plane's 7602 refused).
    `12.1-iv2-follower-https-port-refused` PASS (409: "port 8443 is
    reserved on node `edge-a`: a proxy listener port (https listener)",
    the port read from edge-a's own `GET /api/v1/system`).
    `12.1-ac3-rollback-cold-1.10.7` PASS, in the lane run and alone:
    schema_migrations 80 rows, max 80, unchanged by `lorica 1.10.7`,
    which served the route (200), bound nothing on the stream's port
    (refused) and listed both backends; the path set to `/x` through
    its API; back on 1.11.0 the first backend reads `http /x` with
    `health_check_path` `/x`, the send/expect check and the stream with
    its link are unchanged, and the stream binds and echoes again.
    `12.1-ac3-rollback-hot-1.10.7` **FAIL, product defect** on that
    run, row `pending` with a comment naming it; PASS once fixed (below),
    row `live`.
  - **Product defect: a hot downgrade to 1.10.x turns a stream's port
    into an HTTP listener.** With one TCP stream bound, the signed
    1.10.7 upload completes the handoff (new pid, the stream API now
    404, 14,278 requests across it with none failed), and 1.10.7 then
    serves the stream's port as an HTTP proxy listener: through the
    port, `Host: hot-upgrade.local` answers 200 by the route and `Host:
    backend1` 404, where the stream had forwarded any host to backend1.
    1.10.7's log: "adopted inherited listener from outgoing supervisor"
    for `stream-tcp:<id>:1:0.0.0.0:7801`, then each worker "registered
    TCP listener" on that key. Cause: `send_table`
    (`lorica/src/startup/fd_transfer.rs`) sends a table that fits the
    legacy single message in it, stream entries included, and the
    1.10.x receiver's `partition_inherited_fds` files every key it does
    not know with the proxy listeners. Expected, per Resolved 7: 1.10.7
    refuses the handoff (the old generation keeps serving) or completes
    it without serving the stream's port as anything else. Unreleased
    (streams are 1.11.0's); the scenario stays and turns PASS on either
    outcome once fixed.
  - **Fixed, 2026-11-21: 1.10.7 now refuses the handoff.** A table
    holding any key a 1.8.0 to 1.10.x receiver would misfile (anything
    but the management, cluster and automation prefixes and a bare bind
    address: `hot_upgrade::legacy_receivers_file`) is sent chunked at
    any size, never as the legacy message. The chunked header now leads
    with `0xFF`, never UTF-8, so the fork's `get_from_sock` in every
    released receiver fails its key parse with `EINVAL` before taking a
    descriptor; 1.10.x logs "failed to pull inherited listeners;
    aborting" and exits (read from the 1.10.7 source and pinned by unit
    test, not seen in the e2e log, which keeps no node log on a pass).
    Before, the bare `lorica-fds/2` header parsed as two keys and no
    descriptor and tripped the fork's count assertion, a panic.
    Refusal over withholding the stream sockets: the outgoing side
    cannot tell the incoming binary's version before the transfer, and
    the refusal is safe against every released receiver at once. Tests
    `a_released_receiver_never_takes_a_stream_socket_for_an_http_listener`,
    `a_table_without_streams_still_hands_down_to_a_released_receiver`,
    `only_the_families_released_receivers_know_take_the_legacy_message`
    (`hot_upgrade.rs`),
    `a_table_holding_a_key_legacy_receivers_misfile_never_takes_the_legacy_message`,
    `the_chunked_header_is_not_utf8_from_its_first_byte` and the
    strengthened `a_chunked_table_fails_against_the_legacy_receiver_without_hanging`
    (`fd_transfer.rs`); both red runs recorded (without the key check
    the stream test fails on the legacy receiver taking the
    `stream-tcp:` key, without the lead byte the fork asserts at
    `transfer_fd/mod.rs:64`). Re-run of the `hot-upgrade` profile
    (`run.sh --build` with every other phase and the L4 phase skipped;
    Phase 1 runs regardless): smoke 52 of 52, Lot K's four rows PASS,
    `12.1-ac3-rollback-hot-1.10.7` PASS "1.10.7 refused the handoff
    (exec_failed 0 -> 1): the old generation kept serving, 1270
    requests 0 failed, route 200, backend1 through the stream 200";
    row set `live`, the report then PASSED (5 PASS). `docs/hot-upgrade.md`
    states the fixed behaviour; Story 12.11 D-d amended.
  - **Deviations.** (1) The registry row's order runs the cold rollback
    first in `streams-single`; it stops and restarts the node, and the
    12.2 rows after it pass on the restarted node (`L4_LOTS=A,B,L`, a
    third PASS of the cold rollback, report PASSED). (2) The baseline
    image `lorica-e2e/baseline:1.10.7` is one name for both compose
    files and every lane (it holds the signed release, not the tree);
    `l4/build-images.sh` builds it, in the `streams-single-baseline`
    profile of its own so `streams-single` never starts it, and the
    scenario's `up` builds it when missing (a release run's `--build`
    does not name that profile). (3) In the `hot-upgrade` profile,
    `hot-upgrade-baseline` copies the binary to the shared volume and
    the smoke `depends_on` it: one line outside "the baseline image
    service only", without which `run.sh`'s `up` of the node never
    starts it. (4) The hot rollback deletes any stream an earlier
    section left and waits until the upgrade preview lists its own
    alone, so Lot K's sections (not in this lane) cannot change the
    table it hands over. (5) `/api/v1/system`'s version is `MAJOR.MINOR`
    and reads 1.10 on both binaries until the bump, so the new
    generation is told by its stream API answering 404. (6) Story 12.1
    has no e2e checklist of its own to tick ("Handed to Story 12.12").

- **Lot M, 2026-11-21 and 22.** The performance phase, on `46890e68`
  (images `lorica-e2e-l4/lorica:lotm` built from this tree, `lorica
  --version` 1.10.9 before the bump; the baseline `lorica 1.10.7`).
  - **Topology** (`docker-compose.perf.yml`, project `lorica-e2e-perf`):
    `perf-lorica`, `perf-lorica-baseline` and `perf-nginx` on the proxy
    cpuset, each `--workers N` / `worker_processes N`, nofile 65,536;
    `perf-backend` (iperf3 server 5201, `l4_connect_latency.py serve`
    5202 with control 5203, `udp_echo_peers.py serve` 5300 with control
    5301) and `perf-backend-http` (nginx, static 200 with a 1 KiB body,
    `perf/nginx-http-backend.conf`) on the backends cpuset; `perf-client`
    (iperf3, oha, the tools, `perf/analyse.py`, the Lot B `udp_hold.py`
    mounted unchanged) on the load cpuset. Both Lorica versions start
    through `perf/entrypoint-perf.sh` with flags 1.10.7 knows, as the
    image's `lorica` user (ports above 1024; a same-user exec reads the
    workers' PSS). nginx's `stream` configuration mirrors the Lorica
    streams the driver creates: connect 5 s, idle 600 s TCP and 30 s
    UDP, 16 KiB buffers, a buffered per-connection access log, TCP on a
    shared listening socket and UDP with `reuseport` exactly as Lorica
    binds them, no bound on UDP responses or requests.
  - **Layout and guard** (`perf/run-perf.sh`): `docker info` 24 CPUs
    gives the larger layout (proxy `2-3`, load `4-5`, backends `6-7`,
    N = 2, read back from each container's `CpusetCpus`);
    `PERF_LAYOUT=small` forces proxy `1`, load `2`, backends `3`, N = 1;
    fewer than 4 CPUs writes a `NOT-RUN` report. The environment record
    (CPU count, memory, kernel, Docker version, image ids, commit and
    tree state, cpusets, versions) opens the runs file; the guard before
    every attempt lists running containers outside the project, and any
    makes every gated verdict `INCONCLUSIVE (environment)`. On the
    release run (`run.sh` without `--skip-*`/`--only-*`, which passes
    `PERF_RELEASE_RUN=1`), anything but the larger layout does too
    (Resolved 13).
  - **Statistics and output** (`perf/analyse.py`): one warm-up per arm,
    then 5 repetitions with the first arm rotating; spread IQR over
    median by the inclusive quartiles (the 4th minus the 2nd of 5);
    a check settles on its first attempt whose every series has 5 values
    within 5 %; a gated measurement re-runs whole while one of its checks
    is unsettled, at most `PERF_MAX_RERUNS` (3) times; `PASS`, `FAIL`,
    `INCONCLUSIVE`, `NOT-RUN`, `REPORTED` for the unguarded. Output:
    `results/perf-<ts>.runs.jsonl` (every run as it lands, raw numbers
    included), `perf-<ts>.json` and `perf-summary.md`. `run.sh`:
    `--skip-perf`, `--only-perf` (skips every other phase and the L4
    report), `--perf-advisory` (verdicts written, exit 0 on them; a
    harness error still exits 2); the phase runs last, after the other
    projects are torn down.
  - **Deviations.** (1) iperf3 `-P (8 x N)`, not `-P 4`, and a
    multi-worker run one process carried (over 90 % of the proxy's CPU
    ticks) is kept out of its series with its reason: Debug Log, with
    the evidence. (2) `l4_connect_latency.py` is one single-threaded
    non-blocking loop on each side rather than "a few threads": the open
    loop keeps its schedule (worst lag 1.5 ms), and no interpreter lock
    sits between a socket event and its stamp. (3) The Lorica TCP
    streams keep Lorica's defaults beyond what D-i names (backend
    keepalive on, where nginx's is off; no run lasts the 60 s before its
    first probe). (4) HTTPS NFR1
    runs one attempt, no re-run, since it gates nothing. (5) D-j's
    memory figure "PSS with S sessions minus before the fill" is the
    first fill only for each attempt's warm-up: Lorica's allocator keeps
    what a fill took (nginx frees it), so the later runs read what a
    refill adds. Both are in the report.
  - **The larger-layout dry run, the pre-fix baseline**
    (`./run.sh --only-perf --build`, `L4_IMAGE_TAG=lotm`, ended
    2026-11-22; `results/perf-20261121T221253Z.*`). **76.5 min** for the
    phase (4,591 s): `tcp-up` 402 s and `tcp-down` 402 s (two attempts
    each), `connect` 752 s (three), `udp` 523 s (one), `nfr1-http-rps`
    290 s (one), `nfr1-http-p99` 1,522 s (four), HTTPS 292 + 382 s.
    Verdicts, Lorica over nginx (over 1.10.7 for NFR1), median spread in
    brackets:

    | Check | Lorica / B arm | nginx / L arm | Ratio | Verdict |
    |---|---|---|---|---|
    | TCP upload throughput | 47.91 Gbit/s (2.4 %) | 52.98 (2.1 %) | 0.904 | PASS (attempt 2) |
    | TCP upload CPU per GiB | 0.3565 s (2.4 %) | 0.3223 (2.1 %) | 1.11 | PASS (attempt 2) |
    | TCP download throughput | 44.78 Gbit/s (1.3 %) | 50.84 (0.8 %) | 0.881 | **FAIL** (attempt 2; attempt 1 also 0.881) |
    | TCP download CPU per GiB | 0.3827 s (1.3 %) | 0.3363 (0.9 %) | 1.14 | PASS (attempt 2) |
    | Connect p99 | 485.7 us (4.3 %) | 397.3 (4.9 %) | 1.22 | PASS (attempt 3; 1.21 and 1.57 before) |
    | UDP hold, 21,766 sessions (80 % of 27,208, bound by `source_ports`) | 5 of 5 held | 5 of 5 | - | PASS |
    | PSS per 1,000 sessions, first fill | 3,541 KiB | 10,070 KiB | - | reported |
    | NFR1 HTTP req/s, L0 / B | 16,000 (2.7 %) | 15,940 (0.8 %) | 1.00 | PASS |
    | NFR1 HTTP req/s, L1 / B | 16,120 (0.8 %) | 15,940 (0.8 %) | 1.01 | PASS |
    | NFR1 HTTP p99 at 7,970 req/s, L0 / B | 2.168 ms (4.4 %) | 2.486 (23.0 %) | 0.872 | **INCONCLUSIVE** |
    | NFR1 HTTP p99, L1 / B | 2.575 ms (26.1 %) | 2.486 (23.0 %) | 1.04 | **INCONCLUSIVE** |
    | NFR1 HTTPS req/s, L0 and L1 / B | 13,310 and 13,370 | 13,100 (0.4 %) | 1.02, 1.02 | reported |
    | NFR1 HTTPS p99 at 6,550 req/s, L0 and L1 / B | 2.426 and 4.986 ms | 2.543 | 0.954, 1.96 | reported |

    **NFR1 HTTP p99, the four attempts** (ms, spread; L0, L1 against
    B): 1: 1.627 (5.4 %), 1.656 (17.2 %) against 1.799 (7.6 %), ratios
    0.904, 0.920; 2: 2.053 (25.3 %), 1.745 (21.5 %) against 2.130
    (16.1 %), 0.964, 0.819; 3: 2.063 (14.0 %), 1.917 (3.2 %) against
    2.099 (11.9 %), 0.983, 0.913; 4: 2.168 (4.4 %), 2.575 (26.1 %)
    against 2.486 (23.0 %), 0.872, 1.04. No ratio over the 1.05
    threshold in any attempt, no attempt with all three series within
    5 %: inconclusive, which blocks the release pending an owner
    decision (AC #3), and the method is to change before Lot O.
  - **Which series reach 5 % at all.** Throughput, CPU per GiB and
    saturation req/s: yes, routinely (0.3 to 2.7 %), once the
    accept-spread artefact is out. Every p99 series: rarely and by
    luck. Connect p99 at 4.3 to 21.4 % (its p50 stays within 1 to 3 %);
    NFR1 HTTP p99 at 3.2 to 26.1 %; HTTPS p99 has single runs at 127 ms
    and 18 ms, stalls of the Docker Desktop VM, not of a proxy.
  - **Product findings, not fixed here.** (1) **TCP download throughput
    0.881 x nginx, a conclusive FAIL**, with download CPU per GiB at
    1.14 (just under 1.15) and upload at 0.904 and 1.11. The proxy cores
    are saturated in every run, so throughput is the inverse of CPU per
    byte, and Lorica spends 11 to 14 % more CPU per GiB than nginx's
    copy loop; the download direction (backend to client) is the worse.
    Suspected cause: the forwarding copy path (`lorica-stream/src/tcp/forward.rs`,
    a 16 KiB buffer per direction and a userspace copy), i.e. the
    splice decision Story 12.3 handed to this story ("Handed to other
    stories"), to be taken on Lot O's numbers. (2) **Connect latency:
    Lorica's p50 is about 180 us against nginx's about 105 us**, stable
    in every run (the p99 passes at 1.22). Suspected cause, from the
    code, not measured: in worker mode every stream connect asks the
    supervisor for a breaker admission over the RPC channel
    (`StreamBreakerGate::admit`, `BreakerEngine::Rpc` in
    `lorica/src/proxy_wiring/engines.rs`) before dialling the backend,
    one round trip per connection that nginx does not make.
  - **Not done.** The small-layout dry run (see the task).

- **Lot M, 2026-11-24, the post-audit run.** Both layouts on
  `67573484` (the 1.10.10 merge and every Phase 1 audit fix lot), with
  D-k's amended p99 method; images `lorica-e2e-l4/{lorica,perf-tools}:perf2`
  built from that tree by `l4/build-images.sh` (`lorica --version`
  1.10.10 before the bump; the baseline `lorica 1.10.7`), the tree clean,
  no container outside the project. `L4_IMAGE_TAG=perf2 ./run.sh
  --only-perf`, then the same with `PERF_LAYOUT=small`; bootstrap seed
  12012, 2,000 resamples, 10 runs per p99 arm. No code changed.
  - **Larger layout** (`results/perf-20261124T014806Z.*`), proxy `2-3`,
    load `4-5`, backends `6-7`, N = 2: **64.9 min** (3,891 s; 76.5 min
    pre-fix): `tcp-up` 412 s and `tcp-down` 410 s (two attempts each,
    one nginx run per first attempt excluded on the one-worker guard),
    `connect` 463 s, `udp` 526 s, `nfr1-http-rps` 295 s, `nfr1-http-p99`
    729 s, HTTPS 294 + 731 s; every check settled or completed on its
    first eligible attempt.

    | Check | Lorica / L arm | nginx / B arm | Ratio, spread or 95 % interval | Verdict | Pre-fix |
    |---|---|---|---|---|---|
    | TCP upload throughput | 50.96 Gbit/s (0.7 %) | 52.32 (0.9 %) | 0.974 | PASS (attempt 2) | 0.904 PASS |
    | TCP upload CPU per GiB | 0.3363 s (0.8 %) | 0.3265 (0.9 %) | 1.03 | PASS (attempt 2) | 1.11 PASS |
    | TCP download throughput | 50.07 Gbit/s (1.6 %) | 50.62 (2.9 %) | 0.989 | PASS (attempt 2; attempt 1 also 0.989) | 0.881 FAIL |
    | TCP download CPU per GiB | 0.3422 s (1.6 %) | 0.3373 (3.0 %) | 1.01 | PASS (attempt 2) | 1.14 PASS |
    | Connect p99, pooled | 461.4 us | 320.6 | 1.44 [1.285, 1.642] | **INCONCLUSIVE** | 1.22 PASS (spread rule, attempt 3) |
    | UDP hold, 21,766 sessions (80 % of 27,208, `source_ports`) | 5 of 5 held | 5 of 5 | - | PASS | PASS |
    | PSS per 1,000 sessions, first fill | 3,533 KiB | 10,070 KiB | - | reported | 3,541 |
    | NFR1 HTTP req/s, L0 / B | 16,230 (1.9 %) | 16,010 (1.4 %) | 1.01 | PASS | 1.00 PASS |
    | NFR1 HTTP req/s, L1 / B | 16,220 (0.9 %) | 16,010 (1.4 %) | 1.01 | PASS | 1.01 PASS |
    | NFR1 HTTP p99 at 8,003 req/s, L0 / B | 1.873 ms | 1.827 | 1.02 [0.940, 1.151] | **INCONCLUSIVE** | 0.872 INCONCLUSIVE |
    | NFR1 HTTP p99, L1 / B | 1.750 ms | 1.827 | 0.958 [0.894, 1.049] | PASS | 1.04 INCONCLUSIVE |
    | NFR1 HTTPS req/s, L0 and L1 / B | 15,570 and 15,810 | 15,950 | 0.977, 0.992 | reported | 1.02, 1.02 |
    | NFR1 HTTPS p99 at 7,973 req/s, L0 and L1 / B | 7.186 and 2.024 ms | 17.10 | 0.42 [0.049, 4.858], 0.118 [0.042, 1.131] | reported | 0.954, 1.96 |

  - **Small layout** (`PERF_LAYOUT=small`, `results/perf-20261124T025312Z.*`),
    proxy `1`, load `2`, backends `3`, N = 1: **57.9 min** (3,472 s):
    `tcp-up` 210 s and `tcp-down` 209 s (one attempt each), `connect`
    464 s, `udp` 528 s, `nfr1-http-rps` 294 s, `nfr1-http-p99` 719 s,
    HTTPS 295 + 723 s. Every gated check passes, every one on attempt 1;
    the one-worker counts read 5 of 5 by construction at N = 1 and
    exclude nothing (the guard is for multi-worker runs).

    | Check | Lorica / L arm | nginx / B arm | Ratio, spread or 95 % interval | Verdict |
    |---|---|---|---|---|
    | TCP upload throughput | 24.79 Gbit/s (2.1 %) | 24.50 (1.1 %) | 1.01 | PASS |
    | TCP upload CPU per GiB | 0.3456 s (2.2 %) | 0.3482 (1.1 %) | 0.992 | PASS |
    | TCP download throughput | 25.19 Gbit/s (0.9 %) | 25.13 (1.8 %) | 1.00 | PASS |
    | TCP download CPU per GiB | 0.3403 s (0.9 %) | 0.3400 (1.9 %) | 1.00 | PASS |
    | Connect p99, pooled | 383.5 us | 344.5 | 1.11 [0.997, 1.285] | PASS |
    | UDP hold, 21,766 sessions | 5 of 5 held | 5 of 5 | - | PASS |
    | PSS per 1,000 sessions, first fill | 3,568 KiB | 10,070 KiB | - | reported |
    | NFR1 HTTP req/s, L0 / B | 9,528 (0.6 %) | 9,714 (0.7 %) | 0.981 | PASS |
    | NFR1 HTTP req/s, L1 / B | 9,502 (1.0 %) | 9,714 (0.7 %) | 0.978 | PASS |
    | NFR1 HTTP p99 at 4,857 req/s, L0 / B | 1.443 ms | 1.469 | 0.982 [0.939, 1.016] | PASS |
    | NFR1 HTTP p99, L1 / B | 1.458 ms | 1.469 | 0.993 [0.948, 1.030] | PASS |
    | NFR1 HTTPS req/s, L0 and L1 / B | 9,295 and 9,225 | 9,361 | 0.993, 0.986 | reported |
    | NFR1 HTTPS p99 at 4,680 req/s, L0 and L1 / B | 1.599 and 1.508 ms | 1.527 | 1.05 [1.010, 1.085], 0.988 [0.962, 1.013] | reported |

  - **TCP download, the pre-fix FAIL, now passes** at 0.989 (CPU per
    GiB 1.01), and upload moved from 0.904 to 0.974 (1.11 to 1.03). The
    audit's forwarding-loop fixes are the likely cause, not measured
    separately: `548dc94a` (one timer and one close wait per forwarding
    call instead of one per read and per write) and `e028960f` (a quiet
    direction polled once per turn instead of once per chunk). No
    profile was taken: nothing failed, and the splice decision handed by
    Story 12.3 now has no throughput gap to close on this machine.
  - **Connect p99, larger layout, INCONCLUSIVE**: the pooled ratio 1.44
    is under 1.5 but the interval's upper bound, 1.642, is not. The old
    method would not have rescued it: the median of the per-run p99s
    gives 441.9 against 302.2 us, 1.46. Against the pre-fix run, Lorica's
    tail is about the same (461 against 486 us) and nginx's is faster
    (321 against 397 us). Two things widen the interval: a constant gap
    at the median (Lorica's p50 168.6 to 181.7 us in every run, nginx's
    93.9 to 104.8, as before the fixes), and a drift both arms share
    (runs 1 to 5 higher than runs 6 to 10 in each arm, by about 90 us
    on average),
    which resampling whole runs keeps by design. On the small layout
    the gap is smaller (p50 138.5 to 155.9 against 87.1 to 109.2 us) and
    the check passes at 1.11. Suspected causes, from the code, not
    measured: the breaker admission RPC to the supervisor before each
    backend dial (as in the pre-fix notes), and with two workers the
    supervisor sharing the two proxy cores with them.
  - **NFR1 HTTP p99 L0, larger layout, INCONCLUSIVE**: ratio 1.02,
    interval [0.940, 1.151]. One L0 run of ten had a p99 of 3.451 ms,
    the other nine 1.579 to 2.294 ms, and B's ten 1.514 to 2.102 ms; the
    same binary with a stream bound (L1) passes at 0.958 [0.894, 1.049],
    and the small layout passes both at 0.982 and 0.993 with intervals
    under 1.03. The HTTPS series show the same class of single-run stall
    at larger size (one B run at 76.5 ms, L0 runs at 12.0 and 14.8 ms),
    which is why their intervals span a factor of 100. Read: no evidence
    of an NFR1 regression, one run's stall wide enough to keep the
    interval open. Per D-k's amendment the attempt was complete and is
    not re-run.
  - **Gate status of this dry run**: larger layout NOT PASSED, two
    gated INCONCLUSIVE (connect p99, NFR1 HTTP p99 L0), no FAIL; small
    layout PASSED. On the release run either INCONCLUSIVE blocks pending
    an owner decision (AC #3); Lot O records it on its own numbers.
  - **Which series reach 5 % spread.** Throughput, CPU per GiB and
    saturation req/s in both layouts, at 0.4 to 3.4 %. The PSS refill
    figure never does (139 % and 347 %, refills of 0 to 155 KiB per
    1,000 sessions);
    it is reported only.

- **Lot N, 2026-11-24, CI and the documentation that needs no Lot O
  number**, on `fa89e23c`. No cargo, no image build.
  - **The jobs** (`.github/workflows/ci.yml`), all on the workflow's
    triggers (pull requests to `main`, pushes of `main` and `v*` tags),
    all `needs: lint`:

    | Job | Command, from `tests-e2e-docker/` | Timeout | Release |
    |---|---|---|---|
    | `e2e-docker`, E2E (Docker) | `./run.sh --build --skip-l4 --skip-perf` | 90 min | gates, as before |
    | `e2e-l4`, E2E (L4) | `./run.sh --build --only-l4` | 90 min | gates |
    | `e2e-report`, E2E scenario report (every row) | `report.py --strict` over the two jobs' logs | 10 min | gates |
    | `e2e-perf`, E2E (performance) | `./run.sh --build --only-perf --perf-advisory` | 120 min | waits for it, `continue-on-error: true` |

    `verify-tag` needs `e2e-docker`, `e2e-l4`, `e2e-report` and
    `e2e-perf` beside its previous jobs; `release` still needs
    `verify-tag` alone. Every e2e job appends its Markdown to
    `$GITHUB_STEP_SUMMARY` under `if: always()` (`l4-summary.md`, or
    `perf-summary.md`, or a line saying the run wrote none) and uploads
    `results/` as an artifact (`e2e-docker-results`, `e2e-l4-results`,
    `e2e-perf-results`, 30 days). The timeouts are D-m's: the measured
    runs fit them with room (the L4 Lots' lane runs add up to about 20
    minutes on the development machine, D-o estimates the stream
    sections at about 12 on top of the 43-minute job, the perf phase took
    76.5 minutes on the larger layout before the p99 change), but every
    figure was measured on 24 CPUs, and a hosted runner has 4 and builds the images in the job.
    The first CI run gives the real ones.
  - **Strict mode across the jobs, and a deviation: a fourth job.** The
    report judges a non-strict run per profile that ran, so it reads a
    profile that never announced itself as `NOT-RUN` and passes. Split
    over two jobs, neither run is strict, and a pre-existing phase that
    silently stopped announcing its profile, or an L4 profile the driver
    skipped, would pass both jobs, where the release run's `--strict`
    fails it. Shown on synthetic logs built from the registry (every
    row's profiles, one verdict per row and profile): each job's log
    alone passes per profile that ran; the two together pass `--strict`
    (52 PASS, 6 PARTIAL, 3 NOT-E2E); with the `mcp` block removed from
    the first log, that log alone still passes and the union fails
    `--strict` with 12.7 IV2 and 12.10 IV1 `MISSING`. So `e2e-report`
    concatenates the two logs and runs `report.py --strict` on the
    runner's Python against the registry and the PRD in the checkout,
    the same inputs the `l4-report` service mounts. The two jobs'
    profiles are disjoint (`streams` and `streams-single` in one, every
    other registry profile in the other, `suite` included, since
    `--skip-l4 --skip-perf` skips no pre-existing phase), so the union
    is exactly the release run's set; with no `pending` row left in the
    registry, the per-profile and strict judgements differ only by
    profiles that did not run, which the union check catches. D-m named
    three jobs; this fourth one only reads the other two's artifacts and
    adds about a minute.
  - **Validation.** `yaml.safe_load` parses the workflow and gives the
    expected `needs`, timeouts and `continue-on-error`. actionlint
    1.7.12 from the official image pinned by digest
    (`rhysd/actionlint@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667`,
    run with `--network none`, its bundled shellcheck included): no
    finding on the new workflow, none on `fa89e23c`'s either. No CI run
    yet.
  - **How the open task's branch run will be forced**, on the release
    PR, with throwaway commits reverted before the merge: (1) failure:
    `PERF_REPS: 4` in the `e2e-perf` step's `env`, which `run-perf.sh`
    refuses with exit 2, a harness error `--perf-advisory` does not
    swallow; (2) timeout: `timeout-minutes: 2` on `e2e-perf`; (3) in the
    same commits, a temporary job `needs: e2e-perf` that prints
    `needs.e2e-perf.result`, standing in for `verify-tag`, which only a
    tag reaches. The task is ticked when both runs end with the
    workflow green and the stand-in job run. If a timed-out job reads as
    `cancelled` rather than `failure` and the stand-in is skipped, D-m's
    "fairly sure" was wrong, and `verify-tag`'s condition has to say
    `!cancelled()` and test the other needs' results explicitly.
  - **Documentation.** `docs/benchmarks.md` gains "Layer-4 parity
    harness" (what runs against what, layouts and the environment guard,
    the measurements, the spread rule and the pooled p99 with its
    bootstrap interval, verdicts and output, running it locally with the
    machine alone, what CI runs) and a pointer to it in its
    introduction. `docs/streams.md` gains "Parity verification": the
    matrix is not transcribed; the section links the PRD's coverage
    matrix and the registry's `matrix` column, and says how the report
    derives the P1 rows and where it prints the table. Constants are
    named, not quoted (`CHECKS`, `MIN_REPS`, `MAX_SPREAD`, `P99_RUNS`,
    `BOOTSTRAP_*`, `DEFAULT_SEED`, `ONE_WORKER_SHARE`,
    `IPERF_STREAMS_PER_WORKER`). Both sections end where Lot O appends
    its dated results table. `CHANGELOG.md` `[Unreleased]`: Added, the L4
    phase and the performance phase; Changed, the release waits for the
    L4 phase.

## File List

Lot A:

- `tests-e2e-docker/docker-compose.l4.yml` (new)
- `tests-e2e-docker/l4/run-l4.sh` (new)
- `tests-e2e-docker/l4/lib.sh` (new)
- `tests-e2e-docker/l4/scenarios.tsv` (new)
- `tests-e2e-docker/l4/scenarios/12.12.sh` (new)
- `tests-e2e-docker/test-runner/l4/report.py` (new)
- `tests-e2e-docker/entrypoint-streams.sh` (new)
- `tests-e2e-docker/entrypoint-streams-single.sh` (new)
- `tests-e2e-docker/baseline/Dockerfile` (new)
- `tests-e2e-docker/perf-tools/Dockerfile` (new)
- `tests-e2e-docker/Dockerfile`
- `tests-e2e-docker/test-runner/Dockerfile`
- `tests-e2e-docker/run.sh`
- `tests-e2e-docker/docker-compose.yml`
- `.gitignore`
- `docs/stories/story-12.2-stream-listeners.md`, `story-12.3-tcp-engine.md`,
  `story-12.4-tls-l4.md`, `story-12.5-udp-engine.md`,
  `story-12.6-stream-protection.md`, `story-12.8-proxy-protocol-http.md`,
  `story-12.9-stream-observability.md`, `story-12.10-stream-surfaces.md`,
  `story-12.11-upgrade-drain.md` (the "Delivered by" line)

Lot B:

- `tests-e2e-docker/l4/scenarios/12.2.sh` (new)
- `tests-e2e-docker/l4/scenarios/12.12.sh` (the fd-reserve scenario)
- `tests-e2e-docker/l4/scenarios.tsv` (Lot B rows `live`)
- `tests-e2e-docker/test-runner/l4/udp_hold.py` (new)
- `tests-e2e-docker/test-runner/l4/http_loop.py` (new)
- `tests-e2e-docker/docker-compose.l4.yml` (`lorica-budget-4k`,
  `lorica-budget-8k`, `streams-single-probe`)
- `docs/stories/story-12.2-stream-listeners.md` (Lot H checkboxes)

Lot C:

- `tests-e2e-docker/l4/scenarios/12.3.sh` (new)
- `tests-e2e-docker/l4/scenarios.tsv` (Lot C rows `live`)
- `tests-e2e-docker/test-runner/l4/tcp_backend.py` (new)
- `tests-e2e-docker/l4/coredns/Corefile` (new)
- `tests-e2e-docker/docker-compose.l4.yml` (PostgreSQL x3, `pg-client`,
  five `tcp_backend.py` services, CoreDNS and `l4-dns`, the worker
  node's `dns:`, `NET_ADMIN` on `streams-probe`)
- `docs/stories/story-12.3-tcp-engine.md` (Lot G checkboxes)

Lot H:

- `tests-e2e-docker/test-runner/run-proxy-protocol-smoke.sh` (new)
- `tests-e2e-docker/test-runner/proxy_protocol_client.py` (new)
- `tests-e2e-docker/test-runner/Dockerfile` (`COPY` and `chmod` lines)
- `tests-e2e-docker/test-runner/run-geoip-smoke.sh`,
  `tests-e2e-docker/test-runner/run-tests-workers.sh` (one call each)
- `tests-e2e-docker/run.sh` (the `geoip` phase and `--skip-geoip`; the
  `suite` profile and the 12.8 IV3 line)
- `tests-e2e-docker/l4/scenarios.tsv` (Lot H rows `live`; the header
  comment on `suite` and `geoip`)
- `docs/stories/story-12.8-proxy-protocol-http.md` (Lot G checkboxes)

Lot I:

- `tests-e2e-docker/l4/scenarios/12.9.sh` (new)
- `tests-e2e-docker/l4/scenarios.tsv` (Lot I rows `live`)
- `tests-e2e-docker/docker-compose.l4.yml` (`syslog-collector`)
- `docs/stories/story-12.9-stream-observability.md` (Lot J checkboxes)

Lanes (between Lots C and D):

- `tests-e2e-docker/l4/lib.sh` (lane derivation, `l4_compose -p`)
- `tests-e2e-docker/l4/run-l4.sh` (`--no-build` in a lane, `L4_LOTS`)
- `tests-e2e-docker/l4/build-images.sh` (new)
- `tests-e2e-docker/l4/scenarios/12.3.sh` (the CoreDNS hosts file under
  `${L4_RESULTS}`)
- `tests-e2e-docker/docker-compose.l4.yml` (image tag and subnets from
  the environment)
- `tests-e2e-docker/run.sh` (sources `l4/lib.sh`, lane guard, lane log
  and summary names, `--lots`, no main-project teardown on `--only-l4`)
- `tests-e2e-docker/test-runner/l4/report.py` (`--lots`)

Lot F:

- `tests-e2e-docker/l4/scenarios/12.6.sh` (new)
- `tests-e2e-docker/test-runner/l4/protect_tools.py` (new)
- `tests-e2e-docker/docker-compose.l4.yml` (the worker node on
  `streams-geo` and the GeoIP database mount, `NET_ADMIN` on
  `streams-client`)
- `tests-e2e-docker/l4/scenarios.tsv` (Lot F rows `live`)
- `docs/stories/story-12.6-stream-protection.md` (Lot I checkboxes, Dev
  Agent Record, File List, Change Log, Status)

Lot G:

- `tests-e2e-docker/l4/scenarios/12.7.sh` (new)
- `tests-e2e-docker/test-runner/l4/smtp_banner.py` (new)
- `tests-e2e-docker/docker-compose.l4.yml` (`redis`, `smtp-banner`,
  `smtp-silent`)
- `tests-e2e-docker/l4/scenarios.tsv` (Lot G rows `live`)
- `docs/health-checks.md` ("What the backend sees")
- `docs/stories/story-12.7-tcp-send-expect.md` (Dev Agent Record, File
  List, Change Log)
Lot K:

- `tests-e2e-docker/test-runner/run-hot-upgrade-smoke.sh` (the streams
  section appended)
- `tests-e2e-docker/ssh-backend/Dockerfile`, `entrypoint.sh` (new)
- `tests-e2e-docker/docker-compose.yml` (`hot-upgrade` profile:
  `ssh-backend`, `hot-upgrade-l4-backends`, the smoke's environment and
  `depends_on`)
- `tests-e2e-docker/l4/scenarios.tsv` (Lot K rows `live`)
- `docs/stories/story-12.11-upgrade-drain.md` (Lot G checkboxes)

Lot J:

- `tests-e2e-docker/test-runner/run-mcp-smoke.sh` (the streams section
  appended)
- `tests-e2e-docker/l4/scenarios.tsv` (Lot J rows `live`)
- `docs/stories/story-12.10-stream-surfaces.md` (Lot H checkboxes)
Lot D:

- `tests-e2e-docker/l4/scenarios/12.4.sh` (new)
- `tests-e2e-docker/l4/scenarios.tsv` (Lot D rows `live`)
- `tests-e2e-docker/test-runner/l4/tls_backend.py` (new)
- `tests-e2e-docker/docker-compose.l4.yml` (`tls-raw-1`, `tls-raw-2`,
  `tls-backend`)
- `tests-e2e-docker/test-runner/run-acme-smoke.sh` (12.4 IV2 section
  appended)
- `tests-e2e-docker/test-runner/run-cluster-smoke.sh` (12.4 key
  replication section appended)
- `docs/stories/story-12.4-tls-l4.md` (Lot H checkboxes)

Lot E:

- `tests-e2e-docker/l4/scenarios/12.5.sh` (new)
- `tests-e2e-docker/l4/scenarios.tsv` (Lot E rows `live`)
- `tests-e2e-docker/test-runner/l4/udp_tools.py` (new)
- `tests-e2e-docker/l4/coredns/iv2.test.zone` (new),
  `tests-e2e-docker/l4/coredns/Corefile` (the `iv2.test` block)
- `tests-e2e-docker/docker-compose.l4.yml` (`udp-amplifier`,
  `udp-spoofer`, `udp-victim`, `coredns-2`, `dns-loadgen`,
  `lorica-budget-16k`)
- `tests-e2e-docker/l4/build-images.sh` (builds `dns-loadgen`)
- `docs/stories/story-12.5-udp-engine.md` (Lot I checkboxes)

Lot L:

- `tests-e2e-docker/l4/scenarios/12.1.sh` (new)
- `tests-e2e-docker/l4/scenarios.tsv` (Lot L rows: three `live`, the
  hot rollback `pending` on its defect, then `live` once fixed)
- `tests-e2e-docker/test-runner/run-cluster-smoke.sh` (12.1 IV1 and IV2
  section appended)
- `tests-e2e-docker/test-runner/run-hot-upgrade-smoke.sh` (the hot
  rollback appended)
- `tests-e2e-docker/docker-compose.yml` (`hot-upgrade-baseline`, and the
  smoke's `depends_on` on it)
- `tests-e2e-docker/docker-compose.l4.yml` (`lorica-baseline-single`)
- `tests-e2e-docker/l4/build-images.sh` (builds the baseline)
- `docs/hot-upgrade.md` (the rollback statement, then the fixed
  behaviour)
- The defect's fix: `lorica/src/startup/fd_transfer.rs`,
  `lorica/src/startup/hot_upgrade.rs`, `CHANGELOG.md` (the `[Unreleased]`
  transfer sentence corrected), `docs/stories/story-12.11-upgrade-drain.md`
  (D-d amended)

Lot M:

- `tests-e2e-docker/docker-compose.perf.yml` (new)
- `tests-e2e-docker/perf/run-perf.sh` (new)
- `tests-e2e-docker/perf/analyse.py` (new)
- `tests-e2e-docker/perf/nginx-stream.conf` (new)
- `tests-e2e-docker/perf/nginx-http-backend.conf` (new)
- `tests-e2e-docker/perf/entrypoint-perf.sh` (new)
- `tests-e2e-docker/perf-tools/l4_connect_latency.py` (new)
- `tests-e2e-docker/perf-tools/udp_echo_peers.py` (new)
- `tests-e2e-docker/perf-tools/Dockerfile` (the `COPY` line)
- `tests-e2e-docker/run.sh` (`--skip-perf`, `--only-perf`,
  `--perf-advisory`, the perf call, the L4 report and teardown skipped on
  `--only-perf`)
- `tests-e2e-docker/perf/test_analyse.py` (new, 2026-11-24, the p99
  method of D-k's amendment)

Lot N:

- `.github/workflows/ci.yml` (the `e2e-docker` run line, its summary and
  artifact steps; the `e2e-l4`, `e2e-report` and `e2e-perf` jobs;
  `verify-tag`'s `needs`)
- `docs/benchmarks.md` ("Layer-4 parity harness", the pointer in the
  introduction)
- `docs/streams.md` ("Parity verification")
- `CHANGELOG.md` (`[Unreleased]`: Added, Changed)

## Change Log

| Date | Version | Description | Author |
|---|---|---|---|
| 2026-11-18 | 0.1 | Draft: one L4 phase absorbing the nine story e2e Lots, IV-to-scenario map with automation levels, parity-matrix scenarios, fd-reserve scenario, 1.10.7 from the signed package with toolchain parity, cold and hot rollback scenarios, perf topology, measurements, statistics and verdicts, NFR1 arms, three CI jobs, local release procedure, runtime estimates, artefacts for approval, 16 open questions. | Romain G. |
| 2026-11-18 | 0.2 | Maintainer decisions folded in as Resolved 1 to 16: artefacts approved (digests and checksums recorded by Lot A), three CI jobs, every recommendation accepted except SMTP, now verified against a standard-library banner server (new scenario `12.7-x-smtp-banner-template`); release machine has 24 CPUs, larger cpuset layout. Status Draft. | Romain G. |
| 2026-11-18 | 0.3 | Lot A gains the `stop_grace_period` task Story 12.2 D-f assumed was done. | Romain G. |
| 2026-11-18 | 0.4 | Lot A implemented: L4 compose project, driver, scenario registry with pending rows, report gated on the registry and the PRD matrix, `perf-tools` and `baseline` images, toolchain pin, `run.sh` flags; digests and checksums recorded. The full pre-existing suite with the pin is still to run. Status InProgress. | Romain G. |
| 2026-11-19 | 0.5 | Lot B implemented: Story 12.2's scenarios in both profiles and the fd-reserve scenario, all passing (AC #3 partial as D-d says); budget nodes, a single-process probe, `udp_hold.py` and `http_loop.py`. No product defect. The budget item asserts `worker_fds` for 1,024 ports and `supervisor_fds` for 600, since a UDP session now holds an fd. | Romain G. |
| 2026-11-20 | 0.6 | Lot C implemented: Story 12.3 IV1 to IV4 (IV1 on three PostgreSQL servers, IV4 in full through CoreDNS) and the five TCP matrix rows, all passing; `NET_ADMIN` on the probe recorded as Resolved 17. No product defect. | Romain G. |
| 2026-11-20 | 0.7 | Lot D implemented: Story 12.4 IV1 with the ALPN name, IV2 across a forced ACME renewal (full, not partial), the two-CA proof, upstream mTLS and key replication in the `cluster` profile, all passing; the key-replication defect it found is fixed in `44d6248b`. | Romain G. |
| 2026-11-20 | 0.8 | Lot E implemented: Story 12.5 IV1 (spoofed flood, the reflection bound at the victim), the byte bound, table isolation, IV2 on two CoreDNS servers with dnsperf, reply source, worker death, the AC #6 budget and the UDP idle-timeout row, all passing. No product defect; `response_count_bound` stays 0 under IV1 by D-b's end rule, recorded. | Romain G. |
| 2026-11-21 | 0.9 | Lots D and E re-run in lane 1, all passing; the IV2 zone renamed `iv2.test.zone` (the `.db` name was git-ignored and never committed); the IV1 client check moved first, with counters printed on a failure. | Romain G. |
| 2026-11-21 | 0.10 | Lot F implemented: Story 12.6 IV1 to IV3 (IV3 at 10,000 silent connections, then nine sources filling the pending cap), an IP-literal allow and deny entry in IV2, and the concurrency-caps matrix row, all passing in lane 2; the client joins `streams-geo` per scenario. No product defect. | Romain G. |
| 2026-11-21 | 0.11 | Lot G implemented: Story 12.7 IV1 against the pinned Redis frozen with `docker pause`, and the SMTP banner template against a standard-library banner server, both passing in lane 2; what Redis, PostgreSQL and the banner server see per probe recorded in `docs/health-checks.md`. No product defect. | Romain G. |
| 2026-11-20 | 0.12 | Lot H implemented: Story 12.8 IV1 (`geoip`) and IV2 (`geoip`, `workers`) through a Python PROXY client, both passing; `run.sh` runs the `geoip` profile and prints 12.8 IV3 under a `suite` profile after a complete pre-existing run. No product defect. | Romain G. |
| 2026-11-21 | 0.13 | Lot H re-verified by a fresh run after the lane was interrupted: same verdicts, no file change. | Romain G. |
| 2026-11-20 | 0.14 | Lot I implemented: Story 12.9 IV1 (partial as D-d says), the metrics and sink gauge, and the stream SLA, in the `streams` profile with a syslog collector, all passing. No product defect. | Romain G. |
| 2026-11-21 | 0.15 | Lot I re-verified by a fresh run after the lane was interrupted: same verdicts, no file change. | Romain G. |
| 2026-11-21 | 0.16 | Lot J implemented: Story 12.10 IV1 (partial as D-d says: the form's body, not a click) and Story 12.7 IV2 in the `mcp` profile, both reporting as expected; the section's mints wait out the login limit. No product defect. | Romain G. |
| 2026-11-21 | 0.17 | Lot K implemented: Story 12.11 IV1 and its three handover scenarios in the `hot-upgrade` profile, all passing (SSH session drained at the 120 s deadline with its report on the new `/metrics`, UDP across the upgrade with no loss, 64 range ports handed over); `ssh-backend` image. No product defect. | Romain G. |
| 2026-11-21 | 0.18 | Lot L implemented: 12.1 IV1 and IV2 in the `cluster` smoke and the cold rollback to 1.10.7 passing; the hot rollback finds a product defect (a 1.10.x binary adopts a stream's listener as an HTTP listener) and its row stays `pending`; `docs/hot-upgrade.md` states the observed rollback. | Romain G. |
| 2026-11-21 | 0.19 | Lot L's product defect fixed: a table holding a stream socket goes chunked at any size and the chunked header leads with a non-UTF-8 byte, so 1.10.7 refuses the hot downgrade cleanly and the old generation keeps serving; `12.1-ac3-rollback-hot-1.10.7` PASS and `live`; Lot L's boxes all ticked. | Romain G. |
| 2026-11-21 | 0.20 | Phase 1 audit item N1: a Lot O check added, the breaker RPC load under a UDP flood measured after C9, and the maintainer's decision that a worker-local breaker cache is built only if HTTP p99 then moves past NFR1. | Romain G. |
| 2026-11-22 | 0.21 | Lot M implemented: the performance phase (`docker-compose.perf.yml`, `perf/run-perf.sh`, `perf/analyse.py`, the connect-latency and UDP-peer tools), `run.sh --only-perf`, `--skip-perf`, `--perf-advisory`; iperf3 at 8 streams per worker with single-worker runs excluded (D-j deviation, the accept spread); the larger-layout dry run recorded as the pre-fix baseline: TCP download throughput FAIL at 0.881, NFR1 HTTP p99 INCONCLUSIVE after four attempts, everything else PASS. Small-layout dry run deferred. | Romain G. |
| 2026-11-24 | 0.22 | Phase 1 audit fixes: p99 checks judged on pooled samples with a seeded bootstrap interval on whole runs, 10 runs per p99 series (D-k amended, D-j 2 and D-l noted, Lot M note); shared e2e helpers moved to `l4/lib.sh` with a check that each scenario file runs on its own (C32); `report.py` covered by `test_report.py` (C15). | Romain G. |
| 2026-11-24 | 0.23 | Lot N, all but the Lot O numbers and the forced branch run: the e2e suite split into E2E (Docker), E2E (L4) and E2E (performance, advisory, `continue-on-error`), plus an E2E scenario report job that holds the two gating jobs' logs together to `--strict` (deviation from D-m's three jobs: neither job alone is strict); `verify-tag` waits for all four; actionlint clean. `docs/benchmarks.md` "Layer-4 parity harness", `docs/streams.md` "Parity verification", changelog entries. | Romain G. |
| 2026-11-24 | 0.24 | Lot M's post-audit run on `67573484`, both layouts with D-k's amended method: TCP download 0.989 (the pre-fix FAIL at 0.881 cleared) and every other TCP series passing; larger layout with connect p99 1.44 [1.285, 1.642] and NFR1 HTTP p99 L0 1.02 [0.940, 1.151] inconclusive, small layout passing every gated check; the dry-run task ticked. | Romain G. |
