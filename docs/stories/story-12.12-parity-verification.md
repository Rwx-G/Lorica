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
   backend, not on the proxy's ephemeral ports.
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
  L1 each at most 1.05 x B.
- **HTTPS** is measured the same way and reported, not gated (D-g, the
  crypto library's C compiler differs between the two builds).
- The p99 threshold is tight against the 5 % spread rule. Twenty
  seconds at a fixed rate gives tens of thousands of samples per run,
  which is what keeps a per-run p99 stable; if it still is not, the
  rule says inconclusive, and that blocks the release by design.

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

- [ ] Every item of 12.2 Lot H as the scenarios of D-d.
- [ ] `12.12-fd-reserve-http-unaffected` per D-f.

### Lot C: Story 12.3 scenarios and the TCP matrix rows - Docker e2e

Allowlist: `tests-e2e-docker/l4/scenarios/12.3.sh` (new),
`tests-e2e-docker/test-runner/l4/tcp_backend.py` (new, 12.3 Lot G's
design), `tests-e2e-docker/l4/coredns/` (new: Corefile and zone),
`tests-e2e-docker/docker-compose.l4.yml` (PostgreSQL x3, `pg-client`,
CoreDNS, the Python backends), `docs/stories/story-12.3-tcp-engine.md`
(Lot G checkboxes only).
Depends on: B; 12.3 Lots D2 and E.

- [ ] 12.3 IV1 to IV4 per D-d, IV1 with PostgreSQL and `psql`.
- [ ] The five `12.3-matrix-*` scenarios of D-e.

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

- [ ] Every item of 12.4 Lot H, plus the ALPN name in IV1.

### Lot E: Story 12.5 scenarios - Docker e2e

Allowlist: `tests-e2e-docker/l4/scenarios/12.5.sh` (new),
`tests-e2e-docker/test-runner/l4/udp_tools.py` (new: spoofer,
amplifying backend, victim recorder), `tests-e2e-docker/docker-compose.l4.yml`
(spoofer, victim, amplifier, second CoreDNS, `dns-loadgen` on the
`perf-tools` image), `tests-e2e-docker/l4/coredns/` (the IV2 zone),
`docs/stories/story-12.5-udp-engine.md` (Lot I checkboxes only).
Depends on: C (CoreDNS service); 12.5 Lots F, G, H.

- [ ] Every item of 12.5 Lot I; IV2 with CoreDNS and `dnsperf` instead
      of the stand-ins (the stand-in DNS responder and load generator of
      12.5 Lot I are not written).
- [ ] `12.5-matrix-udp-idle-timeout`.

### Lot F: Story 12.6 scenarios - Docker e2e

Allowlist: `tests-e2e-docker/l4/scenarios/12.6.sh` (new),
`tests-e2e-docker/test-runner/l4/protect_tools.py` (new, 12.6 Lot I's
design), `tests-e2e-docker/docker-compose.l4.yml` (`streams-geo`
attachments, `NET_ADMIN`, the GeoIP database mount),
`docs/stories/story-12.6-stream-protection.md` (Lot I checkboxes only).
Depends on: D, E; 12.6 Lots D, E, F.

- [ ] Every item of 12.6 Lot I; `12.6-matrix-concurrency-caps`.

### Lot G: Story 12.7 IV1 - Docker e2e

Allowlist: `tests-e2e-docker/l4/scenarios/12.7.sh` (new),
`tests-e2e-docker/test-runner/l4/smtp_banner.py` (new, standard
library), `tests-e2e-docker/test-runner/Dockerfile` (`COPY` lines only),
`tests-e2e-docker/docker-compose.l4.yml` (Redis, the two banner
servers), `docs/health-checks.md` (the "Backend-side noise"
observations and the SMTP verification only).
Depends on: C (PostgreSQL); 12.7 in Review.

- [ ] `12.7-iv1-redis-paused-marked-down` as 12.7 handed it; the
      per-probe log lines of Redis and PostgreSQL recorded in
      `docs/health-checks.md`.
- [ ] `12.7-x-smtp-banner-template` (Resolved 4): `smtp_banner.py` in
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

- [ ] Every item of 12.8 Lot G, each printing its scenario line.

### Lot I: Story 12.9 scenarios - Docker e2e

Allowlist: `tests-e2e-docker/l4/scenarios/12.9.sh` (new),
`tests-e2e-docker/docker-compose.l4.yml` (a `syslog-collector` and a
logs-only OTel collector in the `streams` profile, reusing the existing
images and `fixtures/otelcol-logs.yaml`),
`docs/stories/story-12.9-stream-observability.md` (Lot J checkboxes
only).
Depends on: C (Python backend); 12.9 Lots C1, C3, E, H.

- [ ] Every item of 12.9 Lot J, in the `streams` profile instead of a
      `stream-observability` profile of its own (same shape: one node,
      two workers; one boot fewer).

### Lot J: Story 12.10 IV1 and Story 12.7 IV2 - Docker e2e

Allowlist: `tests-e2e-docker/test-runner/run-mcp-smoke.sh` (a streams
section appended), `tests-e2e-docker/test-runner/mcp-helpers.sh`,
`docs/stories/story-12.10-stream-surfaces.md` (Lot H checkboxes only).
Depends on: 12.10 Lots B and D2; 12.7 in Review.

- [ ] Every item of 12.10 Lot H; `12.7-iv2-template-yes-payload-no` in
      the same section.

### Lot K: Story 12.11 scenarios - Docker e2e

Allowlist: as 12.11 Lot G's allowlist (`docker-compose.yml` for the
`hot-upgrade` profile's services, `tests-e2e-docker/ssh-backend/` new,
`run-hot-upgrade-smoke.sh` with a section appended, the runner
Dockerfile, `entrypoint-hot-upgrade.sh` and `run.sh` only if needed),
plus `docs/stories/story-12.11-upgrade-drain.md` (Lot G checkboxes
only).
Depends on: E (the UDP stand-in), I; 12.11 Lots C and D; 12.2 Lot G.

- [ ] Every item of 12.11 Lot G under its four names.

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

- [ ] `12.1-iv1-*`, `12.1-iv2-*` in the `cluster` section.
- [ ] Both rollback scenarios per D-h; `docs/hot-upgrade.md` states
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

- [ ] Topology, cpusets and environment guard per D-i.
- [ ] Measurements 1 to 3 per D-j, NFR1 per D-l.
- [ ] Statistics, re-runs, verdicts and output per D-k.
- [ ] A dry run on the development machine with both layouts (force the
      small one with an override variable) recorded in the Completion
      Notes, including whether any series reaches 5 % spread at all
      and how long the phase took.

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
- [ ] Documentation and changelog.

### Lot O: the release run - IV1

Allowlist: this story's Dev Agent Record and Change Log only.
Depends on: every Lot above; every Phase 1 story in Review.

- [ ] The procedure of D-n; results recorded; owner decision recorded
      for any `INCONCLUSIVE`.

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

## Change Log

| Date | Version | Description | Author |
|---|---|---|---|
| 2026-11-18 | 0.1 | Draft: one L4 phase absorbing the nine story e2e Lots, IV-to-scenario map with automation levels, parity-matrix scenarios, fd-reserve scenario, 1.10.7 from the signed package with toolchain parity, cold and hot rollback scenarios, perf topology, measurements, statistics and verdicts, NFR1 arms, three CI jobs, local release procedure, runtime estimates, artefacts for approval, 16 open questions. | Romain G. |
| 2026-11-18 | 0.2 | Maintainer decisions folded in as Resolved 1 to 16: artefacts approved (digests and checksums recorded by Lot A), three CI jobs, every recommendation accepted except SMTP, now verified against a standard-library banner server (new scenario `12.7-x-smtp-banner-template`); release machine has 24 CPUs, larger cpuset layout. Status Draft. | Romain G. |
| 2026-11-18 | 0.3 | Lot A gains the `stop_grace_period` task Story 12.2 D-f assumed was done. | Romain G. |
| 2026-11-18 | 0.4 | Lot A implemented: L4 compose project, driver, scenario registry with pending rows, report gated on the registry and the PRD matrix, `perf-tools` and `baseline` images, toolchain pin, `run.sh` flags; digests and checksums recorded. The full pre-existing suite with the pin is still to run. Status InProgress. | Romain G. |
