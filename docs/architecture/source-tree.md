# Source Tree

Crate-responsibility map for the Lorica workspace. This document
deliberately stops at crate / top-level-module granularity: per-file
enumerations drift on every release (the v1.0 version of this file
was flagged stale by two audits). For the exact current layout,
`ls <crate>/src/` is authoritative; `docs/BUMP-CHECKLIST.md` lists
every file that pins the product version; `CHANGELOG.md` records
architectural moves per release.

## Product crates (follow the product version)

| Crate | Responsibility |
|-------|----------------|
| `lorica` | The binary. `main.rs` is dispatch only; `cli.rs` holds the clap surface (including the `--automation-listen` / `--automation-listen-any` binds and their validator) plus the `worker`, `rotate-key`, `unban`, `upgrade`, `cluster` and `automation` subcommands; `cli_client.rs` is the loopback management-API client every credential-taking subcommand shares (one trust decision, one login contract, passwords from a file, stdin or the environment but never argv), `cli_cluster.rs` implements `cluster init / join / leave / status / break-glass / token`, `cli_automation.rs` implements `automation token create`; `startup/` holds the three run modes (`supervisor.rs`, `worker.rs`, `single.rs`), the shared background-task helpers (`mod.rs`, audit H-9: one source of truth per spawn cluster) and one file per launch path that is not a run mode: `automation.rs` (what must hold before the automation socket opens), `cluster_plane.rs` and `cluster_follower.rs` (the two cluster roles), `telemetry_drain.rs` (the follower's telemetry push), `environment_reaper.rs` (the sweep for expired automation environments), `hot_upgrade.rs` (the zero-downtime binary handoff); `proxy_wiring.rs` + `proxy_wiring/` hold the data plane (see below); `capture/` the request-capture engine (`rules.rs` compiled predicates, `buffers.rs` the per-request byte buffers, `node_ceiling.rs` the node-wide memory ceiling those buffers reserve from so a diagnostic cannot become a memory-exhaustion primitive, `rule_budgets.rs` the per-rule total and sampling rate, `self_disable.rs` the off-request-path counter writes that disarm a rule which spent its total, `record.rs` the single JSON document a capture produces, `redact.rs` the header and query-parameter redaction applied before it leaves the proxy, `sink.rs` the outputs it leaves through); `health.rs` the prober; `reload.rs` config/cert hot-reload; `bot.rs`/`bot_rdns.rs` bot-protection stash + rDNS; `ai_bot.rs` + `ai_bot/vendor_ips/` the AI-crawler registry and its checksum-verified vendor CIDR bundles; `connection_filter.rs`, `geoip.rs`, `mtls.rs`, `otel.rs` what their names say. |
| `lorica-config` | SQLite `ConfigStore` (per-entity submodules under `src/store/`, migrations under `src/migrations/`), config models (`src/models/`), encryption-at-rest helpers (`crypto.rs`). Sole DB access point for configuration. It also owns every shape that crosses a process or a node boundary: `canonical.rs` is the byte-stable snapshot encoder (`CANONICAL_FORMAT_VERSION = 2`, strict decode) that cluster replication and drift detection hash, and its `restrict_for_recipient` cuts a follower's blob down to the routes that node serves plus their backends, certificates, capture rules and environments, so an edge never holds the rest of the fleet's upstreams and secrets; `export.rs` / `import.rs` are the TOML backup round-trip, with secrets replaced by `**REDACTED**` on the way out and re-import refused while the placeholder is still there; `diff.rs` previews per entity what an import would change; `connection_filter.rs` is the one CIDR parser every address list in the workspace answers to (TCP pre-filter, capture rules, automation tokens, both listeners); `ai_crawler_registry.rs` holds the built-in crawler descriptors and the shared `robots.txt` builder. |
| `lorica-api` | Management plane: axum router + `AppState` (`server.rs`), per-domain handler modules, `routes/` (the route resource split by sub-feature: path rules, header rules, traffic splits, forward auth, mirror, mTLS, response rewrite, cert export), `middleware/` (sessions, rate limit, RBAC, metrics bearer, request span), `management_tls.rs` (the TLS material the localhost listener serves on), `acme/` (issuance / renewal handlers, challenge store, pending manual-DNS state - the pure protocol core lives in `lorica-acme`), `db.rs` (blocking-pool store access, audit H-3), `audit.rs` (the hash-chained audit log and its verifier), `log_store.rs` + `log_writer.rs` (persistent access/WAF logs + batched background writer, backlog #24), `log_sinks/` (fan-out of those same events to an external syslog collector, lossy by design so a slow collector never blocks a request), `metrics.rs` (data-plane counters + `/metrics` handler, built on `lorica-metrics`). Two surfaces here are not the dashboard. `automation/` is the second HTTPS listener added in v1.8.0, whose only credential is a scoped bearer token: `listener.rs` (its own socket, TLS and pre-authentication budgets), `auth.rs` (a minted static token or a GitLab ID token, the mode picked by the value's shape and never by the caller), `oidc/` (the RS256-pinned JWT verifier, its JWKS cache and replay protection), `scope.rs` (the whole authorization matrix in one fail-closed function), `audit.rs` (a row for every request, refusals included), `router.rs` (`whoami`, and the mount point the OpenAPI drift gate reads), `environments/` (the idempotent review-environment resource, one transaction per `PUT`). `cluster/` holds the fleet registry handlers plus the `runtime.rs` the control-plane binary drives the roster and session registry through. `automation_tokens.rs` and `oidc_issuers.rs` administer those credentials from the MANAGEMENT plane on purpose, so no automation token can widen its own scope or mint a successor. `capture.rs` serves capture-rule CRUD, `capture_ring.rs` the in-memory ring of the last records this process emitted (it lives here, not beside the record type, because the record type is in the `lorica` binary crate which depends on this one). `cluster_telemetry_store.rs` is the control plane's separate fan-in database, deliberately off the local log store so fleet-wide write volume is not a latency input to local dashboard and audit queries. |
| `lorica-acme` | Pure ACME / Let's Encrypt core, extracted from `lorica-api` in v1.6.0 (backlog #42a): the `instant-acme` protocol driver (HTTP-01, automated + manual DNS-01), CSR generation, its own `AcmeError`, and the DNS-01 provider challengers (Cloudflare, OVH, Route53 behind the `route53` feature). No dependency on the management API. |
| `lorica-metrics` | Shared Prometheus registry + type-safe registration helpers + cross-worker counter aggregation, extracted from `lorica-api` in v1.6.0 to break the `lorica-api -> lorica-bench` / `lorica-notify` cycle. Re-exports `prometheus` so consumers never depend on it directly. |
| `lorica-cluster` | Cluster plane (Epic 9): the authenticated, encrypted transport a control plane and its followers speak over mutual TLS 1.3. A protobuf message set disjoint from the worker plane's (`messages.rs`, `frame.rs`) riding the same pipelined RPC endpoint with WAN-tuned `limits.rs`; version-range negotiation and the schema-ordering check (`version.rs`, `handshake.rs`); the cluster CA, EKU-split leaf issuance and CRL minting (`ca.rs`, `certs.rs`, `tls.rs`); pre-authentication budgets and the per-source gate (`preauth.rs`, `challenge.rs`) in front of the two `listener/` sockets (enrollment and operational); join tokens, redemption and convergence admission (`token.rs`, `enroll.rs`, `admission.rs`); the follower `dialer.rs`; the in-memory `roster.rs` with its `session.rs` registry and kill switches; the confused-deputy `bridge.rs`; configuration `replication.rs` and telemetry fan-in (`telemetry.rs`). |
| `lorica-waf` | WAF engine: rule set, evaluation (`engine/`), IP blocklist, event types. |
| `lorica-notify` | Alert events + notification channels (stdout, email, webhook, slack). |
| `lorica-bench` | Passive SLA collection, active probes, load-test engine + scheduler. |
| `lorica-dashboard` | Svelte 5 frontend (`frontend/`) embedded into the binary via `build.rs` + rust-embed; serves the SPA and the CSP header. |
| `lorica-challenge` | Bot challenges: PoW + image captcha generation, verdict cookie HMAC. |
| `lorica-geoip` | GeoIP / ASN MMDB resolvers with hot-swappable process-wide handles. |
| `lorica-shmem` | Cross-worker shared-memory region (WAF auto-ban counters, rate-limit buckets). |

## `lorica/src/proxy_wiring/` (data plane, backlog #7 layout)

| Module | Responsibility |
|--------|----------------|
| `proxy_wiring.rs` (root) | `LoricaProxy` struct, spawn helpers, cache statics, the `ProxyHttp` trait impl (request_filter orchestration, upstream_peer, response filters, logging), public re-exports. |
| `config.rs` | `ProxyConfig` / `RouteEntry` / smooth-WRR state, route-table construction, `find_route`. |
| `filters.rs` | The request_filter stage methods (`check_*`, audit H-8) + `write_error_response` (audit H-10) + WAF event persistence hand-off. |
| `lb.rs` | Peak-EWMA tracker, per-(route, backend) circuit breaker. |
| `context.rs` | Per-request `RequestCtx`. |
| `worker_rpc.rs` | Worker-side RPC: two-phase config reload, metrics report. |
| `engines.rs` | Mode-switching engines (local vs supervisor-RPC: rate limit, verdict cache, breaker). |
| `ai_bot_merged.rs` | The AI-crawler snapshot the request path reads: the built-in registry seeded once, then the enabled custom rows layered on top (a custom row wins on name collision, so an operator can ship a fresh vendor CIDR list mid-cycle). Built per config snapshot and never panics on bad operator data. |
| `helpers.rs`, `error_pages.rs` + `error_pages.html`, `forward_auth.rs`, `mirror_rewrite.rs`, `bot_handlers.rs` | Shared pure helpers, error-page rendering and its `include_str!`-ed template, forward-auth client, request mirroring + response rewriting, bot solve/captcha handlers. |
| `tests.rs`, `cert_reload_commit_tests.rs`, `ai_bot_reload_tests.rs` | Unit + regression tests for the above. |

The traffic-capture hook has no module of its own here: it attaches
directly in `proxy_wiring.rs` at four points, because those are the
stages that see the bytes. Admission at `request_filter` (a node with
no capture rule pays one length check), request bytes at
`request_body_filter`, response bytes at `response_body_filter`, then
release and record emission at `logging`, where the record is built
from the same values as the access-log row. Everything it calls lives
in `lorica/src/capture/`.

## Forked crates (Pingora forks, pinned at 0.1.0)

`lorica-core`, `lorica-proxy`, `lorica-http`, `lorica-error`,
`lorica-tls`, `lorica-lb`, `lorica-cache`, `lorica-memory-cache`,
`lorica-lru`, `lorica-ketama`, `lorica-limits`, `lorica-timeout`,
`lorica-pool`, `lorica-runtime`, `lorica-header-serde`, `tinyufo`
preserve upstream Pingora structure to stay rebaseable. `lorica-tls`
additionally carries the native cert resolver + OCSP stapling.
`lorica-worker` and `lorica-command` are first-party process/IPC crates
and follow the product version (1.8.0 on this branch, bumped with the
product per `docs/BUMP-CHECKLIST.md`), not the forked-crate 0.1.0 pin.

## Tests

Test files mirror the source tree: unit tests live in
`#[cfg(test)]` modules beside the code (or sibling `*_tests.rs`
files for large regression suites), integration tests in each
crate's `tests/`, end-to-end Docker suites in `tests-e2e-docker/`,
frontend tests beside their components (`Foo.svelte` /
`Foo.test.ts`). A new test goes in the same directory layout as the
code under test.

## Packaging

`dist/` holds the `.deb` build script (`build-deb.sh`), the RPM spec
(`rpm/lorica.spec`), and the hardened systemd unit
(`lorica.service`). THREE Dockerfiles must list every workspace
member: `Dockerfile` (release), `Dockerfile.dev` (dev image) and
`tests-e2e-docker/Dockerfile` (the image the Docker e2e suite builds).
A missing `COPY` breaks `cargo build --workspace` in Docker. The e2e
one is the easy miss because it lives in a subdirectory: `lorica-acme`
was absent from it for the whole v1.6.0 cycle and only surfaced when
`./tests-e2e-docker/run.sh` failed at build time. Treat them as a
trio, and touch all three in the commit that adds a crate.
(`ci-check.Dockerfile` is not part of the trio: it copies the whole
context and needs no per-crate line.)
