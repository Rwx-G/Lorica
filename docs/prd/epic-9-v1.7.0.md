# Epic 9: Multi-Node Cluster, Unified Control Plane & Log Fan-Out (v1.7.0)

**Author:** Romain G.
**Target version:** 1.7.0
**Status:** Draft (revised 2026-08-23 after a five-pass verification of every "reuses the existing X" claim in the first draft)

**Epic Goal:** Turn Lorica from a standalone edge into a fleet that is operated as one system. A designated control-plane node owns configuration, certificate issuance and the aggregated view; follower nodes dial out to it, replicate configuration locally, and fan their WAF events, health, bans and audit entries back in. Ships alongside two standalone observability sinks (syslog, OTLP logs) that are useful with or without a cluster. Answers [issue #26](https://github.com/Rwx-G/Lorica/issues/26).

**The security boundary this epic must not break:** Lorica's management API and dashboard bind `127.0.0.1` only, on every node, control plane included. That does not change. The cluster plane is a **separate** listener on a separate port with separate authentication, its own crate, off by default, and enabled only by explicit operator opt-in. An operator who does not run a cluster gains no open port and no new attack surface. Follower nodes never open an inbound port at all: they dial out and hold the connection, which also means they work behind NAT.

**The security boundary this epic does move, and must document:** `docs/security/threat-model.md` currently asserts "Management API (9443, localhost only)" and "no remote access", and `docs/security/hardening-guide.md` ships an `iptables` block that DROPs the management port. A control-plane node running `--cluster-listen` accepts inbound connections from the network, and its enrollment path must by construction accept peers that hold no certificate yet. Both documents are deliverables of this epic, not afterthoughts.

**Integration Requirements:** All work lands on a single `feat/v1.7.0` branch with one final PR to `main` (per project workflow). Story 9.1 is a hard prerequisite for everything else; 9.2 gates 9.3 through 9.7; Story 9.8 is fully independent of the cluster and should land first to de-risk the release. Worker-mode parity is mandatory, and every follower-conditional behaviour in this epic must answer explicitly "which process does this run in, and how does the flag get there" (the `spawn_ocsp_refresh_loop` split between `worker.rs:643` and the supervisor is the same shape as the v1.5.2 cert-hotswap bug). Cluster RPCs that mutate shared state round-trip through the supervisor channel (`lorica-command`); telemetry fan-in does **not**, because each worker opens its own `LogStore` on the shared data dir (`startup/worker.rs:720`) while the supervisor sets `log_writer: None` (`supervisor.rs:977`) - the follower supervisor reads that shared store rather than adding a high-volume worker-to-supervisor RPC. The data plane is sacred: no cluster operation, and no control-plane outage, may ever block, slow, or fail a proxied request. `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo audit`, `pnpm lint`, `pnpm tsc --noEmit` and `pnpm exec svelte-check` must stay green at every commit.

**Cross-cutting deliverables** (no single story owns them, all are release-blocking): `lorica-api/openapi.yaml` updated for the ~8 new endpoints and kept green against the existing route-table drift-gate test; `docs/security/threat-model.md` gains a trust boundary and actor for the cluster plane; `docs/security/hardening-guide.md` gains a firewall stanza for the cluster port with a default-deny, allow-enrolled-sources-only policy; `dist/build-deb.sh` and `dist/rpm/lorica.spec` post-install banners and usage help mention the cluster port; `docs/BUMP-CHECKLIST.md` gains `lorica-cluster`.

---

## Story 9.1: Foundations

As a maintainer,
I want the reusable primitives this epic depends on to actually be reusable before any cluster code is written,
so that the cluster stories build on verified seams instead of on assumptions that fail at integration time.

Every item below was verified as missing or unsuitable during the pre-implementation review. None of them is cluster-specific; all of them are prerequisites.

### Acceptance Criteria

1. **`RpcEndpoint` generalised over transport.** `RpcEndpoint`'s struct carries no transport type today (`lorica-command/src/rpc.rs:99-121`), so only `new()` and the reader/writer tasks change: accept any `AsyncRead + AsyncWrite + Unpin + Send + 'static` via `tokio::io::split` instead of `UnixStream::into_split`. `from_raw_fd` stays a `UnixStream`-only constructor. All existing call sites infer unchanged and the UDS tests stay green unmodified.
2. **`RpcEndpoint` generalised over frame type.** The endpoint hard-codes `Envelope`, `Command`, `Response` and `cmd.sequence` (`rpc.rs:53`, `:439-471`). Introduce a `Frame` trait exposing `sequence()` so the cluster message set can live in a separate proto package and version independently of the worker command set. This is the non-trivial half of the generalisation and must not be estimated as a type parameter.
3. **Per-endpoint transport limits.** `MAX_MESSAGE_SIZE` (1 MiB, `rpc.rs:57`), `OUTBOUND_QUEUE_CAP` (256, `rpc.rs:67`), `SLOW_ENQUEUE_WARN` (10 ms, `:74`) and `DEFAULT_REQUEST_TIMEOUT` (5 s, `:77`) become per-endpoint parameters rather than crate constants, because every one of them is tuned for a same-host UDS and is wrong for a WAN.
4. **Oversize outbound frames stop failing silently.** `rpc.rs:384-390` logs and `continue`s, so the caller sees an unexplained `Timeout` indistinguishable from a dead peer. It must return a typed size error. The in-flight map (`rpc.rs:90`, documented at `:79-89` as unsuitable above reload-frequency volume) gains a bound.
5. **Canonical configuration encoder.** A new encoder producing byte-stable output for a given logical configuration: every map serialised through a sorted view (`Route.response_headers`, `HeaderRule.proxy_headers` / `response_headers`, `SecurityHeaderPreset.headers` are `HashMap`s whose iteration order is `RandomState`-seeded per process, so today the same config hashes differently on two nodes and on the same node after a restart), a total order on every collection with a non-unique sort key, secrets included, node-local fields excluded. This is **not** the TOML export path, which redacts `key_pem` and every channel secret (`export.rs:100`, `:59-94`) and whose import rejects those placeholders (`import.rs:244-301`).
6. **Persisted cluster generation.** A `cluster_config_generation` counter persisted in the config DB, distinct from the supervisor's in-memory `reload_generation` (`supervisor.rs:473`) which resets to 0 on every start while `GenerationGate` refuses non-increasing values (`generation.rs:46-48`). Without this, a control-plane restart puts the whole fleet in permanent drift and every follower gate rejects the first post-restart Prepare.
7. **Hot upgrade hands off the cluster listener.** `hot_upgrade.rs:199-216` transfers only proxy and management listeners. Extend the FD set to the cluster listener, and add an interlock so that during the old/new supervisor overlap a follower never holds two live sessions for one `node_id` (both applying config, both eligible to auto-renew the node certificate).
8. **`rotate_encryption_key` covers every encrypted column.** `store/mod.rs:645-700` is a hardcoded two-table loop; a cluster CA key in a third table would be silently skipped, leaving it encrypted under the retired key while the operator is told rotation completed. Convert to a table-driven enumeration with a test asserting every encrypted column is covered.
9. **`Http01ChallengeSolver::present` becomes fallible.** It returns `()` today (`lorica-acme/src/driver.rs:53-57`) and `set_ready()` fires on the next line (`:144-151`), so a partial fleet distribution tells the CA to validate while some nodes have no token. Breaking change to a public trait, budgeted here.
10. **`acme_challenges` folded into the migration system.** Created ad hoc from a second rusqlite connection (`acme/store.rs:87-91`); it gains a network writer in Story 9.5 and its schema ownership must be unambiguous first.
11. **Schema version exposed.** `ConfigStore::schema_version()` (`store/mod.rs:632`) is referenced only from tests. Expose it so the cluster handshake can compare it.
12. **Strict replica decoding.** The types used to decode a replicated configuration blob carry `#[serde(deny_unknown_fields)]`. Nothing in the codebase uses it today, so a follower on schema N-1 receiving a blob from schema N silently discards unknown fields, writes the row without them, and reports "applied ok" - including for a new security-relevant setting.
13. **Pebble ACME fixture.** A Pebble container in `tests-e2e-docker/` with CA-root trust injection into the Lorica image, plus a mock DNS provider for DNS-01. **This does not exist today** - the repo has zero end-to-end ACME coverage, and the v1.5.2 audit item M-22 that first requested it was never implemented. Story 9.5's verification is impossible without it.

### Integration Verification

- IV1: `cargo test -p lorica-command` passes unmodified, proving the UDS path is byte-for-byte unchanged; a new test drives the same endpoint over an in-memory duplex stream.
- IV2: The canonical encoder produces identical bytes for the same logical configuration across two processes with different `RandomState` seeds, and across a process restart, on a configuration exercising every `HashMap` field.
- IV3: A hot upgrade on a node with `--cluster-listen` active completes with the listener handed off, no `EADDRINUSE`, and no follower observing two concurrent sessions. Rotation coverage is asserted by a test that fails when a new encrypted column is added without updating the rotation table.

---

## Story 9.2: `lorica-cluster` Crate, Transport and Listeners

As an infrastructure engineer,
I want a dedicated cluster plane that carries authenticated, encrypted traffic between a control-plane node and its followers,
so that fleet coordination never rides on the loopback-only management API and never forces a follower to expose an inbound port.

### Acceptance Criteria

1. New workspace crate `lorica-cluster`. Per the new-crate checklist: workspace `Cargo.toml` `members`; `COPY lorica-cluster/ lorica-cluster/` in **all three** Dockerfiles (`Dockerfile`, `Dockerfile.dev`, `tests-e2e-docker/Dockerfile`); `docs/BUMP-CHECKLIST.md`; cross-deps in `lorica`, `lorica-api`, `lorica-config`. `#![deny(unsafe_code)]` and `#![warn(missing_docs)]` at the crate root (note: `lorica-command` cannot inherit the former, it needs unsafe for `from_raw_fd`).
2. **Two distinct listeners, because one cannot serve both purposes.** The *operational* listener requires client authentication: a new rustls `ServerConfig` built with `WebPkiClientVerifier` **without** `allow_unauthenticated` - the existing `build_verifier` helper hardcodes it (`lorica/src/mtls.rs:99`) and is therefore not reusable. The *enrollment* listener is separate, accepts peers holding no certificate by definition, is off unless at least one join token is live, and auto-closes when the last unexpired token is burned or expires. It is the only unauthenticated surface in the product and is documented as such.
3. **Pre-authentication budgets on the enrollment listener**, all enforced before any token verification: handshake timeout, maximum concurrent handshakes, maximum in-flight enrollments, and a per-connection byte and time budget. Exceeding any of them drops the connection and increments a counter.
4. **Protocol version negotiation supports rolling upgrades.** A minimum-compatible-version range, not exact equality: refusing on mismatch would make fleet upgrades impossible, since no order exists in which to upgrade the nodes. Prost's unknown-field tolerance stays the compatibility mechanism. The version exchange happens **after** client-certificate verification on the operational path; the enrollment path returns an opaque code on the wire and logs the diagnostic locally, so an unauthenticated peer gets no build fingerprint.
5. **The handshake also exchanges `schema_version()`.** A follower whose config schema is below the control plane's refuses configuration apply with a distinct diagnostic rather than applying a lossy blob.
6. **Cluster messages are a disjoint type in a separate proto package.** The bridge into `lorica-command` is an explicit whitelist translation with no pass-through of a peer-supplied `CommandType`; `Command` is one flat message today including `SHUTDOWN` and `BAN_IP` (`lorica-command/proto/command.proto:14-59`), so a pass-through bridge would let any follower shut down the control plane. A cluster message that decodes as a worker command is a protocol violation that drops the connection.
7. **Telemetry never shares queue budget with configuration.** Separate multiplexed streams with separate credit, or a separate connection. A ~1 MiB config or certificate push must not block heartbeats behind it and produce a false liveness timeout that triggers a reconnect that drops the push.
8. **Cluster CA.** `lorica cluster init` generates the CA keypair and self-signed CA certificate, persisted through the existing AES-256-GCM helpers (`lorica-config/src/crypto.rs:14-115`, generic and reusable). The epic states plainly that the CA key inherits the existing trust model: the master key is 32 raw bytes in a `0600` file beside the database (`crypto.rs:34-70`), with no KDF, no passphrase and no hardware binding. This epic raises that file's value from "this node's leaf keys" to "the identity root of the fleet", and `docs/cluster.md` says so.
9. **Follower dialer:** long-lived outbound connection, mutual TLS, application-level heartbeat, reconnect with exponential backoff and jitter whose cap scales with fleet size. `RpcEndpoint` has no reconnect path (`rpc.rs:475-487` clears in-flight on EOF and `Drop` aborts both tasks), so holders access it through an `ArcSwap` rather than a plain clone.
10. **Control-plane admission control on convergence.** A concurrent-convergence limit with a queue and a `RETRY_LATER` response, so a control-plane restart does not take a synchronised full-state burst from the entire fleet while cold.
11. **`--cluster-listen` takes an explicit `host:port`.** A bare port is refused (one digit from the management port), `0.0.0.0` and `::` are refused unless a separate explicit flag is present, a bind equal to the management port is refused, and the effective bind address is logged at WARN on startup.
12. Prometheus: `lorica_cluster_connection_state{node_id, state}`, `lorica_cluster_rpc_total{direction, method, outcome}`, `lorica_cluster_rpc_duration_seconds`. Labels use the server-side `node_id` only, never the follower-supplied `node_name`, which is display-only and would otherwise let a compromised follower create unbounded series by rotating it on reconnect.

### Integration Verification

- IV1: A peer presenting no client certificate, or one signed by a foreign CA, is rejected at the operational listener's handshake with no application byte processed; the enrollment listener is closed when no token is live and refuses connections outright.
- IV2: Killing the control plane mid-session leaves the follower proxying with zero 5xx and unchanged p99; it reconnects when the control plane returns, and a fleet-wide reconnect burst is admission-limited rather than stampeding.
- IV3: A follower emitting a message that decodes as a worker `Command` (including `SHUTDOWN`) is disconnected and audited, and the control plane's workers are unaffected.

---

## Story 9.3: Node Enrollment, Registry and Revocation

As an operator,
I want to enroll a new node with a single short-lived token and revoke it just as easily,
so that adding an edge is a one-command operation and a decommissioned node loses fleet access immediately.

### Acceptance Criteria

1. **Token shape is `<public_id>.<secret>`.** The database indexes `public_id` and stores a hash of the secret only, so exactly **one** verification runs per attempt. Storing an unindexed hash would force one verification per live token per attempt, and the existing argon2id parameters (19 MiB per verify, `lorica-api/src/auth.rs:24-29`) would turn the enrollment path into a memory-exhaustion primitive: 200 concurrent attempts against 5 live tokens is ~19 GB of transient allocation on a node that is also terminating production TLS. Verification uses HMAC-SHA256 with a server-side key rather than a memory-hard KDF, because the secret is 256 bits of machine-generated entropy and not a human password, and it runs under a global semaphore capping concurrent verifications. Comparison is constant-time and the error and timing are identical whether `public_id` exists or not.
2. **The token pins the control-plane leaf key, not the CA.** Pinning the CA fingerprint admits any certificate the cluster CA ever issued, so a compromised follower could stand up a rogue control plane and harvest the token - the exact attack the pin is meant to prevent. The token embeds the SHA-256 of the control-plane leaf SPKI; the joiner additionally verifies the presented SAN against the `--control-plane` host. Node certificates are issued `clientAuth`-only and the control-plane certificate `serverAuth`-only, so neither can impersonate the other.
3. **No CSR.** The follower generates its keypair locally and sends the **bare public key**; the control plane assigns subject, SANs, EKU, basic constraints (`CA:FALSE`) and validity itself, and validates the key type against an allowlist (Ed25519, P-256, RSA-2048+). This closes the classic extension-copy escalation, where a CSR carrying `CA:TRUE` yields a subordinate CA that node revocation cannot touch, and it avoids enabling rcgen's optional `x509-parser` feature (CSR parsing is `#[cfg]`-gated off in rcgen 0.14's default features). The private key never leaves the node.
4. **Single use is atomic and precedes issuance.** The token is consumed by one conditional update (`UPDATE ... SET state='burned' WHERE id=? AND state='unused'`) that must report exactly one affected row **before** any certificate is signed; zero rows aborts. A burn performed after signing lets N concurrent joins with one token all succeed.
5. **Enrollment lands in `Pending`.** The node receives a certificate scoped to completing enrollment and receives no configuration and no certificates until a SuperAdmin activates it, unless the control plane was started with an explicit auto-activate opt-in. A token may be bound at mint time to an expected node name and optionally a source CIDR, both enforced at redemption. Without this, a one-hour token converts into a 90-day self-renewing identity holding fleet configuration, and the TTL cap protects nothing past the first hour.
6. **The token never appears in argv.** `--token-file`, `--token-stdin` and `LORICA_JOIN_TOKEN` are the documented paths; a literal `--token <value>` either does not exist or emits a loud warning, because argv is readable through `/proc`, lands in shell history, and is logged verbatim by CI and Ansible `command:` modules.
7. **Revocation is enforced during the handshake.** A revoked node's fingerprint is added to a CRL, the cluster `ServerConfig` is rebuilt with `with_crls()` (available in the pinned rustls 0.23.43) and the acceptor is arc-swapped. Note that no such machinery exists in the codebase: the only precedent for a client-CA change is "log a warning, restart required" (`lorica/src/reload.rs:90`), because a rustls `ServerConfig` is immutable once built. Revocation also tears down in-flight sessions synchronously rather than waiting for a heartbeat.
8. **Node identity comes from the certificate, never from the message body.** It is derived exclusively from the peer certificate fingerprint recorded at enrollment; any `node_id` in a payload is ignored, and a mismatch drops the connection and audits. Otherwise any enrolled node can impersonate any other, poisoning its telemetry, forging its applied generation to mask drift, and receiving configuration scoped to it. The fingerprint is SHA-256; do not reuse `compute_ca_fingerprint` (`mtls.rs:132-152`), which is a non-cryptographic `DefaultHasher`.
9. `cluster_nodes` table: `node_id`, `name`, `cert_fingerprint`, `address`, `version`, `schema_version`, `status` (`Pending` / `Active` / `Revoked`), `enrolled_at`, `last_seen_at`, `applied_config_generation`, `applied_config_hash`.
10. `GET /api/v1/cluster/nodes` (Viewer+, secrets scrubbed), `GET /api/v1/cluster/nodes/{id}` (Viewer+), `POST /api/v1/cluster/nodes/{id}/activate` (SuperAdmin), `DELETE /api/v1/cluster/nodes/{id}` (SuperAdmin, revokes).
11. **Rate limiting is listener-level, not middleware.** The existing per-endpoint limiter is axum middleware and does not exist on a raw TLS listener, and it is explicitly documented as loopback-scale (`middleware/rate_limit.rs:52-62`) with a fixed window and a map that only evicts entries older than 300 s. The cluster listener gets its own limiter: per-IP **and** global concurrent-enrollment caps, a hard map size cap with LRU eviction, a sliding window, and IPv6 keyed by /64.
12. Node certificates are valid 90 days and auto-renew at two thirds of lifetime over the established channel.
13. **`lorica cluster leave` is authorised and complete.** It requires either control-plane-side deregistration or a SuperAdmin credential on the local management API; it wipes the node key, the CA bundle **and every replicated certificate private key**; it audits on both sides and alerts immediately on the control plane. The first draft let any local shell drop a node from the fleet while keeping the fleet's keys on disk.
14. `lorica cluster status` prints role, node id, connection state, applied generation, and the fleet roster on a control plane.

### Integration Verification

- IV1: **Concurrent** redemption of one token by three simultaneous joiners yields exactly one enrolled node; sequential replay after a successful join is also refused.
- IV2: A revoked node is refused at the TLS handshake on its next connection attempt, and any session it holds is torn down synchronously rather than surviving to the next heartbeat.
- IV3: A follower that submits a payload claiming another node's `node_id` is disconnected and audited; a `Pending` node receives no configuration and no certificates until activated.

---

## Story 9.4: Configuration Replication

As an operator running several edges,
I want to change a route once on the control plane and have every node serve it,
so that I stop copying configuration by hand and stop discovering drift during an incident.

### Acceptance Criteria

1. **An explicit replication allowlist, by table and by field.** "Global settings" cannot replicate wholesale: `GlobalSettings` mixes fleet policy with node-local machine facts, including `cert_export_dir`, `cert_export_owner_uid`, `cert_export_group_gid` and `cert_export_dir_mode` (`models/settings.rs:284-307`), `management_port`, `management_cert_pem_path` / `management_key_pem_path`, `geoip_db_path`, `asn_db_path`, `upgrade_signing_pubkey_path`, `prometheus_scrape_token`, `bot_hmac_secret_hex` and `trusted_proxies`. Replicating those turns one control-plane compromise into arbitrary-path, arbitrary-uid file writes with world-readable modes on every edge in the fleet. Node-local fields are excluded by construction, and a blob containing one is **refused wholesale with a notification**, never silently filtered.
2. **A dedicated replica-apply function, not `import_to_store`.** The import path calls `clear_all` (`import.rs:320`), which deletes `users` and `global_settings` - the follower's own operators and machine configuration - while leaving `waf_custom_rules`, `cert_export_acls`, `ai_crawlers_custom`, `probe_configs` and `sla_configs` untouched so they go stale forever (`store/mod.rs:733-746`). The replica-apply function covers all of them explicitly. `ai_crawlers_custom` is keyed on its UNIQUE `name`, not its autoincrement id; every other replicated entity already carries a UUID `TEXT PRIMARY KEY`, so no identifier migration is needed.
3. Each mutation increments the persisted `cluster_config_generation` from Story 9.1 and produces the canonical blob and its SHA-256 hash from the same story.
4. **A payload-bearing two-phase protocol.** The worker `ConfigReloadPrepare` carries only a generation number and the worker rebuilds from the shared SQLite file (`proxy_wiring/worker_rpc.rs:327-357`), which is a reload-coordination protocol over shared state, not a distribution protocol. The cluster protocol is modelled on it but carries the blob and hash. Timeouts are the per-endpoint values from Story 9.1, not the 2 s Prepare / 500 ms Commit tuned for a same-host UDS (`supervisor.rs:2323-2324`).
5. **A slow node is evicted, not obeyed.** A Prepare that fails on **transport timeout** evicts that node from the commit set, marks it drifted, and the commit proceeds. Only a **semantic rejection** (validation failure) aborts fleet-wide. The first draft let any single connected-but-unresponsive follower veto every configuration change and, because certificate distribution shared the path, escalate to a fleet-wide TLS expiry with no operator lever. A per-node Prepare deadline and a slow-node quarantine threshold back this up.
6. **The honest guarantee is stated in the story, not implied.** All-or-none holds on Prepare. A Commit failure after other nodes have committed leaves the fleet split and is reconciled by convergence on the next heartbeat, not rolled back - the worker-mode equivalent already exists and is instrumented (`inc_config_reload_split_fleet`, `supervisor.rs:526-544`).
7. An offline node does not block the commit; it converges on reconnect by comparing its applied generation, and the transfer is a delta keyed on `applied_config_hash` where possible.
8. **The API surfaces the outcome.** `notify_config_changed()` returns `()` and the handler responds 200 before workers have prepared (`server.rs:359-365`), and the coordinator's `ConfigReloadReport` is `#[allow(dead_code)]`. A completion channel is new work, budgeted here.
9. The follower persists the replica and applies it through the existing arc-swap reload path; configuration is never fetched remotely on the request path.
10. **Follower read-only is one gate plus an explicit allow-list.** `required_role(method, path)` is a single pure function and the middleware is applied once to the whole protected router (`middleware/authorize.rs:39`, `server.rs:1073-1075`), so the gate is roughly twenty lines rather than per-handler work. The cost is the allow-list: roughly ten read-like POST endpoints must stay reachable per this story's own promise - `validate/mtls-pem`, `validate/forward-auth`, `config/export`, `config/import-preview`, `settings/otel/test`, `settings/dns-provider/test`, `settings/notification/test`, `check-dns-manual`, and load-test start/abort. Refused mutations return `409 Conflict` naming the control plane.
11. **Break-glass.** `lorica cluster break-glass --duration <t>` re-enables local mutations on a follower, is loudly bannered in the dashboard and in `cluster status`, is audited locally, and forces a full drift report and reconciliation when the control plane returns. Without it, a control-plane outage removes every incident-response lever on every edge simultaneously: no route disable, no IP ban, no certificate replacement, anywhere.
12. `GET /api/v1/cluster/drift` lists nodes whose applied generation or hash differs, with divergence age. Drift notifications get their own budget and per-node exponential-backoff suppression; the notification dispatcher rate-limits globally per channel (`lorica-notify/src/channels/mod.rs:122-146`), so a flapping node would otherwise drown `CertExpiring` and `BackendDown` alerts.
13. Targeted apply: a mutation may carry a `node_selector` scoping it to a named subset. Unscoped mutations apply fleet-wide.
14. Prometheus: `lorica_cluster_config_generation{node_id}`, `lorica_cluster_config_apply_total{node_id, outcome}`, `lorica_cluster_drift_nodes`.

### Integration Verification

- IV1: A route created on the control plane is servable on both followers within one commit round-trip; a follower stopped before the mutation converges on reconnect with no operator action.
- IV2: A follower that completes mTLS then stops reading its socket is evicted from the commit set and marked drifted while the commit succeeds on the healthy nodes; a follower that rejects the blob on validation aborts the commit fleet-wide.
- IV3: A blob containing a node-local field (`cert_export_dir`) is refused wholesale by the follower and raises a notification; the follower's own `management_cert_pem_path` and `bot_hmac_secret_hex` are unchanged after a fleet apply.

---

## Story 9.5: Control-Plane Certificate Issuance

As an operator,
I want ACME issuance and renewal to happen once for the fleet,
so that three edges serving the same hostname do not produce three different certificates and do not burn the Let's Encrypt rate limit.

### Acceptance Criteria

1. **Need-to-know key distribution, on by default.** A follower receives private keys only for hostnames bound to routes it is selected for, reusing the `node_selector` predicate from Story 9.4. Pushing every key to every node is an explicit opt-in. This is the single highest-leverage change in the epic: at-rest encryption protects a stolen database file, not the service user on the node, and the master key sits beside the database (`crypto.rs:34-70`), so one compromised DMZ edge would otherwise yield the private key of every hostname in the fleet including those it never serves.
2. **The key handling is stated, not implied.** Distribution means decrypting on the control plane under its `EncryptionKey`, shipping the key material over the mutual-TLS channel, and re-encrypting under the follower's own key. The control plane therefore holds every distributed private key in usable form, and `docs/cluster.md` says so in the threat-model section.
3. **Only the renewal task and the expiry notifier are disabled on followers.** Both are spawned from the single shared call site `startup::run_api_server` (`startup/mod.rs:162-190`), which exists precisely because the two modes drifted and caused the v1.5.2 cert-hotswap bug, so one guard covers both modes. There is no component called an "ACME scheduler"; the first draft named one and omitted the expiry notifier, which would have fired one duplicate fleet-wide alert per node.
4. **OCSP refresh keeps running on every node.** Stapling is a serving concern, not an issuance concern: the refresh loop attaches staples to the resolver the node actually serves from (`startup/mod.rs:332-343`, `worker.rs:640-643`). Disabling it on followers would strip stapling from exactly the nodes terminating client TLS, with no push path to replace it. Note also that it is spawned inside each forked worker and never by the supervisor, so any future per-node gating of it must reach the worker process, not just the supervisor.
5. DNS-01 is unchanged: the control plane holds the provider secrets and completes the challenge itself.
6. **HTTP-01 is fleet-aware and fails safe.** The control plane distributes the token and key authorization to the followers plausibly serving that hostname, writing into each node's existing SQLite-backed `AcmeChallengeStore` - one write per node covers all of its workers, since the store already falls back to SQLite on a cache miss (`acme/store.rs:143-159`). Distribution uses the now-fallible `present` from Story 9.1, so a partial distribution aborts the challenge instead of racing `set_ready()`. Challenge entries carry their own TTL so a node that goes offline mid-validation does not keep a live challenge response indefinitely.
7. Issued chain and key are pushed over the mutual-TLS channel and installed through the existing arc-swap hot-swap. **Certificate distribution uses a path independent of the configuration commit**, so a configuration veto or a drifted node can never block a renewal.
8. A follower offline during a renewal receives its certificates as part of reconnect convergence, before it is asked to serve that hostname.
9. The filesystem certificate export zone and its per-pattern ACL keep working on every node, driven by **node-local** settings per Story 9.4 AC #1.
10. Prometheus: `lorica_cluster_cert_push_total{node_id, outcome}` and a per-hostname gauge of the fleet-wide minimum remaining validity, so alerting fires on the worst node.

### Integration Verification

- IV1: Against the Pebble fixture from Story 9.1, an HTTP-01 issuance driven from the control plane succeeds when the validation request is routed to a follower; a follower that fails to receive the token aborts the challenge with a diagnostic naming it, rather than producing an opaque CA validation failure.
- IV2: After a renewal, selected followers serve the new certificate without restart (compared by serial), and a follower **not** selected for that hostname never receives its private key.
- IV3: The `cluster` e2e profile runs certificate distribution in both single-process and workers mode, and a fleet-wide configuration abort does not delay a renewal.

---

## Story 9.6: Telemetry Fan-In

As an on-call engineer,
I want every node's WAF events, health, bans and audit entries in one place, filterable by node,
so that I stop opening three SSH tunnels to correlate one incident.

### Acceptance Criteria

1. Every node stamps a stable `node_id` and a display-only `node_name` on access-log rows, WAF events, SLA samples, probe results, bans and audit entries. Standalone nodes keep working with an empty node identity. This is six table migrations plus per-row growth on the hot path, and `sla_buckets`' `UNIQUE(route_id, bucket_start, source)` (`003_sla_metrics.sql:29`) must become `UNIQUE(node_id, route_id, bucket_start, source)` or fan-in violates it on every node past the first.
2. **Fan-in lands in a separate `cluster-telemetry.db` with its own connection**, never in the control plane's own `access-log.db`. `LogStore` is one connection behind one mutex (`log_store.rs:20`) shared by every insert, dashboard query, retention pass and audit verify.
3. **Retention is a per-node quota, not a global row cap.** The existing `enforce_retention` is a global count (default 100 000 rows, `settings.rs:468-475`), so five nodes would share it and the fleet view would be shallower than each node's own local log, with a noisy edge evicting every quiet edge's rows - precisely the incident-correlation case this story exists for. Retention also gains a chunked delete loop that releases the lock between chunks, and `enforce_waf_retention`'s full `COUNT(*)` (`log_store.rs:678-680`) is replaced by the `MIN(id)`/`MAX(id)` estimate already used on the access-log path for exactly this reason (`log_store.rs:437-444`). `spawn_blocking` moves the wait off the executor but does **not** release the SQLite mutex.
4. **A documented node-count ceiling for access-log fan-in.** SQLite is not a fleet log sink: write amplification is exactly N, and the log-writer module documents SQLite's ceiling as a few thousand commits per second (`log_writer.rs:6-9`). Access-log fan-in is supported up to a stated fleet size and rps; beyond it, the documented topology is WAF events, audit, health and bans fanned in, with access logs going to the Story 9.8 syslog or OTLP sinks. Saying this in the product is better than pretending otherwise.
5. **A two-stage queue on the follower.** The request path writes to a per-kind drop-oldest ring buffer via a non-blocking `try_send`, and a separate drain task is the only producer into the RPC queue. `RpcEndpoint`'s bounded `mpsc` blocks on `send().await` rather than dropping (`rpc.rs:67`, `:297-322`), so asserting drop-oldest over it directly would be untrue at ship time. Overflow increments `lorica_cluster_telemetry_dropped_total{node_id, kind}` and is surfaced in the dashboard. The existing `log_writer.rs` already implements this exact bounded/`try_send`/drop contract and is the model to follow.
6. **The sink execution model is named.** `log_writer`'s consumer is deliberately a plain OS thread rather than a tokio task so it behaves identically in supervisor, worker and single-process modes (`log_writer.rs:20-23`). The story states whether fan-out happens on that thread or on a parallel tokio task fed by a second queue.
7. **The worker-mode path is named.** Workers write to the shared `LogStore` and the supervisor holds the cluster connection, so the follower supervisor reads the shared store rather than adding a per-request worker-to-supervisor RPC over a channel whose in-flight map is documented as unsuitable for that volume.
8. **A per-node ingest quota on the control plane.** Rate and byte quotas enforced at ingest with excess dropped and counted per node, plus a global storage watermark that sheds telemetry before it can affect configuration or audit writes. The follower-side bound protects the follower; nothing today protects the control plane from one node streaming fabricated rows at line rate.
9. `GET /api/v1/cluster/logs` and `GET /api/v1/cluster/waf-events` with `node`, `route`, `from`, `to` filters and cursor pagination, backed by a `(node_id, timestamp)` composite index. The existing logs query runs `SELECT COUNT(*)` on every page (`log_store.rs:291`); the cluster query must not, or the dashboard stalls the ingest writer.
10. Bans fan in for visibility and the control plane can issue a fleet-wide ban. Automatic per-node auto-ban stays local and is not replicated, and `docs/cluster.md` explains why.
11. New `docs/cluster.md`: topology, the security model of the cluster plane and its two listeners, enrollment, what replicates and what does not, the CA key trust model, blast radius, failure modes including break-glass, the access-log fan-in ceiling, a worked Prometheus federation config, and the standalone-to-cluster migration path.

### Integration Verification

- IV1: A request served by follower B appears in the control plane's aggregated view with B's `node_id` within the flush interval, and B's rows are not evicted by a noisy follower A hitting its own quota.
- IV2: With the control plane stopped and 60 seconds of sustained traffic, the follower shows zero 5xx and unchanged p99, the drop counter is non-zero, and no unbounded backlog is retained.
- IV3: One node streaming fabricated telemetry at line rate is throttled by its ingest quota without affecting other nodes' fan-in, configuration commits, or audit writes on the control plane.

---

## Story 9.7: Fleet Dashboard

As an operator,
I want one dashboard that shows the whole fleet,
so that the single control panel promised by the cluster is usable without curl.

### Acceptance Criteria

1. New "Cluster" page (Viewer+ read, SuperAdmin for mutations): node table with name, address, role, status, version, schema version, last seen, applied generation and a drift indicator. The page is registered in the existing `routeLoaders` map (`routes/Dashboard.svelte:13-25`), which already does per-route dynamic imports; this is one line and house style, not an acceptance criterion of its own. Its gzipped chunk stays under 40 KB.
2. **Join-token dialog** (SuperAdmin): mints a token, shows it once with an explicit warning, and displays a command line using `--token-stdin` with the secret in a **separate** copy field. The first draft displayed a ready-to-paste `--token <value>` command, which guaranteed the leak Story 9.3 AC #6 exists to prevent.
3. Node detail drawer: health, resource gauges, recent WAF events, recent bans, applied hash, certificate inventory with expiry, activate action for a `Pending` node, and revoke behind the existing `ConfirmDialog`.
4. **Read-only mode is orthogonal to role.** `canWrite` and `isSuperAdmin` are two derived stores over one `auth` writable (`lib/auth.ts:19`, `:25`), so the change is to derive both over `[auth, nodeMode]` - one edit, not twenty-seven. But all 27 import sites across 14 files need a review pass, because `canWrite`'s semantics change for every consumer including the read-like actions that must stay available on a follower (log export, load-test start).
5. Node filter on Access Logs, Security and SLA, defaulting to all nodes, hidden entirely on a standalone install.
6. A cluster badge showing role and active-versus-expected node count, in a warning state on drift, on a stale heartbeat, or while break-glass is active.
7. A follower renders a persistent read-only banner naming the control plane, and a distinct, louder banner while break-glass is active.
8. Frontend gates green: `pnpm exec svelte-check`, `pnpm tsc --noEmit` strict, `pnpm lint`. No `any`, no `@ts-ignore`, no `{@html}`. Colocated Vitest files for new components.

### Integration Verification

- IV1: Minting a token in the dashboard and running the displayed `--token-stdin` command on a fresh node enrolls it as `Pending`; activating it moves it to `Active` without a page reload.
- IV2: A follower's dashboard hides mutating controls while leaving log export and the validate/test actions reachable, matching the API allow-list exactly - asserted against the `409` responses rather than assumed.
- IV3: Vitest coverage on the node table, drift indicator, read-only banner and break-glass banner.

---

## Story 9.8: Syslog Sink and OTLP Logs Signal

As an operator with an existing SIEM,
I want Lorica to ship its logs where the rest of my estate already sends them,
so that I do not have to scrape a dashboard or tail a file to get access logs and WAF events into my pipeline.

Independent of the cluster. Should land first in the cycle.

### Acceptance Criteria

1. **Syslog: RFC 5424 implemented in-tree**, over UDP, TCP and TCP with TLS using the already-present `tokio` and `tokio-rustls` stack. No new dependency: the `syslog` crate is unmaintained since 2022 and Unix-socket-oriented, and RFC 5424 framing is a header line plus structured data. Configurable facility, per-event-kind severity mapping and structured-data fields. Access logs, WAF events and audit entries independently toggleable.
2. **OTLP logs: enable the `logs` feature** on the already-pinned `opentelemetry` / `opentelemetry_sdk` / `opentelemetry-otlp` 0.32 crates, which are currently declared `trace`-only (`lorica/Cargo.toml:102-106`). No new crate and no version bump. `trace_id` and `span_id` are attached from the active span context, which `lorica/src/otel.rs:24-70` already parses, rather than by adding `opentelemetry-appender-tracing` (not in the tree).
3. Both sinks carry `node_id` and `node_name` from Story 9.6 and work identically on a standalone install.
4. Both sinks are non-blocking and bounded with the same hard rule as Story 9.6, reusing the `log_writer.rs` bounded/`try_send`/drop contract. Overflow increments `lorica_log_sink_dropped_total{sink, kind}`.
5. **The execution model is an acceptance criterion, not an implementation detail.** `log_writer`'s consumer is deliberately a non-tokio OS thread; a syslog-over-TLS sink and an OTLP exporter both want async I/O. The story states whether the sinks run on that thread with blocking sockets or on a parallel tokio task fed by a second queue.
6. Settings gains a "Log export" tab with a per-sink test action reporting success, failure reason and round-trip time, mirroring the existing OTel exporter test endpoint.
7. Both sinks hot-reload through the existing two-phase path with no restart.
8. Sink secrets (TLS client keys, OTLP authorization headers) are scrubbed from JSON responses and TOML export, matching the existing treatment of webhook and Slack URLs.
9. Documentation in the README observability section and `docs/cluster.md`, with a worked SIEM example and a worked OTLP collector example.

### Integration Verification

- IV1: A WAF block produces a well-formed RFC 5424 message at a listening collector with the expected facility, severity and structured data.
- IV2: A proxied request produces an OTLP log record whose `trace_id` matches the trace exported for the same request, through the existing Jaeger-based smoke harness.
- IV3: The `log-sinks` e2e profile asserts delivery for all three event kinds and asserts zero request-path impact with both collectors stopped.

---

## Story 9.9: Fleet-Wide Audit Trail

As a compliance-conscious operator,
I want the audit log to answer "who changed what, on which node", without overstating what that proves,
so that the guarantee shipped in v1.6.0 survives the move to a fleet and is not misrepresented.

### Acceptance Criteria

1. **The security property is stated accurately.** The chain is an unkeyed SHA-256 over public fields with no signing key; `audit.rs:14-27` already documents it as tamper-evident rather than tamper-proof, and records that an HMAC was considered and rejected. The control plane's aggregated copy is therefore **strictly weaker** than each origin node: a compromised follower can stream a self-consistent forged history that verifies clean, and an attacker with write access to the control plane can rewrite a node's rows and recompute that node's chain. `docs/cluster.md` and this story say so plainly. The authoritative anchor remains each node's own `lorica::audit` tracing event (`audit.rs:387-405`) shipped to a WORM sink via Story 9.8.
2. **Fan-in preserves the origin chain verbatim.** Aggregated rows carry `node_id`, `origin_id`, `prev_chain_hash` and `chain_hash` copied unchanged through a **separate insert path**. They must never go through `insert_audit`, which chains off the global tail (`log_store.rs:832-840`) and would corrupt the control plane's own chain by linking its next entry to a follower row.
3. **Per-node seals and partitioned verification.** `audit_log_meta` is keyed on a single hardcoded `retention_seal` (`log_store.rs:811`) and `verify_audit_chain` walks the whole table `ORDER BY id ASC` with one running hash (`log_store.rs:980-983`), so on an interleaved table it would chain node A's row to node B's and report a false break. The aggregated copy needs a seal per node (`retention_seal:<node_id>`) and a verify variant partitioned `WHERE node_id = ? ORDER BY origin_id ASC`.
4. Cluster lifecycle operations are audited on both sides: token mint, join, activation, certificate issuance and renewal, revocation, `cluster leave`, break-glass entry and exit, fleet-wide ban, and node-scoped apply, each with operator identity, role, source IP and target node.
5. `GET /api/v1/audit` gains a `node` filter (Operator+). `GET /api/v1/audit/verify` (SuperAdmin) accepts a node selector and reports per node, localising the earliest affected row.
6. A fleet-wide mutation records the operator identity once on the control plane and a linked per-node apply outcome, so the action and its effect are linkable without duplicating the operator record N times.
7. Dashboard audit sub-page gains a node column, node filter, and per-node verify results.

### Integration Verification

- IV1: A route created on the control plane and applied to two followers produces one operator-identified entry plus a linked per-node outcome for each follower.
- IV2: **A follower submitting a self-consistent forged chain is accepted by `verify` as arithmetically valid**, and the test asserts this documented limitation rather than a guarantee the design does not provide. Tampering with the aggregated copy of one node's rows without recomputing is localised to that node and row while other nodes verify clean.
- IV3: The control plane's own chain verifies clean after ingesting fan-in rows, proving fan-in never routes through `insert_audit`.

---

## End-to-End Test Topology

The first draft proposed six new `tests-e2e-docker` profiles. Each profile costs seven manual touchpoints (compose service, runner service, two volumes, an entrypoint script, a `Dockerfile` COPY line, a runner script, and a `run.sh` phase plus `ALL_PROFILES` entry, whose omission causes the stale-volume failures `run.sh:40-45` documents). Six profiles, two of them doubled across single-process and workers mode, would roughly double a suite that is already a long serial run.

Consolidated to two:

- **`cluster`** (control plane plus two followers): absorbs transport, enrollment, configuration replication, certificate distribution and telemetry, which all need the identical topology. Runs in both single-process and workers mode. The cluster port binds directly, so unlike the management-API profiles it needs no `socat` shim.
- **`log-sinks`** (one node, two collectors): Story 9.8, no topology overlap with the cluster.

The Pebble fixture from Story 9.1 is a prerequisite of the `cluster` profile's certificate assertions.

---

## Out of Scope (deferred)

- **Peer-to-peer consensus and leader election.** A split-brain bug in a security appliance is a worse failure mode than the configuration drift it would solve. The control plane is designated, not elected.
- **Control-plane high availability.** A standby control plane with state replication and failover is a v1.8.0+ candidate. The accurate statement of the v1.7.0 failure mode is: **already-configured traffic is unaffected**, but no configuration change, certificate renewal or fleet-wide incident-response action is possible while the control plane is down, and node certificates expire at 90 days. Break-glass (Story 9.4 AC #11) is the mitigation, not a substitute.
- **Shared rate-limit budgets across nodes.** The cost of a distributed counter over a WAN is not justified by what it buys.
- **Automatic cross-node ban propagation.** Bans fan in for visibility and a fleet-wide ban can be issued manually.
- **Cross-node session, challenge and forward-auth verdict sharing.**
- **Signed audit checkpoints.** Making follower-side forgery detectable requires each node to sign its chain head and the control plane to record signed checkpoints, so a retroactive rewrite shows as a fork. Deferred; Story 9.9 AC #1 documents the resulting limitation instead of hiding it.
- **Hardware or passphrase protection for the cluster CA key.** It inherits the existing plaintext-file master key. Deferred, documented, and worth revisiting before any deployment where the control plane is not itself a hardened host.
- **Kubernetes Ingress, service discovery and external configuration providers** (etcd, Consul). Out of scope by design per `COMPARISON.md`.
- **Audit-log Merkle-tree mode** (carried over from Epic 8).
