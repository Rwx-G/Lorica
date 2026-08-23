# Story 9.4: Configuration Replication

**Epic:** 9 (v1.7.0)
**Status:** Draft
**Author:** Romain G.

**Depends on:** Stories 9.1, 9.2, 9.3.

## Story

As an operator running several edges,
I want to change a route once on the control plane and have every node
serve it,
so that I stop copying configuration by hand and stop discovering drift
during an incident.

## Acceptance Criteria

1. An explicit replication allowlist, by table and by field. Node-local
   fields are excluded by construction, and a blob containing one is
   **refused wholesale with a notification**, never silently filtered.
2. A dedicated replica-apply function, not `import_to_store`. It covers
   `waf_custom_rules`, `cert_export_acls`, `ai_crawlers_custom` (keyed
   on its UNIQUE `name`, not its autoincrement id), `probe_configs` and
   `sla_configs` explicitly.
3. Each mutation increments the persisted `cluster_config_generation`
   from Story 9.1 and produces the canonical blob and SHA-256 hash from
   the same story.
4. A payload-bearing two-phase protocol modelled on the worker one but
   carrying blob and hash. Timeouts are the per-endpoint values from
   Story 9.1, not the same-host UDS defaults.
5. A Prepare that fails on **transport timeout** evicts that node from
   the commit set, marks it drifted, and the commit proceeds. Only a
   **semantic rejection** aborts fleet-wide. A per-node Prepare deadline
   and a slow-node quarantine threshold back this up.
6. The guarantee is stated honestly in the story and in
   `docs/cluster.md`: all-or-none holds on Prepare; a Commit failure
   after other nodes committed leaves the fleet split and is reconciled
   by convergence on the next heartbeat, not rolled back.
7. An offline node does not block the commit; it converges on reconnect
   by comparing its applied generation, transferring a delta keyed on
   `applied_config_hash` where possible.
8. The API surfaces the outcome. A completion channel is new work.
9. The follower persists the replica and applies it through the existing
   arc-swap reload path. Configuration is never fetched remotely on the
   request path.
10. Follower read-only is one gate in the `authorize` middleware plus an
    explicit allow-list of the read-like POST endpoints that must stay
    reachable. Refused mutations return `409 Conflict` naming the
    control plane.
11. `lorica cluster break-glass --duration <t>` re-enables local
    mutations on a follower, is loudly bannered in the dashboard and in
    `cluster status`, is audited locally, and forces a full drift report
    and reconciliation when the control plane returns.
12. `GET /api/v1/cluster/drift` lists nodes whose applied generation or
    hash differs, with divergence age. Drift notifications get their own
    budget and per-node exponential-backoff suppression.
13. Targeted apply: a mutation may carry a `node_selector` scoping it to
    a named subset. Unscoped mutations apply fleet-wide.
14. Prometheus: `lorica_cluster_config_generation{node_id}`,
    `lorica_cluster_config_apply_total{node_id, outcome}`,
    `lorica_cluster_drift_nodes`.

## Tasks / Subtasks

- [ ] AC #1: enumerate the allowlist; wholesale-refusal path +
      notification.
- [ ] AC #2: replica-apply function covering the five tables the import
      path misses.
- [ ] AC #3: wire generation + canonical hash.
- [ ] AC #4: payload-bearing Prepare/Commit/Abort messages.
- [ ] AC #5: transport-timeout eviction, quarantine threshold, per-node
      deadline.
- [ ] AC #6: split-fleet reconciliation on heartbeat + docs.
- [ ] AC #7: reconnect convergence with hash-keyed delta.
- [ ] AC #8: completion channel from the coordinator back to the handler.
- [ ] AC #9: replica persist + arc-swap apply.
- [ ] AC #10: read-only gate + allow-list; 409 bodies.
- [ ] AC #11: break-glass command, banners, audit, reconciliation.
- [ ] AC #12: drift endpoint, notification budget, suppression.
- [ ] AC #13: `node_selector` plumbing.
- [ ] AC #14: metrics.

## Dev Notes

**AC #1 is the difference between "pushes routes" and "remote file write
as an arbitrary uid on every edge".** `GlobalSettings` mixes fleet policy
with node-local machine facts. The dangerous set:
`cert_export_dir` (`models/settings.rs:284`), `cert_export_owner_uid`
(`:290`), `cert_export_group_gid` (`:296`), `cert_export_dir_mode`
(`:302`). Cert export is driven entirely by those, so a compromised
control plane setting `cert_export_dir=/etc/cron.d`, `owner_uid=0`,
`dir_mode=0777` makes every follower write attacker-influenced files
there as its service user, with private keys world-readable. The rest of
the node-local set: `management_port` (`:92`),
`management_cert_pem_path` / `management_key_pem_path` (`:420`, `:426`),
`geoip_db_path` / `asn_db_path` (`:247`, `:262`),
`upgrade_signing_pubkey_path` (`:390`), `prometheus_scrape_token`
(`:411`), `bot_hmac_secret_hex` (`:320`), `access_log_retention` /
`waf_event_retention` (`:166`, `:170`), `trusted_proxies` (`:189`).

**AC #2: do not reuse the import path.** `import_to_store` calls
`clear_all` (`import.rs:320`), and `clear_all` (`store/mod.rs:733-746`)
deletes `users` and `global_settings`, i.e. the follower's own operators
and machine configuration, while **not** deleting `waf_custom_rules`,
`cert_export_acls`, `ai_crawlers_custom`, `probe_configs` or
`sla_configs`, so those go stale on the follower forever. Destructive
where it must not be, incomplete where it must be.

**Identifiers are not a problem, contrary to an early suspicion.** Every
replicated config entity is `id TEXT PRIMARY KEY` holding a UUIDv4
(`migrations/001_initial.sql:18,36,53,77,85,93`; `store/mod.rs:750`
`new_id()` = `Uuid::new_v4()`), and `route_backends` is `(TEXT, TEXT)`
(`001_initial.sql:68`). No ID remapping and no UUID migration is needed.
Two narrow exceptions: `waf_custom_rules.id` is INTEGER but
operator-assigned, therefore stable across nodes
(`013_waf_persistence.sql:2`, `lorica-api/src/waf.rs:288`); and
`ai_crawlers_custom.id` is AUTOINCREMENT (`store/ai_crawlers.rs:58`) but
nothing references it by id, so key on `name`.

**AC #4: the worker two-phase is not a distribution protocol.**
`ConfigReloadPrepare` carries a generation number and nothing else
(`lorica-command/proto/command.proto:122-124`), and the worker rebuilds
by reading the **shared SQLite file** itself via `build_proxy_config`
(`proxy_wiring/worker_rpc.rs:327-357`, `:359`). That works because
workers are forked siblings on one host. A follower across a WAN has no
shared store. The existing timeouts are also same-host values:
Prepare 2 s, Commit 500 ms (`startup/supervisor.rs:2323-2324`). Note the
worker commit handler already replies *before* the cert-resolver reload
precisely because a slow OCSP fetch blew that deadline
(`worker_rpc.rs:503-520`); a cluster commit touching certificates
inherits the same problem an order of magnitude worse.

**AC #5 closes the worst availability hole in the first draft.** It said
a follower failing Prepare aborts the commit fleet-wide. Combined with
`OUTBOUND_QUEUE_CAP = 256` (`rpc.rs:67`) and the 5 s default timeout
(`:77`), a hostile or merely wedged follower that completes mTLS then
stops reading its socket (TCP zero-window) fills the queue, blocks
`request()`, times out Prepare, and vetoes every configuration change in
the fleet. Because the first draft also pushed renewed certificates over
the same commit path, sustaining that until expiry produced a fleet-wide
TLS outage with no operator lever, since follower APIs were 409-locked.
The optimal attack was to stay connected and slow, a state the design
rewarded because AC #7 exempts *offline* nodes. Story 9.5 AC #7 now also
puts certificate distribution on an independent path.

**AC #6: the honest semantics.** Abort exists only on the Prepare-failure
path (`supervisor.rs:2399-2427`, `CommandType::ConfigReloadAbort`).
There is no rollback after Commit: `supervisor.rs:2432-2478` collects
`commit_failed` and returns, and the code names the outcome itself at
`supervisor.rs:526-544`, logging "two-phase config reload split fleet"
and incrementing `inc_config_reload_split_fleet()`. On failure it force-
converges via the legacy broadcast fallback (`:545-548`), and the
mutation is already committed to SQLite before fan-out begins. The real
guarantee is all-or-none on Prepare, best-effort on Commit, eventually
consistent after.

**AC #8: there is no return path today.** `notify_config_changed()` bumps
a `watch::Sender<u64>` and returns `()` (`lorica-api/src/server.rs:359-365`);
the handler responds 200 before workers have prepared. The coordinator's
`ConfigReloadReport` (`supervisor.rs:2327-2334`) is `#[allow(dead_code)]`
and never leaves the spawned task. Also note the `watch` channel
**coalesces**: two generations landing quickly collapse into one local
reload (`supervisor.rs:446`, `:502`), and the supervisor-local
`reload_generation` (`:473`) is unrelated to the cluster generation. The
cluster generation must be threaded explicitly.

**AC #10 is cheaper than feared, but the allow-list is the real work.**
`required_role(method, path)` is one pure function holding the whole
matrix (`middleware/authorize.rs:39`) and the layer is applied once to
the entire protected router (`server.rs:1073-1075`, 119 routes);
`ApiError::Conflict` already maps to 409 (`error.rs:30`, `:84`). So the
gate is roughly twenty lines. But a naive "refuse every non-GET" breaks
the read-like POSTs this story promises stay available:
`validate/mtls-pem` (`server.rs:538`), `validate/forward-auth` (`:542`),
`config/export` (`:694`), `import_preview` (`:703`),
`test_otel_connection` (`:758`), `test_dns_provider` (`:790`),
`test_notification` (`:826`), `check_dns_manual` (`:908`), load-test
start/abort (`:1054-1062`). `/api/v1/auth/*` is on a separate router and
is unaffected.

**AC #11 exists because the first draft had no break-glass.** An attacker
who DoSes the control plane would simultaneously freeze incident response
on every edge: no route disable, no ban, no certificate replacement, no
WAF change, anywhere.

**AC #12**: the notification dispatcher rate-limits globally per channel
with a suppression counter (`lorica-notify/src/channels/mod.rs:122-146`),
so a node flapping around the drift threshold would consume the budget
and suppress genuine `CertExpiring`, `BackendDown` and `WafAlert` events.

**Schema skew, from Story 9.2 AC #5.** There is no `deny_unknown_fields`
anywhere in `lorica-config` or `lorica-api` today, so without Story 9.1
AC #12 a follower on schema N-1 would silently discard unknown fields
from an N blob, write the row without them, and report "applied ok",
possibly dropping a security-relevant setting.

## Dev Agent Record

### Debug Log

(empty)

### Completion Notes

(empty)

## File List

Anticipated:

- `lorica-cluster/src/replication.rs`, `allowlist.rs`
- `lorica-config/src/store/replica.rs` (replica-apply)
- `lorica-api/src/middleware/authorize.rs` (read-only gate + allow-list)
- `lorica-api/src/server.rs` (completion channel)
- `lorica/src/startup/supervisor.rs` (cluster generation threading)
- `lorica/src/cli.rs` (`cluster break-glass`)
- `lorica-api/openapi.yaml`, `docs/cluster.md`

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-08-23 | 0.1 | Story drafted from the revised Epic 9 PRD. Slow-node eviction replaces fleet-wide veto; replication allowlist replaces wholesale settings replication; break-glass added. Status Draft. | Romain G. |
