# Story 12.1: The Stream Model, Shared Backends and the Release's Schema Decisions

**Epic:** [Epic 12 - TCP and UDP Stream Proxying (v1.11.0 and v1.12.0)](../prd/epic-12-v1.11.0.md)
**Status:** Review
**Priority:** P0
**Author:** Romain G.
**Depends on:** the `lorica-fleet` extraction (backlog #52, "The cycle's
first commit" of the PRD), committed as `4e864593`. Story 12.0 is
independent (frontend only).
**Blocks:** Stories 12.2 to 12.12, and through them Phase 2. This story
owns the stream schema, the `CANONICAL_FORMAT_VERSION` step of 1.11.0,
the typed health check, the reserved-port and listen-address rule shared
by the CLI and the control plane, and the end-reason enum every later
story uses.

---

As an operator,
I want to declare a stream and point it at backends I already manage,
so that one list of backends and one health state serve both my HTTP routes and my TCP streams.

## Problem

Lorica has no object for a layer-4 listener. The PRD decides that a
stream is its own model (D3), that it shares the `Backend` object with
HTTP routes except where UDP forbids it (D2), and that it is replicated,
targeted and audited like a route from the first commit (the "full
citizen" rule). Every later story adds fields to the stream; this one
fixes the frame they land in: the tables, the canonical blob version and
the fleet upgrade order of the whole release, the typed health check
that 12.7 and 12.14 extend, how a control plane learns which ports a
follower already holds, and the closed vocabulary a stream connection
ends with.

Nothing in this story binds a socket. Story 12.2 binds; this story
stores, validates, replicates and exposes, and states the rules 12.2
binds by (D-5, D-8).

## Acceptance Criteria

These are the PRD's, as amended on 2026-11-14 after the first draft of
this story. They are the contract.

1. **New `Stream` model in `lorica-config`** with the fields this story gives meaning to: id, name, group name, protocol (`tcp` or `udp`), `enabled`, listen address and a single port or a port range, IPv4 and IPv6, a list of backends through a `stream_backends` join (the counterpart of `RouteBackend`), `node_selector`, timestamps. A disabled stream is replicated but bound on no node. There is no `managed_by`: nothing in this epic can set it, since D9 keeps stream mutations off the automation and MCP surfaces. Each later story adds its own fields, validation and migration; no field is stored before a story gives it a meaning.
2. **Port ranges map port to port.** A range stream forwards listen port N to backend port N; its backends are given without a port. A range is capped at 1,024 ports per stream by default.
3. **The typed health check, by additive migration (D2).** The migration adds the typed definition and keeps `health_check_path`. In 1.11.0 the typed definition is read, and both the typed definition and `health_check_path` are written; the management API, both OpenAPI documents, the dashboard backend form and `api.ts`, and the MCP and automation backend tools accept both shapes, with the old one documented as deprecated. A test proves the 1.10.6 binary still opens a 1.11.0 database, so a hot-upgrade rollback (`docs/hot-upgrade.md`) does not become an outage.
4. **UDP-only backends.** A backend attached to a UDP stream cannot be attached to an HTTP route or a TCP stream, and cannot carry a non-UDP health check; the validation error names the stream. Until Story 12.14 ships UDP checks, a UDP backend has active checks disabled and relies on passive detection.
5. **The canonical config decision is taken once, here, for the release.** `Stream` and `stream_backends` join `CanonicalConfig`, whose version check is strict equality and whose decoder refuses unknown fields. This story decides the `CANONICAL_FORMAT_VERSION` step for 1.11.0 and the fleet upgrade order it implies, and updates `docs/cluster.md` "Running a Mixed-Version Fleet". Later stories add fields inside that decision.
6. **Replicated and targeted.** Streams take part in two-phase replication and honour `node_selector` exactly as routes do. A follower never binds a stream it was not targeted by. The control plane binds only the streams with an empty selector: it holds every stream to replicate them, and unlike a route, which only answers names, a stream opens a port, so holding one must not open it there. A standalone node binds every enabled stream.
7. **Port conflicts are checked per node.** Followers report their reserved ports (HTTP, HTTPS, management, automation, cluster, enrollment) in their heartbeat. The control plane refuses a stream whose port or range overlaps a targeted node's reserved ports or another stream on that node and protocol, using the same rule as the CLI's `refuse_reserved` so the two cannot drift. The error names the conflicting node and object. The node refuses at bind as the backstop (Story 12.2).
8. **The closed set of end reasons** for stream connections and sessions is defined here, as one enum every later story uses: `client_close`, `backend_close`, `idle_timeout`, `total_timeout`, `connect_failed`, `no_healthy_backend`, `refused` with a reason, `clienthello_timeout`, `proxy_header_invalid`, `detection_timeout`, `request_bound_reached`, `response_bound_reached`, `backend_down`, `config_removed`, `drained_by_upgrade`, `node_shutdown`. Transfer (Story 12.16) is an event, not an end.
9. **Management API CRUD** for streams, with the same validation, audit and JSON GET secret filtering as routes. TOML export and import carry streams.
10. **HTTP non-regression.** The existing backend, route and health-check suites pass on the migrated schema, and the migration is idempotent.

## Integration Verification

- IV1: A stream targeted at one node of a three-node fleet is in that node's replicated configuration only (per-recipient replication, Story 10.0), and is bound on no other node.
- IV2: A stream on a follower's HTTPS port is refused by the control plane with the follower's name in the error.

IV1 is verified in the shape of the e2e `cluster` profile: a control
plane and two followers. A stream targeted at one follower is in that
follower's payload only and is bound on that follower only: not on the
other follower, which never receives it, and not on the control plane,
which holds it to replicate it and does not bind it (AC #6, D-8).

## Decisions taken in this story

Each decision states its reason and what it gives up.

### D-1. The `streams` and `stream_backends` schema (migration 71)

`MIGRATIONS` ends at 70 (`migrate_address_spellings`,
`lorica-config/src/store/mod.rs`); 1.11.0's migrations start at 71.

```sql
CREATE TABLE IF NOT EXISTS streams (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    group_name     TEXT NOT NULL DEFAULT '',
    protocol       TEXT NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    enabled        INTEGER NOT NULL DEFAULT 1,
    listen_address TEXT NOT NULL,
    port_first     INTEGER NOT NULL CHECK (port_first BETWEEN 1 AND 65535),
    port_last      INTEGER NOT NULL CHECK (port_last BETWEEN port_first AND 65535),
    node_selector  TEXT NOT NULL DEFAULT '[]',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_streams_name ON streams(name);
CREATE INDEX IF NOT EXISTS idx_streams_protocol_ports
    ON streams(protocol, port_first, port_last);
CREATE TABLE IF NOT EXISTS stream_backends (
    stream_id  TEXT NOT NULL REFERENCES streams(id) ON DELETE CASCADE,
    backend_id TEXT NOT NULL REFERENCES backends(id) ON DELETE CASCADE,
    PRIMARY KEY (stream_id, backend_id)
);
CREATE INDEX IF NOT EXISTS idx_stream_backends_backend
    ON stream_backends(backend_id);
```

- **Ports as two integers, `port_first` and `port_last`**, a single
  port being `first == last`. Reason: the overlap check is an interval
  comparison the index serves, the canonical blob and the TOML export
  stay flat scalars, and there is no string grammar (`"6000-6099"`) to
  parse at three boundaries. Gives up: the nginx-style range string in
  the API; the dashboard (Story 12.10) renders it.
- **The 1,024-port cap is a constant** (`STREAM_PORT_RANGE_MAX = 1024`,
  `lorica-config/src/models/stream.rs`), enforced by `Stream::validate()`
  and not by the `CHECK`, so a later story that makes it a setting needs
  no table rebuild. The `CHECK`s hold only what no setting can change:
  1..=65535 and `first <= last`.
- **`enabled`**, default true. A disabled stream is stored, replicated,
  cut and applied like an enabled one, and bound on no node (D-8). A
  disabled stream still takes part in the conflict checks of D-5: its
  ports stay reserved, so enabling it can never fail on a conflict that
  was accepted while it was off. Gives up: two streams on one port
  alternated by toggling.
- **`listen_address` is an IP literal, stored in its canonical text
  form** (`IpAddr`'s `Display`, which is RFC 5952 for IPv6, the form
  migration 70 settled for route names). One address per stream,
  IPv4 or IPv6, the unspecified address of either family allowed, with
  the dual-stack semantics of D-5. An IPv4-mapped IPv6 address
  (`::ffff:a.b.c.d`) is refused: it names an IPv4 socket through the
  IPv6 API and would defeat the overlap rule. No hostname: a listener
  binds an address.
- **`name` is an identifier**, required, unique fleet-wide, over the
  `node_selector` alphabet (ASCII lowercase, digits, `-`, `_`,
  1..=64). Reason: errors, audit rows, log rows (12.9) and the
  per-stream metric label name the stream by it. Gives up: free-form
  display names.
- **`group_name`** follows the route and backend rule
  (`validate_group_name`, `lorica-api/src/routes/crud.rs`).
- **`node_selector`** is a JSON array column with the route's exact
  rule (`validate_node_selector_names`, `lorica-config/src/models/route.rs`)
  and the control plane's roster existence check.
- **No `managed_by`** (AC #1 as amended).
- **`stream_backends` carries only the pair.** Per-link fields (a
  backup flag, Story 12.3 AC #3) are added by the story that gives them
  meaning, as columns on this table and fields on `StreamBackend`.
- **Foreign keys cascade on both sides**, like `route_backends`
  (`001_initial.sql`), so `clear_all`, backend deletion and stream
  deletion need no ordering. Story 12.2 owns what a cascade does to
  live connections.
- **Later stories add columns to `streams` through their own
  migrations** (72 and 73 are taken by this story; see D-2 and D-4),
  and the store reads streams through an explicit column list
  (`STREAM_COLUMNS`, the `BACKEND_COLUMNS` pattern of
  `store/backends.rs`), never `SELECT *`.

### D-2. The typed health check (migration 72) and its dual write

**Model.** A new `HealthCheck` enum in
`lorica-config/src/models/health_check.rs`:

```rust
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HealthCheck {
    Http { path: String },
    TcpConnect,
}
```

Only the two kinds that exist today. Story 12.7 adds `TcpSendExpect`,
Story 12.14 `UdpSendExpect`; a kind is a variant here, not a column.
`Backend` gains `#[serde(default)] pub health_check: HealthCheck`
(default `TcpConnect`) and keeps `health_check_path: Option<String>`,
documented as deprecated and HTTP-only. `health_check_enabled` and
`health_check_interval_s` are unchanged.

**Column.** `backends.health_check_json TEXT`, nullable, no default,
added with `add_column_if_absent` (idempotent by construction), no
backfill. NULL means "no typed definition stored", which is every row
1.10.6 or earlier wrote.

**The reconciliation rule, the one place it lives:**
`HealthCheck::reconcile(stored: Option<HealthCheck>, legacy_path: Option<&str>) -> HealthCheck`.
The stored typed definition is honoured only while its projection onto
`health_check_path` (`HealthCheck::legacy_path()`: `Http { path }` gives
`Some(path)`, every other kind `None`) equals the stored
`health_check_path`. Otherwise the row was last written by a binary
that does not know the typed column, and `health_check_path` is the
truth (`Some(p)` gives `Http { path: p }`, `None` gives `TcpConnect`).

Why this rule, and not "typed wins": a rollback to 1.10.6 followed by an
edit of the path, then a re-upgrade, must not resurrect the probe the
operator replaced. The matrix the vector test pins:

| Stored typed | Stored path | Read as | Who wrote it |
|---|---|---|---|
| NULL | NULL | `TcpConnect` | 1.10.6 or earlier |
| NULL | `/h` | `Http{/h}` | 1.10.6 or earlier |
| `Http{/h}` | `/h` | `Http{/h}` | 1.11.0 |
| `TcpConnect` | NULL | `TcpConnect` | 1.11.0 |
| `Http{/h}` | `/x` | `Http{/x}` | 1.10.6 edited the path after 1.11.0 |
| `Http{/h}` | NULL | `TcpConnect` | 1.10.6 cleared the path |
| `TcpConnect` | `/x` | `Http{/x}` | 1.10.6 set a path |

**Where it runs.** On read, in `row_to_backend`
(`lorica-config/src/store/row_helpers.rs`), so every reader (the
canonical encoder, the API, the health loop, the export) sees one
consistent model. On write, `create_backend` and `update_backend`
(`store/backends.rs`) persist the reconciled definition into
`health_check_json` and its projection into `health_check_path`, so a
1.11.0 write can never leave the two columns disagreeing. The setter
`Backend::set_health_check(HealthCheck)` keeps the in-memory pair
consistent for the API. A blob or TOML file carrying a `Backend`
without `health_check` deserialises to the default and is reconciled
against its path by the same rule when the store writes it.

**Why a 1.10.6 binary still opens a 1.11.0 database** (verified on the
`v1.10.6` tag, `git show v1.10.6:lorica-config/src/store/mod.rs`, whose
`run_migrations` is byte-identical to today's):

1. The runner reads `MAX(version)` from `schema_migrations` and applies
   only entries above it. A 1.11.0 database records 73, above 1.10.6's
   last entry (70): 1.10.6 applies nothing and records nothing.
2. 1.10.6 reads `backends` through the explicit `BACKEND_COLUMNS` list
   (`store/backends.rs`), so an extra column is never read.
3. 1.10.6 inserts and updates `backends` with explicit column lists;
   `health_check_json` is nullable with no default, so its inserts
   succeed (NULL) and its updates leave it as it was, which is exactly
   the case the reconciliation rule exists for.
4. `streams`, `stream_backends` and `cluster_nodes.reserved_ports_json`
   are never named by 1.10.6. `clear_all` (import) deletes `backends`,
   which cascades into `stream_backends` with `foreign_keys=ON`; a
   1.10.6 import on a 1.11.0 database therefore leaves streams with no
   backends, not a constraint failure.
5. No migration of this story adds a `UNIQUE` index, a trigger or a
   `NOT NULL` column without default to a table 1.10.6 writes.

The per-commit test is described in Dev Notes, Lot 1; the scenario with
the real 1.10.6 binary belongs to Story 12.12 (Dev Notes, "Handed to
Story 12.12").

What it gives up: a 1.10.6 rollback runs on the legacy path only, so a
backend whose typed kind 1.10.6 cannot express (from 12.7 on:
send/expect) is probed by TCP connect while rolled back. Stated in
`docs/hot-upgrade.md` by the story that adds such a kind.

### D-3. `CANONICAL_FORMAT_VERSION` goes to 3, once, for the whole of 1.11.0; followers first, then the control plane at once

`CanonicalConfig` gains `streams: Vec<Stream>` and
`stream_backends: Vec<StreamBackend>`, and `Backend` gains
`health_check`. All three are unknown fields to a 1.10.6 decoder
(`deny_unknown_fields` on `CanonicalConfig` and on `Backend`), so a
1.10.6 node must refuse a 1.11.0 blob **by version**, which is what the
tolerant peek in `decode_canonical` exists for. The number therefore
moves, from 2 to 3, exactly once in this release. Stories 12.2 to 12.11
add stream fields inside version 3 and update `CANONICAL_SHAPE_DIGEST`
deliberately, the Story 10.4 precedent
(`story_10_4_rides_format_version_two_without_a_second_bump`, which this
story rewrites for version 3: "every 1.11.0 shape rides version 3").

The upgrade order does not change: **followers first, the control plane
last**, because the schema handshake (`evaluate_hello`,
`lorica-cluster/src/handshake.rs`) refuses a follower whose schema is
behind the control plane's (`SCHEMA_TOO_OLD`), and 1.11.0 carries
migrations 71 to 73.

What the strict equality costs, and what `docs/cluster.md` must now say
because it does not today: between the first follower's upgrade and the
control plane's, the control plane (1.10.6) still stamps version 2, an
upgraded follower refuses that blob **semantically**, and a semantic
refusal aborts the round fleet-wide (`docs/cluster.md`, "The two
phases"). So **configuration changes do not replicate to any node during
the rollout window**; traffic is unaffected, every node keeps serving
what it has. The procedure is: freeze configuration changes, upgrade the
followers, upgrade the control plane immediately after, then resume. The
1.8.0 bump (Story 10.1, version 1 to 2) had the same window and the
document never said so.

Rejected alternative: a 1.11.0 decoder accepting versions 2 and 3,
decoding a v2 blob with empty streams. It removes the freeze window, but
a control plane rolled back to 1.10.6 would then push "no streams" to
every 1.11.0 follower and they would delete theirs: a rollback of one
node unbinding listeners fleet-wide. Strict refusal keeps the followers
serving what they have until the control plane is upgraded again.

Rollback of the control plane alone to 1.10.6 (hot-upgrade rollback):
1.10.6 opens the database (D-2), keeps the stream rows it cannot see,
admits the 1.11.0 followers (schema ahead), and every round aborts on
their version refusal until the control plane is upgraded again. That
is the documented state, not an outage.

### D-4. Reserved ports reach the control plane in the heartbeat and are persisted (migration 73)

- **Wire.** `Heartbeat` (`lorica-cluster/src/messages.rs`, mirrored in
  `lorica-cluster/proto/cluster.proto`) gains
  `#[prost(message, optional, tag = "6")] reserved_ports: Option<ReservedPortsReport>`,
  a new message carrying `management`, `http`, `https` (`uint32`) and
  `cluster`, `enrollment`, `automation` (`optional uint32`). A field
  under a new tag is compatible by construction: a 1.10.6 peer ignores
  it, and a 1.11.0 control plane sees it absent from a 1.10.6 follower
  (which the schema gate keeps out of a 1.11.0 fleet anyway). The
  frozen corpus (`lorica-cluster/tests/wire_corpus.rs`) must pass
  unchanged, which proves it.
- **Source.** `FollowerHandler` (`lorica-cluster/src/dialer.rs`) gains
  `fn reserved_ports(&self) -> Option<ReservedPortsReport>`, defaulted
  to `None` exactly like `resources()`, implemented by `ReplicaHandler`
  (`lorica/src/startup/cluster_follower.rs`) from the process's
  `ReservedPorts` passed in `FollowerOptions`.
- **Control plane.** `serve_request` (`lorica-cluster/src/listener/operational.rs`)
  records it on the session entry beside `record_resources`
  (`lorica-cluster/src/roster.rs`), and the session-facts flush that
  builds `LiveNodeFacts` persists it through `touch_cluster_nodes`
  (`lorica-config/src/store/cluster_nodes.rs`) into a new nullable
  column `cluster_nodes.reserved_ports_json`. The flush is still in
  `lorica/src/startup/cluster_plane.rs` after the extraction
  (`4e864593` moved the ingest policy to `lorica-fleet/src/ingest.rs`
  and the runtimes to `lorica-fleet/src/runtime.rs`, not the flush).
  The update keeps the stored value when the session has no report
  (`COALESCE(?, reserved_ports_json)`).
- **Why persisted, unlike the resource gauges.** The heartbeat rule in
  `docs/cluster.md` ("What may ride the heartbeat") keeps gauges as
  session state because they are meaningless as history. Reserved ports
  are a node fact the control plane validates writes against, including
  for a node that is offline at that moment and after a control-plane
  restart; the precedent is `applied_config_generation`, persisted by the
  same flush "so drift survives a control-plane restart". The class table
  in `docs/cluster.md` gains a "Node fact" row.
- **Why the heartbeat and not the `Hello`**: AC #7 says heartbeat, and a
  value replaced every beat needs no separate refresh path.
- **An active node that has never reported** (enrolled but not connected
  since the control plane runs 1.11.0) makes a stream targeting it
  refused, naming the node and saying it has not reported its reserved
  ports. Fail closed: the alternative is a stream accepted for a node
  where it will fail to bind. Gives up: creating a stream for such a
  node until it connects once.

### D-5. One reserved-port and listen-address rule for the CLI, the control plane and the bind

`ReservedPorts` moves from `lorica/src/cli.rs` (where it is
`pub(crate)`) to `lorica-config/src/listen_ports.rs`, public, gaining
`enrollment: Option<u16>` (AC #7 names the enrollment port; the CLI type
has no field for it today). Beside it:

- `ReservedListener` (closed enum: management, http, https, cluster,
  enrollment, automation) with the phrase the CLI prints today ("the
  management API port", "a proxy listener port", "the cluster plane
  port", "the automation API port"; enrollment's new phrase "the cluster
  enrollment port");
- `ReservedPorts::clash(&self, port: u16) -> Option<ReservedListener>`,
  the body of today's `refuse_reserved`;
- `ReservedPorts::clash_in(&self, first: u16, last: u16) -> Option<(u16, ReservedListener)>`
  for a range, defined through `clash` so the two cannot disagree.

`refuse_reserved` in `cli.rs` keeps its signature and its messages
(the CLI tests pin them) and delegates to `clash`. The cluster family
clears both `cluster` and `enrollment` for itself, as it clears
`cluster` today. Side effect, stated in the CHANGELOG: an
`--automation-listen` on the cluster enrollment port is now refused at
startup instead of failing at bind.

**Against reserved ports, the rule is port-only and protocol-agnostic,
as `refuse_reserved` is today.** A stream, TCP or UDP, on any listen
address, whose range contains a reserved port is refused. Reason: AC #7
requires the same rule, the HTTP and HTTPS listeners bind every
address, and UDP 443 is where HTTP/3 (2.0.0) will listen. Gives up: a
UDP stream on a port a TCP listener of Lorica holds.

**Stream against stream: the dual-stack rule.** A stream has one listen
address, and how it binds decides what it conflicts with:

- `[::]` binds with `IPV6_V6ONLY` off (dual-stack) and conflicts with
  every IPv4 and every IPv6 address on the same port and protocol;
- any other IPv6 literal binds with `IPV6_V6ONLY` on and conflicts only
  with the same address and with `[::]`;
- `0.0.0.0` conflicts with every IPv4 address and with `[::]`, and with
  no other IPv6 address;
- any other IPv4 literal conflicts with the same address, `0.0.0.0` and
  `[::]`.

Two streams conflict when they have the same protocol, intersecting port
intervals and conflicting addresses. Two streams on `10.0.0.1:53/udp`
and `10.0.0.2:53/udp` coexist; `0.0.0.0:53/udp` and either do not;
`[2001:db8::1]:53/udp` and `0.0.0.0:53/udp` coexist; `[::]:53/udp`
conflicts with all of them. This is one function,
`listen_addresses_conflict(a: IpAddr, b: IpAddr) -> bool`, called by
`stream_port_conflicts` in the same module, and it is the contract
Story 12.2 binds by: `[::]` with `IPV6_V6ONLY` off, every other IPv6
literal with it on. Whether a later story needs an IPv6-only wildcard is
that story's decision, as a new field.

**Which nodes a candidate stream is checked on** (pure function input
`&[NodePorts]`, assembled by the API): every active `cluster_nodes` row
the stream's selector resolves to through `SelectorResolution` (the
replication resolver, so "checked on" and "delivered to" cannot
disagree), with that row's persisted reserved ports; plus "this node"
with the process's own `ReservedPorts` (`AppState.reserved_ports`,
new) whenever this node would bind the candidate, judged by
`binds_here` (D-8) with `enabled` taken as true, since a disabled stream
keeps its ports (D-1). On a control plane "this node" therefore means
its reserved ports checked against streams with an empty selector, and
the other streams it binds are those with an empty selector; on a
standalone node, every stream; on a follower in break-glass, the
streams its selector names or leaves empty. A stream checked on a node
is checked against the other streams that node binds by the same
predicate, disabled ones included (D-1). Each conflict names the
node (its `cluster_nodes.name`, or "this node") and the object (the
reserved listener, or the other stream's name with its ports, protocol
and address). The API answers `409 Conflict` with the first conflict.

### D-6. UDP-only backends, one rule, one enforcement point per write path

The rule is a pure function,
`check_backend_attachments(&AttachmentSnapshot) -> Result<(), AttachmentConflict>`
in `lorica-config/src/models/stream.rs`, over the streams, the
`stream_backends` and `route_backends` links and the backends. It
refuses, naming the stream:

1. a backend linked to a UDP stream and also to a route or a TCP stream;
2. a backend linked to a UDP stream with `health_check_enabled = true`.
   Attaching such a backend is **refused**, never silently switched
   off: a write to a stream must not change a backend another surface
   may share. The rule reads the enabled flag because no UDP kind exists
   until 12.14 (the kind is inert while checks are off); 12.14 tightens
   it to "enabled implies a UDP kind";
3. a backend whose `managed_by` is `Some` linked to any stream: an
   environment's backend set belongs to its pipeline (Story 10.4), and a
   stream following a pipeline's edits would be a listener the pipeline
   steers, which D9 forbids;
4. the port shape of AC #2: a range stream accepts only backends without
   a port; a single-port stream only backends with one; a portless
   backend attaches to range streams only, never to a route or a
   single-port stream, and has active checks disabled (there is no port
   to probe).

Portless backends: `validate_backend_address`
(`lorica-config/src/store/backends.rs`) accepts `host:port` as today,
and additionally a hostname, an IPv4 literal or a bracketed IPv6 literal
(`[2001:db8::1]`) without a port. An unbracketed IPv6 literal keeps
today's reading (`2001:db8::1` is host `2001:db8:` port 1), pinned by a
test, so no stored backend changes meaning.

Enforcement points, each calling the same function:

- **Management writes**, inside the store transaction that writes:
  `ConfigStore::link_route_backend`, the new
  `ConfigStore::set_stream_backends`, `create_backend` and
  `update_backend` (`lorica-config/src/store/backends.rs`), and the new
  stream create and update. A violation is `ConfigError::Validation`,
  which the API already maps to `400`.
- **Replica apply**: once, on the whole decoded blob, in
  `ConfigStore::prepare_replica` (`store/replica.rs`), as a semantic
  refusal; the apply then writes rows through unchecked internal
  helpers, because a consistent snapshot applied row by row can pass
  through a transient violation (a backend moving from a UDP stream to a
  route). Precedent: hostname uniqueness (`insert_route_row`, "the blob
  is one consistent snapshot").
- **Import**: once, on the whole file, in `validate_structure`
  (`lorica-config/src/import.rs`), before `clear_all` runs.

### D-7. The end-reason enum lives in `lorica-config`

`lorica-config` is the one crate every consumer already reaches: the
data plane (`lorica`, and any stream crate 12.2 or 12.3 creates, which
must depend on `lorica-config` for the `Stream` model anyway), the API
and the log store (12.9), the fleet. It is also where `LoadBalancing`
and `HealthStatus` live. In `lorica-config/src/models/stream.rs`:

- `StreamEndReason`, the end of a connection or session, the closed set
  of AC #8 (`node_shutdown` included: a plain stop, Story 12.2 AC #7),
  with `Refused(StreamRefusal)` the one variant carrying data;
- `StreamEndKind`, its fieldless twin, one variant per word of AC #8,
  deriving `strum::VariantArray` and `strum::IntoStaticStr` with
  `serialize_all = "snake_case"`, and `StreamEndReason::kind()`, an
  exhaustive match. The word list every surface publishes (log rows,
  the metric label set, the OpenAPI enum, the dashboard) is derived from
  `StreamEndKind::VARIANTS`, never typed out
  (`.claude/rules/derived-not-transcribed.md`);
- `StreamRefusal`, the closed set of refusal reasons, seeded with
  `NoMatch` only, which D7 of the PRD fixes for the whole epic. Each
  story that refuses adds its own variants (12.3, 12.5, 12.6, 12.15).
- Serde form: `#[serde(tag = "reason", content = "refusal", rename_all = "snake_case")]`,
  so `{"reason":"idle_timeout"}` and
  `{"reason":"refused","refusal":"no_match"}`.

Transfer (12.16) is not a variant.

### D-8. Where a stream binds: one pure function, `binds_here`

AC #6 as amended: a follower binds what it was targeted by, the control
plane binds only streams with an empty selector, a standalone node binds
every enabled stream. This deliberately differs from routes. Verified in
code: a node serves every route its store holds (the proxy configuration
is built from `store.list_routes()` with no selector filter,
`build_proxy_config_inner`, `lorica/src/reload.rs`), so the control
plane, which has no cluster identity (`set_cluster_identity` is only
called on join, `lorica/src/cli_cluster.rs`), serves every route
whatever its selector. That is harmless for a route, which only answers
names; a stream opens a port, so holding a stream to replicate it must
not open it on the control plane.

The rule lives in one place, in `lorica-config/src/models/stream.rs`:

```rust
pub enum NodeRole<'a> {
    Standalone,
    ControlPlane,
    Follower { node_name: &'a str },
}

pub fn binds_here(stream: &Stream, role: NodeRole<'_>) -> bool
```

`false` whenever `!stream.enabled`; otherwise `Standalone` gives `true`,
`ControlPlane` gives `stream.node_selector.is_empty()`, and
`Follower { node_name }` gives `stream.applies_to_node(node_name)`. The
follower's identity is carried by the role, so a follower without a
name cannot be expressed. Story 12.2's bind path, the port-conflict
check of D-5 and the IV1 test all call it; nothing else decides where a
stream binds. A follower's store already holds only its cut, so on a
follower the predicate is the same assertion the replica apply keeps
(`applies_to_node`), not the filter itself.

The caller maps its runtime to the role: `ClusterRuntime::ControlPlane`
to `ControlPlane`, `ClusterRuntime::Follower` to `Follower` with the
node name the follower runtime carries (`FollowerRuntime.node_name`,
`lorica-fleet/src/runtime.rs`), anything else to `Standalone`. A
follower in break-glass is still a follower: a stream it creates
locally binds only if its own selector names it or is empty.

What it gives up: a stream on the control plane itself needs an empty
selector, which then also opens it on every follower. Naming the
control plane in a selector would need it to have a roster name, which
it does not; that is a later decision if anyone needs it.

### D-9. Streams in TOML export and import

`ExportData` and `ImportData` gain `streams` and `stream_backends`
(`[[streams]]`, `[[stream_backends]]`), `#[serde(default)]` on import so
every existing export still imports. `EXPORT_FORMAT_VERSION` stays 1:
the import already tolerates missing collections, and an older binary
importing a 1.11.0 export fails loudly on `Backend`'s unknown
`health_check` field (`deny_unknown_fields`), which is the right
outcome. Streams carry no secret, so nothing is redacted. `clear_all`
deletes `stream_backends` and `streams` first. `import_to_store` writes
streams after backends and links, through the unchecked writers, after
`validate_structure` has checked references (each link names an
imported stream and backend), every stream's own validation, and the
attachment rule (D-6). `compute_diff` (`lorica-config/src/diff.rs`)
gains a `streams` entity diff. The import handler
(`import_config`, `lorica-api/src/config.rs`) runs the port-conflict
check of D-5 on every imported stream against this node's reserved
ports and the other imported streams, and refuses the import naming the
first conflict.

### D-10. Management API shape

- Paths `/api/v1/streams` (GET list, POST create) and
  `/api/v1/streams/{id}` (GET, PUT, DELETE), in `lorica-api/src/streams.rs`,
  with the `_as(state, actor, ...)` split routes and backends use
  (`create_route_as`, `create_backend_as`), so Story 12.10 can add the
  read surfaces without touching the handlers.
- **Role floors as routes**: reads at Viewer (the GET default of
  `required_role`), writes at Operator (its fall-through), per AC #9
  ("the same validation, audit ... as routes"). `required_role` gains no
  rule; a table test pins both floors so a later rule cannot move them
  unnoticed.
- Follower read-only needs no change: `follower_local_request` does not
  list the paths, so a follower answers 409 outside break-glass.
- The response is a view struct (`StreamResponse`, with its linked
  `backend_ids`), built field by field like `route_to_response`, never a
  `Serialize` of the model, so a later secret-bearing field (12.4) is
  withheld unless added on purpose. A test pins the view's key set
  against the model's field set minus `STREAM_WITHHELD_FIELDS` (empty in
  this story).
- Audit rows `stream.create`, `stream.update`, `stream.delete`, target
  `("stream", id)`, before and after as the response view.
- `notify_config_changed` after every mutation, so the round runs.
- Status codes: validation `400`, port conflict `409`, unknown id `404`.

### D-11. Health-check and TLS fields are HTTP-only in name where they are HTTP-only in fact

D2 of the PRD names `health_check_path`, `h2_upstream`, `tls_upstream`,
`tls_sni` and `tls_skip_verify` as HTTP-only. This story documents them
so in the model doc comments, both OpenAPI documents and the dashboard
form labels ("HTTP routes only; streams ignore it"). It does not refuse
them on a backend a stream uses: a backend shared by a route and a TCP
stream legitimately carries them for the route.

## Tasks

Six lots. **Lot 1 runs alone and first, and is committed before any
other lot starts**: it carries every shape change (new types, new struct
fields, moved types) together with every construction site that change
breaks, so the tree compiles at its end and later lots only change
behaviour inside their own files. **Lots 2, 3 and 4 then run in
parallel**; their allowlists are pairwise disjoint. **Lot 5 runs after
Lots 2 and 4** (it shares `lorica-api/openapi.yaml` with Lot 4 and uses
Lot 2's import). **Lot 6 runs last.** Agents must not run
`git checkout`, `git restore`, `git stash` or `git reset` in the shared
tree; a lot that needs to undo its own edit does it with an edit.

No lot touches `lorica-fleet/src/ingest.rs`,
`lorica-fleet/src/telemetry_store.rs` or `lorica-api/src/cluster/boundary.rs`.
`lorica-fleet/src/runtime.rs` is touched by Lot 1 for one
`ClusterNode` literal only. `crate::cluster::ClusterRuntime`, which
`selector_roster` matches on, is the re-export of
`lorica_fleet::ClusterRuntime` (`lorica-api/src/cluster/mod.rs`) and
needs no change.

Cargo: Lots 1 to 5 run cargo. While lots run in parallel, each runs
`cargo test -p <its crates>` and `cargo clippy -p <its crates> --all-targets`
only; the orchestrator runs the full gate chain of `.claude/rules/lorica-rust.md`
(fmt, workspace clippy with `--features lorica/otel` and
`CARGO_BUILD_WARNINGS=deny`, `cargo test --workspace`, `cargo audit`)
once each wave is merged. Lot 4 also runs the frontend gates of
`.claude/rules/lorica-frontend.md`. Lot 6 runs nothing.

### Lot 1: schema, models, store, shared rules, shape changes (sequential, first; cargo)

Allowlist (new files marked +):
`lorica-config/src/models/stream.rs`+, `lorica-config/src/models/health_check.rs`+,
`lorica-config/src/listen_ports.rs`+, `lorica-config/src/store/streams.rs`+,
`lorica-config/src/models/{mod,backend,cluster}.rs`, `lorica-config/src/lib.rs`,
`lorica-config/src/store/{mod,backends,row_helpers,cluster_nodes}.rs`,
`lorica-config/src/tests.rs`, `lorica-config/tests/config_db_upgrade.rs`,
`lorica/src/cli.rs`, `lorica/src/startup/{single,supervisor,automation,cluster_follower}.rs`,
`lorica-api/src/server.rs` (the `AppState` field only),
and, for construction sites only (no behaviour change): every file
holding a `Backend {` literal, a `ClusterNode {` literal, a
`LiveNodeFacts {` literal, an `AppState {` literal or a
`ReservedPorts {` literal. Print them with
`grep -rln --include=*.rs -e "health_check_path: " -e "ClusterNode {" -e "LiveNodeFacts {" -e "AppState {" -e "ReservedPorts {" . | grep -v "^./target"`.
On `4e864593` that is, besides the files above:
`lorica/src/proxy_wiring/tests.rs`, `lorica/src/startup/cluster_plane.rs`,
the `lorica/tests/*_e2e_test.rs` suites and `lorica/tests/proxy_{config,routing}_test.rs`,
`lorica-fleet/src/runtime.rs`,
`lorica-api/src/{backends,target,tests}.rs`, `lorica-api/src/routes/crud.rs`,
`lorica-api/src/cluster/tests.rs`, `lorica-api/src/acme/tests.rs`,
`lorica-api/src/automation/{audit,environments,protections,redact,write}.rs`,
`lorica-api/src/automation/environments/tests.rs`,
`lorica-api/src/automation/write/plane_tests.rs`,
`lorica-api/src/automation_tokens/tests.rs`, `lorica-api/src/oidc_issuers/tests.rs`,
`lorica-config/src/canonical.rs` and `lorica-config/src/store/replica.rs`
(test fixtures only). The grep is the authority, this list is not.

- [x] `models/health_check.rs`: `HealthCheck`, `legacy_path()`,
      `reconcile()`, `Backend::set_health_check()`; `Backend` gains
      `health_check` (D-2); doc comments mark the D-11 fields HTTP-only.
- [x] `models/stream.rs`: `Stream` (with `enabled`, without
      `managed_by`), `StreamProtocol` (`tcp`, `udp`, strum derives like
      `enums.rs`), `StreamBackend`, `STREAM_PORT_RANGE_MAX`,
      `Stream::validate()` (name, group, address, ports, range cap,
      selector), `Stream::applies_to_node()` (the route predicate, for
      the replication path), `NodeRole` and `binds_here` (D-8),
      `check_backend_attachments` with
      `AttachmentSnapshot` and `AttachmentConflict` (D-6),
      `StreamEndReason`, `StreamEndKind`, `StreamRefusal` (D-7).
      `deny_unknown_fields` on `Stream` and `StreamBackend`.
- [x] `listen_ports.rs`: `ReservedPorts` (moved, plus `enrollment`),
      `ReservedListener`, `clash`, `clash_in`,
      `listen_addresses_conflict` (the dual-stack rule of D-5),
      `NodePorts`, `PortConflict`, `stream_port_conflicts`. Serde on
      `ReservedPorts` for the `cluster_nodes` column.
- [x] Migrations 71 (`migrate_streams`), 72
      (`migrate_backend_health_check`), 73
      (`migrate_cluster_node_reserved_ports`), each with a doc comment in
      the house style, ending with the downgrade statement of D-2.
- [x] `store/streams.rs`: `STREAM_COLUMNS`, `row_to_stream`,
      `create_stream`, `get_stream`, `list_streams`, `update_stream`,
      `delete_stream`, `set_stream_backends` (replace the set in one
      transaction, attachment rule checked), `list_stream_backends`,
      `list_backends_for_stream`, `list_streams_for_backend`, plus the
      unchecked internal writers Lot 2 uses. `clear_all` deletes
      `stream_backends` and `streams`.
- [x] `store/backends.rs` and `row_helpers.rs`: `health_check_json`
      appended to `BACKEND_COLUMNS` and to both writes; reconcile on
      read and on write; attachment rule on `link_route_backend`,
      `create_backend`, `update_backend`; `validate_backend_address`
      accepts the portless forms of D-6.
- [x] `ClusterNode.reserved_ports: Option<ReservedPorts>` and
      `LiveNodeFacts.reserved_ports`, read and written by
      `cluster_nodes.rs`, `COALESCE` on the flush update (D-4).
- [x] `lorica/src/cli.rs`: `ReservedPorts` imported from
      `lorica_config::listen_ports`, `refuse_reserved` delegating to
      `clash`, the cluster family clearing `enrollment`, existing tests
      green with unchanged messages, one new test for the automation
      listen on the enrollment port.
- [x] `lorica/src/startup/{single,supervisor,automation}.rs`: every
      `ReservedPorts` literal gains `enrollment`; the process's complete
      `ReservedPorts` is built once and passed to `AppState.reserved_ports`
      (new field, `lorica-api/src/server.rs`) and to
      `FollowerOptions.reserved_ports` (new field,
      `cluster_follower.rs`; not read until Lot 3).
- [x] Construction-site fixes listed above (`health_check:
      HealthCheck::TcpConnect` beside `health_check_path: None`,
      `reserved_ports: None`, the `AppState` field, `enrollment`).
- [x] Tests listed under Dev Notes, Lot 1.

### Lot 2: replication, cut, export, import, diff (after Lot 1; parallel with 3 and 4; cargo)

Allowlist: `lorica-config/src/canonical.rs`, `lorica-config/src/store/replica.rs`,
`lorica-config/src/export.rs`, `lorica-config/src/import.rs`,
`lorica-config/src/diff.rs`, `lorica-api/src/automation/test_support.rs`
(its `CanonicalConfig` literal).

- [x] `CanonicalConfig` gains `streams` and `stream_backends`, filled in
      `canonical_config`, sorted with `sort_by_canonical_repr`;
      `CANONICAL_FORMAT_VERSION = 3` with its doc comment rewritten
      (D-3); `CANONICAL_SHAPE_DIGEST` updated; the version-two tests
      renamed and rewritten for three.
- [x] `restrict_for_recipient`: streams cut by
      `resolution.targets(&stream.node_selector, node_id)` whatever
      their `enabled` value, their links kept with them, `backends` =
      the union of the backends the kept route links and the kept stream
      links reference. The struct literal at its end names the two new
      fields explicitly, as its comment requires.
- [x] `prepare_replica`: every stream's `validate()` and selector, and
      `check_backend_attachments` on the whole blob, as refusals naming
      the stream id.
- [x] `apply_replica_tables`: streams scoped by `applies_to_node`
      (the assertion the route pass keeps), applied after backends by
      delete-then-insert of every kept stream (the `UNIQUE(name)` index
      would refuse a row-by-row upsert of a blob that swaps two names),
      links rewritten for kept streams through the unchecked writers
      (and `apply_replica_route_backends` switched to the unchecked
      route-link writer, since Lot 1 makes `link_route_backend`
      checked); `ReplicaOutcome` gains `streams`,
      `streams_skipped_by_selector`, `stream_backends`; the module doc's
      table list gains both tables.
- [x] Export, import and diff per D-9.
- [x] Tests listed under Dev Notes, Lot 2.

### Lot 3: reserved ports on the wire, persisted, and the selector warning (after Lot 1; parallel with 2 and 4; cargo)

Allowlist: `lorica-cluster/proto/cluster.proto`,
`lorica-cluster/src/{messages,bridge,roster,dialer}.rs`,
`lorica-cluster/src/listener/operational.rs`,
`lorica-cluster/tests/{cluster_plane,enrollment,wire_corpus}.rs`
(their `Heartbeat` literals only), `lorica/src/startup/cluster_follower.rs`,
`lorica/src/startup/cluster_plane.rs`.

- [x] `ReservedPortsReport` message and `Heartbeat.reserved_ports`
      (tag 6) in the proto and in `messages.rs`; the field-number test in
      `messages.rs` extended; the frozen corpus unchanged and green.
- [x] `InPlaneAction::Heartbeat` carries it (`bridge.rs`);
      `FollowerHandler::reserved_ports` defaulted (`dialer.rs`) and sent
      in every heartbeat (`node_resources` sibling); `record_reserved_ports`
      on the session entry (`roster.rs`), called in `serve_request`.
- [x] A report with a zero port or a port above 65535 is dropped as
      not reported, with a WARN naming the node (never the values of
      other fields).
- [x] `ReplicaHandler::reserved_ports` from `FollowerOptions.reserved_ports`.
- [x] The flush in `cluster_plane.rs` builds `LiveNodeFacts.reserved_ports`
      from the session.
- [x] The unresolvable-selector WARN of the round
      (`resolution.unresolvable(&route.node_selector)` in
      `cluster_plane.rs`) also runs over streams.
- [x] Tests listed under Dev Notes, Lot 3.

### Lot 4: the typed health check on every surface (after Lot 1; parallel with 2 and 3; cargo and frontend)

Allowlist: `lorica/src/health.rs`, `lorica-api/src/backends.rs`,
`lorica-api/src/automation/redact.rs`, `lorica-api/src/automation/write.rs`
(only if `restore_health_check_path`'s call site changes),
`lorica-api/src/automation/write/plane_tests.rs`,
`lorica-api/src/automation/read/plane_tests.rs`,
`lorica-api/openapi.yaml` (backend schemas only),
`lorica-api/openapi-automation.yaml`, `lorica-api/tests/openapi_contract.rs`,
`lorica-mcp/src/tools.rs`,
`lorica-dashboard/frontend/src/lib/api.ts`,
`lorica-dashboard/frontend/src/routes/Backends.svelte`,
`lorica-dashboard/frontend/src/routes/Backends.test.ts`.

- [x] `health.rs`: probe chosen from `backend.health_check`, through a
      pure `fn probe_for(&Backend) -> ProbeTarget` the test can call;
      HTTP behaviour byte-identical for every backend whose path is set.
- [x] `backends.rs`: `CreateBackendRequest` and `UpdateBackendRequest`
      gain `health_check: Option<HealthCheck>`; `health_check_path`
      still accepted and documented deprecated; both given and
      disagreeing is `400` naming both fields; the response carries both.
      Enabling checks on a UDP-attached or portless backend is refused by
      the store (Lot 1) with the stream named; the handler test proves it.
- [x] `redact.rs`: the query values of `health_check.path` masked
      exactly as `health_check_path`'s are, and
      `restore_health_check_path` restores both fields from one stored
      path, so a typed path sent back as read keeps the stored one.
- [x] `lorica-mcp/src/tools.rs`: `BACKEND_FIELDS` gains `health_check`;
      the backend tools' summaries mention the typed shape and the
      deprecated path.
- [x] Both OpenAPI documents: `HealthCheck` schema (`oneOf` by `kind`),
      `health_check` on `Backend`, `CreateBackendRequest`,
      `UpdateBackendRequest`, `health_check_path` marked
      `deprecated: true`; the D-11 fields described HTTP-only; the
      portless address form described on `address`.
- [x] Dashboard: `api.ts` types (`HealthCheck` union, the deprecated
      field kept); the backend form picks the kind (HTTP path or TCP
      connect) and sends `health_check`; Vitest covers both kinds and
      the edit of a backend read with only a legacy path.
- [x] Tests listed under Dev Notes, Lot 4.

### Lot 5: stream management API and conflict checks (after Lots 2 and 4; cargo)

Allowlist: `lorica-api/src/streams.rs`+, `lorica-api/src/streams/tests.rs`+,
`lorica-api/src/lib.rs`, `lorica-api/src/server.rs` (routes),
`lorica-api/src/middleware/authorize.rs` (the table test only, no rule),
`lorica-api/src/routes/crud.rs` (visibility of `validate_node_selector`
and `selector_roster` to `pub(crate)`, nothing else),
`lorica-api/src/config.rs`, `lorica-api/openapi.yaml` (stream paths and
schemas).

- [x] Handlers per D-10 with `create_stream_as`, `update_stream_as`,
      `delete_stream_as`; validation through `Stream::validate()`, the
      roster check of `validate_node_selector`, `validate_group_name`,
      backend existence, and the store's attachment rule.
- [x] The port-conflict check (D-5): map `state.cluster` to a
      `NodeRole` (D-8); assemble `NodePorts` from `list_cluster_nodes()`
      (active rows) on a control plane, plus this node when
      `binds_here` holds for the candidate; call `stream_port_conflicts`
      with every other stored stream, disabled ones included; `409` with
      the node and the object named. Run inside the store closure that
      writes, so two concurrent creates cannot both pass.
- [x] `server.rs` routes with the `routes_cud` body and rate-limit
      layers; the `required_role` table test pinning Viewer reads and
      Operator writes.
- [x] `import_config`: the D-9 port check before `import_to_store`.
- [x] `openapi.yaml`: the five operations, `Stream`, `StreamResponse`,
      `CreateStreamRequest`, `UpdateStreamRequest`, the error codes;
      `openapi_spec_matches_routes` green.
- [x] Tests listed under Dev Notes, Lot 5.

### Lot 6: documentation (last; no cargo)

Allowlist: `docs/cluster.md`, `CHANGELOG.md`, `docs/hot-upgrade.md`,
`docs/architecture/source-tree.md`.

- [x] `docs/cluster.md` "Running a Mixed-Version Fleet": the 1.10.6 to
      1.11.0 step of D-3 (followers first, control plane at once, the
      configuration freeze and why, the control-plane rollback state);
      "Targeting a subset": streams and their links are cut per
      recipient, and where each role binds (D-8: the control plane only
      streams with an empty selector, unlike routes, and why);
      "What may ride the heartbeat":
      the "Node fact" class (reserved ports, persisted).
- [x] `docs/hot-upgrade.md`: a rollback from 1.11.0 to 1.10.6 opens the
      database and serves HTTP as before; streams are not served by
      1.10.6.
- [x] `CHANGELOG.md` `[Unreleased]`: Added (stream model and API,
      reserved ports in the heartbeat, portless backends for range
      streams), Changed (typed health check, `health_check_path`
      deprecated, the enrollment-port refusal at startup), and the
      migration line "Schema migrations 71 to 73: upgrade followers
      first and the control plane immediately after; configuration
      changes do not replicate in between."
- [x] `docs/architecture/source-tree.md`: the new files.

## Dev Notes

### Functions and files to extend (verified on `feat/v1.11.0` at `4e864593`)

- `lorica-config/src/store/mod.rs`: `MIGRATIONS` (last entry
  `(70, migrate_address_spellings)`), `add_column_if_absent`,
  `column_exists`, `apply_migration` (one IMMEDIATE transaction per
  migration), `clear_all`, `SCHEMA_HEAD`, and the `migration_tests`
  module (`migrations_are_idempotent_on_second_run`,
  `migration_versions_are_contiguous_and_ascending`).
- `lorica-config/src/store/backends.rs`: `BACKEND_COLUMNS`,
  `validate_backend_address`, `create_backend`, `update_backend`,
  `link_route_backend`, `list_route_backends`.
- `lorica-config/src/store/row_helpers.rs`: `row_to_backend` (positional,
  reads index 17 last today; `health_check_json` becomes 18).
- `lorica-config/src/store/cluster_nodes.rs`: `touch_cluster_nodes`,
  `LiveNodeFacts`.
- `lorica-config/src/canonical.rs`: `CANONICAL_FORMAT_VERSION`,
  `CanonicalConfig`, `canonical_config`, `restrict_for_recipient`,
  `SelectorResolution`, `decode_canonical` (the `VersionPeek`),
  the tests `the_canonical_format_version_is_two`,
  `story_10_4_rides_format_version_two_without_a_second_bump`,
  `CANONICAL_SHAPE_DIGEST` and its guard.
- `lorica-config/src/store/replica.rs`: `prepare_replica`,
  `apply_replica_tables`, `apply_replica_backends`,
  `apply_replica_route_backends`, `ReplicaOutcome`.
- `lorica-config/src/export.rs` (`ExportData`, `export_to_toml`),
  `import.rs` (`ImportData`, `validate_structure`, `import_to_store`),
  `diff.rs` (`ConfigDiff`, `compute_diff`, `diff_by_id`).
- `lorica-config/src/models/route.rs`: `validate_node_selector_names`,
  `NODE_SELECTOR_MAX_ENTRIES`, `Route::applies_to_node`.
- `lorica/src/reload.rs`: `build_proxy_config_inner` (reads
  `store.list_routes()` unfiltered; the D-8 evidence, read only).
- `lorica/src/cli.rs`: `ReservedPorts`, `refuse_reserved`,
  `validate_listen_bind`, `validate_automation_listen`,
  `validate_cluster_listen`, the tests around `RESERVED`.
- `lorica/src/startup/single.rs` and `supervisor.rs`: the
  `crate::cli::ReservedPorts { ... }` literals and the `AppState { ... }`
  construction; `lorica/src/startup/automation.rs` (`RESERVED` test
  constant).
- `lorica/src/startup/cluster_follower.rs`: `FollowerOptions`,
  `impl FollowerHandler for ReplicaHandler` (`resources`).
- `lorica/src/startup/cluster_plane.rs`: the `LiveNodeFacts` flush
  (`FLUSH_INTERVAL`), the per-round `resolution.unresolvable` WARN.
- `lorica-cluster/src/messages.rs` (`Heartbeat`, `NodeResources`, the
  `proto_tags` field-number tests), `proto/cluster.proto`,
  `bridge.rs` (`InPlaneAction::Heartbeat`), `dialer.rs`
  (`FollowerHandler`, `node_resources`), `roster.rs`
  (`record_resources`), `listener/operational.rs` (`serve_request`),
  `handshake.rs` (`evaluate_hello`, the schema gate, read only).
- `lorica/src/health.rs`: `health_check_loop`, Phase A probe selection,
  `tcp_probe`, `http_probe`.
- `lorica-api/src/backends.rs`: `CreateBackendRequest`,
  `UpdateBackendRequest`, `BackendResponse`, `backend_to_response`,
  `create_backend_as`, `update_backend_as`.
- `lorica-api/src/routes/crud.rs`: `validate_node_selector`,
  `selector_roster`, `validate_group_name`, `route_to_response`,
  `routes_with_links`, `create_route_as` (the model for the `_as`
  split).
- `lorica-api/src/middleware/authorize.rs`: `required_role`,
  `follower_local_request`, `follower_read_only`.
- `lorica-api/src/automation/redact.rs`: `restore_health_check_path`,
  the `mask_string(row, "health_check_path", query_values)` call.
- `lorica-api/src/config.rs`: `import_config`, `import_preview`.
- `lorica-mcp/src/tools.rs`: `BACKEND_FIELDS`, the backend `Mutation`
  entries.
- `lorica-api/tests/openapi_contract.rs`: `openapi_spec_matches_routes`,
  `every_automation_write_accepts_exactly_the_field_names_this_surface_committed_to`.

### Pitfalls

- **Additivity is the whole of AC #3.** Never a `NOT NULL` column
  without default, a `UNIQUE` index or a trigger on a table 1.10.6
  writes (`backends`, `cluster_nodes`). The `UNIQUE` index of D-1 is on
  the new `streams` table, which 1.10.6 never writes.
- **Reconcile on read, write both on write.** A reader that looks at
  `health_check_path` directly after this story is a bug: the
  rollback matrix of D-2 is only true if every reader goes through
  `Backend.health_check`. Grep `health_check_path` after Lot 4: what
  remains is the model, the store, the API's deprecated input and the
  OpenAPI documents.
- **The redaction.** `redact.rs` masks query values of
  `health_check_path` because a token in a probe URL is a credential.
  The typed `health_check.path` carries the same string; forgetting it
  reopens the leak Story 11.4 closed.
- **Replica apply must not use the checked writers** (D-6), and must
  delete-then-insert streams (D-1 `UNIQUE(name)`).
- **The cut must include stream-referenced backends.** Today
  `restrict_for_recipient` derives `backends` from route links only; a
  follower serving only a stream would receive the stream and none of
  its backends, and `apply_replica_backends` would delete them.
- **A disabled stream is cut, applied and conflict-checked like an
  enabled one.** Only the bind reads `enabled`, through `binds_here`.
- **Where a stream binds is not where its route would be served.** Do
  not reuse the route reload's "everything in the store" shape for
  streams: on the control plane that opens every follower's port. Every
  bind decision goes through `binds_here`.
- **The dual-stack rule is a bind contract, not only a validation
  rule.** If 12.2 binds `[::]` with `IPV6_V6ONLY` on, or a specific IPv6
  literal with it off, the conflict check accepts streams the kernel
  then refuses at bind. The test vectors of `listen_addresses_conflict`
  are what 12.2 reads.
- **`Stream` and `StreamBackend` are `deny_unknown_fields`**, and every
  later stream field takes `#[serde(default)]` only when an older 1.11.0
  development blob must still decode; at release, version 3 is one shape.
- **IPv6 portless addresses must be bracketed** (D-6).
- **The `COALESCE` on the flush.** Without it, a session without a
  report (the transport-only tests, a session that has not beaten yet)
  erases the persisted ports.
- **`AppState`, `ClusterNode` and `Backend` literals are many.** Lot 1
  fixes them all, or Lots 2 to 5 inherit a red tree.
- **`CARGO_BUILD_WARNINGS=deny`** must be exported in every local Docker
  gate run (it is what CI's `setup-rust-toolchain` v2 exports).
- **No real infrastructure names** in fixtures, tests or docs:
  `192.0.2.0/24`, `198.51.100.0/24`, `2001:db8::/32`, `edge-1`,
  `example.com`.

### Tests each lot must add

**Lot 1**

- `migration_tests`: each of 71, 72, 73 applied twice on one connection
  is a no-op the second time (AC #10), and
  `migrations_are_idempotent_on_second_run` stays green.
- **The 1.10.6 downgrade test** (AC #3),
  `migration_tests::migrations_after_1_10_6_are_additive`, with
  `const LAST_1_10_6_MIGRATION: i64 = 70` and a comment citing the tag:
  apply `MIGRATIONS` up to 70 on a fresh connection, snapshot
  `sqlite_master` and `pragma_table_info` / `pragma_index_list` for
  every table, apply the rest, and assert that every 1.10.6 table and
  column survives with the same type, `notnull`, default and primary
  key; that every column added to a 1.10.6 table is nullable or
  defaulted; and that no `UNIQUE` index or trigger was added to a
  1.10.6 table. The test derives "1.10.6's tables" from the snapshot, it
  lists nothing. Before writing it, check
  `git diff v1.10.6 -- lorica-config/src/store/mod.rs lorica-config/src/migrations/`
  shows no change to migrations 1 to 70; if it does, the fixture route
  (a `lorica_db_v1_10_6.sql` dump, as `config_db_upgrade.rs` does for
  v1.0.0 and v1.5.13) replaces the "apply up to 70" step.
- `config_db_upgrade.rs`: a test that runs, against a store at head,
  the `INSERT INTO backends`, `UPDATE backends` and `SELECT
  BACKEND_COLUMNS` statements as the `v1.10.6` tag wrote them (copied
  from `git show v1.10.6:lorica-config/src/store/backends.rs` into the
  test as a frozen released artefact, with that provenance in a
  comment), then reads the rows back through the current store and
  checks the D-2 matrix for the rows that statement wrote.
- `HealthCheck::reconcile` over the D-2 matrix, as vectors.
- `Stream::validate`: port 0, first above last, a range of
  `STREAM_PORT_RANGE_MAX` accepted and one more refused, IPv4-mapped
  refused, RFC 5952 canonicalisation, name alphabet and length,
  selector rule shared with routes, `enabled` defaulting to true on
  deserialisation.
- `clash` and `clash_in` over every `ReservedListener` (iterating a
  `ReservedPorts` built so each field holds a distinct port, never a
  typed-out list).
- `listen_addresses_conflict` and `stream_port_conflicts` over the
  dual-stack vectors of D-5: `[::]` against an IPv4 literal, `0.0.0.0`,
  an IPv6 literal and `[::]`; `0.0.0.0` against an IPv4 literal, an
  IPv6 literal and `[::]`; two distinct IPv4 literals; two distinct IPv6
  literals; an IPv6 literal against an IPv4 literal; the same addresses
  on different protocols; intersecting and adjacent port intervals; a
  disabled stream still conflicting. The vector table is a `const` the
  test iterates, and the symmetric case of each vector is asserted from
  the same row.
- `check_backend_attachments`: each refusal of D-6 names the stream
  (UDP shared with a route, UDP shared with a TCP stream, UDP with
  checks on, managed backend, portless on a route, portless on a
  single-port stream, ported backend on a range stream, portless with
  checks on); a backend on two UDP streams is accepted; a backend on a
  route and a TCP stream is accepted.
- `binds_here`: a table test over every `NodeRole` against a stream with
  an empty selector, a selector naming the follower, a selector naming
  another node, each enabled and disabled; the table is a `const` the
  test iterates, and its rows are the whole contract 12.2 reads.
- `validate_backend_address`: the portless forms accepted, an
  unbracketed IPv6 literal still read as host:port.
- `StreamEndReason`: serde round trip of every `StreamEndKind::VARIANTS`
  entry, `kind()` agreeing with the serialised `reason` word.
- Store: stream CRUD with `enabled`, `UNIQUE(name)`,
  `set_stream_backends` replacing the set, cascade on stream and on
  backend deletion, `clear_all`, `cluster_nodes.reserved_ports_json`
  round trip and `COALESCE`.
- `cli.rs`: existing tests unchanged; the automation-on-enrollment test.

**Lot 2**

- `the_canonical_format_version_is_three`; the version-3 ride test; the
  shape digest; a v2 blob refused by version with the version named
  (the existing `CANONICAL_FORMAT_VERSION + 1` test pattern).
- **IV1, automated, in the e2e `cluster` profile's shape**: a source
  store (the control plane) with two enrolled followers `edge-1` and
  `edge-2`, an enabled stream whose selector is `["edge-1"]` and one
  whose selector is empty. `restrict_for_recipient` for `edge-1` holds
  the targeted stream, its links and its backends; for `edge-2` it holds
  only the fleet-wide stream. After applying each cut to a follower
  store, `binds_here` over each node's own stored streams gives: the
  targeted stream bound on `edge-1` only, not on `edge-2` (never
  received) and not on the control plane (held, `ControlPlane` role);
  the fleet-wide stream bound on all three. The end-to-end form of the
  same scenario joins Story 12.12's L4 phase once 12.2 binds.
- A disabled stream is cut and applied exactly like an enabled one.
- A follower serving only a stream receives that stream's backends
  (the cut pitfall).
- `prepare_replica` refuses a blob with a UDP-shared backend, a stream
  with an invalid selector and a range above the cap, each naming the
  stream; the store is untouched (the `a_failed_apply_leaves_the_target_untouched`
  pattern).
- Applying a blob that swaps two stream names succeeds;
  `applying_the_same_replica_twice_is_idempotent` extended with streams.
- Export then import round trip with streams; an export without the
  `streams` key imports; a file with a UDP-shared backend is refused
  before `clear_all`; `compute_diff` reports an added, changed and
  removed stream.

**Lot 3**

- `messages.rs`: the `Heartbeat` field-number assertion gains
  `reserved_ports`; an absent report encodes as an absent field.
- `wire_corpus.rs` passes with its fixture untouched.
- `bridge.rs`: the report passes through `InPlaneAction::Heartbeat`.
- A control-plane test (`lorica-cluster/tests/cluster_plane.rs`
  harness, or the `cluster_plane.rs` unit tests) proving a follower's
  report reaches the session entry and the flush persists it; a session
  without a report keeps the stored value.
- An invalid report is dropped and the node is treated as not reported.

**Lot 4**

- `health.rs`: `probe_for` returns the HTTP probe with the same URL as
  today for a path-only backend, TCP connect for neither.
- `backends.rs` handler tests: create with `health_check` only, with
  `health_check_path` only, with both agreeing, with both disagreeing
  (`400`); update from legacy to typed and back; the response carries
  both fields; enabling checks on a backend linked to a UDP stream is
  refused naming the stream; a portless backend with checks on is
  refused.
- The existing backend, route and health-check suites pass unchanged
  (AC #10).
- `redact.rs`: a typed path with a query token is masked; sent back as
  read, the stored path is kept; any other `[redacted]` is refused.
- Automation and MCP: a token with `backends:write` sets
  `health_check` `http` and `tcp_connect`; the contract tests green.
- Vitest: the backend form sends the typed shape for both kinds and
  loads a legacy-only backend correctly.

**Lot 5**

- CRUD round trip with `enabled` toggled, `404`, `400` on each
  validation, audit rows with before and after, follower `409` outside
  break-glass, the RBAC table test (Viewer reads; Viewer refused on
  writes; Operator admitted on writes).
- **IV2, automated**: a control-plane `AppState` whose store holds an
  active `cluster_nodes` row `edge-1` with reported ports
  (`https: 8443`, ...); `POST /api/v1/streams` with port 8443 and
  selector `["edge-1"]` answers `409` and the message contains `edge-1`
  and the HTTPS listener; the same on `edge-1`'s enrollment port.
- On a control plane, a stream with an empty selector on this node's
  management port is `409` naming "this node"; the same port with a
  selector naming only `edge-1` (whose reported ports do not hold it)
  is accepted, since the control plane does not bind it (D-8). On a
  standalone state, any stream on the management port is `409` naming
  "this node".
- A range overlapping another stream on the same node and protocol is
  `409` naming the other stream; the same range on the other protocol
  is accepted; `[::]` against an existing `0.0.0.0` stream on the same
  port is `409`; a specific IPv6 literal against it is accepted; a
  disabled stream still conflicts; a node that never reported is `409`
  naming it.
- Import refusing a stream on a reserved port.

### Handed to Story 12.12

The scenario with the real 1.10.6 binary (AC #3 by execution rather
than by construction) joins Story 12.12's L4 phase, which already pulls
the 1.10.6 binary for NFR1: start 1.10.6 on a database 1.11.0 migrated,
holding a stream and a backend with a typed check, check that it opens
the database and serves HTTP, then re-upgrade after a path edit made
under 1.10.6 and check the D-2 matrix holds. Lot 1's unit tests remain
the per-commit guard. Story 12.12's file must list this scenario by name.

### Resolved (2026-11-14, maintainer and coordinator)

- **OQ-1, control plane binding.** First answered "as routes do"
  (verified: the control plane serves every route it holds,
  `build_proxy_config_inner`, `lorica/src/reload.rs`), which made IV1
  fail on the control plane. Final answer, AC #6 as amended: the control
  plane binds only streams with an empty selector, a standalone node
  every enabled stream, a follower what it was targeted by, because a
  stream opens a port and holding it for replication must not open it
  there. One pure function, `binds_here` (D-8).
- **OQ-2, IV1 wording.** The PRD reads per recipient; IV1 above is
  copied from it and verified in the e2e `cluster` profile's shape
  (control plane and two followers).
- **OQ-3, the 1,024 cap.** A constant (D-1).
- **OQ-4, portless backends.** Accepted, attach only to range streams,
  active checks off (D-6).
- **OQ-5, UDP and active checks.** Attaching a backend with active
  checks on to a UDP stream is refused, not switched off (D-6).
- **OQ-6, `managed_by`.** Dropped from the stream; the PRD AC #1 is
  amended (D-1).
- **OQ-7, role floor.** Operator for writes, Viewer for reads, as
  routes (D-10).
- **OQ-8, the real 1.10.6 binary.** Handed to Story 12.12's L4 phase
  ("Handed to Story 12.12").
- **New, `enabled`.** A 12.1 field, default true; a disabled stream is
  replicated and bound nowhere (D-1, D-8).
- **New, `node_shutdown`.** Joins `StreamEndReason` as a plain stop
  (D-7).
- **New, dual-stack.** One listen address; `[::]` is dual-stack and
  conflicts with every address; other IPv6 literals bind V6ONLY. In the
  shared conflict function and its tests (D-5).

## Dev Agent Record

### Debug Log

- Lot 1, first workspace clippy: `clippy::type_complexity` on the
  additive-migration test's column map; a `ColumnShape` alias fixed it.
- Lot 1, first product-crate run: the shape digest guard failed, as
  expected, because `Backend` gained `health_check`; and
  `test_backend_address_missing_port_rejected` pinned the pre-D-6
  refusal of a portless address. That test now pins the D-6 rule
  (refused with checks on, stored with checks off).
- Lot 2, first run: the shape digest guard failed as expected (`Stream`
  and `StreamBackend` joined the inventory, `CanonicalConfig` gained two
  fields); the digest moved with the version. The disabled-stream test
  first compared the cut's stream lists in order: the canonical sort key
  includes `enabled`, so flipping the flag can reorder them. The test
  compares them as a set.
- Lot 4, first `lorica-api` run: the empty-path refusal test asserted
  the message started with the field name; the error envelope prefixes
  it, so the test checks that it contains the sentence instead.
- Lot 5, the stream id rule: every Lot 1 and Lot 2 fixture built
  stream ids such as `s-1`, which the new id check in
  `Stream::validate` refuses wherever the store, the replica apply or
  the import write them. `sample_stream` now derives a canonical id
  from its label (`sample_stream_id`), and the tests that name a stream
  by id read it through the same helper.

### Completion Notes

Lot 1 (schema, models, store, shared rules, shape changes) and Lot 2
(replication, cut, export, import, diff) are done, Lot 4 (the typed
health check on every surface), Lot 5 (the stream management API
and the conflict checks), and Lot 3 (reserved ports on the wire,
persisted, and the selector warning), and Lot 6 (documentation).

Lot 6:

- `docs/cluster.md`: "The two phases" lists the stream refusals of
  `prepare_replica`; "Targeting a subset" adds streams and their links
  to the per-recipient cut (a backend travels with a kept route or a
  kept stream), a table of where each role serves routes and binds
  streams (`binds_here`, D-8, and why the control plane differs), and
  the per-node port check with its `stream_port_conflict` `409` and the
  never-reported refusal; "What may ride the heartbeat" adds the
  reserved ports and the "Node fact" class row (persisted by the
  30-second flush, `COALESCE`, the whole-report drop); "Running a
  Mixed-Version Fleet" adds the canonical format version as what
  decides whether configuration replicates, and a "From 1.10.x to
  1.11.0" subsection (D-3: format 3, followers first, the freeze and
  why, the rejected two-version decoder, the control-plane rollback
  state).
- `docs/hot-upgrade.md` "Rollback": from 1.11.0 back to 1.10.6, the
  database opens and HTTP is served (migrations 71 to 73 additive,
  `migrations_after_1_10_6_are_additive`), no stream is served, the
  legacy path decides the probe and a path edited under 1.10.6 wins on
  return, a 1.10.6 import drops stream links, a 1.11.0 export does not
  import into 1.10.6; the fleet case points at `docs/cluster.md`.
- `CHANGELOG.md` `[Unreleased]`: the migration line as the release
  paragraph; Added (the stream model and API, the per-node port check,
  reserved ports in the heartbeat, portless backends); Changed (the
  typed health check with `health_check_path` deprecated, the
  enrollment-port refusal at startup). The existing Fixed lines are
  untouched. Nothing about binding or forwarding: those are Stories
  12.2 and 12.3. Status codes as built, not as D-10 drafted them (`422`
  for a model rule, `400` for the two shapes disagreeing).
- `docs/architecture/source-tree.md`: `CANONICAL_FORMAT_VERSION = 3`,
  the cut by routes and streams, `models/stream.rs`,
  `models/health_check.rs`, `listen_ports.rs`, `store/streams.rs` in the
  `lorica-config` row and `streams.rs` in the `lorica-api` row.
- Handed over by Lot 4, outside the Lot 6 allowlist as drafted:
  `docs/automation.md` and `docs/mcp.md` now mask and restore the probe
  path in both shapes (`health_check.path` and `health_check_path`),
  describe the typed `health_check` on the backend writes with the
  deprecated path, and state that streams are on neither surface (D9).
- Not documented, because no test shows the code does it:
  `HealthCheck` is `deny_unknown_fields`, but the refusal of an extra
  key is tested for the `http` variant only
  (`the_wire_shape_is_tagged_by_kind`). Serde ignores extra keys on a
  unit variant of an internally tagged enum, so
  `{"kind": "tcp_connect", "path": "/x"}` is probably accepted as a TCP
  connect. The docs claim the refusal for `http` only.

Lot 3:

- Wire: `ReservedPortsReport` (`management`, `http`, `https` as
  `uint32`; `cluster`, `enrollment`, `automation` as `optional uint32`,
  absent when the listener is off) and `Heartbeat.reserved_ports` under
  tag 6, in `cluster.proto` and `messages.rs`. Compatibility is tested
  both ways against a frozen copy of the v1.10.6 `Heartbeat` (from the
  tag, in the `messages.rs` tests): a 1.10.6 decoder reads a 1.11.0
  heartbeat carrying a report with every field it knows intact, a
  1.11.0 decoder reads a 1.10.6 heartbeat as not reported, and a
  1.11.0 heartbeat without a report is byte-identical to the 1.10.6
  one. The frozen corpus passes with its fixture untouched (its
  `Heartbeat` literal gains `reserved_ports: None`).
- The decode-boundary check is `ReservedPortsReport::checked`, which
  yields `ReportedPorts` (the same six fields as `u16`) or `None`. All
  or nothing: one zero or one value above 65535 drops the whole report,
  since a partial report would let a stream through on a port the node
  holds, and clamping would check streams against a port the node does
  not hold. The bridge carries the outcome as
  `InPlaneAction::Heartbeat.reserved_ports: ReservedPortsClaim`
  (`NotSent`, `Reported`, `Dropped`); `serve_request` records a
  `Reported` value on the session entry and, for `Dropped`, warns once
  per session with the peer, node id and node name only. A dropped
  report is not a protocol violation and keeps the session.
- `lorica-cluster` keeps its own `ReportedPorts` rather than
  `lorica_config::listen_ports::ReservedPorts`, because it does not
  depend on `lorica-config` (the dependency direction
  `lorica-fleet/Cargo.toml` documents). The two conversions, in
  `cluster_follower.rs` (`reserved_ports_report`) and `cluster_plane.rs`
  (`reserved_ports_of`), destructure their source, so a listener added
  on either side fails to compile until the other carries it.
- The session entry holds the latest valid report of this session
  (`LiveSession::record_reserved_ports`,
  `LiveSessionSnapshot.reserved_ports`); a heartbeat without one, or
  with a dropped one, leaves it as it was. The flush is now
  `flush_session_facts` over a pure `live_node_facts`, so a test drives
  one flush without the 30-second loop; a session with no report maps
  to `None`, which the store's `COALESCE` turns into "keep the stored
  value".
- `ReplicaHandler` holds the report built once from
  `FollowerOptions.reserved_ports` and returns it on every heartbeat;
  the `#[allow(dead_code)]` Lot 1 put on that field is gone.
- The follower's apply log line prints `streams`,
  `streams_not_for_this_node` and `stream_backends` (Lot 2's hand-off).
- The round's unresolvable-selector WARN runs over streams too, naming
  the stream by id and name.
- Outside the allowlist: `lorica-cluster/src/lib.rs` (re-exports of
  `ReservedPortsReport`, `ReportedPorts` and `ReservedPortsClaim`, as
  for `NodeResources`), and one new test in
  `lorica-cluster/tests/enrollment.rs`
  (`a_heartbeat_carries_the_node_s_reserved_ports_onto_its_session`),
  beside the resource-reading test whose fleet harness it uses: the
  `cluster_plane.rs` integration harness registers no sessions.
- Not tested end to end: the dialer putting the follower's report on
  the wire. It is one line beside `node_resources`, which has no such
  test either; the `FollowerHandler` double in
  `lorica-cluster/tests/replication.rs` would be the place.

Follow-up from Lot 5, the import preview: `import_preview` now runs the
same port check as `import_config`, through one function
(`refuse_imported_port_conflicts`, `lorica-api/src/config.rs`) with
the same role, the same reserved ports and the same node assembly
(`first_port_conflict`). A file the import would refuse with the
`stream_port_conflict` `409` is refused by the preview with the same
`409` and the same message, rather than listed beside the diff: the
preview already refuses on structure (`400`) what the import refuses,
and the import itself stops at the first conflict. The
`/config/import/preview` operation in `openapi.yaml` gains the `409`.

Lot 5:

- Endpoints, in `lorica-api/src/streams.rs`: `GET /api/v1/streams`,
  `POST /api/v1/streams`, `GET`, `PUT` and `DELETE /api/v1/streams/{id}`,
  with `create_stream_as`, `update_stream_as` and `delete_stream_as`.
  No rule in `required_role`: reads fall on the Viewer default, writes
  on the Operator fall-through, pinned by
  `streams_have_the_route_floors` against the route twins. Writes take
  the route body cap and the route write budget in a bucket of their
  own, `streams_cud`.
- The `409` of a port conflict is `ApiError::Coded` with
  `error.code` `stream_port_conflict` (`STREAM_PORT_CONFLICT_CODE`), so
  a client tells it from the follower read-only `409` (`conflict`)
  without reading the message. The message names the stream, then
  carries the `PortConflict` display, which names the node ("this
  node", or the node by its roster name) and the object
  (the reserved listener with its phrase and its name, the other stream
  with its address, ports and protocol, or "has not reported its
  reserved ports yet").
- Status codes deviate from D-10's "validation 400" on purpose, to
  follow the rule `ApiError::Unprocessable` documents for new handlers
  and that the store already applies: a body that parses and breaks a
  model rule is `422` (`Stream::validate`, a backend id naming no
  backend, a taken name, the attachment rule, and Axum's own refusal of
  an unknown field, a hostname as listen address or an unknown
  protocol). The two route validators the stream reuses unchanged,
  `validate_group_name` and `validate_node_selector`, still answer
  `400`. Unknown id `404`, port conflict `409`.
- The check (D-5) is `first_port_conflict`, run inside the store
  closure that writes, before the write: this node with
  `AppState.reserved_ports` when `binds_here_when_enabled` holds for
  its role, then on a control plane every `Active` roster row the
  candidate's selector targets through `SelectorResolution` (built
  from every row, as the replication cut builds it), each as
  `NodeRole::Follower` with its persisted reserved ports. A revoked or
  pending row is not checked. Every other stored stream is passed, the
  disabled ones included; `stream_port_conflicts` skips the
  candidate's own row by id and judges each node's streams by its role.
- Update semantics: an absent field keeps its value; `port_first`
  without `port_last` makes the stream a single port, so moving a
  single-port stream never turns it into a range; `port_last` alone
  moves the end of a range; `backend_ids` replaces the set. The new
  links are written before the row in one transaction, so the
  attachment rule judges the row as written against the links as they
  will stand.
- `StreamResponse` is built field by field and serialises
  `listen_address` as `IpAddr` (its canonical text). The view test
  compares its key set with the model's serialised key set minus
  `STREAM_WITHHELD_FIELDS` (empty) plus `backend_ids`.
- Import (D-9): `import_config` runs `first_port_conflict` on every
  imported stream against the other imported streams, inside the store
  closure, before `import_to_store` clears anything. The nodes are
  assembled as for an API write, so on a control plane an import is
  also checked on the enrolled nodes its streams target, which D-9
  leaves out and AC #7 asks for. The preview does not run it (it
  does since the follow-up recorded under Lot 3).
- The stream id rule (decided by the orchestrator, outside D-1):
  `Stream::validate` refuses an id that is not a UUID in its canonical
  lowercase hyphenated form (`is_canonical_stream_id`,
  `STREAM_ID_LEN = 36`), so an id arriving by replication or by file is
  held to the form the API mints (`Uuid::new_v4().to_string()`). The
  refusal shows the id debug-quoted and cut. `lorica_worker::stream_ctl::MAX_STREAM_ID_LEN`
  can drop from 64 to `STREAM_ID_LEN`; that file belongs to Story 12.2
  and is not edited here.
- OpenAPI: a `Streams` tag, the five operations, `StreamProtocol`,
  `StreamResponse`, `CreateStreamRequest`, `UpdateStreamRequest` and a
  `StreamConflict` response; no separate `Stream` schema, since the API
  never answers the model itself. `/config/import` gains its `409`.
- Outside the allowlist: `lorica-config/src/models/mod.rs` (the
  re-export of the id rule and of the test helper), the Lot 1 and Lot 2
  test fixtures of `lorica-config/src/{canonical,diff,import}.rs` and
  `lorica-config/src/store/{replica,streams}.rs`, and the one stream
  fixture of `lorica-api/src/backends.rs`, all for the id rule.

Lot 2:

- `CANONICAL_FORMAT_VERSION` is 3. `the_canonical_format_version_is_three`
  pins the number, `every_1_11_0_shape_rides_format_version_three`
  replaces the 10.4 ride guard (a blob with a stream, a link and a typed
  health check encodes at 3 and decodes), and
  `a_blob_stamped_version_two_is_refused_by_version` builds the 1.10.x
  shape (version 2, no `streams`, no `stream_backends`, no
  `health_check`) and checks the refusal names both versions. The
  older serde-default tests (`a_1_8_0_blob_...` and siblings) are kept:
  they now pin only those defaults, which the digest paragraph says.
- The whole-snapshot check is one call of `check_backend_attachments`
  over the decoded blob's backends, streams and both link tables, in
  `prepare_replica` after every stream's `validate()`. A conflict is
  refused as `stream <id>: <conflict>`, the id looked up from the name
  the conflict carries (or `backend <id>` when no stream is involved).
  The apply then uses only unchecked writers for backends, route links,
  streams and stream links; `apply_replica_backends` was also switched,
  since `update_backend` is checked since Lot 1 and runs while the
  previous generation's links are still on the node
  (`a_generation_moving_a_backend_from_a_udp_stream_to_a_route_applies`
  fails with the checked writers).
- Streams are applied by deleting every local stream (which cascades
  every stream link) and inserting the kept ones, one step after the
  route links. Equivalent to "delete-then-insert of every kept stream"
  plus the deletion of streams no longer kept, in one statement.
- The import runs the stream check (`validate_streams`: each stream's
  rules, name uniqueness inside the file, link references, the
  attachment rule) from `validate_structure`, so both `parse_toml` and
  the preview run it, and `import_to_store` runs it again before
  `clear_all`, because it writes through the unchecked writers and is
  public: a caller holding an `ImportData` built without the parser
  cannot skip the check. A duplicate stream name inside the file is
  refused there, before `clear_all`, rather than by the `UNIQUE` index
  half way through the import.
- `ConfigDiff` gains `stream_backends` beside `streams`, the counterpart
  of `route_backends`, so a change of a stream's backends shows in the
  preview. The two link diffs share one helper, `diff_links`.
  `stream_eq` compares every field but the timestamps.
- `lorica-api/src/automation/test_support.rs` needed no change: it
  holds no `CanonicalConfig` literal on this tree, only a call to
  `canonical_config`.
- Outside the allowlist: `lorica-config/src/store/adcs_authority.rs`,
  whose test fixture builds an `ImportData` literal and gains the two
  empty stream fields (construction site only).
- The follower's apply log line (`lorica/src/startup/cluster_follower.rs`,
  Lot 3's file) does not print the three new `ReplicaOutcome` counts;
  left to that lot.

Lot 4:

- Wire shape, the same on the management API, the automation plane
  and the MCP tools (whose bodies are the management bodies):
  `health_check: {"kind": "http", "path": "/healthz"}` or
  `{"kind": "tcp_connect"}`, the model's own serde form. Every answer
  carries `health_check` and the deprecated `health_check_path`, the
  latter computed from the former (`HealthCheck::legacy_path`).
- Input rule, one function (`requested_health_check`,
  `lorica-api/src/backends.rs`): the typed check alone; the path alone,
  read as before (a path is `http`, the empty string `tcp_connect`);
  both, compared through the projection rather than as checks, so a
  later kind without a path agrees with an empty legacy path. Both
  disagreeing is `400` naming both fields; an `http` check with an
  empty path is `422`. Neither on create is `tcp_connect`, neither on
  update keeps the stored check. The handler always goes through
  `Backend::set_health_check`, so the store's reconcile never sees a
  disagreeing pair from the API.
- Deprecation is expressed as `deprecated: true` on
  `health_check_path` in both OpenAPI documents, `@deprecated` on the
  TypeScript fields, and the doc comments of the request and response
  structs and the MCP tool summaries.
- The store's attachment refusals (UDP-attached with checks on,
  portless with checks on) reach the API as `ConfigError::Validation`,
  which `ApiError` maps to `422`, not `400` as D-6 says; the handler
  tests pin `422` and the stream's name in the message.
- `restore_health_check_path` reads the sent path from the typed check
  (which the handler already set from whichever shape was sent) and
  puts the stored path back through `set_health_check`, so both fields
  are restored. Its refusal now reads
  "health_check_path and health_check.path: ...". `backend_row` masks
  the query values of `health_check.path` as well.
- The automation document keeps its rule of not restating management
  bodies: `ManagementBackendCreate` and `ManagementBackendUpdate` gain
  only `health_check` and the deprecated `health_check_path`, beside a
  `HealthCheck` schema of its own; the management document carries
  `HealthCheck` with a `discriminator` over `HttpHealthCheck` and
  `TcpConnectHealthCheck`, and the D-11 fields described HTTP-only.
- No nested MCP vocabulary for `health_check`: `HealthCheck` is an enum
  with `deny_unknown_fields`, so the plane refuses a mistyped key itself
  (Axum's `422`) rather than dropping it, and `pin_nested` only
  requires a vocabulary for a struct.
- The automation read pin (`AUTOMATION_READ_FIELD_NAMES`) gains
  `health_check` and `kind`, the typed check's tag.
- The dashboard form sends the typed shape only, never
  `health_check_path`; the kind is a select (TCP connect, HTTP GET), the
  path field shows for `http` only, and a new kind is one more option
  and one more `switch` arm in `formHealthCheck` and
  `describeHealthCheck`. The address field still requires `host:port`:
  portless backends are for range streams, whose dashboard is
  Story 12.10.
- `lorica-api/src/automation/write.rs` needed no change: the call site
  of `restore_health_check_path` is unchanged.
- Outside the allowlist, not edited: `docs/automation.md` and
  `docs/mcp.md` describe the masking of `health_check_path` only and
  should name `health_check.path` too; no lot of this story owns them.

- `Stream.listen_address` is an `IpAddr`, not a `String`: the canonical
  RFC 5952 form is then true by construction (serde parses any spelling
  and writes `Display`), a hostname is refused at decode, and
  `Stream::validate` only has the IPv4-mapped refusal left to do.
- "`binds_here` with `enabled` taken as true" (D-5) is a named function,
  `binds_here_when_enabled`; `binds_here` is `enabled &&` it, so the rule
  still lives in one place. `stream_port_conflicts` reads it.
- `AttachmentConflict` names the backend (id and address), the stream by
  name and the rule broken (`AttachmentRule`). Two refusals can involve
  no stream: a portless backend with checks on that is linked nowhere,
  and a portless backend on a route alone; those name the backend and the
  route. The store calls the rule over the backends a write touched
  only, so a write is never refused for a row it did not change.
- Checked writes (`create_backend`, `update_backend`,
  `link_route_backend`, `create_stream`, `update_stream`,
  `set_stream_backends`) run in a SQLite savepoint
  (`ConfigStore::within_savepoint`), not a transaction, because they are
  also called inside `in_transaction` (the environment `PUT`), where a
  nested `BEGIN` fails. Unchecked writers for Lot 2:
  `create_backend_unchecked`, `update_backend_unchecked`,
  `link_route_backend_unchecked`, `create_stream_unchecked`,
  `update_stream_unchecked`, `link_stream_backend_unchecked`. Until Lot 2
  switches the replica apply and the import to them, both still use the
  checked writers; with no stream in any blob or file yet, that refuses
  nothing a 1.10.x write could produce.
- A `health_check_json` this binary cannot parse reads as absent (the
  legacy path decides, with a WARN), not as `Corrupt`: it is a kind a
  newer release added, the rollback case the path column exists for, and
  failing it would fail every backend read.
- `ClusterNode.reserved_ports` is `skip_serializing`: the node's API view
  and its OpenAPI schema stay as they are; only the conflict check reads
  it.
- `ReservedPorts` lives in `lorica_config::listen_ports`; `cli.rs`
  re-exports it `pub(crate)`, so `crate::cli::ReservedPorts` imports in
  `cluster_plane.rs` and `automation.rs` did not move.
- The process's `ReservedPorts` is built once per startup mode in two
  steps: `listener_ports` (management, proxy, and the automation port
  read from `--automation-listen` by `cli::requested_port`, before that
  listener validates it) goes to the follower; the cluster plane's
  operational and enrollment ports are added after the plane spawns, and
  that full value goes to `AppState.reserved_ports` and to the
  automation validator. The cluster plane's own validator still gets it
  without the automation port, as before.
- `FollowerOptions.reserved_ports` carries `#[allow(dead_code)]` with a
  comment: nothing reads it until Lot 3 wires the heartbeat, and a
  never-read field fails `CARGO_BUILD_WARNINGS=deny`. Lot 3 removes the
  attribute.
- `CANONICAL_SHAPE_DIGEST` is updated in Lot 1, with its paragraph,
  because `Backend.health_check` is a Lot 1 shape change and the guard
  would otherwise leave the tree red; `CANONICAL_FORMAT_VERSION` stays 2
  until Lot 2 takes the D-3 step.
- Allowlist extensions, each forced by compilation or by the Lot 1 task
  list: `lorica/src/startup/mod.rs` (`spawn_cluster_runtime` takes the
  follower's ports and fills the `FollowerOptions` literal, which lives
  there); `lorica/src/startup/cluster_plane.rs` beyond its
  `LiveNodeFacts` literal (`ClusterPlane::enrollment_port`, so the
  process's ports include the enrollment bind); `lorica-config/src/canonical.rs`
  beyond fixtures (the digest above).

## File List

Lot 1, new: `lorica-config/src/listen_ports.rs`,
`lorica-config/src/models/health_check.rs`,
`lorica-config/src/models/stream.rs`, `lorica-config/src/store/streams.rs`.

Lot 1, modified: `lorica-config/src/lib.rs`,
`lorica-config/src/models/{mod,backend,cluster}.rs`,
`lorica-config/src/store/{mod,backends,row_helpers,cluster_nodes,replica}.rs`,
`lorica-config/src/canonical.rs`, `lorica-config/src/tests.rs`,
`lorica-config/tests/config_db_upgrade.rs`, `lorica/src/cli.rs`,
`lorica/src/startup/{mod,single,supervisor,automation,cluster_follower,cluster_plane}.rs`,
`lorica/src/proxy_wiring/tests.rs`, `lorica/tests/*_e2e_test.rs` (every
suite holding a `Backend` literal),
`lorica/tests/proxy_{config,routing}_test.rs`, `lorica-fleet/src/runtime.rs`,
`lorica-api/src/server.rs`, `lorica-api/src/{backends,target,tests}.rs`,
`lorica-api/src/routes/crud.rs`, `lorica-api/src/cluster/tests.rs`,
`lorica-api/src/acme/tests.rs`,
`lorica-api/src/automation/{audit,environments,protections,redact,write}.rs`,
`lorica-api/src/automation_tokens/tests.rs`,
`lorica-api/src/oidc_issuers/tests.rs`,
`docs/stories/story-12.1-stream-model.md`.

Lot 2, modified: `lorica-config/src/canonical.rs`,
`lorica-config/src/store/replica.rs`, `lorica-config/src/export.rs`,
`lorica-config/src/import.rs`, `lorica-config/src/diff.rs`,
`lorica-config/src/store/adcs_authority.rs` (test fixture),
`docs/stories/story-12.1-stream-model.md`.

Lot 4, modified: `lorica/src/health.rs`, `lorica-api/src/backends.rs`,
`lorica-api/src/automation/redact.rs`,
`lorica-api/src/automation/read/plane_tests.rs`,
`lorica-api/src/automation/write/plane_tests.rs`,
`lorica-api/openapi.yaml` (backend schemas and `HealthCheck`),
`lorica-api/openapi-automation.yaml`, `lorica-api/tests/openapi_contract.rs`,
`lorica-mcp/src/tools.rs`, `lorica-dashboard/frontend/src/lib/api.ts`,
`lorica-dashboard/frontend/src/routes/Backends.svelte`,
`lorica-dashboard/frontend/src/routes/Backends.test.ts`,
`docs/stories/story-12.1-stream-model.md`.

Lot 3, modified: `lorica-cluster/proto/cluster.proto`,
`lorica-cluster/src/{messages,bridge,roster,dialer,lib}.rs`,
`lorica-cluster/src/listener/operational.rs`,
`lorica-cluster/tests/{cluster_plane,enrollment,wire_corpus}.rs`,
`lorica/src/startup/{cluster_follower,cluster_plane}.rs`,
`docs/stories/story-12.1-stream-model.md`.

Lot 5 follow-up (import preview), modified: `lorica-api/src/config.rs`,
`lorica-api/src/streams/tests.rs`, `lorica-api/openapi.yaml` (the
preview's `409`), `docs/stories/story-12.1-stream-model.md`.

Lot 5, new: `lorica-api/src/streams.rs`, `lorica-api/src/streams/tests.rs`.

Lot 6, modified: `docs/cluster.md`, `docs/hot-upgrade.md`,
`CHANGELOG.md`, `docs/architecture/source-tree.md`, `docs/automation.md`,
`docs/mcp.md`, `docs/stories/story-12.1-stream-model.md`.

Lot 5, modified: `lorica-api/src/lib.rs`, `lorica-api/src/server.rs`
(routes), `lorica-api/src/middleware/authorize.rs` (table test),
`lorica-api/src/routes/crud.rs` (two visibilities),
`lorica-api/src/config.rs`, `lorica-api/openapi.yaml` (stream paths and
schemas, the import `409`), `lorica-config/src/models/{stream,mod}.rs`
(the id rule), the id fixtures of
`lorica-config/src/{canonical,diff,import}.rs`,
`lorica-config/src/store/{replica,streams}.rs` and
`lorica-api/src/backends.rs`, `docs/stories/story-12.1-stream-model.md`.

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-11-14 | 0.1 | Story drafted from the Epic 12 PRD. Status Draft. | Romain G. |
| 2026-11-14 | 0.2 | Open questions resolved and folded in (control plane binds as routes, `enabled`, no `managed_by`, `node_shutdown`, dual-stack rule, Operator floor, constant cap, portless backends, 1.10.6 binary scenario to 12.12); allowlists rechecked against `4e864593`. Status Draft. | Romain G. |
| 2026-11-14 | 0.3 | AC #6 amended: the control plane binds only streams with an empty selector; `binds_here` and `NodeRole` (D-8); the "this node" conflict rule and IV1 test rewritten for the control plane and two followers. Status Draft. | Romain G. |
| 2026-11-14 | 0.4 | Lot 1 implemented: migrations 71 to 73, `Stream`, `HealthCheck`, `listen_ports`, the stream store, the attachment rule on every management write, reserved ports on `cluster_nodes` and in `AppState`, every construction site. Status InProgress. | Romain G. |
| 2026-11-14 | 0.5 | Lot 2 implemented: `CANONICAL_FORMAT_VERSION` 3 with streams and stream links in the blob, the per-recipient cut of streams and their backends, the whole-snapshot attachment check in `prepare_replica`, the apply and the import on the unchecked writers, streams in TOML export, import and diff, IV1 in the `cluster` shape. Status InProgress. | Romain G. |
| 2026-11-14 | 0.6 | Lot 4 implemented: the typed health check on every surface (health loop through `probe_for`, management API with both shapes and the disagreement refusal, redaction of the typed path, MCP backend fields, both OpenAPI documents with `health_check_path` deprecated, dashboard form and `api.ts`). Status InProgress. | Romain G. |
| 2026-11-14 | 0.7 | Lot 5 implemented: the stream management API (CRUD at the route floors, audit, `streams_cud` budget), the per-node port check with its `stream_port_conflict` 409 on every write and on import, IV2 automated, and stream ids held to the canonical UUID form in `Stream::validate`. Status InProgress. | Romain G. |
| 2026-11-14 | 0.8 | Lot 3 implemented: `ReservedPortsReport` in the heartbeat under tag 6, tested both ways against the v1.10.6 shape, checked at the decode boundary and dropped whole on an impossible port, held on the session and persisted by the flush with `COALESCE`, reported by `ReplicaHandler`; the apply log line prints the stream counts; the selector WARN covers streams. The import preview runs the import's port check (Lot 5 follow-up). Status InProgress. | Romain G. |
| 2026-11-14 | 0.9 | Lot 6 implemented: `docs/cluster.md` (streams in the cut, where each role binds, the port check, the Node fact class, the 1.10.x to 1.11.0 step with its replication freeze), `docs/hot-upgrade.md` (rollback to 1.10.6), `CHANGELOG.md` `[Unreleased]`, `docs/architecture/source-tree.md`, and the typed probe path in `docs/automation.md` and `docs/mcp.md`. Every Lot done. Status Review. | Romain G. |
