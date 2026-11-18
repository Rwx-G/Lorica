# Story 12.10: Streams on Every Surface

**Epic:** [Epic 12 - TCP and UDP Stream Proxying (v1.11.0 and v1.12.0)](../prd/epic-12-v1.11.0.md)
**Status:** InProgress
**Priority:** P0
**Author:** Romain G.
**Depends on:**
- Story 12.1 (Review): the stream management API (`lorica-api/src/streams.rs`,
  `StreamResponse` built field by field, `STREAM_WITHHELD_FIELDS` empty,
  the `_as(state, actor, ...)` split, reads at Viewer and writes at
  Operator), the audit rows `stream.create`, `stream.update`,
  `stream.delete`, portless backends (D-6, OQ-4), attachment rule 3 (an
  environment's backend never serves a stream).
- Story 12.2 (InProgress): the bind state (`bind` on the stream view,
  D-h), the per-node stream plane on the cluster nodes response
  (`stream_plane`, `stream_ports`, `NodeStreamBinding`, D-i), the
  dashboard pieces of its Lot F (`StreamBudget.svelte` on the System
  page, the Cluster roster column and node drawer, `lib/streams.ts`).
- Story 12.3 (InProgress): the D-q fields and the "local backend" flag.
- Story 12.4 (Draft): the D-k fields, `drains_on_upgrade` (D-j), the
  "no SNI" rule kind and `upstream_tls.skip_verify` (Resolved 5). Lot F
  (API surfaces) must have landed before this story's Lots B and D1.
- Story 12.5 (InProgress): the `udp` object and `udp.unbounded_responses`
  (D-l). Lot G (API) before Lots B and D1.
- Story 12.6 (Draft): the D-m fields and the link's `max_active`. Lot E
  (API) before Lots B and D1, Lot F (allowlist hook-ups) before Lot D2.
- Story 12.7 (InProgress): the backend form's typed health check and
  template picker (`routes/Backends.svelte`, Lot 3), which Lot E extends.
- Story 12.9 (Draft): `StreamMetricsCollector` (Lot C2), the stream log
  tab and SLA section (Lot H), the D-j rule that stream rows need
  `logs:read` and `streams:read`.

**Blocks:** Story 12.9 Lot C3 (its stream-log read needs the
`streams:read` scope this story adds), Story 12.12 (the parity matrix's
"dashboard", "automation read" and "MCP read" rows), Story 12.13 and
Story 12.15 (each adds its badge kind to the map of D-c). It closes the
dashboard halves left open by 12.2 AC #4 (failed-bind badge), 12.4 AC #6
("drains on upgrade") and 12.5 AC #4 (unbounded responses).

---

As an operator running a fleet with automation and an MCP client,
I want to see streams wherever I see routes, and manage them from the dashboard,
so that layer 4 is not a second-class feature.

## Problem

After Stories 12.1 to 12.9 a stream is a full object on the management
API, and nowhere else. The dashboard shows stream bind states on the
System and Cluster pages but has no page to list, create or edit a
stream; the backend form refuses the portless address range streams
need; a node's binding for a stream the control plane does not target
there shows a bare id. The automation plane and the MCP server know
nothing of streams: a pipeline or a model cannot even see that a port
is open. And two paths change a stream without a `stream.*` audit row:
a TOML import, and a backend delete that cascades out of a stream's
backend set, which a token holding `backends:write` can trigger today.

## Acceptance Criteria

These are the PRD's, unchanged. They are the contract.

1. **Dashboard**: a Streams page beside Routes (loader map in `lorica-dashboard/frontend/src/routes/Dashboard.svelte`, sidebar entry in `components/Nav.svelte`) with list, form, badges (unbounded UDP responses, "no SNI", silent client, local backend, transparent mode, drains on upgrade, failed bind), live counters, and the backend page showing which routes and streams use each backend.
2. **Automation API (D9)**: a new `streams:read` scope in the closed `AutomationScope` enum, justified where the enum is defined, with every artefact the enum's comment lists moving in the same commit. No stream write scope. The `environment` resource stays HTTP-only.
3. **MCP (D9)**: the read tier gains stream listings and stream status, paginated and capped like the other read tools. No tier gains a stream mutation.
4. **Cluster**: the fleet view shows each stream's bind state per node.
5. **Audit**: every stream mutation lands in the tamper-evident chain with its origin.

## Integration Verification

- IV1: A stream created from the dashboard appears in the automation API with a `streams:read` token and in the MCP read tier; an automation token has no way to create one.

## What the code does today

Verified on `e275a00e`.

- **Scope vocabulary.** `AutomationScope` (`lorica-automation-policy/src/scope.rs`)
  has 13 variants. The comment above the enum names every restatement:
  `as_str` (pinned against the serde renames by
  `every_scope_round_trips_through_its_exact_wire_string`),
  `is_published_reason` in `lorica-api/src/automation/audit.rs` (derived
  from `ALL`), both OpenAPI documents (held to `ALL` by
  `lorica-api/tests/openapi_contract.rs`),
  `automation-scopes.generated.ts` (diffed by
  `lorica-api/tests/automation_scope_fixture.rs`, which also renders the
  tier vectors), and the tier partition in `tier.rs`. Not named there and
  also restating it: the exhaustive `is_grant_bounded` match (a compile
  error until placed), the `AutomationScope` string union in
  `lorica-dashboard/frontend/src/lib/api.ts` (around line 2449), the MCP
  catalogue test `every_scope_but_the_environment_pair_has_a_tool`
  (`lorica-mcp/src/tools.rs`), and the scope list in
  `docs/architecture/api-design-and-integration.md` line 61.
- **`AUTOMATION_AUDIT_REASONS` does not move for a scope.** The PRD lists
  it among the artefacts; the code says otherwise. Scope spellings were
  removed from that list and are published by derivation from `ALL`, and
  a test asserts no listed word contains `:`. It moves only if this story
  adds a refusal word, which it does not (D-f).
- **Tiers.** `READ.requires` lists the eight read scopes;
  `lorica mcp token create --tier read` mints every one of them except the
  environment pair. `resolve` places a token by the highest tier its
  scopes touch.
- **Automation reads** (`lorica-api/src/automation/read.rs`) are wrappers
  of management handlers, windowed by `PageQuery` to
  `AUTOMATION_READ_MAX_ROWS` (200) and `AUTOMATION_READ_MAX_ANSWER_BYTES`
  (256 KiB), masked through `redact`, and filtered to the grant for a
  principal that `carries_grants()`. `read/plane_tests.rs` pins every key
  name any answer carries (`AUTOMATION_READ_FIELD_NAMES`). The path to
  scope matrix is `required_scope` in `lorica-api/src/automation/scope.rs`;
  an undeclared path is a 403 `no_declared_scope` for any token.
- **Cluster status on the automation plane** (`cluster:read`) carries no
  stream data: `FleetEntry` has no stream column and `get_status` passes
  no stream to `node_responses`.
- **Stream audit.** `create_stream_as`, `update_stream_as`,
  `delete_stream_as` write `stream.create|update|delete` with before and
  after views. `import_config` (`lorica-api/src/config.rs`) writes one
  `config.import` row with no payload. `delete_backend` in the store
  cascades both route and stream links; `delete_backend_as`
  (`lorica-api/src/backends.rs`) writes the backend's row only. The
  automation `DELETE /automation/v1/backends/{id}` reaches
  `delete_backend_as` with no stream check; only an address move under a
  stream with `allow_local_backend` is refused
  (`ensure_not_moved_under_a_local_stream`, `automation/write.rs`).
- **Fleet view.** `NodeStreamBinding` (`lorica-api/src/cluster/mod.rs`)
  carries `stream_id` and no name; the drawer joins it with
  `stream_ports`, so a binding for a stream not in `stream_ports` (12.2
  Lot F's "kept, by id") shows an id only.
- **Dashboard.** No `StreamResponse` type in `lib/api.ts` yet (only the
  stream plane types of 12.2). `Backends.svelte`'s address validator
  requires `host:port` (`ADDRESS_PATTERN`), and its table has no usage
  column. `GET /api/v1/streams/budget` is the precedent for a static
  segment beside `/api/v1/streams/{id}`.

## Decisions taken in this story

### D-a. The Streams page: a list and a drawer, like Routes

- `routes/Streams.svelte`, loaded as `'/streams'` in `Dashboard.svelte`'s
  loader map, and a `Streams` entry directly after `Routes` in
  `Nav.svelte` (icon `radio` is taken by Probes; Lot D1 picks an existing
  glyph or adds one to the icon switch Nav already has). Visible to every
  role: reads are at Viewer (12.1 D-10). The create button and the
  drawer's save are hidden for a Viewer through `canWrite`, as on Routes.
- **List**: grouped by `group_name` as Routes groups, with search over
  name, group and endpoint, sortable columns: name, protocol, endpoint
  (`streamEndpoint` of `lib/streams.ts`: `[::]:7000`, ranges as
  `6000-6009`), backends (count, primaries and backups), bind state
  (D-d), live counters (D-e), badges (D-c), enabled.
- **Row actions**: edit, enable or disable (an update of `enabled` only),
  delete with a confirmation that says established connections drain for
  `worker_drain_timeout_s` and then close with `config_removed` (12.2
  AC #8). Links: the stream log tab filtered on the stream and the stream
  SLA section, in whatever URL shape 12.9 Lot H gives them (D1 runs after
  H and reads it there).

### D-b. The form covers every stored field, and refuses nothing itself

`components/StreamDrawer.svelte` with one tab component per concern under
`components/stream-tabs/`, as `RouteDrawer` and `route-tabs/` do:

| Tab | Fields | Shown for |
|---|---|---|
| General | name, group, protocol, enabled, listen address, first and last port, `node_selector` | always |
| Backends | primary and backup backend lists, each link's `max_active` (12.6); on a TLS stream, the links per match rule instead (12.4 D-k) | always |
| TLS | `tls_mode`, `match_rules`, `no_sni_acknowledged`, `clienthello_timeout_ms`, `tls_terminate` (certificates, client auth CA bundle), `upstream_tls` (verification, SNI, client certificate, CA bundle, `skip_verify`) | TCP |
| Connection | `load_balancing`, connect, idle and total timeouts, `max_connect_attempts`, keepalive and its idle, `close_on_backend_down`, PROXY send, PROXY accept and its trusted CIDRs, `source_addresses`, `allow_local_backend`, upload and download rates, `max_connections` | TCP; on UDP only the fields 12.5 D-l lifts |
| UDP | every key of the `udp` object, `unbounded_responses` with the two bounds it suspends shown disabled beside it (12.5 Resolved 6) | UDP |
| Protection | source allow and deny CIDRs, GeoIP, `source_max_connections`, `max_pending_connections`, `source_open_rate`, `open_rate` | always (TCP-only caps hidden on UDP) |

- **The applicability table lives in one function**, `lib/stream-form.ts`
  `fieldsFor(protocol, tlsMode)`, which decides what is shown and what is
  sent. A field not shown is never sent: the server refuses fields that
  do not apply (12.4 D-g, 12.3 D-q's UDP rule), it does not ignore them.
  A protocol switch on an existing stream sends the new protocol and lets
  the server reset `udp` (12.5 Lot G).
- **No range is transcribed into the frontend.** An empty field means the
  server default, as the backend form's interval does since 12.7 Lot 0;
  the placeholder says "server default", never a number. The server is
  the authority: a 400 is shown inline, routed to the tab whose field
  the message names (`fieldTab(message)` in `stream-form.ts`, tested on
  every field prefix). What it gives up: a range error appears on save,
  not on keystroke. What it avoids: a second copy of about forty bounds
  that drifts the first time a story moves one.
- **Every cap is labelled "per node"** (12.6 D-k): `max_connections`,
  `source_max_connections`, `max_pending_connections`, the two open
  rates, `max_active`, `udp.max_sessions`, `udp.source_session_cap`, the
  two UDP source rates. A Vitest asserts the label on each.
- **Help text** for the fields that open a hole states it in one line
  next to the control, never in a modal (D6's rule): unbounded responses,
  `allow_local_backend`, PROXY accept, `no_sni_acknowledged`,
  `upstream_tls.skip_verify`.
- **Certificates** are picked from `GET /api/v1/certificates`; the
  coverage check is the server's (12.4 D-k), its 400 names the rule.

### D-c. Badges: one derived map, no dead badge

- `lib/streams.ts` gains `StreamBadgeKind`, a string union of the kinds
  1.11.0 can derive, `STREAM_BADGES: Record<StreamBadgeKind, { label, tone,
  help }>` and `streamBadges(stream, status)`, an exhaustive `switch`
  that derives each badge from fields the API returns, never from a
  field of its own:

| Kind | Derived from | Note |
|---|---|---|
| `failed_bind` | any node's state `failed` in the status (D-d) | tooltip: node, kind, port, OS error, since |
| `unbounded_responses` | `udp.unbounded_responses` | suffix "allowlisted" when `source_allow_cidrs` is non-empty |
| `no_sni` | a match rule of the `no_sni` kind | suffix "allowlisted" or "acknowledged" (12.6 D-l) |
| `local_backend` | `allow_local_backend` | |
| `drains_on_upgrade` | `drains_on_upgrade` (12.4 D-j) | help says what it means in 1.11.0, where every stream drains |
| `unverified_upstream` | `upstream_tls.skip_verify` | 12.4 Resolved 5 |

- **Silent client (12.15) and transparent mode (12.13) are not in the
  union.** Their fields do not exist in 1.11.0, so a badge for them could
  never render: it would be dead code, which the house rules forbid. The
  slot is reserved by the shape instead: the badge column renders
  whatever `streamBadges` returns, and `Record<StreamBadgeKind, ...>`
  makes a new kind a `tsc` error until it has a label and help. Each of
  those stories adds one kind and one `switch` arm in its dashboard Lot;
  "Handed to other stories" says so, and so does the comment above the
  union. The PRD's AC #1 list is therefore met in 1.11.0 for the five
  kinds whose fields exist, and completed by 12.13 and 12.15 in 1.12.0.
- The badges show in the list row and in the drawer header. The same map
  feeds both, so they cannot disagree.

### D-d. Bind state per node: a status endpoint, and names on the fleet view

- **Management `GET /api/v1/streams/status`** (Viewer, the GET default of
  `required_role`), in a new `lorica-api/src/streams/status.rs`. One
  answer for every stream, so the page makes one call per refresh:

```json
{
  "streams": [
    {
      "id": "<UUID>",
      "name": "pg",
      "protocol": "tcp",
      "bind": { "state": "bound", "workers_serving": 4, "workers": 4 },
      "nodes": [
        { "node_id": "<UUID>", "node_name": "host01", "state": "bound" },
        { "node_id": "<UUID>", "node_name": "host02", "state": "failed",
          "kind": "address_in_use", "port": 5432,
          "os_error": "Address already in use (os error 98)",
          "since": "2026-11-15T10:00:00Z" }
      ],
      "nodes_truncated": false,
      "counters": { "node_name": null, "active": 3, "...": "D-e" }
    }
  ]
}
```

- `bind` is this node's state, the same value as on the stream view.
  `nodes` is present on a control plane only: one entry per node the
  stream targets (the node's `stream_ports`), the state read through the
  same `stream_plane_view` rule the drawer uses (a targeted stream the
  node does not list is `bound` when the node is in sync, `unknown` under
  drift or before a report). The control plane factors that rule into a
  `pub(crate)` function in `cluster/mod.rs` so the roster and this
  endpoint call one implementation. Standalone and follower: `nodes` is
  `null`, `bind` says it all. Bounded: nodes per stream by the fleet,
  streams by the listening-socket cap (12.2 AC #5).
- **`NodeStreamBinding` gains `stream_name: Option<String>`**, resolved
  from the control plane's stored streams when the roster is built
  (`streams_for_review` already reads them). `null` means the control
  plane no longer holds that stream (a node still reporting one deleted
  since); the drawer then shows the id with "not in this configuration".
  `openapi.yaml` and `lib/cluster.ts` follow. This closes the gap 12.2 Lot
  F left: every row of the drawer names its stream.
- **AC #4 is met twice**: per node in the Cluster drawer (12.2, names now
  complete), and per stream on the Streams page (bound on N of M nodes,
  each failed node listed), both from one rule.
- **Amended by Lot A, against the code** (2026-11-18):
  - The rule already existed in 12.2 as `ReportedBindings`
    (`stream_budget.rs`), which the budget view uses. Lot A wraps it in
    `node_bind_state(report, drifted, stream_id)` in `cluster/mod.rs`
    (a report-less node reads `unknown`), called by `stream_plane_view`
    for the drift entries and by `stream_node_states` for the status.
  - `nodes` lists **active** nodes only: a pending node binds nothing
    until activated, and showing it `unknown` would read as a fault.
  - A targeted node **without a report** (offline, or not reported yet)
    is listed `unknown`, as the bullet above says; the Lot A test line
    "before a report absent" is read that way, since an absent node
    would make "bound on N of M" count it out silently. The budget view
    of 12.2 still omits such a node; it answers a different question.
  - **`nodes_truncated` is dropped.** No cap bounds the roster below the
    fleet, so the flag could never be true.
  - `NodeStreamBinding` keeps its JSON shape plus `stream_name`; in Rust
    its state and failure fields moved into a flattened `NodeBindState`,
    which `StreamNodeState` (the status entry) shares.

### D-e. Live counters: this node's, from 12.9's collector

- `StreamMetricsCollector` (12.9 D-e, `lorica-api/src/stream_metrics.rs`)
  gains a typed accessor, `snapshot_for(stream_id) -> Option<StreamLiveCounters>`,
  read from the same aggregate the Prometheus render reads, so the page
  and `/metrics` cannot disagree. The status entry's `counters`:
  `node_name` (`null` on a standalone node), `active` (connections on
  TCP, sessions on UDP, node-exact on UDP as 12.9 reads it), `pending`,
  `accepted_total`, `bytes_upload_total`, `bytes_download_total`, and
  `refused`, `ended`, `datagrams_dropped` as arrays of
  `{ "reason": ..., "count": ... }` with non-zero entries only. Arrays,
  not maps keyed by reason: a map would put reason words in the key-name
  pin of the automation plane (D-f) and every new reason would turn it
  red for nothing. `counters` is `null` before the stream plane reports.
- **Counters are the answering node's**, labelled with its name. On a
  fleet the control plane serves the dashboard and most stream traffic
  is on followers; the page says "traffic on this node" and links the
  stream SLA, which 12.9 D-i fans in fleet-wide. Fleet-wide live
  counters would need the heartbeat to carry per-stream figures, which
  12.2 D-i refused because it grows with the stream count (Resolved
  2).
- **Rates** (connections per second, bytes per second) are computed in
  the browser from two successive samples, 5 s apart as on the System
  page; a sample whose total went down (a restart) shows `-` for one
  interval, never a negative rate. `lib/streams.ts` `ratesBetween(a, b)`,
  tested.
- **Amended by Lot A, against the code** (2026-11-18):
  - The accessor is `StreamMetricsCollector::live_counters()`, every
    stream in one pass (`BTreeMap<String, StreamLiveCounters>`), not
    `snapshot_for(stream_id)`: the status answers every stream, and a
    per-stream call would re-aggregate every series once per stream.
    `render` and the accessor share `counter_totals` and `gauge_values`,
    so the two read one aggregate.
  - `counters` is `null` while the collector holds no series of the
    stream on this node, which is what "before the stream plane reports"
    comes to in the collector's terms.
  - `node_name` is `null` on a control plane too: like a standalone node
    it has no roster row (`get_stream_budget` names it the same way).
  - In Rust `node_name` sits on `StreamStatusCounters`, which flattens
    the collector's `StreamLiveCounters`; `openapi.yaml` documents the
    object as answered, under `StreamLiveCounters`, plus
    `StreamReasonCount`.
  - Until 12.9 Lot F wires the collector in the binary (`apply_worker`,
    `set_local_counters`), a running node holds no series, so `counters`
    is `null` on every stream in production. The endpoint and its tests
    do not depend on that wiring.

### D-f. `streams:read`: the scope, its tier, its two paths

- **The variant**: `AutomationScope::StreamsRead`, serde
  `"streams:read"`, doc comment "Read streams, their bind state per node
  and this node's live counters." The comment above the enum gains a
  paragraph: the scope arrived with Epic 12 for the read tier; there is
  no stream write scope, because a stream is a listener, which the
  `settings:write` definition already keeps off the automation plane, and
  a token has no axis that could confine a listen address or port (PRD
  D9; what it gives up: creating streams from CI).
- `ALL` gains it after `BackendsRead`; `as_str`; `is_grant_bounded`
  answers `false` (no stream read consults a grant).
- **Tier**: `READ.requires` gains it. The config and admin tiers do not
  tolerate it: no config tool needs a stream id. A read-tier token minted
  after 1.11.0 carries it; one minted before does not, and the stream
  tools are simply not registered for it (the registry builds a tool list
  from the token's scopes). No migration adds a grant an operator never
  wrote down (Resolved 3).
- **`GET /automation/v1/streams`** (scope `streams:read`): the management
  list (`list_streams_as`) as the stream views, windowed by `PageQuery`,
  filters `?group=`, `?protocol=tcp|udp`, `?name=` (exact; names are
  unique), each bounded by `AUTOMATION_READ_MAX_FILTER_BYTES`. **No
  value is masked.** `STREAM_WITHHELD_FIELDS` is empty for reasons three
  stories wrote down (12.1 D-10, 12.3 D-q, 12.6 D-m): the CIDR lists and
  the local flag are what a reviewer must see. The two PEM fields
  (`tls_terminate.client_auth`'s and `upstream_tls`'s CA bundles) are
  public CA certificates, which is also why a route's `mtls.ca_cert_pem`
  is not masked (`redact.rs`, "What is not masked"). Every key is added
  to `AUTOMATION_READ_FIELD_NAMES` deliberately, which is the decision
  the pin exists to force.
- **`GET /automation/v1/streams/status`** (scope `streams:read`): the
  entries of D-d, windowed, same filters. It is the one automation read
  that names nodes without `cluster:read`: a stream's bind state per
  node is meaningless without the node, and the docs say that
  `streams:read` reveals the names of the nodes that bind streams.
- **Confinement**: a principal that `carries_grants()` gets an empty page
  on both paths (a stream has no hostname or backend address to match
  `allowed_hostnames` against), the rule 12.9 D-j relies on for stream
  rows. Tested with a `routes:write` + `streams:read` token.
- **No mutation path is declared.** `required_scope` declares GET on the
  two paths only; any other method, or any sub-path, falls on the
  fail-closed default and answers 403 `no_declared_scope` to a token
  holding every scope. That word is already published; no new refusal
  word enters `AUTOMATION_AUDIT_REASONS`.
- **`environment` stays HTTP-only**, held by what exists and pinned by
  two tests: the environment request schema in `openapi-automation.yaml`
  names no stream property (contract test), and an environment write
  body carrying a `streams` key is refused by `deny_unknown_fields`
  (verified at the Lot's start; if the body does not deny unknown
  fields, the Lot stops and reports rather than widening scope). 12.1's
  attachment rule 3 already refuses an environment's backend on a stream.

### D-g. MCP read tools

- `lorica_streams`: `GET /automation/v1/streams`, filters `group`,
  `protocol`, `name`, `paginated: true`, `Kind::Read`, `Tier::Read`.
  Summary: every stream with its listen endpoint, backends, settings and
  this node's bind state; the D6 and D7 flags (`udp.unbounded_responses`,
  a `no_sni` rule, `allow_local_backend`, `drains_on_upgrade`) named so a
  model reads them as flags.
- `lorica_stream_status`: `GET /automation/v1/streams/status`, same
  filters. Summary: bind state on every node a control plane targets and
  this node's live counters.
- Names follow the catalogue's convention (`lorica_routes`,
  `lorica_backends`, `lorica_sla_route`), not `list_streams` /
  `stream_status`.
- Tests in `tools.rs`: both tools exist in the read tier; no tool of any
  tier with `Kind` other than `Read` has a path under `/automation/v1/streams`;
  `every_scope_but_the_environment_pair_has_a_tool` passes unchanged.
- Answers go through `untrusted` like every read: stream names and group
  names are operator-authored text.

### D-h. Audit: every stream mutation, with its origin

The origin is the audit row's actor as it exists (username, role, IP,
user agent): a management session (dashboard or operator API call), an
automation principal (role `automation`, its `audit_identity`), or a
node actor (`cluster`, `stream-plane`). No new column. What changes is
which mutations get a `stream.*` row:

| Path | Today | After |
|---|---|---|
| Management create, update, delete, enable/disable | `stream.create`, `stream.update`, `stream.delete` with before and after | unchanged |
| TOML import (`import_config`) | one `config.import` row, no payload | plus one `stream.create`, `stream.update`, `stream.delete` per stream the import changes, before and after as stream views, actor the importer. The import body carries keys (hence no payload on `config.import`); a stream view carries none (`STREAM_WITHHELD_FIELDS` empty), so its rows can. The changed set is `compute_diff`'s streams entity diff, computed before the import as the preview does |
| Backend delete that cascades out of a stream (management) | `backend.delete` only | plus one `stream.backend_unlinked` per stream that held the backend, target `("stream", id)`, after `{ backend_id, was_backup, rule }`, same actor, written with the backend's row |
| Backend delete by a token (`backends:write`) on a stream's backend | allowed, cascades | **refused**, D-i |
| Follower applying a replicated stream | node rows `stream.bind`/`stream.release` (12.2 D-h) | unchanged: the mutation's row is the operator's on the control plane, the per-node outcome fans in |

- A test walks every write path above and asserts, for each, a chained
  row with the expected action, target and actor role, and that
  `verify` holds the chain afterwards.

### D-i. A token may not remove a backend from a stream (D9)

- `DELETE /automation/v1/backends/{id}` (and `lorica_backend_delete`, and
  its preview) refuses a backend linked to any stream with a 409 naming
  the streams, before `delete_backend_as` is called. A stream's backend
  set is a stream field; D9 keeps every stream write on the management
  plane, and the cascade made one reachable with `backends:write`.
  Modelled on the certificate-delete refusal while a stream names the
  certificate (12.4 D-k).
- **Address updates stay allowed**, as 12.3 decided
  (`ensure_not_moved_under_a_local_stream` is the narrow exception, and
  rule A still refuses a local address). Not reopened here.
- The `lorica_backend_delete` summary and the 409 in
  `openapi-automation.yaml` say so. Accepted as Resolved 1, since
  it narrows what an existing scope can do.

### D-j. The backend page: usage, and portless creation

- **Usage**: a "Used by" column, counts of routes and streams, with a
  popover listing route hostnames and stream names (links to each page).
  Joined in the browser from `GET /api/v1/routes` (`backend_ids`) and
  `GET /api/v1/streams` (`backend_ids`, `backup_backend_ids`, and the
  per-rule lists of a TLS stream). Not a new field on `BackendResponse`:
  that view is also the automation `backends:read` answer, and a token
  with `backends:read` and not `streams:read` must not learn stream
  names through it.
- **The delete confirmation** names the streams that lose the backend
  and says their connections to it drain (12.2 AC #8).
- **UDP-attached backends**: the form says "serves UDP stream X: active
  checks are not available until 1.12.0" and disables the check toggle,
  mirroring 12.1 D-6's refusal instead of letting the save fail.
- **Portless addresses** (handed over by 12.1 Lot 4): the validator moves
  to `lib/backend-address.ts`, `validateBackendAddress(value)` returning
  `{ error } | { portless: boolean }`. It accepts `host:port`,
  `[v6]:port`, and the portless forms 12.1 D-6 stores: a hostname, an
  IPv4 literal, a bracketed IPv6 literal. An unbracketed IPv6 literal
  keeps today's reading (`2001:db8::1` is host `2001:db8:` port 1), as
  the server does. A portless address forces active checks off in the
  form, with the reason ("no port to probe; serves range streams only").
  The server stays the authority on attachment (a portless backend on a
  route or a single-port stream is refused there, naming the object).
  Tests: each form accepted and refused as the server does, with the
  cases 12.1's store tests use.

## Tasks

Lots with hard file allowlists. A Lot touches only its files; two Lots
that share a file are sequential, never parallel, and say so. Every Lot
that runs cargo ends on a tree that passes the gate chain CI runs
(`cargo fmt --all -- --check`, the workspace clippy with `--all-targets
--features lorica/otel -- -D warnings` under `CARGO_BUILD_WARNINGS=deny`,
the CI `cargo test` lines, `cargo audit`), through Docker on Linux. Every
Lot that touches the frontend runs `tsc`, `svelte-check`, ESLint and
Vitest per `.claude/rules/lorica-frontend.md`, with `pnpm-lock.yaml`
untouched (no dependency). No agent runs `git checkout`, `git restore`,
`git stash` or `git reset` in the shared tree. No new dependency.

**Order.** A after 12.9 Lot C2 (the collector), sequential with 12.9 Lot
C1 in either order (`server.rs`, `openapi.yaml`), and after 12.4 Lot F,
12.5 Lot G and 12.6 Lot E (`streams.rs`, `openapi.yaml`). B after A.
**12.9 Lot C3 after B** (its stream-log test needs the scope; this
amends 12.9's order, which put C3 after C1 and D only). C1 after B
(`openapi-automation.yaml`, `tools.rs` are B's first). C2 after C1
(`automation/write.rs` tests reuse C1's helpers). D1 after A, 12.4 Lot F,
12.5 Lot G, 12.6 Lot E and 12.9 Lot H (shared `api.ts`, log and SLA
links). D2 after D1 and 12.6 Lot F. E after D1, parallel with D2. F after
A and D1 (`lib/streams.ts`), parallel with D2 and E. G after B, C2, D2,
E and F. H after B and C2, alone on the machine.

Why B waits for the three API Lots: `AUTOMATION_READ_FIELD_NAMES` pins
every key the stream view carries. Landing B earlier would turn that pin
red in each of 12.4 F, 12.5 G and 12.6 E, none of which has the file in
its allowlist. Waiting costs nothing on the critical path: 12.9 C3 is
not on it (12.9 F already waits for 12.4 E and 12.6 D). A stream field
added after B (Stories 12.13, 12.15) adds its key to the pin in its own
API Lot, deliberately.

### Lot A: stream status and binding names (`lorica-api`) - cargo

Allowlist: `lorica-api/src/streams/status.rs` (new),
`lorica-api/src/streams.rs` (the module line and re-export only),
`lorica-api/src/streams/tests.rs`, `lorica-api/src/cluster/mod.rs`,
`lorica-api/src/cluster/tests.rs`, `lorica-api/src/stream_metrics.rs`
(the accessor only), `lorica-api/src/server.rs` (one route line),
`lorica-api/openapi.yaml`, `lorica-api/tests/openapi_contract.rs` (only
if it lists paths by hand).

- [x] `NodeStreamBinding.stream_name` resolved from the stored streams;
      the per-node state rule factored into one `pub(crate)` function the
      roster and the status share (D-d).
- [x] `StreamMetricsCollector::snapshot_for` and `StreamLiveCounters`
      (D-e), reason arrays with non-zero entries only (built as
      `live_counters`, see D-e's amendment).
- [x] `GET /api/v1/streams/status` (D-d, D-e); `openapi.yaml`:
      `StreamStatus`, `StreamNodeState`, `StreamLiveCounters`,
      `NodeStreamBinding.stream_name`.
- [x] Tests: standalone, follower and control-plane shapes (`nodes`
      present only on a control plane); a node in sync not listing a
      targeted stream reads `bound`, under drift `unknown`, before a
      report absent; a binding for a stream the control plane no longer
      holds has `stream_name: null`; counters equal what the collector
      renders for the same stream; a Viewer session reads the endpoint;
      the contract test green.

### Lot B: the `streams:read` scope, its paths and its MCP tools - cargo and frontend gates

One commit, as the PRD requires.

Allowlist: `lorica-automation-policy/src/scope.rs`,
`lorica-automation-policy/src/tier.rs`,
`lorica-api/src/automation/scope.rs`, `lorica-api/src/automation/read.rs`,
`lorica-api/src/automation/router.rs`,
`lorica-api/src/automation/read/plane_tests.rs`,
`lorica-api/src/automation/tests.rs`,
`lorica-api/src/automation/environments.rs` (tests only, for the
`environment` pin of D-f), `lorica-mcp/src/tools.rs`,
`lorica-api/openapi.yaml` (the scope enum only),
`lorica-api/openapi-automation.yaml`,
`lorica-dashboard/frontend/src/components/settings-tabs/automation-scopes.generated.ts`,
`lorica-dashboard/frontend/src/lib/api.ts` (the `AutomationScope` union
only), `lorica/src/cli_mcp.rs` (only if its blast-radius test names
tools by hand).

- [x] The variant, its doc comment, the enum comment's paragraph,
      `ALL`, `as_str`, `is_grant_bounded` (D-f).
- [x] `READ.requires` gains it; the tier tests and the module comment's
      list of read things.
- [x] `required_scope`: GET on the two paths; the two wrappers in
      `read.rs`; the router lines.
- [x] `AUTOMATION_READ_FIELD_NAMES` gains every key of both answers.
- [x] `lorica_streams`, `lorica_stream_status` (D-g).
- [x] Both OpenAPI documents; the generated fixture rewritten from the
      fixture test's own rendering (tier vectors included), never by
      hand-editing the vectors.
- [x] Tests: a `streams:read` token reads both paths; a token without it
      gets 403 naming `streams:read`; a grant-carrying principal gets an
      empty page; POST, PUT, PATCH, DELETE on `/automation/v1/streams`
      and `/automation/v1/streams/{anything}` answer 403
      `no_declared_scope` to a token holding every scope; the window
      caps hold (`AUTOMATION_READ_MAX_ROWS + 1` streams, an answer over
      the byte budget); no non-read MCP tool has a stream path;
      `resolve` places `streams:read` alone in the read tier and refuses
      it beside `routes:write`; the environment pin; the fixture test,
      the contract test, the Vitest replay of the tier vectors.

### Lot C1: stream rows for imports and backend cascades (`lorica-api`) - cargo

Allowlist: `lorica-api/src/config.rs`, `lorica-api/src/backends.rs`,
`lorica-api/src/streams/tests.rs`, `lorica-api/src/streams/audit_tests.rs`
(new, if `tests.rs` would pass 1,500 lines).

- [x] Import: the streams diff before the import, one row per changed
      stream (D-h; built as the views before and after, see the Lot C1
      notes).
- [x] `delete_backend_as`: `stream.backend_unlinked` per stream holding
      the backend, written with the backend's row (D-h).
- [x] Test: the walk of D-h over every path, chain verified.

### Lot C2: a token cannot unlink a backend from a stream (`lorica-api`, `lorica-mcp`) - cargo

Allowlist: `lorica-api/src/automation/write.rs`,
`lorica-api/src/automation/write/plane_tests.rs`,
`lorica-api/openapi-automation.yaml` (the 409 on backend delete),
`lorica-mcp/src/tools.rs` (the `lorica_backend_delete` summary only).

- [ ] The refusal of D-i, preview and apply alike, the 409 naming every
      stream.
- [ ] Tests: refused with one and with two streams named; allowed once
      the management plane unlinked it; a backend on a route only still
      deletes; the dry run is refused the same way.

### Lot D1: the Streams page, list, badges, status - frontend gates

Allowlist: `lorica-dashboard/frontend/src/routes/Streams.svelte` (new),
`lorica-dashboard/frontend/src/routes/Streams.test.ts` (new),
`lorica-dashboard/frontend/src/routes/Dashboard.svelte` (the loader
line), `lorica-dashboard/frontend/src/components/Nav.svelte` (the entry,
and an icon arm if one is added), `lorica-dashboard/frontend/src/lib/api.ts`
(stream types and calls), `lorica-dashboard/frontend/src/lib/streams.ts`,
`lorica-dashboard/frontend/src/lib/streams.test.ts`.

- [ ] Types for the stream view with every field of 12.1, 12.3, 12.4,
      12.5 and 12.6 as `openapi.yaml` documents them, the requests, the
      status; `listStreams`, `getStream`, `createStream`, `updateStream`,
      `deleteStream`, `getStreamStatus`.
- [ ] The list of D-a, the badges of D-c, the per-node states of D-d,
      counters and rates of D-e, refreshed every 5 s while the page is
      visible.
- [ ] Vitest: every badge kind derived and not derived; the "allowlisted"
      and "acknowledged" suffixes; `ratesBetween` across a reset; a
      Viewer sees no create or save; the failed-bind tooltip; enable and
      disable send `enabled` only; delete says connections drain.

### Lot D2: the stream form - frontend gates

Allowlist: `lorica-dashboard/frontend/src/components/StreamDrawer.svelte`
(new), `lorica-dashboard/frontend/src/components/StreamDrawer.test.ts`
(new), `lorica-dashboard/frontend/src/components/stream-tabs/*.svelte`
(new), `lorica-dashboard/frontend/src/lib/stream-form.ts` (new),
`lorica-dashboard/frontend/src/lib/stream-form.test.ts` (new),
`lorica-dashboard/frontend/src/routes/Streams.svelte` (opening the
drawer only).

- [ ] Tabs and `fieldsFor` of D-b; `fieldTab` routing of server errors.
- [ ] Vitest: for each (protocol, TLS mode) pair, the shown set equals
      the sent set and excludes every field the server refuses for that
      pair; a create with only name, port and one backend sends exactly
      those (the IV1 request, pinned as a fixture the e2e reuses); every
      cap's label carries "per node"; a 400 lands on the right tab; a
      protocol switch sends no `udp` keys of the old protocol.

### Lot E: the backend page - frontend gates

Allowlist: `lorica-dashboard/frontend/src/routes/Backends.svelte`,
`lorica-dashboard/frontend/src/routes/Backends.test.ts`,
`lorica-dashboard/frontend/src/lib/backend-address.ts` (new),
`lorica-dashboard/frontend/src/lib/backend-address.test.ts` (new).
`lib/api.ts` is read, not edited.

- [ ] Usage column and popover, delete confirmation naming streams, the
      UDP-attached hint, the portless address (D-j).
- [ ] Vitest: the join over a route, a TCP stream with a backup, a TLS
      stream's per-rule links; the address cases; checks forced off for a
      portless address.

### Lot F: stream names in the Cluster drawer - frontend gates

Allowlist: `lorica-dashboard/frontend/src/routes/Cluster.svelte`,
`lorica-dashboard/frontend/src/routes/Cluster.test.ts`,
`lorica-dashboard/frontend/src/lib/cluster.ts`,
`lorica-dashboard/frontend/src/lib/streams.ts`,
`lorica-dashboard/frontend/src/lib/streams.test.ts`.

- [ ] `NodeStreamBinding.stream_name` in the type and the join; a
      `null` name reads "not in this configuration" beside the id.
- [ ] Vitest: a binding outside `stream_ports` shows its name.

### Lot G: documentation - no cargo

Allowlist: `docs/streams.md` (a "Managing streams" section: the page,
the form's tabs, the badges and what each means, counters being this
node's), `docs/automation.md` (`streams:read`, both paths, filters,
confinement, no write scope and why, node names revealed, the backend
delete refusal), `docs/mcp.md` (the two tools, the read tier, re-minting
for older read tokens), `docs/architecture/api-design-and-integration.md`
(the scope list line), `CHANGELOG.md` (`[Unreleased]`: Added for the page,
the scope, the tools, the status endpoint; Security for the backend
delete refusal and the import and cascade audit rows; under Changed, re-minting read-tier tokens to gain `streams:read` as an operator action, Resolved 3), `README.md` (the
streams line of the feature list, only if no earlier Lot of this epic
added it).

- [ ] Each document above; every example uses `example.com`, `host01`,
      `192.0.2.10` and `<UUID>` placeholders.

### Lot H: end-to-end, IV1 - Docker e2e

Allowlist: `tests-e2e-docker/test-runner/run-mcp-smoke.sh`,
`tests-e2e-docker/test-runner/mcp-helpers.sh`. LF line endings checked
before the run (a tool-written `.sh` keeps CRLF).

- [ ] A "streams" phase in the MCP smoke: a management session posts the
      Lot D2 fixture body to `POST /api/v1/streams` (the request the
      form sends) on a free high port; `ss -ltn` shows it; a token minted
      by `lorica mcp token create --tier read` reads it on
      `/automation/v1/streams` and `/automation/v1/streams/status` with
      `bind.state` `bound`; the read-tier MCP session lists it through
      `lorica_streams` and `lorica_stream_status`; the config and admin
      tier `tools/list` carry no stream tool; a token holding every
      scope gets 403 `no_declared_scope` on POST, PUT and DELETE of
      `/automation/v1/streams`; `lorica_backend_delete` on the stream's
      backend is refused naming the stream; the audit holds
      `stream.create` with the session's actor and the chain verifies.
- [ ] Run alone on the machine, orphan containers torn down first.

## Dev Notes

### Where to extend, verified on `e275a00e`

- `lorica-automation-policy/src/scope.rs`: the enum comment (the list of
  restatements), `ALL`, `is_grant_bounded`, `as_str`, the tests at the
  file's end. `tier.rs`: `READ`, the module comment, `resolve`.
- `lorica-api/src/automation/read.rs`: `PageQuery`, `page_within`,
  `window_of`, `of_window`, `list_routes` (the model for filtering before
  building views), `AUTOMATION_READ_MAX_FILTER_BYTES`.
  `read/plane_tests.rs`: `AUTOMATION_READ_FIELD_NAMES` and the walk
  derived from the scope matrix. `scope.rs`: `required_scope`, the path
  constants, `the_layer_refuses_an_undeclared_path_for_a_token_holding_every_scope`.
- `lorica-api/src/automation/audit.rs`: `AUTOMATION_AUDIT_REASONS`,
  `is_published_reason`, `NO_DECLARED_SCOPE`.
- `lorica-api/tests/automation_scope_fixture.rs`: the failure message
  says how to regenerate; follow it.
- `lorica-mcp/src/tools.rs`: the `ToolSpec` entries of `lorica_backends`
  and `lorica_routes` (the model), `every_scope_but_the_environment_pair_has_a_tool`.
- `lorica-api/src/cluster/mod.rs`: `stream_ports`, `NodeStreamBinding`,
  `stream_plane_view`, `streams_for_review`, `node_responses`.
- `lorica-api/src/streams.rs`: `list_streams_as`, `StreamResponse`,
  `STREAM_WITHHELD_FIELDS`, the three `_as` writers and their audit
  calls.
- `lorica-api/src/config.rs`: `import_config` (the `config.import` row),
  `import_preview` (the diff call to reuse).
- `lorica-api/src/backends.rs`: `delete_backend_as`.
  `lorica-api/src/automation/write.rs`: `delete_backend`,
  `ensure_not_moved_under_a_local_stream` (the model for a stream
  lookup on a backend id).
- `lorica-api/src/audit.rs`: `AuditContext::new`, `AuditContext::node`,
  `record`.
- Frontend: `routes/Routes.svelte` and `components/RouteDrawer.svelte`
  with `route-tabs/` (the model), `routes/Dashboard.svelte` loader map,
  `components/Nav.svelte` entries, `lib/streams.ts` (`BIND_STATE_BADGE`,
  `streamEndpoint`, `nodeStreamRows`, `unboundCounts`),
  `components/StreamBudget.svelte` (role gating and the 5 s refresh),
  `routes/Backends.svelte` (`ADDRESS_PATTERN`, `validateAddress`).

### Tests per Lot

Listed in each Lot. What no automated test here proves: the visual
rendering in both themes (no browser in the agent environment). The
Streams page, the drawer's six tabs, the badges and the Backends usage
popover need a look in light and dark before the release PR.

### Handed to other stories

- **12.9:** Lot C3 runs after this story's Lot B. Lot H's log and SLA
  URL shapes are what Lot D1 links to.
- **12.11:** the upgrade preview may read `GET /api/v1/streams/status`
  for per-node bound streams instead of building its own join.
- **12.12:** the parity matrix rows for the dashboard, the automation
  read and the MCP read are verified against IV1 (Lot H).
- **12.13:** adds `transparent` to `StreamBadgeKind` with its `switch`
  arm and help, and the field to the Connection tab's `fieldsFor`; its
  API Lot adds the key to `AUTOMATION_READ_FIELD_NAMES`.
- **12.15:** adds `silent_client` the same way, derived from the matcher
  kind, with the allowlist or acknowledgement suffix; its API Lot extends
  the pin.
- **12.2, 12.4, 12.5:** their AC #4, AC #6 and AC #4 dashboard halves are
  checked off when Lot D1 lands.

### The `streams:read` artefact list, corrected (Resolved 6)

The PRD's "Delivery requirements" names the serde rename test,
`AUTOMATION_AUDIT_REASONS`, both OpenAPI documents and
`automation-scopes.generated.ts`. Against the code on `e275a00e`:

- **`AUTOMATION_AUDIT_REASONS` does not move.** It carries no scope
  spelling by design: `is_published_reason` derives scope words from
  `AutomationScope::ALL`, and
  `every_scope_a_403_can_name_is_published_and_every_mcp_reason_too`
  asserts no listed word contains `:`. This story adds no refusal word
  (D-f), so the list is untouched.
- **Four restatements the PRD and the enum's comment do not name**, each
  in Lot B's allowlist: the exhaustive `is_grant_bounded` match
  (`lorica-automation-policy/src/scope.rs`, a compile error until
  placed), the `AutomationScope` string union in
  `lorica-dashboard/frontend/src/lib/api.ts`, the MCP catalogue test
  `every_scope_but_the_environment_pair_has_a_tool`
  (`lorica-mcp/src/tools.rs`, red until a tool carries the scope), and
  the scope list of `docs/architecture/api-design-and-integration.md`
  line 61 (Lot G).
- The rest of the PRD's list holds: the serde rename test is
  `every_scope_round_trips_through_its_exact_wire_string`, the OpenAPI
  documents are held by `lorica-api/tests/openapi_contract.rs`, the
  generated fixture by `lorica-api/tests/automation_scope_fixture.rs`
  (tier vectors included), and the tier partition in `tier.rs`.

### Story 12.9's order is amended (Resolved 7)

12.9 Lot C3 tests that a `logs:read` token without `streams:read` gets
403 on stream logs, so it needs the scope this story's Lot B adds. 12.9
put C3 after its C1 and D only; it now also runs after 12.10 Lot B. B
itself waits for 12.4 Lot F, 12.5 Lot G and 12.6 Lot E so the automation
field pin is written once (see "Order"). This costs nothing on the
critical path: 12.9 Lot F already waits for 12.4 Lot E and 12.6 Lot D.
12.9's story file is not edited by this story; the orchestrator applies
the order.

## Resolved (maintainer, 2026-11-15)

The draft's five open questions, each accepted as recommended, and two
Dev Notes facts recorded on the same review. The decisions above cite
each one as "Resolved N".

1. **A `backends:write` token may not delete a backend a stream uses**
   (D-i): 409 naming the streams, preview and apply alike, on the D9
   reading that a stream's backend set is a stream field. Address
   updates stay allowed as 12.3 decided. What it gives up: a pipeline
   retiring a backend must first have an operator unlink it from its
   streams.
2. **Live counters are the answering node's only** in 1.11.0, labelled
   with its name; the fleet-wide view is the stream SLA 12.9 fans in
   (D-e). Per-stream figures in the heartbeat stay refused (12.2 D-i).
   On a control plane that binds nothing, the page says its counters are
   this node's and links the SLA.
3. **No automatic `streams:read` for existing tokens.** Tokens minted
   from 1.11.0 on carry it; older read-tier tokens do not see the stream
   tools until re-minted. The CHANGELOG states this as an operator
   action, and `docs/mcp.md` says the same (Lot G).
4. **`streams:read` reveals the names of the nodes that bind streams**
   (D-f), documented in `docs/automation.md` (Lot G).
5. **Per-stream audit rows on import, for streams only** (D-h). Routes
   keep the single `config.import` row.
6. **The corrected `streams:read` artefact list** (Dev Notes): no scope
   names in `AUTOMATION_AUDIT_REASONS`, plus the four restatements found
   in the code.
7. **12.9 Lot C3 runs after 12.10 Lot B** (Dev Notes).

## Dev Agent Record

### Debug Log

- Lot A, 2026-11-18, on `a29a12b2`. Gates, `rust:1-bookworm` with
  `CARGO_BUILD_WARNINGS=deny`, on the final tree: `cargo fmt --check`
  and the workspace clippy green; the CI test lines green (3,662
  product, 957 `lorica`, 911 forked, 592 TLS-featured tests).
  `cargo audit` fails on `lettre` 0.11.23 (RUSTSEC-2026-0560 to 0565),
  left to the dependency bump running beside this Lot.
- The first product test run failed once on
  `lorica-stream/tests/tcp_engine.rs`
  `two_thousand_silent_connections_never_pass_the_pending_cap` ("past
  the cap after source 83") while another agent's build shared the
  machine. Not touched by this Lot; five isolated reruns and the full
  rerun passed. Recorded because a pending-cap overshoot under load is
  worth a look by whoever owns 12.6's admission.
- Lot B, 2026-11-18, on `7e66b6be`, with 12.9 Lot C3's stream-log read
  (12.10 Resolved 7). Gates on the final tree: see the Change Log row.
  The generated fixture's tier section was replaced with what
  `the_dashboard_fixture_carries_the_tier_table_and_vectors_rendered_from_the_policy`
  printed, by a script cutting it out of the failure message; the
  scope list was edited by hand, as the fixture's header says.
- Lot C1, 2026-11-18, on `0adaa713`. Gates on the final tree: see the
  Change Log row.

### Completion Notes

- **Lot A, the shared rule.** `cluster::node_bind_state(report, drifted,
  stream_id)` wraps 12.2's `ReportedBindings`; `stream_plane_view` uses
  it for its drift entries, `stream_node_states` for the status. The
  latter is pure over `NodeStreamSight { node, report, drifted }`, so it
  is tested without a live session (a session needs an `RpcEndpoint`,
  which `lorica-api` cannot build without a dependency on
  `lorica-command`); `fleet_stream_states` reads the sessions and the
  drift verdicts (`drift_of`, now shared with `node_responses`) and
  calls it.
- **Binding names.** `stream_plane_view` takes the stored streams' names
  by id; `node_responses` builds that map once per roster.
- **Counters.** `StreamMetricsCollector::live_counters()`;
  `StreamLiveCounters` and `ReasonCount` in `stream_metrics.rs`. The
  status test compares every answered field with what `collect()`
  renders for the same stream, the reasons derived from the rendered
  series rather than listed.
- **Endpoint.** `streams/status.rs`: `stream_statuses(state, collector)`,
  the testable core that Lot B's automation wrapper can call, and
  `get_stream_status`, which reads the process collector. No change to
  `required_role`: the GET default is Viewer.
- **For Lot B:** the status answer's keys are `id`, `name`, `protocol`,
  `bind` (and the `StreamBindState` keys), `nodes` (`node_id`,
  `node_name`, the bind keys), `counters` (`node_name`, `active`,
  `pending`, `accepted_total`, `bytes_upload_total`,
  `bytes_download_total`, `refused`, `ended`, `datagrams_dropped`,
  each entry `reason`, `count`). `openapi.yaml` holds them, and
  `the_published_status_schemas_name_exactly_the_fields_the_status_answers`
  pins the document to the answer.
- **For Lot F:** `NodeStreamBinding.stream_name` is always present,
  `null` for a stream the control plane no longer holds.
- **Outside the allowlist:** none. `openapi_contract.rs` derives the
  paths from `server.rs` and was not touched.
- **Lot B, the scope.** `AutomationScope::StreamsRead` after
  `BackendsRead`, with the no-write-scope paragraph above the enum; the
  enum comment now also names the three restatements it did not
  (`is_grant_bounded`, the `api.ts` union, the MCP catalogue test).
  `READ.requires` carries it; neither other tier tolerates it, which
  `streams_read_is_a_read_tier_scope_and_no_write_tier_tolerates_it`
  pins with `resolve`. `AUTOMATION_AUDIT_REASONS` is untouched, as
  Resolved 6 says.
- **Lot B, the reads.** `list_streams` wraps the management
  `streams::list_streams` (there is no `list_streams_as`; the handler
  takes no actor) and filters its rows by `?group=`, `?protocol=`,
  `?name=` (`StreamsQuery`, exact, each under
  `AUTOMATION_READ_MAX_FILTER_BYTES`, a protocol refused naming the
  `StreamProtocol` words, never the caller's). `stream_status` wraps
  Lot A's `stream_statuses` with the process collector, reading the
  groups from the store since a status entry carries none. Both answer
  an empty page, the store unread, to a principal that
  `carries_grants()`. No value is masked.
- **Lot B, the field pin** gained 83 names, walked on two more streams
  seeded in the plane tests (`with_every_stream_shape`: a UDP stream
  with GeoIP, a terminating TLS stream with both rule kinds, client
  verification and upstream TLS) and on stream log rows. The status's
  `counters` object and a failed bind's fields are not reached by the
  fixture (no collector series, no stream plane in a unit test), so
  their inner keys are pinned by Lot A's
  `the_published_status_schemas_name_exactly_the_fields_the_status_answers`
  against `openapi.yaml`, not by this pin.
- **12.9 Lot C3's stream log, done here.** `GET /automation/v1/stream-logs`
  needs `streams:read` and `logs:read`. The matrix keeps one scope per
  path, `streams:read` (the one an older read token lacks, so it never
  sees the tool), and `scope::companion_scope` names the second;
  `authorize_scope` and the audit layer's `refusal_reason` both read
  it, so the 403 and the row (`automation.request.forbidden:logs:read`)
  name whichever scope is missing. Rejected: a fourth
  `ScopeRequirement` state, which every reader of that type (the
  OpenAPI `x-required-scope`, the MCP one-scope-per-tool pin) would
  have had to learn for one path. `lorica_stream_logs` sits behind
  `streams:read` and its summary names `logs:read`, which
  `every_tool_on_a_path_that_needs_a_second_scope_names_it` derives
  from `companion_scope`. `LogStore::stream_log_rows` reads the rows
  without the match count, which the window never uses.
- **Outside the allowlist:** `lorica-api/src/automation/mod.rs` (the
  `companion_scope` re-export), `automation/audit.rs` (the companion in
  `refusal_reason`), `lorica-api/src/stream_logs.rs` (`stream_log_rows`
  and the shared `newest_rows`), `automation/environments/tests.rs`
  (the environment pins live there, not in `environments.rs`). The
  last three are in 12.9 Lot C3's allowlist or its record. No change
  to `lorica/src/cli_mcp.rs`: its blast-radius test names no tool.
- **Lot C1, the import rows, amended against the code.** D-h names
  `compute_diff`'s streams entity diff as the changed set. That diff
  answers labels (`name (id)`), not ids, and compares the stream row
  alone: a file that only moves a stream's backend links shows in the
  separate `stream_backends` diff, and a stream row compare would give
  it no row although its backend set, a stream field (D-i), changed.
  So `import_config` reads `streams::stream_views` (every stored
  stream's view, by id) before and after `import_to_store`, in the
  store closure that runs both, and `imported_stream_changes` writes
  `stream.create` (only after), `stream.delete` (only before) or
  `stream.update` (both, views differing in anything but `created_at`
  and `updated_at`, the fields the preview's `stream_eq` ignores too).
  The rows follow the `config.import` row, with the importer as actor
  and the views as payloads. The test pins the result against the
  preview: the ids the rows name are exactly the ids of the preview's
  `streams` and `stream_backends` diffs together.
- **Lot C1, the cascade rows.** `delete_backend_as` reads the stream
  links of the backend under the lock that deletes it or marks it
  closing, and after the `backend.delete` row writes one
  `stream.backend_unlinked` per link, target `("stream", id)`, after
  `{ backend_id, was_backup, rule }`. A backend serves a stream through
  one link at most (the store refuses a second rule and a primary that
  is also a backup), so one link is one stream. A backend in normal
  service drains first and its links go with the row when the drain
  ends; the rows are written when the delete is decided, as the
  backend's own row is. A preview writes none.
- **Lot C1, the walk.** `streams/audit_tests.rs` (new, `tests.rs` is
  past 4,000 lines): the import rows and their payloads, the preview
  agreement and a no-op re-import; the cascade rows with a primary and
  a backup link; and D-h's table walked (create, two updates, import,
  cascade, delete), each row's action, target and the admin's role,
  then `verify_audit_chain` holding. The follower row is unchanged and
  not walked; the token's backend delete is Lot C2's.
- **Outside the allowlist (Lot C1):** `lorica-api/src/streams.rs`, the
  `audit_tests` module line and `stream_views`, which reuses the
  private `StreamLinks::by_stream` rather than copying it into
  `config.rs`. `streams/tests.rs` made its `Node` fixture, `tcp` and
  `without_bind` `pub(super)` for the new module.

## File List

- `lorica-api/src/streams/status.rs` (new, Lot A)
- `lorica-api/src/streams.rs` (Lot A, the module line and re-export)
- `lorica-api/src/streams/tests.rs` (Lot A)
- `lorica-api/src/cluster/mod.rs` (Lot A)
- `lorica-api/src/cluster/tests.rs` (Lot A)
- `lorica-api/src/stream_metrics.rs` (Lot A, the accessor)
- `lorica-api/src/server.rs` (Lot A, one route line)
- `lorica-api/openapi.yaml` (Lot A)
- `lorica-automation-policy/src/scope.rs`, `tier.rs` (Lot B)
- `lorica-api/src/automation/scope.rs`, `read.rs`, `router.rs`,
  `audit.rs`, `mod.rs`, `tests.rs`, `read/plane_tests.rs`,
  `environments/tests.rs` (Lot B)
- `lorica-api/src/stream_logs.rs` (Lot B, `stream_log_rows`)
- `lorica-mcp/src/tools.rs` (Lot B)
- `lorica-api/openapi.yaml` (Lot B, the scope enum),
  `lorica-api/openapi-automation.yaml` (Lot B)
- `lorica-dashboard/frontend/src/components/settings-tabs/automation-scopes.generated.ts`,
  `lorica-dashboard/frontend/src/lib/api.ts` (Lot B)
- `lorica-api/src/config.rs`, `lorica-api/src/backends.rs`,
  `lorica-api/src/streams/audit_tests.rs` (new),
  `lorica-api/src/streams/tests.rs` (the fixture's visibility),
  `lorica-api/src/streams.rs` (`stream_views`, the module line) (Lot C1)

## Change Log

| Date | Version | Description | Author |
|---|---|---|---|
| 2026-11-15 | 0.1 | Draft: the Streams page with a drawer covering every stored field and a derived badge map that reserves 12.13's and 12.15's kinds by type rather than by dead code, `GET /api/v1/streams/status` with per-node bind state and this node's live counters, stream names on the fleet view's bindings, the `streams:read` scope with its two automation paths and two MCP read tools in one commit after the field-adding API Lots, per-stream audit rows for imports and backend cascades, the refusal of a token's delete of a stream's backend, the backend page's usage column and portless addresses, IV1 in the MCP smoke, Lots A to H. | Romain G. |
| 2026-11-15 | 0.2 | Maintainer answers folded in as Resolved 1 to 5 (token delete of a stream's backend refused, address updates allowed; this node's counters only; no automatic `streams:read`, re-minting stated in the CHANGELOG as an operator action; node names revealed and documented; per-stream import rows for streams only), plus Resolved 6 (the corrected artefact list) and 7 (12.9 Lot C3 after Lot B) recorded in Dev Notes. Status Draft. | Romain G. |
| 2026-11-18 | 0.3 | Lot A: `GET /api/v1/streams/status` (this node's bind state, per-node states on a control plane, this node's live counters with per-reason arrays), `StreamMetricsCollector::live_counters`, `node_bind_state` shared by the fleet view and the status, `NodeStreamBinding.stream_name`, `openapi.yaml`. D-d and D-e amended against the code (active nodes only, `unknown` before a report, no `nodes_truncated`, one-pass accessor, `node_name` null on a control plane). Status InProgress. | Romain G. |
| 2026-11-18 | 0.4 | Lot B: `streams:read` in the closed scope enum with every restatement in one commit (both OpenAPI documents, the `api.ts` union, the generated fixture and its tier vectors), the read tier carrying it; `GET /automation/v1/streams` and `/automation/v1/streams/status`, filtered, unmasked, empty for a grant-carrying principal; `lorica_streams` and `lorica_stream_status`; with 12.9 Lot C3's `/automation/v1/stream-logs` and `lorica_stream_logs` behind `streams:read` plus `logs:read` through `companion_scope`. Gates on the final tree: the CI chain green (3,678 product, 957 `lorica`, 915 forked, 592 TLS-featured tests), `cargo audit` clean, frontend check, lint and Vitest (878) green. | Romain G. |
| 2026-11-18 | 0.5 | Lot C1: a TOML import writes one `stream.create`, `stream.update` or `stream.delete` row per stream whose view it moved, links included, beside its `config.import` row; a backend delete writes one `stream.backend_unlinked` per stream that linked it, beside `backend.delete`; the D-h walk with the chain verified. D-h's changed set amended against the code (views before and after, pinned equal to the preview's stream and link diffs). Gates on the final tree: the CI chain green (3,682 product, 957 `lorica`, 915 forked, 592 TLS-featured tests), `cargo audit` clean. | Romain G. |
