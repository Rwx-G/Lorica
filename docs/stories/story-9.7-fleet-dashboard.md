# Story 9.7: Fleet Dashboard

**Epic:** 9 (v1.7.0)
**Status:** Done
**Author:** Romain G.

**Depends on:** Stories 9.3 (registry, tokens), 9.4 (read-only mode,
break-glass, drift), 9.6 (per-node telemetry).

## Story

As an operator,
I want one dashboard that shows the whole fleet,
so that the single control panel promised by the cluster is usable
without curl.

## Acceptance Criteria

1. New "Cluster" page (Viewer+ read, SuperAdmin for mutations): node
   table with name, address, role, status, version, schema version, last
   seen, applied generation and a drift indicator. Registered in the
   existing `routeLoaders` map. Its gzipped chunk stays under 40 KB.
2. Join-token dialog (SuperAdmin): mints a token, shows it once with an
   explicit warning, and displays a command line using `--token-stdin`
   with the secret in a **separate** copy field.
3. Node detail drawer: health, resource gauges, recent WAF events,
   recent bans, applied hash, certificate inventory with expiry,
   activate action for a `Pending` node, and revoke behind the existing
   `ConfirmDialog`.
4. Read-only mode is orthogonal to role: `canWrite` and `isSuperAdmin`
   are derived over `[auth, nodeMode]`.
5. Node filter on Access Logs, Security and SLA, defaulting to all
   nodes, hidden entirely on a standalone install.
6. A cluster badge showing role and active-versus-expected node count,
   in a warning state on drift, on a stale heartbeat, or while
   break-glass is active.
7. A follower renders a persistent read-only banner naming the control
   plane, and a distinct, louder banner while break-glass is active.
8. Frontend gates green: `pnpm exec svelte-check`, `pnpm tsc --noEmit`
   strict, `pnpm lint`. No `any`, no `@ts-ignore`, no `{@html}`.
   Colocated Vitest files for new components.

## Tasks / Subtasks

- [x] AC #1: Cluster page + `routeLoaders` entry + node table with
      name, status, connected, version, schema, applied generation, a
      drift pill and last seen. Chunk measured on a production build:
      `Cluster-*.js` 6072 B gzipped plus `Cluster-*.css` 1367 B, so
      7.4 KB against the 40 KB cap.
- [x] AC #2: token dialog with the `--token-stdin` command line and the
      secret in its own copy field, behind the one-time-display
      warning.
- [x] AC #3: node detail drawer. Health, applied hash, activate behind
      the `selected_for_hostnames` review panel, revoke behind the
      existing `ConfirmDialog`. Certificate inventory is derived from
      the selecting hostnames rather than reported, because nothing
      records what was pushed to whom, and that derivation is the same
      rule the push path applies. Recent WAF events and bans come from
      the 9.6 fan-in endpoints, scoped to the node.

      Resource gauges needed a protocol change: nothing in the cluster
      wire format carried a resource figure. `Heartbeat` gains an
      OPTIONAL `NodeResources` message (D18), so absence stays
      representable and a node with no sampler renders as unknown
      rather than as an idle node at 0%.
- [x] AC #4: `auth.ts` derives `canWrite` / `isSuperAdmin` over
      `[auth, clusterStatus]`; `isSuperAdminRole` keeps the role-only
      view for break-glass and leave. The review pass over every
      consumer IS now done and found four controls hidden from a
      follower that the server still serves; see D19. `canWriteRole`
      is its counterpart for the write actions on the same allow-list.
- [x] Foundation (not an AC, but everything else sits on it):
      `lib/cluster.ts` with the status store, the read-only and
      break-glass predicates, the badge builder and the join-command
      helper, 17 Vitest cases; the six `api.ts` cluster methods.
- [x] AC #5: node filter on Access Logs and Security, hidden entirely
      when standalone. On a control plane both pages read the fan-in
      endpoints and name the origin node in a column; the actions that
      would act on this node's own tables rather than on what is
      displayed (Clear Events, Unban) are absent there rather than
      wired to the wrong target. `category` was threaded through the
      fleet WAF query so the existing filter keeps meaning the same
      thing in both modes instead of quietly filtering one page of
      results. **The SLA leg is deliberately not built**: see D17 in
      the Debug Log. AC #5 as written is therefore short by one page,
      and that is a decision for the user, not a silent omission.
- [x] AC #6: `fleetBadge` in `lib/cluster.ts`, rendered in the
      `Dashboard.svelte` fleet bar. Warns on three distinct conditions
      and names WHICH one in the reason, because "something is wrong
      with the fleet" is not actionable at 03:00: a node the control
      plane expects is not connected, a connected node has not been
      heard from within `STALE_AFTER_MS`, or a break-glass window is
      open.
- [x] AC #7: the follower read-only banner names the control plane and
      says what happens to a local edit; the break-glass banner is
      distinct and louder, and is repeated on the Cluster page itself.
      `breakGlassActive` recomputes from the timestamp rather than
      trusting a boolean, so a window that expires with the tab open
      stops being reported as open without waiting for a poll.
- [x] AC #8: `npm run check`, `npm run lint` and `npx vitest run` all
      green. Colocated Vitest: `lib/cluster.test.ts` (21 cases,
      including `gaugePercent`), `components/NodeFilter.test.ts`, and
      the `fleetQuery` cases in `lib/api.test.ts`. No `any`, no
      `@ts-ignore`, no new `{@html}`.

      Note the gates recorded before 2026-09-09 covered less than they
      claimed: see the Debug Log on the vacuous `tsc --noEmit`.

## Dev Notes

**AC #1: lazy loading is already the house style, not a deliverable.**
`routes/Dashboard.svelte:13-25` is a
`Record<string, () => Promise<...>>` of dynamic `import()`s, one per
page, with stale-chunk reload recovery at `:30-41`, and
`lorica-dashboard/frontend/dist/assets/` confirms one chunk per route.
Adding the Cluster page is one line in an existing map.

The first draft carried a "total gzipped bundle within 15% of the v1.6.0
baseline" criterion. It was dropped as both ambiguous and wrong-target:
the initial payload is ~32.6 KB gz (`index-*.js` 27.2 + `index-client`
0.9 + `index-*.css` 4.6), all JS and CSS chunks sum to ~210 KB gz, and
`world-map-*.svg` alone is ~402 KB gz, so "15% of the bundle" could mean
31 KB or 92 KB. More to the point, because chunks are per-route a
standalone install downloads **zero** bytes of the Cluster chunk
regardless of its size, so the budget constrains something no operator
pays. The one real cost of a larger frontend is binary and `.deb` size:
`lorica-dashboard/src/lib.rs:13-15` embeds `frontend/dist` through
`rust-embed` **uncompressed** (no `compression` feature in
`lorica-dashboard/Cargo.toml`), so ~1.9 MB of assets already sits in the
binary. Hence the per-chunk cap instead.

**AC #2 must not undo Story 9.3 AC #6.** The first draft had the
dashboard display the exact `lorica cluster join --token <value>` command
to paste, which guarantees the token reaches shell history, `/proc`, and
any CI or Ansible log that captures argv. The displayed command uses
`--token-stdin`; the secret goes in its own copy field with the
one-time-display warning.

**AC #4 is one edit plus a review pass, not twenty-seven edits.**
`canWrite` (`lorica-dashboard/frontend/src/lib/auth.ts:19`) and
`isSuperAdmin` (`:25`) are two derived stores over a single `auth`
writable, with 27 import sites across 14 files. Deriving both over
`[auth, nodeMode]` changes one file. But the semantics of `canWrite`
then change for every existing consumer, including the read-like actions
Story 9.4 AC #10 promises stay available on a follower: the log export
in `routes/Logs.svelte:6` and the load-test controls in
`routes/LoadTest.svelte:15` are the two to check first. Those sites need
reviewing even though they need no edit, and the review must match the
API allow-list exactly.

**AC #5**: the filter is driven by the per-node stamping from Story 9.6
AC #1 and the endpoints from 9.6 AC #9. It must be genuinely absent, not
merely disabled, on a standalone install, so the standalone UI is
unchanged.

**AC #3** covers the `Pending` lifecycle from Story 9.3 AC #5. A node
that enrolled but was never activated must be visible and actionable, or
the activation gate becomes a support ticket.

## Dev Agent Record

### Debug Log

**The typecheck gate was vacuous, and it let two broken files through.**

The gate this story had been running was `npx tsc --noEmit` at
`lorica-dashboard/frontend/`, which is what
`.claude/rules/lorica-frontend.md` documented. The root `tsconfig.json`
is `{"files": [], "references": [...]}`, so that invocation type-checks
zero files and exits 0. It is a gate that passes on any input. Bare
`npx svelte-check` has the same defect for `.ts` files: without
`--tsconfig ./tsconfig.app.json` it loads the root project and reports
only on `.svelte` files.

Two commits had already landed on green from it:

- `c516745d` shipped `api.ts` importing `FleetAccessRow`, `FleetWafRow`
  and `FleetBanRow` from `./cluster`. None of the three had been
  written. `tsc -p tsconfig.app.json --noEmit` reports three TS2305.
- `c516745d` also shipped `Cluster.svelte:352`, where `minted.token` is
  read inside a copy handler. The `{#if !minted}` narrowing does not
  reach into a closure, so it is `'minted' is possibly null`.

CI would have caught both: `.github/workflows/ci.yml:34` runs
`npm run check`, which is `svelte-check --tsconfig ./tsconfig.app.json
&& tsc -p tsconfig.node.json`. The hole was in the local recipe and in
the rule file that described it, not in the pipeline. Both are
corrected, and the rule now says why bare `tsc --noEmit` must never be
used here.

Worth stating plainly because it is the same failure this epic's audits
keep finding: a check that reports success without having verified
anything is worse than no check, because it is quoted as evidence.
Every "gates green" line recorded in this story before 2026-09-09
covered less than it claimed.

**D17: AC #5's SLA leg is not built. The filter would filter nothing.**

AC #5 asks for a node filter on Access Logs, Security and SLA. The
first two have fanned-in data; SLA does not. Story 9.6's Phase 1 review
deliberately removed the `sla_buckets` node-id migration from its scope
(`story-9.6-telemetry-fan-in.md`: "AC #1's six migrations become zero
on the hot-path tables"), so the gap sits between the two stories, not
inside this one. Two agents were dispatched on it as the standing
instruction requires, one on published practice and one on the code.
They agree on the mechanics and split on the conclusion; the mechanics
decide it.

What the code says. `sla_buckets` lives in `lorica.db`, not in a
fan-in store, and is written with `INSERT OR REPLACE` on
`UNIQUE(route_id, bucket_start, source)`. The telemetry drain advances
a cursor with `MAX(value, excluded.value)` over a monotonic row id,
which is correct precisely because access rows are never rewritten. A
`REPLACE` in SQLite is a delete plus an insert, so a rewritten bucket
returns above the cursor and is shipped again, and the fan-in ingest is
a plain `INSERT` with no unique key. Shipping buckets down that channel
would therefore accumulate one row per rewrite and over-count every
`SUM(request_count)` by exactly that factor. The active-probe writer
rewrites the open minute on every probe, roughly twelve times a minute
at the five-second floor. Making it correct means a closed-bucket
watermark on the sender and an upsert ingest on the receiver, neither
of which the two existing row kinds use: new mechanism, not a copy of
the access path. Around 35 to 45 edit sites across eight crates, two
new schemas, plus the two pre-existing bugs now filed as backlog #68,
because fanning in known-wrong numbers is worse than not fanning them
in.

What published practice says. Every system that pre-aggregates locally
before shipping converges on the same rule: do not transmit the open
window, hold it behind a watermark and emit once. VictoriaMetrics
vmagent drops the first and last aggregation interval as known
incomplete and, since v1.112.0, buffers two windows specifically
because flushing on the tick was producing incomplete histograms.
Prometheus remote-write, OpenTelemetry delta temporality and Netdata
parent/child avoid the problem entirely by making the shipped unit
immutable, which is what this project's existing row fan-in already
does. That research supports building an SLA fan-in properly, and it
also confirms it is a different pipeline from the one 9.6 built.

What settles it. The only thing a fleet SLA view adds over the
per-node pages is a fleet-wide figure, and the figure cannot be
computed. Percentiles are not additive: p95 of node A and p95 of node B
do not combine into a fleet p95 by any weighting. Correct fleet
percentiles need either the raw latency samples, which
`passive_sla/bucket.rs` discards, or a mergeable sketch per bucket
instead of three scalar columns, which is a schema change to the SLA
model itself and not a clustering feature. Both agents state this
independently.

Deriving the view from the access rows already fanned in was also
examined and does not work: the fan-in table has no `route_id`, only
host and path; the SLA collector deliberately excludes 101s, WAF
blocks, bans, rate limits and connection errors, and no column records
which of those a row was, so the derived numbers would not match the
per-node page an operator can open beside them; and the retention
windows are three orders of magnitude apart, 100 000 rows per node per
kind against 90 days, so at 100 rps the fleet view would cover about
seventeen minutes while the page is built around 1h, 24h, 7d and 30d.

So: Access Logs and Security get the filter. SLA keeps being what it
already is, a per-node view served by whichever node the operator is
looking at, against a target that replication keeps identical fleet
wide. `docs/cluster.md` already names Prometheus federation as the
answer for cross-fleet metrics, and `lorica_sla_*` already feeds it.

AC text is contract and has not been edited. The story ships AC #5
short by one page, deliberately, and this is the item to put in front
of the user: either AC #5 narrows to two pages, or a fleet SLA fan-in
becomes its own story with the closed-bucket watermark, the upsert
ingest and backlog #68 fixed first.

**D18: resource gauges ride the heartbeat, as an optional message.**

AC #3 lists resource gauges and the cluster protocol carried no
resource figure at all: `Heartbeat` had four fields, none of them about
the machine, and the roster row has none either. So the choice was a
new telemetry kind or a change to something that already flows.

The heartbeat, for three reasons. The data is a current value, not a
series, and the heartbeat already carries exactly that kind of field
(`applied_generation`, `applied_hash`, `break_glass`). Its cadence is
already the refresh rate a gauge wants. And the fan-in channel is built
for append-only rows with a cursor and a quota, all of which would be
dead weight for five scalars that are replaced on every beat.

Carried as an optional nested `NodeResources` message rather than as
five scalar fields on `Heartbeat`, and that is the load-bearing choice.
Proto3 scalars have no presence: a node whose runtime installs no
sampler would report zeros, and zero CPU with zero memory reads as an
idle node, not an unknown one. A message field has presence, so absence
survives the wire, `Option<NodeResources>` survives the API, and
`gaugePercent` returns `null` rather than 0 for a total it does not
know. The same rule covers a disk whose size could not be read: a gauge
at zero would say the disk is empty.

Three smaller decisions inside it:

- `FollowerHandler::resources` has a default returning `None`, unlike
  the push handlers Story 9.6 deliberately left without one. The
  asymmetry is the point: a missing push handler silently drops work
  the control plane believes was done, while a missing sampler reports
  nothing and misleads no one.
- The reading is clamped at the decode boundary, not refused. A CPU
  figure above 100 is a wrong number on a dashboard, not a protocol
  violation, and dropping the session over it would let a buggy peer
  take itself offline.
- It lives on the session, not in the store, and a heartbeat that
  carries no reading leaves the previous one in place. A node that
  stops sampling has not become idle, and the staleness an operator
  needs is already on `last_seen`. On reconnect it is re-learned within
  one interval; a figure from before a restart would look live while
  describing a process that no longer runs.

The follower samples through `lorica-api`'s existing `SystemCache` and
`disk_usage_statvfs`, so no new dependency and no second implementation
of the reserved-blocks correction that makes the disk figure match
`df`. The sampler is owned by the follower rather than shared with the
management API's cache, which is refreshed by operator requests that on
a follower may never come.

The disk gauge reports the data directory's filesystem, not the root
one: what fills up on a proxy is where its logs and databases live.

**D19: the AC #4 consumer review found four controls hidden from a
follower that the server still serves.**

Deriving `canWrite` and `isSuperAdmin` over the cluster state is one
edit; the review pass the story flagged as NOT done is where the actual
defects were. The authority is `follower_local_request` in
`lorica-api/src/middleware/authorize.rs`, which lists what a follower
still accepts. Four UI controls map to entries on that list and were
nonetheless hidden:

- **Load-test run and abort.** The allow-list names
  `/api/v1/loadtest/start/` and `/api/v1/loadtest/abort`, and its own
  comment calls them "a probe, not configuration". Editing a test
  config is a genuine configuration mutation and stays on `canWrite`.
- **Configuration export.** `/api/v1/config/export` is on the list. A
  follower handing out its own snapshot is exactly what an operator
  diagnosing drift wants.
- **Audit chain verification.** The `/api/v1/audit` prefix is on the
  list. It reads this node's own records and changes nothing.
- **Users and Access.** `replica.rs` never writes `users`, and the
  `/api/v1/users` prefix is on the list. This is the worst of the four:
  a follower whose only SuperAdmin credential is compromised could not
  rotate it without first opening a break-glass window, which is the
  wrong tool and leaves the node writable meanwhile.

Fixed with `canWriteRole`, the counterpart of the existing
`isSuperAdminRole`: write permission from the role alone. Its doc says
to reach for it only against a path the allow-list actually names, and
each of the four call sites says which.

Two cases were left as they are, deliberately:

- **Import.** `/api/v1/config/import/preview` is allowed on a follower
  but `/api/v1/config/import` is not. Offering a preview that cannot be
  applied is a dead end, so the panel stays hidden.
- **The connectivity probes** in the settings tabs (`otel/test`,
  `syslog/test`, `otlp-logs/test`, and the per-notification and
  per-DNS-provider ones). All are on the allow-list, but each sits
  inside a form whose save is legitimately refused on a follower.
  Splitting the buttons out of four settings tabs to expose a probe
  against a setting you cannot change is not worth the restructuring.
  Worth revisiting if an operator asks for it.

The general lesson, and the reason this is written down: a role
predicate and a node-mode predicate answer different questions, and
collapsing them means every consumer inherits an answer nobody checked
against the server. The server's allow-list is the specification; the
dashboard has to be read against it, not guessed at.

**D20: the audit, and what it found.**

Four auditors (security, quality, architecture, performance) on the
story as it stood at `8615a2e5`. One Critical, four High, eight Medium.
Every finding below was verified against the code before acting on it,
because an auditor can be wrong too; two were downgraded on that
reading and are recorded as such.

**Critical, and it was a comment asserting a safety the code did not
have, again.** The drawer derived its certificate inventory by
intersecting `selected_for_hostnames` with each certificate's subject
names, and said in a doc comment that this "reproduces the same rule
the push path applies". Read side by side, the two resolvers answer
opposite questions about a fleet-wide route:
`hostnames_selecting_node_name` deliberately EXCLUDES an empty
selector, because it answers what approving one NAME would hand over
and a route that entitles everyone is not a per-node decision;
`cert_key_recipients` treats an empty selector as fleet-wide and
entitles every Active node. So a node holding every fleet-wide
certificate was shown as holding none, under the words "it receives no
certificate keys", on the page built to answer exactly that question.
Fixed server-side with `certificates_by_node`, the stated inverse, and
a test that walks every node against every certificate asserting the
two agree in both directions.

**The one only the security auditor found, and the one that matters
most, because this story caused it.** AC #4 hid every mutation control
on a follower. `isSuperAdminRole`'s own doc says it exists "for the
controls that must stay available on a follower: the two that are how
an operator gets OUT of read-only mode (opening a break-glass window,
leaving the fleet)". Neither control existed anywhere in the dashboard,
and `api.ts` had no method for either. Before this story a SuperAdmin
on a follower saw the mutation controls and got a 409 naming the
break-glass endpoint; after it, an operator on an edge whose control
plane is unreachable gets a banner explaining that local edits would be
overwritten, and no way to act. AC #7 shipped the alarm without the
lever. Both controls now exist, gated on the role alone.

That the defect took the form of a doc comment describing call sites
nobody had written, in a doc comment written to explain a fix, is worth
stating plainly: this is the fourth instance of the same class in this
epic.

**Also fixed:** the drawer showed the wrong node's data when two were
opened in quick succession; a failed drawer read rendered identically
to a quiet node; the live tail leaked this node's rows into the fleet
table under an unknown-origin label; `NodeFilter` populated only if the
cluster status happened to arrive before it mounted, and the test
written for it had encoded that early return as intended behaviour;
`clusterStatus` had two writers where `Dashboard.svelte` claims in a
comment to be the only one; the resource sampler ran `sysinfo` and a
`statvfs(2)` inline on the heartbeat's async task, where a stalled
mount could cost the node its session; the CPU gauge's only bound was
in another crate; and the resource gauges sat at the Viewer floor.

**Downgraded on verification.** The architecture auditor rated the
blocking sampler "no change now" while the performance auditor rated it
Medium; the tail-latency argument decides it, because the failure is a
false fleet disconnect caused by a slow disk, and the fix is contained.
The `NodeResources` domain-type duplication was left alone: three lines
and no invariant, per the auditor's own recommendation.

**Raised rather than fixed here**, because each belongs to another
story's acceptance criteria or needs measurement first: backlog #69
(the Viewer floor on fleet telemetry as a whole, to decide with #54 in
one pass rather than one field per story), #70 (the unindexed
`category` filter, `EXPLAIN QUERY PLAN` before indexing), #71 (the
drift pill reimplementing the server's predicate against a column
flushed on a 30 s timer). Recorded on existing entries: #52's stated
trigger has fired, and #59's hazard did not materialise.

**Pinned so it cannot drift back.** The dashboard's four auth
predicates depend on a Rust allow-list nothing cross-checked, and one
manual pass found four controls hidden that the list admits; a test now
asserts every path the dashboard offers on a follower is still
admitted, naming the `.svelte` file on each line and stating in its own
comment which direction it does not catch. `Cluster.svelte` had no
tests at all, which is why both of this story's shipped defects were in
it; it now has six, including the drawer race and the break-glass
controls.

**D21: the roster type was wrong, every test passed, and the first
real fleet showed no node names.**

Found by the first run of the `cluster` e2e profile (backlog #66),
which is the point of having one. `NodeResponse` on the server carries
`#[serde(flatten)]` on its registry row, so the JSON is flat: the
roster columns and the live session facts are siblings. The dashboard's
`ClusterNodeResponse` nested them under `node`, so `Cluster.svelte`
read `n.node.name`, `NodeFilter.svelte` read `n.node.node_id`, and the
audit tab's node names went through the same path. On a real fleet the
Cluster page rendered a table of empty names and the node filter
offered empty options.

Every unit test on those components passed. Their fixtures encoded the
same nested shape, so they were asserting the components against a
response the API never sends. `openapi.yaml` had it right all along;
the type was transcribed from memory rather than from the contract.

Three lessons worth writing down because they are the same lesson the
epic keeps teaching. A fixture that models a shape nobody verified is
counted as coverage and is worth less than none. A unit test cannot
tell you the API's shape; only the API can. And the "gates green" line
this story kept writing covered, once again, less than it claimed: the
real gate for a frontend type is a request against a running server,
which this project now has for the fleet.

### Completion Notes

Every acceptance criterion is implemented except one leg of AC #5, and
that exception is a decision to put to the user rather than a gap to
close quietly.

**What was built.** The Cluster page and its `routeLoaders` entry, the
node table with a drift pill, the join-token dialog on `--token-stdin`
with the secret in its own field, the node drawer with resource gauges,
certificates, recent WAF events and bans, activate behind the
`selected_for_hostnames` review and revoke behind `ConfirmDialog`. Read-
only mode made orthogonal to role and every consumer read against the
server's allow-list. The node filter on Access Logs and Security, with
the fleet endpoints behind them. The header badge and the two banners.

**What needs a decision.** AC #5 names three pages; SLA is not one of
them any more. D17 has the reasoning: there is no fanned-in SLA data,
the mutable-bucket shape does not fit the drain's id cursor, and the
single figure a fleet view would add cannot be computed because
percentiles are not additive. Either AC #5 narrows to two pages, or a
fleet SLA fan-in becomes its own story.

**What this story changed outside the frontend.** AC #3's gauges needed
a protocol addition, so `Heartbeat` now carries an optional
`NodeResources` (D18), and AC #5's category filter needed the fan-in
WAF query to accept one. Both are covered by tests, including the
tag-map test that pins the Rust field numbers to the published proto.

**What it found in other people's code.** A vacuous typecheck gate that
had been reporting success without reading a file, and which had let
two broken files through (Debug Log). Two SLA defects unrelated to this
story, filed as backlog #67 and #68. Four follower-local controls the
AC #4 derivation had hidden (D19).

**Not done, and deliberately so.** The connectivity-probe buttons in
four settings tabs stay hidden on a follower even though the server
allows them, because each sits in a form whose save is refused; see
D19. The `cluster` e2e profile (backlog #66) still does not exist, so
this story, like 9.2 through 9.6, ships on unit and integration tests
without its Integration Verification ever having run.

## File List

Frontend, new:

- `lorica-dashboard/frontend/src/routes/Cluster.svelte`
- `lorica-dashboard/frontend/src/components/NodeFilter.svelte`
- `lorica-dashboard/frontend/src/components/NodeFilter.test.ts`
- `lorica-dashboard/frontend/src/lib/cluster.ts`
- `lorica-dashboard/frontend/src/lib/cluster.test.ts`

Frontend, modified:

- `lorica-dashboard/frontend/src/lib/auth.ts` (node-mode dimension,
  `canWriteRole`)
- `lorica-dashboard/frontend/src/lib/api.ts`, `lib/api.test.ts`
- `lorica-dashboard/frontend/src/routes/Dashboard.svelte`
  (`routeLoaders` entry, poll, fleet bar)
- `lorica-dashboard/frontend/src/routes/{Logs,Security}.svelte`
- `lorica-dashboard/frontend/src/routes/{LoadTest,Settings}.svelte`
  (D19)
- `lorica-dashboard/frontend/src/components/Nav.svelte`
- `lorica-dashboard/frontend/src/components/settings-tabs/ExportImportTab.svelte`
  (D19)

Backend (AC #3's gauges and AC #5's category filter):

- `lorica-cluster/proto/cluster.proto`, `src/messages.rs`,
  `src/bridge.rs`, `src/dialer.rs`, `src/roster.rs`,
  `src/listener/operational.rs`, `src/lib.rs`
- `lorica-cluster/tests/{cluster_plane,enrollment}.rs`
- `lorica-api/src/cluster/mod.rs`, `src/cluster_telemetry_store.rs`,
  `src/system.rs`, `openapi.yaml`
- `lorica/src/startup/cluster_follower.rs`, `src/startup/mod.rs`

Corrected in passing:

- `lorica-config/src/store/replica.rs` (the `sla_buckets` comment)
- `docs/backlog.md` (#67, #68)
- `.claude/rules/lorica-frontend.md` (the real gate; untracked)

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-09-09 | 1.2 | Epic close. The one acceptance criterion knowingly short (AC #5 on SLA, D17) is carried to the epic report for the operator's decision rather than left as a Review blocker; the four epic-wide auditors raised nothing against this story's own surface beyond `STALE_AFTER_MS`'s comment ("three intervals" over a six-interval value; now derived from `HEARTBEAT_INTERVAL_MS` and the badge label reads the constant). Revocation now answers 200 with `certificates_to_reissue` and the page keeps that list on screen until dismissed, because a toast would scroll away before an operator re-issued anything. Status Done. | Romain G. |
| 2026-09-09 | 1.1 | Audit and remediation complete (D20). Four auditors returned one Critical, four High and eight Medium; every finding was verified against the code before acting, two were downgraded on that reading. The Critical was another comment asserting a safety the code did not have: the drawer's certificate inventory omitted every fleet-wide entitlement while claiming to reproduce the push path's rule, so a node holding every fleet-wide certificate was shown as holding none. The most consequential finding is one this story caused: AC #4 hid every mutation control on a follower, including the break-glass and leave controls that `isSuperAdminRole`'s own doc claimed to exist for and which had never been written, so AC #7 shipped an alarm with no lever. Both now exist. Also fixed: the drawer race, swallowed drawer errors, the live-tail leak into the fleet table, `NodeFilter` populating only if the status arrived before it mounted, two writers on the cluster store, the blocking sampler on the heartbeat task, the unbounded CPU gauge, and the resource gauges sitting at the Viewer floor. Pinned: a test cross-checking the dashboard's follower paths against the server allow-list, and six cases on `Cluster.svelte`, which had none and is where both shipped defects were. Raised to the backlog rather than fixed here: #69, #70, #71, plus verification notes on #52 and #59. Gates: `npm run check`, `npm run lint`, 419 Vitest cases, three clippy gates, 599 + 286 + cluster Rust tests, all green. Status stays Review: one acceptance criterion is knowingly short and that is the user's call, not the author's. | Romain G. |
| 2026-09-09 | 1.0 | Story complete and moved to Review. AC #1 (chunk measured at 7.4 KB gz against the 40 KB cap), #2, #3, #4, #6, #7 and #8 done; AC #5 done on Access Logs and Security, and deliberately NOT on SLA (D17: no fanned-in SLA data, the mutable-bucket shape does not fit the drain's id cursor, and a fleet percentile is not computable from minute buckets). Two agents were dispatched on that question as the standing instruction requires. AC #3's resource gauges needed a protocol addition, an OPTIONAL `NodeResources` on `Heartbeat` (D18), so a node with no sampler renders as unknown rather than as idle at 0%. AC #4's review pass found four follower-local controls the derivation had hidden and the server still serves (D19), fixed with `canWriteRole`. Also in this pass: the local typecheck gate was vacuous and had let two broken files through, now corrected along with the rule that described it; and two SLA defects unrelated to this story were found and filed as backlog #67 (a config apply cascade-deletes a follower's SLA history) and #68 (passive SLA is last-writer-wins across workers). Gates: `npm run check`, `npm run lint`, 412 Vitest cases, three clippy gates and the Rust suites all green. | Romain G. |
| 2026-09-09 | 0.2 | Foundation landed: `lib/cluster.ts` (status store, read-only and break-glass predicates, fleet badge, join-command helper) with 17 Vitest cases, the six `api.ts` cluster methods, and AC #4. Read-only mode is now orthogonal to role, so a follower stops offering mutations the control plane would silently undo at the next apply. The Svelte surface (AC #1, #2, #3, #5, #6, #7) was NOT built in that first pass. The reason recorded here initially ("the session ran out of room") was wrong and is corrected: there was ample budget left. The author stopped on a subjective call about quality and wrote it up as a resource limit, which is the same unverified-claim defect this epic keeps finding in comments. `tsc --noEmit` strict and `svelte-check` clean; `pnpm lint` NOT yet run on new components because there are none. Status InProgress. | Romain G. |
| 2026-08-23 | 0.1 | Story drafted from the revised Epic 9 PRD. Bundle-percentage criterion dropped for a per-chunk cap; token dialog reworked to `--token-stdin`. Status Draft. | Romain G. |
