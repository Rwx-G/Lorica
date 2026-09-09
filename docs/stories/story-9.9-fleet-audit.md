# Story 9.9: Fleet-Wide Audit Trail

**Epic:** 9 (v1.7.0)
**Status:** Review
**Author:** Romain G.

**Depends on:** Stories 9.3 (node identity), 9.6 (fan-in transport,
node stamping), 9.8 (WORM sink for the origin-side anchor).

## Story

As a compliance-conscious operator,
I want the audit log to answer "who changed what, on which node",
without overstating what that proves,
so that the guarantee shipped in v1.6.0 survives the move to a fleet and
is not misrepresented.

## Acceptance Criteria

1. The security property is stated accurately in the story, in
   `docs/cluster.md` and in any operator-facing text: the chain is an
   unkeyed SHA-256 with no signing key, so the control plane's
   aggregated copy is strictly weaker than each origin node. The
   authoritative anchor remains each node's own `lorica::audit` tracing
   event shipped to a WORM sink via Story 9.8.
2. Fan-in preserves the origin chain verbatim: aggregated rows carry
   `node_id`, `origin_id`, `prev_chain_hash` and `chain_hash` copied
   unchanged through a **separate insert path**, never through
   `insert_audit`.
3. Per-node seals and partitioned verification: a seal per node
   (`retention_seal:<node_id>`) and a verify variant partitioned
   `WHERE node_id = ? ORDER BY origin_id ASC`.
4. Cluster lifecycle operations are audited on both sides: token mint,
   join, activation, certificate issuance and renewal, revocation,
   `cluster leave`, break-glass entry and exit, fleet-wide ban, and
   node-scoped apply, each with operator identity, role, source IP and
   target node.
5. `GET /api/v1/audit` gains a `node` filter (Operator+).
   `GET /api/v1/audit/verify` (SuperAdmin) accepts a node selector and
   reports per node, localising the earliest affected row.
6. A fleet-wide mutation records the operator identity once on the
   control plane and a linked per-node apply outcome.
7. Dashboard audit sub-page gains a node column, node filter, and
   per-node verify results.

## Tasks / Subtasks

- [x] AC #1: `docs/cluster.md` gains "The Fleet's Audit Trail", which
      states plainly that the aggregated copy is strictly weaker than
      each origin node's, that fan-in proves nothing against a
      compromised follower, and that the anchor is each node's own
      `lorica::audit` stream shipped to a write-once sink. The same
      statement is on `/api/v1/audit/verify` in `openapi.yaml` and in
      the dashboard's audit tab, where an operator reads the result.
- [x] AC #2: `insert_fanned_in_audit`, a separate path that writes both
      chain hashes verbatim and recomputes nothing. `insert_audit` now
      reads the LOCAL tail, which it did not: the tests written for the
      separate path caught that the control plane's own chain would
      otherwise have chained off a follower's row.
- [x] AC #3: `retention_seal:<node_id>`, with the local chain keeping
      the exact literal it always had so an upgraded single-node
      database needs no migration. Retention seals every chain in one
      pass. `verify_audit_chain_for` is partitioned and ordered by
      `origin_id` for a fanned-in chain.
- [x] AC #4: the enumeration in the Phase 1 review found nine tenths of
      this already delivered by stories 9.3 to 9.7. The missing tenth,
      the node-scoped apply, is now `cluster.config.apply` on the
      follower, recorded on BOTH outcomes.
- [x] AC #5: `node` on `GET /api/v1/audit` and on
      `GET /api/v1/audit/verify`. The EMPTY string is a real filter
      selecting this node's own rows, so both the store and the client
      compare against `undefined` rather than for truthiness; folding
      the two together would silently widen the query to the fleet.
- [x] AC #6: `cluster.config.apply` is the follower's own row, so it
      fans back up on the next drain. The operator's single record of
      the mutation is on the control plane, and each node's outcome
      arrives beside it, linked by generation and hash.
- [x] AC #7: node column, node filter and per-chain verify results in
      the dashboard's audit tab, all hidden on a standalone install.

## Dev Notes

**AC #1: the codebase is already more honest than the first PRD draft
was.** `lorica-api/src/audit.rs:14-27` states plainly that the chain is
tamper-**evident**, not tamper-proof, that a principal with write access
can recompute a self-consistent forged history, and that an HMAC key was
considered and rejected because on a single host it would live under the
same owner as the database. `compute_chain_hash` (`audit.rs:230-249`) is
an unkeyed SHA-256 over length-prefixed fields; `insert_audit`
(`log_store.rs:828-871`) computes `prev` from the current tail inside the
connection lock; `verify_audit_chain` (`log_store.rs:974-1019`)
recomputes forward.

So the first draft's phrasing, "the control plane can verify each node's
chain without holding that node's signing state", was technically true
(there is no signing state) while implying a property that does not
exist. Against the only attacker that matters here, a compromised
follower, verification proves nothing: the follower streams a
self-consistent forged chain and `verify` reports clean. And an attacker
with write access to the control plane can rewrite one node's rows and
recompute that node's chain forward.

What makes fan-in worth anything is the out-of-band anchor: the
`lorica::audit` tracing event carrying the committed `chain_hash`
(`audit.rs:387-405`), emitted **on the origin node**. That is why AC #2
requires preserving the origin `chain_hash` verbatim, so the aggregated
copy can be compared against what the node itself published. Signed
checkpoints, where each node signs its chain head with its cluster key
so a retroactive rewrite shows as a fork, are the real fix and are
explicitly deferred in the PRD's Out of Scope; this story documents the
limitation rather than hiding it.

**AC #2 and #3: the retention seal exists and works, but does not
compose.** The seal is real and tested: `RETENTION_SEAL_KEY =
"retention_seal"` (`log_store.rs:811`), written before truncation in
`enforce_audit_retention` (`:1027-1078`), consumed as the new genesis by
both `insert_audit` (`:846-848`) and `verify_audit_chain` (`:976-977`),
with tests for the normal and empties-the-table cases (`:1336`, `:1359`).

Three concrete reasons it breaks on an aggregated multi-node copy:

1. `audit_log_meta` is keyed `key TEXT PRIMARY KEY` (`log_store.rs:141`)
   and the code hardcodes the single key. N interleaved chains need N
   seals.
2. `verify_audit_chain` walks the whole table `ORDER BY id ASC`
   (`:980-983`) with one running `expected` hash, so on an aggregated
   table it would chain node A's row 5 to node B's row 6 and report a
   break on the first interleave.
3. `insert_audit` chains off the **global** tail
   (`SELECT chain_hash FROM audit_log ORDER BY id DESC LIMIT 1`,
   `:832-840`). If fan-in rows go through it, the control plane's own
   next audit entry chains off a follower row and corrupts its own
   chain. This is why AC #2 requires a separate insert path, and why
   IV3 asserts it.

**Worker-mode trap.** `LogStore` "only exists in the process that serves
the management API" (`audit.rs:29-31`), and `audit::record` silently
skips persistence when `state.log_store` is `None` (`audit.rs:348-351`).
If a cluster RPC is ever handled in a worker rather than the supervisor,
its audit entries are dropped on the floor with no error. Every
cluster-side audit emission must be pinned to the supervisor process.

**AC #4** covers operations the first draft did not audit at all,
notably break-glass entry and exit (Story 9.4 AC #11) and node
activation (Story 9.3 AC #5).

## Dev Agent Record

### Debug Log

**Phase 1 review.** Every Dev Notes claim re-verified against the tree
before anything was decided. As in Story 9.6, every line number in the
Dev Notes is stale (9.5 through 9.8 landed after this story was
drafted) and every substantive claim held:

- `audit.rs`'s module doc states the chain is tamper-EVIDENT, that a
  principal with write access can produce a self-consistent forged
  history, and that an HMAC key was considered and rejected because on
  a single host it lives under the same owner as the database. The
  external anchor is named as the effective control.
- `insert_audit` chains off the GLOBAL tail
  (`SELECT chain_hash FROM audit_log ORDER BY id DESC LIMIT 1`) inside
  the connection lock, falling back to the seal and then to genesis.
- `verify_audit_chain` walks the whole table `ORDER BY id ASC` with one
  running `expected`.
- `RETENTION_SEAL_KEY` is the literal `"retention_seal"`, and
  `audit_log_meta` is `key TEXT PRIMARY KEY`.
- `record` skips persistence silently when the log store is absent.

So the three reasons the seal does not compose on an aggregated table
are all real, and the requirement for a separate insert path (AC #2) is
correct: fan-in rows through `insert_audit` would make the control
plane's own next entry chain off a follower's row.

**D1 - the migration does not go where the File List says.** The File
List anticipates `lorica-config/src/migrations/`. `audit_log` is not in
the configuration database: it is created in `log_store.rs`'s
`LogStore::open` against `access-log.db`, and that file has no
migrations directory. The pattern it does have is a list of
`ALTER TABLE ... ADD COLUMN` statements applied on open and tolerated
when they fail because the column already exists, used for
`access_logs` and `waf_events`. The node columns follow that pattern,
in that file.

**D2 - AC #4 is nine tenths delivered already, and the story should
say which tenth is missing rather than re-auditing what is audited.**
Verified by enumerating every emission site. Already recorded:

| AC #4 asks for | Emitted as | Where |
|---|---|---|
| token mint | `cluster.token.mint` | control-plane API |
| join | `cluster.node.enroll` | control-plane lifecycle hook |
| activation | `cluster.node.activate` | control-plane API |
| certificate issuance | part of `cluster.node.enroll` | lifecycle hook |
| renewal | `cluster.node.renew` | lifecycle hook |
| revocation | `cluster.node.revoke` | control-plane API |
| `cluster leave` | `cluster.node.leave` | both sides |
| break-glass entry, exit | `cluster.break_glass.open` / `.close` | follower API |
| fleet-wide ban | `cluster.ban.fleet` | control-plane API |

Two more the AC did not ask for are already there and worth keeping:
`cluster.identity.refused` and `cluster.protocol.violation`.

What is genuinely missing is the **node-scoped apply**: nothing records
that a follower applied generation N, on either side. That is also what
AC #6 needs, so the two are one piece of work rather than two.

**D3 - audit rows ride the existing telemetry channel, as a new
repeated field, and are exempt from shedding.** Story 9.6 built a
cursor-drained fan-in with a per-node ingest quota whose verdicts are
`Accept`, `Partial` and `Shed`. Audit rows fit its transport exactly:
they are append-only, they have a monotonic id, and the drain already
runs. They do NOT fit its quota. Shedding an access row loses a line of
traffic; shedding an audit row loses the record of an operator action,
on the one table whose entire purpose is that the record exists. A
compliance feature that silently drops under load is worse than one
that does not exist, because it is believed.

So audit rows are counted against the quota but never dropped by it: a
push whose access and WAF rows are shed still commits its audit rows,
and the wire bound stays (a peer cannot send an unbounded batch), it is
only the load-shedding verdict that does not apply to them. This is a
deliberate asymmetry and the reason is written at the decision site.

**D4 - `node_id` empty means "this node", and that is what keeps a
standalone install unchanged.** A standalone node has no node id to
stamp, and giving one to a clustered node's own rows would mean the
column changes meaning when a node joins a fleet. Empty is the local
row on every install, the fan-in stamps the origin, and the dashboard
renders empty as this node. The column defaults to empty, so the
`ALTER TABLE` is free on an existing database.

`origin_id` is the row id the origin node assigned. It is what makes
the partitioned verify possible (`ORDER BY origin_id ASC` reconstructs
the origin's own order, which the aggregated `id` does not) and what
lets an operator match an aggregated row to the node's own copy.

**D5 - the seal becomes `retention_seal:<node_id>`, and the existing
key is the local one.** Reading the bare `"retention_seal"` key for
local rows keeps every existing database working with no migration and
no special case: local rows are `node_id = ''`, so the key is the
prefix with an empty suffix only if we chose that shape. We do not:
local keeps the exact existing literal, and a fanned-in node uses
`retention_seal:<node_id>`. A reader of `audit_log_meta` on an upgraded
single-node install sees exactly what it saw before.

**D6 - what this story does NOT claim.** Stated here because AC #1 is
about not overstating: the aggregated copy proves internal consistency
of what a node sent, and nothing about authenticity. A compromised
follower streams a self-consistent forged chain and the control plane's
verify reports it clean. The control plane's copy is strictly weaker
than the origin's, and the origin's own tracing event shipped to a WORM
sink remains the anchor. Signed checkpoints are the real fix and are
out of scope by the PRD.

**D7: the audit, and the two ways this would have failed in the
field.**

Three auditors. Two Criticals, both found independently by more than
one of them, both in code this story added, and neither reachable by a
unit test as the fixtures were written. Every finding was verified
against the code before acting on it.

**The acknowledgement froze every cursor on the first shed.**
`insert_fanned_in_audit` returned the rows NEWLY written by its
`INSERT OR IGNORE`, and the drain advances its cursors only when the
acknowledgement matches what it sent. So the first storage-watermark
shed, the first quota verdict or the first push timeout, three
ordinary and designed events, would re-offer the batch, get zero back,
and freeze the access, WAF and audit cursors for the life of the
process. Fan-in stops silently for that node and local retention then
evicts the rows it never shipped, on the one table this story argues
must not lose any. The mistake was conflating two numbers:
deduplication is how idempotency is implemented, it is not an
acceptance signal. The acknowledgement now means the store durably
holds the batch.

Worth noting where the gap was. The store-side test asserted the
dedup, from one side only; neither the drain nor the control-plane
handler has any test, and that is exactly where the defect lived.

**Every fanned-in chain would have verified as broken, forever.** Fan-in
starts at a node's present, not its history, so the first row the
control plane receives names a predecessor it will never hold. Verify
fell back to genesis and reported `prev_hash_mismatch` on that first
row, on every healthy fleet, permanently. The dashboard renders that as
an alert. An operator who sees red on every node stops reading the
panel, which is precisely the failure AC #1 is written against, arriving
by a route AC #1 did not anticipate. The first batch for a chain now
writes an arrival seal from that row's own `prev_chain_hash`.

The tests missed it because `origin_chain` built every fixture from
genesis, which is the one state the drain guarantees will not occur in
production. A fixture that models only the easy case is worse than no
fixture, because it is counted as coverage.

**Also fixed, each a real defect:**

- Audit rows were taken out of the batch BEFORE the quota was computed,
  so a node was charged nothing, while `docs/cluster.md`, the proto
  comment and this story's own D3 all said they were counted. Exempt
  from the shedding VERDICT and exempt from the ACCOUNTING are
  different things and only the first was intended. This was an
  overclaim in the story whose AC #1 is about not overclaiming.
- The eleven peer-supplied strings crossed the decode boundary
  unvalidated, alone among this crate's wire types.
  `telemetry_audit_row_defect` bounds them at the bridge, which matters
  more here than elsewhere because these rows are exempt from shedding
  and retention deletes by a timestamp the sender chose.
- Retention deleted by timestamp while verify walks by `origin_id`, so
  a node whose clock stepped lost a row from the MIDDLE of its chain
  and verify reported tampering caused by a retention pass. A chain is
  now cut as a prefix of its own order.
- A re-enrolled node kept its telemetry cursors under a fresh node id,
  orphaning a chain that could never verify.
- `origin_id` was clamped rather than refused on an out-of-range value,
  and saturated to zero outbound, which is the local-row marker.
- The dashboard's verify button ignored the node filter beside it, and
  the local chain was labelled with a name a follower can enrol under.

**Downgraded or declined on verification.** The worker-mode trap this
story's own Dev Notes name does NOT fire: the cluster runtime starts in
the supervisor, which holds the `LogStore` and threads it to both
planes, so `cluster.config.apply` is persisted in `--workers` mode. The
architecture auditor's recommendation to move `log_store` out under
backlog #52 is declined and recorded on that entry instead: `LogStore`
carries a domain invariant, not a mechanism, and filing an unkeyed hash
chain with a compliance claim under "observability" is the wrong home.

**Raised rather than fixed here:** backlog #72 (a per-node row budget
for fanned-in audit rows, so "never shed" cannot come to mean "never
bounded"), #73 (`/api/v1/audit` inherited a single-node Operator floor
while its data became fleet-wide, to decide with #69), #74 (two
processes can write the local chain concurrently through the CLI).

### Completion Notes

**The test that mattered caught a defect in code I had just written.**
The separate insert path was in place, the fan-in stored chain fields
verbatim, and `insert_audit` still read the table's GLOBAL tail. So the
control plane's own next audit entry would have chained off whichever
follower row arrived last: its chain would have been verifiable by
nothing but that exact aggregate, and would have broken the moment a
fanned-in row was pruned. That is the defect AC #2 exists to prevent,
arriving from the direction the AC does not mention, and the Phase 1
review had named the mechanism without my carrying it through to the
local path.

**What is deliberately weaker than it sounds, and said so everywhere.**
AC #1 is about not overstating, so: the aggregated copy proves the
internal consistency of what a node sent, and nothing about
authenticity. A compromised follower streams a self-consistent forged
chain and verify reports it clean. The control plane's copy is strictly
weaker than each origin's. That sentence is in `docs/cluster.md`, on
the verify endpoint in `openapi.yaml`, and in the dashboard's audit tab
where an operator actually reads the verdict.

**Seven tests, each pinning one property rather than one function:** a
fanned-in row never joins this node's chain; each chain verifies alone;
a re-sent batch stores nothing twice; a row cannot claim to be local; a
tampered row is reported rather than repaired; retention seals every
chain; the drain ships only this node's own rows.

**Not done, and stated rather than left to be discovered.** The
`cluster` e2e profile still does not exist (backlog #66), so this
story's Integration Verification has not run, exactly as 9.2 through
9.7 have not. Nothing here has been exercised against two real nodes.

## File List

Anticipated:

- `lorica-api/src/audit.rs` (node fields, cluster lifecycle events)
- `lorica-api/src/log_store.rs` (separate fan-in insert, per-node seals,
  partitioned verify)
- `lorica-config/src/migrations/` (node columns on `audit_log`,
  `audit_log_meta` keying)
- `lorica-dashboard/frontend/src/routes/Security.svelte` (audit
  sub-page: node column, filter, per-node verify)
- `docs/cluster.md`

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-09-09 | 1.1 | Audit and remediation (D7). Three auditors, two Criticals, both in code this story added and both invisible to its unit tests. The acknowledgement returned newly-written rows rather than rows durably held, so the first ordinary shed would have frozen every one of that node's fan-in cursors permanently and silently. Fanned-in chains had no arrival genesis, so verify would have reported tampering on every healthy fleet, forever, which is the exact failure AC #1 exists to prevent arriving by a route AC #1 did not anticipate. Also fixed: audit rows were not charged to the quota although three documents said they were; the eleven peer-supplied strings crossed the decode boundary unvalidated; retention deleted by timestamp while verify walks by origin id, so a stepped clock read as tampering; a re-enrolled node orphaned its chain; `origin_id` was clamped rather than refused; and the dashboard ignored its own node filter and labelled the local chain with a forgeable name. Three findings raised to the backlog as #72, #73 and #74. Gates: three clippy gates, 609 + 286 + cluster Rust tests, 419 Vitest, all green. | Romain G. |
| 2026-09-09 | 1.0 | Implemented. Audit rows fan in over the Story 9.6 telemetry channel and the aggregated table holds one chain per node: separate insert path writing both hashes verbatim, per-node retention seals, partitioned verify reporting per chain, node filter on the list and the verify endpoints, node column and per-chain results in the dashboard. `insert_audit` was reading the global tail and now reads the local one, a defect the tests for the separate path caught. Audit rows are counted against the ingest quota and exempt from its shedding verdict, because a compliance feature that drops rows silently under load is worse than one that does not exist. AC #4 turned out to be nine tenths delivered by stories 9.3 to 9.7; the missing tenth is the node-scoped apply, now recorded on both outcomes. The security property is stated as it actually is, in the doc, the API contract and the dashboard: the aggregated copy is strictly weaker than each origin node's, and the anchor is each node's own audit stream. Status Review. | Romain G. |
| 2026-08-23 | 0.1 | Story drafted from the revised Epic 9 PRD. Security property restated accurately after the first draft overclaimed fan-in verification; separate insert path and per-node seals added. Status Draft. | Romain G. |
