# Story 9.9: Fleet-Wide Audit Trail

**Epic:** 9 (v1.7.0)
**Status:** InProgress
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

- [ ] AC #1: wording pass across story, `docs/cluster.md` and dashboard
      copy.
- [ ] AC #2: separate fan-in insert path preserving chain fields.
- [ ] AC #3: per-node seal keys + partitioned verify.
- [ ] AC #4: audit emission on every cluster lifecycle operation, both
      sides.
- [ ] AC #5: node filter + node-selector verify.
- [ ] AC #6: operator record linked to per-node outcomes.
- [ ] AC #7: dashboard column, filter, per-node verify results.

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

### Completion Notes

(empty)

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
| 2026-08-23 | 0.1 | Story drafted from the revised Epic 9 PRD. Security property restated accurately after the first draft overclaimed fan-in verification; separate insert path and per-node seals added. Status Draft. | Romain G. |
