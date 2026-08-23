# Story 9.9: Fleet-Wide Audit Trail

**Epic:** 9 (v1.7.0)
**Status:** Draft
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

(empty)

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
