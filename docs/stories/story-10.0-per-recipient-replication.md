# Story 10.0: Per-Recipient Replication Payload

**Epic:** [Epic 10 - Conditional Request Capture & CI Automation API (v1.8.0)](../prd/epic-10-v1.8.0.md)
**Status:** Review
**Priority:** P0, first of the cycle
**Author:** Romain G.
**Depends on:** nothing. Blocks Story 10.4, which creates routes through the same replication path.
**Closes:** backlog #56

---

As an operator running a fleet whose edges are not equally trusted,
I want a follower to receive only the configuration it is meant to serve,
so that compromising the least-trusted node does not hand over the routing topology of every other one.

## Problem

The replicated blob is fleet-wide. `node_selector` is evaluated by the RECIPIENT (`apply_replica_tables`, `store/replica.rs`, filtering with `Route::applies_to_node`), so every follower receives and holds, in memory and on the wire, the definition of every other node's routes: upstream addresses, IP allow and deny lists, mTLS configuration and Basic-auth password hashes. `docs/cluster.md` states this plainly today under "Targeting a subset": *"It scopes serving, not disclosure."*

That was an acceptable trade in Story 9.4 on the grounds that the payload carries no secret material, which remains true: private keys and channel credentials travel as `sha256:` digests. It is a worse trade now for two reasons.

First, it was always a disclosure of topology, and topology is what an attacker who has taken an edge wants next. Second, Story 10.4 makes a CI pipeline a writer: review-app routes with their backend addresses will flow through this same blob to every node in the fleet, at the rate a pipeline creates them.

The fix is the one `docs/cluster.md` already names: filter on the **control plane**, per recipient, matching on `node_id` rather than the display name. `cluster_nodes.name` has no UNIQUE constraint and is chosen by the joining node, so a name is not an identity (Story 9.5 decision D3 reached the same conclusion for certificate distribution and resolved the chain to `node_id` at send time).

## What this changes that is not obvious

The control plane currently holds ONE `ConfigVersion` (generation and hash) and every node either matches it or is drifted. Per-recipient payloads end that: two nodes correctly converged on the same generation legitimately hold different bytes, so **the single fleet-wide hash the convergence design rests on becomes per-node**. Everything that compares a hash moves with it: the drift predicate, the applied-generation reporting, the replication round's accounting, and what the dashboard shows.

The generation stays fleet-wide. It is a monotonic counter over configuration changes, not a content digest, and keeping it fleet-wide is what lets "node N is behind" stay a meaningful sentence.

## Acceptance Criteria

1. **The control plane builds one payload per recipient.** For each Active node, `node_selector` is evaluated control-plane side against that node's `node_id`, resolved from `cluster_nodes` at send time, never against the name carried in the selector alone. A route whose selector is empty is fleet-wide and appears in every payload. The recipient keeps applying what it is given; `apply_replica_tables` stops being the place where targeting happens, and its filter becomes a defence-in-depth assertion rather than the mechanism.

2. **Name-to-id resolution is explicit and auditable.** A selector entry naming a node that does not exist, or that matches more than one row, is a configuration error surfaced at write time by the API validator and logged at WARN by the replicator, not silently dropped. Two nodes that have ever carried the same display name must not be able to receive each other's routes: the resolution answers with ids, and an ambiguous name resolves to none of them.

3. **A per-node expected hash.** The control plane records, per node and per generation, the hash of the payload it sent. `ConfigVersion` keeps the fleet generation; the hash it carries becomes the hash of the fleet-wide portion only, and per-node expectations live beside the roster row. Both are persisted, because a control-plane restart must not turn every node into a drift alert.

4. **Drift compares like with like.** `runtime::evaluate_drift` (the single predicate, Story #71) takes the node's expected hash rather than the fleet's. A node reporting the hash of its own payload at the current generation is in sync. This is where a mistake would be loudest, so the story covers it with a test per case: converged, behind by a generation, same generation with the wrong hash, and never-connected.

5. **Two-phase semantics are unchanged.** Prepare still carries a generation, a blob and its hash; a semantic refusal still aborts the round fleet-wide; transport failures still evict and quarantine. What changes is that the blob differs per node, so the round's report names, per node, the hash that node was offered.

6. **The wire format does not move.** The blob is still an opaque byte string with its own hash, so `lorica-cluster/tests/fixtures/wire-corpus-v1.txt` stays green unmodified. If a field must be added, the story stops and the change is taken deliberately, because that corpus is what makes a mixed-version fleet safe.

7. **Mixed-version behaviour is stated and tested.** A 1.7.x follower receives a smaller payload and applies it; it reports the hash of what it applied, which is what the 1.8.0 control plane expects from it. A 1.8.0 follower against a 1.7.x control plane receives the fleet-wide blob, as before. The documented upgrade order (followers first, control plane last) is unchanged, and `docs/cluster.md` says why it still holds.

8. **Cost is bounded and measured.** Building N payloads per round is N canonical encodings where there was one. The story reports the cost at 2, 10 and 50 nodes on the e2e fixture and states the shape (payloads are built once per round, not per Prepare retry, and a node whose payload is byte-identical to the previous generation's is still sent, because the generation is what the follower acknowledges).

9. **`docs/cluster.md` stops describing the old behaviour.** The "Targeting a subset" section currently says the blob is fleet-wide and that the selector scopes serving rather than disclosure. It must say what is true afterwards, including what a follower can still infer: it knows the fleet's generation, and it knows the routes it serves.

10. **The threat model moves with it.** `docs/security/threat-model.md` records that a compromised follower no longer discloses the fleet's routing topology, and what it does still disclose.

## Integration Verification

- **IV1:** In the `cluster` e2e profile, a route selected for `edge-a` only is absent from `edge-b`'s payload on the wire, not merely unapplied. Asserted by inspecting what `edge-b` stores and by the per-node hash the control plane expects from it, so the test cannot pass by the recipient filtering it out after the fact.
- **IV2:** Both followers converge on the same generation with different hashes, and neither reads as drifted on `/cluster/drift` or in the dashboard.
- **IV3:** A control-plane restart mid-fleet does not produce drift alerts: the per-node expected hashes survive it.
- **IV4:** A selector naming a node that does not exist produces a 422 at write time and no silent omission at replication time.
- **IV5:** The frozen wire corpus passes unmodified.

## Tasks

- [x] AC #1/#2: control-plane-side selection, name-to-id resolution with the ambiguity rule, API validator message.
- [x] AC #3: per-node expected hash, DERIVED rather than persisted (see the Debug Log), with the restart path.
- [x] AC #4: `evaluate_drift` takes the expected hash; four tests plus the regression guard.
- [x] AC #5: replication round report carries the per-node hash (`ReplicationReport::offered`).
- [x] AC #6: the wire corpus passes unmodified.
- [x] AC #7: mixed-version tests both ways, in `lorica-cluster/tests/replication.rs`.
- [x] AC #8: the measurement, in the story's Dev Agent Record.
- [x] AC #9/#10: `docs/cluster.md` and the threat model.
- [ ] Gates: the three CI clippy commands with `RUSTFLAGS=-D warnings`, every Rust suite, `cargo audit`, the frontend three if `NodeResponse` moves.

## Dev Notes

### Why this is Story 10.0 and not 10.6

Story 10.4 creates routes from a CI pipeline. Those routes carry backend addresses inside private ranges, they are created at pipeline rate, and they flow through the replication path unchanged. Closing the disclosure after building the automation API on top of it means changing the payload shape under a feature that already depends on it. The cost of doing it first is one ordering constraint; the cost of doing it last is a migration.

### The thing most likely to go wrong

A per-node hash where a fleet-wide one is still assumed. The candidates are the drift pill (now reading the server's verdict, Story #71), the applied-generation column written by `spawn_session_flush`, the replication report, and the `/cluster/status` fleet list. Grep for `config_version` and treat every call site as a question about which hash it means.

### What a follower still learns

Its own routes, the fleet's current generation, and the fact that other generations exist. That is the floor for a node that has to know when it is behind, and the docs should say so rather than implying the payload tells it nothing.

## Dev Agent Record

### Debug Log

**The story's premise about node names was wrong, and the correction is
narrow.** The problem statement says `cluster_nodes.name` has no UNIQUE
constraint. It has one: migration 53, `migrate_cluster_node_name_unique`,
added `idx_cluster_nodes_name` for exactly this reason under Story 9.5
D3, renaming duplicates first so a pre-existing fleet still boots. So the
ambiguity case cannot arise at the current schema head. The rule is kept
anyway, because the resolver models both failures and a database restored
from a pre-53 backup that lost the index would hit it, and because "an
entry that resolves to no single node targets nobody" is one sentence
where "unknown name" and "collided name" would be two. Its coverage is a
unit test that hands the validator a synthetic two-row roster; the
HTTP-level test could not build the state.

The load-bearing property was never name uniqueness anyway: it is that
the resolution happens on the control plane and answers with the
`node_id` the recipient's certificate proves.

**AC #3: derived, not persisted, and that is the better answer.** The
criterion asks for the per-node expected hash to be persisted so a
control-plane restart does not turn every node into a drift alert. It is
not persisted, and the restart still raises nothing. `AcceptedConfig`
holds the accepted generation's `PayloadSource` rather than the bytes it
produced, and recomputes a recipient's cut on demand (memoised per
round). Canonical encoding is deterministic, so the boot seed rebuilds an
identical source from the store and every node's expected hash comes out
the same. Persisting it would have created a second copy of a derivable
fact, which is the exact shape of the drift this cycle has been closing
(the drift pill against `/cluster/drift`, two package managers, two
definitions of ambiguous authority). One source, recomputed, cannot
disagree with itself.

**The consequence that was not in the story: what the control plane
ADVERTISES had to move too.** With a per-node hash, a follower comparing
its applied hash against the fleet hash is behind forever and pulls on
every heartbeat. So the version in every answer addressed to a node is
now that node's expected version: `HelloAck`, `HeartbeatAck` and the
up-to-date `ConfigPullAck`. All three had the peer's identity in scope
already. `OperationalConfig::config_version`, an `Arc<ArcSwap<ConfigVersion>>`,
became `OperationalConfig::accepted: Arc<AcceptedConfig>`, because the
listener now needs a question answered per node rather than a slot read.
That also removes `version_handle`, so there is one way to ask what a
node should be holding.

The fleet hash keeps exactly two jobs: change detection on the reload
path (has anything the fleet replicates changed?) and the header of
`/cluster/drift` and `/cluster/replication`, which is where the fleet is.
Neither is a per-node comparison.

**What was NOT changed.** `apply_replica_tables` still filters on
`node_selector` at the recipient. It is no longer the mechanism, and its
doc comment now says so: it is what makes a 1.8.0 follower work under a
1.7.x control plane, and on a current fleet it is the assertion that the
cut was correct, since a row it removes means the control plane sent
something it should not have.

### The measurement (AC #8)

`per_recipient_encoding_cost_at_fleet_scale` in `lorica-config/src/canonical.rs`,
`#[ignore]` because it is a measurement and not a gate. Fixture per fleet
size N: N nodes with 20 pinned routes each, every pinned route carrying
its own backend, certificate and link, plus 10 fleet-wide routes. Run in
the dev container.

| N | routes | fleet encode (release) | per-recipient total | mean per node | fleet bytes | mean recipient bytes |
|---|--------|------------------------|---------------------|---------------|-------------|----------------------|
| 2 | 50 | 1.14 ms | 1.10 ms | 0.55 ms | 123 718 | 70 968 |
| 10 | 210 | 4.48 ms | 7.82 ms | 0.78 ms | 545 718 | 70 968 |
| 50 | 1010 | 25.28 ms | 96.13 ms | 1.92 ms | 2 663 718 | 71 128 |

Debug figures run about 5x higher and are in the test output; the release
column is the one that describes production.

**The shape is quadratic, and knowingly so.** Each recipient's cut is one
pass over the whole fleet configuration, so the round costs N passes over
a configuration that itself grows with N. At 50 nodes that is 96 ms
against the 25 ms a single fleet-wide encode would cost, for a round that
also performs 50 network round-trips under a per-node deadline measured in
seconds. It is not the term that decides how long a round takes.

Two properties keep it from mattering more than that. The payloads are
built once per round, memoised per node, so a Prepare retry, the Commit
and every convergence pull answered until the next generation reuse the
same bytes. And each recipient's blob stays flat at about 71 KB while the
fleet's grows to 2.6 MB, so the wire and the follower's decode both get
cheaper as the fleet grows, which is the opposite of the old shape and
the reason the 4 MiB frame cap stops being a fleet-size limit.

If N ever does matter, the fix is one pass that buckets routes by
resolved recipient instead of N passes that each filter the whole list.
That is a change inside `restrict_for_recipient` with no effect on
anything around it, which is why it is not being made now.

### Completion Notes

(in progress)

## File List

Anticipated, to be corrected during implementation.

- `lorica-cluster/src/replication.rs`, `roster.rs`, `certs.rs` (the recipient-resolution helper is shared with the key path)
- `lorica-config/src/canonical.rs`, `store/replica.rs`, `store/cluster_replica.rs`
- `lorica-api/src/cluster/runtime.rs`, `cluster/mod.rs`
- `lorica/src/startup/cluster_plane.rs`
- `lorica-cluster/tests/replication.rs`, `tests/wire_corpus.rs` (assertion only)
- `tests-e2e-docker/` cluster profile
- `docs/cluster.md`, `docs/security/threat-model.md`, `docs/backlog.md` (#56), `CHANGELOG.md`

## Change Log

- 2026-09-16: Story drafted from backlog #56 and the `docs/cluster.md` paragraph that states the current behaviour. The per-node hash is identified as the load-bearing consequence: two correctly converged nodes at the same generation legitimately hold different bytes, which ends the single fleet-wide hash the convergence design rests on.
