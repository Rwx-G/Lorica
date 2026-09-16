# Story 10.0: Per-Recipient Replication Payload

**Epic:** [Epic 10 - Conditional Request Capture & CI Automation API (v1.8.0)](../prd/epic-10-v1.8.0.md)
**Status:** Draft
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

- [ ] AC #1/#2: control-plane-side selection, name-to-id resolution with the ambiguity rule, API validator message.
- [ ] AC #3: per-node expected hash, persisted next to the roster row, with the restart path.
- [ ] AC #4: `evaluate_drift` takes the expected hash; four tests.
- [ ] AC #5: replication round report carries the per-node hash.
- [ ] AC #6: assert the wire corpus unchanged before anything else lands.
- [ ] AC #7: mixed-version tests both ways.
- [ ] AC #8: the measurement, in the story's Dev Agent Record.
- [ ] AC #9/#10: `docs/cluster.md` and the threat model.
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

(empty)

### Completion Notes

(empty)

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
