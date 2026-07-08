# Story 8.4: Hot Binary Upgrade

**Epic:** [Epic 8 - Multi-User RBAC, AI Bot Defense & Zero-Downtime Upgrades (v1.6.0)](../prd/epic-8-v1.6.0.md)
**Status:** Review
**Priority:** P0 (headline)
**Author:** Romain G.

---

As an operator, I want to replace the running `lorica` binary with a newer version without dropping a single in-flight request and without restarting the systemd unit, so that I can ship security patches and minor releases without a maintenance window.

## Acceptance Criteria (from the Epic 8 PRD)

1. CLI subcommand `lorica upgrade --binary <path>` initiates the handoff.
2. Handoff: the old supervisor hands its listening sockets (HTTP, HTTPS, management) to a new supervisor which rebinds from the inherited FDs (same kernel sockets), spawns workers, then signals the old to drain.
3. Old workers drain (no new connections, in-flight complete on the configured worker drain timeout, default 30s).
4. `POST /api/v1/system/upgrade` (multipart binary upload) verifies the signature against the configured signing key, stages `/var/lib/lorica/upgrade/lorica.new`, triggers the handoff.
5. `lorica_hot_upgrade_total{outcome="ok|signature_failed|exec_failed|drain_timeout"}` counter + `lorica_hot_upgrade_drain_seconds` histogram.
6. Rollback: if the new binary fails to bind / start within 10s, the old cancels the drain and resumes; the staged binary is quarantined to `lorica.failed.<ts>`.
7. Dashboard "Binary upgrade" panel (file picker, signature result, current vs uploaded version, Start upgrade + ConfirmDialog).
8. systemd drop-in note: `ExecStart` unchanged; `KillMode=mixed` + `TimeoutStopSec` accommodate the drain.
9. Docker image honours the same handoff.

## Tasks

- [x] AC #4/#5: Ed25519-verified multipart upload + atomic staging + `lorica_hot_upgrade_total` (commit 5925565f).
- [x] AC #1/#2/#3/#6: FD handoff (transfer_fd SCM_RIGHTS), worker drain, 10s rollback, sd_notify, `lorica upgrade --binary` CLI, drain histogram (commit 41010ebf).
- [x] AC #7 + IV3 PID: dashboard Binary upgrade panel + `proxy.pid` on `/api/v1/system` (e156265c, 900d69ce).
- [x] AC #8/#9: systemd `Type=notify` unit + startup sd_notify READY + docs/installation.md + docs/hot-upgrade.md (a927fb66, e32f2010).
- [x] `upgrade_signing_pubkey_path` settable via the settings API (139c5260).
- [x] IV1/IV2/IV3: `hot-upgrade-smoke` e2e, 27 assertions, validated green (e3296097).

## Integration Verification (result)

- IV1 (zero-drop under load): PASS - ~2000 requests across the swap, 0 failed / 0 refused / 0 5xx.
- IV2 (wrong-key rejected): PASS - 400, running binary unaffected.
- IV3 (new PID + e2e): PASS - `proxy.pid` changes and converges; `outcome=ok` counter ticks; 27/27 e2e assertions green on the committed handoff core (no handoff code change was needed once the live swap ran).

## Dev Notes

### Decisions (user-approved deviations from the PRD letter)
- **FD handoff reuses the existing `lorica_core::server::transfer_fd` SCM_RIGHTS Unix-socket transfer**, NOT the PRD's `LORICA_HOT_UPGRADE_FDS` env var. The machinery already existed in the pingora fork (it is pingora's graceful-upgrade mechanism) and is more robust than env-var FD inheritance. The new supervisor receives the SAME kernel listening socket FDs, so during the overlap BOTH processes accept from the same queue and zero connections drop; the old closes its copies only after draining.
- **Signature is Ed25519 (`ed25519-dalek`), not GPG.** No GPG/signing infrastructure existed in the repo; a native Ed25519 verify (operator-managed 32-byte public key at `upgrade_signing_pubkey_path`, 64-hex; releases signed offline with the private key) is minimal, has no external-tool dependency, and avoids a heavy OpenPGP dep tree. No key is compiled in: with none configured the endpoint 400s (opt-in).
- **systemd `Type=notify` + MAINPID handover.** The new supervisor sends `sd_notify READY=1\nMAINPID=<newpid>` so systemd reassigns the unit MainPID (the old then exit(0)s without a restart). `Type=notify` REQUIRES a startup `READY=1` on EVERY boot, so both the supervisor cold path and single-process startup now emit it (no-op when `$NOTIFY_SOCKET` is unset, e.g. Docker). The unit gained `NotifyAccess=all` (the handover comes from the new process), `KillMode=mixed`, `TimeoutStopSec=90`; all hardening directives preserved.

### Honest caveats (validated, not failures)
- The old workers' drain hits the full 30s window and stragglers are force-killed (so `lorica_hot_upgrade_total{outcome="drain_timeout"}` also ticks on a normal upgrade): pingora workers hold idle upstream-keepalive connections and do not self-exit. This is the same `shutdown_all` behavior as a normal shutdown, not a handoff regression; the swap is zero-drop throughout (new workers accept before old stop), the old supervisor just lingers up to 30s post-handoff.
- The `outcome=ok` counter is recorded in the OLD supervisor at stage time and is observable on `/metrics` for the ~30s drain before exit; it cannot be read after the old process is gone (the new registry starts at 0). Correct per-process semantics.
- The sd_notify MAINPID reassignment itself is only exercisable under real systemd; the e2e (Docker, no `$NOTIFY_SOCKET`) validates the FD handoff / drain / rollback / zero-drop, and the payload format is unit-tested. Real-systemd MainPID handover is validated by inspection + the unit `notify_payload` test, NOT by the e2e.
- fork/execv unsafe is isolated in `lorica-worker/src/hot_upgrade.rs` (the crate already forks); the `lorica` binary's new code stays unsafe-free.

### Follow-ups flagged
- A separate WAF-flood vs WAF-critical-rule ban distinction and a manual-ban endpoint (would give `BanReason::Manual` an emitter) are unrelated 8.11 notes.
- The e2e seeds `upgrade_signing_pubkey_path` directly (now also settable via the settings API, fix 139c5260); the dashboard panel can configure it once the operator sets a key.

## File List

- lorica-api/: src/upgrade.rs (new), src/metrics.rs, src/server.rs, src/system.rs, src/settings.rs, src/tests.rs, src/lib.rs, Cargo.toml (ed25519-dalek)
- lorica-config/: src/models/settings.rs, src/store/settings.rs (upgrade_signing_pubkey_path)
- lorica-worker/: src/hot_upgrade.rs (new, fork/execv), src/manager.rs, src/fd_passing.rs, src/lib.rs
- lorica/: src/startup/hot_upgrade.rs (new), src/startup/supervisor.rs, src/startup/single.rs, src/startup/mod.rs, src/cli.rs, src/main.rs
- lorica-core/: src/server/transfer_fd/mod.rs (transfer.sock 0o666 -> 0o600, v1.2 audit L1)
- lorica-dashboard/frontend/: src/components/settings-tabs/BinaryUpgradeTab.svelte (new), src/lib/api.ts, src/routes/Settings.svelte, src/lib/api.test.ts
- dist/lorica.service (Type=notify, --workers auto), dist/build-deb.sh, dist/rpm/lorica.spec
- docs/installation.md (new), docs/hot-upgrade.md (new), docs/security.md
- tests-e2e-docker/: entrypoint-hot-upgrade.sh (new), test-runner/run-hot-upgrade-smoke.sh (new; v1.2 adds the sd_notify MAINPID capture), docker-compose.yml (v1.2 sets NOTIFY_SOCKET on the hot-upgrade service), Dockerfile (+ lorica-metrics COPY), test-runner/Dockerfile, run.sh

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-07-08 | 1.2 | BMad audit remediation ("fix all" from the v1.1 audit). **H1** packaged unit now runs `--workers auto` (multi-process, so the handoff is real); `--workers` is a proper `auto`/`0`/`N` enum; `POST /system/upgrade` returns a `handoff` discriminator (`triggered`/`staged_only`/`trigger_unavailable`) surfaced honestly by the CLI and dashboard. **H2** `fork_exec` pre-builds the null-terminated argv array before fork and calls `libc::execv` (was `nix::execv`, which allocates via `to_exec_array` post-fork); false SAFETY comment corrected. **H3** readiness is now a bidirectional ready/ack handshake (`ack.sock`): the new supervisor resends "ready" until the old acks and reassigns the systemd MAINPID + records `completed` ONLY after the ack; a lost datagram can no longer strand systemd on a killed PID (split-brain closed). **M1** `decode_hex` ASCII-guarded (no panic on multibyte signature input). **M2** child argv derived from the live `Cli` via `Cli::hot_upgrade_argv` (round-trip unit-tested). **M3/M4** metrics split: `ok` = staged, `completed` = handoff done (recorded in the surviving new process), `drain_timeout` documented as informational. **M5** 128 MiB upload no longer `.to_vec()`-copied (kept as `Bytes`). **M7** supervisor re-hashes the staged binary against the stage-time SHA-256 before fork/exec (TOCTOU). **L1** transfer.sock 0o666 -> 0o600 in the fork; **L2** ready.sock/ack.sock chmod 0600 after bind. **L3** signing-key load error is generic (path logged server-side only). **L5** docs docker-exec typo fixed. **L6** FD-transfer task error logged on rollback. **M8** RBAC trust-unit note added to docs/hot-upgrade.md (gate endpoint + `upgrade_signing_pubkey_path` together as SuperAdmin when Story 8.3 lands). **L4** unchanged (accepted deviation). Validated in Docker (toolchain 1.95.0, matching CI): clippy `-D warnings` on the product crates, `cargo build -p lorica`, and unit tests (lorica-api 524, lorica-core 371, lorica-worker 18, lorica bin 39 - all 0 failed); frontend gates svelte-check 0/0 + tsc + lint + vitest 363/363. The `hot-upgrade-smoke` e2e was extended to bind a datagram listener on `$NOTIFY_SOCKET` (set on the hot-upgrade service) and now passes 29/29 (zero-drop: 3648 requests across the swap, 0 failed/refused/5xx; `proxy.pid` 11 -> 239 converged stable; wrong-key rejected; `outcome=ok` ticked; **`sd_notify READY=1` captured and `MAINPID=239` matches the replacement supervisor pid**), reconfirming H2/H3 under the live multi-process swap. The sd_notify emit path (payload, correct new PID, post-ack timing) is now exercised in Docker; only systemd's own MainPID reassignment (its side of the contract, not Lorica's) is out of scope without real systemd. | Romain G. |
| 2026-06-28 | 1.1 | BMad completion audit (AC-completion, security, pentest, architecture+quality). Verdict: machinery sound, 0 critical; the zero-drop invariant, strict Ed25519 verify (no default key), auth/CSRF/loopback, and the 0750/0700 packaging perms (which neutralize local FD-theft + staging TOCTOU) all hold. PENDING REMEDIATION (next session, user approved "fix all"): **H1** the packaged unit ships single-process (no --workers) so the headline feature no-ops while CLI/dashboard claim a handoff happened -> DECISION: ship --workers by default in the unit + add a stage_only/triggered discriminator + honest CLI/dashboard/docs messaging. **H2** `nix::execv` allocates after fork (to_exec_array) from the multi-threaded tokio runtime -> pre-build the argv pointer array before fork + call libc::execv; fix the false SAFETY comment (needs e2e re-validation). **H3** a lost ready datagram causes a false rollback that SIGKILLs a healthy new supervisor that already took the systemd MAINPID (split-brain) -> make ready delivery robust (retry/ack) + do not reassign MAINPID before the old acks (needs e2e re-validation). **M1** decode_hex panics on multibyte UTF-8 in the signature field -> iterate bytes / is_ascii guard. **M2** child argv is a hand-maintained CLI subset (silent config drift) -> derive from the live Cli. **M3/M4** drain_timeout ticks on every upgrade (pingora keepalive workers never self-exit) and ok is recorded at stage not completion -> only record drain_timeout on real force-kill + add a terminal completed outcome (or split stage/handoff metrics). **M5** 128 MiB upload double-copied (.to_vec()) -> drop the copy. **M7** staged binary exec'd without re-verify -> re-hash against the stage-time SHA-256 before fork_exec. **M8** when 8.3 RBAC lands, gate the upgrade endpoint AND upgrade_signing_pubkey_path as one SuperAdmin trust unit (document now). **L1/L2** transfer.sock 0o666 + ready.sock umask -> chmod 0600. **L3** signing-key load error leaks the path -> generic message. **L5** docs/hot-upgrade.md docker exec typo (missing 2nd `lorica`). **L6** serve_task error discarded on rollback -> log it. **L4** AC #7 "uploaded version" shows sha256/size instead (cannot extract a version from a binary blob) - accepted deviation. ALSO decided this session: a follow-up story will make `dpkg -i` / `apt upgrade` use the hot swap instead of systemctl restart, via a root-local (no mgmt-API password) trigger that TRUSTS the dpkg-placed binary (apt/GPG already vetted the package) - NO Ed25519 re-verification on that path - with a systemctl restart fallback; first-install just starts. | Romain G. |
| 2026-06-28 | 1.0 | Story implemented across 11 commits. Ed25519-verified upload + staging; transfer_fd SCM_RIGHTS handoff with shared-FD zero-drop + worker drain + 10s rollback; CLI; dashboard panel + proxy.pid; systemd Type=notify + startup sd_notify READY (gap found and fixed) + docs; upgrade_signing_pubkey_path settable via settings API (gap found and fixed). User-approved deviations: transfer_fd over the PRD env-var; Ed25519 over GPG. hot-upgrade-smoke e2e: 27/27 green, the live multi-process swap validated the committed handoff core with no handoff code change. Caveats: drain hits 30s (pingora keepalive workers, drain_timeout also ticks); sd_notify MAINPID handover validated by inspection + unit test, not the Docker e2e. cargo audit clean (ed25519-dalek tree). | Romain G. |
