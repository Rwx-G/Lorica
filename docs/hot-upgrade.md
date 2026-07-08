# Hot binary upgrade

Lorica replaces its own running binary with no dropped connections and no
systemd restart (Story 8.4). The old supervisor hands its listening
sockets to a freshly exec'd new supervisor over a Unix-socket
`SCM_RIGHTS` transfer; both sets of workers accept from the same kernel
sockets during the overlap, so there is always an acceptor and no
connection is lost. The old supervisor then drains its in-flight
connections and exits 0.

This is opt-in: until you configure a signing public key, the upgrade
endpoint rejects every upload.

**Requires multi-process mode.** The handoff hands listening sockets from
the old supervisor to a new one, which only exists when Lorica runs with
worker processes. The packaged systemd unit starts `lorica` with
`--workers auto` (one worker per CPU core) for exactly this reason. In
single-process mode (`--workers 0`) an upload is still verified and staged,
but no live swap happens: the API response's `handoff` field reports
`staged_only`, and the binary takes effect on the next restart.

## Workflow

1. **Sign the new binary.** On an offline or CI signing host, produce a
   detached Ed25519 signature over the new `lorica` executable bytes with
   the release private key. The private key never touches the proxy host.
2. **Upload it.** Either:
   - Dashboard: Settings -> Binary upgrade panel (SuperAdmin only). Pick
     the binary and its signature, review the verification result and the
     current-vs-uploaded version, then Start upgrade. A confirmation
     dialog warns that traffic drains over up to 30s.
   - CLI: `lorica upgrade --binary <path> --signature <path>`.
   Both post a `multipart/form-data` body to
   `POST /api/v1/system/upgrade` (the `binary` part is the raw executable,
   the `signature` part is the 128-hex-char detached signature).
3. **Verify + stage.** The server verifies the signature against the
   configured public key (`verify_strict`, rejecting non-canonical /
   small-order edge cases), then atomically stages the binary at
   `<data_dir>/upgrade/lorica.new` (mode 0755, written to a temp file and
   renamed). A bad signature returns `400` and changes nothing.
4. **Zero-downtime handoff.** The supervisor re-verifies the staged
   binary's SHA-256 against the value computed at stage time (so a file
   swapped in the staging directory between staging and exec is refused),
   then fork+execv's `lorica.new` with the live arguments (reconstructed
   from the running process's CLI) plus `--hot-upgrade`. The new
   supervisor pulls the inherited listeners, spawns its workers, starts
   the management API, then runs the readiness handshake: it resends a
   "ready" datagram to the old supervisor until it gets an ack back. Only
   after the ack does it reassign the systemd MainPID (`sd_notify
   MAINPID=`) and record `lorica_hot_upgrade_total{outcome="completed"}`.
   Deferring the MainPID handover until the old has acked is what keeps a
   lost datagram from stranding systemd on a killed PID.
5. **Drain.** Once it has acked the new process, the old supervisor stops
   its worker monitor, drains in-flight connections on
   `worker_drain_timeout_s` (default 30s), records the drain histogram,
   and exits 0. The new process owns the unit from that point.

## Signature model

- **Algorithm:** Ed25519, detached signature over the raw binary bytes.
- **Public key:** operator-managed. A file at
  `upgrade_signing_pubkey_path` holding the 32-byte verifying key as a
  single 64-hex-character line. A natural location is
  `/etc/lorica/upgrade-signing.pub`. No key is compiled into the binary,
  by design: a development key must never be trusted in production.
- **Private key:** stays offline. It signs releases on a signing host or
  in CI; it is never copied to the proxy.
- **Not GPG:** the binary-upgrade path uses Ed25519 rather than GPG to
  keep verification to a small, audited, dependency-light primitive
  (`ed25519-dalek`) with no keyring, agent, or web-of-trust state on the
  proxy host. The GPG key that signs the `.deb` / `.rpm` packages is a
  separate, distribution-level trust path and is unaffected.

If `upgrade_signing_pubkey_path` is unset or blank, the endpoint returns
`400 "no upgrade signing key configured"` and the running binary is
untouched.

> **Trust boundary (RBAC, Story 8.3).** The upgrade endpoint and the
> `upgrade_signing_pubkey_path` setting are ONE trust unit and must be
> gated to the same role. Whoever can point `upgrade_signing_pubkey_path`
> at a key they control can then upload a binary signed with the matching
> private key. When multi-user RBAC lands (Story 8.3), both
> `POST /api/v1/system/upgrade` and the settings write that changes
> `upgrade_signing_pubkey_path` must be `SuperAdmin`-only; do not gate one
> without the other, or the weaker gate becomes the effective one.

## Rollback

If the new process fails to come up or panics within 10 seconds of being
forked, the upgrade rolls back with zero impact:

- The old supervisor never stopped accepting (the shared listening sockets
  stayed open throughout), so no connection is dropped.
- The failed child is killed and reaped.
- The staged binary is quarantined to
  `<data_dir>/upgrade/lorica.failed.<unix_ts>` for inspection, so a retry
  stages a fresh `lorica.new` and the failed image is preserved.
- The old supervisor resumes its normal control loop and keeps serving.

A drain that overruns its window (stragglers force-killed) records the
`drain_timeout` outcome but is still a completed upgrade, not a rollback.

## Metrics to watch

- `lorica_hot_upgrade_total{outcome="ok"}` - a successful verify + stage.
- `lorica_hot_upgrade_total{outcome="signature_failed"}` - a rejected
  upload (wrong key, tampered binary, or malformed signature).
- `lorica_hot_upgrade_total{outcome="exec_failed"}` - the new process did
  not signal ready in time and the upgrade rolled back.
- `lorica_hot_upgrade_total{outcome="drain_timeout"}` - the handoff
  succeeded but the connection drain overran and stragglers were killed.
- `lorica_hot_upgrade_drain_seconds` - histogram of drain duration; alert
  if it approaches `worker_drain_timeout_s`.

After an upgrade, confirm the new PID is live at `GET /api/v1/system`.

## systemd integration

The packaged unit is configured for the MainPID handover:
`Type=notify` + `NotifyAccess=all` + `KillMode=mixed` +
`TimeoutStopSec=90`. See
[docs/installation.md](installation.md#hot-binary-upgrade) for the per-directive
rationale. When the new process is accepting it sends
`sd_notify READY=1\nMAINPID=<newpid>`, and systemd reassigns the unit's
main PID to the new supervisor while the old one drains and exits 0
(a clean exit code that `Restart=on-failure` correctly ignores).

When `$NOTIFY_SOCKET` is unset (running outside systemd: a manual run or a
plain Docker container) the `sd_notify` step is skipped cleanly and the
handoff still completes; the old supervisor falls back to a liveness-based
readiness check on the new child.

## Docker

The in-container supervisor honours the same handoff. The typical Docker
workflow is still "rebuild the image and `docker compose up -d`", which is
simpler to reason about and keeps the image immutable. For an in-place
swap without recreating the container:

```bash
docker exec lorica lorica upgrade --binary /path/in/container/lorica.new \
  --signature /path/in/container/lorica.new.sig
```

(The first `lorica` is the container name, the second is the `lorica`
binary inside it.)

This requires the binary and its signature to be readable inside the
container (bind-mount or `docker cp` them first), a configured signing
key, and the container running Lorica in multi-process mode
(`--workers auto`), exactly as on a bare-metal install. Outside systemd
there is no `$NOTIFY_SOCKET`, so the MainPID notify is skipped, but the
new-to-old readiness ack handshake still runs (it is independent of
systemd), and the zero-downtime drain is unchanged.

## See also

- [docs/installation.md](installation.md#hot-binary-upgrade) - unit directives and signing setup
- [docs/worker-mode.md](worker-mode.md) - supervisor / worker drain behaviour
- [docs/security.md](security.md) - security posture overview
