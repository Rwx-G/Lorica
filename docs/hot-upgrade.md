# Hot binary upgrade

Lorica replaces its own running binary with no dropped connections and no
systemd restart (Story 8.4). The old supervisor hands its listening
sockets to a freshly exec'd new supervisor over a Unix-socket
`SCM_RIGHTS` transfer; both sets of workers accept from the same kernel
sockets during the overlap, so there is always an acceptor and no
connection is lost. The old supervisor then drains its in-flight
connections for `worker_drain_timeout_s` at most and exits 0.

Since 1.11.0 the same handoff carries the stream listeners (TCP and
UDP, see [docs/streams.md](streams.md)): their ports never close during
an upgrade, and every established stream connection the old generation
still holds is drained, then closed with the end reason
`drained_by_upgrade`. No established connection moves to the new
binary in 1.11.0; live transfer is Phase 2 of Epic 12 (v1.12.0).

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
     current-vs-uploaded version, then Start upgrade. The confirmation
     dialog loads the upgrade preview (below): the drain delay that will
     apply, the streams holding connections and what the upgrade does to
     them, and a warning when an earlier generation is still draining.
     A preview that cannot be read is said in one line and does not
     block the upgrade.
   - CLI: `lorica upgrade --binary <path> --signature <path>` (the admin
     password comes from `--password-file`, `--password-stdin` or
     `LORICA_ADMIN_PASSWORD`). It prints the preview to stderr before it
     uploads, without prompting, so scripts are unchanged; a node too old
     to answer the preview gets a one-line note and the upload anyway.
     `lorica upgrade --preview` prints the preview and exits without
     uploading (no `--binary` needed), and fails if the preview cannot be
     read.
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
   The listening sockets cross on `<data_dir>/upgrade/transfer.sock`. A
   table that holds no stream socket and fits the legacy single message
   (at most 32 descriptors, keys within 2,048 bytes) is sent in it, so a
   node without streams still hands over to a 1.10.x binary. Any other
   table, which every node with a stream bound produces, is sent in
   acknowledged chunks of at most 32 descriptors (`lorica-fds/2`), a
   format a 1.10.x binary refuses (see [Rollback](#rollback)). A
   receiver that meets any framing error closes everything it received
   and fails the pull, and the upgrade rolls back.
5. **Drain.** Once it has acked the new process, the old supervisor
   shuts its cluster planes down, stops its worker monitor and **stops
   serving its management and automation APIs**: the new supervisor
   holds its own copies of those sockets, so every request from then on
   reaches the new binary, and the old one ends its open API
   connections (a response in flight completes, an idle keep-alive
   closes, a log or load-test WebSocket gets a `1001` close). Its health
   loop and its periodic background loops (probe scheduler, SLA flush,
   retention, load-test cron, GeoIP and ASN updaters, blocklist refresh,
   certificate checks, prunes) stop with them; what its draining
   workers still call stays up (their command and RPC channels, the
   log and WAF fan-in, the stream plane, the shared-memory eviction,
   the alert dispatcher). It then reads `worker_drain_timeout_s` once,
   tells every worker to drain for that long (next section), waits for
   them with a 10 s kill margin, collects their drain reports, writes
   the generation's report for the new supervisor, and exits 0. The new
   process owns the unit from the ack on.

## What the drain does

`D` is `worker_drain_timeout_s` (global setting, default 30 s, 1 to
3,600 s; replicated fleet policy), read by the old supervisor at the
handoff. The drain an operator previewed is the one applied, unless the
setting changed in between. Each worker ends as soon as it has no HTTP
request and no stream connection in flight, or at `D`; `D` is a
deadline, not a length.

- **HTTP.** Each old worker stops accepting; requests in flight
  complete. A request still open at `D` is cut when the worker exits.
  HTTP has no end-reason field: the cut requests are counted in the
  drain report (`http_cut`) and in the new supervisor's summary line.
- **TCP streams.** The listening socket is one kernel object both
  generations hold, so a connection belongs for life to the generation
  that accepted it. An old worker closes its own descriptor of each
  stream listener (never `shutdown`, which would stop the new
  generation's accepts too); the port stays open through the new
  generation. Every connection it still holds, in any phase
  (forwarding, connecting, reading a PROXY header or a ClientHello), is
  marked draining with the deadline `D` and closed then with
  `drained_by_upgrade`. A connection that ends on its own keeps its
  natural reason, and one already draining for a configuration change
  keeps `config_removed`. Streams that terminate or originate TLS drain
  the same way.
- **UDP streams.** The slot sockets of each UDP stream are handed to
  the new generation slot by slot, worker `k`'s to worker `k`, so the
  `SO_REUSEPORT` group keeps its size and no client is moved to another
  worker. (If the slot count does not match the new worker count, the
  inherited sockets are closed, a warning names the stream, and a fresh
  group is bound.) The old workers stop reading; what happens to their
  sessions depends on the stream:
  - responses bounded and at least one per request (`relay_in_flight`
    in the preview): a session keeps its upstream socket only to relay
    responses already owed. It ends at its request or response bound
    with that natural reason, otherwise at the earlier of its idle
    timeout and `D`, with `drained_by_upgrade`;
  - `udp.unbounded_responses`, or no response expected
    (`udp.responses_per_request = 0`) (`close` in the preview): every
    session ends at once with `drained_by_upgrade`, since nothing is
    owed and a session kept open would serve one client flow from two
    generations.
- During the drain each generation counts a stream's caps in its own
  shared-memory regions, so a stream may briefly hold up to twice its
  caps on the node.

| Event | End reason of a stream connection it closes |
|---|---|
| Hot upgrade, handoff succeeded | `drained_by_upgrade` |
| Hot upgrade rolled back | none: nothing drains, the old generation never stopped |
| Stop (`systemctl stop`, `SIGTERM`, single-process shutdown) and `systemctl restart` | `node_shutdown` |
| Configuration change that removes a stream, a stream's backend or a listen address | `config_removed` |
| A worker `SIGTERM`ed without the drain message reaching it (degraded path, logged with the worker id) | `node_shutdown` |

Each closed connection writes its stream access-log row with that end
reason, from the old worker. At the deadline an old worker also logs
one warning per stream with the count it closed, and one for the HTTP
requests it cut.

## The upgrade preview

`GET /api/v1/system/upgrade/preview` (management API, SuperAdmin, the
role of the upload itself; never on the automation plane or the MCP
server) answers what an upgrade started now would do on **this node**:

- `drain_timeout_s`: the stored `worker_drain_timeout_s`, the delay
  that will apply;
- `handoff_available`: `false` in single-process mode, where an upload
  is only staged;
- `previous_generation`: `null`, or `{ "pid": ... }` while an earlier
  generation of this node is still draining (see "Chained upgrades");
- `streams`: one entry per stream bound on this node, with its
  `stream_id`, `name`, `protocol`, `established` (open connections on
  TCP, live sessions on UDP, read after the workers' counters are
  pulled), `on_upgrade` (`drain`, `relay_in_flight` or `close`, as
  above) and `drains_on_upgrade` (the stream terminates or originates
  TLS, so the live transfer of Phase 2 will never move it; in 1.11.0
  every stream drains whatever this flag says);
- `as_of`: when the figures were read.

The dashboard's confirmation dialog and `lorica upgrade` show the same
answer. An upgrade is per node, and so is its preview: on a fleet, ask
each node you upgrade.

## The drain report

Each old worker sends its supervisor, before it exits, the counts of
its drain per stream; the old supervisor sums them and writes
`<data_dir>/upgrade/drain-report.<new_pid>.json` (mode 0600, temp file
then rename): both pids, `drain_timeout_s`, the drain's length, how it
ended (`idle`, `deadline`, or `killed` when a worker had to be
`SIGKILL`ed), the workers that sent no report, `http_cut`, and per
stream the connections `closed` by the upgrade and those `finished` on
their own during it. The new supervisor polls for its own report every
second, records the metrics below from it, logs one summary line and
deletes the file. It gives up with a warning when its predecessor is no
longer its parent, or after the longest drain plus the kill margin plus
60 s. A supervisor at start deletes reports addressed to another
process once they are older than that bound.

## Chained upgrades and stops

- **A second upgrade while an earlier generation still drains is
  allowed.** The preview names the draining generation and the
  dashboard warns, but nothing refuses: a security upgrade must not
  wait up to an hour. The cost is a third generation holding its
  connections' descriptors until its own deadline.
- **A stop ends an earlier generation's drain.** The unit's
  `KillMode=mixed` sends `SIGTERM` to the main process, the new
  supervisor, and `SIGKILL`s the rest of the cgroup once it has exited.
  A generation still draining is in that rest: its remaining
  connections are cut without an end reason.
- **A stop on its own** drains for the same `worker_drain_timeout_s`,
  closing what is left with `node_shutdown`, and extends systemd's stop
  timeout while it drains ([docs/installation.md](installation.md#unit-directives-that-make-it-work)).
  The management API stops answering when the stop begins, not when it
  ends.

**From 1.8.0 to 1.9.0.** The CLI pins the certificate the node records
at `<data-dir>/management/served-cert.pem`. A node older than 1.9.0
writes no such record; the 1.9.0 CLI then pins the certificate that
node serves (`management_cert_pem_path` when both override paths are
set, `<data-dir>/management/cert.pem` otherwise) and says so on
stderr, so a 1.8.0 node can be hot-upgraded with the new binary. Run
it as root or as `lorica`: it reads that certificate and the settings
in `lorica.db`. If neither can be read the command refuses and sends
nothing; there is deliberately no fallback that skips the pin, which
would reopen the path by which a local user holding the port received
the password.

The CLI opens that older node's `lorica.db` read-only and runs no
migration in it, whatever version the CLI is: the schema stays the one
the running node knows. It refuses a `lorica.db` or a certificate under
the data directory that is a symbolic link, and a `lorica.db` the data
directory's owner does not own. An operator certificate may sit behind
links (an ACME client's `live/` tree); it is resolved, and pinned only
if the file it resolves to belongs to root or to `lorica` and its group
and others cannot write it.

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
> `upgrade_signing_pubkey_path` setting are ONE trust unit and are gated
> to the same role. Whoever can point `upgrade_signing_pubkey_path` at a
> key they control can then upload a binary signed with the matching
> private key. As of v1.6.0 both `POST /api/v1/system/upgrade` and the
> settings write that changes `upgrade_signing_pubkey_path` are
> `SuperAdmin`-only (enforced by the `authorize` middleware, which gates
> `/api/v1/settings*` and the upgrade endpoint alike), so the weaker gate
> can never become the effective one.

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

A drain that reaches `worker_drain_timeout_s` with traffic still open
records the `drain_timeout` outcome but is still a completed upgrade,
not a rollback.

**Hot-downgrading a node that serves streams is refused.** Uploading an
older binary is an upgrade like any other, but a binary before 1.11.0
has no stream plane, and it files every listener whose key it does not
know with its HTTP listeners: handed a stream's socket, it would serve
HTTP routes on a port opened for a TCP or UDP service. So a table that
holds any stream socket is never sent in the format those binaries
read. It goes chunked, whatever its size, and a 1.8.0 to 1.10.x binary
refuses it before taking any socket: it logs `hot upgrade: failed to
pull inherited listeners; aborting` (`EINVAL`) and exits. The 1.11.0
generation logs that it sent the table chunked and, at the rollback,
why the transfer failed; it counts `exec_failed`, quarantines the
binary, and keeps serving every route and every stream with no request
dropped (the e2e scenario `12.1-ac3-rollback-hot-1.10.7`). To go back
to 1.10.x on a node with streams, disable or delete its streams first
and wait until the upgrade preview lists none (a UDP stream keeps its
sockets while its sessions drain): the table then hands down as
before. Or downgrade by package with a restart.

After a rollback from 1.9.0 to an older binary, or a package downgrade,
`<data-dir>/management/served-cert.pem` stays behind, and the older
node never updates it. If that node then serves another certificate (a
rotation, or a 1.9.0 start that regenerated the self-signed pair before
it was rolled back), the CLI refuses it as it refuses a stranger on the
port: the failure is closed, and the message blames another process.
Delete `served-cert.pem` in that case; the CLI then pins what the older
node serves, as above. A token minted by 1.9.0 is unreadable by 1.8.0.

**From 1.11.0 back to 1.10.7.** The new supervisor runs the database
migrations before it forks its workers, so a 1.11.0 process that is
rolled back has usually already taken `lorica.db` to schema 80, and a
package downgrade always finds it there. 1.10.7 opens that database
and serves HTTP as before. Its migration runner applies nothing above
its own last migration (70), and migrations 71 to 80 are additive by
construction: new tables (the streams, their backend links and their
SLA targets and buckets), nullable or defaulted columns on them and on
`backends` and `cluster_nodes`, and the new stream alert types appended
to the notification channels saved with an explicit type list, which
1.10.7 reads as strings and never raises. No `UNIQUE` index, trigger or
`NOT NULL` column without a default is added to a table 1.10.7 writes,
and no column it knows changes. A test
(`migrations_after_1_10_6_are_additive`) holds every later migration to
that. The access-log database gains a stream log table, created on open
with no numbered migration, which 1.10.7 does not see.

What the rolled-back node does not do:

- **It serves no stream.** The stream rows stay in the database
  untouched, and 1.11.0 finds them again on the next upgrade.
- **It reads a backend's active check from `health_check_path` only**:
  a path is an HTTP check, no path a TCP connect. 1.11.0 keeps writing
  that column beside the typed `health_check` for exactly this case.
  A probe path edited under 1.10.7 is the one 1.11.0 honours when it
  comes back: the typed definition is trusted only while it still
  agrees with `health_check_path`.
- **It probes a protocol check by TCP connect.** A backend with a
  template (`tcp_template`) or a custom send/expect check
  (`tcp_send_expect`) has no `health_check_path`, so 1.10.7 probes it
  by TCP connect: weaker, since a hung backend whose port still accepts
  stays in rotation, and never the other way, since a healthy backend is
  not marked down by it. 1.10.7 never writes the typed column, so the
  check survives the rollback, and 1.11.0 probes with it again on
  re-upgrade, unless a probe path was set under 1.10.7 meanwhile, in
  which case that HTTP check is the one kept.
- **A configuration import run under 1.10.7** deletes every backend,
  which removes the streams' backend links with them; the streams
  remain, without backends. And a 1.11.0 export is refused by 1.10.7,
  which does not know the `health_check` field it carries.

In a fleet, rolling the control plane alone back to 1.10.7 stops
configuration replication until it runs 1.11.0 again; the nodes keep
serving. `docs/cluster.md`, "From 1.10.x to 1.11.0", has the reason
and the upgrade order.

## Metrics to watch

- `lorica_hot_upgrade_total{outcome="ok"}` - a successful verify + stage.
- `lorica_hot_upgrade_total{outcome="completed"}` - the new supervisor
  acked the readiness handshake and took over the systemd MainPID (the
  terminal success of the handoff started by an `ok` verify + stage).
- `lorica_hot_upgrade_total{outcome="signature_failed"}` - a rejected
  upload (wrong key, tampered binary, or malformed signature).
- `lorica_hot_upgrade_total{outcome="exec_failed"}` - the new process did
  not signal ready in time and the upgrade rolled back.
- `lorica_hot_upgrade_total{outcome="drain_timeout"}` - the handoff
  succeeded but the drain reached `worker_drain_timeout_s` with traffic
  still open (or a worker had to be killed). Since 1.11.0 a worker ends
  its drain as soon as nothing is in flight, so this no longer fires on
  idle upstream keep-alives alone.
- `lorica_hot_upgrade_drain_seconds` - histogram of drain duration, with
  buckets up to 3,600 s; alert if it approaches `worker_drain_timeout_s`.
- `lorica_hot_upgrade_stream_connections_total{stream_id, outcome}` -
  per stream, the connections and sessions an upgrade drained:
  `outcome="drained"` counts those it closed with `drained_by_upgrade`,
  `outcome="finished"` those that ended on their own during the drain.
  It counts connections; `lorica_hot_upgrade_total` counts upgrades and
  is unchanged. The label is the stream id, never its name, and a
  deleted stream's series are removed.

The drain metrics are recorded by the **new** process, from the old
generation's drain report, so they appear on the `/metrics` that is
scraped after the upgrade (before 1.11.0 the old process recorded them
just before it exited, and they were lost with it). They appear once
the report has arrived, at the end of the old generation's drain.

After an upgrade, confirm the new PID is live at `GET /api/v1/system`.

## systemd integration

The packaged unit is configured for the MainPID handover:
`Type=notify` + `NotifyAccess=all` + `KillMode=mixed` +
`TimeoutStopSec=90`. An upgrade involves no stop job, so
`TimeoutStopSec` does not bound its drain: the old supervisor bounds it
itself, at `worker_drain_timeout_s` plus a 10 s kill margin. See
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
systemd), and the zero-downtime drain is unchanged. A `docker stop`,
on the other hand, is bounded by Docker, not by the drain: set
`stop_grace_period` above `worker_drain_timeout_s` (the hardening guide,
"The drain on a stop", has the figure).

## See also

- [docs/installation.md](installation.md#hot-binary-upgrade) - unit directives and signing setup
- [docs/worker-mode.md](worker-mode.md) - supervisor / worker drain behaviour
- [docs/streams.md](streams.md) - stream listeners, their end reasons and their upgrade policy
- [docs/security/hardening-guide.md](security/hardening-guide.md) - the drain on a stop, under systemd and Docker
- [docs/security.md](security.md) - security posture overview
