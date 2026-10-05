# Installation

Lorica ships as a binary plus a hardened systemd unit. The `.deb`
(Debian/Ubuntu) and `.rpm` (Fedora/RHEL) packages install the binary at
`/usr/bin/lorica` and, since v1.9.0, the management MCP server at
`/usr/bin/lorica-mcp`, which no unit starts: an MCP client launches it
over stdio for one session (`docs/mcp.md`). They install the unit at
`/lib/systemd/system/lorica.service` (`.rpm`:
`/usr/lib/systemd/system/lorica.service`), create a dedicated unprivileged
`lorica` user, and own the data directory `/var/lib/lorica`.

## Install from a package

```bash
# Debian / Ubuntu
sudo dpkg -i lorica_<version>_amd64.deb

# Fedora / RHEL
sudo rpm -i lorica-<version>-1.x86_64.rpm
```

On a first install the post-install hook enables and starts the service.
An upgrade keeps the state you left it in: it never enables the
service, and restarts it only if it was running. The one hop it cannot
read is from a `.deb` of 1.8.0 or earlier, whose removal script
stopped and disabled the service without recording anything: since
1.9.1 that upgrade enables and starts it, as every upgrade between
those releases did, unless the ownership repair below holds it. (The
`.rpm` reads the state before the old package's scripts run, so an
upgrade from any `.rpm` keeps it.) Lorica listens on
8080 (HTTP proxy), 8443 (HTTPS proxy), and 9443 (dashboard, localhost
only). The initial admin password is written to
`/var/lib/lorica/initial-admin-password` (mode 0600).

Two further listeners exist and neither opens unless you ask for it on
the command line. `--cluster-listen` (v1.7.0) serves the fleet's control
plane, 9444 and 9445 by convention, and only a control plane needs it:
followers dial out and expose nothing. `--automation-listen` (v1.8.0)
serves the CI automation API, 9446 by convention, and refuses to open
until `automation_allowed_cidrs` names the sources allowed to reach it.
See `docs/cluster.md` and `docs/automation.md`; both surfaces are
covered by `docs/security/hardening-guide.md`.

The management plane on 9443 is served over TLS. On first boot Lorica
generates a self-signed certificate (SANs `localhost`, the machine
hostname, `127.0.0.1`, `::1`) under `/var/lib/lorica/management/` and
auto-rotates it 30 days before expiry, so browsers show a
self-signed-certificate warning that you accept once. To present your own
certificate instead (for example when fronting the dashboard behind a
reverse proxy that forwards TLS), set `management_cert_pem_path` and
`management_key_pem_path` in Settings; when both are set the self-signed
certificate is not used.

Customize ports, worker count, or log level via a drop-in override rather
than editing the packaged unit (the unit is owned by the package and is
replaced on upgrade):

```bash
sudo systemctl edit lorica
```

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/lorica --data-dir /var/lib/lorica \
  --http-port 80 --https-port 443 --management-port 9443 \
  --workers 4 --log-level info
```

```bash
sudo systemctl restart lorica
```

`--log-level` sets the level the process starts with. Once the
configuration store is open, the log level saved in Settings replaces
it in every Lorica process, the supervisor and each worker, and a
change saved there applies without a restart. `RUST_LOG`, when set,
takes precedence over both and is never replaced.

## Upgrading a .deb from 1.8.0 or earlier

Every .deb up to 1.8.0 recorded the CI build account (`runner`, uid
1001) as the owner of its files, so on every host upgraded from one of
them some shipped paths, at least `/usr/share/doc/lorica`, are left
owned by that uid. The upgrade resets them to root. What it does next
depends on whether anyone could have written them:

- No local account has their previous owner's uid (the usual case: no
  `runner` account and nothing at uid 1001). Nobody could have changed
  them; the repair is silent, and the service is enabled and started.
- A local account has that uid, such as a `runner` account on a
  self-hosted CI machine. That account could have changed them or
  planted units, drop-ins or generators beside them, so Lorica is left
  stopped and the upgrade names the paths it repaired and the account.
  Run `dpkg --verify lorica`, inspect the listed directories and
  `/etc/systemd/system`, then
  `systemctl daemon-reload && systemctl enable --now lorica`.

The 1.9.0 package held the service in both cases, so every host
upgraded from 1.8.0 or earlier straight to 1.9.0 was left stopped and
disabled. On such a host, run `sudo dpkg --verify lorica` (no output:
the files are as shipped), then
`sudo systemctl daemon-reload && sudo systemctl enable --now lorica`.
Upgrading it to 1.9.1 first does not start it: 1.9.0 recorded the
service as stopped, and an upgrade from 1.9.0 keeps that state.

## systemd unit

The packaged unit is hardened against the sandbox checklist in
`.claude/rules/lorica-systemd.md` (target `systemd-analyze security`
exposure score under 2.0). It runs as the `lorica` user with only
`CAP_NET_BIND_SERVICE`, `ProtectSystem=strict`, `MemoryDenyWriteExecute=yes`,
a `@system-service` syscall filter, and a narrow `RestrictAddressFamilies`
set. The single writable path is `/var/lib/lorica`.

## Hot binary upgrade

Lorica can replace its running binary with no dropped connections and no
unit restart (Story 8.4). The packaged unit is already configured for it;
the operator guide is [docs/hot-upgrade.md](hot-upgrade.md).

### Unit directives that make it work

- `--workers auto` (packaged default) runs Lorica as a multi-process
  supervisor, which the handoff **requires**: it hands listening sockets
  to a new supervisor, and that only exists in multi-process mode. If a
  drop-in overrides `ExecStart` to `--workers 0`, an upload is verified
  and staged but no live swap happens (it takes effect on the next
  restart); the API response's `handoff` field reports `staged_only`.
- `ExecStart` is otherwise **unchanged** by an upgrade. The upgrade does
  not alter the command line; the old supervisor fork+execv's the staged
  binary with the same arguments plus an internal `--hot-upgrade` flag.
- `Type=notify` lets systemd track the MainPID handover. When the new
  process is accepting it sends `sd_notify READY=1\nMAINPID=<newpid>` and
  systemd reassigns the unit's main PID to it.
- `NotifyAccess=all` is required because that notification comes from the
  **new** process, which is not the original MainPID; `NotifyAccess=main`
  would discard it and the handover would not register.
- `KillMode=mixed` sends `SIGTERM` to the main process only, so the
  supervisor orchestrates the worker drain itself instead of systemd
  killing the whole cgroup at once.
- `TimeoutStopSec=90` exceeds the worker drain window
  (`worker_drain_timeout_s`, default 30s) with headroom, so a legitimate
  drain is never cut short.
- `Restart=on-failure` is kept. A clean hot-upgrade exit is code 0 (the
  new process has already taken over the MainPID), which does not trigger
  a restart; a real crash exits non-zero and still restarts.

A drop-in override that changes `ExecStart` flags (ports, workers) is
honoured by the new process: the upgrade reuses the live supervisor's
arguments, so customizations survive the swap.

### Configure signing (opt-in)

The upgrade endpoint refuses unsigned binaries. It verifies a detached
Ed25519 signature over the uploaded binary against an operator-managed
public key. Set it up once:

```bash
# Generate an Ed25519 keypair OFFLINE (keep the private key off the host).
openssl genpkey -algorithm ed25519 -out lorica-release.key
openssl pkey -in lorica-release.key -pubout -outform DER 2>/dev/null \
  | tail -c 32 | xxd -p -c 32 > lorica-release.pub.hex

# Copy ONLY the 64-hex-char public key to the server.
sudo install -o lorica -g lorica -m 0640 \
  lorica-release.pub.hex /etc/lorica/upgrade-signing.pub
```

Then point Lorica at the public key file by setting
`upgrade_signing_pubkey_path` (Settings -> Binary upgrade in the
dashboard, or the global settings API) to
`/etc/lorica/upgrade-signing.pub`. The file holds the 32-byte Ed25519
verifying key as a single 64-hex-character line.

The private key never touches the server: it signs releases on an offline
or CI signing host. With **no** signing key configured the upgrade
endpoint returns `400 "no upgrade signing key configured"` and the running
binary is untouched. The feature is therefore opt-in.

This binary-upgrade key is separate from the GPG key used to sign the
`.deb` / `.rpm` packages themselves (see "Package Verification" in the
README); the two serve different trust paths.

## Docker

The container image honours the same handoff (see
[docs/hot-upgrade.md](hot-upgrade.md#docker)). The typical Docker workflow
stays "rebuild the image and `docker compose up -d`", but an in-place
`docker exec lorica upgrade --binary ...` swap works when the container
runs the supervisor.

## See also

- [docs/hot-upgrade.md](hot-upgrade.md) - hot binary upgrade operator guide
- [docs/worker-mode.md](worker-mode.md) - supervisor / worker operational notes
- [docs/tuning.md](tuning.md) - kernel, FD limits, production checklist
- [docs/security/hardening-guide.md](security/hardening-guide.md) - hardening reference
