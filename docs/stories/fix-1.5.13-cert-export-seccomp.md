# Fix 1.5.13 - cert-export `chown` crashed the proxy via seccomp SIGSYS

Status: Review

## Symptom

An operator triggered the cert-export "re-export all" action (`POST
/api/v1/cert-export/reapply`). Lorica returned HTTP 500 and the whole
service went down, then systemd restarted it ~90 s later. The same class
of failure prevented renewed certificates from being written to the
configured export directory.

## Root cause

The shipped systemd unit hardens syscalls with:

```
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
```

The deny list uses the default action `SECCOMP_RET_KILL`, which kills the
whole process with `SIGSYS` (signal 31). The `chown` family
(`chown`/`fchown`/`lchown`/`fchownat`) is part of `@privileged`.

The cert-export feature applies the configured owner UID/GID by calling
`nix::unistd::chown` (`lorica-api/src/cert_export.rs:151`). Because the
export runs in the privileged supervisor process (it serves the
management API), that `chown` syscall was answered by the kernel with
`SIGSYS`, killing the supervisor. All workers then lost their command
channel (`command channel recv error: early eof`) and systemd tore the
cgroup down after `TimeoutStopSec`.

Journal evidence:

```
lorica.service: Main process exited, code=killed, status=31/SYS
```

The code was written to degrade gracefully when `CAP_CHOWN` is absent
(`Err(Errno::EPERM) => Ok(false)` at `cert_export.rs:153`), but that
contract assumes the syscall is *allowed* by seccomp and only denied by
capabilities. seccomp evaluates before the capability check, so the kill
happened before `EPERM` could ever be returned.

## Fix

Downgrade only the `chown` family from kill to a soft `EPERM`, without
granting any capability, via a trailing directive in `dist/lorica.service`:

```
SystemCallFilter=~@chown:EPERM
```

`@chown` is a subset of `@privileged`; the later rule overrides only
those syscalls, so every other `@privileged`/`@resources` syscall still
hard-kills. On `EPERM` the exporter falls back to
`ExportOutcome::PermissionsSkipped`: the bundle is written with the
configured file mode (`0640`) and left owned by the `lorica` user.
Operators who genuinely need the `chown` to take effect must instead add
`CAP_CHOWN` to the bounding/ambient sets and re-allow `@chown`.

## Syscall audit (proactive - are there other latent SIGSYS?)

Every `@privileged`/`@resources` syscall reachable on the runtime path
was traced. Result: `chown` is the only one, and it is now handled.

- Privilege drop is entirely systemd's job (`User=`/`Group=` pre-exec);
  the fork+exec path in `lorica-worker/src/manager.rs` never calls
  `setuid`/`setgid`/`setgroups`.
- No `setrlimit`/`prlimit`/`sched_setaffinity`/`setpriority`/`mbind`
  call sites anywhere in the workspace (jemalloc is a dev-dependency
  only).
- `lorica-shmem` uses `memfd_create` + `mmap` (both in
  `@system-service`), not `mount`/NUMA calls.

Latent future risk (no action today): `lorica-core/src/server/daemon.rs`
documents a would-be inline `setuid`/`setgid` daemonization path. It is a
no-op since v1.3.0. If anyone ever reactivates it to run Lorica outside
systemd, those calls would hit `@privileged` -> SIGSYS under the current
unit.

## Regression protection

- CI job `test-deb-install` (ubuntu-latest, real systemd) now runs
  `systemd-analyze verify` on the installed unit and a syscall-level
  probe: `chown` executed under the unit's exact `SystemCallFilter`
  directives must fail soft (EPERM, exit < 128), not be killed by a
  signal. Before the fix this probe returns 159 (128 + SIGSYS).
- The existing `cert_export.rs` unit tests already exercise the
  `EPERM -> PermissionsSkipped` code contract (the test harness has no
  `CAP_CHOWN`, so `chown` returns `EPERM` naturally). No Rust test can
  catch the SIGSYS itself because `cargo test` does not apply the systemd
  seccomp filter - hence the deb-install probe.

## Verification not runnable on the Windows dev host

`systemd-analyze` and the seccomp behaviour require Linux + systemd and a
built package. They are validated by the CI run on the PR, or on the
server after deploying the new `.deb`/`.rpm`. The Docker test suite was
not run locally (Docker Desktop was not available on the dev host at fix
time).

## File List

- `dist/lorica.service` - added `SystemCallFilter=~@chown:EPERM` + rationale comment
- `.github/workflows/ci.yml` - `test-deb-install`: unit verify + seccomp chown regression probe
- `CHANGELOG.md` - `[1.5.13]` Fixed + Security entries
- version bump `1.5.12 -> 1.5.13` across the pinned files (see `docs/BUMP-CHECKLIST.md`)

## Change Log

- 2026-07-08 - Root-caused the SIGSYS crash to `@chown` in the seccomp deny
  list, softened it to EPERM, audited for sibling syscalls (none found),
  added the deb-install seccomp regression probe. Bump 1.5.12 -> 1.5.13.
