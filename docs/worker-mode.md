# Worker Mode - Operator Notes

Author: Romain G.

This page documents operational behaviours that change between the
default single-process mode and the multi-worker mode (`--workers N`).
Read it before promoting a `--workers N >= 1` deployment to production.

---

## What worker mode is

`--workers N` (default `0` = single-process) forks `N` proxy worker
processes from a long-lived supervisor. The supervisor owns the REST
API, the SQLite store, the TLS cert resolver, the ACME provisioning
loop, the notification dispatcher, the session store, the active probes
and the worker lifecycle. Workers own the proxy data plane and the
listener file descriptors (passed at fork via `SCM_RIGHTS`).
`SO_REUSEPORT` distributes incoming connections across workers.

This split improves crash isolation (a worker that segfaults takes
down ~`1/N` of the data plane and is respawned by the supervisor) and
lets the proxy take advantage of multiple cores without sharing a
single Tokio runtime.

---

## Settings that require a supervisor restart

The following settings cannot be changed at runtime in worker mode.
The dashboard accepts the change and writes it to the database, but
the new value will only take effect after a `systemctl restart lorica`
(or equivalent).

### `--workers N`

The worker count is fixed at supervisor startup. Adding or removing
workers requires creating new socket pairs, a fork, FD passing, and
re-wiring the heartbeat / reload tasks; removing a worker needs a
draining protocol that does not exist today.

To change the worker count:

```bash
# Edit the systemd unit or CLI invocation, then:
sudo systemctl restart lorica
```

Hot-scalable workers are tracked as a future enhancement; until then,
treat `--workers N` as deployment-time configuration.

### Listener ports (`http_port`, `https_port`, `management_port`)

The TCP listeners are bound by the supervisor before the fork and
passed to workers as inherited file descriptors. Workers have no
mechanism to bind a new address at runtime, and the supervisor cannot
hot-rebind without a kernel-level dance that would also need a drain
protocol for in-flight connections on the old port.

To change a listener port:

1. Update the value in **Settings -> Networking** (or via the API).
   The new value is persisted.
2. `sudo systemctl restart lorica` to bind the new port.

The dashboard surfaces an "applies on next restart" hint on these
fields. Backend addresses (per-route upstreams) are not affected -
those reload live via the normal config reload path.

---

## Things to keep in mind under `N > 1`

These items are not bugs; they are consequences of running independent
worker processes that the operator should be aware of when choosing
`N`.

(Detailed write-ups for these items - rate limits, forward-auth cache,
circuit breaker amplification, metrics staleness, reload window - will
be added here as those audit findings are addressed in a future
release.)

---

## Reference

- Architecture overview: [docs/architecture.md](architecture.md).
