#!/bin/sh
# Entrypoint of the Lorica proxies of the performance phase (Story 12.12
# D-i): the same script for 1.11.0 (`perf-lorica`) and the released
# 1.10.7 (`perf-lorica-baseline`), so it passes only flags both versions
# know. Anything 1.11.0 added (a drain setting, a stream flag) would stop
# the baseline container at start.
#
# Runs as the image's `lorica` user: every port of the phase is above
# 1024, so no capability is needed, and the processes stay readable to an
# exec as the same user, which reads their PSS (`/proc/<pid>/smaps_rollup`)
# for the UDP hold's memory figure.
#
# The management API listens on loopback; socat exposes it on 9443 for
# the driver's client. Lorica's own output goes to a file in the
# container, not to Docker's log driver, whose cost would land outside
# the container's cgroup; run-perf.sh prints its tail when the phase
# fails. `exec` makes Lorica PID 1, so `docker stop` signals it directly.

socat TCP-LISTEN:9443,fork,reuseaddr TCP:127.0.0.1:19443 &

exec lorica --data-dir /var/lib/lorica --management-port 19443 --workers "${PERF_WORKERS:?}" \
    > /tmp/lorica.log 2>&1
