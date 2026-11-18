#!/bin/sh
# E2E entrypoint of the L4 phase's `streams` profile (Story 12.12 Lot A):
# Lorica in worker mode (--workers 2).
#
# The container starts as root and drops to the `lorica` user with
# CAP_NET_BIND_SERVICE as an ambient capability, the way systemd's
# `AmbientCapabilities=` does for the packaged unit, so a stream on a
# privileged port binds exactly as in production (Story 12.2 AC #3).
# The compose service sets `net.ipv4.ip_unprivileged_port_start=1024`,
# otherwise Docker's default of 0 would let any user bind port 853.
#
# SIGTERM from `docker stop` is forwarded to Lorica and the script waits
# for the drain to end: a shell as PID 1 ignores SIGTERM, and without
# the forward `docker stop` would always end in SIGKILL.

mkdir -p /shared

as_lorica() {
    setpriv --reuid=lorica --regid=lorica --init-groups \
        --inh-caps=+net_bind_service --ambient-caps=+net_bind_service -- "$@"
}

as_lorica socat TCP-LISTEN:9443,fork,reuseaddr TCP:127.0.0.1:19443 &

LOGFILE=/tmp/lorica_boot.log
as_lorica lorica --data-dir /var/lib/lorica --management-port 19443 --workers 2 \
  > "$LOGFILE" 2>&1 &
LORICA_PID=$!
trap 'kill -TERM "$LORICA_PID" 2>/dev/null' TERM INT

for i in $(seq 1 30); do
    if [ -f /var/lib/lorica/initial-admin-password ]; then
        cat /var/lib/lorica/initial-admin-password > /shared/admin_password
        break
    fi
    sleep 1
done

cat "$LOGFILE"
tail -f "$LOGFILE" &

# `wait` returns as soon as a trapped signal arrives; keep waiting until
# Lorica has finished its drain and exited, and exit with its status.
wait "$LORICA_PID"
status=$?
while kill -0 "$LORICA_PID" 2>/dev/null; do
    wait "$LORICA_PID"
    status=$?
done
exit "$status"
