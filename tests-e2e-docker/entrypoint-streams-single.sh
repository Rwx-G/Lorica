#!/bin/sh
# E2E entrypoint of the L4 phase's `streams-single` profile (Story 12.12
# Lot A): Lorica in single-process mode. Same shape as
# entrypoint-streams.sh, which explains the privilege drop and the
# SIGTERM forwarding; only the process mode differs.

mkdir -p /shared

as_lorica() {
    setpriv --reuid=lorica --regid=lorica --init-groups \
        --inh-caps=+net_bind_service --ambient-caps=+net_bind_service -- "$@"
}

as_lorica socat TCP-LISTEN:9443,fork,reuseaddr TCP:127.0.0.1:19443 &

LOGFILE=/tmp/lorica_boot.log
as_lorica lorica --data-dir /var/lib/lorica --management-port 19443 \
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

wait "$LORICA_PID"
status=$?
while kill -0 "$LORICA_PID" 2>/dev/null; do
    wait "$LORICA_PID"
    status=$?
done
exit "$status"
