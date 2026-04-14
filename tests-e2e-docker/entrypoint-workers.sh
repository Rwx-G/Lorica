#!/bin/sh
# E2E test entrypoint for multi-worker mode.
# Runs Lorica with --workers 2 to test process isolation.
# Container runs as the non-root lorica user (see Dockerfile USER).

mkdir -p /shared

socat TCP-LISTEN:9443,fork,reuseaddr TCP:127.0.0.1:19443 &

LOGFILE=/tmp/lorica_boot.log
lorica --data-dir /var/lib/lorica --management-port 19443 --workers 2 \
  > "$LOGFILE" 2>&1 &
LORICA_PID=$!

for i in $(seq 1 30); do
    if grep -q "Initial admin password:" "$LOGFILE" 2>/dev/null; then
        PW=$(grep "Initial admin password:" "$LOGFILE" | sed 's/.*Initial admin password: //')
        echo "$PW" > /shared/admin_password
        break
    fi
    sleep 1
done

cat "$LOGFILE"
tail -f "$LOGFILE" &

wait $LORICA_PID
