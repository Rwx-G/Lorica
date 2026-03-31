#!/bin/sh
# E2E test entrypoint: socat forwards external 0.0.0.0:9443 to Lorica's
# localhost-only management API. The admin password is captured from Lorica's
# first-run output and written to /shared/admin_password for the test runner.

mkdir -p /shared

socat TCP-LISTEN:9443,fork,reuseaddr TCP:127.0.0.1:19443 &

# Start Lorica, capture output to a temp file to extract the password
LOGFILE=/tmp/lorica_boot.log
su -s /bin/sh lorica -c \
  "lorica --data-dir /var/lib/lorica --management-port 19443" \
  > "$LOGFILE" 2>&1 &
LORICA_PID=$!

# Wait for the password line to appear (up to 30s)
for i in $(seq 1 30); do
    if grep -q "Initial admin password:" "$LOGFILE" 2>/dev/null; then
        PW=$(grep "Initial admin password:" "$LOGFILE" | sed 's/.*Initial admin password: //')
        echo "$PW" > /shared/admin_password
        break
    fi
    sleep 1
done

# Stream the log to stdout for docker logs
cat "$LOGFILE"
tail -f "$LOGFILE" &

# Wait for Lorica process
wait $LORICA_PID
