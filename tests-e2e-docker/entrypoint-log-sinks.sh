#!/bin/sh
# =============================================================================
# Lorica log-sinks E2E entrypoint (Story 9.8). Identical to the default
# entrypoint except the boot log is also written to `/shared/lorica.log`
# so the test-runner (which mounts `shared-log-sinks:/shared`) can debug
# sink behaviour without a docker socket. The sink settings themselves
# (syslog endpoint, OTLP logs toggle) are configured by the smoke over
# the management API, not via env.
# =============================================================================
mkdir -p /shared

socat TCP-LISTEN:9443,fork,reuseaddr TCP:127.0.0.1:19443 &

LOGFILE=/shared/lorica.log
: > "$LOGFILE"  # truncate on each boot so stale content from a
                # previous run cannot satisfy an assertion.

lorica --data-dir /var/lib/lorica --management-port 19443 \
    > "$LOGFILE" 2>&1 &
LORICA_PID=$!

# Wait for the password line (up to 30s), scraped from the JSON log.
for i in $(seq 1 30); do
    # v1.5.9 writes the bootstrap password to a 0600 file under the
    # data dir (kept off stdout and the journal, CWE-532); read it
    # first and keep the stdout parse only as the legacy fallback
    # for the write-failed path.
    if [ -f /var/lib/lorica/initial-admin-password ]; then
        cat /var/lib/lorica/initial-admin-password > /shared/admin_password
        break
    fi
    if grep -q "Initial admin password:" "$LOGFILE" 2>/dev/null; then
        PW=$(grep "Initial admin password:" "$LOGFILE" | sed 's/.*Initial admin password: //')
        echo "$PW" > /shared/admin_password
        break
    fi
    sleep 1
done

cat "$LOGFILE"
tail -f "$LOGFILE" &

wait "$LORICA_PID"
