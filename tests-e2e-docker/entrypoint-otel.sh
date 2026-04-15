#!/bin/sh
# =============================================================================
# Lorica OTel E2E entrypoint. Identical to the default entrypoint
# except the boot log is also written to `/shared/lorica.log` so the
# test-runner (which mounts `shared-otel:/shared:ro`) can assert that
# the trace_id from a request's W3C traceparent also appears in the
# structured JSON log records. This is the story 1.5 log/trace
# correlation coverage: without the log copy, the test-runner has no
# cheap way to read the lorica-otel container's stdout.
# =============================================================================
mkdir -p /shared

socat TCP-LISTEN:9443,fork,reuseaddr TCP:127.0.0.1:19443 &

LOGFILE=/shared/lorica.log
: > "$LOGFILE"  # truncate on each boot so stale trace IDs from a
                # previous run cannot accidentally satisfy the
                # correlation assertion.

lorica --data-dir /var/lib/lorica --management-port 19443 \
    > "$LOGFILE" 2>&1 &
LORICA_PID=$!

# Wait for the password line (up to 30s), scraped from the JSON log.
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

wait "$LORICA_PID"
