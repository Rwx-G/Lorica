#!/bin/sh
# =============================================================================
# Lorica capture E2E entrypoint for WORKER MODE (Stories 10.1 / 10.2).
#
# Identical to entrypoint-capture.sh except for `--workers 2`, and the
# difference is the whole point of the profile: under `--workers` every
# capture decision is taken in a worker process while the management API
# runs in the supervisor. The workers inherit this process's stdout, so
# `/shared/lorica.log` holds the `lorica::capture` records the workers
# emitted even though the supervisor emits none of them - which is how
# the smoke reads records on a node whose `GET /api/v1/capture/recent`
# answers 503 (docs/capture.md, Troubleshooting).
#
# The writable capture directory is created here for the same reason as
# in the single-process entrypoint: the directory writer never creates
# it (docs/capture.md, "Sinks").
# =============================================================================
mkdir -p /shared
mkdir -p /shared/captures
chmod 0750 /shared/captures
rm -f /shared/captures/*.json /shared/captures/.*.tmp 2>/dev/null

socat TCP-LISTEN:9443,fork,reuseaddr TCP:127.0.0.1:19443 &

LOGFILE=/shared/lorica.log
: > "$LOGFILE"  # truncate on each boot so stale content from a
                # previous run cannot satisfy an assertion.

lorica --data-dir /var/lib/lorica --management-port 19443 --workers 2 \
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
