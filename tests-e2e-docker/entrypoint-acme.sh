#!/bin/sh
# =============================================================================
# Lorica ACME E2E entrypoint (Story 9.1 AC #13, Pebble fixture).
# Same shape as the other profile entrypoints (socat management
# forward, boot log teed to /shared/lorica.log, admin password
# scrape), plus one fixture-specific step: wait for the Pebble CA the
# `acme-ca-init` service generates into the shared volume, because
# SSL_CERT_FILE (set on the service) must point at an existing file
# when the ACME client builds its trust store.
# =============================================================================
mkdir -p /shared

# Wait up to 60s for the fixture CA. Without it every provision would
# fail TLS verification against Pebble's directory.
for i in $(seq 1 60); do
    [ -f /shared/pebble-ca.pem ] && break
    sleep 1
done
if [ ! -f /shared/pebble-ca.pem ]; then
    echo "ERROR: /shared/pebble-ca.pem never appeared (acme-ca-init failed?)" >&2
    exit 1
fi

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
