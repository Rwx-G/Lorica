#!/bin/sh
# =============================================================================
# Lorica GeoIP E2E entrypoint (v1.4.0 Epic 2).
#
# With hot-reload of `geoip_db_path` landed in `lorica::reload`, this
# entrypoint no longer needs to pre-seed the DB path via sqlite3
# before Lorica starts. The smoke test sets the path over the
# management API after login; the first `reload_proxy_config` fires
# `apply_geoip_settings_from_store` which calls `load_from_path` on
# the process-wide resolver atomically. This is the same path an
# operator walks from the dashboard.
#
# We still tee the boot log to /shared/lorica.log so the test runner
# can grep for startup diagnostics if anything goes wrong.
# =============================================================================
mkdir -p /shared

socat TCP-LISTEN:9443,fork,reuseaddr TCP:127.0.0.1:19443 &

LOGFILE=/shared/lorica.log
: > "$LOGFILE"

lorica --data-dir /var/lib/lorica --management-port 19443 \
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

wait "$LORICA_PID"
