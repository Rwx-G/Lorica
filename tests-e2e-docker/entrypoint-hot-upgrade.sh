#!/bin/sh
# E2E entrypoint for the hot binary-upgrade profile (Story 8.4, IV1/IV3).
#
# Lorica runs in supervisor/workers mode because the zero-downtime
# handoff only exists in supervisor mode. After a successful hot upgrade
# the OLD supervisor exits(0) and the freshly fork+exec'd NEW supervisor
# (a child of the old) is reparented to PID 1. So this entrypoint must
# NOT terminate when the first lorica PID leaves: it foregrounds
# `tail -f` on the shared log, which never returns, keeping the container
# alive while the inheriting new supervisor serves. The new supervisor
# inherited the old's stdout/stderr (both redirected to the same log
# file), so its handoff log lines keep streaming to `docker logs`.

set -eu
mkdir -p /shared

# Expose the localhost-only management API on 0.0.0.0:9443. The hot
# upgrade hands the SAME 127.0.0.1:19443 listening socket to the new
# supervisor, so socat keeps forwarding across the swap unchanged.
socat TCP-LISTEN:9443,fork,reuseaddr TCP:127.0.0.1:19443 &

# Publish the running binary so the test-runner can sign + re-upload the
# exact same executable (a valid lorica the supervisor will exec as the
# replacement). Write to a temp name then rename so a reader on the
# shared volume never observes a partial copy.
cp /usr/local/bin/lorica /shared/.lorica-bin.tmp
mv /shared/.lorica-bin.tmp /shared/lorica-bin

LOGFILE=/tmp/lorica_boot.log
lorica --data-dir /var/lib/lorica --management-port 19443 --workers 2 \
  > "$LOGFILE" 2>&1 &

# Capture the bootstrap admin password for the test-runner (same scheme
# as entrypoint-workers.sh: 0600 file first, stdout parse as fallback).
for i in $(seq 1 30); do
    if [ -f /var/lib/lorica/initial-admin-password ]; then
        cat /var/lib/lorica/initial-admin-password > /shared/admin_password
        break
    fi
    if grep -q "Initial admin password:" "$LOGFILE" 2>/dev/null; then
        grep "Initial admin password:" "$LOGFILE" \
            | sed 's/.*Initial admin password: //' > /shared/admin_password
        break
    fi
    sleep 1
done

# Seed the upgrade signing-key PATH (a fixed location) directly into the
# config store. The PUT /settings API does not expose
# upgrade_signing_pubkey_path, so the operator-configures-the-key path is
# the config store itself; the e2e seeds the path row here and the
# test-runner drops the runtime-generated public key at that path. The
# upgrade handler reads this row fresh from the DB on every request
# (get_global_settings), so no reload is needed. Retry until migrations
# have created the global_settings table.
DB=/var/lib/lorica/lorica.db
PUBKEY_PATH=/shared/upgrade-pubkey.hex
for i in $(seq 1 30); do
    if sqlite3 "$DB" "PRAGMA busy_timeout=5000; INSERT OR REPLACE INTO global_settings (key, value) VALUES ('upgrade_signing_pubkey_path', '$PUBKEY_PATH');" >/dev/null 2>&1; then
        echo "seeded upgrade_signing_pubkey_path=$PUBKEY_PATH"
        break
    fi
    sleep 1
done

cat "$LOGFILE"
# Foreground tail keeps PID 1 alive across the supervisor swap.
exec tail -f "$LOGFILE"
