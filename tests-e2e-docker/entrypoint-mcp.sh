#!/bin/sh
# =============================================================================
# Lorica MCP E2E entrypoint (Story 11.4 AC #4, IV2).
#
# A standalone node serving the automation listener, which is the only
# plane `lorica-mcp` ever talks to. The listener is bound on loopback:
# the smoke shares this container's network namespace (see the
# `mcp-smoke` service), because `lorica mcp token create` mints through
# the management API at 127.0.0.1 and nowhere else, and the smoke has to
# run the real command rather than a direct API call.
#
# The listener refuses to open while `automation_allowed_cidrs` is empty,
# and the setting lives in the store, so the first boot walks the path an
# operator walks, as entrypoint-cluster-cp.sh does: start without the
# flag, set the allowlist on the management API, stop, start with the
# flag. The allowlist is 127.0.0.1/32, the source every smoke connection
# comes from.
#
# Two files land on /shared for the smoke: the bootstrap password (the
# CLI reads it with --password-file, never argv) and the listener's
# certificate, which is the management plane's self-signed leaf and is
# what LORICA_MCP_CA_BUNDLE has to name. There is no switch in lorica-mcp
# that turns verification off, so the smoke trusts exactly this leaf.
# =============================================================================
set -e
mkdir -p /shared

DATA_DIR=/var/lib/lorica
LOGFILE=/shared/mcp-node.log
: > "$LOGFILE"

say() { echo "$*" | tee -a "$LOGFILE"; }

ALLOWLIST_MARKER="$DATA_DIR/.e2e-automation-allowlist"
if [ -f "$ALLOWLIST_MARKER" ]; then
    say "automation_allowed_cidrs already seeded; starting with the automation listener (restart)"
else
    say "seeding automation_allowed_cidrs through the management API (first boot)"
    lorica --data-dir "$DATA_DIR" --management-port 19443 >> "$LOGFILE" 2>&1 &
    SEED_PID=$!

    for i in $(seq 1 60); do
        [ -f "$DATA_DIR/initial-admin-password" ] && break
        sleep 1
    done
    for i in $(seq 1 60); do
        curl -sk -o /dev/null https://127.0.0.1:19443/api/v1/status && break
        sleep 1
    done

    SEED_OK=0
    (
        umask 077
        LOGIN_BODY=/tmp/seed_login.json
        COOKIE=/tmp/seed_cookie
        printf '{"username":"admin","password":"%s"}' \
            "$(cat "$DATA_DIR/initial-admin-password")" > "$LOGIN_BODY"
        curl -sk -c "$COOKIE" -X POST "https://127.0.0.1:19443/api/v1/auth/login" \
            -H 'Content-Type: application/json' --data "@$LOGIN_BODY" > /dev/null
        rm -f "$LOGIN_BODY"
        SET_OUT=$(curl -sk -b "$COOKIE" -X PUT "https://127.0.0.1:19443/api/v1/settings" \
            -H 'Content-Type: application/json' \
            -d '{"automation_allowed_cidrs":["127.0.0.1/32"]}')
        rm -f "$COOKIE"
        echo "$SET_OUT" | grep -q '127.0.0.1/32'
    ) && SEED_OK=1

    kill "$SEED_PID" 2>/dev/null || true
    for i in $(seq 1 30); do
        kill -0 "$SEED_PID" 2>/dev/null || break
        sleep 1
    done
    kill -KILL "$SEED_PID" 2>/dev/null || true
    wait "$SEED_PID" 2>/dev/null || true

    if [ "$SEED_OK" != "1" ]; then
        say "seeding automation_allowed_cidrs failed"
        exit 1
    fi
    touch "$ALLOWLIST_MARKER"
    say "automation_allowed_cidrs = 127.0.0.1/32"
fi

lorica --data-dir "$DATA_DIR" --management-port 19443 \
    --automation-listen "127.0.0.1:9446" 2>&1 | tee -a "$LOGFILE" &

for i in $(seq 1 60); do
    if [ -f "$DATA_DIR/initial-admin-password" ] && [ -f "$DATA_DIR/management/cert.pem" ]; then
        (umask 077; cat "$DATA_DIR/initial-admin-password" > /shared/admin_password)
        cat "$DATA_DIR/management/cert.pem" > /shared/automation-listener-ca.pem
        break
    fi
    sleep 1
done

if [ ! -f /shared/admin_password ] || [ ! -f /shared/automation-listener-ca.pem ]; then
    say "the node never wrote its bootstrap password or its management certificate"
    exit 1
fi

# The marker the smoke waits on: written last, so its presence means
# both files above are already readable.
echo ready > /shared/mcp_ready
say "mcp node ready"

wait
