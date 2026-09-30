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
# The listener refuses to open while `automation_allowed_cidrs` is empty;
# the first boot seeds it through seed-automation-allowlist.sh, the
# helper entrypoint-cluster-cp.sh sources too. The allowlist is
# 127.0.0.1/32, the source every smoke connection comes from.
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

automation_allowed_cidrs() { echo "127.0.0.1/32"; }
. /seed-automation-allowlist.sh
seed_automation_allowlist || exit 1

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
