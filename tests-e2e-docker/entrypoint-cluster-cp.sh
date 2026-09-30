#!/bin/sh
# =============================================================================
# Lorica cluster control-plane E2E entrypoint (Epic 9 Integration
# Verification, backlog #66).
#
# This is the node the fleet dials. It initialises the cluster CA before
# starting, then serves the operational listener on 9444, the
# enrollment listener on 9445 and, since Epic 10, the automation
# listener on 9446.
#
# `--cluster-listen-any` and `--automation-listen-any` are passed
# deliberately: inside compose the container's own name is the routable
# address and binding it explicitly would require knowing the container
# IP before it exists. Each flag is exactly the "I meant a wildcard"
# acknowledgement the CLI demands, and this is the case it was written
# for.
#
# The automation listener refuses to open while `automation_allowed_cidrs`
# is empty; the first boot seeds it through seed-automation-allowlist.sh,
# the helper entrypoint-mcp.sh sources too. The allowlist is the /24 of
# the e2e network (read off backend1, which sits on that network and
# nowhere else), so every runner on it is inside, plus 127.0.0.1/32 for
# the cluster MCP phase (backlog #91): it shares this node's network
# namespace to mint with the real `lorica mcp token create`, and the
# listener's certificate names 127.0.0.1, not the e2e address. The
# control plane also joins a second compose network on which nothing is
# allowlisted, which is where the smoke's "outside" connection comes
# from. Once per data volume, like the CA: a `docker compose restart`
# finds the marker and starts straight away.
#
# The bootstrap password is written to /shared so the smoke runner and
# the followers can read it without a docker socket.
#
# Every step also prints to stdout. The first run of this profile died
# in `cluster init` and left `docker logs` completely empty, because the
# output existed only in a file nobody could reach from a container that
# had already exited.
# =============================================================================
set -e
mkdir -p /shared

DATA_DIR=/var/lib/lorica
LOGFILE=/shared/cp.log
: > "$LOGFILE"

say() { echo "$*" | tee -a "$LOGFILE"; }

# `--data-dir` is a GLOBAL flag: it belongs before the subcommand, not
# after it. The CA has to exist before the listener starts, or the node
# comes up as a standalone install and every join is refused.
# The control plane is the node that runs ACME for the fleet (Story
# 9.5), against the Pebble fixture the `acme` profile already ships.
# SSL_CERT_FILE names the fixture CA `acme-ca-init` writes; the client
# reads it when the trust store is built, so it must exist first.
if [ -n "${SSL_CERT_FILE:-}" ]; then
    for i in $(seq 1 60); do
        [ -f "$SSL_CERT_FILE" ] && break
        sleep 1
    done
    if [ ! -f "$SSL_CERT_FILE" ]; then
        say "$SSL_CERT_FILE never appeared (acme-ca-init failed?)"
        exit 1
    fi
fi

# Once per data volume: `cluster init` generates the fleet CA and
# refuses to replace one, so a `docker compose restart` would die here
# instead of exercising the restart the cluster e2e phase observes
# (backlog #77). The marker lives in the data volume, like the CA.
CA_MARKER="$DATA_DIR/.e2e-ca-initialised"
if [ -f "$CA_MARKER" ]; then
    say "the cluster CA already exists; starting (restart)"
else
    say "initialising the cluster CA"
    if ! lorica --data-dir "$DATA_DIR" cluster init \
            --common-name "Lorica E2E Cluster CA" 2>&1 | tee -a "$LOGFILE"; then
        say "cluster init failed"
        exit 1
    fi
    touch "$CA_MARKER"
fi

# Harness only: exposes the loopback management API to the runner and
# the followers, which mint their own tokens through it. An operator's
# control plane keeps its management API on loopback or behind the TLS
# listener with a verified certificate.
socat TCP-LISTEN:9443,fork,reuseaddr TCP:127.0.0.1:19443 &

# The automation allowlist (Story 10.3), seeded once. The e2e /24 comes
# first: it is the one the automation smoke reads back from /shared.
automation_allowed_cidrs() {
    backend1_ip=$(getent hosts backend1 | awk '{print $1}' | head -1)
    if [ -z "$backend1_ip" ]; then
        say "backend1 does not resolve; cannot derive the automation allowlist" >&2
        return 1
    fi
    echo "$(echo "$backend1_ip" | awk -F. '{print $1"."$2"."$3".0/24"}') 127.0.0.1/32"
}
. /seed-automation-allowlist.sh
seed_automation_allowlist \
    --cluster-listen "0.0.0.0:9444" \
    --cluster-listen-any \
    --cluster-enrollment-listen "0.0.0.0:9445" \
    --cluster-advertise "lorica-cp" || exit 1
if [ -n "$SEEDED_CIDRS" ]; then
    echo "${SEEDED_CIDRS%% *}" > /shared/automation_allowed_cidr
fi

lorica --data-dir "$DATA_DIR" --management-port 19443 \
    --cluster-listen "0.0.0.0:9444" \
    --cluster-listen-any \
    --cluster-enrollment-listen "0.0.0.0:9445" \
    --cluster-advertise "lorica-cp" \
    --automation-listen "0.0.0.0:9446" \
    --automation-listen-any 2>&1 | tee -a "$LOGFILE" &

for i in $(seq 1 60); do
    if [ -f "$DATA_DIR/initial-admin-password" ]; then
        cat "$DATA_DIR/initial-admin-password" > /shared/cp_admin_password
        break
    fi
    sleep 1
done

if [ ! -f /shared/cp_admin_password ]; then
    say "the control plane never wrote its bootstrap password"
    exit 1
fi

# The marker the followers wait on: written last, so its presence means
# the password file is already readable.
echo ready > /shared/cp_ready
say "control plane ready"

wait
