#!/bin/sh
# =============================================================================
# Lorica cluster control-plane E2E entrypoint (Epic 9 Integration
# Verification, backlog #66).
#
# This is the node the fleet dials. It initialises the cluster CA before
# starting, then serves the operational listener on 9444 and the
# enrollment listener on 9445.
#
# `--cluster-listen-any` is passed deliberately: inside compose the
# container's own name is the routable address and binding it explicitly
# would require knowing the container IP before it exists. The flag is
# exactly the "I meant a wildcard" acknowledgement the CLI demands, and
# this is the case it was written for.
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

lorica --data-dir "$DATA_DIR" --management-port 19443 \
    --cluster-listen "0.0.0.0:9444" \
    --cluster-listen-any \
    --cluster-enrollment-listen "0.0.0.0:9445" \
    --cluster-advertise "lorica-cp" 2>&1 | tee -a "$LOGFILE" &

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
