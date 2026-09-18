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
# is empty, and the setting lives in the store, so the first boot walks
# the path an operator walks: start without the flag, set the allowlist
# on the management API, stop, start with the flag. The allowlist is the
# /24 of the e2e network (read off backend1, which sits on that network
# and nowhere else), so every runner on it is inside; the control plane
# also joins a second compose network on which nothing is allowlisted,
# which is where the smoke's "outside" connection comes from. Once per
# data volume, like the CA: a `docker compose restart` finds the marker
# and starts straight away.
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

# The automation allowlist (Story 10.3), seeded once. The login body
# and the cookie go through 0600 files, never argv, for the reason the
# follower entrypoint gives.
ALLOWLIST_MARKER="$DATA_DIR/.e2e-automation-allowlist"
if [ -f "$ALLOWLIST_MARKER" ]; then
    say "automation_allowed_cidrs already seeded; starting with the automation listener (restart)"
else
    say "seeding automation_allowed_cidrs through the management API (first boot)"
    lorica --data-dir "$DATA_DIR" --management-port 19443 \
        --cluster-listen "0.0.0.0:9444" \
        --cluster-listen-any \
        --cluster-enrollment-listen "0.0.0.0:9445" \
        --cluster-advertise "lorica-cp" >> "$LOGFILE" 2>&1 &
    SEED_PID=$!

    for i in $(seq 1 60); do
        [ -f "$DATA_DIR/initial-admin-password" ] && break
        sleep 1
    done
    for i in $(seq 1 60); do
        curl -sk -o /dev/null https://127.0.0.1:19443/api/v1/status && break
        sleep 1
    done

    BACKEND1_IP=$(getent hosts backend1 | awk '{print $1}' | head -1)
    if [ -z "$BACKEND1_IP" ]; then
        say "backend1 does not resolve; cannot derive the automation allowlist"
        exit 1
    fi
    ALLOW_CIDR=$(echo "$BACKEND1_IP" | awk -F. '{print $1"."$2"."$3".0/24"}')

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
            -d "{\"automation_allowed_cidrs\":[\"$ALLOW_CIDR\"]}")
        rm -f "$COOKIE"
        echo "$SET_OUT" | grep -q "$ALLOW_CIDR"
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
    echo "$ALLOW_CIDR" > /shared/automation_allowed_cidr
    touch "$ALLOWLIST_MARKER"
    say "automation_allowed_cidrs = $ALLOW_CIDR"
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
