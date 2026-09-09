#!/bin/sh
# =============================================================================
# Lorica cluster follower E2E entrypoint (Epic 9 Integration
# Verification, backlog #66).
#
# Waits for the control plane, mints itself a join token through the
# control plane's management API, redeems it, then starts. Two things
# about that are deliberate:
#
#   - The token is written to a file and passed with `--token-file`,
#     never on the command line. That is the Story 9.3 AC #6 rule, and
#     an e2e that took the shortcut would be exercising a path the
#     product refuses to offer.
#   - The mint names this node (`node_name`), because since Story 9.5
#     D15 the name decides which certificate private keys the node
#     receives, so the token rather than the joining machine chooses it.
#   - The SuperAdmin password used to mint goes to curl through a 0600
#     file, never on argv, for the same reason the product refuses a
#     password on argv: every local process can read another's command
#     line. The mint response is never logged whole; only the token's
#     public id is, and the token itself goes straight to its file.
#
# What this script does NOT model, and an operator must not copy: the
# `socat` line below publishes the management API off loopback so a
# runner in another container can reach it, and every curl here is
# `-k` because the harness's management certificates are self-signed
# per container. A production node keeps its management API on
# loopback (or the TLS listener with a real certificate) and automation
# verifies it.
#
# NODE_NAME and WORKERS come from compose, so the same script serves
# both the single-process and the workers-mode follower.
#
# Every step also prints to stdout, so a container that dies leaves
# something in `docker logs`.
# =============================================================================
set -e
mkdir -p /shared

DATA_DIR=/var/lib/lorica
NODE_NAME="${NODE_NAME:?NODE_NAME is required}"
LOGFILE="/shared/${NODE_NAME}.log"
: > "$LOGFILE"

say() { echo "[$NODE_NAME] $*" | tee -a "$LOGFILE"; }

say "waiting for the control plane"
for i in $(seq 1 120); do
    [ -f /shared/cp_ready ] && break
    sleep 1
done
if [ ! -f /shared/cp_ready ]; then
    say "the control plane never became ready"
    exit 1
fi

umask 077

# Log in to the control plane's management API and mint a token bound to
# this node's name. The login body is built in a 0600 file and handed to
# curl with `--data @file`, so the password is never on argv.
LOGIN_BODY=/tmp/cp_login.json
printf '{"username":"admin","password":"%s"}' "$(cat /shared/cp_admin_password)" > "$LOGIN_BODY"
COOKIE=/tmp/cp_cookie
if ! curl -sk -c "$COOKIE" -X POST "https://lorica-cp:9443/api/v1/auth/login" \
        -H 'Content-Type: application/json' \
        --data "@$LOGIN_BODY" > /dev/null; then
    rm -f "$LOGIN_BODY"
    say "could not log in to the control plane"
    exit 1
fi
rm -f "$LOGIN_BODY"

# The response goes to a 0600 file, never into a shell variable that a
# later line might echo. The one field logged is the public id.
MINT_FILE=/tmp/mint.json
curl -sk -b "$COOKIE" -X POST "https://lorica-cp:9443/api/v1/cluster/tokens" \
    -H 'Content-Type: application/json' \
    -d "{\"node_name\":\"${NODE_NAME}\",\"ttl_seconds\":600}" > "$MINT_FILE"
say "minted token $(sed -n 's/.*"public_id":"\([^"]*\)".*/\1/p' "$MINT_FILE")"

TOKEN_FILE=/tmp/join-token
sed -n 's/.*"token":"\([^"]*\)".*/\1/p' "$MINT_FILE" > "$TOKEN_FILE"
rm -f "$MINT_FILE"
if [ ! -s "$TOKEN_FILE" ]; then
    say "the control plane did not mint a token"
    exit 1
fi

# `--data-dir` is a GLOBAL flag and belongs before the subcommand.
say "joining the fleet"
# Captured to a file rather than piped: a pipeline's exit status is the
# LAST command's, so `if ! lorica ... | tee` reports tee's success and
# this node would announce itself ready after a refused join.
JOIN_OUT=/tmp/join.out
if lorica --data-dir "$DATA_DIR" cluster join \
        --control-plane "lorica-cp:9444" \
        --enrollment "lorica-cp:9445" \
        --name "$NODE_NAME" \
        --server-name "lorica-cp" \
        --token-file "$TOKEN_FILE" > "$JOIN_OUT" 2>&1; then
    say "$(cat "$JOIN_OUT")"
else
    say "$(cat "$JOIN_OUT")"
    say "the join was refused"
    rm -f "$TOKEN_FILE"
    exit 1
fi
rm -f "$TOKEN_FILE"

# Harness only: exposes the loopback management API to the runner
# container. See the header; never do this on an operator's node.
socat TCP-LISTEN:9443,fork,reuseaddr TCP:127.0.0.1:19443 &

if [ "${WORKERS:-0}" = "1" ]; then
    lorica --data-dir "$DATA_DIR" --management-port 19443 --workers 2 \
        2>&1 | tee -a "$LOGFILE" &
else
    lorica --data-dir "$DATA_DIR" --management-port 19443 \
        2>&1 | tee -a "$LOGFILE" &
fi

for i in $(seq 1 60); do
    if [ -f "$DATA_DIR/initial-admin-password" ]; then
        cat "$DATA_DIR/initial-admin-password" > "/shared/${NODE_NAME}_admin_password"
        break
    fi
    sleep 1
done

if [ ! -f "/shared/${NODE_NAME}_admin_password" ]; then
    say "this node never wrote its bootstrap password"
    exit 1
fi

echo ready > "/shared/${NODE_NAME}_ready"
say "ready"

wait
