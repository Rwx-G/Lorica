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

CP_PASSWORD=$(cat /shared/cp_admin_password)

# Log in to the control plane's management API and mint a token bound to
# this node's name.
COOKIE=/tmp/cp_cookie
if ! curl -sk -c "$COOKIE" -X POST "https://lorica-cp:9443/api/v1/auth/login" \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"admin\",\"password\":\"${CP_PASSWORD}\"}" > /dev/null; then
    say "could not log in to the control plane"
    exit 1
fi

MINT=$(curl -sk -b "$COOKIE" -X POST "https://lorica-cp:9443/api/v1/cluster/tokens" \
    -H 'Content-Type: application/json' \
    -d "{\"node_name\":\"${NODE_NAME}\",\"ttl_seconds\":600}")
# The token never reaches a log line, a shell history or argv.
say "minted: $(echo "$MINT" | sed 's/"token":"[^"]*"/"token":"<REDACTED>"/')"

TOKEN_FILE=/tmp/join-token
umask 077
echo "$MINT" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p' > "$TOKEN_FILE"
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
