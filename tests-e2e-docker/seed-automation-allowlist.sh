# shellcheck shell=sh
# =============================================================================
# Seeding `automation_allowed_cidrs`, shared by every entrypoint that
# serves the automation listener (entrypoint-cluster-cp.sh,
# entrypoint-mcp.sh). Sourced, never executed.
#
# The listener refuses to open while `automation_allowed_cidrs` is empty,
# and the setting lives in the store, so the first boot walks the path an
# operator walks: start without --automation-listen, set the allowlist on
# the management API, stop, and let the caller start with the flag. Once
# per data volume: the marker lives in the data volume, so a
# `docker compose restart` finds it and the caller starts straight away.
#
# The login body and the cookie go through 0600 files, never argv, for
# the reason entrypoint-cluster-follower.sh gives.
#
# The caller provides:
#   DATA_DIR                  the node's data directory
#   LOGFILE                   where the seeding boot's output goes
#   say                       a function that prints a line and logs it
#   automation_allowed_cidrs  a function printing the CIDRs to allowlist,
#                             space-separated, called once the seeding
#                             boot's management API answers; a non-zero
#                             return aborts the seeding
#
# Usage: seed_automation_allowlist [extra lorica flags for the seeding boot]
# Returns non-zero when the seeding failed; the caller exits. After a
# seeding (not a restart), SEEDED_CIDRS holds what was allowlisted.
# =============================================================================

SEEDED_CIDRS=""

seed_automation_allowlist() {
    allowlist_marker="$DATA_DIR/.e2e-automation-allowlist"
    if [ -f "$allowlist_marker" ]; then
        say "automation_allowed_cidrs already seeded; starting with the automation listener (restart)"
        return 0
    fi

    say "seeding automation_allowed_cidrs through the management API (first boot)"
    lorica --data-dir "$DATA_DIR" --management-port 19443 "$@" >> "$LOGFILE" 2>&1 &
    seed_pid=$!

    for i in $(seq 1 60); do
        [ -f "$DATA_DIR/initial-admin-password" ] && break
        sleep 1
    done
    for i in $(seq 1 60); do
        curl -sk -o /dev/null https://127.0.0.1:19443/api/v1/status && break
        sleep 1
    done

    seed_ok=0
    if cidrs=$(automation_allowed_cidrs) && [ -n "$cidrs" ]; then
        cidrs_json=$(printf '%s\n' $cidrs | awk 'BEGIN{ORS=""; print "["} NR>1{print ","} {print "\"" $0 "\""} END{print "]"}')
        (
            umask 077
            login_body=/tmp/seed_login.json
            cookie=/tmp/seed_cookie
            printf '{"username":"admin","password":"%s"}' \
                "$(cat "$DATA_DIR/initial-admin-password")" > "$login_body"
            curl -sk -c "$cookie" -X POST "https://127.0.0.1:19443/api/v1/auth/login" \
                -H 'Content-Type: application/json' --data "@$login_body" > /dev/null
            rm -f "$login_body"
            set_out=$(curl -sk -b "$cookie" -X PUT "https://127.0.0.1:19443/api/v1/settings" \
                -H 'Content-Type: application/json' \
                -d "{\"automation_allowed_cidrs\":$cidrs_json}")
            rm -f "$cookie"
            for cidr in $cidrs; do
                echo "$set_out" | grep -q "\"$cidr\"" || exit 1
            done
        ) && seed_ok=1
    fi

    kill "$seed_pid" 2>/dev/null || true
    for i in $(seq 1 30); do
        kill -0 "$seed_pid" 2>/dev/null || break
        sleep 1
    done
    kill -KILL "$seed_pid" 2>/dev/null || true
    wait "$seed_pid" 2>/dev/null || true

    if [ "$seed_ok" != "1" ]; then
        say "seeding automation_allowed_cidrs failed"
        return 1
    fi
    touch "$allowlist_marker"
    SEEDED_CIDRS="$cidrs"
    say "automation_allowed_cidrs = $cidrs"
}
