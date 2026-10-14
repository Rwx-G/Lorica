# shellcheck shell=bash
# Persistence checks shared by deb-upgrade.sh and rpm-upgrade.sh, sourced
# by both. They need `fail` from the sourcing script, openssl and the
# node's first-run admin password; nothing else is installed for them.
#
# Every release from 1.7.0 to 1.9.1 failed to open an access-log.db a
# 1.6.0 node had written, logged one warning and ran on with no access
# log, WAF event or audit persistence: the service was active and every
# package-level check passed. So an upgrade is not done until the node
# it started has persistence: every one of its processes reports an
# open store on `lorica_log_store_up`, and an audited action it performs
# reads back through its own API, above the rows the previous version
# left, on an audit chain that still verifies.
#
# The gauge, not the journal, is what says a store is open: a grep for
# the failure's wording holds only until someone rewords it, and the
# audit read-back exercises only the process serving the API, not the
# workers that write the access logs and WAF events.
#
# The management API is spoken to through `openssl s_client`, without
# pinning: this is the node under test on its own loopback, and the
# CLI's pin is tested elsewhere in these scripts. The password is read
# with a shell redirection and handed to openssl on stdin, never on a
# command line.

MANAGEMENT_ADDRESS=127.0.0.1:9443
ADMIN_PASSWORD_FILE=/var/lib/lorica/initial-admin-password
# The audit row count the last check read; each later one must exceed it.
AUDIT_FLOOR_FILE=/tmp/lorica-audit-floor

rm -f "$AUDIT_FLOOR_FILE"

# Send the HTTP/1.1 request `printf` builds from the arguments to the
# management API; print the response. Built here rather than passed in:
# a command substitution would strip the blank line ending the headers.
management_request() {
    # shellcheck disable=SC2059 # the format is the caller's request template
    printf "$@" | timeout 20 openssl s_client -quiet -connect "$MANAGEMENT_ADDRESS" 2> /dev/null
}

# Log in as the first-run admin, which the node audits as `auth.login`,
# and print the session cookie.
management_login() {
    local password body response cookie
    password=$(< "$ADMIN_PASSWORD_FILE")
    body=$(printf '{"username":"admin","password":"%s"}' "$password")
    response=$(management_request 'POST /api/v1/auth/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' "${#body}" "$body")
    cookie=$(printf '%s\n' "$response" | tr -d '\r' \
        | sed -n 's/^[Ss][Ee][Tt]-[Cc][Oo][Oo][Kk][Ii][Ee]: *\(lorica_session=[^;]*\).*/\1/p' | head -1)
    [ -n "$cookie" ] || { printf '%s\n' "$response" | head -1; return 1; }
    printf '%s' "$cookie"
}

# GET `path` with the session `cookie`; print the body, or fail on a
# status other than 200.
management_get() {
    local cookie="$1" path="$2" response
    response=$(management_request 'GET %s HTTP/1.1\r\nHost: localhost\r\nCookie: %s\r\nConnection: close\r\n\r\n' "$path" "$cookie")
    case "$(printf '%s\n' "$response" | head -1)" in
        "HTTP/1.1 200"*) printf '%s' "$response" ;;
        *) printf '%s\n' "$response" | head -1; return 1 ;;
    esac
}

# Wait for the audit log to hold more than `floor` rows, and print how
# many it holds. The row the login that opened the session `cookie`
# wrote is queued, not written inline, hence the wait. A node whose log
# store did not open answers with an empty log.
audit_rows_above() {
    local cookie="$1" floor="$2" body total=0
    for _ in $(seq 1 20); do
        body=$(management_get "$cookie" '/api/v1/audit?limit=1') || { echo "GET /api/v1/audit: $body"; return 1; }
        total=$(printf '%s' "$body" | grep -o '"total":[0-9]*' | tail -1 | cut -d: -f2)
        [ "${total:-0}" -gt "$floor" ] && { printf '%s' "$total"; return 0; }
        sleep 1
    done
    echo "$total audit rows, expected more than $floor"
    return 1
}

# Wait for every process of the node to report an open log store on
# `lorica_log_store_up`, and print the series read; fail at once on a
# series reading 0. The process serving the API publishes its own
# series (`single` or `supervisor`); in worker mode each worker the
# supervisor lists publishes one through the metrics report a scrape
# pulls, so a worker missing from the gauge is waited for, not passed.
log_store_up_everywhere() {
    local cookie="$1" metrics series workers id missing=
    for _ in $(seq 1 30); do
        metrics=$(management_get "$cookie" '/api/v1/metrics') || { echo "GET /api/v1/metrics: $metrics"; return 1; }
        series=$(printf '%s\n' "$metrics" | tr -d '\r' | grep '^lorica_log_store_up{')
        if printf '%s\n' "$series" | grep -q ' 0$'; then
            printf '%s\n' "$series" | grep ' 0$' | tr '\n' ' '
            return 1
        fi
        missing=
        printf '%s\n' "$series" | grep -qE 'role="(single|supervisor)".* 1$' \
            || missing="the process serving the API"
        if printf '%s\n' "$series" | grep -q 'role="supervisor"'; then
            workers=$(management_get "$cookie" '/api/v1/workers') || { echo "GET /api/v1/workers: $workers"; return 1; }
            workers=$(printf '%s' "$workers" | grep -o '"worker_id":[0-9]*' | cut -d: -f2)
            [ -n "$workers" ] || missing="$missing, any worker"
            for id in $workers; do
                printf '%s\n' "$series" | grep 'role="worker"' | grep -q "worker_id=\"$id\".* 1$" \
                    || missing="$missing, worker $id"
            done
        fi
        [ -z "$missing" ] && { printf '%s' "$series" | tr '\n' ' '; return 0; }
        sleep 1
    done
    echo "no open log store reported by ${missing#, }; series: $(printf '%s' "$series" | tr '\n' ' ')"
    return 1
}

# Before an upgrade: the old node must have written at least one audit
# row to its access-log.db, which the upgraded node then has to read.
record_old_audit_rows() {
    local label="$1" cookie rows
    cookie=$(management_login) || fail "$label: login refused: $cookie"
    rows=$(audit_rows_above "$cookie" 0) || fail "$label: wrote no audit row before the upgrade: $rows"
    printf '%s' "$rows" > "$AUDIT_FLOOR_FILE"
    echo "$label: $rows audit rows in access-log.db before the upgrade"
}

# After an upgrade, with the service active: the node has persistence.
assert_persistence() {
    local label="$1" floor rows persisted=yes stores cookie verdict
    floor=$(cat "$AUDIT_FLOOR_FILE" 2> /dev/null || echo 0)
    cookie=$(management_login) || fail "$label: login refused: $cookie"
    rows=$(audit_rows_above "$cookie" "$floor") || persisted=no
    stores=$(log_store_up_everywhere "$cookie") || fail "$label: a process has no open log store: $stores"
    [ "$persisted" = yes ] || fail "$label: no audit row persisted: $rows"
    printf '%s' "$rows" > "$AUDIT_FLOOR_FILE"

    verdict=$(management_get "$cookie" '/api/v1/audit/verify') || fail "$label: GET /api/v1/audit/verify: $verdict"
    if printf '%s' "$verdict" | grep -q '"verified":false' \
        || ! printf '%s' "$verdict" | grep -q '"total_rows":[1-9]'; then
        printf '%s\n' "$verdict" | tail -1
        fail "$label: the audit chain does not verify"
    fi
    echo "$label: persistence holds ($floor -> $rows audit rows, chain verified, every store open: $stores)"
}
