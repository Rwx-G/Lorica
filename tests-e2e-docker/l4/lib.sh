# shellcheck shell=bash
# Shared library of the L4 phase driver (Story 12.12 D-c). Sourced by
# l4/run-l4.sh, which runs from tests-e2e-docker/ with MSYS path
# conversion off; every path below is relative to that directory.
#
# The scenario contract: every scenario, wherever it runs, prints
# exactly one line
#
#   L4-SCENARIO <name> <PASS|FAIL|PARTIAL> <one-line detail>
#
# at the start of a line. A scenario run by this driver prints it
# through `pass`, `fail` or `partial`; a section appended to an
# in-container smoke of a pre-existing profile echoes it itself.
# test-runner/l4/report.py checks every line against l4/scenarios.tsv.

L4_COMPOSE_FILE=docker-compose.l4.yml
L4_REGISTRY=l4/scenarios.tsv

# ---- Lanes -----------------------------------------------------------
# `L4_LANE=1..4` runs the L4 phase as an isolated lane, so several run at
# once on one Docker host: its own compose project (containers,
# networks and volumes are named after it), its own pinned subnets, and
# results files of its own. Unset is the single-run layout. The subnets
# are derived here and nowhere else; docker-compose.l4.yml reads them.
#   - project       lorica-e2e-l4[-N]
#   - l4 (IPv6)     fd00:4c34:N::/64      (N = 0 when unset)
#   - l4-dns        10.89.(53+N).0/24, CoreDNS at .53
#   - streams-geo   214.78.(119+N).0/24, lane 1 sharing the unset /24:
#                   the GeoIP test database's US block is 214.78.120.0/22,
#                   four /24s, so an unset run and lane 1 cannot overlap
# `L4_IMAGE_TAG` (default `local`) names the Lorica and runner images;
# l4/build-images.sh builds them once for every lane that reuses them.
case "${L4_LANE:-}" in
    ""|1|2|3|4) ;;
    *) echo "l4/lib.sh: L4_LANE must be 1 to 4 or unset, not '${L4_LANE}'" >&2; exit 2 ;;
esac
L4_LANE_INDEX=${L4_LANE:-0}
L4_GEO_INDEX=$(( L4_LANE_INDEX == 0 ? 1 : L4_LANE_INDEX ))
export L4_PROJECT="lorica-e2e-l4${L4_LANE:+-$L4_LANE}"
export L4_IMAGE_TAG="${L4_IMAGE_TAG:-local}"
export L4_V6_SUBNET="fd00:4c34:${L4_LANE_INDEX}::/64"
export L4_DNS_SUBNET="10.89.$(( 53 + L4_LANE_INDEX )).0/24"
export L4_DNS_IP="10.89.$(( 53 + L4_LANE_INDEX )).53"
export L4_GEO_SUBNET="214.78.$(( 119 + L4_GEO_INDEX )).0/24"
# Prefix of the files a lane writes under results/.
L4_RESULTS="results/${L4_PROJECT}"

l4_compose() {
    docker compose -p "$L4_PROJECT" -f "$L4_COMPOSE_FILE" "$@"
}

# Run a command in the client, which has its own address on the `l4`
# network. Every timed assertion runs inside one such command, timer
# included: an exec costs 100 to 300 ms on Docker Desktop.
l4_client() {
    l4_compose exec -T streams-client "$@"
}

# Run a command in the probe, inside the worker-mode node's network and
# pid namespaces (`streams` profile only).
l4_probe() {
    l4_compose exec -T streams-probe "$@"
}

# Run a command in the node of the profile being run, as root.
l4_node() {
    l4_compose exec -T "$L4_NODE" "$@"
}

# The L4 project's equivalent of run.sh's dump_node_log.
# Usage: l4_dump_node_log <service> [lines]
l4_dump_node_log() {
    local node="$1" lines="${2:-80}"
    echo ""
    echo "--- last ${lines} log lines from ${node} (${L4_PROJECT}) ---"
    l4_compose logs --no-color "$node" 2>&1 | tail -n "$lines"
    echo "--- end ${node} ---"
    echo ""
}

# Registry rows as tab-separated fields, comments and header dropped,
# CR stripped (a Windows checkout with autocrlf writes the file CRLF).
l4_registry_rows() {
    tr -d '\r' < "$L4_REGISTRY" | grep -v -e '^#' -e '^[[:space:]]*$' | tail -n +2
}

# The shell function a scenario file defines for a registry name:
# `scenario_` followed by the name with every `.` and `-` turned into
# `_` (12.2-iv1-bind-and-release-within-5s is
# scenario_12_2_iv1_bind_and_release_within_5s).
l4_function_name() {
    printf 'scenario_%s' "$1" | tr '.-' '__'
}

# ---- Scenario API ----------------------------------------------------
# The driver calls `scenario <name>` before the scenario's function and
# gives it a fresh L4_VERDICT_FILE. The function ends with exactly one
# of `pass`, `fail` or `partial`. `fail` returns 1, so under the
# driver's `set -e` it also ends the function.

scenario() {
    L4_CURRENT="$1"
    echo ""
    echo "--- L4 scenario ${L4_CURRENT} (profile ${L4_PROFILE}) ---"
}

l4_verdict() {
    local status="$1"
    shift
    local detail
    detail=$(printf '%s' "$*" | tr '\r\n\t' '   ')
    echo "L4-SCENARIO ${L4_CURRENT} ${status} ${detail:--}"
    echo "$status" >> "$L4_VERDICT_FILE"
}

pass() {
    l4_verdict PASS "$@"
}

fail() {
    l4_verdict FAIL "$@"
    return 1
}

# `partial <note>`: the part of the IV the note names is not automated
# (Story 12.12 D-d). Only rows whose level is `partial` may report it.
partial() {
    if [ $# -eq 0 ] || [ -z "$*" ]; then
        l4_verdict FAIL "partial called without the note naming what is not automated"
        return 1
    fi
    l4_verdict PARTIAL "$@"
}

# ---- Management API, from inside the client --------------------------
# `l4_api <METHOD> <PATH> [JSON]` prints the response body and fails
# (exit 22) on a status outside 2xx; `l4_api_status` prints the status
# alone, for scenarios asserting a refusal. The session lives in the
# client's /tmp for the life of the profile: the first call logs in
# with the bootstrap password, changing it when the node requires it.
# The script runs in the client's bash, so it is one literal string.
L4_API_SCRIPT='
set -eu
mode=$1; method=$2; path=$3; body=${4-}
api=https://l4-node:9443
jar=/tmp/l4-api-session
pwfile=/tmp/l4-api-password
login() {
    pw=$(cat "$pwfile" 2>/dev/null || tr -d "[:space:]" < /shared/admin_password)
    out=$(mktemp); hdr=$(mktemp)
    code=$(curl -s -o "$out" -D "$hdr" -w "%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -d "$(jq -nc --arg pw "$pw" "{username:\"admin\",password:\$pw}")" \
        "$api/api/v1/auth/login")
    if [ "$code" != 200 ]; then
        echo "l4_api: login refused (HTTP $code)" >&2
        exit 1
    fi
    grep -io "lorica_session=[^;]*" "$hdr" | head -n 1 > "$jar"
    if [ "$(jq -r .data.must_change_password "$out")" = true ]; then
        new="L4-harness-Pw!42"
        code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -b "$(cat "$jar")" \
            -H "Content-Type: application/json" \
            -d "$(jq -nc --arg cur "$pw" --arg new "$new" "{current_password:\$cur,new_password:\$new}")" \
            "$api/api/v1/auth/password")
        if [ "$code" != 200 ]; then
            echo "l4_api: password change refused (HTTP $code)" >&2
            exit 1
        fi
        printf "%s" "$new" > "$pwfile"
        login
    fi
    rm -f "$out" "$hdr"
}
request() {
    if [ -n "$body" ]; then
        curl -s -o "$resp" -w "%{http_code}" -X "$method" -b "$(cat "$jar")" \
            -H "Content-Type: application/json" -d "$body" "$api$path"
    else
        curl -s -o "$resp" -w "%{http_code}" -X "$method" -b "$(cat "$jar")" "$api$path"
    fi
}
resp=$(mktemp)
[ -s "$jar" ] || login
code=$(request)
if [ "$code" = 401 ]; then
    login
    code=$(request)
fi
if [ "$mode" = status ]; then
    echo "$code"
    exit 0
fi
cat "$resp"
echo
case "$code" in
    2??) ;;
    *) echo "l4_api: $method $path answered HTTP $code" >&2; exit 22 ;;
esac
'

l4_api() {
    l4_client bash -c "$L4_API_SCRIPT" l4_api body "$@"
}

l4_api_status() {
    l4_client bash -c "$L4_API_SCRIPT" l4_api status "$@"
}
