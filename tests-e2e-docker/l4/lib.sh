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

# Wait until the node of the profile being run answers its management
# API and has written its bootstrap password; 1 after 120 s.
l4_wait_for_node() {
    local i
    for i in $(seq 1 60); do
        if l4_node sh -c 'test -s /shared/admin_password && curl -skf https://127.0.0.1:19443/ >/dev/null' >/dev/null 2>&1; then
            echo "${L4_NODE} is ready."
            return 0
        fi
        sleep 2
    done
    echo "ERROR: ${L4_NODE} did not start within 120s"
    return 1
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

# ---- Shared scenario helpers (`l4s_*`) --------------------------------
# Every helper more than one scenario file uses lives here, so a
# scenario file runs with lib.sh and itself alone. A file's own
# helpers keep a prefix of its own (`l4b_*` in 12.2.sh, `l4c_*` in
# 12.3.sh, ...); one that a second file starts to use moves here as
# `l4s_*`. l4_check_scenario_files enforces it. Each in-container
# script is a literal string run by `bash -c` in one container
# command, so a timed assertion keeps its timer inside the container
# (Story 12.12 D-c).

# The HTTP route every scenario that needs HTTP traffic uses: a backend
# served by test-runner/l4/http_loop.py in the client, on this port.
L4S_HTTP_HOST=l4-http.test
L4S_HTTP_PORT=8000
# The UDP and TCP echo backends in the client.
L4S_UDP_ECHO_PORT=9100
L4S_TCP_ECHO_PORT=9000

# Prepended to a client script: `api METHOD PATH [BODY]` (the body on
# stdout, exit 22 on a status outside 2xx) and `api_try METHOD PATH
# [BODY]` (prints `<status>` then the body on the next line, never
# fails), both over the l4/lib.sh API script given as the script's
# first argument, both waiting out a 429 of the management API's rate
# limits instead of failing on it.
L4S_PRELUDE='
set -euo pipefail
API_SCRIPT=$1
shift
api_try() {
    local i err out code
    for i in $(seq 1 30); do
        err=$(mktemp)
        if out=$(bash -c "$API_SCRIPT" l4_api body "$@" 2>"$err"); then
            rm -f "$err"
            printf "2xx\n%s\n" "$out"
            return 0
        fi
        code=$(grep -o "answered HTTP [0-9]*" "$err" | grep -o "[0-9]*$" || true)
        if [ "$code" = 429 ]; then
            rm -f "$err"
            sleep 3
            continue
        fi
        if [ -z "$code" ]; then
            code="error: $(tr "\n" " " < "$err")"
        fi
        rm -f "$err"
        printf "%s\n%s\n" "$code" "$out"
        return 0
    done
    printf "429\nstill rate-limited after 90 s\n"
}
api() {
    local res
    res=$(api_try "$@")
    if [ "${res%%$'"'"'\n'"'"'*}" != 2xx ]; then
        echo "api $1 $2: ${res//$'"'"'\n'"'"'/ }" >&2
        return 22
    fi
    printf "%s\n" "${res#*$'"'"'\n'"'"'}"
}
now_us() {
    echo "${EPOCHREALTIME/./}"
}
'

# Run a script in the client with the prelude: l4s_client_script
# <script> [args...]. The API script is l4/lib.sh's, which talks to
# l4-node; l4s_node_api_script gives one for another node.
l4s_client_script() {
    local script="$1"
    shift
    l4_client bash -c "${L4S_PRELUDE}${script}" l4s "${L4S_API_SCRIPT:-$L4_API_SCRIPT}" "$@"
}

# The lib.sh API script, aimed at another node of the project: its own
# address, its own session files in the client, and the bootstrap
# password the host reads from the node and leaves in the client.
# Usage: L4S_API_SCRIPT=$(l4s_node_api_script <service>)
l4s_node_api_script() {
    local node="$1" script pw
    pw=$(l4_compose exec -T "$node" cat /shared/admin_password | tr -d '\r\n')
    printf '%s' "$pw" | l4_compose exec -T streams-client sh -c "cat > /tmp/l4s-${node}-initial"
    script=${L4_API_SCRIPT//https:\/\/l4-node:9443/https://${node}:9443}
    script=${script//\/tmp\/l4-api-session/\/tmp\/l4s-${node}-session}
    script=${script//\/tmp\/l4-api-password/\/tmp\/l4s-${node}-password}
    script=${script//\/shared\/admin_password/\/tmp\/l4s-${node}-initial}
    printf '%s' "$script"
}

# Wait until another node of the project answers its management API.
l4s_wait_ready() {
    local node="$1" i
    for i in $(seq 1 60); do
        if l4_compose exec -T "$node" sh -c 'test -s /shared/admin_password && curl -skf https://127.0.0.1:19443/ >/dev/null' >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    fail "${node} did not answer its management API within 120 s"
}

# The probe of the profile being run: in the node's network and pid
# namespaces.
l4s_probe_service() {
    case "$L4_PROFILE" in
        streams-single) echo streams-single-probe ;;
        *) echo streams-probe ;;
    esac
}

l4s_probe() {
    l4_compose exec -T "$(l4s_probe_service)" "$@"
}

# The supervisor (or the single process): the `lorica` process whose
# parent is not one. Busybox ps, by comm (see 12.12.sh's self-test).
L4S_PIDS_SCRIPT='
ps -o pid,ppid,comm | awk -v want="$1" '"'"'
    $3 == "lorica" { parent[$1] = $2 }
    END {
        for (p in parent) {
            top = !(parent[p] in parent)
            if ((want == "top" && top) || (want == "workers" && !top)) print p
        }
    }'"'"'
'

l4s_supervisor_pid() {
    l4s_probe bash -c "$L4S_PIDS_SCRIPT" pids top | tr -d '\r'
}

l4s_worker_pids() {
    l4s_probe bash -c "$L4S_PIDS_SCRIPT" pids workers | tr -d '\r' | sort -n | tr '\n' ' '
}

# The client's own IPv4 address on the `l4` network.
l4s_client_ip() {
    l4_client python3 -c 'import socket; print(socket.gethostbyname(socket.gethostname()))' | tr -d '\r'
}

# Start a long-running tool in the client unless something already
# listens on its port: l4s_client_daemon <proto tcp|udp> <port> <cmd...>
l4s_client_daemon() {
    local proto="$1" port="$2" flag=-ltnH i
    shift 2
    [ "$proto" = udp ] && flag=-lunH
    if [ -n "$(l4_client ss "$flag" "sport = :${port}" | tr -d '\r')" ]; then
        return 0
    fi
    l4_compose exec -d streams-client "$@"
    for i in $(seq 1 50); do
        [ -n "$(l4_client ss "$flag" "sport = :${port}" | tr -d '\r')" ] && return 0
        sleep 0.2
    done
    fail "the client's ${proto} ${port} service did not start: $*"
}

l4s_echo_backends() {
    l4s_client_daemon udp "$L4S_UDP_ECHO_PORT" python3 /tests/l4/udp_hold.py serve --port "$L4S_UDP_ECHO_PORT"
    l4s_client_daemon tcp "$L4S_TCP_ECHO_PORT" socat "TCP-LISTEN:${L4S_TCP_ECHO_PORT},fork,reuseaddr" EXEC:cat
}

# The HTTP backend in the client and, on the node the API script
# targets, a route `l4-http.test` to it; returns once the route answers
# 200 through the node's HTTP listener (`l4s_http_ready [<node host>]`).
L4S_HTTP_ROUTE_SCRIPT='
host=$1 backend=$2 node=$3
if ! api GET /api/v1/routes | jq -e --arg h "$host" ".data.routes[] | select(.hostname == \$h)" >/dev/null; then
    bid=$(api POST /api/v1/backends "{\"address\":\"$backend\",\"health_check_enabled\":false}" | jq -r .data.id)
    api POST /api/v1/routes "{\"hostname\":\"$host\",\"backend_ids\":[\"$bid\"]}" >/dev/null
fi
for i in $(seq 1 100); do
    status=$(python3 /tests/l4/http_loop.py get --target "$node:8080" --host-header "$host" --timeout 2 | jq -r .status)
    [ "$status" = 200 ] && exit 0
    sleep 0.2
done
echo "route $host on $node never answered 200 (last: $status)" >&2
exit 1
'

l4s_http_ready() {
    local node="${1:-l4-node}"
    l4s_client_daemon tcp "$L4S_HTTP_PORT" python3 /tests/l4/http_loop.py serve --port "$L4S_HTTP_PORT"
    l4s_client_script "$L4S_HTTP_ROUTE_SCRIPT" "$L4S_HTTP_HOST" "$(l4s_client_ip):${L4S_HTTP_PORT}" "$node"
}

# A detached HTTP loop in the client (50 new connections per second to
# the route), stopped and read by l4s_loop_stop. Usage: l4s_loop_start
# <tag> [<node host>]
l4s_loop_start() {
    local tag="$1" node="${2:-l4-node}"
    l4_client rm -f "/tmp/loop-${tag}.stop" "/tmp/loop-${tag}.json"
    l4_compose exec -d streams-client python3 /tests/l4/http_loop.py loop \
        --target "${node}:8080" --host-header "$L4S_HTTP_HOST" --rate 50 \
        --stop-file "/tmp/loop-${tag}.stop" --out "/tmp/loop-${tag}.json"
}

# Prints `sent=<n> failed=<n> errors=<json>`.
l4s_loop_stop() {
    local tag="$1"
    l4_client bash -c '
        touch "/tmp/loop-$1.stop"
        for i in $(seq 1 100); do
            [ -s "/tmp/loop-$1.json" ] && break
            sleep 0.1
        done
        jq -r "\"sent=\(.sent) failed=\(.failed) errors=\(.errors|tojson)\"" "/tmp/loop-$1.json"
    ' l4s "$tag" | tr -d '\r'
}

# Delete every stream whose name starts with a prefix, on l4-node.
L4S_CLEANUP_SCRIPT='
api GET /api/v1/streams | jq -r --arg p "$1" ".data.streams[] | select(.name | startswith(\$p)) | .id" |
while read -r id; do
    api DELETE "/api/v1/streams/$id" >/dev/null || true
done
'

l4s_cleanup_streams() {
    l4s_client_script "$L4S_CLEANUP_SCRIPT" "$1" >/dev/null 2>&1 || true
}

# Poll a stream's bind state in the client until it is <state>, within
# <seconds>: prints `<elapsed ms> <bind json>`; exit 1 on a timeout.
L4S_WAIT_BIND_SCRIPT='
id=$1 want=$2 limit_ms=$(( $3 * 1000 ))
t0=$(now_us)
while :; do
    bind=$(api GET "/api/v1/streams/$id" | jq -c .data.bind)
    elapsed=$(( ($(now_us) - t0) / 1000 ))
    if [ "$(printf "%s" "$bind" | jq -r ".state // empty")" = "$want" ]; then
        echo "$elapsed $bind"
        exit 0
    fi
    if [ "$elapsed" -ge "$limit_ms" ]; then
        echo "$elapsed $bind"
        exit 1
    fi
    sleep 0.2
done
'

l4s_wait_bind() {
    l4s_client_script "$L4S_WAIT_BIND_SCRIPT" "$@" | tr -d '\r'
}

# Create a stream (a backend) through the API script in use and print
# its id; on a refusal, print the refusal and return 1. Helpers whose
# output a scenario captures never call `fail` themselves: the verdict
# line would land in the variable. Usage: id=$(l4s_create_stream
# <json>) || fail "...: ${id}"
l4s_create_stream() {
    l4s_client_script 'api POST /api/v1/streams "$1" | jq -r .data.id' "$1" 2>&1 | tr -d '\r'
}

l4s_create_backend() {
    l4s_client_script 'api POST /api/v1/backends "$1" | jq -r .data.id' "$1" 2>&1 | tr -d '\r'
}

# A service's address on `l4`, from the client.
l4s_ip() {
    l4_client python3 -c 'import socket, sys; print(socket.gethostbyname(sys.argv[1]))' "$1" | tr -d '\r'
}

# A backend object for <address>, with an active TCP-connect check at
# the health loop's 5 s floor (a flip is confirmed after three probes,
# each bounded by a 5 s connect timeout: up to about 30 s), or none with
# `nocheck`. Prints its id, or the refusal and returns 1.
l4s_backend() {
    local check='"health_check_enabled":true,"health_check_interval_s":1'
    [ "${2:-}" = nocheck ] && check='"health_check_enabled":false'
    l4s_create_backend "{\"address\":\"$1\",${check}}"
}

# The count under one reason in a stream's live counters, refusals and
# ends together.
l4s_reason_count() {
    l4s_client_script '
        api GET /api/v1/streams/status | jq -r --arg id "$1" --arg r "$2" \
            "[.data.streams[] | select(.id == \$id) | .counters | (.refused // []) + (.ended // []) | .[] | select(.reason == \$r) | .count] | add // 0"
    ' "$1" "$2" | tr -d '\r'
}

# l4s_reason_count, polled for up to 5 s until it reaches <at least>:
# a connection's end is counted once its task has finished, a moment
# after the client saw the close. Prints the last count read.
l4s_wait_reason_count() {
    local i count=0
    for i in $(seq 1 25); do
        count=$(l4s_reason_count "$1" "$2")
        [ "${count:-0}" -ge "$3" ] && break
        sleep 0.2
    done
    echo "${count:-0}"
}

# Poll a backend's health_status until it reads <status>, within
# <seconds>; prints the elapsed milliseconds.
L4S_WAIT_HEALTH_SCRIPT='
id=$1 want=$2 limit_ms=$(( $3 * 1000 ))
t0=$(now_us)
while :; do
    got=$(api GET "/api/v1/backends/$id" | jq -r .data.health_status)
    elapsed=$(( ($(now_us) - t0) / 1000 ))
    [ "$got" = "$want" ] && { echo "$elapsed"; exit 0; }
    [ "$elapsed" -ge "$limit_ms" ] && { echo "$got after $elapsed ms"; exit 1; }
    sleep 0.2
done
'

l4s_wait_health() {
    l4s_client_script "$L4S_WAIT_HEALTH_SCRIPT" "$@" | tr -d '\r'
}

# The node's interface on `l4` and its prefix length, read in the probe:
# prints `<dev> <prefix>`. (The worker node is also on l4-dns.)
l4s_l4_interface() {
    l4s_probe ip -o -4 addr show | tr -d '\r' | awk -v ip="$1" '{ split($4, a, "/"); if (a[1] == ip) print $2, a[2] }'
}

# The address at <index> of a subnet, counted from the top as Python
# does with a negative index: one Docker has not handed out, on a
# network this lightly used.
l4s_subnet_address() {
    l4_client python3 -c 'import ipaddress, sys; print(ipaddress.ip_network(sys.argv[1], strict=False)[int(sys.argv[2])])' "$1" "$2" | tr -d '\r'
}

# The count of <name> in a `name=count ...` tally (0 when absent).
l4s_count() {
    local n
    n=$(printf '%s' "$1" | grep -o "\(^\| \)$2=[0-9]*" | cut -d= -f2)
    echo "${n:-0}"
}

# Start the node again after a stop, its probe with it (the probe's
# namespaces are the node's container's), and wait for the API.
l4s_restart_node() {
    l4_compose start "$L4_NODE" >/dev/null
    l4_compose restart "$(l4s_probe_service)" >/dev/null
    l4_wait_for_node >/dev/null || fail "${L4_NODE} did not come back after the stop"
}

l4s_seconds_between() {
    awk -v a="$1" -v b="$2" 'BEGIN { printf "%.3f", b - a }'
}

l4s_less_than() {
    awk -v a="$1" -v b="$2" 'BEGIN { exit !(a < b) }'
}

# jq in the client (the host has none) over a JSON text, CR stripped:
# l4s_jq <json> [jq options] <filter>.
l4s_jq() {
    local json="$1"
    shift
    printf '%s' "$json" | l4_client jq "$@" | tr -d '\r'
}

# One test-runner/l4 tool in a service, CR stripped: l4s_tool
# <service> <tool.py> [args...] (the tools print one JSON line).
l4s_tool() {
    local service="$1" tool="$2"
    shift 2
    l4_compose exec -T "$service" python3 "/tests/l4/${tool}" "$@" | tr -d '\r'
}

# ---- Scenario file check ---------------------------------------------
# `l4_check_scenario_files <file>...` sources lib.sh and one scenario
# file at a time in a fresh bash, and fails when a file names an
# `l4<x>_*` helper or an `L4<X>_*` constant that neither lib.sh nor the
# file defines or assigns: one it borrows from another scenario file,
# which works only while every file is sourced together. Prints the
# names per offending file. The driver's variables, set while a
# scenario runs, are exempt.
# shellcheck disable=SC2034 # read by the bash -c below, which sources this file
L4_RUNTIME_VARS="L4_PROFILE L4_NODE L4_CURRENT L4_VERDICT_FILE L4_LOTS L4_LANE L4S_API_SCRIPT"

l4_check_scenario_files() {
    local file missing status=0
    for file in "$@"; do
        missing=$(bash -c '
            . l4/lib.sh
            . "$1"
            for name in $(grep -oE "\b(l4[a-z]?_[a-z0-9_]+|L4[A-Z]?_[A-Z0-9_]+)\b" "$1" | sort -u); do
                case " $L4_RUNTIME_VARS " in *" $name "*) continue ;; esac
                grep -qE "\b${name}=" "$1" && continue
                case "$name" in
                    [A-Z]*) [ -n "${!name+set}" ] || printf "%s " "$name" ;;
                    *) declare -F "$name" > /dev/null || printf "%s " "$name" ;;
                esac
            done
        ' l4_check "$file")
        if [ -n "$missing" ]; then
            echo "${file}: not defined by l4/lib.sh or the file itself: ${missing}"
            status=1
        fi
    done
    return "$status"
}
