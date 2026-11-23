# shellcheck shell=bash
# Story 12.2 scenarios (Story 12.12 Lot B, the items of Story 12.2 Lot H).
# Sourced by l4/run-l4.sh; see that file for the scenario contract.
# Its own helpers are `l4b_*`; the shared `l4s_*` helpers are l4/lib.sh's.

# The session cookie of the client's API session, for a probe script
# that calls the API from inside the node's namespace.
l4b_cookie() {
    l4_api GET /api/v1/streams >/dev/null
    l4_client cat /tmp/l4-api-session | tr -d '\r\n'
}

# ---- The probe's timed API scripts -----------------------------------
# Both run in the probe, which shares the node's network namespace: the
# API on the node's loopback (the client's session cookie), `ss` on the
# node's sockets, one clock from the request to the socket's change.

# Create the stream, then poll `ss -ltn` until its port listens:
# prints `id=<id> ms=<elapsed>`, exit 1 past the limit.
L4B_PROBE_CREATE_SCRIPT='
cookie=$1 port=$2 body=$3 limit_ms=$4
t0=${EPOCHREALTIME/./}
resp=$(curl -s -w "\n%{http_code}" -b "$cookie" -H "Content-Type: application/json" \
    -d "$body" https://127.0.0.1:19443/api/v1/streams)
code=${resp##*$'"'"'\n'"'"'}
json=${resp%$'"'"'\n'"'"'*}
if [ "$code" != 201 ]; then
    echo "create answered $code: $json"
    exit 1
fi
id=$(printf "%s" "$json" | jq -r .data.id)
while [ -z "$(ss -ltnH "sport = :$port")" ]; do
    ms=$(( (${EPOCHREALTIME/./} - t0) / 1000 ))
    if [ "$ms" -ge "$limit_ms" ]; then
        echo "id=$id ms=$ms (not listening)"
        exit 1
    fi
    sleep 0.05
done
echo "id=$id ms=$(( (${EPOCHREALTIME/./} - t0) / 1000 ))"
'

# Delete the stream, then poll until no socket listens on its port.
L4B_PROBE_DELETE_SCRIPT='
cookie=$1 port=$2 id=$3 limit_ms=$4
t0=${EPOCHREALTIME/./}
code=$(curl -s -o /dev/null -w "%{http_code}" -b "$cookie" -X DELETE \
    "https://127.0.0.1:19443/api/v1/streams/$id")
case "$code" in
    2??) ;;
    *) echo "delete answered $code"; exit 1 ;;
esac
while [ -n "$(ss -ltnH "sport = :$port")" ]; do
    ms=$(( (${EPOCHREALTIME/./} - t0) / 1000 ))
    if [ "$ms" -ge "$limit_ms" ]; then
        echo "ms=$ms (still listening)"
        exit 1
    fi
    sleep 0.05
done
echo "ms=$(( (${EPOCHREALTIME/./} - t0) / 1000 ))"
'

# ---- IV1 -------------------------------------------------------------

# IV1: an HTTP loop runs throughout; a TCP stream created on 5432
# through the API listens (`ss -ltn` in the node's namespace) within
# 5 s and accepts a connection; deleted, it stops listening within 5 s;
# the supervisor never restarted and the loop saw zero failures.
scenario_12_2_iv1_bind_and_release_within_5s() {
    local port=5432 probe cookie sup_before sup_after created deleted id loop
    trap 'l4s_cleanup_streams l4s-iv1-; l4_client touch /tmp/loop-iv1.stop >/dev/null 2>&1 || true' EXIT
    l4s_cleanup_streams l4s-iv1-
    l4s_http_ready
    probe=$(l4s_probe_service)
    sup_before=$(l4s_supervisor_pid)
    l4s_loop_start iv1
    sleep 1
    cookie=$(l4b_cookie)

    created=$(l4_compose exec -T "$probe" bash -c "$L4B_PROBE_CREATE_SCRIPT" l4s "$cookie" "$port" \
        "{\"name\":\"l4s-iv1-pg\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":${port}}" \
        5000 | tr -d '\r') || fail "create on :${port}: ${created}"
    id=${created#id=}
    id=${id%% *}

    l4_client python3 -c "
import socket
with socket.create_connection(('l4-node', ${port}), timeout=3):
    pass
" || fail "a TCP connect to l4-node:${port} was not accepted"

    deleted=$(l4_compose exec -T "$probe" bash -c "$L4B_PROBE_DELETE_SCRIPT" l4s "$cookie" "$port" "$id" 5000 \
        | tr -d '\r') || fail "delete of :${port}: ${deleted}"

    sleep 1
    loop=$(l4s_loop_stop iv1)
    sup_after=$(l4s_supervisor_pid)
    [ -n "$sup_before" ] && [ "$sup_before" = "$sup_after" ] \
        || fail "the Lorica process changed (pid ${sup_before} then ${sup_after})"
    case "$loop" in
        *" failed=0 "*) ;;
        *) fail "the HTTP loop saw failures: ${loop}" ;;
    esac
    case "$loop" in
        sent=0\ *) fail "the HTTP loop sent nothing: ${loop}" ;;
    esac
    pass "listening ${created#* } after create, released ${deleted} after delete, connect accepted, pid ${sup_after} unchanged, HTTP loop ${loop%% errors=*}"
}

# ---- IV2 -------------------------------------------------------------

# A process outside Lorica holding a TCP port in the node's namespace.
L4B_SQUATTER='import socket, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 6000))
s.listen()
time.sleep(3600)
'

# IV2: a squatter holds 6000 in Lorica's namespace; a stream on 6000 is
# failed with `address_in_use` and the OS error, a `stream.bind_failed`
# audit row is written, HTTP still answers 200; once the squatter goes,
# the stream is bound within the retry interval (10 s) plus 5 s.
scenario_12_2_iv2_port_in_use_fails_cleanly() {
    local probe id failed audit http bound
    probe=$(l4s_probe_service)
    trap 'l4s_cleanup_streams l4s-iv2-; l4_compose exec -T '"$probe"' pkill -f l4s-squatter >/dev/null 2>&1 || true' EXIT
    l4s_cleanup_streams l4s-iv2-
    l4s_http_ready
    l4_compose exec -T "$probe" pkill -f l4s-squatter >/dev/null 2>&1 || true
    l4_compose exec -d "$probe" python3 -c "$L4B_SQUATTER" l4s-squatter
    local i
    for i in $(seq 1 50); do
        [ -n "$(l4s_probe ss -ltnH 'sport = :6000' | tr -d '\r')" ] && break
        sleep 0.2
    done
    [ -n "$(l4s_probe ss -ltnH 'sport = :6000' | tr -d '\r')" ] || fail "the squatter does not listen on 6000"

    id=$(l4s_create_stream '{"name":"l4s-iv2-squatted","protocol":"tcp","listen_address":"0.0.0.0","port_first":6000}') || fail "stream create refused: ${id}"
    failed=$(l4s_wait_bind "$id" failed 10) || fail "the stream on a squatted port is not failed: ${failed}"
    case "$failed" in
        *'"kind":"address_in_use"'*'Address already in use'*|*'Address already in use'*'"kind":"address_in_use"'*) ;;
        *) fail "failed without address_in_use and the OS error: ${failed}" ;;
    esac

    audit=$(l4s_client_script '
        api GET "/api/v1/audit?action=stream.bind_failed&limit=100" |
            jq -r --arg id "$1" "[.data.entries[] | select((. | tostring) | contains(\$id))] | length"
    ' "$id" | tr -d '\r') || fail "audit read failed: ${audit}"
    [ "${audit:-0}" -ge 1 ] || fail "no stream.bind_failed audit row for ${id}"

    http=$(l4_client sh -c 'python3 /tests/l4/http_loop.py get --target l4-node:8080 --host-header "$1" | jq -r .status' \
        l4s "$L4S_HTTP_HOST" | tr -d '\r')
    [ "$http" = 200 ] || fail "HTTP answered ${http} while the stream was failed"

    l4_compose exec -T "$probe" pkill -f l4s-squatter
    bound=$(l4s_wait_bind "$id" bound 15) || fail "not bound within 15 s of the squatter leaving: ${bound}"
    pass "failed ${failed#* }; ${audit} bind_failed audit row(s); HTTP 200; bound ${bound%% *} ms after the squatter left"
}

# ---- AC #3 -----------------------------------------------------------

# AC #3 (partial): a stream on port 853 binds while Lorica runs as the
# unprivileged `lorica` user with CAP_NET_BIND_SERVICE ambient, set by
# setpriv as systemd's AmbientCapabilities= would. The namespace's
# unprivileged-port floor is 1024, so a process without the capability
# cannot bind 853: checked as the probe's unprivileged user.
scenario_12_2_ac3_privileged_port_853() {
    local id bound sup capamb uid denied
    trap 'l4s_cleanup_streams l4s-ac3-' EXIT
    l4s_cleanup_streams l4s-ac3-
    sup=$(l4s_supervisor_pid)
    capamb=$(l4s_probe awk '/^CapAmb/ {print $2}' "/proc/${sup}/status" | tr -d '\r')
    uid=$(l4s_probe awk '/^Uid/ {print $2}' "/proc/${sup}/status" | tr -d '\r')
    [ "$uid" != 0 ] || fail "Lorica runs as root, so the check proves nothing"
    # CAP_NET_BIND_SERVICE is bit 10.
    [ $(( 16#${capamb} & 0x400 )) -ne 0 ] || fail "CAP_NET_BIND_SERVICE is not ambient on pid ${sup} (CapAmb ${capamb})"

    denied=$(l4s_probe su -s /bin/sh testuser -c 'python3 -c "
import socket
try:
    socket.socket().bind((\"0.0.0.0\", 853))
    print(\"bound\")
except PermissionError:
    print(\"denied\")
"' | tr -d '\r')
    [ "$denied" = denied ] || fail "an unprivileged process could bind 853 (${denied}): the check would pass without the capability"

    id=$(l4s_create_stream '{"name":"l4s-ac3-dot","protocol":"tcp","listen_address":"0.0.0.0","port_first":853}') || fail "stream create refused: ${id}"
    bound=$(l4s_wait_bind "$id" bound 5) || fail "the stream on 853 did not bind: ${bound}"
    [ -n "$(l4s_probe ss -ltnH 'sport = :853' | tr -d '\r')" ] || fail "853 bound per the API but not listening"
    partial "bound on 853 as uid ${uid} with CAP_NET_BIND_SERVICE ambient (CapAmb ${capamb}); an unprivileged process is refused 853 -- not automated: the packaged systemd unit is not booted in e2e, setpriv sets the capability as AmbientCapabilities= would"
}

# ---- AC #1, worker respawn -------------------------------------------

# Kills workers one at a time, each time waiting for the supervisor to
# respawn it, until the session sockets connected to the given backend
# port are gone, which identifies the worker that held the client's
# session. The probe cannot ask which worker owns a socket: it is root
# without CAP_SYS_PTRACE, and the workers, started with an ambient
# capability, are not dumpable, so their /proc/<pid>/fd is closed to it.
# Prints `victim=<pid> respawn_ms=<n> killed=<pids>`.
# Usage: <pids script> <dport>
L4B_KILL_SESSION_OWNER='import os, subprocess, sys, time
pids_script, dport = sys.argv[1], int(sys.argv[2])
def workers():
    out = subprocess.run(["bash", "-c", pids_script, "pids", "workers"],
                         capture_output=True, text=True).stdout
    return sorted(out.split())
def sessions():
    found = set()
    for table in ("/proc/net/udp", "/proc/net/udp6"):
        with open(table) as f:
            for line in list(f)[1:]:
                fields = line.split()
                if int(fields[2].rsplit(":", 1)[1], 16) == dport:
                    found.add(fields[9])
    return found
target = sessions()
if not target:
    print("no session socket towards the backend")
    sys.exit(1)
killed = []
for victim in workers():
    os.kill(int(victim), 9)
    killed.append(victim)
    t0 = time.monotonic()
    while True:
        now = workers()
        if victim not in now and len(now) == 2:
            break
        if time.monotonic() - t0 > 40:
            print(f"no respawn of {victim} within 40 s; workers {now}")
            sys.exit(1)
        time.sleep(0.1)
    if not target & sessions():
        ms = int((time.monotonic() - t0) * 1000)
        joined = "+".join(killed)
        print(f"victim={victim} respawn_ms={ms} killed={joined}")
        sys.exit(0)
print(f"the session outlived every worker: killed {killed}")
sys.exit(1)
'

# AC #1: a UDP stream on two workers; the worker serving a client is
# killed with SIGKILL; after the respawn `ss -uan` shows as many sockets
# on the port as before, and the same client (same source port, so the
# same SO_REUSEPORT slot) is served again. The stream keeps its sessions
# open past their answer (`unbounded_responses`, a 60 s idle timeout):
# the worker to kill is the one holding the client's session.
scenario_12_2_ac1_udp_group_survives_worker_respawn() {
    local port=7100 sport=41000 bid id before after served again respawn
    trap 'l4s_cleanup_streams l4s-ac1-' EXIT
    l4s_cleanup_streams l4s-ac1-
    l4s_echo_backends
    bid=$(l4s_create_backend "{\"address\":\"$(l4s_client_ip):${L4S_UDP_ECHO_PORT}\",\"health_check_enabled\":false}") || fail "backend create refused: ${bid}"
    id=$(l4s_create_stream "{\"name\":\"l4s-ac1-respawn\",\"protocol\":\"udp\",\"listen_address\":\"0.0.0.0\",\"port_first\":${port},\"backend_ids\":[\"${bid}\"],\"idle_timeout_s\":60,\"udp\":{\"source_session_cap\":64,\"unbounded_responses\":true}}") || fail "stream create refused: ${id}"
    l4s_wait_bind "$id" bound 5 >/dev/null || fail "the UDP stream did not bind"

    served=$(l4_client python3 /tests/l4/udp_hold.py ping --target "l4-node:${port}" --sport "$sport" --deadline 10 | tr -d '\r')
    case "$served" in *'"answered": true'*) ;; *) fail "the client was not served before the kill: ${served}" ;; esac

    before=$(l4s_probe ss -uanH "sport = :${port}" | tr -d '\r' | grep -c . || true)
    [ "$before" -eq 2 ] || fail "expected one socket per worker (2) on ${port}, ss shows ${before}"

    # Kill the worker that holds the client's session (and, if the first
    # killed was the other one, that one too).
    respawn=$(l4s_probe python3 -c "$L4B_KILL_SESSION_OWNER" "$L4S_PIDS_SCRIPT" "$L4S_UDP_ECHO_PORT" | tr -d '\r') || fail "${respawn}"

    after=$(l4s_probe ss -uanH "sport = :${port}" | tr -d '\r' | grep -c . || true)
    [ "$after" -eq "$before" ] || fail "the group shrank: ${before} sockets before the kill, ${after} after"

    again=$(l4_client python3 /tests/l4/udp_hold.py ping --target "l4-node:${port}" --sport "$sport" --deadline 20 | tr -d '\r')
    case "$again" in *'"answered": true'*) ;; *) fail "the client is not served after the respawn: ${again}" ;; esac
    pass "${respawn}; ${after} sockets on ${port} before and after; client from :${sport} served again (${again})"
}

# ---- AC #1, dual stack -----------------------------------------------

# A stream on [::]:7000 refuses a second one on 0.0.0.0:7000, and IPv4
# and IPv6 clients both reach the first (through to its echo backend).
scenario_12_2_ac1_dual_stack_conflict() {
    local port=7000 bid id second reach
    trap 'l4s_cleanup_streams l4s-ds-' EXIT
    l4s_cleanup_streams l4s-ds-
    l4s_echo_backends
    bid=$(l4s_create_backend "{\"address\":\"$(l4s_client_ip):${L4S_TCP_ECHO_PORT}\",\"health_check_enabled\":false}") || fail "backend create refused: ${bid}"
    id=$(l4s_create_stream "{\"name\":\"l4s-ds-dual\",\"protocol\":\"tcp\",\"listen_address\":\"::\",\"port_first\":${port},\"backend_ids\":[\"${bid}\"]}") || fail "stream create refused: ${id}"
    l4s_wait_bind "$id" bound 5 >/dev/null || fail "the [::] stream did not bind"

    second=$(l4s_client_script 'api_try POST /api/v1/streams "$1" | tr "\n" " "' \
        "{\"name\":\"l4s-ds-v4\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":${port}}" | tr -d '\r')
    case "$second" in
        409\ *stream_port_conflict*) ;;
        *) fail "a second stream on 0.0.0.0:${port} was not refused 409 stream_port_conflict: ${second}" ;;
    esac

    reach=$(l4_client python3 -c "
import socket
out = []
for family, name in ((socket.AF_INET, 'IPv4'), (socket.AF_INET6, 'IPv6')):
    addr = socket.getaddrinfo('l4-node', ${port}, family, socket.SOCK_STREAM)[0][4]
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect(addr)
        s.sendall(b'hello ' + name.encode())
        reply = s.recv(64)
    if reply != b'hello ' + name.encode():
        raise SystemExit(f'{name} {addr[0]}: echo {reply!r}')
    out.append(f'{name} {addr[0]}')
print(', '.join(out))
" 2>&1 | tr -d '\r') || fail "a client did not reach the [::] stream: ${reach}"
    pass "0.0.0.0:${port} refused (${second:0:60}...); echoed through [::]:${port} for ${reach}"
}

# ---- AC #7, the stop path --------------------------------------------

# Sends SIGTERM to the supervisor from the probe and prints the time it
# was sent (CLOCK_REALTIME, seconds with microseconds).
L4B_PROBE_TERM_SCRIPT='
sup=$(bash -c "$1" pids top)
[ -n "$sup" ] || { echo "no lorica process"; exit 1; }
echo "$EPOCHREALTIME"
kill -TERM "$sup"
'

# Wait for the node's container to exit and print its exit time as
# seconds since the epoch (Docker's FinishedAt, the VM clock); return 1
# if it still runs after 70 s.
l4b_wait_exited() {
    local cid i finished
    cid=$(l4_compose ps -aq "$L4_NODE" | tr -d '\r')
    for i in $(seq 1 700); do
        [ "$(docker inspect -f '{{.State.Running}}' "$cid" | tr -d '\r')" = false ] && break
        sleep 0.1
    done
    if [ "$(docker inspect -f '{{.State.Running}}' "$cid" | tr -d '\r')" != false ]; then
        echo "${L4_NODE} still runs 70 s after SIGTERM"
        return 1
    fi
    finished=$(docker inspect -f '{{.State.FinishedAt}}' "$cid" | tr -d '\r')
    l4_client python3 -c "
import datetime, re, sys
stamp = re.sub(r'(\.\d{6})\d*', r'\1', sys.argv[1]).replace('Z', '+00:00')
print(f'{datetime.datetime.fromisoformat(stamp).timestamp():.6f}')
" "$finished" | tr -d '\r'
}

# AC #7: with no traffic, SIGTERM ends the process in under 10 s; with
# worker_drain_timeout_s = 20 and an HTTP request to a backend answering
# after 8 s, the request completes and the process exits shortly after
# it (within 3 s), before 20 s.
scenario_12_2_ac7_stop_drains_then_exits() {
    local probe quiet term finished idle req sent done status held exit_after
    trap 'l4_api PUT /api/v1/settings "{\"worker_drain_timeout_s\":30}" >/dev/null 2>&1 || true' EXIT
    probe=$(l4s_probe_service)
    l4s_http_ready

    # "No traffic" includes what earlier scenarios left draining: a
    # deleted stream's sessions drain for worker_drain_timeout_s, and a
    # stop rightly waits for them. Wait until the node holds no stream
    # connection or session (connected UDP sockets, TCP connections
    # outside the management API, its forwarder and the HTTP route's
    # upstream pool).
    quiet=$(l4_compose exec -T "$probe" bash -c '
        t0=${EPOCHREALTIME/./}
        while :; do
            udp=$(ss -Hua state established | grep -c . || true)
            tcp=$(ss -Htn state established "( not sport = :19443 and not dport = :19443 and not sport = :9443 and not dport = :8000 )" | grep -c . || true)
            ms=$(( (${EPOCHREALTIME/./} - t0) / 1000 ))
            if [ "$udp" = 0 ] && [ "$tcp" = 0 ]; then echo "$ms"; exit 0; fi
            if [ "$ms" -ge 45000 ]; then echo "udp=$udp tcp=$tcp after ${ms} ms"; exit 1; fi
            sleep 0.5
        done' | tr -d '\r') || fail "the node never went quiet before the stop: ${quiet}"

    term=$(l4_compose exec -T "$probe" bash -c "$L4B_PROBE_TERM_SCRIPT" l4s "$L4S_PIDS_SCRIPT" | tr -d '\r')
    finished=$(l4b_wait_exited) || fail "${finished}"
    idle=$(l4s_seconds_between "$term" "$finished")
    l4s_restart_node
    l4s_less_than "$idle" 10 || fail "with no traffic the stop took ${idle} s"

    l4_api PUT /api/v1/settings '{"worker_drain_timeout_s":20}' >/dev/null
    l4s_http_ready
    l4_client rm -f /tmp/l4s-slow.json
    l4_compose exec -d streams-client python3 /tests/l4/http_loop.py get --target l4-node:8080 \
        --host-header "$L4S_HTTP_HOST" --path /delay/8 --timeout 30 --out /tmp/l4s-slow.json
    sleep 2
    term=$(l4_compose exec -T "$probe" bash -c "$L4B_PROBE_TERM_SCRIPT" l4s "$L4S_PIDS_SCRIPT" | tr -d '\r')
    finished=$(l4b_wait_exited) || fail "${finished}"
    req=$(l4_client cat /tmp/l4s-slow.json | tr -d '\r')
    l4s_restart_node
    l4_api PUT /api/v1/settings '{"worker_drain_timeout_s":30}' >/dev/null

    sent=$(printf '%s' "$req" | l4_client jq -r .sent | tr -d '\r')
    done=$(printf '%s' "$req" | l4_client jq -r .done | tr -d '\r')
    status=$(printf '%s' "$req" | l4_client jq -r .status | tr -d '\r')
    [ "$status" = 200 ] || fail "the in-flight request did not complete across the stop: ${req}"
    held=$(l4s_seconds_between "$sent" "$done")
    l4s_less_than 7.5 "$held" || fail "the request answered in ${held} s, not after its 8 s"
    exit_after=$(l4s_seconds_between "$done" "$finished")
    l4s_less_than -0.5 "$exit_after" || fail "the process exited ${exit_after} s after the request: before it"
    l4s_less_than "$exit_after" 3 || fail "the process exited ${exit_after} s after the request completed, not shortly after"
    local total
    total=$(l4s_seconds_between "$term" "$finished")
    l4s_less_than "$total" 20 || fail "the drain took ${total} s, past worker_drain_timeout_s = 20"
    pass "idle stop ${idle} s; with a request in flight: answered 200 after ${held} s, process exited ${exit_after} s later, ${total} s after SIGTERM"
}

# ---- AC #5, the budget -----------------------------------------------

# On a node whose fd limit is 4096 (S = 4096 - 1024 - 2048 = 1024), a
# 1,024-port UDP range is refused with the budget named, and a range
# whose sockets fit one worker but not the supervisor (one socket per
# worker per UDP port) is refused naming the supervisor constraint. A
# range that fits is accepted, so the refusals are the budget's.
#
# The story item reads "a 1,024-port UDP range refused with the
# supervisor constraint named", written before Story 12.5 gave a UDP
# session one fd: a 1,024-port range now needs 1,024 listening sockets
# plus at least one session in one worker, 1,025 > 1,024, and the worker
# constraint is checked first. The 600-port range keeps the item's point.
scenario_12_2_ac5_budget_refuses_range() {
    local node=lorica-budget-4k budget full sup fits
    l4s_wait_ready "$node"
    L4S_API_SCRIPT=$(l4s_node_api_script "$node")
    budget=$(l4s_client_script 'api GET /api/v1/streams/budget | jq -c ".data.nodes[0] | {fd_limit, stream_budget, worker_count}"' | tr -d '\r')
    [ "$budget" = '{"fd_limit":4096,"stream_budget":1024,"worker_count":2}' ] \
        || fail "unexpected budget on ${node}: ${budget}"

    local range='"protocol":"udp","listen_address":"0.0.0.0","udp":{"max_sessions":1,"source_session_cap":1}'
    full=$(l4s_client_script 'api_try POST /api/v1/streams "$1" | tr "\n" " "' \
        "{\"name\":\"l4s-ac5-full\",${range},\"port_first\":20000,\"port_last\":21023}" | tr -d '\r')
    case "$full" in
        422\ *stream_fd_budget*) ;;
        *) fail "a 1,024-port UDP range was not refused for the fd budget: ${full}" ;;
    esac
    sup=$(l4s_client_script 'api_try POST /api/v1/streams "$1" | tr "\n" " "' \
        "{\"name\":\"l4s-ac5-sup\",${range},\"port_first\":20000,\"port_last\":20599}" | tr -d '\r')
    case "$sup" in
        422\ *stream_fd_budget*supervisor_fds*) ;;
        *) fail "a 600-port UDP range was not refused on supervisor_fds: ${sup}" ;;
    esac
    fits=$(l4s_client_script 'api_try POST /api/v1/streams "$1" | head -n 1' \
        "{\"name\":\"l4s-ac5-fits\",${range},\"port_first\":20000,\"port_last\":20099}" | tr -d '\r')
    [ "$fits" = 2xx ] || fail "a 100-port UDP range that fits was refused: ${fits}"
    pass "fd limit 4096, S 1024, 2 workers; 1,024 ports refused $(printf '%s' "$full" | grep -o '([a-z_]*)' | head -n 1); 600 ports refused (supervisor_fds); 100 ports accepted"
}
