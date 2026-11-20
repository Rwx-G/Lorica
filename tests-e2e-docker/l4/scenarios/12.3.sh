# shellcheck shell=bash
# Story 12.3 scenarios (Story 12.12 Lot C: IV1 to IV4 and the TCP rows
# of the parity matrix, D-e). Sourced by l4/run-l4.sh; see that file for
# the scenario contract. The `l4s_*` helpers are l4/scenarios/12.2.sh's.
#
# Backends: three PostgreSQL servers and a `pg-client` for `psql` (IV1),
# test-runner/l4/tcp_backend.py in five services (an identity line then
# an echo, an HTTP 200 on a GET, SIGUSR1 closes its listener and SIGUSR2
# reopens it), CoreDNS for the re-resolution half of IV4. Each scenario
# creates its own backend objects and streams, on ports of its own
# (74xx), and deletes its streams at the end.

# A TCP client in the client container, standard library; every timed
# assertion runs inside one of its invocations. Subcommands:
#   ident <port> [v1|v2 <src>]   connect, optionally send a PROXY header
#                                carrying <src>, send a line, print the
#                                backend identity line (`closed` if the
#                                connection ended with nothing)
#   idents <port> <n>            n connections, a tally of the names
#   http <host header> <n>       n HTTP requests on l4-node:8080, a tally
#   held <port> <want> <stop> <out>
#                                connect until <want> answers, then echo a
#                                ping every 0.5 s until <stop> exists,
#                                keeping a JSON status in <out>
#   transfer <port> <bytes>      send <bytes> and read their echo; seconds
#   lifetime <port> <every>      send a line at once, then one every
#                                <every> s (0: never); seconds until EOF
L4C_TCP_CLIENT='import json, os, socket, struct, sys, threading, time
from collections import Counter

HOST = "l4-node"

def connect(port):
    s = socket.create_connection((HOST, port), timeout=10)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s

def read_line(s):
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(1)
        if not chunk:
            return None
        buf += chunk
    return buf.decode().strip()

def proxy_header(version, src):
    if version == "v1":
        return f"PROXY TCP4 {src} 192.0.2.1 40000 7400\r\n".encode()
    sig = b"\r\n\r\n\x00\r\nQUIT\n"
    body = socket.inet_aton(src) + socket.inet_aton("192.0.2.1") + struct.pack("!HH", 40000, 7400)
    return sig + bytes([0x21, 0x11]) + struct.pack("!H", len(body)) + body

def ident(port, version=None, src=None):
    try:
        with connect(port) as s:
            if version:
                s.sendall(proxy_header(version, src))
            s.sendall(b"hello\n")
            line = read_line(s)
            return line if line else "closed"
    except OSError as e:
        return f"error {type(e).__name__}"

def name_of(line):
    for field in line.split():
        if field.startswith("name="):
            return field[5:]
    return line.split()[0] if line else "none"

cmd, args = sys.argv[1], sys.argv[2:]
if cmd == "ident":
    print(ident(int(args[0]), *(args[1:3] if len(args) > 1 else ())))
elif cmd == "idents":
    tally = Counter(name_of(ident(int(args[0]))) for _ in range(int(args[1])))
    print(" ".join(f"{k}={v}" for k, v in sorted(tally.items())))
elif cmd == "http":
    tally = Counter()
    for _ in range(int(args[1])):
        try:
            with socket.create_connection((HOST, 8080), timeout=10) as s:
                s.sendall(f"GET / HTTP/1.1\r\nHost: {args[0]}\r\nConnection: close\r\n\r\n".encode())
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            head, _, body = data.partition(b"\r\n\r\n")
            status = head.split(b" ")[1].decode() if head else "none"
            tally[name_of(body.decode()) if status == "200" else f"status{status}"] += 1
        except OSError as e:
            tally[f"error{type(e).__name__}"] += 1
    print(" ".join(f"{k}={v}" for k, v in sorted(tally.items())))
elif cmd == "held":
    port, want, stop, out = int(args[0]), args[1], args[2], args[3]
    status = {"target": None, "pings": 0, "failures": 0, "error": None}
    def save():
        with open(out + ".tmp", "w") as f:
            json.dump(status, f)
        os.replace(out + ".tmp", out)
    for _ in range(50):
        s = connect(port)
        s.sendall(b"hello\n")
        line = read_line(s) or ""
        read_line(s)
        if name_of(line) == want:
            break
        s.close()
    else:
        status["error"] = f"never reached {want}"
        save()
        sys.exit(1)
    status["target"] = want
    save()
    n = 0
    while not os.path.exists(stop):
        n += 1
        try:
            s.sendall(f"ping {n}\n".encode())
            if read_line(s) == f"ping {n}":
                status["pings"] += 1
            else:
                status["failures"] += 1
        except OSError as e:
            status["failures"] += 1
            status["error"] = f"{type(e).__name__}: {e}"
        save()
        time.sleep(0.5)
    s.close()
elif cmd == "transfer":
    port, size = int(args[0]), int(args[1])
    payload = os.urandom(size)
    with connect(port) as s:
        start = time.monotonic()
        threading.Thread(target=s.sendall, args=(payload,), daemon=True).start()
        line = read_line(s)
        got = 0
        while got < size:
            chunk = s.recv(65536)
            if not chunk:
                break
            got += len(chunk)
        print(f"{time.monotonic() - start:.3f} {got} {line}")
elif cmd == "lifetime":
    port, every = int(args[0]), float(args[1])
    s = connect(port)
    start = time.monotonic()
    s.sendall(b"hello\n")
    s.settimeout(0.1)
    next_send = start + every if every else None
    received = 0
    while time.monotonic() - start < 30:
        if next_send and time.monotonic() >= next_send:
            try:
                s.sendall(b"x\n")
            except OSError:
                break
            next_send += every
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            received += len(chunk)
        except socket.timeout:
            continue
        except OSError:
            break
    print(f"{time.monotonic() - start:.3f} {received}")
'

l4c_tcp() {
    l4_client python3 -c "$L4C_TCP_CLIENT" "$@" | tr -d '\r'
}

# A service's address on `l4`, from the client.
l4c_ip() {
    l4_client python3 -c 'import socket, sys; print(socket.gethostbyname(sys.argv[1]))' "$1" | tr -d '\r'
}

# A backend object for <address>, with an active TCP-connect check at
# the health loop's 5 s floor (a flip is confirmed after three probes,
# each bounded by a 5 s connect timeout: up to about 30 s), or none with
# `nocheck`. Prints its id, or the refusal and returns 1.
l4c_backend() {
    local check='"health_check_enabled":true,"health_check_interval_s":1'
    [ "${2:-}" = nocheck ] && check='"health_check_enabled":false'
    l4s_create_backend "{\"address\":\"$1\",${check}}"
}

# The count under one reason in a stream's live counters, refusals and
# ends together.
l4c_reason_count() {
    l4s_client_script '
        api GET /api/v1/streams/status | jq -r --arg id "$1" --arg r "$2" \
            "[.data.streams[] | select(.id == \$id) | .counters | (.refused // []) + (.ended // []) | .[] | select(.reason == \$r) | .count] | add // 0"
    ' "$1" "$2" | tr -d '\r'
}

# l4c_reason_count, polled for up to 5 s until it reaches <at least>:
# a connection's end is counted once its task has finished, a moment
# after the client saw the close. Prints the last count read.
l4c_wait_reason_count() {
    local i count=0
    for i in $(seq 1 25); do
        count=$(l4c_reason_count "$1" "$2")
        [ "${count:-0}" -ge "$3" ] && break
        sleep 0.2
    done
    echo "${count:-0}"
}

# Poll a backend's health_status until it reads <status>, within
# <seconds>; prints the elapsed milliseconds.
L4C_WAIT_HEALTH_SCRIPT='
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

l4c_wait_health() {
    l4s_client_script "$L4C_WAIT_HEALTH_SCRIPT" "$@" | tr -d '\r'
}

# The node's interface on `l4` and its prefix length, read in the probe:
# prints `<dev> <prefix>`. (The worker node is also on l4-dns.)
l4c_l4_interface() {
    l4s_probe ip -o -4 addr show | tr -d '\r' | awk -v ip="$1" '{ split($4, a, "/"); if (a[1] == ip) print $2, a[2] }'
}

# The address at <index> of a subnet, counted from the top as Python
# does with a negative index: one Docker has not handed out, on a
# network this lightly used.
l4c_subnet_address() {
    l4_client python3 -c 'import ipaddress, sys; print(ipaddress.ip_network(sys.argv[1], strict=False)[int(sys.argv[2])])' "$1" "$2" | tr -d '\r'
}

# The count of <name> in a `name=count ...` tally (0 when absent).
l4c_count() {
    local n
    n=$(printf '%s' "$1" | grep -o "\(^\| \)$2=[0-9]*" | cut -d= -f2)
    echo "${n:-0}"
}

# ---- IV1 -------------------------------------------------------------

# Runs in pg-client: <n> `psql` connections through the stream on
# l4-node:5432, each asking which server answered, tallied by service
# name. `concurrent` holds each session 4 s and opens them 50 ms apart,
# so they overlap (what least_conn balances).
L4C_PG_TALLY='
n=$1 mode=${2:-sequential}
declare -A name
for p in pg-1 pg-2 pg-3; do
    # A killed server no longer resolves; its address then tallies as
    # `other`, which the failover check refuses.
    ip=$(getent ahostsv4 "$p" | awk "NR == 1 {print \$1}")
    [ -n "$ip" ] && name[$ip]=$p
done
one() {
    local out
    if [ "$mode" = concurrent ]; then
        out=$(psql -h l4-node -p 5432 -Atc "select host(inet_server_addr())" -c "select pg_sleep(4)" 2>/dev/null | head -n 1)
    else
        out=$(psql -h l4-node -p 5432 -Atc "select host(inet_server_addr())" 2>/dev/null)
    fi
    if [ -n "$out" ]; then echo "${name[$out]:-other}"; else echo fail; fi
}
dir=$(mktemp -d)
for i in $(seq 1 "$n"); do
    if [ "$mode" = concurrent ]; then
        one > "$dir/$i" &
        sleep 0.05
    else
        one > "$dir/$i"
    fi
done
wait
cat "$dir"/* | sort | uniq -c | awk "{printf \"%s=%s \", \$2, \$1}"
echo
'

l4c_pg_tally() {
    l4_compose exec -T pg-client bash -c "$L4C_PG_TALLY" l4c "$@" | tr -d '\r'
}

l4c_set_algorithm() {
    l4s_client_script 'api PUT "/api/v1/streams/$1" "{\"load_balancing\":\"$2\"}" >/dev/null' "$1" "$2"
    # The workers swap their table on the refresh that follows the
    # commit; a connection accepted before it uses the old snapshot.
    sleep 1
}

# IV1: a TCP stream in front of three PostgreSQL servers balances `psql`
# connections by the configured algorithm (round robin evenly, consistent
# hash all on one server for one client, random over all three, least
# connections evenly over overlapping sessions; peak EWMA reported, not
# asserted); one server is killed, and once it is marked down every new
# connection succeeds, none on it; a session opened before the kill on a
# survivor finishes its queries.
scenario_12_3_iv1_pg_balance_and_failover() {
    local p n ids=() id rr ch rnd lc ew held victim down after survived min max
    trap 'l4s_cleanup_streams l4c-iv1-; l4_compose start pg-1 pg-2 pg-3 >/dev/null 2>&1 || true' EXIT
    l4s_cleanup_streams l4c-iv1-
    for p in pg-1 pg-2 pg-3; do
        id=$(l4c_backend "$(l4c_ip "$p"):5432") || fail "backend ${p}: ${id}"
        ids+=("\"${id}\"")
    done
    id=$(l4s_create_stream "{\"name\":\"l4c-iv1-pg\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":5432,\"backend_ids\":[$(IFS=,; echo "${ids[*]}")],\"connect_timeout_ms\":1000}") \
        || fail "stream create refused: ${id}"
    l4s_wait_bind "$id" bound 5 >/dev/null || fail "the PostgreSQL stream did not bind"
    # Every server answers before the balance counts start.
    for p in pg-1 pg-2 pg-3; do
        l4_compose exec -T pg-client sh -c "until pg_isready -h $p -q; do sleep 0.5; done" || fail "${p} never accepted connections"
    done

    rr=$(l4c_pg_tally 300)
    for p in pg-1 pg-2 pg-3; do
        n=$(l4c_count "$rr" "$p")
        [ "$n" -ge 95 ] && [ "$n" -le 105 ] || fail "round robin over 300 connections: ${rr}"
    done

    l4c_set_algorithm "$id" consistent_hash
    ch=$(l4c_pg_tally 300)
    case "$ch" in
        "pg-"[123]"=300 ") ;;
        *) fail "consistent hash sent one client's 300 connections to several servers: ${ch}" ;;
    esac

    l4c_set_algorithm "$id" random
    rnd=$(l4c_pg_tally 300)
    for p in pg-1 pg-2 pg-3; do
        [ "$(l4c_count "$rnd" "$p")" -ge 60 ] || fail "random over 300 connections: ${rnd}"
    done

    l4c_set_algorithm "$id" least_conn
    lc=$(l4c_pg_tally 30 concurrent)
    min=30 max=0
    for p in pg-1 pg-2 pg-3; do
        n=$(l4c_count "$lc" "$p")
        [ "$n" -lt "$min" ] && min=$n
        [ "$n" -gt "$max" ] && max=$n
    done
    [ $(( max - min )) -le 4 ] || fail "least connections over 30 overlapping sessions: ${lc}"

    l4c_set_algorithm "$id" peak_ewma
    ew=$(l4c_pg_tally 100)
    [ "$(l4c_count "$ew" fail)" = 0 ] || fail "peak EWMA: failed connections: ${ew}"

    # Failover, round robin.
    l4c_set_algorithm "$id" round_robin
    l4_compose exec -d pg-client sh -c 'psql -h l4-node -p 5432 -At -c "select host(inet_server_addr())" -c "select pg_sleep(20)" -c "select 42" > /tmp/held.out 2>&1'
    held=""
    for p in $(seq 1 50); do
        held=$(l4_compose exec -T pg-client sh -c 'head -n 1 /tmp/held.out 2>/dev/null' | tr -d '\r')
        [ -n "$held" ] && break
        sleep 0.2
    done
    [ -n "$held" ] || fail "the held psql session did not start"
    victim=""
    for p in pg-1 pg-2 pg-3; do
        if [ "$(l4c_ip "$p")" != "$held" ]; then victim=$p; break; fi
    done
    local victim_backend
    victim_backend=$(l4s_client_script 'api GET /api/v1/backends | jq -r --arg a "$1:5432" ".data.backends[] | select(.address == \$a) | .id" | head -n 1' "$(l4c_ip "$victim")" | tr -d '\r')
    l4_compose kill "$victim" >/dev/null
    down=$(l4c_wait_health "$victim_backend" down 45) || fail "${victim} not marked down after the kill: ${down}"
    after=$(l4c_pg_tally 100)
    local survivors=0
    for p in pg-1 pg-2 pg-3; do
        [ "$p" = "$victim" ] || survivors=$(( survivors + $(l4c_count "$after" "$p") ))
    done
    [ "$survivors" = 100 ] || fail "after ${victim} was marked down, 100 new connections went: ${after}"
    survived=""
    for p in $(seq 1 150); do
        survived=$(l4_compose exec -T pg-client cat /tmp/held.out | tr -d '\r' | tr '\n' ' ')
        case "$survived" in *" 42 "*) break ;; esac
        sleep 0.2
    done
    case "$survived" in
        "${held}  42 "|"${held} 42 ") ;;
        *) fail "the session held on ${held} across the kill of ${victim} did not finish: ${survived}" ;;
    esac
    pass "round robin ${rr}; consistent hash ${ch}; random ${rnd}; least_conn (30 overlapping) ${lc}; peak EWMA (reported) ${ew}; ${victim} killed, marked down in ${down} ms, then ${after}; the session held on ${held} finished"
}

# ---- IV2 -------------------------------------------------------------

# IV2: one backend serves an HTTP route and a TCP stream, each beside a
# second backend. Its listener closes (SIGUSR1: established connections
# stay); once the health check marks it down, neither the route nor the
# stream selects it, and the stream connection established to it before
# keeps echoing.
scenario_12_3_iv2_shared_backend_down_both_planes() {
    local shared other id route down http stream held
    trap 'l4s_cleanup_streams l4c-iv2-; l4_client touch /tmp/l4c-held.stop >/dev/null 2>&1 || true; l4_compose kill -s USR2 tcp-backend-1 >/dev/null 2>&1 || true' EXIT
    l4s_cleanup_streams l4c-iv2-
    shared=$(l4c_backend "$(l4c_ip tcp-backend-1):9000") || fail "backend: ${shared}"
    other=$(l4c_backend "$(l4c_ip tcp-backend-2):9000") || fail "backend: ${other}"
    l4c_wait_health "$shared" healthy 45 >/dev/null || fail "the shared backend never read healthy"
    route=$(l4s_client_script 'api_try POST /api/v1/routes "$1" | head -n 1' \
        "{\"hostname\":\"l4c-iv2.test\",\"backend_ids\":[\"${shared}\",\"${other}\"]}" | tr -d '\r')
    [ "$route" = 2xx ] || l4s_client_script 'api GET /api/v1/routes | jq -e ".data.routes[] | select(.hostname == \"l4c-iv2.test\")" >/dev/null' \
        || fail "route create refused: ${route}"
    id=$(l4s_create_stream "{\"name\":\"l4c-iv2-shared\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7401,\"backend_ids\":[\"${shared}\",\"${other}\"]}") \
        || fail "stream create refused: ${id}"
    l4s_wait_bind "$id" bound 5 >/dev/null || fail "the stream did not bind"

    l4_client rm -f /tmp/l4c-held.stop /tmp/l4c-held.json
    l4_compose exec -d streams-client python3 -c "$L4C_TCP_CLIENT" held 7401 tcp-backend-1 /tmp/l4c-held.stop /tmp/l4c-held.json
    local i
    for i in $(seq 1 50); do
        l4_client grep -q '"target": "tcp-backend-1"' /tmp/l4c-held.json 2>/dev/null && break
        sleep 0.2
    done
    l4_client grep -q '"target": "tcp-backend-1"' /tmp/l4c-held.json || fail "no stream connection reached the shared backend"

    l4_compose kill -s USR1 tcp-backend-1 >/dev/null
    down=$(l4c_wait_health "$shared" down 45) || fail "the shared backend was not marked down: ${down}"
    sleep 1
    http=$(l4c_tcp http l4c-iv2.test 20)
    stream=$(l4c_tcp idents 7401 20)
    sleep 1
    l4_client touch /tmp/l4c-held.stop
    sleep 1
    held=$(l4_client cat /tmp/l4c-held.json | tr -d '\r')
    l4_compose kill -s USR2 tcp-backend-1 >/dev/null
    l4s_client_script 'api GET /api/v1/routes | jq -r ".data.routes[] | select(.hostname == \"l4c-iv2.test\") | .id" | while read -r r; do api DELETE "/api/v1/routes/$r" >/dev/null; done' >/dev/null 2>&1 || true

    [ "$http" = "tcp-backend-2=20" ] || fail "the route still selected the down backend: ${http}"
    [ "$stream" = "tcp-backend-2=20" ] || fail "the stream still selected the down backend: ${stream}"
    case "$held" in
        *'"failures": 0'*) ;;
        *) fail "the stream connection established before the backend went down broke: ${held}" ;;
    esac
    pass "marked down ${down} ms after its listener closed; route ${http}; stream ${stream}; established connection ${held}"
}

# ---- IV3 -------------------------------------------------------------

# IV3: a stream sending PROXY v2 gives the backend the client's real
# address; on a stream accepting PROXY from 192.0.2.0/24 only, the
# client (outside it) sending a v1 or a v2 header is disconnected with
# nothing forwarded, counted as `proxy_header_invalid`, while it is
# served without one; and a trusted peer's header is honoured: the
# address it carries reaches the backend through a v2 send and the
# stream's access-log row.
scenario_12_3_iv3_proxy_v2_send_and_accept() {
    local client proxied echo send untrusted trusted v1 v2 plain counted carried logged
    trap 'l4s_cleanup_streams l4c-iv3-' EXIT
    l4s_cleanup_streams l4c-iv3-
    client=$(l4s_client_ip)
    proxied=$(l4c_backend "$(l4c_ip tcp-backend-proxy):9000") || fail "backend: ${proxied}"
    echo=$(l4c_backend "$(l4c_ip tcp-backend-1):9000") || fail "backend: ${echo}"
    send=$(l4s_create_stream "{\"name\":\"l4c-iv3-send\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7402,\"backend_ids\":[\"${proxied}\"],\"proxy_protocol_send\":\"v2\"}") \
        || fail "stream create refused: ${send}"
    untrusted=$(l4s_create_stream "{\"name\":\"l4c-iv3-untrusted\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7403,\"backend_ids\":[\"${echo}\"],\"proxy_protocol_accept\":true,\"proxy_protocol_trusted_cidrs\":[\"192.0.2.0/24\"]}") \
        || fail "stream create refused: ${untrusted}"
    trusted=$(l4s_create_stream "{\"name\":\"l4c-iv3-trusted\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7404,\"backend_ids\":[\"${proxied}\"],\"proxy_protocol_accept\":true,\"proxy_protocol_trusted_cidrs\":[\"${client}/32\"],\"proxy_protocol_send\":\"v2\"}") \
        || fail "stream create refused: ${trusted}"
    for id in "$send" "$untrusted" "$trusted"; do
        l4s_wait_bind "$id" bound 5 >/dev/null || fail "stream ${id} did not bind"
    done

    local seen
    seen=$(l4c_tcp ident 7402)
    case "$seen" in *" src=${client}") ;; *) fail "the v2 header did not carry the client ${client}: ${seen}" ;; esac

    v1=$(l4c_tcp ident 7403 v1 203.0.113.7)
    v2=$(l4c_tcp ident 7403 v2 203.0.113.7)
    plain=$(l4c_tcp ident 7403)
    [ "$v1" = closed ] && [ "$v2" = closed ] \
        || fail "an untrusted client's PROXY header was not refused: v1 '${v1}', v2 '${v2}'"
    case "$plain" in name=tcp-backend-1*) ;; *) fail "a direct client without a header was not served: ${plain}" ;; esac
    counted=$(l4c_wait_reason_count "$untrusted" proxy_header_invalid 2)
    [ "${counted:-0}" -ge 2 ] || fail "the two refused headers were counted ${counted} times as proxy_header_invalid"

    carried=$(l4c_tcp ident 7404 v2 203.0.113.7)
    case "$carried" in *" src=203.0.113.7") ;; *) fail "the trusted header's address did not reach the backend: ${carried}" ;; esac
    logged=""
    for i in $(seq 1 25); do
        logged=$(l4s_client_script 'api GET "/api/v1/stream-logs?stream_id=$1" | jq -r "[.. | strings | select(contains(\"203.0.113.7\"))] | length"' "$trusted" | tr -d '\r')
        [ "${logged:-0}" -ge 1 ] && break
        sleep 0.4
    done
    [ "${logged:-0}" -ge 1 ] || fail "the trusted stream's access-log row does not carry 203.0.113.7"
    pass "v2 send: ${seen}; untrusted v1 and v2 headers closed, ${counted} counted proxy_header_invalid, a plain client served; trusted v2 carrying 203.0.113.7: backend saw '${carried}', the access log records it"
}

# ---- IV4 -------------------------------------------------------------

# IV4: a stream pointed at 127.0.0.1:<management port> is refused at
# creation, flag or not: 409 `stream_local_backend` both times (12.3's
# rule B, which no flag lifts). Then a stream whose backend is a host name
# served by CoreDNS (5 s TTL, through Docker's embedded DNS) reaches the
# backend; the name moves to 127.0.0.1 and, once re-resolved, no
# connection reaches anything: the address is excluded for the stream
# and the exclusion is logged and counted. Partial, as D-d allows, only
# if the move is never seen within 70 s (Docker's DNS not forwarding the
# record or its TTL as expected); 12.3 Lot D2's hickory test then proves
# that half.
scenario_12_3_iv4_local_backend_refused_and_rebind_excluded() {
    local mgmt with without hostname id served moved after excluded backend_ip
    trap 'l4s_cleanup_streams l4c-iv4-' EXIT
    l4s_cleanup_streams l4c-iv4-
    mgmt=$(l4c_backend 127.0.0.1:19443 nocheck) || fail "backend: ${mgmt}"
    with=$(l4s_client_script 'api_try POST /api/v1/streams "$1" | tr "\n" " "' \
        "{\"name\":\"l4c-iv4-mgmt\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7405,\"backend_ids\":[\"${mgmt}\"],\"allow_local_backend\":true}" | tr -d '\r')
    without=$(l4s_client_script 'api_try POST /api/v1/streams "$1" | tr "\n" " "' \
        "{\"name\":\"l4c-iv4-mgmt\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7405,\"backend_ids\":[\"${mgmt}\"]}" | tr -d '\r')
    case "$with" in 409\ *stream_local_backend*) ;; *) fail "the management port with allow_local_backend was not refused 409: ${with}" ;; esac
    case "$without" in 409\ *stream_local_backend*) ;; *) fail "the management port without allow_local_backend was not refused 409: ${without}" ;; esac

    backend_ip=$(l4c_ip tcp-backend-1)
    mkdir -p results
    printf '%s rebind.l4.test\n' "$backend_ip" > "${L4_RESULTS}-coredns-hosts"
    l4_compose cp "${L4_RESULTS}-coredns-hosts" coredns:/l4-hosts >/dev/null 2>&1 || fail "could not install the CoreDNS hosts file"
    hostname=$(l4c_backend rebind.l4.test:9000 nocheck) || fail "backend: ${hostname}"
    id=$(l4s_create_stream "{\"name\":\"l4c-iv4-rebind\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7406,\"backend_ids\":[\"${hostname}\"]}") \
        || fail "stream create refused: ${id}"
    l4s_wait_bind "$id" bound 5 >/dev/null || fail "the stream did not bind"
    served=""
    for i in $(seq 1 30); do
        served=$(l4c_tcp ident 7406)
        case "$served" in name=tcp-backend-1*) break ;; esac
        sleep 1
    done
    case "$served" in
        name=tcp-backend-1*) ;;
        *) fail "rebind.l4.test never reached tcp-backend-1 (${served}): the node does not resolve through CoreDNS" ;;
    esac

    printf '127.0.0.1 rebind.l4.test\n' > "${L4_RESULTS}-coredns-hosts"
    l4_compose cp "${L4_RESULTS}-coredns-hosts" coredns:/l4-hosts >/dev/null 2>&1 || fail "could not rewrite the CoreDNS hosts file"
    moved=""
    local t0=$SECONDS
    while [ $(( SECONDS - t0 )) -lt 70 ]; do
        moved=$(l4c_tcp ident 7406)
        case "$moved" in name=*) sleep 1 ;; *) break ;; esac
    done
    case "$moved" in
        name=*)
            partial "the management port refused 409 stream_local_backend, flag or not; rebind.l4.test still reached ${backend_ip} 70 s after it moved to 127.0.0.1 -- not automated: the re-resolution half, which Story 12.3 Lot D2's hickory test proves"
            return 0
            ;;
    esac
    after=$(l4c_tcp idents 7406 10)
    [ "$after" = "closed=10" ] || fail "after the move to 127.0.0.1: ${after}"
    excluded=$(l4_api GET /metrics | grep '^lorica_stream_backend_dns_local_excluded_total' | awk '{s += $NF} END {print s + 0}')
    [ "${excluded:-0}" -ge 1 ] || fail "no lorica_stream_backend_dns_local_excluded_total after the exclusion"
    pass "management port refused (409 stream_local_backend, flag or not); rebind.l4.test served by ${backend_ip}, then moved to 127.0.0.1 and excluded after $(( SECONDS - t0 )) s: ${after}, ${excluded} exclusion(s) counted"
}

# ---- The TCP rows of the parity matrix (D-e) -------------------------

# Backup backends: connections go to the primary; with the primary down
# they go to the backup; with it back, to the primary again.
scenario_12_3_matrix_backup_backends() {
    local primary backup id up down back
    trap 'l4s_cleanup_streams l4c-bk-; l4_compose kill -s USR2 tcp-backend-3 >/dev/null 2>&1 || true' EXIT
    l4s_cleanup_streams l4c-bk-
    primary=$(l4c_backend "$(l4c_ip tcp-backend-3):9000") || fail "backend: ${primary}"
    backup=$(l4c_backend "$(l4c_ip tcp-backend-2):9000") || fail "backend: ${backup}"
    id=$(l4s_create_stream "{\"name\":\"l4c-bk-stream\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7407,\"backend_ids\":[\"${primary}\"],\"backup_backend_ids\":[\"${backup}\"]}") \
        || fail "stream create refused: ${id}"
    l4s_wait_bind "$id" bound 5 >/dev/null || fail "the stream did not bind"
    l4c_wait_health "$primary" healthy 45 >/dev/null || fail "the primary never read healthy"
    up=$(l4c_tcp idents 7407 10)
    l4_compose kill -s USR1 tcp-backend-3 >/dev/null
    l4c_wait_health "$primary" down 45 >/dev/null || fail "the primary was not marked down"
    down=$(l4c_tcp idents 7407 10)
    l4_compose kill -s USR2 tcp-backend-3 >/dev/null
    l4c_wait_health "$primary" healthy 45 >/dev/null || fail "the primary did not come back healthy"
    back=$(l4c_tcp idents 7407 10)
    [ "$up" = tcp-backend-3=10 ] && [ "$down" = tcp-backend-2=10 ] && [ "$back" = tcp-backend-3=10 ] \
        || fail "primary up: ${up}; primary down: ${down}; primary back: ${back}"
    pass "primary up: ${up}; primary down: ${down}; primary back: ${back}"
}

# Bandwidth: 64 KiB echoed through a stream limited to 16 KiB/s upload
# takes about 4 s, and so does one limited to 16 KiB/s download; the same
# through an unlimited stream takes well under a second.
scenario_12_3_matrix_bandwidth() {
    local echo up down free tu td tf
    trap 'l4s_cleanup_streams l4c-bw-' EXIT
    l4s_cleanup_streams l4c-bw-
    echo=$(l4c_backend "$(l4c_ip tcp-backend-1):9000") || fail "backend: ${echo}"
    local base="\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"backend_ids\":[\"${echo}\"]"
    up=$(l4s_create_stream "{\"name\":\"l4c-bw-up\",${base},\"port_first\":7408,\"upload_rate_bps\":16384}") || fail "stream create refused: ${up}"
    down=$(l4s_create_stream "{\"name\":\"l4c-bw-down\",${base},\"port_first\":7409,\"download_rate_bps\":16384}") || fail "stream create refused: ${down}"
    free=$(l4s_create_stream "{\"name\":\"l4c-bw-free\",${base},\"port_first\":7410}") || fail "stream create refused: ${free}"
    for id in "$up" "$down" "$free"; do
        l4s_wait_bind "$id" bound 5 >/dev/null || fail "stream ${id} did not bind"
    done
    tu=$(l4c_tcp transfer 7408 65536)
    td=$(l4c_tcp transfer 7409 65536)
    tf=$(l4c_tcp transfer 7410 65536)
    for t in "$tu" "$td"; do
        set -- $t
        [ "$2" = 65536 ] || fail "a limited transfer lost bytes: ${t}"
        l4s_less_than 2.5 "$1" && l4s_less_than "$1" 10 || fail "64 KiB at 16 KiB/s took ${1} s (upload ${tu%% *}, download ${td%% *})"
    done
    set -- $tf
    [ "$2" = 65536 ] && l4s_less_than "$1" 1.5 || fail "the unlimited transfer: ${tf}"
    pass "64 KiB echoed: upload-limited ${tu%% *} s, download-limited ${td%% *} s, unlimited ${tf%% *} s"
}

# Timeouts: a connect to an address that never answers ends at
# connect_timeout_ms (500 ms, one attempt) as connect_failed; a silent
# connection ends at idle_timeout_s (2 s) as idle_timeout; a busy one at
# total_timeout_s (3 s) as total_timeout.
scenario_12_3_matrix_timeouts() {
    local dead black echo connect idle total tc ti tt
    trap 'l4s_cleanup_streams l4c-to-' EXIT
    l4s_cleanup_streams l4c-to-
    # An unassigned address on the client's own subnet: ARP goes
    # unanswered, so the SYN is never answered and the connect hangs
    # until Lorica's timeout (the kernel's own gives up after seconds).
    local node_ip prefix
    node_ip=$(l4c_ip l4-node)
    read -r _ prefix <<< "$(l4c_l4_interface "$node_ip")"
    [ -n "$prefix" ] || fail "no interface of the node carries ${node_ip}"
    dead=$(l4c_subnet_address "${node_ip}/${prefix}" -7)
    black=$(l4c_backend "${dead}:9" nocheck) || fail "backend: ${black}"
    echo=$(l4c_backend "$(l4c_ip tcp-backend-1):9000") || fail "backend: ${echo}"
    connect=$(l4s_create_stream "{\"name\":\"l4c-to-connect\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7411,\"backend_ids\":[\"${black}\"],\"connect_timeout_ms\":500,\"max_connect_attempts\":1}") || fail "stream create refused: ${connect}"
    idle=$(l4s_create_stream "{\"name\":\"l4c-to-idle\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7412,\"backend_ids\":[\"${echo}\"],\"idle_timeout_s\":2}") || fail "stream create refused: ${idle}"
    total=$(l4s_create_stream "{\"name\":\"l4c-to-total\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7413,\"backend_ids\":[\"${echo}\"],\"total_timeout_s\":3}") || fail "stream create refused: ${total}"
    for id in "$connect" "$idle" "$total"; do
        l4s_wait_bind "$id" bound 5 >/dev/null || fail "stream ${id} did not bind"
    done
    tc=$(l4c_tcp lifetime 7411 0)
    ti=$(l4c_tcp lifetime 7412 0)
    tt=$(l4c_tcp lifetime 7413 0.5)
    l4s_less_than 0.3 "${tc%% *}" && l4s_less_than "${tc%% *}" 2.5 || fail "the connect timeout of 500 ms ended the connection after ${tc%% *} s"
    l4s_less_than 1.5 "${ti%% *}" && l4s_less_than "${ti%% *}" 4.5 || fail "the idle timeout of 2 s ended the connection after ${ti%% *} s"
    l4s_less_than 2.5 "${tt%% *}" && l4s_less_than "${tt%% *}" 4.5 || fail "the total timeout of 3 s ended the connection after ${tt%% *} s"
    [ "$(l4c_wait_reason_count "$connect" connect_failed 1)" -ge 1 ] || fail "the connect timeout did not end as connect_failed"
    [ "$(l4c_wait_reason_count "$idle" idle_timeout 1)" -ge 1 ] || fail "the idle timeout did not end as idle_timeout"
    [ "$(l4c_wait_reason_count "$total" total_timeout 1)" -ge 1 ] || fail "the total timeout did not end as total_timeout"
    pass "connect 500 ms: closed after ${tc%% *} s (connect_failed); idle 2 s: ${ti%% *} s (idle_timeout); total 3 s while busy: ${tt%% *} s (total_timeout)"
}

# Chosen source address: the node gets a second address on `l4` (the
# probe holds NET_ADMIN in the node's namespace); a stream with it as
# its source address reaches the backend from it, and a stream without
# one from the node's own address.
scenario_12_3_matrix_proxy_bind() {
    local node_ip second dev prefix echo bound plain via direct
    node_ip=$(l4c_ip l4-node)
    read -r dev prefix <<< "$(l4c_l4_interface "$node_ip")"
    [ -n "$dev" ] || fail "no interface of the node carries ${node_ip}"
    second=$(l4c_subnet_address "${node_ip}/${prefix}" -6)
    trap 'l4s_cleanup_streams l4c-pb-; l4s_probe ip addr del "'"${second}/${prefix}"'" dev "'"${dev}"'" >/dev/null 2>&1 || true' EXIT
    l4s_cleanup_streams l4c-pb-
    l4s_probe ip addr add "${second}/${prefix}" dev "$dev" || fail "could not add ${second} to ${dev}"
    echo=$(l4c_backend "$(l4c_ip tcp-backend-1):9000") || fail "backend: ${echo}"
    bound=$(l4s_create_stream "{\"name\":\"l4c-pb-bound\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7414,\"backend_ids\":[\"${echo}\"],\"source_addresses\":[\"${second}\"]}") || fail "stream create refused: ${bound}"
    plain=$(l4s_create_stream "{\"name\":\"l4c-pb-plain\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7415,\"backend_ids\":[\"${echo}\"]}") || fail "stream create refused: ${plain}"
    for id in "$bound" "$plain"; do
        l4s_wait_bind "$id" bound 5 >/dev/null || fail "stream ${id} did not bind"
    done
    via=$(l4c_tcp ident 7414)
    direct=$(l4c_tcp ident 7415)
    case "$via" in *" peer=${second}"*) ;; *) fail "the stream with source address ${second} reached the backend as: ${via}" ;; esac
    case "$direct" in *" peer=${node_ip}"*) ;; *) fail "the stream without a source address reached the backend as: ${direct}" ;; esac
    pass "with source_addresses [${second}] the backend saw ${via#* port=9000 }; without, ${direct#* port=9000 }"
}

# Port ranges: a 16-port stream forwards listen port N to backend port
# N (a portless backend).
scenario_12_3_matrix_port_range() {
    local range id port got wrong=""
    trap 'l4s_cleanup_streams l4c-pr-' EXIT
    l4s_cleanup_streams l4c-pr-
    range=$(l4c_backend "$(l4c_ip tcp-backend-range)" nocheck) || fail "backend: ${range}"
    id=$(l4s_create_stream "{\"name\":\"l4c-pr-range\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7300,\"port_last\":7315,\"backend_ids\":[\"${range}\"]}") || fail "stream create refused: ${id}"
    l4s_wait_bind "$id" bound 5 >/dev/null || fail "the range did not bind"
    got=$(for port in $(seq 7300 7315); do l4c_tcp ident "$port"; done)
    for port in $(seq 7300 7315); do
        printf '%s\n' "$got" | grep -q "^name=tcp-backend-range port=${port} " || wrong="${wrong} ${port}"
    done
    [ -z "$wrong" ] || fail "ports not forwarded to the same backend port:${wrong} (${got//$'\n'/; })"
    pass "16 listen ports 7300-7315 each reached backend port N"
}
