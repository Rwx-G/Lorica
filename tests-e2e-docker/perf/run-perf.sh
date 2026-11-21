#!/usr/bin/env bash
# The performance phase of the e2e suite (Story 12.12 D-i to D-l), run by
# run.sh on the host. Lorica 1.11.0 against nginx `stream` (TCP throughput
# and CPU per GiB both ways, connection setup, a UDP hold at 80 % of
# Lorica's ceiling), and NFR1 against the released 1.10.7 (HTTP, gated;
# HTTPS, reported). Every number it gates on is a ratio taken on this
# machine in this run.
#
# Usage: perf/run-perf.sh [--build] [--keep] [--advisory]
#   --build     rebuild the phase's images first
#   --keep      leave the perf project up afterwards
#   --advisory  write the verdicts and exit 0 whatever they are (CI, D-m);
#               a harness error still exits 2
#
# Environment:
#   PERF_LAYOUT        auto (default), large or small: the cpuset layout of
#                      D-i, derived from the CPU count Docker reports unless
#                      forced; `small` on a large machine is the CI layout,
#                      for a dry run of it
#   PERF_RELEASE_RUN   1 on the local release run (run.sh sets it): anything
#                      but the larger layout is INCONCLUSIVE (environment)
#   PERF_REPS          repetitions per arm and attempt, at least 5 (default 5)
#   PERF_MAX_RERUNS    re-runs of an inconclusive measurement (default 3)
#   PERF_MEASUREMENTS  comma list, default every one:
#                      tcp-up,tcp-down,connect,udp,nfr1-http,nfr1-https;
#                      a measurement left out reports NOT-RUN, which gates
#   L4_IMAGE_TAG       the Lorica and perf-tools image tag (default local)
#
# Output: results/perf-<ts>.runs.jsonl (every run, appended as it lands),
# results/perf-<ts>.json and results/perf-summary.md (perf/analyse.py).
# Exit 0 when every gated check passes, 1 otherwise, 2 on a harness error.

set -euo pipefail
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1

BUILD=false
KEEP=false
ADVISORY=false
for arg in "$@"; do
    case "$arg" in
        --build) BUILD=true ;;
        --keep) KEEP=true ;;
        --advisory) ADVISORY=true ;;
        *) echo "run-perf.sh: unknown argument $arg" >&2; exit 2 ;;
    esac
done

PERF_PROJECT=lorica-e2e-perf
export L4_IMAGE_TAG="${L4_IMAGE_TAG:-local}"
PERF_RELEASE_RUN="${PERF_RELEASE_RUN:-0}"
PERF_REPS="${PERF_REPS:-5}"
PERF_MAX_RERUNS="${PERF_MAX_RERUNS:-3}"
PERF_MEASUREMENTS="${PERF_MEASUREMENTS:-tcp-up,tcp-down,connect,udp,nfr1-http,nfr1-https}"
if [ "$PERF_REPS" -lt 5 ]; then
    echo "run-perf.sh: PERF_REPS must be at least 5 (Story 12.12 AC #2)" >&2
    exit 2
fi

# The tools' fixed parameters (D-j, D-l). iperf3 runs IPERF_STREAMS_PER_WORKER
# parallel streams per proxy worker, not D-j's `-P 4` (Lot M deviation):
# both proxies' workers share one TCP listening socket, and a burst of 4
# connects is usually accepted whole by whichever worker wakes first, so
# a `-P 4` series measured which worker took the accepts (nginx on one
# worker in 4 runs of 5, Lorica in 1 of 5). At 8 streams per worker the
# accepts spread over every worker in every run measured.
IPERF_STREAMS_PER_WORKER=8
IPERF_ARGS="-t 15 -J"
CONNECT_COUNT=10000
CONNECT_RATE=500
UDP_IDLE_S=30
UDP_HOLD_INTERVAL_S=5
UDP_HOLD_DURATION_S=30
OHA_CONNECTIONS=64
OHA_SATURATION_S=15s
OHA_FIXED_RATE_S=20s

TS=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p results
RUNS="/results/perf-${TS}.runs.jsonl"
PHASE_START=$(date +%s)

perf_compose() {
    docker compose -p "$PERF_PROJECT" -f docker-compose.perf.yml "$@"
}

in_client() {
    perf_compose exec -T perf-client "$@"
}

analyse() {
    in_client python3 /perf-driver/analyse.py "$@"
}

die() {
    echo "run-perf.sh: $*" >&2
    exit 2
}

# ---- Layout (D-i) ------------------------------------------------------
NCPU=$(docker info --format '{{.NCPU}}' | tr -d '\r')
LAYOUT="${PERF_LAYOUT:-auto}"
case "$LAYOUT" in
    auto)
        if [ "$NCPU" -ge 8 ]; then LAYOUT=large
        elif [ "$NCPU" -ge 4 ]; then LAYOUT=small
        else LAYOUT=none
        fi ;;
    large) [ "$NCPU" -ge 8 ] || die "PERF_LAYOUT=large needs 8 CPUs, Docker reports ${NCPU}" ;;
    small) [ "$NCPU" -ge 4 ] || LAYOUT=none ;;
    *) die "PERF_LAYOUT must be auto, large or small, not '${LAYOUT}'" ;;
esac
case "$LAYOUT" in
    large)
        export PERF_CPUS_PROXY=2-3 PERF_CPUS_LOAD=4-5 PERF_CPUS_BACKEND=6-7
        export PERF_WORKERS=2 PERF_BACKEND_WORKERS=2 ;;
    small)
        export PERF_CPUS_PROXY=1 PERF_CPUS_LOAD=2 PERF_CPUS_BACKEND=3
        export PERF_WORKERS=1 PERF_BACKEND_WORKERS=1 ;;
    none)
        export PERF_CPUS_PROXY=0 PERF_CPUS_LOAD=0 PERF_CPUS_BACKEND=0
        export PERF_WORKERS=1 PERF_BACKEND_WORKERS=1 ;;
esac

echo ""
echo "=== Lorica E2E performance phase (Story 12.12) ==="
echo "Layout ${LAYOUT} on ${NCPU} CPUs: proxy ${PERF_CPUS_PROXY}, load ${PERF_CPUS_LOAD}, backends ${PERF_CPUS_BACKEND}, ${PERF_WORKERS} worker(s) per proxy"

finish() {
    local status=$?
    if [ "$status" -ge 2 ] && [ "$LAYOUT" != none ]; then
        for svc in perf-lorica perf-lorica-baseline; do
            echo "--- last 40 lines of ${svc}'s /tmp/lorica.log ---"
            perf_compose exec -T "$svc" tail -n 40 /tmp/lorica.log 2>&1 || true
        done
    fi
    if [ "$KEEP" = false ]; then
        perf_compose down -v --remove-orphans >/dev/null 2>&1 || true
    fi
    echo "Performance phase: $(( $(date +%s) - PHASE_START )) s"
}
trap finish EXIT

report() {
    local status=0
    analyse report --runs "$RUNS" --json "/results/perf-${TS}.json" \
        --markdown /results/perf-summary.md "$@" || status=$?
    echo "Wrote tests-e2e-docker/results/perf-${TS}.json and perf-summary.md"
    if [ "$ADVISORY" = true ]; then
        [ "$status" -le 1 ] || exit "$status"
        echo "Advisory run (--perf-advisory): verdicts reported, not gated"
        exit 0
    fi
    exit "$status"
}

if [ "$LAYOUT" = none ]; then
    perf_compose run --rm --no-deps -T --entrypoint python3 perf-client /perf-driver/analyse.py \
        env --runs "$RUNS" layout=none ncpu="$NCPU" release_run="$PERF_RELEASE_RUN"
    status=0
    perf_compose run --rm --no-deps -T --entrypoint python3 perf-client /perf-driver/analyse.py \
        report --runs "$RUNS" --json "/results/perf-${TS}.json" --markdown /results/perf-summary.md \
        --not-run "Docker reports ${NCPU} CPUs, fewer than the 4 the smallest layout needs" || status=$?
    [ "$ADVISORY" = true ] && exit 0
    exit "$status"
fi

# ---- Topology ------------------------------------------------------------
if [ "$BUILD" = true ]; then
    perf_compose build
fi
perf_compose up -d

wait_for() {
    local what="$1" i
    shift
    for i in $(seq 1 60); do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    die "${what} not ready within 120 s"
}
for svc in perf-lorica perf-lorica-baseline; do
    wait_for "$svc" perf_compose exec -T "$svc" sh -c \
        'test -s /var/lib/lorica/initial-admin-password && curl -skf https://127.0.0.1:19443/'
done
wait_for perf-nginx perf_compose exec -T perf-nginx test -s /tmp/nginx.pid
wait_for perf-backend-http perf_compose exec -T perf-backend-http test -s /tmp/nginx.pid
wait_for "the backends" in_client python3 -c '
import socket
for port in (5201, 5203, 5301):
    socket.create_connection(("perf-backend", port), timeout=2).close()
socket.create_connection(("perf-backend-http", 80), timeout=2).close()
'

ip_of() {
    in_client python3 -c 'import socket, sys; print(socket.gethostbyname(sys.argv[1]))' "$1" | tr -d '\r'
}
CLIENT_IP=$(in_client python3 -c 'import socket; print(socket.gethostbyname(socket.gethostname()))' | tr -d '\r')
BACKEND_IP=$(ip_of perf-backend)
HTTP_BACKEND_IP=$(ip_of perf-backend-http)

# ---- Management API, from the client -------------------------------------
# `api <node> <METHOD> <PATH> [BODY] [--field a.b.0.k=v]` prints the body,
# or the field the dotted path names (a list segment is an index or a
# `key=value` filter); exits non-zero on a status outside 2xx. Waits out a
# 429 of the API's rate limits; logs in on the first call or a 401, with
# the bootstrap password the driver leaves in the client, changing it when
# the node requires it. One literal string: no single quote inside.
PERF_API_PY='
import json, ssl, sys, time, urllib.error, urllib.request

node, method, path = sys.argv[1:4]
body = None
field = None
rest = sys.argv[4:]
while rest:
    if rest[0] == "--field":
        field, rest = rest[1], rest[2:]
    else:
        body, rest = rest[0], rest[1:]
base = "https://" + node + ":9443"
ctx = ssl._create_unverified_context()
jar = "/tmp/perf-api-" + node + ".cookie"
pwfile = "/tmp/perf-api-" + node + ".password"
initial = "/tmp/perf-api-" + node + ".initial"


def read(name):
    try:
        with open(name) as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""


def send(verb, url, payload=None, cookie=None):
    data = None if payload is None else payload.encode()
    req = urllib.request.Request(base + url, data=data, method=verb)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            return resp.status, resp.read().decode(), resp.headers
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode(), err.headers


def login():
    pw = read(pwfile) or read(initial)
    status, text, headers = send("POST", "/api/v1/auth/login", json.dumps({"username": "admin", "password": pw}))
    if status != 200:
        sys.exit(f"perf api: login on {node} refused (HTTP {status}): {text}")
    cookie = next(c.split(";", 1)[0] for c in headers.get_all("Set-Cookie") or [] if c.startswith("lorica_session="))
    with open(jar, "w") as f:
        f.write(cookie)
    if json.loads(text)["data"].get("must_change_password"):
        new = "Perf-harness-Pw!42"
        status, text, _ = send("PUT", "/api/v1/auth/password",
                               json.dumps({"current_password": pw, "new_password": new}), cookie)
        if status != 200:
            sys.exit(f"perf api: password change on {node} refused (HTTP {status}): {text}")
        with open(pwfile, "w") as f:
            f.write(new)
        return login()
    return cookie


cookie = read(jar) or login()
for _ in range(40):
    status, text, _ = send(method, path, body, cookie)
    if status == 401:
        cookie = login()
        continue
    if status == 429:
        time.sleep(3)
        continue
    break
if not 200 <= status < 300:
    sys.exit(f"perf api: {method} {path} on {node} answered HTTP {status}: {text}")
value = json.loads(text) if text.strip() else None
if field:
    try:
        for part in field.split("."):
            if isinstance(value, list):
                if "=" in part:
                    key, want = part.split("=", 1)
                    value = next(el for el in value if str(el.get(key)) == want)
                else:
                    value = value[int(part)]
            else:
                value = value[part]
    except (KeyError, IndexError, StopIteration, TypeError):
        value = ""
print(value if isinstance(value, (str, int, float)) else json.dumps(value))
'

api() {
    in_client python3 -c "$PERF_API_PY" "$@" | tr -d '\r'
}

for svc in perf-lorica perf-lorica-baseline; do
    perf_compose exec -T "$svc" cat /var/lib/lorica/initial-admin-password | tr -d '\r\n' \
        | perf_compose exec -T perf-client sh -c "cat > /tmp/perf-api-${svc}.initial"
done

# The NFR1 route on both versions, through endpoints 1.10.7 has too: a
# backend, a self-signed certificate and a route answering on the plain
# HTTP listener and on HTTPS. Returns once both answer 200 with the 1 KiB
# body.
seed_route() {
    local svc="$1" bid cert
    bid=$(api "$svc" POST /api/v1/backends \
        "{\"name\":\"perf-http\",\"address\":\"${HTTP_BACKEND_IP}:80\",\"health_check_enabled\":false}" --field data.id)
    cert=$(api "$svc" POST /api/v1/certificates/self-signed '{"domain":"perf.test"}' --field data.id)
    api "$svc" POST /api/v1/routes \
        "{\"hostname\":\"perf.test\",\"path_prefix\":\"/\",\"backend_ids\":[\"${bid}\"],\"certificate_id\":\"${cert}\"}" \
        --field data.id >/dev/null
    in_client sh -c '
        for i in $(seq 1 75); do
            plain=$(curl -s -o /dev/null -w "%{http_code} %{size_download}" -H "Host: perf.test" "http://$1:8080/")
            tls=$(curl -sk -o /dev/null -w "%{http_code} %{size_download}" --connect-to "perf.test:8443:$1:8443" https://perf.test:8443/)
            [ "$plain" = "200 1024" ] && [ "$tls" = "200 1024" ] && exit 0
            sleep 0.2
        done
        echo "route perf.test on $1: HTTP $plain, HTTPS $tls" >&2
        exit 1
    ' sh "$svc" || die "the NFR1 route did not answer on ${svc}"
}
seed_route perf-lorica
seed_route perf-lorica-baseline

IPERF_BACKEND=$(api perf-lorica POST /api/v1/backends \
    "{\"name\":\"perf-iperf\",\"address\":\"${BACKEND_IP}:5201\",\"health_check_enabled\":false}" --field data.id)
CONNECT_BACKEND=$(api perf-lorica POST /api/v1/backends \
    "{\"name\":\"perf-connect\",\"address\":\"${BACKEND_IP}:5202\",\"health_check_enabled\":false}" --field data.id)
UDP_BACKEND=$(api perf-lorica POST /api/v1/backends \
    "{\"name\":\"perf-udp\",\"address\":\"${BACKEND_IP}:5300\",\"health_check_enabled\":false}" --field data.id)

# Create a stream on perf-lorica, wait until it is bound, print its id.
create_stream() {
    local id i state=""
    id=$(api perf-lorica POST /api/v1/streams "$1" --field data.id)
    for i in $(seq 1 30); do
        state=$(api perf-lorica GET "/api/v1/streams/${id}" --field data.bind.state)
        [ "$state" = bound ] && { echo "$id"; return 0; }
        sleep 0.5
    done
    die "stream ${id} not bound after 15 s (state ${state}): $1"
}

delete_stream() {
    api perf-lorica DELETE "/api/v1/streams/$1" >/dev/null
}

# ---- Environment record and guard (D-i) ----------------------------------
container_of() {
    perf_compose ps -q "$1" | tr -d '\r'
}
env_pairs=(
    "layout=${LAYOUT}" "ncpu=${NCPU}" "release_run=${PERF_RELEASE_RUN}" "advisory=${ADVISORY}"
    "reps=${PERF_REPS}" "max_reruns=${PERF_MAX_RERUNS}" "measurements=${PERF_MEASUREMENTS}"
    "workers_per_proxy=${PERF_WORKERS}"
    "iperf_streams=$(( IPERF_STREAMS_PER_WORKER * PERF_WORKERS ))"
    "docker_memory_bytes=$(docker info --format '{{.MemTotal}}' | tr -d '\r')"
    "kernel=$(docker info --format '{{.KernelVersion}}' | tr -d '\r')"
    "docker_version=$(docker info --format '{{.ServerVersion}}' | tr -d '\r')"
    "docker_os=$(docker info --format '{{.OperatingSystem}}' | tr -d '\r')"
    "lorica_commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
    "lorica_tree_changes=$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
    "lorica_version=$(perf_compose exec -T perf-lorica lorica --version | tr -d '\r')"
    "baseline_version=$(perf_compose exec -T perf-lorica-baseline lorica --version | tr -d '\r')"
)
for svc in perf-lorica perf-lorica-baseline perf-nginx perf-backend perf-backend-http perf-client; do
    cid=$(container_of "$svc")
    env_pairs+=("image_${svc}=$(docker inspect --format '{{.Image}}' "$cid" | tr -d '\r')")
    env_pairs+=("cpuset_${svc}=$(docker inspect --format '{{.HostConfig.CpusetCpus}}' "$cid" | tr -d '\r')")
done
analyse env --runs "$RUNS" "${env_pairs[@]}"

# No container outside the perf project may run during a measurement; one
# that does makes every gated verdict INCONCLUSIVE (environment).
guard() {
    local foreign
    foreign=$(docker ps --format '{{.Names}} {{.Label "com.docker.compose.project"}}' | tr -d '\r' \
        | awk -v p="$PERF_PROJECT" '$2 != p { print $1 }' | tr '\n' ' ')
    # shellcheck disable=SC2086 # one argument per container name
    analyse guard --runs "$RUNS" --at "$1" $foreign
}

# ---- Readings from the proxy containers ----------------------------------
service_of() {
    case "$1" in
        lorica|L0|L1) echo perf-lorica ;;
        nginx) echo perf-nginx ;;
        B) echo perf-lorica-baseline ;;
    esac
}

# The container's CPU time in microseconds (cgroup v2, private cgroup
# namespace: the container's own cpu.stat).
cpu_usec() {
    perf_compose exec -T "$1" cat /sys/fs/cgroup/cpu.stat | tr -d '\r' | awk '$1 == "usage_usec" { print $2 }'
}

# Summed PSS in KiB of the proxy processes an exec user can read: Lorica's
# all run as `lorica`; nginx's master is root's and its workers nginx's,
# each readable only by its own user (no CAP_SYS_PTRACE in the container).
PSS_SCRIPT='
total=0
for d in /proc/[0-9]*; do
    case "$(cat "$d/comm" 2>/dev/null)" in
        lorica|nginx)
            v=$(awk "/^Pss:/ { print \$2 }" "$d/smaps_rollup" 2>/dev/null) || v=""
            [ -n "$v" ] && total=$((total + v)) ;;
    esac
done
echo "$total"
'
pss_kib() {
    local svc="$1" a b
    if [ "$svc" = perf-nginx ]; then
        a=$(perf_compose exec -T -u 0 "$svc" sh -c "$PSS_SCRIPT" | tr -d '\r')
        b=$(perf_compose exec -T -u 101 "$svc" sh -c "$PSS_SCRIPT" | tr -d '\r')
        echo $(( a + b ))
    else
        perf_compose exec -T "$svc" sh -c "$PSS_SCRIPT" | tr -d '\r'
    fi
}

# Each proxy process's CPU ticks (utime + stime of /proc/<pid>/stat, which
# any user may read), as `pid:ticks,...`. Their deltas over a run show how
# the run's connections were spread over the workers: the iperf3 streams
# arrive in one burst on a listening socket the workers share, and a run
# one worker carried alone used one core of the proxy's N. analyse.py
# keeps such a run out of the series (see IPERF_STREAMS_PER_WORKER).
PROC_TICKS_SCRIPT='
for d in /proc/[0-9]*; do
    case "$(cat "$d/comm" 2>/dev/null)" in
        lorica|nginx) awk -v pid="${d#/proc/}" "{ printf \"%s:%s,\", pid, \$14 + \$15 }" "$d/stat" 2>/dev/null ;;
    esac
done
'
proc_ticks() {
    perf_compose exec -T "$1" sh -c "$PROC_TICKS_SCRIPT" | tr -d '\r'
}

# ---- One run of each kind --------------------------------------------------
# Every runner takes <measurement> <attempt> <rep, 0 the warm-up> <arm>.

run_iperf() {
    local m="$1" attempt="$2" rep="$3" arm="$4" svc before after ticks_before ticks_after reverse=""
    svc=$(service_of "$arm")
    [ "$m" = tcp-down ] && reverse="-R"
    in_client rm -f /tmp/run.json
    ticks_before=$(proc_ticks "$svc")
    before=$(cpu_usec "$svc")
    in_client sh -c "iperf3 -c ${svc} -p 7001 -P $(( IPERF_STREAMS_PER_WORKER * PERF_WORKERS )) ${IPERF_ARGS} ${reverse} > /tmp/run.json" || true
    after=$(cpu_usec "$svc")
    ticks_after=$(proc_ticks "$svc")
    analyse record --runs "$RUNS" --measurement "$m" --attempt "$attempt" --rep "$rep" --arm "$arm" \
        --kind iperf --file /tmp/run.json --cpu-before "$before" --cpu-after "$after" \
        --ticks-before "$ticks_before" --ticks-after "$ticks_after" --workers "$PERF_WORKERS"
}

run_connect() {
    local m="$1" attempt="$2" rep="$3" arm="$4" svc
    svc=$(service_of "$arm")
    in_client rm -f /tmp/run.json
    in_client python3 /opt/perf/l4_connect_latency.py run --target "${svc}:7002" --control perf-backend:5203 \
        --count "$CONNECT_COUNT" --rate "$CONNECT_RATE" --out /tmp/run.json >/dev/null || true
    analyse record --runs "$RUNS" --measurement "$m" --attempt "$attempt" --rep "$rep" --arm "$arm" \
        --kind connect --file /tmp/run.json
}

# A proxy keeps a session for the idle timeout after its last datagram, so
# a second hold on the same proxy waits it out: S old sessions and S new
# ones would not fit in its ephemeral ports.
declare -A UDP_LAST_END=()
run_udp() {
    local m="$1" attempt="$2" rep="$3" arm="$4" svc ready_at before during peers
    svc=$(service_of "$arm")
    ready_at=$(( ${UDP_LAST_END[$arm]:-0} + UDP_IDLE_S + 5 ))
    while [ "$(date +%s)" -lt "$ready_at" ]; do
        sleep 1
    done
    in_client python3 /opt/perf/udp_echo_peers.py control --target perf-backend:5301 --command RESET >/dev/null
    in_client rm -f /tmp/hold.json
    before=$(pss_kib "$svc")
    perf_compose exec -d -T perf-client python3 /opt/perf-l4/udp_hold.py hold --target "${svc}:7003" \
        --sessions "$UDP_SESSIONS" --interval "$UDP_HOLD_INTERVAL_S" --duration "$UDP_HOLD_DURATION_S" \
        --timeout 1 --out /tmp/hold.json
    # Every session has been opened by the end of the first round (5 s) and
    # answered three rounds by 15 s.
    sleep 15
    during=$(pss_kib "$svc")
    in_client sh -c 'for i in $(seq 1 600); do [ -s /tmp/hold.json ] && exit 0; sleep 0.1; done; exit 1' \
        || echo "  the UDP hold wrote no result within 60 s of its middle"
    UDP_LAST_END[$arm]=$(date +%s)
    peers=$(in_client python3 /opt/perf/udp_echo_peers.py control --target perf-backend:5301 --command COUNT \
        | tr -d '\r' | sed -n 's/.*"peers": \([0-9]*\).*/\1/p')
    analyse record --runs "$RUNS" --measurement "$m" --attempt "$attempt" --rep "$rep" --arm "$arm" \
        --kind udp --file /tmp/hold.json --sessions "$UDP_SESSIONS" --peers "${peers:-0}" \
        --pss-before "$before" --pss-during "$during"
}

# NFR1: oha on the route, closed loop at saturation (`*-rps`) or at the
# fixed rate NFR1_RATE with coordinated-omission correction (`*-p99`). The
# L1 arm is L0's container with one idle TCP stream bound for the run.
run_oha() {
    local m="$1" attempt="$2" rep="$3" arm="$4" svc idle="" target load
    svc=$(service_of "$arm")
    case "$m" in
        nfr1-http-*) target="-H 'Host: perf.test' http://${svc}:8080/" ;;
        nfr1-https-*) target="--insecure --connect-to perf.test:8443:${svc}:8443 https://perf.test:8443/" ;;
    esac
    case "$m" in
        *-rps) load="-z ${OHA_SATURATION_S} -c ${OHA_CONNECTIONS}" ;;
        *-p99) load="-z ${OHA_FIXED_RATE_S} -c ${OHA_CONNECTIONS} -q ${NFR1_RATE} --latency-correction" ;;
    esac
    if [ "$arm" = L1 ]; then
        idle=$(create_stream "{\"name\":\"perf-idle\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7101,\"backend_ids\":[\"${IPERF_BACKEND}\"]}")
    fi
    in_client rm -f /tmp/run.json
    in_client sh -c "oha ${load} --no-tui --output-format json ${target} > /tmp/run.json" || true
    [ -n "$idle" ] && delete_stream "$idle"
    analyse record --runs "$RUNS" --measurement "$m" --attempt "$attempt" --rep "$rep" --arm "$arm" \
        --kind oha --file /tmp/run.json
}

# ---- Attempts, alternation and re-runs (D-j, D-k) --------------------------
# One attempt: a discarded warm-up run per arm, then PERF_REPS repetitions,
# every arm once each, the first arm rotating. A gated measurement is run
# again whole while one of its checks has no conclusive attempt, at most
# PERF_MAX_RERUNS times; a reported-only one runs once.
measure() {
    local m="$1" runner="$2" gated="$3" attempt=1 rep arm k started
    shift 3
    local arms=("$@") order
    started=$(date +%s)
    while :; do
        guard "${m} attempt ${attempt}"
        echo ""
        echo "--- ${m}, attempt ${attempt} (arms ${arms[*]}) ---"
        for arm in "${arms[@]}"; do
            "$runner" "$m" "$attempt" 0 "$arm"
        done
        for rep in $(seq 1 "$PERF_REPS"); do
            k=$(( (rep - 1) % ${#arms[@]} ))
            order=("${arms[@]:$k}" "${arms[@]:0:$k}")
            for arm in "${order[@]}"; do
                "$runner" "$m" "$attempt" "$rep" "$arm"
            done
        done
        [ "$gated" = gated ] || break
        if analyse settled --runs "$RUNS" --measurement "$m"; then
            break
        fi
        if [ "$attempt" -gt "$PERF_MAX_RERUNS" ]; then
            echo "  ${m}: still inconclusive after ${PERF_MAX_RERUNS} re-run(s)"
            break
        fi
        attempt=$(( attempt + 1 ))
    done
    echo "  ${m}: $(( $(date +%s) - started )) s"
}

wanted() {
    case ",${PERF_MEASUREMENTS}," in
        *",$1,"*) return 0 ;;
    esac
    return 1
}

TCP_STREAM_BASE='"protocol":"tcp","listen_address":"0.0.0.0","connect_timeout_ms":5000,"idle_timeout_s":600'

# 1. TCP throughput and CPU per GiB, upload then download.
if wanted tcp-up || wanted tcp-down; then
    stream=$(create_stream "{\"name\":\"perf-iperf\",${TCP_STREAM_BASE},\"port_first\":7001,\"backend_ids\":[\"${IPERF_BACKEND}\"]}")
    wanted tcp-up && measure tcp-up run_iperf gated lorica nginx
    wanted tcp-down && measure tcp-down run_iperf gated lorica nginx
    delete_stream "$stream"
fi

# 2. Connection setup.
if wanted connect; then
    stream=$(create_stream "{\"name\":\"perf-connect\",${TCP_STREAM_BASE},\"port_first\":7002,\"backend_ids\":[\"${CONNECT_BACKEND}\"]}")
    measure connect run_connect gated lorica nginx
    delete_stream "$stream"
fi

# 3. The UDP hold at 80 % of Lorica's derived ceiling, read with the
# stream in place (its listening sockets are part of the budget), then the
# stream's share raised to it. Caps and rates lifted for the client alone.
if wanted udp; then
    UDP_LIFTED='"source_session_cap":65535,"source_datagram_rate":1000000,"source_byte_rate":1073741824,"unbounded_responses":true,"requests_per_session":null'
    stream=$(create_stream "{\"name\":\"perf-udp\",\"protocol\":\"udp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7003,\"backend_ids\":[\"${UDP_BACKEND}\"],\"idle_timeout_s\":${UDP_IDLE_S},\"source_allow_cidrs\":[\"${CLIENT_IP}/32\"],\"udp\":{\"max_sessions\":100,${UDP_LIFTED}}}")
    UDP_CEILING=$(api perf-lorica GET /api/v1/streams/budget --field data.nodes.0.session_ceiling)
    UDP_BOUND_BY=$(api perf-lorica GET /api/v1/streams/budget --field data.nodes.0.session_ceiling_bound_by)
    UDP_SESSIONS=$(( UDP_CEILING * 8 / 10 ))
    held=$(api perf-lorica PUT "/api/v1/streams/${stream}" "{\"udp\":{\"max_sessions\":${UDP_SESSIONS},${UDP_LIFTED}}}" \
        --field data.udp.max_sessions)
    [ "$held" = "$UDP_SESSIONS" ] || die "max_sessions reads ${held} after the update to ${UDP_SESSIONS}"
    echo "UDP ceiling ${UDP_CEILING} (bound by ${UDP_BOUND_BY}): holding ${UDP_SESSIONS} sessions per run"
    analyse env --runs "$RUNS" "udp_ceiling=${UDP_CEILING}" "udp_ceiling_bound_by=${UDP_BOUND_BY}" \
        "udp_sessions=${UDP_SESSIONS}"
    measure udp run_udp gated lorica nginx
    delete_stream "$stream"
fi

# 4. NFR1: no stream on perf-lorica but L1's own. Throughput first, then
# p99 at half of 1.10.7's median saturation throughput of this run.
if wanted nfr1-http || wanted nfr1-https; then
    remaining=$(api perf-lorica GET /api/v1/streams --field data.streams)
    [ "$remaining" = "[]" ] || die "streams left on perf-lorica before NFR1: ${remaining}"
fi
if wanted nfr1-http; then
    measure nfr1-http-rps run_oha gated B L0 L1
    NFR1_RATE=$(analyse rate --runs "$RUNS" --measurement nfr1-http-rps --arm B --fraction 0.5 | tr -d '\r')
    echo "NFR1 HTTP fixed rate: ${NFR1_RATE} requests/s"
    analyse env --runs "$RUNS" "nfr1_http_rate=${NFR1_RATE}"
    measure nfr1-http-p99 run_oha gated B L0 L1
fi
if wanted nfr1-https; then
    measure nfr1-https-rps run_oha reported B L0 L1
    NFR1_RATE=$(analyse rate --runs "$RUNS" --measurement nfr1-https-rps --arm B --fraction 0.5 | tr -d '\r')
    echo "NFR1 HTTPS fixed rate: ${NFR1_RATE} requests/s"
    analyse env --runs "$RUNS" "nfr1_https_rate=${NFR1_RATE}"
    measure nfr1-https-p99 run_oha reported B L0 L1
fi

guard "end of the phase"
analyse env --runs "$RUNS" "phase_seconds=$(( $(date +%s) - PHASE_START ))"
report
