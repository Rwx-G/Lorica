# shellcheck shell=bash
# Story 12.9 scenarios (Story 12.12 Lot I, the items of Story 12.9 Lot J),
# in the `streams` profile: one node, two workers. Sourced by
# l4/run-l4.sh; see that file for the scenario contract. Uses the
# shared `l4s_*` helpers of l4/lib.sh.
#
# Every row is asserted where the dashboard reads it (`GET
# /api/v1/stream-logs`) and as an RFC 5424 frame with MSGID `stream` in
# the `syslog-collector` service. The OTLP lane is not exercised: the L4
# image is built without the `otel` feature (one image for every L4
# node), and Lot J asserts the syslog lane only.

# Ports of this file's streams, apart from every other scenario's.
L4O_PORT_REFUSED=7910
L4O_PORT_IDLE=7911
L4O_PORT_DRAIN=7912
L4O_PORT_METRICS=7913
L4O_PORT_SLA=7914
L4O_BACKEND=tcp-backend-1:9000
L4O_SYSLOG=syslog-collector:6601
# The node's worker count (entrypoint-streams.sh): each process has its
# own refusal-log window per key (lorica-stream/src/refusal_log.rs).
L4O_WORKERS=2

# Delete this file's streams and backends, and put the settings the
# scenarios move back to their defaults.
L4O_CLEANUP_SCRIPT='
api GET /api/v1/streams | jq -r ".data.streams[] | select(.name | startswith(\"l4o-\")) | .id" |
while read -r id; do api DELETE "/api/v1/streams/$id" >/dev/null || true; done
api GET /api/v1/backends | jq -r ".data.backends[] | select((.name // \"\") | startswith(\"l4o-\")) | .id" |
while read -r id; do api DELETE "/api/v1/backends/$id" >/dev/null || true; done
api PUT /api/v1/settings "{\"worker_drain_timeout_s\":30,\"syslog_endpoint\":\"\"}" >/dev/null
'

l4o_cleanup() {
    l4s_client_script "$L4O_CLEANUP_SCRIPT" >/dev/null 2>&1 || true
}

# Point the node's syslog sink at the collector (TCP; the stream kind is
# on by default).
l4o_sink_ready() {
    local out
    out=$(l4_api PUT /api/v1/settings "{\"syslog_endpoint\":\"${L4O_SYSLOG}\",\"syslog_transport\":\"tcp\"}" | tr -d '\r')
    printf '%s' "$out" | l4_client jq -e '.data.syslog_endpoint == "'"${L4O_SYSLOG}"'" and .data.syslog_stream_enabled == true' >/dev/null
}

# A backend on tcp-backend-1 (identity line then echo, after the
# client's first bytes): prints its id.
l4o_backend() {
    l4s_create_backend "{\"name\":\"l4o-$1\",\"address\":\"${L4O_BACKEND}\",\"health_check_enabled\":false}"
}

# Create a TCP stream from extra JSON fields and wait for it to bind:
# prints its id, or the refusal and returns 1.
l4o_stream() {
    local name="$1" port="$2" extra="$3" id
    id=$(l4s_create_stream "{\"name\":\"${name}\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":${port}${extra:+,$extra}}") || { echo "$id"; return 1; }
    l4s_wait_bind "$id" bound 5 >/dev/null || { echo "${name} did not bind"; return 1; }
    echo "$id"
}

# The stream frames the collector holds, one per line (RFC 5424 header,
# MSGID `stream`, then the JSON body, which holds no `<`).
l4o_stream_frames() {
    l4_compose exec -T syslog-collector sh -c 'cat /tmp/syslog/*.log 2>/dev/null' \
        | grep -aoE '<[0-9]+>1 [^ ]+ [^ ]+ lorica [0-9]+ stream [^<]*' || true
}

# Wait up to 15 s for a stream frame of <stream id> holding every given
# `"key":"value"` fragment; prints the frame.
l4o_wait_frame() {
    local id="$1" i frame fragment
    shift
    for i in $(seq 1 30); do
        frame=$(l4o_stream_frames | grep -F "\"stream_id\":\"${id}\"" || true)
        for fragment in "$@"; do
            frame=$(printf '%s\n' "$frame" | grep -F "$fragment" || true)
        done
        if [ -n "$frame" ]; then
            printf '%s\n' "$frame" | head -n 1
            return 0
        fi
        sleep 0.5
    done
    return 1
}

# The rows of one stream as one JSON array (oldest first), from the
# endpoint the dashboard reads.
L4O_ROWS_SCRIPT='
api GET "/api/v1/stream-logs?stream_id=$1&limit=500" | jq -c ".data.entries | sort_by(.id)"
'

l4o_rows() {
    l4s_client_script "$L4O_ROWS_SCRIPT" "$1" | tr -d '\r'
}

# Refused: one connect, a pause, then a burst, all from the client the
# stream denies; then wait until every refusal is accounted for in the
# rows (refused rows plus the counts of the suppressed rows), which the
# limiter completes when its windows close, 10 s after they opened.
# Prints the rows.
L4O_REFUSED_SCRIPT='
id=$1 port=$2 burst=$3
python3 - "$port" "$burst" <<"PY"
import socket, sys, time
port, burst = int(sys.argv[1]), int(sys.argv[2])
def knock():
    try:
        with socket.create_connection(("l4-node", port), timeout=3) as s:
            s.sendall(b"knock\n")
            while s.recv(4096):
                pass
    except OSError:
        pass
knock()
time.sleep(1)
for _ in range(burst):
    knock()
PY
want=$(( burst + 1 ))
for i in $(seq 1 60); do
    rows=$(api GET "/api/v1/stream-logs?stream_id=$id&limit=500" | jq -c ".data.entries | sort_by(.id)")
    got=$(printf "%s" "$rows" | jq "[.[] | if .entry == \"refusals_suppressed\" then .suppressed else 1 end] | add // 0")
    if [ "$got" -ge "$want" ]; then
        printf "%s\n" "$rows"
        exit 0
    fi
    sleep 0.5
done
echo "rows account for ${got} of ${want} refusals: $rows" >&2
exit 1
'

# Idle: a connection that sends nothing on a stream with a 2 s idle
# timeout; prints the seconds until the node closed it.
L4O_IDLE_CLIENT='import socket, sys, time
t0 = time.monotonic()
with socket.create_connection(("l4-node", int(sys.argv[1])), timeout=20) as s:
    try:
        while s.recv(4096):
            pass
    except OSError:
        pass
print(f"{time.monotonic() - t0:.2f}")
'

# config_removed: hold a connection (one echo exchanged), unlink the
# backend from the stream and time, from that update, the row that ends
# the connection with `config_removed`. Prints `ms=<n> closed_after=<s>`.
L4O_DRAIN_SCRIPT='
id=$1 port=$2
rm -f /tmp/l4o-held.ready /tmp/l4o-held.closed
python3 - "$port" <<"PY" &
import socket, sys, time
s = socket.create_connection(("l4-node", int(sys.argv[1])), timeout=30)
s.sendall(b"held\n")
got = b""
while b"held" not in got:
    got += s.recv(4096)
open("/tmp/l4o-held.ready", "w").close()
t0 = time.monotonic()
try:
    while s.recv(4096):
        pass
except OSError:
    pass
with open("/tmp/l4o-held.closed", "w") as f:
    f.write(f"{time.monotonic() - t0:.2f}")
PY
for i in $(seq 1 50); do [ -e /tmp/l4o-held.ready ] && break; sleep 0.1; done
[ -e /tmp/l4o-held.ready ] || { echo "the held connection got no echo"; exit 1; }
t0=$(now_us)
api PUT "/api/v1/streams/$id" "{\"backend_ids\":[]}" >/dev/null
while :; do
    n=$(api GET "/api/v1/stream-logs?stream_id=$id&end_reason=config_removed" | jq ".data.total")
    ms=$(( ($(now_us) - t0) / 1000 ))
    [ "$n" -ge 1 ] && break
    if [ "$ms" -ge 15000 ]; then echo "no config_removed row ${ms} ms after the update"; exit 1; fi
    sleep 0.2
done
wait
echo "ms=$ms closed_after=$(cat /tmp/l4o-held.closed 2>/dev/null || echo unknown)"
'

# IV1 (partial: the dashboard is not driven): a refused connection, an
# idle-timeout close and a config_removed drain each produce a row with
# the right end reason, in GET /api/v1/stream-logs (what the dashboard
# reads) and in the syslog collector.
scenario_12_9_iv1_end_reasons_in_api_and_syslog() {
    local client bid refused_id idle_id drain_id rows first refused_rows supp_rows supp_sum idle_s idle_rows drain f burst=30
    trap 'l4o_cleanup' EXIT
    l4o_cleanup
    l4o_sink_ready || fail "the syslog sink could not be pointed at ${L4O_SYSLOG}"
    client=$(l4s_client_ip)
    bid=$(l4o_backend iv1) || fail "backend create refused: ${bid}"

    # Refused, by the stream's deny list holding the client.
    refused_id=$(l4o_stream l4o-iv1-refused "$L4O_PORT_REFUSED" "\"backend_ids\":[\"${bid}\"],\"source_deny_cidrs\":[\"${client}/32\"]") \
        || fail "refused stream: ${refused_id}"
    rows=$(l4s_client_script "$L4O_REFUSED_SCRIPT" "$refused_id" "$L4O_PORT_REFUSED" "$burst" 2>&1 | tr -d '\r') \
        || fail "refusals not accounted for in the rows: ${rows}"
    first=$(printf '%s' "$rows" | l4_client jq -c '.[0] | {entry, end_reason, refusal_reason, client_ip}' | tr -d '\r')
    [ "$first" = "{\"entry\":\"ended\",\"end_reason\":\"refused\",\"refusal_reason\":\"source_denied\",\"client_ip\":\"${client}\"}" ] \
        || fail "the first refusal row is ${first}"
    refused_rows=$(printf '%s' "$rows" | l4_client jq '[.[] | select(.entry == "ended" and .end_reason == "refused" and .refusal_reason == "source_denied")] | length' | tr -d '\r')
    supp_rows=$(printf '%s' "$rows" | l4_client jq '[.[] | select(.entry == "refusals_suppressed" and .end_reason == "refused" and .refusal_reason == "source_denied")] | length' | tr -d '\r')
    supp_sum=$(printf '%s' "$rows" | l4_client jq '[.[] | select(.entry == "refusals_suppressed") | .suppressed] | add // 0' | tr -d '\r')
    [ "$(printf '%s' "$rows" | l4_client jq 'length' | tr -d '\r')" -eq $(( refused_rows + supp_rows )) ] \
        || fail "rows other than refusals on the refused stream: ${rows}"
    [ "$refused_rows" -ge 1 ] && [ "$refused_rows" -le "$L4O_WORKERS" ] \
        || fail "${refused_rows} refused rows for $(( burst + 1 )) refusals within one window, expected 1 to ${L4O_WORKERS} (one per process)"
    [ "$supp_rows" -ge 1 ] && [ "$supp_rows" -le "$L4O_WORKERS" ] \
        || fail "${supp_rows} refusals_suppressed rows, expected 1 to ${L4O_WORKERS} (one per process window)"
    [ $(( refused_rows + supp_sum )) -eq $(( burst + 1 )) ] \
        || fail "${refused_rows} refused rows plus ${supp_sum} suppressed count for $(( burst + 1 )) refusals"
    l4o_wait_frame "$refused_id" '"entry":"ended"' '"end_reason":"refused"' '"refusal_reason":"source_denied"' >/dev/null \
        || fail "no syslog frame of the refused row"
    l4o_wait_frame "$refused_id" '"entry":"refusals_suppressed"' '"end_reason":"refused"' >/dev/null \
        || fail "no syslog frame of the refusals_suppressed row"

    # Idle timeout of 2 s, a connection that sends nothing.
    idle_id=$(l4o_stream l4o-iv1-idle "$L4O_PORT_IDLE" "\"backend_ids\":[\"${bid}\"],\"idle_timeout_s\":2") \
        || fail "idle stream: ${idle_id}"
    idle_s=$(l4_client python3 -c "$L4O_IDLE_CLIENT" "$L4O_PORT_IDLE" | tr -d '\r')
    local i
    for i in $(seq 1 30); do
        idle_rows=$(l4o_rows "$idle_id")
        [ "$(printf '%s' "$idle_rows" | l4_client jq 'length' | tr -d '\r')" -ge 1 ] && break
        sleep 0.5
    done
    [ "$(printf '%s' "$idle_rows" | l4_client jq -r '[.[] | .end_reason] | join(",")' | tr -d '\r')" = idle_timeout ] \
        || fail "the idle connection's rows (closed after ${idle_s} s): ${idle_rows}"
    l4o_wait_frame "$idle_id" '"end_reason":"idle_timeout"' >/dev/null \
        || fail "no syslog frame of the idle_timeout row"

    # config_removed: worker_drain_timeout_s = 3, the backend unlinked
    # from the stream under an open connection; the row within 3 + 2 s.
    l4_api PUT /api/v1/settings '{"worker_drain_timeout_s":3}' >/dev/null || fail "worker_drain_timeout_s = 3 refused"
    drain_id=$(l4o_stream l4o-iv1-drain "$L4O_PORT_DRAIN" "\"backend_ids\":[\"${bid}\"],\"idle_timeout_s\":60") \
        || fail "drain stream: ${drain_id}"
    drain=$(l4s_client_script "$L4O_DRAIN_SCRIPT" "$drain_id" "$L4O_PORT_DRAIN" 2>&1 | tr -d '\r') \
        || fail "config_removed: ${drain}"
    f=${drain#ms=}
    f=${f%% *}
    [ "$f" -le 5000 ] || fail "the config_removed row came ${f} ms after the backend was unlinked, past the 3 s drain plus 2 s"
    l4o_wait_frame "$drain_id" '"end_reason":"config_removed"' >/dev/null \
        || fail "no syslog frame of the config_removed row"

    partial "refused: first row source_denied from ${client}, ${refused_rows} refused row(s) and ${supp_rows} refusals_suppressed row(s) counting ${supp_sum}, for $(( burst + 1 )) refusals; idle_timeout row (closed after ${idle_s} s on a 2 s timeout); config_removed row ${drain}; each also a syslog frame with MSGID stream -- not automated: the dashboard rendering of these rows (no browser in the suite); asserted in GET /api/v1/stream-logs, which the dashboard reads"
}

# A stream whose one connection exchanges an echo and then idles out.
# Prints its id.
l4o_idle_connection() {
    local name="$1" port="$2" bid="$3" id
    id=$(l4o_stream "$name" "$port" "\"backend_ids\":[\"${bid}\"],\"idle_timeout_s\":2") || { echo "$id"; return 1; }
    l4_client python3 -c '
import socket, sys
with socket.create_connection(("l4-node", int(sys.argv[1])), timeout=20) as s:
    s.sendall(b"ping\n")
    got = b""
    while b"ping" not in got:
        got += s.recv(4096)
    while s.recv(4096):
        pass
' "$port" >/dev/null || { echo "the echo through ${name} failed"; return 1; }
    echo "$id"
}

# Sum of a family's series on the supervisor's /metrics that hold every
# given label matcher; empty when no series matches.
L4O_METRIC_SCRIPT='
name=$1
shift
lines=$(api GET /metrics | grep "^${name}{" || true)
for m in "$@"; do lines=$(printf "%s\n" "$lines" | grep -F "$m" || true); done
printf "%s\n" "$lines" | awk "NF { s += \$NF; n++ } END { if (n) printf \"%d\n\", s }"
'

l4o_metric() {
    l4s_client_script "$L4O_METRIC_SCRIPT" "$@" | tr -d '\r'
}

# Poll the syslog sink gauge until it reads <want>, within <seconds>;
# prints the client's CLOCK_REALTIME when it did (seconds), exit 1 past
# the limit.
L4O_GAUGE_WAIT_SCRIPT='
want=$1 limit=$2
t0=$(now_us)
while :; do
    v=$(api GET /metrics | grep -F "lorica_log_sink_up{sink=\"syslog\"}" | awk "{ print \$NF }")
    if [ "$v" = "$want" ]; then echo "$EPOCHREALTIME"; exit 0; fi
    if [ $(( ($(now_us) - t0) / 1000000 )) -ge "$limit" ]; then echo "still ${v:-absent} after ${limit} s"; exit 1; fi
    sleep 0.5
done
'

# A container state time (FinishedAt, StartedAt) as seconds since the
# epoch, the VM clock the client's EPOCHREALTIME reads too.
l4o_container_time() {
    local field="$1" cid stamp
    cid=$(l4_compose ps -aq syslog-collector | tr -d '\r')
    stamp=$(docker inspect -f "{{.State.${field}}}" "$cid" | tr -d '\r')
    l4_client python3 -c "
import datetime, re, sys
stamp = re.sub(r'(\.\d{6})\d*', r'\1', sys.argv[1]).replace('Z', '+00:00')
print(f'{datetime.datetime.fromisoformat(stamp).timestamp():.6f}')
" "$stamp" | tr -d '\r'
}

# Lot J's metrics: lorica_stream_ended_total{reason="idle_timeout"} on
# the supervisor's /metrics (a value only the workers hold, so the
# aggregation is proven), lorica_stream_bytes_total above zero, and
# lorica_log_sink_up{sink="syslog"} 1, then 0 within 10 s of the
# collector stopping, then 1 within 40 s of its restart with no traffic
# in between.
scenario_12_9_x_metrics_and_sink_up() {
    local bid id ended bytes i down_at stopped up_at started down_s up_s
    trap 'l4_compose start syslog-collector >/dev/null 2>&1 || true; l4o_cleanup' EXIT
    l4o_cleanup
    l4o_sink_ready || fail "the syslog sink could not be pointed at ${L4O_SYSLOG}"
    bid=$(l4o_backend metrics) || fail "backend create refused: ${bid}"
    id=$(l4o_idle_connection l4o-metrics "$L4O_PORT_METRICS" "$bid") || fail "${id}"

    for i in $(seq 1 30); do
        ended=$(l4o_metric lorica_stream_ended_total "stream_id=\"${id}\"" 'reason="idle_timeout"')
        bytes=$(l4o_metric lorica_stream_bytes_total "stream_id=\"${id}\"")
        [ "${ended:-0}" -ge 1 ] && [ "${bytes:-0}" -gt 0 ] && break
        sleep 0.5
    done
    [ "${ended:-0}" -ge 1 ] || fail "lorica_stream_ended_total{stream_id=${id},reason=idle_timeout} reads '${ended}' on the supervisor"
    [ "${bytes:-0}" -gt 0 ] || fail "lorica_stream_bytes_total{stream_id=${id}} reads '${bytes}'"

    l4s_client_script "$L4O_GAUGE_WAIT_SCRIPT" 1 20 >/dev/null || fail "lorica_log_sink_up{sink=syslog} never read 1 with the collector up"
    l4_compose stop -t 2 syslog-collector >/dev/null 2>&1
    stopped=$(l4o_container_time FinishedAt)
    down_at=$(l4s_client_script "$L4O_GAUGE_WAIT_SCRIPT" 0 30 | tr -d '\r') || fail "the sink gauge after the collector stopped: ${down_at}"
    down_s=$(l4s_seconds_between "$stopped" "$down_at")
    l4s_less_than "$down_s" 10 || fail "the sink gauge read 0 ${down_s} s after the collector stopped, not within 10 s"

    l4_compose start syslog-collector >/dev/null 2>&1
    started=$(l4o_container_time StartedAt)
    up_at=$(l4s_client_script "$L4O_GAUGE_WAIT_SCRIPT" 1 60 | tr -d '\r') || fail "the sink gauge after the collector restarted: ${up_at}"
    up_s=$(l4s_seconds_between "$started" "$up_at")
    l4s_less_than "$up_s" 40 || fail "the sink gauge read 1 ${up_s} s after the collector restarted, not within 40 s"

    pass "on the supervisor: stream_ended_total{reason=idle_timeout} ${ended}, stream_bytes_total ${bytes} for ${id}; log_sink_up{sink=syslog} 1, 0 at ${down_s} s after the collector stopped, 1 at ${up_s} s after it started, no traffic between"
}

# Lot J's stream SLA: after connections through a stream, GET
# /api/v1/sla/streams/{id} has judged them. Buckets are flushed once
# their minute is over, by a 60 s task in each process, so the wait
# allows three minutes.
scenario_12_9_x_stream_sla() {
    local bid id sla judged i conns=5
    trap 'l4o_cleanup' EXIT
    l4o_cleanup
    bid=$(l4o_backend sla) || fail "backend create refused: ${bid}"
    id=$(l4o_stream l4o-sla "$L4O_PORT_SLA" "\"backend_ids\":[\"${bid}\"]") || fail "sla stream: ${id}"
    l4_client python3 -c '
import socket, sys
for _ in range(int(sys.argv[2])):
    with socket.create_connection(("l4-node", int(sys.argv[1])), timeout=5) as s:
        s.sendall(b"sla\n")
        got = b""
        while b"sla" not in got:
            got += s.recv(4096)
' "$L4O_PORT_SLA" "$conns" || fail "a connection through the SLA stream failed"

    for i in $(seq 1 90); do
        sla=$(l4_api GET "/api/v1/sla/streams/${id}" | tr -d '\r')
        judged=$(printf '%s' "$sla" | l4_client jq '[.data[].judged_count] | max // 0' | tr -d '\r')
        [ "${judged:-0}" -ge "$conns" ] && break
        sleep 2
    done
    [ "${judged:-0}" -ge "$conns" ] || fail "the stream SLA judged ${judged:-0} of ${conns} connections after 180 s: ${sla}"
    local window
    window=$(printf '%s' "$sla" | l4_client jq -c "[.data[] | select(.judged_count >= ${conns})][0] | {window, judged_count, success_count, failure_count, sla_pct}" | tr -d '\r')
    [ "$(printf '%s' "$window" | l4_client jq '.failure_count' | tr -d '\r')" = 0 ] || fail "failures judged on a healthy backend: ${window}"
    pass "GET /api/v1/sla/streams/${id} after ${conns} connections: ${window}"
}
