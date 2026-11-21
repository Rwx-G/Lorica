# shellcheck shell=bash
# Story 12.7 scenarios (Story 12.12 Lot G: IV1 as Story 12.7 handed it,
# and the SMTP banner template, Resolved 4). Sourced by l4/run-l4.sh;
# see that file for the scenario contract. The `l4s_*` and `l4c_*`
# helpers are l4/scenarios/12.2.sh's and 12.3.sh's.
#
# Backends: the pinned `redis` image, test-runner/l4/smtp_banner.py in
# two services (one greets with 220, one never writes), and Lot C's
# `pg-1` and `tcp-backend-2`. A health check runs at the loop's floor,
# MIN_PROBE_INTERVAL (5 s), with a 1 s timeout; a backend is marked down
# after HEALTH_FLIP_THRESHOLD (3) failing probes (lorica/src/health.rs).
# Streams use ports 775x, names start with `l4g-`.

L4G_INTERVAL_S=5
L4G_TIMEOUT_MS=1000
L4G_FLIP_THRESHOLD=3
# What the scenarios allow for a flip: the threshold's probes at the
# interval, the last probe's timeout, plus the loop's one-second tick
# per probe and a second for the API poll.
L4G_FLIP_LIMIT_S=$(( L4G_FLIP_THRESHOLD * L4G_INTERVAL_S + (L4G_TIMEOUT_MS + 999) / 1000 + L4G_FLIP_THRESHOLD + 1 ))

# A backend at <address> checked by <template> at the scenario's
# interval and timeout; prints its id, or the refusal and returns 1.
l4g_template_backend() {
    l4s_create_backend "{\"address\":\"$1\",\"health_check_enabled\":true,\"health_check_interval_s\":${L4G_INTERVAL_S},\"health_check\":{\"kind\":\"tcp_template\",\"template\":\"$2\",\"timeout_ms\":${L4G_TIMEOUT_MS}}}"
}

l4g_delete_backend() {
    l4s_client_script 'api DELETE "/api/v1/backends/$1" >/dev/null' "$1" >/dev/null 2>&1 || true
}

# The sum of lorica_backend_health_probe_failures_total for one backend
# and reason (every reason when none is given); 0 when no series exists.
l4g_probe_failures() {
    l4_api GET /metrics | tr -d '\r' | awk -v id="backend_id=\"$1\"" -v r="${2:-}" '
        index($0, "lorica_backend_health_probe_failures_total{") == 1 && index($0, id) \
            && (r == "" || index($0, "reason=\"" r "\"")) { s += $NF }
        END { print s + 0 }'
}

# Connections Redis has accepted since it started (INFO stats).
l4g_redis_connections() {
    l4_compose exec -T redis redis-cli info stats | tr -d '\r' | awk -F: '$1 == "total_connections_received" {print $2}'
}

# <n> connections through l4-node:<port>, each sending a Redis PING and
# reading the first line back: a tally of who answered (`redis` for
# +PONG, a tcp_backend.py name, `timeout`, `closed`).
L4G_PING_TALLY='import socket, sys
from collections import Counter
port, n = int(sys.argv[1]), int(sys.argv[2])
tally = Counter()
for _ in range(n):
    try:
        with socket.create_connection(("l4-node", port), timeout=3) as s:
            s.sendall(b"PING\r\n")
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(1)
                if not chunk:
                    break
                buf += chunk
        line = buf.decode(errors="replace").strip()
        if line == "+PONG":
            tally["redis"] += 1
        elif line.startswith("name="):
            tally[line.split()[0][5:]] += 1
        else:
            tally["closed" if not line else "other"] += 1
    except socket.timeout:
        tally["timeout"] += 1
    except OSError as e:
        tally["error" + type(e).__name__] += 1
print(" ".join(f"{k}={v}" for k, v in sorted(tally.items())))
'

l4g_ping_tally() {
    l4_client python3 -c "$L4G_PING_TALLY" "$@" | tr -d '\r'
}

# The lines a service logged since <RFC 3339 time>.
l4g_logs_since() {
    l4_compose logs --no-color --no-log-prefix --since "$2" "$1" 2>/dev/null | tr -d '\r'
}

# ---- IV1 -------------------------------------------------------------

# IV1, as Story 12.7 handed it: a real Redis behind a TCP stream, its
# backend on tcp_template{redis_ping}, beside a second backend. `docker
# pause` freezes Redis while the kernel keeps completing handshakes into
# its backlog: the backend is marked down within the threshold's probes
# at the interval plus the timeout, by response_timeout, and the stream
# stops selecting it; `docker unpause` brings it back. Along the way it
# records what Redis and PostgreSQL log per probe (Story 12.7 Dev Notes,
# "Backend-side noise"): Redis under its own probe, PostgreSQL (`pg-1`)
# under a postgresql_ssl_request probe for a few intervals.
scenario_12_7_iv1_redis_paused_marked_down() {
    local since redis other id before down failures during up after redis_lines pg pg_since pg_lines pg_status i conns
    trap 'l4s_cleanup_streams l4g-iv1-; l4_compose unpause redis >/dev/null 2>&1 || true' EXIT
    l4s_cleanup_streams l4g-iv1-
    for i in $(seq 1 30); do
        [ "$(l4_compose exec -T redis redis-cli ping 2>/dev/null | tr -d '\r')" = PONG ] && break
        sleep 1
    done
    since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    redis=$(l4g_template_backend "$(l4c_ip redis):6379" redis_ping) || fail "backend: ${redis}"
    other=$(l4c_backend "$(l4c_ip tcp-backend-2):9000" nocheck) || fail "backend: ${other}"
    id=$(l4s_create_stream "{\"name\":\"l4g-iv1-redis\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7750,\"backend_ids\":[\"${redis}\",\"${other}\"]}") \
        || fail "stream create refused: ${id}"
    l4s_wait_bind "$id" bound 5 >/dev/null || fail "the stream did not bind"
    # Healthy, and staying so over the threshold's probes, before the pause.
    l4c_wait_health "$redis" healthy 30 >/dev/null || fail "the Redis backend never read healthy"
    conns=$(l4g_redis_connections)
    sleep $(( L4G_FLIP_THRESHOLD * L4G_INTERVAL_S ))
    conns=$(( $(l4g_redis_connections) - conns ))
    [ "$(l4g_probe_failures "$redis" response_timeout)" = 0 ] || fail "redis_ping probes failed against a running Redis"
    before=$(l4g_ping_tally 7750 10)
    [ "$(l4c_count "$before" redis)" -ge 1 ] && [ "$(l4c_count "$before" tcp-backend-2)" -ge 1 ] \
        || fail "the stream does not balance over Redis and the second backend: ${before}"
    redis_lines=$(l4g_logs_since redis "$since" | grep -c . || true)

    l4_compose pause redis >/dev/null || fail "docker pause of redis failed"
    down=$(l4c_wait_health "$redis" down "$L4G_FLIP_LIMIT_S") \
        || fail "the paused Redis was not marked down within ${L4G_FLIP_LIMIT_S} s: ${down}"
    failures=$(l4g_probe_failures "$redis" response_timeout)
    [ "$failures" -ge "$L4G_FLIP_THRESHOLD" ] || fail "${failures} response_timeout probe failures counted for the paused Redis"
    during=$(l4g_ping_tally 7750 10)
    [ "$during" = "tcp-backend-2=10" ] || fail "the stream still selected the paused Redis: ${during}"

    l4_compose unpause redis >/dev/null || fail "docker unpause of redis failed"
    up=$(l4c_wait_health "$redis" healthy $(( L4G_FLIP_LIMIT_S + 10 ))) || fail "Redis was not healthy again after the unpause: ${up}"
    after=$(l4g_ping_tally 7750 10)
    [ "$(l4c_count "$after" redis)" -ge 1 ] || fail "the stream did not select Redis again: ${after}"

    # PostgreSQL under its template, for the threshold's probes.
    pg_since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    pg=$(l4g_template_backend "$(l4c_ip pg-1):5432" postgresql_ssl_request) || fail "backend: ${pg}"
    sleep $(( L4G_FLIP_THRESHOLD * L4G_INTERVAL_S + 2 ))
    pg_status=$(l4_api GET "/api/v1/backends/${pg}" | l4_client jq -r .data.health_status | tr -d '\r')
    l4g_delete_backend "$pg"
    pg_lines=$(l4g_logs_since pg-1 "$pg_since" | grep -c . || true)
    [ "$pg_status" = healthy ] && [ "$(l4g_probe_failures "$pg" no_match)" = 0 ] \
        || fail "the postgresql_ssl_request backend on pg-1 read ${pg_status}"
    l4g_delete_backend "$redis"
    pass "redis_ping on a running Redis: healthy, stream ${before}; paused: marked down in ${down} ms (limit ${L4G_FLIP_LIMIT_S} s: ${L4G_FLIP_THRESHOLD} x ${L4G_INTERVAL_S} s + ${L4G_TIMEOUT_MS} ms + ticks), ${failures} response_timeout probe failures, stream ${during}; unpaused: healthy in ${up} ms, stream ${after}; backend-side noise: Redis accepted ${conns} connection(s) in ${L4G_FLIP_THRESHOLD} intervals of its probe and logged ${redis_lines} line(s) since the backend was created, pg-1 ${pg_lines} line(s) over ${L4G_FLIP_THRESHOLD}+ postgresql_ssl_request probes"
}

# ---- AC #3, the SMTP banner template (Resolved 4) --------------------

# smtp_banner against the standard-library banner server: a backend on
# the server that writes `220 example.com ESMTP` stays healthy with no
# failed probe, one on the server that never writes is marked down
# within the threshold's probes at the interval plus the timeout, by
# response_timeout. The banner server's own log counts the probes it
# saw, each closed by Lorica without a byte sent (no QUIT).
scenario_12_7_x_smtp_banner_template() {
    local since banner silent down banner_status banner_failures silent_failures probes sent
    since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    banner=$(l4g_template_backend "$(l4c_ip smtp-banner):2525" smtp_banner) || fail "backend: ${banner}"
    silent=$(l4g_template_backend "$(l4c_ip smtp-silent):2525" smtp_banner) || fail "backend: ${silent}"
    trap 'l4g_delete_backend '"$banner"'; l4g_delete_backend '"$silent" EXIT
    down=$(l4c_wait_health "$silent" down "$L4G_FLIP_LIMIT_S") \
        || fail "the server that never writes was not marked down within ${L4G_FLIP_LIMIT_S} s of the create: ${down}"
    banner_status=$(l4_api GET "/api/v1/backends/${banner}" | l4_client jq -r .data.health_status | tr -d '\r')
    banner_failures=$(l4g_probe_failures "$banner")
    silent_failures=$(l4g_probe_failures "$silent" response_timeout)
    local seen ends
    seen=$(l4g_logs_since smtp-banner "$since")
    probes=$(printf '%s\n' "$seen" | grep -c '^connection from [0-9.]*$' || true)
    sent=$(printf '%s\n' "$seen" | grep -c 'closed by the client after [1-9]' || true)
    ends=$(printf '%s\n' "$seen" | grep '^connection from .* \(closed\|ended\)' | sed 's/^connection from [0-9.]* //; s/after 0 bytes/with no byte sent/' | sort | uniq -c | awk '{n = $1; $1 = ""; printf "%s%s x%s", sep, substr($0, 2), n; sep = ", "}')
    [ "$banner_status" = healthy ] && [ "$banner_failures" = 0 ] \
        || fail "the 220 server's backend read ${banner_status} with ${banner_failures} failed probe(s)"
    [ "$silent_failures" -ge "$L4G_FLIP_THRESHOLD" ] || fail "${silent_failures} response_timeout probe failures for the server that never writes"
    [ "$probes" -ge "$L4G_FLIP_THRESHOLD" ] || fail "the 220 server saw ${probes} probe(s); its log since the create: $(printf '%s' "$seen" | tail -n 5 | tr '\n' '|')"
    [ "$sent" = 0 ] || fail "${sent} probe(s) sent bytes to the 220 server"
    pass "220 server: healthy, 0 failed probes, ${probes} probes seen (${ends:-no end logged yet}); silent server: marked down ${down} ms after the create (limit ${L4G_FLIP_LIMIT_S} s), ${silent_failures} response_timeout probe failures"
}
