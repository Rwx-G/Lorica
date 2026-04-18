#!/bin/sh
# =============================================================================
# Lorica OTel E2E entrypoint for WORKER MODE (story 1.6 coverage).
#
# Worker-mode has a limitation the single-process path does not: the
# supervisor's `apply_otel_settings_from_store` hot-reload hook
# re-initialises OTel on the SUPERVISOR process only. Workers are
# forked at startup and inherit whatever OTel state the supervisor
# had at fork time; a dashboard edit to `otlp_endpoint` does not
# propagate into workers without a proper RPC reload command (tracked
# as a follow-up; out of scope for v1.4.0). For this smoke to exercise
# the worker-side OTel init path end-to-end, the entrypoint pre-seeds
# `otlp_endpoint` + related settings via sqlite3 BEFORE Lorica starts,
# so `try_init_otel_from_settings("worker")` sees a populated config
# at fork time and boots the BatchSpanProcessor in each worker.
#
#   1. Seed boot: start Lorica briefly so migrations run + admin
#      password is generated. Capture the password.
#   2. SIGTERM the seed instance and wait for exit.
#   3. sqlite3 INSERT the OTLP settings.
#   4. Start Lorica for real with `--workers 2` so the OTel init
#      exercises the forked-worker path.
# =============================================================================
set -eu

mkdir -p /shared

LOGFILE=/shared/lorica.log
SEED_LOG=/tmp/lorica_seed.log

# --- Step 1: migrations + capture admin password ---------------------------
lorica --data-dir /var/lib/lorica --management-port 19443 \
    > "$SEED_LOG" 2>&1 &
SEED_PID=$!

for i in $(seq 1 30); do
    if grep -q "Initial admin password:" "$SEED_LOG" 2>/dev/null; then
        PW=$(grep "Initial admin password:" "$SEED_LOG" | sed 's/.*Initial admin password: //')
        echo "$PW" > /shared/admin_password
        break
    fi
    if ! kill -0 "$SEED_PID" 2>/dev/null; then
        break
    fi
    sleep 1
done
sleep 2  # let settings writes settle

# --- Step 2: stop the seed instance ----------------------------------------
kill -TERM "$SEED_PID" 2>/dev/null || true
for i in $(seq 1 10); do
    kill -0 "$SEED_PID" 2>/dev/null || break
    sleep 1
done
kill -KILL "$SEED_PID" 2>/dev/null || true
wait "$SEED_PID" 2>/dev/null || true

# --- Step 3: pre-seed OTLP settings ----------------------------------------
# jaeger-workers:4318 is the Compose-network DNS name for the
# worker-mode Jaeger side-car; `http-proto` matches the reload path
# in `apply_otel_settings_from_store` and keeps the smoke identical
# to the single-process otel-smoke.
sqlite3 /var/lib/lorica/lorica.db <<'SQL'
INSERT OR REPLACE INTO global_settings (key, value)
    VALUES ('otlp_endpoint', 'http://jaeger-workers:4318');
INSERT OR REPLACE INTO global_settings (key, value)
    VALUES ('otlp_protocol', 'http-proto');
INSERT OR REPLACE INTO global_settings (key, value)
    VALUES ('otlp_service_name', 'lorica');
INSERT OR REPLACE INTO global_settings (key, value)
    VALUES ('otlp_sampling_ratio', '1.0');
SQL

# --- Step 4: start Lorica in worker mode -----------------------------------
: > "$LOGFILE"
socat TCP-LISTEN:9443,fork,reuseaddr TCP:127.0.0.1:19443 &

lorica --data-dir /var/lib/lorica --management-port 19443 --workers 2 \
    > "$LOGFILE" 2>&1 &
LORICA_PID=$!

cat "$LOGFILE" 2>/dev/null || true
tail -f "$LOGFILE" &

wait "$LORICA_PID"
