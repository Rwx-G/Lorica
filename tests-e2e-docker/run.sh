#!/usr/bin/env bash
# Run the Lorica E2E test suite with Docker Compose.
# Usage: ./run.sh [--build] [--keep] [--skip-workers] [--skip-cert-export] [--skip-ai-bot] [--skip-rbac] [--skip-hot-upgrade] [--skip-log-sinks]
#   --build             Force rebuild all images
#   --keep              Don't tear down containers after tests
#   --skip-workers      Skip worker isolation tests (faster)
#   --skip-cert-export  Skip the v1.4.1 cert-export profile (faster)
#   --skip-ai-bot       Skip the v1.6.0 Story 8.2 AI-bot profile (faster)
#   --skip-rbac         Skip the v1.6.0 Story 8.3 RBAC profile (faster)
#   --skip-audit        Skip the v1.6.0 Story 8.9 audit-log profile (faster)
#   --skip-hot-upgrade  Skip the v1.6.0 Story 8.4 hot binary-upgrade profile (faster)
#   --skip-log-sinks    Skip the v1.7.0 Story 9.8 log-sinks profile (faster)

set -euo pipefail
cd "$(dirname "$0")"

BUILD_FLAG=""
KEEP=false
SKIP_WORKERS=false
SKIP_CERT_EXPORT=false
SKIP_AI_BOT=false
SKIP_RBAC=false
SKIP_AUDIT=false
SKIP_HOT_UPGRADE=false
SKIP_LOG_SINKS=false

for arg in "$@"; do
    case "$arg" in
        --build)             BUILD_FLAG="--build" ;;
        --keep)              KEEP=true ;;
        --skip-workers)      SKIP_WORKERS=true ;;
        --skip-cert-export)  SKIP_CERT_EXPORT=true ;;
        --skip-ai-bot)       SKIP_AI_BOT=true ;;
        --skip-rbac)         SKIP_RBAC=true ;;
        --skip-audit)        SKIP_AUDIT=true ;;
        --skip-hot-upgrade)  SKIP_HOT_UPGRADE=true ;;
        --skip-log-sinks)    SKIP_LOG_SINKS=true ;;
    esac
done

EXIT_CODE=0

# Profile-gated services need explicit --profile flags: on teardown
# `down -v` otherwise skips their containers and named volumes (the next
# run boots against stale data - e.g. the cert-export smoke rotates the
# admin password, and a stale volume 401s the next login), and on BUILD a
# plain `docker compose build` (no profile flags) skips them entirely.
ALL_PROFILES="--profile bot --profile bot-workers --profile cert-export --profile geoip --profile otel --profile otel-workers --profile rdns --profile ai-bot --profile ai-bot-workers --profile rbac --profile rbac-workers --profile audit --profile hot-upgrade --profile log-sinks"

# `docker compose run` never rebuilds an existing image, so a stale runner
# would silently run old assertions. With --build, build every service
# INCLUDING the profile-gated smoke/lorica images up front. Passing
# $ALL_PROFILES is load-bearing: a plain `docker compose build` skips the
# gated images, which once left a pre-HTTPS `ai-bot-smoke` image (built
# before the management API went TLS) failing every curl with a TLS
# verification error against the now-self-signed endpoint.
if [ -n "$BUILD_FLAG" ]; then
    docker compose $ALL_PROFILES build
fi

# ---- Phase 1: Single-process tests ----
echo "=== Lorica E2E Tests (single-process) ==="
echo ""

docker compose up $BUILD_FLAG -d backend1 backend2 lorica

echo "Waiting for Lorica to initialize..."
for i in $(seq 1 60); do
    if docker compose exec -T lorica curl -skf https://127.0.0.1:19443/ >/dev/null 2>&1; then
        echo "Lorica is ready."
        break
    fi
    if [ "$i" = "60" ]; then
        echo "ERROR: Lorica did not start within 120s"
        docker compose logs lorica | tail -20
        docker compose $ALL_PROFILES down -v
        exit 1
    fi
    sleep 2
done

docker compose run --rm test-runner || EXIT_CODE=$?

# ---- Phase 2: Worker isolation tests ----
if [ "$SKIP_WORKERS" = false ] && [ "$EXIT_CODE" = "0" ]; then
    echo ""
    echo "=== Lorica E2E Tests (worker isolation) ==="
    echo ""

    docker compose up $BUILD_FLAG -d lorica-workers

    echo "Waiting for Lorica workers to initialize..."
    for i in $(seq 1 60); do
        if docker compose exec -T lorica-workers curl -skf https://127.0.0.1:19443/ >/dev/null 2>&1; then
            echo "Lorica workers instance is ready."
            break
        fi
        if [ "$i" = "60" ]; then
            echo "ERROR: Lorica workers did not start within 120s"
            docker compose logs lorica-workers | tail -20
            break
        fi
        sleep 2
    done

    docker compose run --rm test-runner-workers || EXIT_CODE=$?
fi

# ---- Phase 3: Cert export profile ----
# Profile is opt-out via --skip-cert-export (default is ON) so the
# main suite covers the v1.4.1 filesystem export path end-to-end.
if [ "$SKIP_CERT_EXPORT" = false ] && [ "$EXIT_CODE" = "0" ]; then
    echo ""
    echo "=== Lorica E2E Tests (cert export profile) ==="
    echo ""

    docker compose --profile cert-export up $BUILD_FLAG -d lorica-cert-export

    echo "Waiting for Lorica (cert-export) to initialize..."
    for i in $(seq 1 60); do
        if docker compose exec -T lorica-cert-export curl -skf https://127.0.0.1:19443/ >/dev/null 2>&1; then
            echo "Lorica (cert-export) is ready."
            break
        fi
        if [ "$i" = "60" ]; then
            echo "ERROR: Lorica (cert-export) did not start within 120s"
            docker compose logs lorica-cert-export | tail -20
            break
        fi
        sleep 2
    done

    docker compose --profile cert-export run --rm cert-export-smoke || EXIT_CODE=$?
fi

# ---- Phase 4: AI-bot deny-list profile (single-process + workers) ----
# Story 8.2 (v1.6.0) IV4. Opt-out via --skip-ai-bot (default ON). Both
# the single-process and workers variants run so the custom-crawler
# hot-reload propagates across the supervisor -> worker RPC path too.
if [ "$SKIP_AI_BOT" = false ] && [ "$EXIT_CODE" = "0" ]; then
    echo ""
    echo "=== Lorica E2E Tests (AI-bot deny-list profile) ==="
    echo ""

    docker compose --profile ai-bot up $BUILD_FLAG -d lorica-ai-bot

    echo "Waiting for Lorica (ai-bot) to initialize..."
    for i in $(seq 1 60); do
        if docker compose exec -T lorica-ai-bot curl -skf https://127.0.0.1:19443/ >/dev/null 2>&1; then
            echo "Lorica (ai-bot) is ready."
            break
        fi
        if [ "$i" = "60" ]; then
            echo "ERROR: Lorica (ai-bot) did not start within 120s"
            docker compose logs lorica-ai-bot | tail -20
            break
        fi
        sleep 2
    done

    docker compose --profile ai-bot run --rm ai-bot-smoke || EXIT_CODE=$?

    if [ "$SKIP_WORKERS" = false ] && [ "$EXIT_CODE" = "0" ]; then
        echo ""
        echo "=== Lorica E2E Tests (AI-bot deny-list, worker mode) ==="
        echo ""

        docker compose --profile ai-bot-workers up $BUILD_FLAG -d lorica-ai-bot-workers

        echo "Waiting for Lorica (ai-bot workers) to initialize..."
        for i in $(seq 1 60); do
            if docker compose exec -T lorica-ai-bot-workers curl -skf https://127.0.0.1:19443/ >/dev/null 2>&1; then
                echo "Lorica (ai-bot workers) is ready."
                break
            fi
            if [ "$i" = "60" ]; then
                echo "ERROR: Lorica (ai-bot workers) did not start within 120s"
                docker compose logs lorica-ai-bot-workers | tail -20
                break
            fi
            sleep 2
        done

        docker compose --profile ai-bot-workers run --rm ai-bot-smoke-workers || EXIT_CODE=$?
    fi
fi

# ---- Phase 5: RBAC profile (Story 8.3, IV3; single-process + workers) --
# Users CRUD, per-role 403 matrix, session invalidation, legacy login
# shim, last-super-admin guards. Opt-out via --skip-rbac (default ON).
if [ "$SKIP_RBAC" = false ] && [ "$EXIT_CODE" = "0" ]; then
    echo ""
    echo "=== Lorica E2E Tests (RBAC profile) ==="
    echo ""

    docker compose --profile rbac up $BUILD_FLAG -d lorica-rbac

    echo "Waiting for Lorica (rbac) to initialize..."
    for i in $(seq 1 60); do
        if docker compose exec -T lorica-rbac curl -skf https://127.0.0.1:19443/ >/dev/null 2>&1; then
            echo "Lorica (rbac) is ready."
            break
        fi
        if [ "$i" = "60" ]; then
            echo "ERROR: Lorica (rbac) did not start within 120s"
            docker compose logs lorica-rbac | tail -20
            break
        fi
        sleep 2
    done

    docker compose --profile rbac run --rm rbac-smoke || EXIT_CODE=$?

    if [ "$SKIP_WORKERS" = false ] && [ "$EXIT_CODE" = "0" ]; then
        echo ""
        echo "=== Lorica E2E Tests (RBAC, worker mode) ==="
        echo ""

        docker compose --profile rbac-workers up $BUILD_FLAG -d lorica-rbac-workers

        echo "Waiting for Lorica (rbac workers) to initialize..."
        for i in $(seq 1 60); do
            if docker compose exec -T lorica-rbac-workers curl -skf https://127.0.0.1:19443/ >/dev/null 2>&1; then
                echo "Lorica (rbac workers) is ready."
                break
            fi
            if [ "$i" = "60" ]; then
                echo "ERROR: Lorica (rbac workers) did not start within 120s"
                docker compose logs lorica-rbac-workers | tail -20
                break
            fi
            sleep 2
        done

        docker compose --profile rbac-workers run --rm rbac-smoke-workers || EXIT_CODE=$?
    fi
fi

# ---- Phase 6: Audit-log profile (Story 8.9, IV1/IV4) ---------------
# Real mutation -> audit row -> GET /audit; chain verify passes;
# sqlite tamper of a middle row makes verify localise the break.
# Opt-out via --skip-audit (default ON).
if [ "$SKIP_AUDIT" = false ] && [ "$EXIT_CODE" = "0" ]; then
    echo ""
    echo "=== Lorica E2E Tests (audit-log profile) ==="
    echo ""

    docker compose --profile audit up $BUILD_FLAG -d lorica-audit

    echo "Waiting for Lorica (audit) to initialize..."
    for i in $(seq 1 60); do
        if docker compose exec -T lorica-audit curl -skf https://127.0.0.1:19443/ >/dev/null 2>&1; then
            echo "Lorica (audit) is ready."
            break
        fi
        if [ "$i" = "60" ]; then
            echo "ERROR: Lorica (audit) did not start within 120s"
            docker compose logs lorica-audit | tail -20
            break
        fi
        sleep 2
    done

    docker compose --profile audit run --rm audit-smoke || EXIT_CODE=$?
fi

# ---- Phase 7: Hot binary-upgrade profile (Story 8.4, IV1/IV3) -------
# Boots Lorica in supervisor/workers mode and drives a live zero-downtime
# binary swap while sustained traffic flows through the proxy. Opt-out
# via --skip-hot-upgrade (default ON).
if [ "$SKIP_HOT_UPGRADE" = false ] && [ "$EXIT_CODE" = "0" ]; then
    echo ""
    echo "=== Lorica E2E Tests (hot binary-upgrade profile) ==="
    echo ""

    docker compose --profile hot-upgrade up $BUILD_FLAG -d lorica-hot-upgrade

    echo "Waiting for Lorica (hot-upgrade) to initialize..."
    for i in $(seq 1 60); do
        if docker compose exec -T lorica-hot-upgrade curl -skf https://127.0.0.1:19443/ >/dev/null 2>&1; then
            echo "Lorica (hot-upgrade) is ready."
            break
        fi
        if [ "$i" = "60" ]; then
            echo "ERROR: Lorica (hot-upgrade) did not start within 120s"
            docker compose logs lorica-hot-upgrade | tail -20
            break
        fi
        sleep 2
    done

    docker compose --profile hot-upgrade run --rm hot-upgrade-smoke || EXIT_CODE=$?
fi

# ---- Phase 8: Log-sinks profile (Story 9.8, IV1/IV2/IV3) ------------
# Syslog (RFC 5424 over TCP) + OTLP logs delivery for all three event
# kinds, trace correlation on the OTLP record, and zero request-path
# impact with both collectors dead. Opt-out via --skip-log-sinks
# (default ON).
if [ "$SKIP_LOG_SINKS" = false ] && [ "$EXIT_CODE" = "0" ]; then
    echo ""
    echo "=== Lorica E2E Tests (log-sinks profile) ==="
    echo ""

    docker compose --profile log-sinks up $BUILD_FLAG -d backend1 syslog-collector otelcol-logs lorica-log-sinks

    echo "Waiting for Lorica (log-sinks) to initialize..."
    for i in $(seq 1 60); do
        if docker compose exec -T lorica-log-sinks curl -skf https://127.0.0.1:19443/ >/dev/null 2>&1; then
            echo "Lorica (log-sinks) is ready."
            break
        fi
        if [ "$i" = "60" ]; then
            echo "ERROR: Lorica (log-sinks) did not start within 120s"
            docker compose logs lorica-log-sinks | tail -20
            break
        fi
        sleep 2
    done

    docker compose --profile log-sinks run --rm log-sinks-smoke || EXIT_CODE=$?
fi

# Cleanup unless --keep
if [ "$KEEP" = false ]; then
    docker compose $ALL_PROFILES down -v
fi

if [ "$EXIT_CODE" = "0" ]; then
    echo ""
    echo "=== ALL E2E TESTS PASSED ==="
fi

exit $EXIT_CODE
