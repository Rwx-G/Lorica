#!/usr/bin/env bash
# Run the Lorica E2E test suite with Docker Compose.
# Usage: ./run.sh [--build] [--keep] [--skip-workers] [--skip-cert-export]
#                 [--skip-geoip] [--skip-ai-bot] [--skip-rbac] [--skip-audit] [--skip-hot-upgrade]
#                 [--skip-log-sinks] [--skip-log-sinks-workers] [--skip-acme]
#                 [--skip-cluster] [--skip-capture] [--skip-capture-workers]
#                 [--skip-mcp] [--skip-adcs] [--skip-l4] [--skip-perf]
#                 [--only-l4] [--only-perf] [--perf-advisory]
#   --build             Force rebuild all images
#   --keep              Don't tear down containers after tests
#   --skip-workers      Skip worker isolation tests (faster)
#   --skip-geoip        Skip the v1.4.0 Story 2.7 GeoIP profile (faster)
#   --skip-cert-export  Skip the v1.4.1 cert-export profile (faster)
#   --skip-ai-bot       Skip the v1.6.0 Story 8.2 AI-bot profile (faster)
#   --skip-rbac         Skip the v1.6.0 Story 8.3 RBAC profile (faster)
#   --skip-audit        Skip the v1.6.0 Story 8.9 audit-log profile (faster)
#   --skip-hot-upgrade  Skip the v1.6.0 Story 8.4 hot binary-upgrade profile (faster)
#   --skip-log-sinks    Skip the v1.7.0 Story 9.8 log-sinks profile (faster)
#   --skip-log-sinks-workers  Skip the worker-mode variant of the log-sinks profile
#   --skip-acme         Skip the v1.7.0 Story 9.1 Pebble ACME profile (faster)
#   --skip-cluster      Skip the v1.7.0 Epic 9 cluster profile (faster)
#   --skip-capture      Skip the v1.8.0 Stories 10.1/10.2 capture profile (faster)
#   --skip-capture-workers  Skip the worker-mode variant of the capture profile
#   --skip-mcp          Skip the v1.9.0 Story 11.4 MCP profile (faster)
#   --skip-adcs         Skip the v1.10.0 Story 13.6 AD CS profile (faster)
#   --skip-l4           Skip the v1.11.0 Story 12.12 L4 phase (streams and
#                       streams-single profiles, docker-compose.l4.yml)
#   --skip-perf         Skip the Story 12.12 performance phase
#   --only-l4           Run the L4 phase alone: every pre-existing phase,
#                       Phase 1 included, is skipped
#   --only-perf         Run the performance phase alone: every other phase,
#                       Phase 1 and the L4 phase included, is skipped
#   --perf-advisory     Report the performance verdicts without gating (CI)
#
# Every run is teed to results/e2e-<UTC timestamp>.log. After the last
# phase, test-runner/l4/report.py checks the log against the L4 scenario
# registry (l4/scenarios.tsv) and writes results/l4-summary.md. A run with
# no --skip-* and no --only-* flag is the release run: there, every row of
# the registry must report, pending rows included (Story 12.12 D-m).
#
# L4 lanes: `L4_LANE=1..4 ./run.sh --only-l4` runs the L4 phase as an
# isolated lane (its own compose project, subnets and results files; see
# l4/lib.sh), so several lanes run at once on one Docker host. A lane is
# --only-l4 only and never builds: build the images once with
# `[L4_IMAGE_TAG=<tag>] l4/build-images.sh` and run every lane with the
# same L4_IMAGE_TAG. Without L4_LANE, nothing changes. `L4_LOTS=B,D`
# (any run) runs only those Lots' L4 rows; the report reads the others
# as not run. The lane's report is results/l4-summary-lane-N.md.
#
# The performance phase (Story 12.12 D-i to D-m, perf/run-perf.sh) runs
# last, in its own compose project (lorica-e2e-perf), after the other
# projects are torn down: its environment guard makes every gated verdict
# INCONCLUSIVE when a container outside it is running, so with --keep a
# full run's perf verdicts are inconclusive by design. It gates the run
# (any FAIL, INCONCLUSIVE or NOT-RUN) unless --perf-advisory; on the
# release run (no --skip-* or --only-* flag) it also requires the larger
# cpuset layout. Its own knobs (PERF_LAYOUT, PERF_REPS, ...) are listed in
# perf/run-perf.sh.

set -euo pipefail
cd "$(dirname "$0")"

BUILD_FLAG=""
KEEP=false
SKIP_WORKERS=false
SKIP_GEOIP=false
SKIP_CERT_EXPORT=false
SKIP_AI_BOT=false
SKIP_RBAC=false
SKIP_AUDIT=false
SKIP_HOT_UPGRADE=false
SKIP_LOG_SINKS=false
SKIP_LOG_SINKS_WORKERS=false
SKIP_ACME=false
SKIP_CLUSTER=false
SKIP_CAPTURE=false
SKIP_CAPTURE_WORKERS=false
SKIP_MCP=false
SKIP_ADCS=false
SKIP_L4=false
SKIP_PERF=false
ONLY_L4=false
ONLY_PERF=false
PERF_ADVISORY=false
STRICT_REPORT=true

for arg in "$@"; do
    case "$arg" in
        --build)             BUILD_FLAG="--build" ;;
        --keep)              KEEP=true ;;
        --skip-workers)      SKIP_WORKERS=true ;;
        --skip-geoip)        SKIP_GEOIP=true ;;
        --skip-cert-export)  SKIP_CERT_EXPORT=true ;;
        --skip-ai-bot)       SKIP_AI_BOT=true ;;
        --skip-rbac)         SKIP_RBAC=true ;;
        --skip-audit)        SKIP_AUDIT=true ;;
        --skip-hot-upgrade)  SKIP_HOT_UPGRADE=true ;;
        --skip-log-sinks)    SKIP_LOG_SINKS=true ;;
        --skip-log-sinks-workers) SKIP_LOG_SINKS_WORKERS=true ;;
        --skip-acme)         SKIP_ACME=true ;;
        --skip-cluster)      SKIP_CLUSTER=true ;;
        --skip-capture)      SKIP_CAPTURE=true ;;
        --skip-capture-workers) SKIP_CAPTURE_WORKERS=true ;;
        --skip-mcp)          SKIP_MCP=true ;;
        --skip-adcs)         SKIP_ADCS=true ;;
        --skip-l4)           SKIP_L4=true ;;
        --skip-perf)         SKIP_PERF=true ;;
        --only-l4)           ONLY_L4=true ;;
        --only-perf)         ONLY_PERF=true ;;
        --perf-advisory)     PERF_ADVISORY=true ;;
    esac
    case "$arg" in
        --skip-*|--only-*) STRICT_REPORT=false ;;
    esac
done

if [ "$ONLY_L4" = true ] && [ "$ONLY_PERF" = true ]; then
    echo "run.sh: --only-l4 and --only-perf exclude each other" >&2
    exit 2
fi

# --only-l4 skips every pre-existing phase and the performance phase;
# --only-perf skips them and the L4 phase. A new phase gets its SKIP_
# variable set here too.
RUN_PHASE_1=true
if [ "$ONLY_L4" = true ]; then
    SKIP_PERF=true
fi
if [ "$ONLY_PERF" = true ]; then
    SKIP_L4=true
fi
if [ "$ONLY_L4" = true ] || [ "$ONLY_PERF" = true ]; then
    RUN_PHASE_1=false
    SKIP_WORKERS=true
    SKIP_GEOIP=true
    SKIP_CERT_EXPORT=true
    SKIP_AI_BOT=true
    SKIP_RBAC=true
    SKIP_AUDIT=true
    SKIP_HOT_UPGRADE=true
    SKIP_LOG_SINKS=true
    SKIP_LOG_SINKS_WORKERS=true
    SKIP_ACME=true
    SKIP_CLUSTER=true
    SKIP_CAPTURE=true
    SKIP_CAPTURE_WORKERS=true
    SKIP_MCP=true
    SKIP_ADCS=true
fi

# The L4 project's name, subnets and image tag, from L4_LANE and
# L4_IMAGE_TAG (l4/lib.sh is their one derivation). A lane runs the L4
# phase alone, on images built beforehand: the pre-existing phases share
# one compose project, and several lanes building one tag would race.
# shellcheck source=l4/lib.sh
. l4/lib.sh
if [ -n "${L4_LANE:-}" ]; then
    if [ "$ONLY_L4" = false ] || [ -n "$BUILD_FLAG" ]; then
        echo "run.sh: L4_LANE runs --only-l4 without --build; build first with l4/build-images.sh" >&2
        exit 2
    fi
fi

# Tee the whole run, so the L4 report can read every phase's scenario
# lines and CI can upload the log.
mkdir -p results
RESULTS_LOG="results/e2e${L4_LANE:+-l4-lane-$L4_LANE}-$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee -a "$RESULTS_LOG") 2>&1
echo "Logging this run to tests-e2e-docker/${RESULTS_LOG}"

EXIT_CODE=0

# Mark the start of a phase for the L4 report: a scenario line belongs to
# the profile of the last marker before it (Story 12.12 D-c).
announce_profile() {
    echo "L4-PROFILE $1"
}

# The L4 project's compose file and every profile in it, for build and
# teardown.
L4_COMPOSE="docker compose -p ${L4_PROJECT} -f docker-compose.l4.yml"
L4_ALL_PROFILES="--profile streams --profile streams-single --profile l4-report"

# Dump a node's log when a smoke fails.
#
# A failing assertion names the request and the status; the reason lives
# in the node's own log, and on CI the run ends before anyone can ask
# the container for it. The ACME phase lost a full CI cycle to exactly
# that: a 500 whose body is the deliberate generic "internal error",
# with the real cause in a `warn!` nobody kept.
#
# Usage: dump_node_log <compose-service> [lines]
dump_node_log() {
    node="$1"
    lines="${2:-80}"
    echo ""
    echo "--- last ${lines} log lines from ${node} ---"
    docker compose logs --no-color "$node" 2>&1 | tail -n "$lines"
    echo "--- end ${node} ---"
    echo ""
}

# Profile-gated services need explicit --profile flags: on teardown
# `down -v` otherwise skips their containers and named volumes (the next
# run boots against stale data - e.g. the cert-export smoke rotates the
# admin password, and a stale volume 401s the next login), and on BUILD a
# plain `docker compose build` (no profile flags) skips them entirely.
ALL_PROFILES="--profile bot --profile bot-workers --profile cert-export --profile geoip --profile otel --profile otel-workers --profile rdns --profile ai-bot --profile ai-bot-workers --profile rbac --profile rbac-workers --profile audit --profile hot-upgrade --profile log-sinks --profile log-sinks-workers --profile acme --profile cluster --profile capture --profile capture-workers --profile mcp --profile adcs"

# `docker compose run` never rebuilds an existing image, so a stale runner
# would silently run old assertions. With --build, build every service
# INCLUDING the profile-gated smoke/lorica images up front. Passing
# $ALL_PROFILES is load-bearing: a plain `docker compose build` skips the
# gated images, which once left a pre-HTTPS `ai-bot-smoke` image (built
# before the management API went TLS) failing every curl with a TLS
# verification error against the now-self-signed endpoint.
# The L4 report runs after every run (except --only-perf), so its image
# is rebuilt whatever is skipped: a stale one would check the log with an
# old report. The performance phase builds its own images when it starts
# (perf/run-perf.sh --build); the Lorica one is cached by then.
if [ -n "$BUILD_FLAG" ] && [ "$ONLY_PERF" = false ]; then
    if [ "$ONLY_L4" = false ]; then
        docker compose $ALL_PROFILES build
    fi
    if [ "$SKIP_L4" = false ]; then
        $L4_COMPOSE $L4_ALL_PROFILES build
    else
        $L4_COMPOSE --profile l4-report build
    fi
fi

# ---- Phase 1: Single-process tests ----
if [ "$RUN_PHASE_1" = true ]; then
    echo "=== Lorica E2E Tests (single-process) ==="
    echo ""
    announce_profile default

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
fi

# ---- Phase 2: Worker isolation tests ----
if [ "$SKIP_WORKERS" = false ] && [ "$EXIT_CODE" = "0" ]; then
    echo ""
    echo "=== Lorica E2E Tests (worker isolation) ==="
    echo ""
    announce_profile workers

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

# ---- Phase 2b: GeoIP profile (Story 2.7; Story 12.8 IV1 and IV2) ----
# The MaxMind test database mounted on a single-process node: route
# GeoIP allow and deny lists, then the PROXY protocol scenarios of Story
# 12.8, which need a carried address the database knows. The profile
# existed before run.sh ran it (Story 12.12 Lot A). Opt-out via
# --skip-geoip (default ON).
if [ "$SKIP_GEOIP" = false ] && [ "$EXIT_CODE" = "0" ]; then
    echo ""
    echo "=== Lorica E2E Tests (geoip profile) ==="
    echo ""
    announce_profile geoip

    docker compose --profile geoip up $BUILD_FLAG -d backend1 lorica-geoip

    echo "Waiting for Lorica (geoip) to initialize..."
    for i in $(seq 1 60); do
        if docker compose exec -T lorica-geoip curl -skf https://127.0.0.1:19443/ >/dev/null 2>&1; then
            echo "Lorica (geoip) is ready."
            break
        fi
        if [ "$i" = "60" ]; then
            echo "ERROR: Lorica (geoip) did not start within 120s"
            docker compose logs lorica-geoip | tail -20
            break
        fi
        sleep 2
    done

    if ! docker compose --profile geoip run --rm geoip-smoke; then
        EXIT_CODE=1
        dump_node_log lorica-geoip
    fi
fi

# ---- Phase 3: Cert export profile ----
# Profile is opt-out via --skip-cert-export (default is ON) so the
# main suite covers the v1.4.1 filesystem export path end-to-end.
if [ "$SKIP_CERT_EXPORT" = false ] && [ "$EXIT_CODE" = "0" ]; then
    echo ""
    echo "=== Lorica E2E Tests (cert export profile) ==="
    echo ""
    announce_profile cert-export

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
    announce_profile ai-bot

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
        announce_profile ai-bot-workers

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
    announce_profile rbac

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
        announce_profile rbac-workers

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
    announce_profile audit

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
    announce_profile hot-upgrade

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
    announce_profile log-sinks

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

# ---- Phase 8b: Log-sinks profile, worker mode (backlog #53) ----------
# The sink counters are incremented in the workers, where the access
# events are published, and the supervisor's /metrics reports them only
# through the per-worker counter aggregation. The smoke compares the
# supervisor's sent and truncated counts with the frames the collector
# received from at least two worker PIDs, and checks that the dropped
# family carries every shed event. Opt-out via --skip-log-sinks-workers
# (default ON); --skip-workers and --skip-log-sinks skip it too.
if [ "$SKIP_LOG_SINKS_WORKERS" = false ] && [ "$SKIP_LOG_SINKS" = false ] \
    && [ "$SKIP_WORKERS" = false ] && [ "$EXIT_CODE" = "0" ]; then
    echo ""
    echo "=== Lorica E2E Tests (log-sinks profile, worker mode) ==="
    echo ""
    announce_profile log-sinks-workers

    docker compose --profile log-sinks-workers up $BUILD_FLAG -d \
        backend1 syslog-collector-log-sinks-workers otelcol-logs-log-sinks-workers \
        lorica-log-sinks-workers

    echo "Waiting for Lorica (log-sinks workers) to initialize..."
    for i in $(seq 1 60); do
        if docker compose exec -T lorica-log-sinks-workers curl -skf https://127.0.0.1:19443/ >/dev/null 2>&1; then
            echo "Lorica (log-sinks workers) is ready."
            break
        fi
        if [ "$i" = "60" ]; then
            echo "ERROR: Lorica (log-sinks workers) did not start within 120s"
            docker compose logs lorica-log-sinks-workers | tail -20
            break
        fi
        sleep 2
    done

    if ! docker compose --profile log-sinks-workers run --rm log-sinks-workers-smoke; then
        EXIT_CODE=1
        dump_node_log lorica-log-sinks-workers
    fi
fi

# ---- Phase 9: ACME / Pebble profile (Story 9.1 AC #13) --------------
# First end-to-end ACME coverage (audit M-22): HTTP-01 issuance
# against Pebble routed through the proxy, and DNS-01 via the manual
# flow with TXT records published on the challtestsrv mock DNS
# provider. Opt-out via --skip-acme (default ON).
if [ "$SKIP_ACME" = false ] && [ "$EXIT_CODE" = "0" ]; then
    echo ""
    echo "=== Lorica E2E Tests (acme profile) ==="
    echo ""
    announce_profile acme

    docker compose --profile acme up $BUILD_FLAG -d backend1 challtestsrv pebble lorica-acme

    echo "Waiting for Lorica (acme) to initialize..."
    for i in $(seq 1 60); do
        if docker compose exec -T lorica-acme curl -skf https://127.0.0.1:19443/ >/dev/null 2>&1; then
            echo "Lorica (acme) is ready."
            break
        fi
        if [ "$i" = "60" ]; then
            echo "ERROR: Lorica (acme) did not start within 120s"
            docker compose logs lorica-acme | tail -20
            break
        fi
        sleep 2
    done

    if ! docker compose --profile acme run --rm acme-smoke; then
        EXIT_CODE=1
        dump_node_log lorica-acme
        dump_node_log pebble 40
    fi
fi

# ---- Phase 10: Capture profile (Stories 10.1 IV1-IV3, 10.2 IV1-IV4) --
# Request capture driven through a real proxy from two source addresses
# (a network pinned to 172.30.0.0/16 and the e2e one), with the records
# asserted on stdout, in the syslog collector, in the OTLP collector,
# in the recent-captures ring and in an `output.dir`, read-only and
# writable. Opt-out via --skip-capture (default ON).
if [ "$SKIP_CAPTURE" = false ] && [ "$EXIT_CODE" = "0" ]; then
    echo ""
    echo "=== Lorica E2E Tests (capture profile) ==="
    echo ""
    announce_profile capture

    docker compose --profile capture up $BUILD_FLAG -d \
        backend1 syslog-collector-capture otelcol-logs-capture lorica-capture

    echo "Waiting for Lorica (capture) to initialize..."
    for i in $(seq 1 60); do
        if docker compose exec -T lorica-capture curl -skf https://127.0.0.1:19443/ >/dev/null 2>&1; then
            echo "Lorica (capture) is ready."
            break
        fi
        if [ "$i" = "60" ]; then
            echo "ERROR: Lorica (capture) did not start within 120s"
            docker compose logs lorica-capture | tail -20
            break
        fi
        sleep 2
    done

    docker compose --profile capture run --rm capture-smoke || EXIT_CODE=$?
fi

# ---- Phase 10b: Capture profile, worker mode (Epic 10 e2e section) ---
# The epic PRD asks for this variant in so many words: "the workers
# variant exists because body buffering and the per-worker budget
# semantics are precisely the kind of thing that passes in single-process
# mode and breaks in a worker". Two runners drive it, in this order:
# `capture-smoke-workers` re-runs the whole single-process smoke with
# CAPTURE_SMOKE_WORKERS=1 (records read from the `lorica::capture` stdout
# sink, because the ring answers 503 in the supervisor, and the counts
# relaxed to per-worker ones), then `capture-workers-smoke` asserts what
# only a workers node can show: the 503 itself, the per-worker budget
# overshoot, the sinks fed from inside a worker, and the aggregated
# metric families. Opt-out via --skip-capture-workers (default ON);
# --skip-workers and --skip-capture skip it too, the way every other
# workers variant sits under its own profile's switch.
if [ "$SKIP_CAPTURE_WORKERS" = false ] && [ "$SKIP_CAPTURE" = false ] \
    && [ "$SKIP_WORKERS" = false ] && [ "$EXIT_CODE" = "0" ]; then
    echo ""
    echo "=== Lorica E2E Tests (capture profile, worker mode) ==="
    echo ""
    announce_profile capture-workers

    docker compose --profile capture-workers up $BUILD_FLAG -d \
        backend1 syslog-collector-capture-workers otelcol-logs-capture-workers \
        lorica-capture-workers

    echo "Waiting for Lorica (capture workers) to initialize..."
    for i in $(seq 1 60); do
        if docker compose exec -T lorica-capture-workers curl -skf https://127.0.0.1:19443/ >/dev/null 2>&1; then
            echo "Lorica (capture workers) is ready."
            break
        fi
        if [ "$i" = "60" ]; then
            echo "ERROR: Lorica (capture workers) did not start within 120s"
            docker compose logs lorica-capture-workers | tail -20
            break
        fi
        sleep 2
    done

    docker compose --profile capture-workers run --rm capture-smoke-workers || EXIT_CODE=$?

    if [ "$EXIT_CODE" = "0" ]; then
        docker compose --profile capture-workers run --rm capture-workers-smoke || EXIT_CODE=$?
    fi
fi

# ---- Phase 11: MCP profile (Story 11.4 AC #4, IV1, IV2) --------------
# A standalone node with the automation listener, and a smoke that
# spawns `lorica-mcp` over stdio for each tier: tokens minted by the
# real `lorica mcp token create --tier`, tool lists, one mutation and
# one refusal per mutating tier, the audit rows, a revocation mid
# session, the two-tier refusal (exit 78) and the audit chain.
# Opt-out via --skip-mcp (default ON).
if [ "$SKIP_MCP" = false ] && [ "$EXIT_CODE" = "0" ]; then
    echo ""
    echo "=== Lorica E2E Tests (mcp profile) ==="
    echo ""
    announce_profile mcp

    docker compose --profile mcp up $BUILD_FLAG -d lorica-mcp

    echo "Waiting for Lorica (mcp) to initialize..."
    for i in $(seq 1 60); do
        if docker compose --profile mcp exec -T lorica-mcp sh -c 'test -f /shared/mcp_ready' >/dev/null 2>&1; then
            echo "Lorica (mcp) is ready."
            break
        fi
        if [ "$i" = "60" ]; then
            echo "ERROR: Lorica (mcp) did not start within 120s"
            docker compose logs lorica-mcp | tail -20
            break
        fi
        sleep 2
    done

    if ! docker compose --profile mcp run --rm mcp-smoke; then
        EXIT_CODE=1
        dump_node_log lorica-mcp
    fi
fi

# ---- Phase 12: AD CS profile (Story 13.6 AC #2, IV1) -----------------
# A node joined to the Story 13.1 Kerberos harness (an MIT KDC and a CES
# fixture enforcing the channel binding), driven through the management
# API: authority and connection test, issuance from a route served on
# the HTTPS listener, "Renew now", adoption and reversion, and the D15
# breaker. Then the harness probe client, run where python-gssapi is:
# a token without a channel binding must be refused. Opt-out via
# --skip-adcs (default ON).
if [ "$SKIP_ADCS" = false ] && [ "$EXIT_CODE" = "0" ]; then
    echo ""
    echo "=== Lorica E2E Tests (adcs profile) ==="
    echo ""
    announce_profile adcs

    docker compose --profile adcs up $BUILD_FLAG -d lorica-adcs

    echo "Waiting for Lorica (adcs) to initialize..."
    ADCS_READY_TRIES=60
    ADCS_READY_INTERVAL_S=2
    for i in $(seq 1 "$ADCS_READY_TRIES"); do
        if docker compose --profile adcs exec -T lorica-adcs curl -skf https://127.0.0.1:19443/ >/dev/null 2>&1; then
            echo "Lorica (adcs) is ready."
            break
        fi
        if [ "$i" = "$ADCS_READY_TRIES" ]; then
            echo "ERROR: Lorica (adcs) did not start after $ADCS_READY_TRIES tries ${ADCS_READY_INTERVAL_S}s apart"
            docker compose logs lorica-adcs | tail -20
            break
        fi
        sleep "$ADCS_READY_INTERVAL_S"
    done

    if ! docker compose --profile adcs run --rm adcs-smoke; then
        EXIT_CODE=1
        dump_node_log lorica-adcs
        dump_node_log ces 40
        dump_node_log kdc 40
    fi

    if [ "$EXIT_CODE" = "0" ]; then
        echo ""
        echo "=== AD CS harness probe: a token without a channel binding is refused ==="
        # `sh -c` for the same MSYS path-conversion reason as the cluster
        # readiness probe below.
        docker compose --profile adcs exec -T ces sh -c 'python3 /app/probe.py' || EXIT_CODE=$?
    fi
fi

# ---- Phase: cluster (Epic 9 Integration Verification, backlog #66) ----
# One control plane and two followers, one of them in workers mode. This
# is the profile stories 9.2 through 9.9 were written against and none
# of them could run: each of those story files records that it shipped
# on unit tests alone. Opt-out via --skip-cluster (default ON).
if [ "$SKIP_CLUSTER" = false ] && [ "$EXIT_CODE" = "0" ]; then
    echo ""
    echo "=== Lorica E2E Tests (cluster profile) ==="
    echo ""
    announce_profile cluster

    # backend2 and oidc-issuer serve the automation phase below: the
    # backend an environment moves its traffic to, and the ID-token
    # issuer (Story 10.5).
    docker compose --profile cluster up $BUILD_FLAG -d \
        backend1 backend2 challtestsrv pebble oidc-issuer lorica-cp lorica-edge-a lorica-edge-b

    # The followers mint and redeem a real join token before they start,
    # so readiness here means the whole enrolment handshake completed,
    # not merely that a process is up.
    echo "Waiting for the fleet to form..."
    for i in $(seq 1 90); do
        # `sh -c` on purpose: a bare `/shared/...` argument is rewritten
        # into a Windows path by Git Bash before docker sees it (MSYS
        # path conversion), so the probe never succeeded on a Windows
        # host and this phase always waited out its full budget.
        if docker compose --profile cluster exec -T lorica-cp sh -c 'test -f /shared/edge-b_ready' >/dev/null 2>&1; then
            echo "Fleet is ready."
            break
        fi
        if [ "$i" = "90" ]; then
            echo "ERROR: the fleet did not form within 180s"
            docker compose logs lorica-cp | tail -30
            docker compose logs lorica-edge-a | tail -30
            docker compose logs lorica-edge-b | tail -30
            break
        fi
        sleep 2
    done

    docker compose --profile cluster run --rm cluster-smoke || EXIT_CODE=$?

    # ---- Restart phase (backlog #77) ----
    # Nothing in this profile ever crossed a process boundary, so
    # nothing covered what survives one: a follower's session and its
    # SLA history, the private key it holds, and the control plane's
    # own in-memory replication policy state. Only run.sh can restart
    # a container, so the assertions live in their own runner and this
    # drives the restarts.
    if [ "$EXIT_CODE" = "0" ]; then
        echo ""
        echo "=== Lorica E2E Tests (cluster restart phase) ==="
        echo ""

        docker compose --profile cluster restart lorica-edge-a
        docker compose --profile cluster run --rm cluster-restart-smoke follower \
            || EXIT_CODE=$?

        if [ "$EXIT_CODE" = "0" ]; then
            docker compose --profile cluster restart lorica-cp
            docker compose --profile cluster run --rm cluster-restart-smoke control-plane \
                || EXIT_CODE=$?
        fi
    fi

    # ---- Automation phase (Epic 10, stories 10.3 to 10.5) ----
    # The control plane serves the automation listener (see
    # entrypoint-cluster-cp.sh). Story 10.3 IV3 needs a FOLLOWER started
    # with --automation-listen, which only run.sh can do: edge-a is
    # stopped so two processes never share its SQLite file, a throwaway
    # container runs the binary on edge-a's data volume with the flag,
    # its exit code and output land on the shared volume for the smoke
    # to assert, and edge-a is started again. The `sh -c` wrapper is
    # deliberate for the same MSYS reason as the readiness probe above.
    if [ "$EXIT_CODE" = "0" ]; then
        echo ""
        echo "=== Lorica E2E Tests (automation phase) ==="
        echo ""

        docker compose --profile cluster stop lorica-edge-a
        docker compose --profile cluster run --rm -T --no-deps --entrypoint sh lorica-edge-a \
            -c 'timeout 120 lorica --data-dir /var/lib/lorica --management-port 19443 --automation-listen 0.0.0.0:9446 --automation-listen-any > /shared/edge-a_automation_refusal.log 2>&1; echo $? > /shared/edge-a_automation_refusal.code; tail -c 600 /shared/edge-a_automation_refusal.log' \
            || true
        docker compose --profile cluster start lorica-edge-a

        docker compose --profile cluster run --rm automation-smoke || EXIT_CODE=$?
    fi

    # ---- MCP phase (Story 11.2 IV3, backlog #91) ----
    # A config-tier route write through `lorica-mcp` on the control
    # plane, minted by the real `lorica mcp token create`, and both
    # followers converging on the created then the changed route.
    if [ "$EXIT_CODE" = "0" ]; then
        echo ""
        echo "=== Lorica E2E Tests (cluster mcp phase) ==="
        echo ""

        if ! docker compose --profile cluster run --rm cluster-mcp-smoke; then
            EXIT_CODE=1
            dump_node_log lorica-cp
        fi
    fi

    # ---- Revocation, last: it is terminal for a node, so everything
    # that needs a live follower has already run.
    if [ "$EXIT_CODE" = "0" ]; then
        docker compose --profile cluster run --rm cluster-revocation-smoke || EXIT_CODE=$?
    fi
fi

# ---- 12.8 IV3: the pre-existing suite with PROXY accept off ----------
# Announced only when every pre-existing phase was asked for: the `suite`
# profile of the L4 registry is the whole pre-existing suite, and a run
# that skipped part of it proves nothing about it. Each profile starts
# with PROXY accept off (the default), and the two sections that turn it
# on (geoip, workers) put it back. What "unchanged" means is a review of
# the diff of tests-e2e-docker/ since v1.10.7 (Story 12.12 Lot O), which
# no run can do, hence PARTIAL.
SUITE_COMPLETE=$RUN_PHASE_1
for skipped in "$SKIP_WORKERS" "$SKIP_GEOIP" "$SKIP_CERT_EXPORT" "$SKIP_AI_BOT" \
    "$SKIP_RBAC" "$SKIP_AUDIT" "$SKIP_HOT_UPGRADE" "$SKIP_LOG_SINKS" "$SKIP_LOG_SINKS_WORKERS" \
    "$SKIP_ACME" "$SKIP_CLUSTER" "$SKIP_CAPTURE" "$SKIP_CAPTURE_WORKERS" "$SKIP_MCP" "$SKIP_ADCS"; do
    [ "$skipped" = false ] || SUITE_COMPLETE=false
done
if [ "$SUITE_COMPLETE" = true ]; then
    announce_profile suite
    if [ "$EXIT_CODE" = "0" ]; then
        echo "L4-SCENARIO 12.8-iv3-proxy-off-suite-unchanged PARTIAL every pre-existing profile passed with PROXY accept off -- not automated: that no pre-existing assertion changed is the review of git diff v1.10.7 -- tests-e2e-docker/ (Story 12.12 Lot O)"
    else
        echo "L4-SCENARIO 12.8-iv3-proxy-off-suite-unchanged FAIL a pre-existing phase failed (exit ${EXIT_CODE}); the phases after it did not run"
    fi
fi

# ---- Phase: L4 (Story 12.12 D-b, D-c) ---------------------------------
# Its own compose project (lorica-e2e-l4): the `streams` profile (worker
# mode) then `streams-single`, each scenario of l4/scenarios/*.sh run by
# the host-side driver. Opt-out via --skip-l4 (default ON).
if [ "$SKIP_L4" = false ] && [ "$EXIT_CODE" = "0" ]; then
    L4_ARGS=""
    if [ "$KEEP" = true ]; then
        L4_ARGS="--keep"
    fi
    bash l4/run-l4.sh $L4_ARGS || EXIT_CODE=$?
fi

# ---- L4 report: every scenario line of the run against the registry --
# Runs whatever failed before it, so a failing run still shows which
# scenarios reported. The host user's uid makes results/ files the
# user's own; MSYS_NO_PATHCONV keeps Git Bash from rewriting /results.
REPORT_ARGS="--log /results/$(basename "$RESULTS_LOG") --markdown /results/l4-summary${L4_LANE:+-lane-$L4_LANE}.md"
if [ "$STRICT_REPORT" = true ]; then
    REPORT_ARGS="$REPORT_ARGS --strict"
fi
# L4_LOTS (l4/run-l4.sh) selects part of the registry; never on a release
# run, which the report refuses.
if [ -n "${L4_LOTS:-}" ]; then
    REPORT_ARGS="$REPORT_ARGS --lots ${L4_LOTS}"
fi
if [ "$ONLY_PERF" = false ]; then
    echo ""
    echo "=== L4 scenario report ==="
    if ! MSYS_NO_PATHCONV=1 $L4_COMPOSE --profile l4-report run --rm -T \
            --user "$(id -u):$(id -g)" l4-report $REPORT_ARGS; then
        EXIT_CODE=1
    fi
fi

# Cleanup unless --keep. An --only-l4 or --only-perf run started nothing
# in the main project, and tearing it down would stop another run's
# containers: it leaves it alone.
if [ "$KEEP" = false ]; then
    if [ "$ONLY_L4" = false ] && [ "$ONLY_PERF" = false ]; then
        docker compose $ALL_PROFILES down -v
    fi
    if [ "$ONLY_PERF" = false ]; then
        $L4_COMPOSE $L4_ALL_PROFILES down -v --remove-orphans
    fi
fi

# ---- Phase: performance (Story 12.12 D-i to D-m) ------------------------
# Last, with the other projects gone (see the header). The release run
# passes PERF_RELEASE_RUN=1, which holds it to the larger cpuset layout.
# --perf-advisory reports the verdicts and never fails the run on them.
if [ "$SKIP_PERF" = false ] && [ "$EXIT_CODE" = "0" ]; then
    PERF_ARGS=""
    [ -n "$BUILD_FLAG" ] && PERF_ARGS="$PERF_ARGS --build"
    [ "$KEEP" = true ] && PERF_ARGS="$PERF_ARGS --keep"
    [ "$PERF_ADVISORY" = true ] && PERF_ARGS="$PERF_ARGS --advisory"
    PERF_RELEASE_RUN=0
    [ "$STRICT_REPORT" = true ] && PERF_RELEASE_RUN=1
    PERF_RELEASE_RUN=$PERF_RELEASE_RUN bash perf/run-perf.sh $PERF_ARGS || EXIT_CODE=$?
fi

if [ "$EXIT_CODE" = "0" ]; then
    echo ""
    echo "=== ALL E2E TESTS PASSED ==="
fi

exit $EXIT_CODE
