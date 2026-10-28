#!/usr/bin/env bash
# The AD CS Kerberos harness of Story 13.1: builds the KDC and CES
# fixture images, starts them, runs the probe client (IV1 third leg),
# then the #[ignore]d Rust tests of lorica-adcs/tests/harness.rs against
# them, and tears everything down whatever happens.
#
# Usage: tests-e2e-docker/adcs/run.sh [--keep]
#   --keep  leave the containers running after the tests

set -euo pipefail
cd "$(dirname "$0")"

# Git Bash on a Windows host rewrites absolute container paths otherwise.
export MSYS_NO_PATHCONV=1
export COMPOSE_PROJECT_NAME=lorica-adcs-harness

KEEP=false
for arg in "$@"; do
    case "$arg" in
        --keep) KEEP=true ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        echo ""
        echo "--- harness logs (exit $status) ---"
        docker compose logs --no-color --tail 80 kdc ces kdc-blackhole 2>&1 || true
        echo "--- end harness logs ---"
    fi
    if [ "$KEEP" = false ]; then
        docker compose --profile tests down -v --remove-orphans >/dev/null 2>&1 || true
    fi
    exit "$status"
}
trap cleanup EXIT

docker compose build
docker compose up -d --wait kdc kdc-blackhole ces

echo "=== probe client: a token without a channel binding must be refused ==="
docker compose exec -T ces python3 /app/probe.py

echo "=== lorica-adcs harness tests ==="
docker compose run --rm tests

echo "=== AD CS harness: all checks passed ==="
