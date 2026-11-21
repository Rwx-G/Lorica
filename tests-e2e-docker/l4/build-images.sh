#!/usr/bin/env bash
# Build the L4 phase's images once from this working tree: the Lorica
# node image and the runner (clients, probes, backends, the report), as
# lorica-e2e-l4/{lorica,runner}:${L4_IMAGE_TAG:-local}. Every run and
# every lane after it reuses them without --build: rebuilding the
# release image is most of an iteration's wall clock. Rebuild after a
# product change (the Lorica image) or a change under test-runner/
# (the runner); scenario files under l4/ run on the host and need no
# rebuild.
#
# Usage: [L4_IMAGE_TAG=<tag>] l4/build-images.sh [--runner-only]
#   --runner-only  rebuild the runner alone, the cheap one

set -euo pipefail
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1

# shellcheck source=lib.sh
. l4/lib.sh

services="lorica-streams streams-client dns-loadgen lorica-baseline-single"
case "${1:-}" in
    --runner-only) services="streams-client" ;;
    "") ;;
    *) echo "build-images.sh: unknown argument $1" >&2; exit 2 ;;
esac

# Every profile, so profile-gated services resolve; the Lorica image,
# the runner image and the perf-tools image (dns-loadgen, Story 12.5
# IV2) are each named by one service of the `streams` profile and
# shared by every other service that uses them. The 1.10.7 baseline
# (Story 12.1's cold rollback) has a profile of its own.
# shellcheck disable=SC2086 # the service list is word-split on purpose
l4_compose --profile streams --profile streams-single --profile streams-single-baseline \
    --profile l4-report build $services
echo "Built lorica-e2e-l4 images with tag ${L4_IMAGE_TAG}"
