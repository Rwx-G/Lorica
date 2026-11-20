#!/usr/bin/env bash
# The L4 phase of the e2e suite (Story 12.12 D-c), run on the host by
# run.sh. It owns everything that needs Docker itself (start, stop,
# kill, pause, a throwaway container on a data volume, a container's
# cgroup) and runs the scenarios of l4/scenarios/*.sh profile by
# profile. test-runner/l4/report.py, which run.sh runs after every
# phase, is the gate; this script's exit status only adds a node that
# never became ready or a scenario that failed.
#
# Usage: [L4_LANE=1..4] [L4_IMAGE_TAG=<tag>] l4/run-l4.sh [--build] [--keep]
#   --build  rebuild the L4 images when a profile starts
#   --keep   leave the last profile's containers up (profiles are torn
#            down between each other: both nodes answer as `l4-node`)
# L4_LANE and L4_IMAGE_TAG: see the lanes paragraph of l4/lib.sh. A lane
# runs on images l4/build-images.sh built and never builds them itself.
# L4_LOTS=B,D runs only the rows of those Lots (the `lot` column); run.sh
# hands the same list to the report, which then reads the other Lots'
# rows as not run instead of missing.
#
# Adding a scenario: give its registry row (l4/scenarios.tsv, already
# written for every scenario of D-d and D-e) state `live`, and define
# `scenario_<name with . and - as _>` in l4/scenarios/<story>.sh. For
# every profile the row names, the driver calls `scenario <name>` and
# then the function, in a subshell under `set -euo pipefail`, stdin
# closed. The function asserts through l4_client, l4_probe, l4_node and
# l4_api (l4/lib.sh) and ends with one `pass`, `fail` or `partial`.

set -uo pipefail
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1

# shellcheck source=lib.sh
. l4/lib.sh
for scenario_file in l4/scenarios/*.sh; do
    # shellcheck source=/dev/null
    . "$scenario_file"
done

BUILD_FLAG=""
KEEP=false
for arg in "$@"; do
    case "$arg" in
        --build) BUILD_FLAG="--build" ;;
        --keep)  KEEP=true ;;
        *) echo "run-l4.sh: unknown argument $arg" >&2; exit 2 ;;
    esac
done

# Profiles in run order, with the node each one starts.
L4_PROFILES="streams:lorica-streams streams-single:lorica-streams-single"

mapfile -t REGISTRY_ROWS < <(l4_registry_rows)

wait_for_node() {
    local i
    for i in $(seq 1 60); do
        if l4_node sh -c 'test -s /shared/admin_password && curl -skf https://127.0.0.1:19443/ >/dev/null' >/dev/null 2>&1; then
            echo "${L4_NODE} is ready."
            return 0
        fi
        sleep 2
    done
    echo "ERROR: ${L4_NODE} did not start within 120s"
    return 1
}

# Runs one scenario and returns 1 when it failed. Never call it from a
# conditional context (`if`, `||`, `&&`): bash ignores `set -e` in
# everything such a context runs, the subshell below included.
run_scenario() {
    local name="$1" fn="$2" verdicts rc count
    verdicts=$(mktemp)
    (
        set -euo pipefail
        L4_VERDICT_FILE="$verdicts"
        scenario "$name"
        "$fn"
    ) < /dev/null
    rc=$?
    count=$(wc -l < "$verdicts")
    L4_CURRENT="$name"
    L4_VERDICT_FILE="$verdicts"
    if [ "$count" -eq 0 ]; then
        fail "ended without a verdict (exit $rc)"
    elif [ "$rc" -ne 0 ] && ! grep -q '^FAIL$' "$verdicts"; then
        fail "exited $rc after its verdict"
    fi
    rc=0
    grep -q '^FAIL$' "$verdicts" && rc=1
    rm -f "$verdicts"
    return "$rc"
}

run_profile() {
    local profile="$1" failed=0 row name profiles fn
    echo ""
    echo "=== Lorica E2E Tests (L4, ${profile} profile) ==="
    echo ""
    echo "L4-PROFILE ${profile}"

    # A lane never builds: lanes share images built once by
    # l4/build-images.sh, and several lanes building one tag at once
    # would race. `--no-build` fails at once on a missing image instead.
    local build="$BUILD_FLAG"
    if [ -z "$build" ] && [ -n "${L4_LANE:-}" ]; then
        build="--no-build"
    fi
    l4_compose --profile "$profile" up $build -d
    wait_for_node
    if [ $? -ne 0 ]; then
        l4_dump_node_log "$L4_NODE"
        return 1
    fi

    for row in "${REGISTRY_ROWS[@]}"; do
        IFS=$'\t' read -r name _ _ profiles _ lot _ <<< "$row"
        case ",${profiles}," in
            *",${profile},"*) ;;
            *) continue ;;
        esac
        if [ -n "${L4_LOTS:-}" ]; then
            case ",${L4_LOTS}," in
                *",${lot},"*) ;;
                *) continue ;;
            esac
        fi
        fn=$(l4_function_name "$name")
        # A row with no function prints no line; the report fails it
        # unless the row is still pending.
        declare -F "$fn" > /dev/null || continue
        run_scenario "$name" "$fn"
        [ $? -eq 0 ] || failed=1
    done

    if [ "$failed" -ne 0 ]; then
        l4_dump_node_log "$L4_NODE"
    fi
    return "$failed"
}

RC=0
last_profile="${L4_PROFILES##* }"
for entry in $L4_PROFILES; do
    export L4_PROFILE="${entry%%:*}" L4_NODE="${entry#*:}"
    run_profile "$L4_PROFILE"
    [ $? -eq 0 ] || RC=1
    if [ "$KEEP" = false ] || [ "$entry" != "$last_profile" ]; then
        l4_compose --profile "$L4_PROFILE" down -v --remove-orphans
    fi
done

exit "$RC"
