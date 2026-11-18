#!/bin/sh
# Host-side driver: builds the spike in rust:1-bookworm, builds the small
# netem image, runs every scenario in its own container and prints each
# verdict. Linux shell or Git Bash on Windows.
#
#   OUT=/path/to/logs sh run-all.sh [scenario...]
#
# Cargo uses the lorica-target-b and lorica-cargo-registry volumes.
set -u
HERE=$(cd "$(dirname "$0")" && (pwd -W 2>/dev/null || pwd))
OUT=${OUT:-$HERE/out}
mkdir -p "$OUT"
export MSYS_NO_PATHCONV=1

build() {
  docker run --rm --name s1216-build \
    -v "$HERE:/spike" \
    -v lorica-target-b:/tmp/target \
    -v lorica-cargo-registry:/usr/local/cargo/registry \
    -e CARGO_TARGET_DIR=/tmp/target/s1216 -w /spike rust:1-bookworm \
    cargo build --release --offline || exit 1
  docker build -q -t s1216-netem "$HERE" >/dev/null || exit 1
}

# scenario <label> <netem> <netem_udp> <harness args...>
scenario() {
  label=$1 netem=$2 netem_udp=$3
  shift 3
  docker run --rm --init --name "s1216-$label" --cap-add NET_ADMIN \
    -e LABEL="$label" -e NETEM="$netem" -e NETEM_UDP="$netem_udp" \
    -v lorica-target-b:/tmp/target:ro \
    -v "$HERE:/spike:ro" -v "$OUT:/out" \
    s1216-netem sh /spike/run.sh "$@"
}

LOSSY="delay 2ms 1ms loss 1% reorder 5%"
HARSH="delay 5ms 3ms loss 5% duplicate 1% reorder 25%"

run() {
  case $1 in
    main) scenario main "$LOSSY" 0 --upgrades 50 --interval-ms 200 --long 8 --churn 16 --udp 4 ;;
    main-carry) scenario main-carry "$LOSSY" 0 --upgrades 50 --interval-ms 200 --long 8 --churn 16 --udp 4 --carry-held 1 ;;
    harsh-carry) scenario harsh-carry "$HARSH" 0 --upgrades 50 --interval-ms 200 --long 8 --churn 16 --udp 4 --carry-held 1 ;;
    stall-carry) scenario stall-carry "$LOSSY" 0 --upgrades 12 --interval-ms 700 --long 2 --stall 1 --churn 4 --udp 2 --carry-held 1 ;;
    scale-carry) scenario scale-carry "$LOSSY" 0 --upgrades 10 --interval-ms 1000 --long 1000 --rate 20000 --churn 0 --udp 50 --carry-held 1 ;;
    harsh) scenario harsh "$HARSH" 0 --upgrades 50 --interval-ms 200 --long 8 --churn 16 --udp 4 ;;
    udp-netem) scenario udp-netem "$LOSSY" 1 --upgrades 50 --interval-ms 200 --long 2 --churn 2 --udp 8 ;;
    scale) scenario scale "$LOSSY" 0 --upgrades 10 --interval-ms 1000 --long 1000 --rate 20000 --churn 0 --udp 50 ;;
    baseline) scenario baseline "$LOSSY" 0 --upgrades 0 --duration-ms 10000 --long 8 --churn 16 --udp 4 ;;
    stall) scenario stall "$LOSSY" 0 --upgrades 12 --interval-ms 700 --long 2 --stall 1 --churn 4 --udp 2 ;;
    faults) scenario faults "$LOSSY" 0 --upgrades 20 --interval-ms 250 --long 8 --churn 16 --udp 4 \
      --crash-schedule "2:before-hello,4:before-ready,6:hang-before-ready,8:after-ready,10:hang-after-ready,12:before-committed,14:hang-before-committed,15:old-abort-after-ready,17:old-crash-after-ready" ;;
    abort-shutdown) scenario abort-shutdown "$LOSSY" 0 --upgrades 6 --interval-ms 300 --long 8 --churn 0 --udp 0 \
      --crash-schedule "3:old-abort-after-ready" --abort-with-shutdown 1 ;;
    udp-naive) scenario udp-naive "$LOSSY" 0 --upgrades 20 --interval-ms 200 --long 0 --churn 0 --udp 32 --udp-naive 1 ;;
    total-timeout) scenario total-timeout "$LOSSY" 0 --upgrades 15 --interval-ms 300 --long 4 --churn 0 --udp 0 --total-timeout-ms 3000 ;;
    *) echo "unknown scenario $1"; return 2 ;;
  esac
}

build
if [ $# -eq 0 ]; then
  set -- baseline main main-carry harsh harsh-carry udp-netem scale scale-carry stall stall-carry faults abort-shutdown udp-naive total-timeout
fi
for s in "$@"; do
  run "$s" > "$OUT/$s.txt" 2>&1
  echo "$s: exit $? ($(grep '^VERDICT' "$OUT/$s.txt" | cut -d: -f2))"
done
