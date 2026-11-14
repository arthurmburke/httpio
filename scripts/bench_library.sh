#!/usr/bin/env bash
# Run inside Linux with DPDK. Configure loopback in an isolated network
# namespace first; see docs/tcp-library-benchmark.md for interpretation.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ${BENCH_LIBRARY_SKIP_BUILD:-0} != 1 ]]; then
    cargo build --release --example bench_library
fi
bin=${BENCH_LIBRARY_BIN:-${CARGO_TARGET_DIR:-target}/release/examples/bench_library}
out=${BENCH_LIBRARY_OUT:-benchmarks/library}
core=${BENCH_LIBRARY_CORE:-0}
export BENCH_LIBRARY_ROUNDS=${BENCH_LIBRARY_ROUNDS:-3000}
unset BENCH_LIBRARY_BREAKDOWN
mkdir -p "$out"
if (( $# == 0 )); then
    set -- -l "$core" -m 256 --no-huge --no-pci --log-level=error --vdev=net_ring0 --vdev=net_ring1
fi
for trial in $(seq 1 "${BENCH_LIBRARY_TRIALS:-5}"); do
    for backend in kernel dpdk; do
        args=()
        if [[ $backend == dpdk ]]; then args=("$@"); fi
        taskset -c "$core" "$bin" "$backend" "${args[@]}" > "$out/$backend-$trial.tsv"
    done
done
BENCH_LIBRARY_BREAKDOWN=1 taskset -c "$core" "$bin" dpdk "$@" > "$out/breakdown.tsv"
printf 'Results: %s\n' "$out"
