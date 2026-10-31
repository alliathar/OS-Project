#!/usr/bin/env bash
#
# measure.sh -- performance and memory cost of each available allocator.
#
# Runs the same workloads under glibc / Scudo / hardened_malloc (via LD_PRELOAD)
# and records:
#   results/perf.csv    allocator,threads,iters,run,ops_per_sec,seconds
#   results/memory.csv  allocator,blocks,block_bytes,run,requested_kib,peak_rss_kib
#
# Randomized allocators (Scudo) vary run-to-run, so every configuration is
# repeated N_RUNS times; report.py averages and reports N.
#
# Usage: ./scripts/measure.sh [N_RUNS]   (default 5)

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS="$ROOT/results"
BENCH="$ROOT/build/bench"
CONF="$ROOT/config/allocators.env"
N_RUNS="${1:-5}"

mkdir -p "$RESULTS"

if [[ ! -f "$CONF" ]]; then
    echo "ERROR: $CONF missing. Run ./scripts/setup.sh first." >&2
    exit 1
fi
if [[ ! -x "$BENCH/throughput" || ! -x "$BENCH/rss" ]]; then
    echo "ERROR: benchmarks not built. Run 'make' first." >&2
    exit 1
fi
# shellcheck disable=SC1090
source "$CONF"

# name|so rows for available allocators
allocs=("glibc|")
[[ -n "${SCUDO_SO:-}" ]]    && allocs+=("scudo|$SCUDO_SO")    || echo "NOTE: skipping Scudo (not configured)."
[[ -n "${HARDENED_SO:-}" ]] && allocs+=("hardened|$HARDENED_SO") || echo "NOTE: skipping hardened_malloc (not configured)."

# run_bench <so> <cmd...>  -> prints the benchmark's stdout line
run_bench() {
    local so="$1"; shift
    if [[ -n "$so" ]]; then
        LD_PRELOAD="$so" "$@"
    else
        "$@"
    fi
}

# --- performance --------------------------------------------------------------
PERF="$RESULTS/perf.csv"
echo "allocator,threads,iters,run,ops_per_sec,seconds" > "$PERF"
THREAD_SET=(1 4)      # single- and multi-threaded
ITERS=2000000
echo "== throughput ($ITERS iters/thread, threads: ${THREAD_SET[*]}, $N_RUNS runs each) =="
for row in "${allocs[@]}"; do
    IFS='|' read -r name so <<< "$row"
    for t in "${THREAD_SET[@]}"; do
        for ((r=1; r<=N_RUNS; r++)); do
            line="$(run_bench "$so" "$BENCH/throughput" "$t" "$ITERS")"
            ops="$(sed -n 's/.*ops_per_sec=\([0-9.]*\).*/\1/p' <<< "$line")"
            secs="$(sed -n 's/.*seconds=\([0-9.]*\).*/\1/p' <<< "$line")"
            echo "$name,$t,$ITERS,$r,${ops:-NA},${secs:-NA}" >> "$PERF"
        done
        echo "  [$name] threads=$t done"
    done
done

# --- memory -------------------------------------------------------------------
MEM="$RESULTS/memory.csv"
echo "allocator,blocks,block_bytes,run,requested_kib,peak_rss_kib" > "$MEM"
BLOCKS=200000
BLOCK_BYTES=256
echo "== peak RSS ($BLOCKS blocks x $BLOCK_BYTES B, $N_RUNS runs each) =="
for row in "${allocs[@]}"; do
    IFS='|' read -r name so <<< "$row"
    for ((r=1; r<=N_RUNS; r++)); do
        line="$(run_bench "$so" "$BENCH/rss" "$BLOCKS" "$BLOCK_BYTES")"
        req="$(sed -n 's/.*requested_kib=\([0-9.]*\).*/\1/p' <<< "$line")"
        peak="$(sed -n 's/.*peak_rss_kib=\([0-9]*\).*/\1/p' <<< "$line")"
        echo "$name,$BLOCKS,$BLOCK_BYTES,$r,${req:-NA},${peak:-NA}" >> "$MEM"
    done
    echo "  [$name] done"
done

echo
echo "== wrote $PERF and $MEM =="
