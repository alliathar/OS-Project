#!/usr/bin/env bash
#
# run_all.sh -- run every attack under every available allocator, N times, and
# record the outcome per (attack x allocator x run) into results/attack_matrix.csv.
#
# For each run we FIRST verify (via build/bench/fingerprint) that the intended
# allocator is really mapped into the process -- no silent fallback to glibc.
#
# Outcome classification (per run):
#   succeeded    -> process printed "ATTACK SUCCEEDED" and exited 0
#                   (the allocator let the bug run to completion -> a MISS)
#   stopped      -> process was killed by a signal (abort/segv/bus) OR exited
#                   non-zero without the marker (the allocator caught it)
#   inconclusive -> timed out, or exited 0 with no marker (unexpected)
#
# Usage: ./scripts/run_all.sh [N_RUNS]   (default N_RUNS=5)

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS="$ROOT/results"
LOGS="$RESULTS/logs"
ATTACK_BIN="$ROOT/build/attacks"
FINGERPRINT="$ROOT/build/bench/fingerprint"
CONF="$ROOT/config/allocators.env"
CSV="$RESULTS/attack_matrix.csv"
N_RUNS="${1:-5}"
TIMEOUT_S=10

mkdir -p "$LOGS"

if [[ ! -f "$CONF" ]]; then
    echo "ERROR: $CONF missing. Run ./scripts/setup.sh first." >&2
    exit 1
fi
if [[ ! -d "$ATTACK_BIN" || -z "$(ls -A "$ATTACK_BIN" 2>/dev/null)" ]]; then
    echo "ERROR: no attack binaries in $ATTACK_BIN. Run 'make' first." >&2
    exit 1
fi
# shellcheck disable=SC1090
source "$CONF"

# Build the list of available allocators as "name|so|fingerprint" rows.
allocs=()
allocs+=("glibc||libc")   # baseline: empty preload, libc always mapped
if [[ -n "${SCUDO_SO:-}" ]]; then
    allocs+=("scudo|$SCUDO_SO|$(basename "$SCUDO_SO")")
else
    echo "NOTE: Scudo not configured; skipping (re-run setup.sh after installing it)."
fi
if [[ -n "${HARDENED_SO:-}" ]]; then
    allocs+=("hardened|$HARDENED_SO|$(basename "$HARDENED_SO")")
else
    echo "NOTE: hardened_malloc not configured; skipping."
fi

# Record the environment these results came from (read by findings_pdf.py).
{
    echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "os: $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
    echo "kernel: $(uname -r)"
    echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//')"
    echo "cpus: $(nproc)"
    echo "glibc: $(ldd --version 2>/dev/null | head -n1)"
    echo "compiler: $(cc --version 2>/dev/null | head -n1)"
    echo "scudo_so: ${SCUDO_SO:-none}"
    echo "hardened_so: ${HARDENED_SO:-none}"
    echo "hardened_commit: $(git -C "$ROOT/third_party/hardened_malloc" log -1 --format='%h (%cs)' 2>/dev/null || echo unknown)"
    echo "runs_per_cell: $N_RUNS"
    echo "timeout_s: $TIMEOUT_S"
} > "$RESULTS/environment.txt"

echo "attack,allocator,run,outcome,exit_code,signal,loaded" > "$CSV"

# classify <exit_status> <marker_found> -> echoes "outcome exit_code signal"
classify() {
    local status="$1" marker="$2" outcome exit_code signal
    if (( status >= 128 )); then
        signal=$(( status - 128 )); exit_code=""
    else
        signal=""; exit_code="$status"
    fi
    if (( status == 124 )); then
        outcome="inconclusive"          # timeout returns 124
    elif [[ "$marker" == "1" && "$status" == "0" ]]; then
        outcome="succeeded"
    elif [[ -n "$signal" || "$status" != "0" ]]; then
        outcome="stopped"
    else
        outcome="inconclusive"
    fi
    # '|'-delimited so empty exit_code/signal fields keep their position.
    echo "$outcome|$exit_code|$signal"
}

for exe in "$ATTACK_BIN"/*; do
    attack="$(basename "$exe")"
    for row in "${allocs[@]}"; do
        IFS='|' read -r name so fp <<< "$row"

        # --- verify the intended allocator is actually loaded (once per combo) ---
        if [[ -n "$so" ]]; then
            fp_out="$(LD_PRELOAD="$so" "$FINGERPRINT" "$fp" 2>/dev/null || true)"
        else
            fp_out="$("$FINGERPRINT" "$fp" 2>/dev/null || true)"
        fi
        if [[ "$fp_out" != LOADED:* ]]; then
            echo "  [$attack / $name] allocator NOT loaded ($fp_out) -- recording inconclusive"
            for ((r=1; r<=N_RUNS; r++)); do
                echo "$attack,$name,$r,inconclusive,,,no" >> "$CSV"
            done
            continue
        fi

        for ((r=1; r<=N_RUNS; r++)); do
            log="$LOGS/${attack}.${name}.${r}.log"
            if [[ -n "$so" ]]; then
                LD_PRELOAD="$so" timeout "$TIMEOUT_S" "$exe" > "$log" 2>&1
            else
                timeout "$TIMEOUT_S" "$exe" > "$log" 2>&1
            fi
            status=$?
            marker=0
            grep -q "ATTACK SUCCEEDED" "$log" && marker=1
            IFS='|' read -r outcome exit_code signal <<< "$(classify "$status" "$marker")"
            echo "$attack,$name,$r,$outcome,$exit_code,$signal,yes" >> "$CSV"
        done
        echo "  [$attack / $name] done ($N_RUNS runs)"
    done
done

echo
echo "== wrote $CSV =="
column -t -s, "$CSV" 2>/dev/null || cat "$CSV"
