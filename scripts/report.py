#!/usr/bin/env python3
"""
report.py -- turn the generated CSVs into a human-readable summary and plots.

Reads (all produced by the other scripts; never hand-edited):
    results/attack_matrix.csv
    results/perf.csv
    results/memory.csv

Writes:
    results/summary.md          outcome matrix + perf/memory tables
    results/plot_attacks.png    stacked outcome counts per allocator (if matplotlib)
    results/plot_perf.png       throughput per allocator x threads
    results/plot_memory.png     peak RSS per allocator

Every number here is computed from the CSVs -- nothing is typed in. Run after
run_all.sh and measure.sh. matplotlib is optional: without it, tables are still
written and plotting is skipped.
"""

import csv
import os
import statistics
from collections import defaultdict, Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(ROOT, "results")

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAVE_MPL = True
except Exception:
    HAVE_MPL = False


def load_csv(name):
    path = os.path.join(RESULTS, name)
    if not os.path.exists(path):
        return None
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


# ---- attack matrix -----------------------------------------------------------
def summarize_attacks(rows):
    """Return (attacks, allocators, cell) where cell[(a,alloc)] = (verdict, detail)."""
    attacks, allocators = [], []
    buckets = defaultdict(list)
    for r in rows:
        a, alloc = r["attack"], r["allocator"]
        if a not in attacks:
            attacks.append(a)
        if alloc not in allocators:
            allocators.append(alloc)
        buckets[(a, alloc)].append(r["outcome"])

    cell = {}
    for key, outcomes in buckets.items():
        c = Counter(outcomes)
        verdict = c.most_common(1)[0][0]           # majority outcome across runs
        detail = ", ".join(f"{k}x{v}" for k, v in c.most_common())
        cell[key] = (verdict, detail)
    return attacks, allocators, cell


SYMBOL = {"stopped": "STOPPED", "succeeded": "MISS (succeeded)",
          "inconclusive": "inconclusive"}


def write_attack_section(md, rows):
    attacks, allocators, cell = summarize_attacks(rows)
    n_runs = max(Counter((r["attack"], r["allocator"]) for r in rows).values()) if rows else 0
    md.append("## Attack outcomes\n")
    md.append(f"Majority verdict over {n_runs} run(s) per cell. "
              "`STOPPED` = allocator caught the bug; `MISS` = bug ran to completion.\n")
    header = ["attack"] + allocators
    md.append("| " + " | ".join(header) + " |")
    md.append("|" + "|".join(["---"] * len(header)) + "|")
    for a in attacks:
        line = [a]
        for alloc in allocators:
            v, _ = cell.get((a, alloc), ("n/a", ""))
            line.append(SYMBOL.get(v, v))
        md.append("| " + " | ".join(line) + " |")
    md.append("")
    return attacks, allocators, cell


def plot_attacks(rows):
    if not HAVE_MPL or not rows:
        return
    allocators = []
    counts = defaultdict(Counter)
    for r in rows:
        if r["allocator"] not in allocators:
            allocators.append(r["allocator"])
        counts[r["allocator"]][r["outcome"]] += 1
    cats = ["stopped", "succeeded", "inconclusive"]
    colors = {"stopped": "#2e7d32", "succeeded": "#c62828", "inconclusive": "#9e9e9e"}
    bottom = [0] * len(allocators)
    fig, ax = plt.subplots(figsize=(7, 4))
    for cat in cats:
        vals = [counts[a][cat] for a in allocators]
        ax.bar(allocators, vals, bottom=bottom, label=cat, color=colors[cat])
        bottom = [b + v for b, v in zip(bottom, vals)]
    ax.set_ylabel("run count")
    ax.set_title("Attack outcomes by allocator")
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(RESULTS, "plot_attacks.png"), dpi=120)
    plt.close(fig)


# ---- performance -------------------------------------------------------------
def write_perf_section(md, rows):
    agg = defaultdict(list)  # (alloc, threads) -> [ops_per_sec]
    for r in rows:
        try:
            agg[(r["allocator"], r["threads"])].append(float(r["ops_per_sec"]))
        except (ValueError, KeyError):
            pass
    md.append("## Throughput (malloc+free ops/sec, higher is better)\n")
    md.append("| allocator | threads | runs | mean ops/sec | stdev |")
    md.append("|---|---|---|---|---|")
    for (alloc, threads) in sorted(agg):
        vals = agg[(alloc, threads)]
        mean = statistics.mean(vals)
        sd = statistics.stdev(vals) if len(vals) > 1 else 0.0
        md.append(f"| {alloc} | {threads} | {len(vals)} | {mean:,.0f} | {sd:,.0f} |")
    md.append("")
    return agg


def plot_perf(agg):
    if not HAVE_MPL or not agg:
        return
    allocators = sorted({a for (a, _t) in agg})
    thread_vals = sorted({t for (_a, t) in agg}, key=lambda x: int(x))
    fig, ax = plt.subplots(figsize=(7, 4))
    width = 0.8 / max(1, len(thread_vals))
    x = range(len(allocators))
    for i, t in enumerate(thread_vals):
        means = [statistics.mean(agg[(a, t)]) if (a, t) in agg else 0 for a in allocators]
        ax.bar([xx + i * width for xx in x], means, width, label=f"{t} thread(s)")
    ax.set_xticks([xx + width * (len(thread_vals) - 1) / 2 for xx in x])
    ax.set_xticklabels(allocators)
    ax.set_ylabel("ops/sec")
    ax.set_title("Throughput by allocator")
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(RESULTS, "plot_perf.png"), dpi=120)
    plt.close(fig)


# ---- memory ------------------------------------------------------------------
def write_memory_section(md, rows):
    agg = defaultdict(list)
    requested = {}
    for r in rows:
        try:
            agg[r["allocator"]].append(float(r["peak_rss_kib"]))
            requested[r["allocator"]] = float(r["requested_kib"])
        except (ValueError, KeyError):
            pass
    md.append("## Peak memory (RSS, lower is better for the same workload)\n")
    md.append("| allocator | runs | requested KiB | mean peak RSS KiB | overhead x |")
    md.append("|---|---|---|---|---|")
    for alloc in sorted(agg):
        vals = agg[alloc]
        mean = statistics.mean(vals)
        req = requested.get(alloc, 0) or 1
        md.append(f"| {alloc} | {len(vals)} | {req:,.0f} | {mean:,.0f} | {mean/req:.2f} |")
    md.append("")
    return agg


def plot_memory(agg):
    if not HAVE_MPL or not agg:
        return
    allocators = sorted(agg)
    means = [statistics.mean(agg[a]) for a in allocators]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(allocators, means, color="#1565c0")
    ax.set_ylabel("peak RSS (KiB)")
    ax.set_title("Peak memory by allocator (same workload)")
    fig.tight_layout()
    fig.savefig(os.path.join(RESULTS, "plot_memory.png"), dpi=120)
    plt.close(fig)


def main():
    md = ["# Results summary",
          "",
          "_Generated by `scripts/report.py` from the CSVs in `results/`. "
          "Do not edit by hand._",
          ""]

    attacks = load_csv("attack_matrix.csv")
    if attacks:
        write_attack_section(md, attacks)
        plot_attacks(attacks)
    else:
        md.append("## Attack outcomes\n\n_No results/attack_matrix.csv -- run ./scripts/run_all.sh._\n")

    perf = load_csv("perf.csv")
    if perf:
        plot_perf(write_perf_section(md, perf))
    else:
        md.append("## Throughput\n\n_No results/perf.csv -- run ./scripts/measure.sh._\n")

    mem = load_csv("memory.csv")
    if mem:
        plot_memory(write_memory_section(md, mem))
    else:
        md.append("## Peak memory\n\n_No results/memory.csv -- run ./scripts/measure.sh._\n")

    if not HAVE_MPL:
        md.append("> matplotlib not installed; plots skipped. "
                  "`pip install matplotlib` to enable them.\n")

    out = os.path.join(RESULTS, "summary.md")
    os.makedirs(RESULTS, exist_ok=True)
    with open(out, "w") as f:
        f.write("\n".join(md))
    print(f"wrote {out}")
    if HAVE_MPL:
        print("wrote plots: plot_attacks.png, plot_perf.png, plot_memory.png (where data existed)")


if __name__ == "__main__":
    main()
