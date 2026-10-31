# Heap Allocator Security: What Hardened `malloc` Actually Stops

OS final project (Habib University, Fall 2026) — **Memory Management** + **Security**.

> **Research question.** When common heap bugs (double free, use-after-free,
> overflow, …) are thrown at the standard `malloc` and two security-enhanced
> replacements, which attacks does each one stop, which still get through, and
> what does the extra safety cost in speed and memory?

**Author:** Muhammad Ali Athar (10569). **Team:** _add members before submitting._

---

## The three allocators compared

All three are swapped in at **runtime with `LD_PRELOAD`** — the attack programs
are compiled once and never changed between allocators.

| Allocator | What it is | Defenses it adds |
|---|---|---|
| **glibc malloc** | Linux default — the **baseline**, not hardened | Some modern checks: tcache double-free detection, safe-linking |
| **Scudo** | From LLVM; default on Android | Per-chunk checksums, delayed reuse (quarantine), randomized placement |
| **hardened_malloc** | From GrapheneOS | Metadata separated from user data, guard pages, freed memory wiped |

---

## Requirements

- **Linux, x86-64** (a VM or **WSL2** — `LD_PRELOAD` allocator swapping is Linux-only).
- `gcc` or `clang`, `make`, `git`, `python3` (+ `python3-venv` for the PDF report).
- For plots: `matplotlib` (optional for `report.py`; tables still work without it).
- For Scudo: an LLVM compiler-rt that ships it (`libclang-rt-18-dev` on Ubuntu 24.04).
- For hardened_malloc: built from source automatically by `setup.sh` (needs `git` + `make`).
- For the PDF: `setup.sh` creates a Python venv at `~/.heapalloc/venv` and installs
  `reportlab` into it (needs network access once).

On Ubuntu 24.04 / WSL2, one command installs everything:

```bash
sudo apt-get update && sudo apt-get install -y build-essential git python3 python3-venv python3-matplotlib clang libclang-rt-18-dev
```

> On Windows, open this folder inside WSL2 (`wsl` then `cd` to it) and run everything there.

Two things `setup.sh` handles for you, in case you wonder why:
- **hardened_malloc needs C23.** Its Makefile uses `-std=c23`, which gcc < 14 rejects
  (Ubuntu 24.04 ships gcc 13). `setup.sh` detects that and builds it with `clang` instead.
- **`LD_PRELOAD` can't take paths containing spaces** (it is a space/colon-separated list).
  If the project lives under a path with a space (e.g. `OS Project/`), `setup.sh` copies
  the allocator `.so` files to `~/.heapalloc/lib/` and records that path instead.

---

## How to run it (from a clean checkout)

```bash
./scripts/setup.sh          # locate/build the allocators, print each .so path
make                        # build all attacks + benchmarks into build/
./scripts/run_all.sh        # attacks x allocators  -> results/attack_matrix.csv
./scripts/measure.sh        # speed + memory         -> results/perf.csv, results/memory.csv
python3 scripts/report.py   # CSVs -> results/summary.md (+ PNG plots)
./scripts/make_pdf.sh       # everything -> results/findings.pdf (report with charts)
```

If scripts aren't executable yet: `chmod +x scripts/*.sh`.
`run_all.sh` and `measure.sh` take an optional run count, e.g. `./scripts/run_all.sh 10`.
Open **`results/findings.pdf`** for the write-up with charts, or
**`results/summary.md`** for the plain tables.

An allocator that `setup.sh` could not find is simply **skipped** (its rows are
left out) so the rest of the pipeline still runs — e.g. glibc-only on a box
without Scudo/hardened_malloc installed.

---

## How a run is judged

Every attack prints a single marker, **`ATTACK SUCCEEDED`**, only if it reaches
the end without being stopped. `run_all.sh` classifies each run:

- **STOPPED** — killed by a signal (abort/segfault) or exited non-zero without
  the marker → *the allocator caught the bug*.
- **MISS (succeeded)** — printed the marker and exited 0 → *the bug ran to completion*.
- **inconclusive** — timed out, or the intended allocator wasn't actually loaded.

**Allocator-load verification.** Before each (attack × allocator) combo,
`build/bench/fingerprint` is run under the same `LD_PRELOAD` and checks
`/proc/self/maps` to confirm the intended `.so` is really mapped — so a result
is never silently glibc-by-accident (a CLAUDE.md hard rule).

**No fabricated numbers.** Every cell in `results/summary.md` traces to a logged
run under `results/logs/` and a row in the CSVs. Nothing is typed by hand.

---

## Repository layout

```
Final/
  README.md              # this file
  CLAUDE.md              # project brief / guidance
  Makefile               # builds attacks + benchmarks into build/
  src/
    attacks/             # one .c per heap bug (deliberate UB, commented why)
      attack.h           #   shared outcome markers (ATTACK SUCCEEDED, steps)
      double_free.c
      use_after_free.c
      heap_overflow.c
      metadata_overwrite.c
      invalid_free.c
      uninitialized_read.c
    bench/
      throughput.c       # malloc/free ops-per-sec, single- & multi-threaded
      rss.c              # peak resident memory for a fixed workload
      fingerprint.c      # proves the intended allocator is actually loaded
  scripts/
    setup.sh             # find/build allocators -> config/allocators.env
    run_all.sh           # -> results/attack_matrix.csv (+ results/logs/)
    measure.sh           # -> results/perf.csv, results/memory.csv
    report.py            # CSVs -> results/summary.md + plots
    make_pdf.sh          # runs findings_pdf.py with the report venv
    findings_pdf.py      # CSVs + logs -> results/findings.pdf + results/figures/
  config/                # generated: allocators.env (.so paths, report Python)
  third_party/           # generated: cloned/built hardened_malloc
  build/                 # generated: compiled binaries
  results/               # generated, never hand-edited:
    attack_matrix.csv    #   one row per attack run (outcome, exit code, signal)
    logs/                #   full output of every attack run
    environment.txt      #   machine + versions the results came from
    perf.csv, memory.csv #   benchmark runs
    summary.md           #   plain tables (report.py)
    findings.pdf         #   report with charts (make_pdf.sh)
    figures/             #   the charts embedded in findings.pdf
  report/                # the written report
```

## The attack programs (`src/attacks/`)

| File | Bug | What it tells us |
|---|---|---|
| `double_free.c` | free the same pointer twice | tcache / checksum double-free detection |
| `use_after_free.c` | read+write through a freed pointer | quarantine / page protection on freed memory |
| `heap_overflow.c` | write past the end of a chunk | guard pages; metadata checks at next `free` |
| `metadata_overwrite.c` | overflow into a neighbour's header | **inline vs. separated metadata** — the core design difference |
| `invalid_free.c` | `free()` a non-heap pointer | pointer validity checks |
| `uninitialized_read.c` | read reused memory for a leftover secret | zero-on-free / delayed reuse (info-leak defense) |

> ⚠️ These programs contain **intentional** undefined behaviour — that is the
> experiment. Each file comments *why* the UB is there. Do not reuse them as
> examples of correct C.

## Reference detectors (not part of the 3-way comparison)

Use **ASan** (`-fsanitize=address`) or **Valgrind** to confirm each attack is a
real bug first. They replace `malloc` too, so run them **separately** — never
stacked with Scudo/hardened_malloc. If a detector flags a bug but an allocator
still reaches `ATTACK SUCCEEDED`, that's a genuine miss worth reporting.

## Next step: bypass variants

Once the baseline matrix is clean, add tuned variants under `src/attacks/` that
try to *evade* a specific defense (e.g. heap-spray + delayed reuse vs. Scudo's
quarantine; an overflow sized to miss a guard page). Label which defense each
targets — that comparison is the project's research contribution.
