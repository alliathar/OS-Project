# CLAUDE.md — Heap Allocator Security Project

Guidance for Claude Code working in this repo. Read this before doing anything.

## What this project is
Operating Systems final project (Habib University, Fall 2026). Research question:

> When common heap bugs like double free and use-after-free are used to attack
> the standard malloc and two security-enhanced versions of it, which attacks
> does each one stop, which still get through, and what does the extra safety cost?

Course elements covered: **Memory Management** and **Security** (the brief asks for one or more).
Author: Muhammad Ali Athar (ID 10569). Team: _add members before submitting_.
Deadlines: proposal + group registration **Nov 2, 2026**; final submission **Nov 26, 2026, 11:59 PM**.

## The core comparison
Three allocators, swapped at runtime with `LD_PRELOAD` — no source changes to the attack programs:

- **glibc malloc** — the Linux default. This is the BASELINE, not a hardened allocator.
  (Recent versions do add some checks: tcache double-free detection, safe-linking.)
- **Scudo** — from LLVM, default on Android. Per-chunk checksums, delayed reuse of freed
  memory (quarantine), randomized placement.
- **hardened_malloc** — from GrapheneOS. Metadata kept separate from user data, guard pages
  around allocations, freed memory wiped.

## What to build (in this order)
1. **Attack programs** — C, one bug per file, each prints a clear outcome marker
   (e.g. reaches `"ATTACK SUCCEEDED"` vs aborts/crashes before it):
   - `double_free`
   - `use_after_free`
   - `heap_overflow` (write past the end of a chunk)
   - `metadata_overwrite`
   - `invalid_free` (free a pointer not from malloc)
   - `uninitialized_read` (read freed/fresh memory for leftover data)
2. **Attack runner** — compile all attacks once, run each under each allocator via
   `LD_PRELOAD`, repeat N times, record outcome per (attack × allocator):
   `stopped` (aborted/crashed safely) / `succeeded` / `inconclusive`, plus exit signal.
   Output: `results/attack_matrix.csv`.
3. **Bypass variants** — versions tuned to evade a specific defense, e.g. heap spray +
   delayed reuse against Scudo's quarantine, or an overflow sized to land outside a guard
   page. Label which defense each targets. THIS is the research contribution — do it only
   after step 2 produces a clean baseline matrix.
4. **Measurement harness**:
   - speed: a malloc/free throughput microbenchmark, single- and multi-threaded,
   - memory: peak RSS for a fixed workload,
   - each run under all three allocators → `results/perf.csv`, `results/memory.csv`.
5. **Report generator** — `scripts/report.py` turns the CSVs into a summary table and
   simple plots. No hand-typed numbers anywhere.

## Environment
- Linux (VM or WSL2), x86-64. `gcc`/`clang`, `make`, `python3` (+ matplotlib for plots).
- Scudo: via LLVM compiler-rt, or `clang -fsanitize=scudo` where available.
- hardened_malloc: build from source (GitHub: GrapheneOS/hardened_malloc).
- `scripts/setup.sh` installs/builds the allocators and prints each `.so` path.
- CRITICAL: before trusting any run, verify the intended allocator is actually loaded
  (print a fingerprint — e.g. a known symbol or `mallinfo` quirk), not glibc by accident.

## Reference detectors (NOT part of the 3-way comparison)
- Use ASan or Valgrind to CONFIRM each attack triggers a real bug first. If the detector
  flags it but an allocator lets it run to `"ATTACK SUCCEEDED"`, that's a genuine miss.
- Do NOT stack these with Scudo/hardened_malloc — they replace malloc too. Run separately.

## Repo layout
```
Final/
  CLAUDE.md
  README.md            # REQUIRED and graded: how to run everything + file/folder guide
  Makefile
  src/attacks/         # one .c per bug, plus bypass variants
  src/bench/           # throughput + RSS benchmarks
  scripts/setup.sh     # build/install allocators, print .so paths
  scripts/run_all.sh   # attacks × allocators -> results/attack_matrix.csv
  scripts/measure.sh   # perf + memory -> results/*.csv
  scripts/report.py    # CSVs -> summary table + plots
  results/             # all generated; never edited by hand
  report/              # written report, matching the provided Part-4 sample format
```

## Target run flow (must work from a clean checkout)
```
./scripts/setup.sh        # allocators ready, prints .so paths
make                      # builds all attacks + benchmarks
./scripts/run_all.sh      # -> results/attack_matrix.csv
./scripts/measure.sh      # -> results/perf.csv, results/memory.csv
python3 scripts/report.py # -> results/summary.md + plots
```

## Hard rules (from the course brief — do not break)
- The project MUST run by following only the README from a clean checkout.
  Poor code documentation or code that doesn't run = instant ZERO.
- README must say how to run it and what every file/folder is.
- No fabricated results. Every table cell traces to a real logged run under `results/`.
- GitHub repo with a self-explanatory README is part of the grade.

## Conventions
- C11, compile with `-Wall -Wextra`. Attack programs contain deliberate undefined behaviour:
  isolate each in its own file and comment WHY the UB is there.
- Deterministic where possible. Where randomization matters (Scudo), average over N runs
  and report N.
- Scripts in bash, idempotent (safe to re-run).
- Prefer simple and readable over clever.

## First session: start here
1. Scaffold the layout above — stub files, Makefile, README skeleton.
2. Write `scripts/setup.sh`; confirm all three allocators load (print fingerprint each).
3. Port the author's existing `double_free.c` and `use_after_free.c` from the OS Lab 05
   folder (`C:\Users\Ali\Desktop\OS\Lab05`) as the first two attacks.
4. Get `run_all.sh` producing a first `attack_matrix.csv` across all three allocators
   BEFORE writing any bypass variants.
