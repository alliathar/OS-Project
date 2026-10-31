#!/usr/bin/env bash
#
# setup.sh -- make the three allocators available and record their .so paths.
#
# Produces config/allocators.env, sourced by run_all.sh and measure.sh:
#     GLIBC_SO=""                         # baseline: no preload
#     SCUDO_SO="/path/to/libclang_rt.scudo_standalone.so"   (empty if missing)
#     HARDENED_SO="/path/to/libhardened_malloc.so"          (empty if missing)
#
# Idempotent: safe to re-run. Only (re)builds hardened_malloc if its .so is
# missing. Prints a fingerprint line per allocator so you can see what was found.
#
# Requires: bash, gcc or clang, make, git. On Debian/Ubuntu:
#     sudo apt-get install build-essential git clang

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR="$ROOT/config"
THIRD_PARTY="$ROOT/third_party"
mkdir -p "$CONFIG_DIR" "$THIRD_PARTY"

echo "== Heap allocator setup =="
echo "project root: $ROOT"

# --- sanity: this project targets Linux ---------------------------------------
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "WARNING: this is not Linux. LD_PRELOAD allocator swapping needs Linux"
    echo "         (use WSL2 or a Linux VM). Continuing, but builds may fail."
fi

# --- 1. glibc (baseline) ------------------------------------------------------
# Nothing to install: the system libc IS the baseline. Empty preload selects it.
GLIBC_SO=""
echo
echo "[glibc]   baseline, no preload. libc: $(ldd --version 2>/dev/null | head -n1 || echo unknown)"

# --- 2. Scudo -----------------------------------------------------------------
# Scudo ships inside LLVM's compiler-rt. We look for the standalone runtime .so.
echo
echo "[scudo]   searching for the standalone runtime .so ..."
SCUDO_SO=""
scudo_candidates=$(
    { ls /usr/lib/llvm-*/lib/clang/*/lib/linux/libclang_rt.scudo_standalone-x86_64.so 2>/dev/null || true; } ;
    { ls /usr/lib/clang/*/lib/linux/libclang_rt.scudo_standalone-x86_64.so 2>/dev/null || true; } ;
    { ls /usr/lib/x86_64-linux-gnu/libclang_rt.scudo_standalone* 2>/dev/null || true; } ;
    { find /usr/lib /usr/local/lib -name 'libclang_rt.scudo_standalone*-x86_64.so' 2>/dev/null || true; }
)
for c in $scudo_candidates; do
    if [[ -f "$c" ]]; then SCUDO_SO="$c"; break; fi
done
if [[ -n "$SCUDO_SO" ]]; then
    echo "[scudo]   found: $SCUDO_SO"
else
    echo "[scudo]   NOT found. Install an LLVM compiler-rt that ships Scudo, e.g.:"
    echo "            sudo apt-get install clang libclang-rt-dev"
    echo "          (or build compiler-rt). Scudo rows will be skipped until present."
fi

# --- 3. hardened_malloc -------------------------------------------------------
echo
echo "[hardened] checking GrapheneOS/hardened_malloc ..."
HM_DIR="$THIRD_PARTY/hardened_malloc"
HARDENED_SO=""
if [[ ! -d "$HM_DIR/.git" ]]; then
    echo "[hardened] cloning into $HM_DIR ..."
    git clone --depth 1 https://github.com/GrapheneOS/hardened_malloc.git "$HM_DIR"
else
    echo "[hardened] repo already present at $HM_DIR"
fi
# Build if the .so is not there yet.
existing_so=$(find "$HM_DIR/out" -name 'libhardened_malloc*.so' 2>/dev/null | head -n1 || true)
if [[ -z "$existing_so" ]]; then
    # hardened_malloc's Makefile uses -std=c23. gcc < 14 only knows -std=c2x and
    # fails; clang >= 17 supports c23. So if the default cc can't do c23, build
    # with clang instead (falling back to a versioned clang if needed).
    HM_CC="${CC:-cc}"; HM_CXX="${CXX:-c++}"
    if ! printf 'int main(void){return 0;}\n' | "$HM_CC" -std=c23 -x c - -o /dev/null 2>/dev/null; then
        clang_bin=""
        for c in clang clang-18 clang-17 clang-19; do
            command -v "$c" >/dev/null 2>&1 && { clang_bin="$c"; break; }
        done
        if [[ -n "$clang_bin" ]]; then
            HM_CC="$clang_bin"; HM_CXX="${clang_bin/clang/clang++}"
            echo "[hardened] default compiler lacks -std=c23; building with $HM_CC / $HM_CXX"
        else
            echo "[hardened] WARNING: no C23-capable compiler found (need gcc>=14 or clang>=17)"
        fi
    fi
    echo "[hardened] building (make CC=$HM_CC CXX=$HM_CXX)..."
    ( cd "$HM_DIR" && make CC="$HM_CC" CXX="$HM_CXX" ) || echo "[hardened] build FAILED -- see output above"
    existing_so=$(find "$HM_DIR/out" -name 'libhardened_malloc*.so' 2>/dev/null | head -n1 || true)
fi
if [[ -n "$existing_so" ]]; then
    HARDENED_SO="$existing_so"
    echo "[hardened] found: $HARDENED_SO"
else
    echo "[hardened] .so not built; hardened rows will be skipped until present."
fi

# --- stage .so files out of any space-containing path -------------------------
# LD_PRELOAD is a space/colon-separated list, so it CANNOT reference a path that
# contains a space (e.g. this "OS Project" folder). Any such .so is copied into
# a space-free staging dir, and that copy's path is what we record.
STAGE="$HOME/.heapalloc/lib"
case "$STAGE" in *" "*) STAGE="/tmp/heapalloc-lib";; esac
mkdir -p "$STAGE"

stage_so() { # $1 = source .so path (may be empty); prints a space-free path
    local src="$1"
    [[ -z "$src" ]] && { echo ""; return; }
    if [[ "$src" == *" "* ]]; then
        local dst="$STAGE/$(basename "$src")"
        cp -f "$src" "$dst"
        echo "$dst"
    else
        echo "$src"
    fi
}

if [[ "$ROOT" == *" "* ]]; then
    echo
    echo "NOTE: project path contains a space; staging allocator .so files into"
    echo "      $STAGE so LD_PRELOAD can use them."
fi
SCUDO_SO="$(stage_so "$SCUDO_SO")"
HARDENED_SO="$(stage_so "$HARDENED_SO")"

# --- write config -------------------------------------------------------------
CONF="$CONFIG_DIR/allocators.env"
cat > "$CONF" <<EOF
# Generated by scripts/setup.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Empty value = allocator unavailable (its rows are skipped).
GLIBC_SO="$GLIBC_SO"
SCUDO_SO="$SCUDO_SO"
HARDENED_SO="$HARDENED_SO"
EOF

echo
echo "== wrote $CONF =="
cat "$CONF"
echo
echo "Next: make   &&   ./scripts/run_all.sh   &&   ./scripts/measure.sh   &&   python3 scripts/report.py"
