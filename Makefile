# Makefile for the Heap Allocator Security project.
#
# Builds the attack programs and the benchmarks into build/ . The attacks
# contain DELIBERATE heap bugs (double free, use-after-free, overflow, ...), so
# we keep the standard warnings on but do NOT treat them as errors -- the bugs
# are the point. We also disable fortify/optimization for the attacks so the
# undefined behaviour is not rewritten away by the compiler.

CC      ?= gcc
CSTD     = -std=c11
WARN     = -Wall -Wextra

# Attacks: no optimization, keep frame pointers, no _FORTIFY_SOURCE so the bug
# actually reaches the allocator instead of being caught/removed at compile time.
ATTACK_CFLAGS = $(CSTD) $(WARN) -O0 -g -fno-builtin -U_FORTIFY_SOURCE

# Benchmarks: optimized; measure the allocator, not unoptimized glue code.
BENCH_CFLAGS  = $(CSTD) $(WARN) -O2 -g
BENCH_LIBS    = -lpthread

BUILD        = build
ATTACK_BIN   = $(BUILD)/attacks
BENCH_BIN    = $(BUILD)/bench

ATTACK_SRC  = $(wildcard src/attacks/*.c)
ATTACK_EXE  = $(patsubst src/attacks/%.c,$(ATTACK_BIN)/%,$(ATTACK_SRC))

BENCH_EXE   = $(BENCH_BIN)/throughput $(BENCH_BIN)/rss $(BENCH_BIN)/fingerprint

.PHONY: all attacks bench dirs clean

all: attacks bench

attacks: dirs $(ATTACK_EXE)

bench: dirs $(BENCH_EXE)

dirs:
	@mkdir -p $(ATTACK_BIN) $(BENCH_BIN)

# Each attack depends on the shared marker header.
$(ATTACK_BIN)/%: src/attacks/%.c src/attacks/attack.h | dirs
	$(CC) $(ATTACK_CFLAGS) -o $@ $<

$(BENCH_BIN)/throughput: src/bench/throughput.c | dirs
	$(CC) $(BENCH_CFLAGS) -o $@ $< $(BENCH_LIBS)

$(BENCH_BIN)/rss: src/bench/rss.c | dirs
	$(CC) $(BENCH_CFLAGS) -o $@ $<

$(BENCH_BIN)/fingerprint: src/bench/fingerprint.c | dirs
	$(CC) $(BENCH_CFLAGS) -o $@ $<

clean:
	rm -rf $(BUILD)
