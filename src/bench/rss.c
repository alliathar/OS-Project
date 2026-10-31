#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Peak-RSS memory benchmark.
 *
 * Allocates a fixed workload -- COUNT live blocks of SIZE bytes each -- and
 * touches every page so the memory is really resident, then reads the kernel's
 * high-water mark for resident set size (VmHWM) from /proc/self/status. This
 * captures the allocator's real memory overhead (metadata, rounding, guard
 * pages, quarantine) for the SAME logical workload.
 *
 * Output (one line, machine-parseable):
 *   memory blocks=<N> block_bytes=<B> requested_kib=<K> peak_rss_kib=<H>
 *
 * Args:  rss [count] [size_bytes]
 * Default: 200,000 blocks of 256 bytes (~50 MiB requested).
 */

static long read_vmhwm_kib(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    long kib = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmHWM:", 6) == 0) {
            sscanf(line + 6, "%ld", &kib);
            break;
        }
    }
    fclose(f);
    return kib;
}

int main(int argc, char **argv) {
    long count = (argc > 1) ? atol(argv[1]) : 200000L;
    long size  = (argc > 2) ? atol(argv[2]) : 256L;
    if (count < 1) count = 1;
    if (size < 1) size = 1;

    char **blocks = calloc((size_t)count, sizeof(char *));
    if (!blocks) {
        perror("calloc index");
        return 1;
    }

    for (long i = 0; i < count; i++) {
        blocks[i] = malloc((size_t)size);
        if (!blocks[i]) {
            perror("malloc block");
            return 1;
        }
        /* Touch every page so the mapping becomes resident. */
        for (long off = 0; off < size; off += 4096) {
            blocks[i][off] = (char)i;
        }
        blocks[i][size - 1] = (char)i;
    }

    long peak = read_vmhwm_kib();
    double requested_kib = (double)count * (double)size / 1024.0;

    printf("memory blocks=%ld block_bytes=%ld requested_kib=%.0f peak_rss_kib=%ld\n",
           count, size, requested_kib, peak);

    for (long i = 0; i < count; i++) {
        free(blocks[i]);
    }
    free(blocks);
    return 0;
}
