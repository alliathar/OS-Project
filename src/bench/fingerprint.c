#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Allocator load verifier.
 *
 * CLAUDE.md rule: before trusting any run, prove the INTENDED allocator is
 * actually loaded, not glibc by accident. This program forces an allocation
 * (so the preloaded allocator initializes) and then scans /proc/self/maps for a
 * substring passed on the command line -- the basename of the allocator's .so.
 *
 * Usage:   fingerprint <substring-to-find-in-maps>
 * Prints:  LOADED: <substring>      and exits 0  if the library is mapped
 *          NOT-LOADED: <substring>  and exits 2  if it is not
 *
 * For the glibc baseline there is no preload; pass "libc" -- libc is always
 * mapped, which correctly confirms the baseline.
 */

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <maps-substring>\n", argv[0]);
        return 1;
    }
    const char *needle = argv[1];

    /* Force the allocator to initialize and map itself. */
    void *p = malloc(4096);
    if (p) {
        memset(p, 0, 4096);
        free(p);
    }

    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        perror("fopen /proc/self/maps");
        return 1;
    }

    char line[4096];
    int found = 0;
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, needle)) {
            found = 1;
            break;
        }
    }
    fclose(maps);

    if (found) {
        printf("LOADED: %s\n", needle);
        return 0;
    }
    printf("NOT-LOADED: %s\n", needle);
    return 2;
}
