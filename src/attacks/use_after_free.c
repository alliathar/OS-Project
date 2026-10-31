#include <stdio.h>
#include <stdlib.h>
#include "attack.h"

/*
 * Attack: use-after-free (UAF).
 *
 * A block is allocated, initialized, freed, and then read and written through
 * the now-dangling pointer.
 * WHY this is undefined behaviour: once freed, the memory no longer belongs to
 * the program. The allocator may have reused it, written free-list metadata
 * into it, or unmapped it. Reading leaks whatever is there now; writing can
 * corrupt another live allocation or allocator metadata.
 *
 * What each allocator is expected to do:
 *   - glibc: no detection; the access usually "works" silently (a MISS).
 *   - Scudo: quarantines freed memory so immediate reuse is delayed; the write
 *     may land on a region flagged on later access.
 *   - hardened_malloc: freed pages can be protected / the slot wiped, so the
 *     access may fault.
 *
 * Ported from the author's OS Lab 05 (use_after_free.c).
 */

int main(void) {
    ATTACK_BEGIN("use_after_free");

    int *data = malloc(5 * sizeof(int));
    if (data == NULL) {
        perror("malloc failed");
        return 1;
    }
    for (int i = 0; i < 5; i++) {
        data[i] = (i + 1) * 11;
    }
    STEP("before free: data[2] = %d at %p", data[2], (void *)&data[2]);

    STEP("free()");
    free(data);

    STEP("read through dangling pointer (use-after-free read)");
    int read_val = data[2]; /* <-- invalid read */
    STEP("read back: %d", read_val);

    STEP("write through dangling pointer (use-after-free write)");
    data[2] = 999; /* <-- invalid write */
    STEP("wrote 999, read back: %d", data[2]);

    /* Reached only if the allocator did NOT catch the use-after-free. */
    ATTACK_SUCCEEDED();
    return 0;
}
