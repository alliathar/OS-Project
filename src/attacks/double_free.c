#include <stdio.h>
#include <stdlib.h>
#include "attack.h"

/*
 * Attack: double free.
 *
 * A heap block is freed, then freed a second time with no intervening malloc.
 * WHY this is undefined behaviour: after the first free() the block is owned by
 * the allocator again; freeing it a second time hands the same chunk back to
 * the free list twice. A classic exploitation primitive, because it can make
 * malloc() later return the same address for two live allocations.
 *
 * What each allocator is expected to do:
 *   - glibc: recent tcache has a limited double-free check and usually aborts
 *     ("free(): double free detected in tcache 2").
 *   - Scudo / hardened_malloc: detect the double free and abort by design.
 *
 * Ported from the author's OS Lab 05 (double_free.c).
 */

int main(void) {
    ATTACK_BEGIN("double_free");

    int *ptr = malloc(20 * sizeof(int));
    if (ptr == NULL) {
        perror("malloc failed");
        return 1;
    }
    STEP("allocated block at %p", (void *)ptr);

    STEP("first free() (legal)");
    free(ptr);

    STEP("second free() on the same pointer (double free)");
    free(ptr); /* <-- deliberate double free */

    /* Reached only if the allocator did NOT catch the double free. */
    ATTACK_SUCCEEDED();
    return 0;
}
