#include <stdio.h>
#include <stdlib.h>
#include "attack.h"

/*
 * Attack: free() of a pointer that did not come from malloc.
 *
 * We call free() on the address of a stack variable. The allocator is handed a
 * pointer it never gave out, so there is no valid chunk header in front of it.
 * WHY this is undefined behaviour: free() assumes its argument points just past
 * allocator metadata it created; a stack address makes it interpret unrelated
 * stack bytes as a chunk header.
 *
 * What each allocator is expected to do:
 *   - glibc: sanity-checks the pointer and usually aborts with
 *     "free(): invalid pointer".
 *   - Scudo / hardened_malloc: the address is not a valid managed chunk, so
 *     both reject it and abort.
 */

int main(void) {
    ATTACK_BEGIN("invalid_free");

    long not_from_malloc = 0x4142434445464748L;
    STEP("stack variable at %p", (void *)&not_from_malloc);

    STEP("free() of a pointer that did not come from malloc");
    free(&not_from_malloc); /* <-- deliberate invalid free */

    /* Reached only if the allocator accepted the bogus pointer. */
    ATTACK_SUCCEEDED();
    return 0;
}
