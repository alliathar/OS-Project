#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "attack.h"

/*
 * Attack: inline-metadata corruption.
 *
 * Two chunks are allocated next to each other. We overflow out of the first one
 * into the region immediately after it, then free the second chunk. On an
 * allocator that stores bookkeeping (size / flags) inline right before each
 * user block, that overflow lands on the second chunk's header, and the free()
 * of the second chunk then operates on corrupted metadata.
 *
 * WHY this is undefined behaviour: the overflow writes outside the first
 * allocation, and freeing a chunk whose header has been tampered with drives
 * the allocator through an inconsistent internal state -- the mechanism behind
 * many classic heap exploits.
 *
 * This is the key allocator-design comparison:
 *   - glibc: inline metadata. Overflow reaches it; free() typically aborts with
 *     "corrupted size vs. prev_size" / "invalid next size" -- but only because
 *     it noticed, not because the write was prevented.
 *   - Scudo: header checksum detects tampering on the next operation.
 *   - hardened_malloc: metadata is kept in a SEPARATE region from user data, so
 *     an inline overflow cannot reach it at all; a large overflow instead hits a
 *     guard page and faults.
 */

int main(void) {
    ATTACK_BEGIN("metadata_overwrite");

    char *a = malloc(32);
    char *b = malloc(32);
    if (a == NULL || b == NULL) {
        perror("malloc failed");
        return 1;
    }
    STEP("chunk a = %p, chunk b = %p (delta %ld bytes)",
         (void *)a, (void *)b, (long)(b - a));

    /*
     * Overflow from a forward by 64 bytes. With inline metadata this reaches
     * into b's header area; with separated metadata it only hits other user
     * data or a guard page.
     */
    STEP("overflowing chunk a by 64 bytes toward chunk b's header");
    memset(a, 'B', 32 + 64); /* <-- deliberate out-of-bounds write */

    STEP("free(b) -- acts on possibly-corrupted metadata");
    free(b);

    STEP("free(a)");
    free(a);

    /* Reached only if the corruption was neither prevented nor detected. */
    ATTACK_SUCCEEDED();
    return 0;
}
