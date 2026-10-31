#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "attack.h"

/*
 * Attack: linear heap buffer overflow.
 *
 * A fixed-size buffer is allocated and then written well past its end.
 * WHY this is undefined behaviour: writing beyond the requested size clobbers
 * whatever follows the chunk in the heap -- adjacent user data, allocator
 * metadata, or (if far enough) unmapped memory.
 *
 * The overflow is sized to clearly exceed one small chunk (64 requested, 256
 * written) so it reaches into neighbouring heap space rather than just the
 * slack inside the same chunk.
 *
 * What each allocator is expected to do:
 *   - glibc: no inline bounds checking; a small overflow often goes unnoticed
 *     until a later free() hits corrupted metadata (a MISS at write time).
 *   - Scudo: chunk headers are checksummed, so later operations can detect the
 *     corruption.
 *   - hardened_malloc: guard pages around allocation regions turn a large
 *     enough overflow into an immediate fault.
 */

#define REQUESTED 64
#define WRITTEN   256

int main(void) {
    ATTACK_BEGIN("heap_overflow");

    char *buf = malloc(REQUESTED);
    if (buf == NULL) {
        perror("malloc failed");
        return 1;
    }
    STEP("allocated %d bytes at %p", REQUESTED, (void *)buf);

    STEP("writing %d bytes (overflow of %d bytes past the end)",
         WRITTEN, WRITTEN - REQUESTED);
    memset(buf, 'A', WRITTEN); /* <-- deliberate out-of-bounds write */

    STEP("overflow write returned; freeing (may trip a metadata check)");
    free(buf);

    /* Reached only if neither the write nor the free was caught. */
    ATTACK_SUCCEEDED();
    return 0;
}
