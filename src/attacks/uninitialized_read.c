#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "attack.h"

/*
 * Attack: information disclosure via uninitialized / reused memory.
 *
 * We write a recognizable "secret" into a block, free it, then immediately
 * allocate the same size again and read what comes back WITHOUT initializing
 * it. If the allocator handed us the same physical bytes, the secret leaks into
 * the new allocation.
 * WHY this is undefined behaviour: reading malloc'd memory before writing it is
 * reading indeterminate bytes; the bug is that those bytes may be a previous
 * allocation's confidential contents.
 *
 * Unlike the other attacks, "success" here is a silent data leak, not a crash.
 * So this program classifies itself:
 *   - prints ATTACK SUCCEEDED and exits 0 if the secret was recovered (a MISS),
 *   - exits 1 (no marker) if the bytes were wiped/randomized (defense worked).
 *
 * What each allocator is expected to do:
 *   - glibc: no wiping and eager reuse -> the secret is usually recovered.
 *   - Scudo: delayed reuse (quarantine) often hands back a different region.
 *   - hardened_malloc: zero-on-free wipes the secret before reuse.
 */

#define N     64
#define SECRET "TOP-SECRET-CANARY-0xDEADBEEF"

int main(void) {
    ATTACK_BEGIN("uninitialized_read");

    char *first = malloc(N);
    if (first == NULL) {
        perror("malloc failed");
        return 1;
    }
    memset(first, 0, N);
    strncpy(first, SECRET, N - 1);
    STEP("wrote secret into first block at %p", (void *)first);

    STEP("free() the block holding the secret");
    free(first);

    char *second = malloc(N);
    if (second == NULL) {
        perror("malloc failed");
        return 1;
    }
    STEP("re-allocated %d bytes at %p; reading WITHOUT initializing", N, (void *)second);

    /* Deliberate read of uninitialized memory, scanning for the leftover secret. */
    int leaked = (memcmp(second, SECRET, strlen(SECRET)) == 0);

    if (leaked) {
        STEP("leftover secret recovered from freed memory");
        ATTACK_SUCCEEDED();
        free(second);
        return 0;
    }

    STEP("memory was wiped or not reused; no secret recovered (defense worked)");
    free(second);
    return 1; /* no ATTACK SUCCEEDED marker -> runner records this as STOPPED */
}
