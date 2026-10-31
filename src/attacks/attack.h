#ifndef ATTACK_H
#define ATTACK_H

/*
 * Shared output markers for all attack programs.
 *
 * Every attack is a small, self-contained program that deliberately triggers
 * ONE heap bug. The runner (scripts/run_all.sh) does not parse the bug itself;
 * it only looks at:
 *   - whether the process reached the "ATTACK SUCCEEDED" marker, and
 *   - how the process exited (clean exit vs. killed by a signal / abort).
 *
 * We flush after every print because a hardened allocator may abort() the
 * process at any point. Without flushing, buffered stdout would be lost and a
 * genuine "the allocator stopped it here" run could look like a crash with no
 * evidence of where it got to.
 */

#include <stdio.h>

/* Print the attack's name once at startup. */
#define ATTACK_BEGIN(name)                                                     \
    do {                                                                       \
        printf("[attack] %s\n", (name));                                       \
        fflush(stdout);                                                        \
    } while (0)

/* Narrate a step so a stopped run shows how far it got. */
#define STEP(...)                                                              \
    do {                                                                       \
        printf("[step] ");                                                     \
        printf(__VA_ARGS__);                                                   \
        printf("\n");                                                          \
        fflush(stdout);                                                        \
    } while (0)

/*
 * The one marker the runner classifies on. If a program prints this and exits
 * 0, the allocator let the bug run to completion (a MISS). If the allocator
 * aborts/crashes the process before this line, the runner records it as
 * STOPPED.
 */
#define ATTACK_SUCCEEDED()                                                     \
    do {                                                                       \
        printf("ATTACK SUCCEEDED\n");                                          \
        fflush(stdout);                                                        \
    } while (0)

#endif /* ATTACK_H */
