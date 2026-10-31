#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

/*
 * malloc/free throughput microbenchmark.
 *
 * Each worker thread performs a fixed number of allocate-touch-free cycles over
 * a rotating set of live allocations, cycling through a range of sizes. We touch
 * one byte of every allocation so the pages are actually faulted in (otherwise a
 * clever allocator could optimize the work away).
 *
 * Output (one line, machine-parseable):
 *   throughput threads=<T> iters=<I> ops=<total> seconds=<S> ops_per_sec=<R>
 *
 * "ops" counts malloc+free as two operations.
 *
 * Args:  throughput [threads] [iters_per_thread]
 * Default: 1 thread, 2,000,000 iters.
 */

#define LIVE_SLOTS 128
static const size_t SIZES[] = {16, 32, 64, 128, 256, 512, 1024, 4096};
#define NSIZES ((int)(sizeof(SIZES) / sizeof(SIZES[0])))

typedef struct {
    long iters;
} work_t;

static void *worker(void *arg) {
    work_t *w = (work_t *)arg;
    char *live[LIVE_SLOTS];
    memset(live, 0, sizeof(live));

    for (long i = 0; i < w->iters; i++) {
        int slot = (int)(i % LIVE_SLOTS);
        if (live[slot]) {
            free(live[slot]);
        }
        size_t sz = SIZES[i % NSIZES];
        char *p = malloc(sz);
        if (p) {
            p[0] = (char)i;        /* touch to force a real page fault */
            p[sz - 1] = (char)i;   /* touch the far end too */
        }
        live[slot] = p;
    }
    for (int s = 0; s < LIVE_SLOTS; s++) {
        free(live[s]);
    }
    return NULL;
}

int main(int argc, char **argv) {
    int threads = (argc > 1) ? atoi(argv[1]) : 1;
    long iters  = (argc > 2) ? atol(argv[2]) : 2000000L;
    if (threads < 1) threads = 1;
    if (iters < 1) iters = 1;

    pthread_t tids[256];
    if (threads > 256) threads = 256;
    work_t w = { iters };

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (int i = 0; i < threads; i++) {
        pthread_create(&tids[i], NULL, worker, &w);
    }
    for (int i = 0; i < threads; i++) {
        pthread_join(tids[i], NULL);
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double secs = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

    long total_ops = (long)threads * iters * 2; /* malloc + free */
    double rate = (secs > 0.0) ? total_ops / secs : 0.0;

    printf("throughput threads=%d iters=%ld ops=%ld seconds=%.6f ops_per_sec=%.2f\n",
           threads, iters, total_ops, secs, rate);
    return 0;
}
