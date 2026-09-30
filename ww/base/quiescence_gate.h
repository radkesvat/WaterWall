#pragma once

/*
 * Generic operation-admission and quiescence gate for short, non-blocking I/O paths.
 *
 * Close-and-quiesce belongs to the external lifecycle owner. It must never run
 * from a callback that is currently inside the same gate: the owner would be
 * waiting for its own callback to return.
 */

#include "watomic.h"
#include "wlibc.h"
#include "wmutex.h"
#include "wtime.h"

typedef struct quiescence_gate_s
{
    atomic_uint state;
} quiescence_gate_t;

typedef void (*QuiescenceGateYieldFn)(void *context);

#ifdef QUIESCENCE_GATE_TEST_HOOKS
typedef void (*QuiescenceGateBeforeEnterCasHook)(quiescence_gate_t *gate, void *context);

/*
 * Translation-unit-local deterministic interleaving seam. Only the gate unit
 * test defines QUIESCENCE_GATE_TEST_HOOKS; production entry has no hook load.
 */
static QuiescenceGateBeforeEnterCasHook quiescence_gate_before_enter_cas_hook;
static void                            *quiescence_gate_before_enter_cas_context;

static inline void quiescenceGateInstallBeforeEnterCasHook(QuiescenceGateBeforeEnterCasHook hook, void *context)
{
    quiescence_gate_before_enter_cas_hook    = hook;
    quiescence_gate_before_enter_cas_context = context;
}
#endif

#define QUIESCENCE_GATE_VALUE_BITS   ((unsigned int) (sizeof(w_atomic_uint_value_t) * CHAR_BIT))
#define QUIESCENCE_GATE_CLOSED_SHIFT (QUIESCENCE_GATE_VALUE_BITS - 1U - W_ATOMIC_UINT_VALUE_SIGNED)
#define QUIESCENCE_GATE_CLOSED       ((w_atomic_uint_value_t) 1 << QUIESCENCE_GATE_CLOSED_SHIFT)
#define QUIESCENCE_GATE_COUNT_MASK   (QUIESCENCE_GATE_CLOSED - (w_atomic_uint_value_t) 1)

_Static_assert(QUIESCENCE_GATE_CLOSED_SHIFT >= 30U, "quiescence gate requires at least 30 counter bits");
_Static_assert(sizeof(atomic_uint) == sizeof(w_atomic_uint_value_t),
               "atomic_uint compare/exchange value type must match its storage");

#ifndef NDEBUG
enum
{
    kQuiescenceGateTrackedGatesPerThread = 8
};

typedef struct quiescence_gate_thread_entry_s
{
    quiescence_gate_t *gate;
    unsigned int       depth;
} quiescence_gate_thread_entry_t;

typedef struct quiescence_gate_thread_entries_s
{
    quiescence_gate_thread_entry_t entries[kQuiescenceGateTrackedGatesPerThread];
} quiescence_gate_thread_entries_t;

/*
 * Debug-only tracking turns same-gate self-close and unbalanced leave into
 * immediate contract failures. Release builds have no TLS work in the hot path.
 */
extern thread_local quiescence_gate_thread_entries_t quiescence_gate_thread_entries;

static inline void quiescenceGateTrackThreadEnter(quiescence_gate_t *gate)
{
    quiescence_gate_thread_entry_t *free_entry = NULL;
    for (unsigned int i = 0; i < kQuiescenceGateTrackedGatesPerThread; i++)
    {
        quiescence_gate_thread_entry_t *entry = &quiescence_gate_thread_entries.entries[i];
        if (entry->gate == gate)
        {
            entry->depth++;
            return;
        }
        if (entry->gate == NULL && free_entry == NULL)
        {
            free_entry = entry;
        }
    }

    if (free_entry != NULL)
    {
        free_entry->gate  = gate;
        free_entry->depth = 1;
        return;
    }

    assert(! "quiescence gate debug tracking capacity exceeded");
}

static inline void quiescenceGateTrackThreadLeave(quiescence_gate_t *gate)
{
    for (unsigned int i = 0; i < kQuiescenceGateTrackedGatesPerThread; i++)
    {
        quiescence_gate_thread_entry_t *entry = &quiescence_gate_thread_entries.entries[i];
        if (entry->gate != gate)
        {
            continue;
        }

        assert(entry->depth > 0);
        entry->depth--;
        if (entry->depth == 0)
        {
            entry->gate = NULL;
        }
        return;
    }

    assert(! "quiescence gate leave without matching enter");
}

static inline bool quiescenceGateThreadIsInsideGate(const quiescence_gate_t *gate)
{
    for (unsigned int i = 0; i < kQuiescenceGateTrackedGatesPerThread; i++)
    {
        const quiescence_gate_thread_entry_t *entry = &quiescence_gate_thread_entries.entries[i];
        if (entry->gate == gate)
        {
            return true;
        }
    }
    return false;
}
#endif

static inline void quiescenceGateInit(quiescence_gate_t *gate)
{
    atomicStoreRelaxed(&gate->state, QUIESCENCE_GATE_CLOSED);
}

/*
 * Advisory lifecycle-owner check used before installing fields that Open's
 * release CAS will publish. It is not an admission or reclamation mechanism.
 */
static inline bool quiescenceGateIsClosedAndQuiesced(const quiescence_gate_t *gate)
{
    return atomicLoadRelaxed(&gate->state) == QUIESCENCE_GATE_CLOSED;
}

WW_EXPORT bool quiescenceGateOpen(quiescence_gate_t *gate);

/* Keep rare diagnostics out of callers' logger selection and the inline fast paths. */
WW_EXPORT void           quiescenceGateReportSaturation(void);
WW_EXPORT _Noreturn void quiescenceGateAbortUnderflow(void);

static inline bool quiescenceGateEnter(quiescence_gate_t *gate)
{
    w_atomic_uint_value_t state = atomicLoadRelaxed(&gate->state);
    for (;;)
    {
        if ((state & QUIESCENCE_GATE_CLOSED) != 0)
        {
            return false;
        }
        if (UNLIKELY((state & QUIESCENCE_GATE_COUNT_MASK) == QUIESCENCE_GATE_COUNT_MASK))
        {
            quiescenceGateReportSaturation();
            assert(! "quiescence gate entry count saturated");
            return false;
        }

#ifdef QUIESCENCE_GATE_TEST_HOOKS
        if (quiescence_gate_before_enter_cas_hook != NULL)
        {
            quiescence_gate_before_enter_cas_hook(gate, quiescence_gate_before_enter_cas_context);
        }
#endif

        // Observes fields published before the successful Open release CAS.
        if (atomic_compare_exchange_weak_explicit(
                &gate->state, &state, state + 1, memory_order_acquire, memory_order_relaxed))
        {
#ifndef NDEBUG
            quiescenceGateTrackThreadEnter(gate);
#endif
            return true;
        }
    }
}

static inline void quiescenceGateLeave(quiescence_gate_t *gate)
{
#ifndef NDEBUG
    quiescenceGateTrackThreadLeave(gate);
#endif
    // Publishes completion of protected work to the closing owner.
    const w_atomic_uint_value_t entered = atomicSubExplicit(&gate->state, 1, memory_order_release);
    assert((entered & QUIESCENCE_GATE_COUNT_MASK) > 0);
    if (UNLIKELY((entered & QUIESCENCE_GATE_COUNT_MASK) == 0))
    {
        quiescenceGateAbortUnderflow();
    }
}

/*
 * Diagnostic only. A caller must successfully enter the gate before touching
 * protected state; observing "active" here grants no lifetime ownership.
 */
static inline bool quiescenceGateIsActive(const quiescence_gate_t *gate)
{
    return (atomicLoadRelaxed(&gate->state) & QUIESCENCE_GATE_CLOSED) == 0;
}

static inline void quiescenceGateYieldThread(void *context)
{
    discard context;

    YIELD_CPU();

    /*
     * Cadence is deliberately not uniform across platforms and is preserved as
     * it was: Windows' scheduler yield is far more expensive than a POSIX one,
     * so this loop only enters the scheduler every 64th pass there. Only the
     * platform selection moved into YIELD_THREAD().
     */
#ifdef OS_WIN
    static thread_local unsigned int windows_yield_count;
    windows_yield_count++;
    if (windows_yield_count % 64 == 0)
    {
        YIELD_THREAD();
    }
#else
    YIELD_THREAD();
#endif
}

static inline void quiescenceGateClose(quiescence_gate_t *gate)
{
#ifndef NDEBUG
    assert(! quiescenceGateThreadIsInsideGate(gate));
#endif
    discard atomic_fetch_or_explicit(&gate->state, QUIESCENCE_GATE_CLOSED, memory_order_acq_rel);
}

WW_EXPORT void quiescenceGateWaitQuiesced(quiescence_gate_t *gate, QuiescenceGateYieldFn yield_fn, void *yield_context);

static inline void quiescenceGateCloseAndQuiesce(quiescence_gate_t *gate, QuiescenceGateYieldFn yield_fn,
                                                 void *yield_context)
{
    quiescenceGateClose(gate);
    quiescenceGateWaitQuiesced(gate, yield_fn, yield_context);
}
