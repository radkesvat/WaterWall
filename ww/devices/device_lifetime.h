#pragma once

/*
 * Device-neutral lifetime primitives for short, non-blocking I/O hot paths.
 *
 * Close-and-quiesce belongs to the external lifecycle owner. It must never run
 * from a callback that is currently inside the same gate: the owner would be
 * waiting for its own callback to return.
 */

#include "loggers/internal_logger.h"
#include "watomic.h"
#include "wmutex.h"
#include "wtime.h"

typedef struct device_lifetime_gate_s
{
    atomic_uint state;
} device_lifetime_gate_t;

typedef void (*DeviceLifetimeYieldFn)(void *context);

#ifdef DEVICE_LIFETIME_TEST_HOOKS
typedef void (*DeviceLifetimeBeforeEnterCasHook)(device_lifetime_gate_t *gate, void *context);

/*
 * Translation-unit-local deterministic interleaving seam. Only the gate unit
 * test defines DEVICE_LIFETIME_TEST_HOOKS; production entry has no hook load.
 */
static DeviceLifetimeBeforeEnterCasHook device_lifetime_before_enter_cas_hook;
static void                            *device_lifetime_before_enter_cas_context;

static inline void deviceLifetimeInstallBeforeEnterCasHook(DeviceLifetimeBeforeEnterCasHook hook, void *context)
{
    device_lifetime_before_enter_cas_hook    = hook;
    device_lifetime_before_enter_cas_context = context;
}
#endif

enum
{
    kDeviceLifetimeGateWarningWaitMs          = 2000,
    kDeviceLifetimeGateWarningCheckYieldCount = 256
};

#define DEVICE_LIFETIME_VALUE_BITS        ((unsigned int) (sizeof(w_atomic_uint_value_t) * CHAR_BIT))
#define DEVICE_LIFETIME_GATE_CLOSED_SHIFT (DEVICE_LIFETIME_VALUE_BITS - 1U - W_ATOMIC_UINT_VALUE_SIGNED)
#define DEVICE_LIFETIME_GATE_CLOSED       ((w_atomic_uint_value_t) 1 << DEVICE_LIFETIME_GATE_CLOSED_SHIFT)
#define DEVICE_LIFETIME_GATE_COUNT_MASK   (DEVICE_LIFETIME_GATE_CLOSED - (w_atomic_uint_value_t) 1)

_Static_assert(DEVICE_LIFETIME_GATE_CLOSED_SHIFT >= 30U, "device lifetime gate requires at least 30 counter bits");
_Static_assert(sizeof(atomic_uint) == sizeof(w_atomic_uint_value_t),
               "atomic_uint compare/exchange value type must match its storage");

#ifndef NDEBUG
enum
{
    kDeviceLifetimeTrackedGatesPerThread = 8
};

typedef struct device_lifetime_thread_entry_s
{
    device_lifetime_gate_t *gate;
    unsigned int            depth;
} device_lifetime_thread_entry_t;

typedef struct device_lifetime_thread_entries_s
{
    device_lifetime_thread_entry_t entries[kDeviceLifetimeTrackedGatesPerThread];
} device_lifetime_thread_entries_t;

/*
 * Debug-only tracking turns same-gate self-close and unbalanced leave into
 * immediate contract failures. Release builds have no TLS work in the hot path.
 */
extern thread_local device_lifetime_thread_entries_t device_lifetime_thread_entries;

static inline void deviceLifetimeTrackThreadEnter(device_lifetime_gate_t *gate)
{
    device_lifetime_thread_entry_t *free_entry = NULL;
    for (unsigned int i = 0; i < kDeviceLifetimeTrackedGatesPerThread; i++)
    {
        device_lifetime_thread_entry_t *entry = &device_lifetime_thread_entries.entries[i];
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

    assert(! "device lifetime gate debug tracking capacity exceeded");
}

static inline void deviceLifetimeTrackThreadLeave(device_lifetime_gate_t *gate)
{
    for (unsigned int i = 0; i < kDeviceLifetimeTrackedGatesPerThread; i++)
    {
        device_lifetime_thread_entry_t *entry = &device_lifetime_thread_entries.entries[i];
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

    assert(! "device lifetime gate leave without matching enter");
}

static inline bool deviceLifetimeThreadIsInsideGate(const device_lifetime_gate_t *gate)
{
    for (unsigned int i = 0; i < kDeviceLifetimeTrackedGatesPerThread; i++)
    {
        const device_lifetime_thread_entry_t *entry = &device_lifetime_thread_entries.entries[i];
        if (entry->gate == gate)
        {
            return true;
        }
    }
    return false;
}
#endif

static inline void deviceLifetimeGateInit(device_lifetime_gate_t *gate)
{
    atomicStoreRelaxed(&gate->state, DEVICE_LIFETIME_GATE_CLOSED);
}

/*
 * Advisory lifecycle-owner check used before installing fields that Open's
 * release CAS will publish. It is not an admission or reclamation mechanism.
 */
static inline bool deviceLifetimeGateIsClosedAndQuiesced(const device_lifetime_gate_t *gate)
{
    return atomicLoadRelaxed(&gate->state) == DEVICE_LIFETIME_GATE_CLOSED;
}

static inline bool deviceLifetimeGateOpen(device_lifetime_gate_t *gate)
{
    w_atomic_uint_value_t expected = DEVICE_LIFETIME_GATE_CLOSED;

    // Publishes the protected fields installed by the lifecycle owner.
    if (atomicCompareExchangeExplicit(&gate->state, &expected, 0, memory_order_release, memory_order_relaxed))
    {
        return true;
    }

    LOGE("Device lifetime gate open requires a closed, quiesced gate (state=%llu)", (unsigned long long) expected);
    assert(expected == DEVICE_LIFETIME_GATE_CLOSED);
    return false;
}

static inline bool deviceLifetimeGateEnter(device_lifetime_gate_t *gate)
{
    w_atomic_uint_value_t state = atomicLoadRelaxed(&gate->state);
    for (;;)
    {
        if ((state & DEVICE_LIFETIME_GATE_CLOSED) != 0)
        {
            return false;
        }
        if (UNLIKELY((state & DEVICE_LIFETIME_GATE_COUNT_MASK) == DEVICE_LIFETIME_GATE_COUNT_MASK))
        {
            LOGE("Device lifetime gate entry count saturated");
            assert(! "device lifetime gate entry count saturated");
            return false;
        }

#ifdef DEVICE_LIFETIME_TEST_HOOKS
        if (device_lifetime_before_enter_cas_hook != NULL)
        {
            device_lifetime_before_enter_cas_hook(gate, device_lifetime_before_enter_cas_context);
        }
#endif

        // Observes fields published before the successful Open release CAS.
        if (atomic_compare_exchange_weak_explicit(
                &gate->state, &state, state + 1, memory_order_acquire, memory_order_relaxed))
        {
#ifndef NDEBUG
            deviceLifetimeTrackThreadEnter(gate);
#endif
            return true;
        }
    }
}

static inline void deviceLifetimeGateLeave(device_lifetime_gate_t *gate)
{
#ifndef NDEBUG
    deviceLifetimeTrackThreadLeave(gate);
#endif
    // Publishes completion of protected work to the closing owner.
    const w_atomic_uint_value_t entered = atomicSubExplicit(&gate->state, 1, memory_order_release);
    assert((entered & DEVICE_LIFETIME_GATE_COUNT_MASK) > 0);
    discard entered;
}

/*
 * Diagnostic only. A caller must successfully enter the gate before touching
 * protected state; observing "active" here grants no lifetime ownership.
 */
static inline bool deviceLifetimeGateIsActive(const device_lifetime_gate_t *gate)
{
    return (atomicLoadRelaxed(&gate->state) & DEVICE_LIFETIME_GATE_CLOSED) == 0;
}

static inline void deviceLifetimeYieldThread(void *context)
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

static inline void deviceLifetimeGateCloseAndQuiesce(device_lifetime_gate_t *gate, DeviceLifetimeYieldFn yield_fn,
                                                     void *yield_context)
{
    assert(yield_fn != NULL);

#ifndef NDEBUG
    assert(! deviceLifetimeThreadIsInsideGate(gate));
#endif

    /*
     * Admission and close share one atomic modification order:
     * - an Enter CAS that wins first contributes to the count and Close waits
     *   for its Leave;
     * - a Close RMW that wins first sets CLOSED and the Enter rejects;
     * - Open-release publishes protected fields to Enter-acquire;
     * - Leave-release publishes completed work to the acquire close/load that
     *   observes the final zero count.
     */
    w_atomic_uint_value_t state =
        atomic_fetch_or_explicit(&gate->state, DEVICE_LIFETIME_GATE_CLOSED, memory_order_acquire);
    if ((state & DEVICE_LIFETIME_GATE_COUNT_MASK) == 0)
    {
        return;
    }

    unsigned int wait_started_at = getTickMS();
    unsigned int yields          = 0;
    bool         warned          = false;
    for (;;)
    {
        // Acquire pairs with the final entrant's release Leave before reclamation.
        state                                 = atomicLoadExplicit(&gate->state, memory_order_acquire);
        const w_atomic_uint_value_t in_flight = state & DEVICE_LIFETIME_GATE_COUNT_MASK;
        if (in_flight == 0)
        {
            return;
        }

        yield_fn(yield_context);
        yields++;
        if (! warned && yields % kDeviceLifetimeGateWarningCheckYieldCount == 0 &&
            getTickMS() - wait_started_at >= kDeviceLifetimeGateWarningWaitMs)
        {
            LOGW("Device lifetime gate is still waiting for %llu in-flight operation(s)",
                 (unsigned long long) in_flight);
            warned = true;
        }
    }
}
