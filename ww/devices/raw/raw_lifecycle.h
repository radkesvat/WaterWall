#pragma once

#include "watomic.h"

typedef enum raw_lifecycle_state_e
{
    kRawLifecycleDown = 0,
    kRawLifecycleStarting,
    kRawLifecycleUp,
    kRawLifecycleStopping,
    kRawLifecycleFailed
} raw_lifecycle_state_t;

/*
 * The lifecycle atomic arbitrates only this enum's modification order. Thread
 * creation/join and writer-generation publication provide the ordering for
 * companion resources, so these state operations are relaxed.
 */
static inline bool rawLifecycleIsActive(raw_lifecycle_state_t state)
{
    return state == kRawLifecycleStarting || state == kRawLifecycleUp;
}

static inline raw_lifecycle_state_t rawLifecycleLoad(const atomic_int *lifecycle)
{
    return (raw_lifecycle_state_t) atomicLoadRelaxed(lifecycle);
}

static inline bool rawLifecycleTransitionDownToStarting(atomic_int *lifecycle)
{
    w_atomic_int_value_t expected = kRawLifecycleDown;
    return atomicCompareExchangeExplicit(
        lifecycle, &expected, kRawLifecycleStarting, memory_order_relaxed, memory_order_relaxed);
}

static inline bool rawLifecycleTransitionStartingToUp(atomic_int *lifecycle)
{
    w_atomic_int_value_t expected = kRawLifecycleStarting;
    return atomicCompareExchangeExplicit(
        lifecycle, &expected, kRawLifecycleUp, memory_order_relaxed, memory_order_relaxed);
}

/*
 * Attempts to publish FAILED from an active state. On success, failed_from
 * receives the exact state replaced by the compare/exchange, allowing startup
 * rollback to stay synchronous while runtime loss requests process shutdown.
 */
static inline bool rawLifecycleTransitionToFailed(atomic_int *lifecycle, raw_lifecycle_state_t *failed_from)
{
    w_atomic_int_value_t expected = atomicLoadRelaxed(lifecycle);
    while (expected == kRawLifecycleStarting || expected == kRawLifecycleUp)
    {
        if (atomicCompareExchangeExplicit(
                lifecycle, &expected, kRawLifecycleFailed, memory_order_relaxed, memory_order_relaxed))
        {
            if (failed_from != NULL)
            {
                *failed_from = (raw_lifecycle_state_t) expected;
            }
            return true;
        }
    }
    return false;
}

static inline void rawLifecycleTransitionToStopping(atomic_int *lifecycle)
{
    w_atomic_int_value_t expected = atomicLoadRelaxed(lifecycle);
    while (expected != kRawLifecycleStopping && expected != kRawLifecycleDown)
    {
        if (atomicCompareExchangeExplicit(
                lifecycle, &expected, kRawLifecycleStopping, memory_order_relaxed, memory_order_relaxed))
        {
            return;
        }
    }
}

static inline void rawLifecycleTransitionStoppingToDown(atomic_int *lifecycle)
{
    atomicStoreRelaxed(lifecycle, kRawLifecycleDown);
}
