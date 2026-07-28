#pragma once

#include "watomic.h"

typedef enum tun_lifecycle_state_e
{
    kTunLifecycleDown = 0,
    kTunLifecycleStarting,
    kTunLifecycleUp,
    kTunLifecycleStopping,
    kTunLifecycleFailed
} tun_lifecycle_state_t;

static inline bool tunLifecycleIsActive(tun_lifecycle_state_t state)
{
    return state == kTunLifecycleStarting || state == kTunLifecycleUp;
}

static inline tun_lifecycle_state_t tunLifecycleLoad(const atomic_int *lifecycle)
{
    return (tun_lifecycle_state_t) atomicLoadExplicit(lifecycle, memory_order_acquire);
}

static inline bool tunLifecycleTransitionDownToStarting(atomic_int *lifecycle)
{
    w_atomic_int_value_t expected = kTunLifecycleDown;
    return atomicCompareExchangeExplicit(
        lifecycle, &expected, kTunLifecycleStarting, memory_order_acq_rel, memory_order_acquire);
}

static inline bool tunLifecycleTransitionStartingToUp(atomic_int *lifecycle)
{
    w_atomic_int_value_t expected = kTunLifecycleStarting;
    return atomicCompareExchangeExplicit(
        lifecycle, &expected, kTunLifecycleUp, memory_order_acq_rel, memory_order_acquire);
}

/*
 * Attempts to transition from an active state (STARTING or UP) to FAILED.
 * Returns true only for the single caller that performs the transition.
 *
 * On success, *failed_from receives the exact state the successful
 * compare/exchange replaced, so the caller can distinguish:
 *   - kTunLifecycleStarting: bring-up is still in progress and will observe the
 *     failed publication, roll back, and decide what to do on the main thread;
 *   - kTunLifecycleUp: an already published device lost a required I/O thread at
 *     runtime, which is process-fatal.
 * The source state must come from the CAS itself: a separate load followed by a
 * transition can observe STARTING and then lose to a concurrent STARTING -> UP,
 * misreporting a runtime failure as a startup failure.
 *
 * On failure, *failed_from is left unchanged and must not be used. STOPPING,
 * DOWN and an already FAILED state are never overwritten.
 *
 * @param lifecycle Device lifecycle state.
 * @param failed_from Optional out-parameter; may be NULL.
 */
static inline bool tunLifecycleTransitionToFailed(atomic_int *lifecycle, tun_lifecycle_state_t *failed_from)
{
    w_atomic_int_value_t expected = atomicLoadExplicit(lifecycle, memory_order_acquire);
    while (expected == kTunLifecycleStarting || expected == kTunLifecycleUp)
    {
        if (atomicCompareExchangeExplicit(
                lifecycle, &expected, kTunLifecycleFailed, memory_order_acq_rel, memory_order_acquire))
        {
            if (failed_from != NULL)
            {
                *failed_from = (tun_lifecycle_state_t) expected;
            }
            return true;
        }
    }
    return false;
}

// Moves any active or failed state to STOPPING.
static inline void tunLifecycleTransitionToStopping(atomic_int *lifecycle)
{
    w_atomic_int_value_t expected = atomicLoadExplicit(lifecycle, memory_order_acquire);
    while (expected != kTunLifecycleStopping && expected != kTunLifecycleDown)
    {
        if (atomicCompareExchangeExplicit(
                lifecycle, &expected, kTunLifecycleStopping, memory_order_acq_rel, memory_order_acquire))
        {
            return;
        }
    }
}

// Final publication back to DOWN.
static inline void tunLifecycleTransitionStoppingToDown(atomic_int *lifecycle)
{
    atomicStoreExplicit(lifecycle, kTunLifecycleDown, memory_order_release);
}
