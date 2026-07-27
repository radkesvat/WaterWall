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

// Attempts to transition from an active state (STARTING or UP) to FAILED.
// Returns true if this thread successfully transitioned it.
static inline bool tunLifecycleTransitionToFailed(atomic_int *lifecycle)
{
    w_atomic_int_value_t expected = atomicLoadExplicit(lifecycle, memory_order_acquire);
    while (expected == kTunLifecycleStarting || expected == kTunLifecycleUp)
    {
        if (atomicCompareExchangeExplicit(
                lifecycle, &expected, kTunLifecycleFailed, memory_order_acq_rel, memory_order_acquire))
        {
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
