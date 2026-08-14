#pragma once

#include "watomic.h"

typedef enum device_lifecycle_state_e
{
    kDeviceLifecycleDown = 0,
    kDeviceLifecycleStarting,
    kDeviceLifecycleUp,
    kDeviceLifecycleStopping,
    kDeviceLifecycleFailed
} device_lifecycle_state_t;

/*
 * This atomic orders only the five-state lifecycle machine. Device-specific
 * gates, thread publication/join, and resource ownership provide ordering for
 * companion fields, so every transition deliberately remains relaxed.
 */
static inline bool deviceLifecycleIsActive(device_lifecycle_state_t state)
{
    return state == kDeviceLifecycleStarting || state == kDeviceLifecycleUp;
}

static inline device_lifecycle_state_t deviceLifecycleLoad(const atomic_int *lifecycle)
{
    return (device_lifecycle_state_t) atomicLoadRelaxed(lifecycle);
}

static inline bool deviceLifecycleTransitionDownToStarting(atomic_int *lifecycle)
{
    w_atomic_int_value_t expected = kDeviceLifecycleDown;
    return atomicCompareExchangeExplicit(
        lifecycle, &expected, kDeviceLifecycleStarting, memory_order_relaxed, memory_order_relaxed);
}

static inline bool deviceLifecycleTransitionStartingToUp(atomic_int *lifecycle)
{
    w_atomic_int_value_t expected = kDeviceLifecycleStarting;
    return atomicCompareExchangeExplicit(
        lifecycle, &expected, kDeviceLifecycleUp, memory_order_relaxed, memory_order_relaxed);
}

/* Reports the exact active state replaced by the successful CAS. */
static inline bool deviceLifecycleTransitionToFailed(atomic_int *lifecycle, device_lifecycle_state_t *failed_from)
{
    w_atomic_int_value_t expected = atomicLoadRelaxed(lifecycle);
    while (expected == kDeviceLifecycleStarting || expected == kDeviceLifecycleUp)
    {
        if (atomicCompareExchangeExplicit(
                lifecycle, &expected, kDeviceLifecycleFailed, memory_order_relaxed, memory_order_relaxed))
        {
            if (failed_from != NULL)
            {
                *failed_from = (device_lifecycle_state_t) expected;
            }
            return true;
        }
    }
    return false;
}

static inline void deviceLifecycleTransitionToStopping(atomic_int *lifecycle)
{
    w_atomic_int_value_t expected = atomicLoadRelaxed(lifecycle);
    while (expected != kDeviceLifecycleStopping && expected != kDeviceLifecycleDown)
    {
        if (atomicCompareExchangeExplicit(
                lifecycle, &expected, kDeviceLifecycleStopping, memory_order_relaxed, memory_order_relaxed))
        {
            return;
        }
    }
}

static inline void deviceLifecycleTransitionStoppingToDown(atomic_int *lifecycle)
{
    atomicStoreRelaxed(lifecycle, kDeviceLifecycleDown);
}
