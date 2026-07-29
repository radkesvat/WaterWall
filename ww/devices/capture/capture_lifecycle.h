#pragma once

#include "watomic.h"

typedef enum capture_lifecycle_state_e
{
    kCaptureLifecycleDown = 0,
    kCaptureLifecycleStarting,
    kCaptureLifecycleUp,
    kCaptureLifecycleStopping,
    kCaptureLifecycleFailed
} capture_lifecycle_state_t;

/*
 * The lifecycle atomic arbitrates only this enum's modification order. Thread
 * creation/join, reader gates, and platform resource publication provide the
 * ordering for companion resources, so these state operations are relaxed.
 */
static inline bool captureLifecycleIsActive(capture_lifecycle_state_t state)
{
    return state == kCaptureLifecycleStarting || state == kCaptureLifecycleUp;
}

static inline capture_lifecycle_state_t captureLifecycleLoad(const atomic_int *lifecycle)
{
    return (capture_lifecycle_state_t) atomicLoadRelaxed(lifecycle);
}

static inline bool captureLifecycleTransitionDownToStarting(atomic_int *lifecycle)
{
    w_atomic_int_value_t expected = kCaptureLifecycleDown;
    return atomicCompareExchangeExplicit(
        lifecycle, &expected, kCaptureLifecycleStarting, memory_order_relaxed, memory_order_relaxed);
}

static inline bool captureLifecycleTransitionStartingToUp(atomic_int *lifecycle)
{
    w_atomic_int_value_t expected = kCaptureLifecycleStarting;
    return atomicCompareExchangeExplicit(
        lifecycle, &expected, kCaptureLifecycleUp, memory_order_relaxed, memory_order_relaxed);
}

/*
 * Attempts to publish FAILED from an active state. On success, failed_from
 * receives the exact state replaced by the compare/exchange, allowing startup
 * rollback to stay synchronous while runtime loss requests process shutdown.
 */
static inline bool captureLifecycleTransitionToFailed(atomic_int *lifecycle, capture_lifecycle_state_t *failed_from)
{
    w_atomic_int_value_t expected = atomicLoadRelaxed(lifecycle);
    while (expected == kCaptureLifecycleStarting || expected == kCaptureLifecycleUp)
    {
        if (atomicCompareExchangeExplicit(
                lifecycle, &expected, kCaptureLifecycleFailed, memory_order_relaxed, memory_order_relaxed))
        {
            if (failed_from != NULL)
            {
                *failed_from = (capture_lifecycle_state_t) expected;
            }
            return true;
        }
    }
    return false;
}

static inline void captureLifecycleTransitionToStopping(atomic_int *lifecycle)
{
    w_atomic_int_value_t expected = atomicLoadRelaxed(lifecycle);
    while (expected != kCaptureLifecycleStopping && expected != kCaptureLifecycleDown)
    {
        if (atomicCompareExchangeExplicit(
                lifecycle, &expected, kCaptureLifecycleStopping, memory_order_relaxed, memory_order_relaxed))
        {
            return;
        }
    }
}

static inline void captureLifecycleTransitionStoppingToDown(atomic_int *lifecycle)
{
    atomicStoreRelaxed(lifecycle, kCaptureLifecycleDown);
}
