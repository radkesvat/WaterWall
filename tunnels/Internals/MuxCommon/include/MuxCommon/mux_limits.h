#ifndef MUX_COMMON_MUX_LIMITS_H_
#define MUX_COMMON_MUX_LIMITS_H_

#include "wwapi.h"

typedef struct mux_detached_defaults_s
{
    uint32_t buffer_limit;
    uint32_t child_limit;
} mux_detached_defaults_t;

typedef struct mux_admission_defaults_s
{
    uint32_t memory_reserve;
    uint32_t fallback_live_children;
} mux_admission_defaults_t;

/**
 * Return the MUX hard-memory-budget charge for one retained queue entry.
 *
 * Logical payload length remains the correct measurement for queue contents,
 * protocol flow control, and most buffer users. MUX uses this stricter charge
 * only because its child, parent, and detached hard limits must bound the
 * allocations retained while the shared parent transport remains readable.
 * The capacity includes left padding; the header and aligned-allocation
 * over-allocation are also bytes held by the live sbuf allocation.
 */
static inline size_t muxQueuedSbufCharge(const sbuf_t *buf)
{
    assert(! buf->is_temporary);
    return sizeof(sbuf_t) + (size_t) sbufGetTotalCapacity(buf) + (size_t) kSbufAllocationAlignment;
}

/**
 * Test whether adding a candidate charge would reach a nonzero hard limit.
 *
 * The subtraction form deliberately avoids evaluating current + candidate, so
 * even an unrepresentable projected sum is rejected without wrapping.
 */
static inline bool muxQueueChargeWouldReachLimit(size_t current, size_t candidate, size_t limit)
{
    assert(limit != 0);
    return current >= limit || candidate >= limit - current;
}

enum
{
    kMuxMinimumDetachedBufferLimit = 32 * 1024 * 1024,
    kMuxMaximumDetachedBufferLimit = 256 * 1024 * 1024,
    kMuxMinimumDetachedChildLimit  = 4096,
    kMuxMaximumDetachedChildLimit  = 12000,
    kMuxDetachedLimitUnlimited     = 0,
    kMuxRamProfileTierMaximum      = 5,

    kMuxDefaultMaxChildrenPerParent       = 10000,
    kMuxDefaultMaxLiveChildren            = 256U * 1024U,
    kMuxDefaultInitialChildIdleTimeoutMs  = 10U * 1000U,
    kMuxDefaultActiveChildIdleTimeoutMs   = 300U * 1000U,
    kMuxDefaultMemoryHighWatermarkPercent = 85,
    kMuxDefaultMemoryLowWatermarkPercent  = 75,

    kMuxMinimumAdmissionMemoryReserve    = 32U * 1024U * 1024U,
    kMuxMaximumAdmissionMemoryReserve    = 256U * 1024U * 1024U,
    kMuxMinimumAdmissionFallbackChildren = 4096,
    kMuxMaximumAdmissionFallbackChildren = 12000,
};

_Static_assert(kMuxMaximumDetachedBufferLimit <= INT_MAX,
               "Mux detached byte defaults must remain representable by JSON integer parsing");
_Static_assert(kMuxMaximumDetachedChildLimit <= INT_MAX,
               "Mux detached child defaults must remain representable by JSON integer parsing");
_Static_assert(kMuxDefaultMaxChildrenPerParent <= INT_MAX,
               "Mux per-parent child default must remain representable by JSON integer parsing");
_Static_assert(kMuxDefaultMaxLiveChildren <= INT_MAX,
               "Mux aggregate child default must remain representable by JSON integer parsing");
_Static_assert(kMuxDefaultInitialChildIdleTimeoutMs <= INT_MAX,
               "Mux initial child idle default must remain representable by JSON integer parsing");
_Static_assert(kMuxDefaultActiveChildIdleTimeoutMs <= INT_MAX,
               "Mux active child idle default must remain representable by JSON integer parsing");
_Static_assert(kMuxMaximumAdmissionMemoryReserve <= INT_MAX,
               "Mux admission reserve defaults must remain representable by JSON integer parsing");
_Static_assert(kMuxMaximumAdmissionFallbackChildren <= INT_MAX,
               "Mux admission fallback defaults must remain representable by JSON integer parsing");

static inline uint32_t muxRamProfileTier(uint32_t ram_profile)
{
    switch (ram_profile)
    {
    case kRamProfileS1Memory:
        return 0;
    case kRamProfileS2Memory:
        return 1;
    case kRamProfileM1Memory:
        return 2;
    case kRamProfileM2Memory:
        return 3;
    case kRamProfileL1Memory:
        return 4;
    case kRamProfileL2Memory:
        return 5;
    default:
        assert(false);
        return 0;
    }
}

/**
 * Select the default detached-drain budgets for one Mux worker.
 *
 * RAM-profile enum values are pool-sizing weights rather than evenly spaced
 * profile ranks. Interpolate over the six ordered tiers so every step makes
 * meaningful progress from the S1 minimum to the L2 maximum. The byte budget
 * is rounded to the nearest whole MiB; explicit node settings bypass these
 * defaults entirely.
 */
static inline mux_detached_defaults_t muxGetDefaultDetachedLimits(uint32_t ram_profile)
{
    const uint32_t tier = muxRamProfileTier(ram_profile);

    enum
    {
        kMinimumMiB = kMuxMinimumDetachedBufferLimit / (1024 * 1024),
        kMaximumMiB = kMuxMaximumDetachedBufferLimit / (1024 * 1024),
    };

    const uint32_t buffer_mib =
        kMinimumMiB +
        (((kMaximumMiB - kMinimumMiB) * tier) + (kMuxRamProfileTierMaximum / 2U)) / kMuxRamProfileTierMaximum;
    const uint32_t child_limit =
        kMuxMinimumDetachedChildLimit +
        (((kMuxMaximumDetachedChildLimit - kMuxMinimumDetachedChildLimit) * tier) + (kMuxRamProfileTierMaximum / 2U)) /
            kMuxRamProfileTierMaximum;

    return (mux_detached_defaults_t) {
        .buffer_limit = buffer_mib * 1024U * 1024U,
        .child_limit  = child_limit,
    };
}

/**
 * Select the default MuxServer admission reserve and conservative fallback
 * child ceiling for the configured RAM profile.
 *
 * Admission defaults intentionally have their own semantic helper. Their
 * initial six-tier interpolation matches the detached-drain profile, but the
 * two policies may evolve independently without silently changing callers.
 */
static inline mux_admission_defaults_t muxGetDefaultAdmissionLimits(uint32_t ram_profile)
{
    const uint32_t tier = muxRamProfileTier(ram_profile);

    enum
    {
        kMinimumMiB = kMuxMinimumAdmissionMemoryReserve / (1024U * 1024U),
        kMaximumMiB = kMuxMaximumAdmissionMemoryReserve / (1024U * 1024U),
    };

    const uint32_t reserve_mib =
        kMinimumMiB +
        (((kMaximumMiB - kMinimumMiB) * tier) + (kMuxRamProfileTierMaximum / 2U)) / kMuxRamProfileTierMaximum;
    const uint32_t fallback_children =
        kMuxMinimumAdmissionFallbackChildren +
        (((kMuxMaximumAdmissionFallbackChildren - kMuxMinimumAdmissionFallbackChildren) * tier) +
         (kMuxRamProfileTierMaximum / 2U)) /
            kMuxRamProfileTierMaximum;

    return (mux_admission_defaults_t) {
        .memory_reserve         = reserve_mib * 1024U * 1024U,
        .fallback_live_children = fallback_children,
    };
}

#endif // MUX_COMMON_MUX_LIMITS_H_
