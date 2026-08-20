#ifndef MUX_COMMON_MUX_LIMITS_H_
#define MUX_COMMON_MUX_LIMITS_H_

#include "wwapi.h"

typedef struct mux_detached_defaults_s
{
    uint32_t buffer_limit;
    uint32_t child_limit;
} mux_detached_defaults_t;

enum
{
    kMuxMinimumDetachedBufferLimit = 32 * 1024 * 1024,
    kMuxMaximumDetachedBufferLimit = 256 * 1024 * 1024,
    kMuxMinimumDetachedChildLimit  = 4096,
    kMuxMaximumDetachedChildLimit  = 12000,
    kMuxDetachedLimitUnlimited     = 0,
    kMuxRamProfileTierMaximum      = 5,
};

_Static_assert(kMuxMaximumDetachedBufferLimit <= INT_MAX,
               "Mux detached byte defaults must remain representable by JSON integer parsing");
_Static_assert(kMuxMaximumDetachedChildLimit <= INT_MAX,
               "Mux detached child defaults must remain representable by JSON integer parsing");

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

#endif // MUX_COMMON_MUX_LIMITS_H_
