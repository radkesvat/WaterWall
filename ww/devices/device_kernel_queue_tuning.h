#pragma once

#include "wconfig.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

/* Startup targets only. Native setup must preserve larger existing values,
 * tolerate refused increases, and report what the kernel actually accepted.
 * Zero overrides select automatic sizing; JSON accepts only positive overrides.
 * Receive-buffer values are SO_RCVBUF requests, not Linux's doubled readback. */
enum
{
    kDeviceKernelQueueAutomaticPacketCap = 128 * 1024,
    kDeviceKernelQueueCaptureBasePackets = 64 * 1024,
    kDeviceKernelQueueCaptureBaseBytes   = 64 * 1024 * 1024,
    kDeviceKernelQueueAutomaticByteCap   = 128 * 1024 * 1024
};

static inline uint32_t deviceKernelQueueTunTarget(uint32_t profile, uint32_t queue_count, uint32_t override_length)
{
    assert(queue_count > 0 && queue_count <= 256);
    if (override_length != 0)
        return override_length;

    const uint32_t preferred = profile >= kRamProfileL1Memory   ? 8192
                               : profile >= kRamProfileM2Memory ? 4096
                               : profile >= kRamProfileM1Memory ? 2048
                                                                : 1024;
    const uint32_t cap       = kDeviceKernelQueueAutomaticPacketCap / queue_count;
    return preferred < cap ? preferred : cap;
}

static inline uint32_t deviceKernelQueueCaptureTarget(uint32_t queue_count, uint32_t override_total, bool enabled,
                                                      uint32_t baseline_total, uint32_t preferred, uint32_t cap_total)
{
    assert(queue_count > 0 && queue_count <= 256);
    const uint32_t baseline = baseline_total / queue_count;
    if (! enabled)
        return baseline;

    uint32_t target;
    if (override_total != 0)
        target = override_total / queue_count;
    else
    {
        const uint32_t cap = cap_total / queue_count;
        target             = preferred < cap ? preferred : cap;
    }
    return target > baseline ? target : baseline;
}

static inline uint32_t deviceKernelQueueCapturePackets(uint32_t profile, uint32_t queue_count, uint32_t override_total,
                                                       bool enabled)
{
    const uint32_t preferred = profile >= kRamProfileL1Memory ? 4096 : profile >= kRamProfileM1Memory ? 2048 : 1024;
    return deviceKernelQueueCaptureTarget(queue_count,
                                          override_total,
                                          enabled,
                                          kDeviceKernelQueueCaptureBasePackets,
                                          preferred,
                                          kDeviceKernelQueueAutomaticPacketCap);
}

static inline uint32_t deviceKernelQueueCaptureReceiveBytes(uint32_t profile, uint32_t queue_count,
                                                            uint32_t override_total, bool enabled)
{
    const uint32_t preferred = (profile >= kRamProfileL1Memory   ? 4U
                                : profile >= kRamProfileM1Memory ? 2U
                                                                 : 1U) *
                               1024U * 1024U;
    return deviceKernelQueueCaptureTarget(queue_count,
                                          override_total,
                                          enabled,
                                          kDeviceKernelQueueCaptureBaseBytes,
                                          preferred,
                                          kDeviceKernelQueueAutomaticByteCap);
}
