#pragma once

#include <stdbool.h>
#include <stdint.h>

enum
{
    kTunLinuxRequestedGsoMaxSegments = 2048
};

/* Best-effort RTM_NEWLINK update followed by RTM_GETLINK verification.
 * Returns true only when the active limit equals requested. On failure, errno
 * describes the failure; *active is zero unless readback succeeded. The caller
 * decides whether and how to log the nonfatal result. This is an offload work
 * hint, not a validity limit for received GSO records. */
bool tunLinuxGsoMaxSegmentsConfigure(const char *ifname, uint32_t requested, uint32_t *active);
