#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef enum ww_lwip_transport_e
{
    kWwLwipTcp,
    kWwLwipUdp
} ww_lwip_transport_t;

void wwLwipPortsInitialize(void);
void wwLwipPortsFinalize(void);
/* Returns a reserved port, or zero after one bounded pass through the range. */
uint16_t wwLwipPortAllocate(ww_lwip_transport_t transport, uint16_t first, uint16_t last);
/* Commit a permanent assignment. Explicit binds retain their engine-local semantics.
 * reserved transfers the hold returned by Allocate; old occupancy is released atomically. */
void wwLwipPortCommit(ww_lwip_transport_t transport, uint16_t *tracked, uint16_t port, bool reserved);
void wwLwipPortRelease(ww_lwip_transport_t transport, uint16_t *tracked);

uint16_t wwLwipNextIpv4Id(void);
uint32_t wwLwipNextIpv6Id(void);

#if defined(WW_LWIP_TEST_SEAM)
uint32_t wwLwipTestPortOccupancy(ww_lwip_transport_t transport, uint16_t port);
#endif
