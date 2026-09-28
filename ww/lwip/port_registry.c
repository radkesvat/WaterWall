#include "port_registry.h"

#include "lwip/debug.h"
#include "lwip/opt.h"
#include "lwip/sys.h"

/* Counts never contain a PCB or line pointer. The existing short protection
 * primitive covers only this metadata, never a bind, output, free or callback. */
static uint32_t occupancy[2][UINT16_MAX + 1U];
static uint32_t holders[2];
static uint16_t cursor[2];
static uint16_t ipv4_id;
static uint32_t ipv6_id;

void wwLwipPortsInitialize(void)
{
    LWIP_ASSERT("no retained TCP port holders", holders[kWwLwipTcp] == 0);
    LWIP_ASSERT("no retained UDP port holders", holders[kWwLwipUdp] == 0);
    cursor[kWwLwipTcp] = (uint16_t) LWIP_RAND();
    cursor[kWwLwipUdp] = (uint16_t) LWIP_RAND();
    ipv4_id            = 0;
    ipv6_id            = 0;
}

void wwLwipPortsFinalize(void)
{
    LWIP_ASSERT("all TCP PCBs released their ports", holders[kWwLwipTcp] == 0);
    LWIP_ASSERT("all UDP PCBs released their ports", holders[kWwLwipUdp] == 0);
}

uint16_t wwLwipPortAllocate(ww_lwip_transport_t transport, uint16_t first, uint16_t last)
{
    LWIP_ASSERT("valid transport", transport == kWwLwipTcp || transport == kWwLwipUdp);
    LWIP_ASSERT("nonzero bounded port range", first != 0 && first <= last);
    const uint32_t range = (uint32_t) last - first + 1U;
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    uint16_t candidate = cursor[transport];
    if (candidate < first || candidate > last)
        candidate = (uint16_t) (first + (uint32_t) candidate % range);
    for (uint32_t i = 0; i < range; ++i)
    {
        candidate = candidate == last ? first : (uint16_t) (candidate + 1U);
        if (occupancy[transport][candidate] == 0)
        {
            occupancy[transport][candidate] = 1;
            ++holders[transport];
            cursor[transport] = candidate;
            SYS_ARCH_UNPROTECT(protection);
            return candidate;
        }
    }
    SYS_ARCH_UNPROTECT(protection);
    return 0;
}

void wwLwipPortCommit(ww_lwip_transport_t transport, uint16_t *tracked, uint16_t port, bool reserved)
{
    LWIP_ASSERT("valid transport", transport == kWwLwipTcp || transport == kWwLwipUdp);
    if (*tracked == port && ! reserved)
        return;
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    if (port != 0)
    {
        if (reserved)
            LWIP_ASSERT("automatic port was reserved", occupancy[transport][port] != 0);
        else
        {
            LWIP_ASSERT("port occupancy cannot overflow", occupancy[transport][port] != UINT32_MAX);
            ++occupancy[transport][port];
            ++holders[transport];
        }
    }
    if (*tracked != 0)
    {
        LWIP_ASSERT("port occupancy cannot underflow", occupancy[transport][*tracked] != 0);
        --occupancy[transport][*tracked];
        --holders[transport];
    }
    *tracked = port;
    SYS_ARCH_UNPROTECT(protection);
}

void wwLwipPortRelease(ww_lwip_transport_t transport, uint16_t *tracked)
{
    wwLwipPortCommit(transport, tracked, 0, false);
}

uint16_t wwLwipNextIpv4Id(void)
{
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    const uint16_t id = ipv4_id++;
    SYS_ARCH_UNPROTECT(protection);
    return id;
}

uint32_t wwLwipNextIpv6Id(void)
{
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    const uint32_t id = ++ipv6_id;
    SYS_ARCH_UNPROTECT(protection);
    return id;
}

#if defined(WW_LWIP_TEST_SEAM)
uint32_t wwLwipTestPortOccupancy(ww_lwip_transport_t transport, uint16_t port)
{
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    const uint32_t count = occupancy[transport][port];
    SYS_ARCH_UNPROTECT(protection);
    return count;
}
#endif
