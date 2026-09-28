#include "shared_pools.h"

#include "lwip/debug.h"
#include "lwip/opt.h"
#include "lwip/sys.h"

static uint16_t reassembly_usage[2];

static unsigned familyIndex(unsigned family)
{
    LWIP_ASSERT("IPv4 or IPv6 reassembly account", family == 4 || family == 6);
    return family == 6;
}

bool wwLwipReassemblyReserve(unsigned family, uint16_t count)
{
    const unsigned index = familyIndex(family);
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    const bool admitted = (uint32_t) reassembly_usage[index] + count <= IP_REASS_MAX_PBUFS;
    if (admitted)
    {
        reassembly_usage[index] = (uint16_t) (reassembly_usage[index] + count);
    }
    SYS_ARCH_UNPROTECT(protection);
    return admitted;
}

void wwLwipReassemblyRelease(unsigned family, uint16_t count)
{
    const unsigned index = familyIndex(family);
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    LWIP_ASSERT("balanced reassembly reservation", reassembly_usage[index] >= count);
    reassembly_usage[index] = (uint16_t) (reassembly_usage[index] - count);
    SYS_ARCH_UNPROTECT(protection);
}

uint16_t wwLwipReassemblyUsage(unsigned family)
{
    const unsigned index = familyIndex(family);
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    const uint16_t used = reassembly_usage[index];
    SYS_ARCH_UNPROTECT(protection);
    return used;
}
