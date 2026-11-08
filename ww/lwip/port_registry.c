#include "port_registry.h"

#include "lwip/debug.h"
#include "lwip/opt.h"
#include "lwip/sys.h"

/* Counts never contain a PCB or line pointer. The existing short protection
 * primitive covers only this metadata, never a bind, output, free or callback. */
static uint64_t              occupancy[2][UINT16_MAX + 1U];
static ww_lwip_port_scope_t *connected[2][UINT16_MAX + 1U];
static uint64_t              holders[2];
static uint64_t              scoped_holders[2];
static uint64_t              peak[2];
static uint64_t              refused[2];
static uint16_t              cursor[2];
static uint16_t              ipv4_id;
static uint32_t              ipv6_id;

void wwLwipPortsInitialize(void)
{
    LWIP_ASSERT("no retained TCP port holders", holders[kWwLwipTcp] == 0);
    LWIP_ASSERT("no retained UDP port holders", holders[kWwLwipUdp] == 0);
    cursor[kWwLwipTcp] = (uint16_t) LWIP_RAND();
    cursor[kWwLwipUdp] = (uint16_t) LWIP_RAND();
    ipv4_id            = 0;
    ipv6_id            = 0;
    for (unsigned transport = 0; transport < 2; ++transport)
    {
        peak[transport]    = 0;
        refused[transport] = 0;
    }
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
        if (occupancy[transport][candidate] == 0 && connected[transport][candidate] == NULL)
        {
            occupancy[transport][candidate] = 1;
            ++holders[transport];
            if (holders[transport] > peak[transport])
                peak[transport] = holders[transport];
            cursor[transport] = candidate;
            SYS_ARCH_UNPROTECT(protection);
            return candidate;
        }
    }
    ++refused[transport];
    SYS_ARCH_UNPROTECT(protection);
    return 0;
}

static void portCommitLocked(ww_lwip_transport_t transport, uint16_t *tracked, uint16_t port, bool reserved)
{
    if (*tracked == port && ! reserved)
        return;
    if (port != 0)
    {
        if (reserved)
            LWIP_ASSERT("automatic port was reserved", occupancy[transport][port] != 0);
        else
        {
            LWIP_ASSERT("port occupancy cannot overflow", occupancy[transport][port] != UINT64_MAX);
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
    if (holders[transport] > peak[transport])
        peak[transport] = holders[transport];
    *tracked = port;
}

void wwLwipPortCommit(ww_lwip_transport_t transport, uint16_t *tracked, uint16_t port, bool reserved)
{
    LWIP_ASSERT("valid transport", transport == kWwLwipTcp || transport == kWwLwipUdp);
    if (*tracked == port && ! reserved)
        return;
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    portCommitLocked(transport, tracked, port, reserved);
    SYS_ARCH_UNPROTECT(protection);
}

void wwLwipPortRelease(ww_lwip_transport_t transport, uint16_t *tracked)
{
    wwLwipPortCommit(transport, tracked, 0, false);
}

bool wwLwipPortScopeMatches(const ww_lwip_port_scope_t *scope, const ip_addr_t *local, const ip_addr_t *remote,
                            uint16_t remote_port)
{
    return scope->remote_port == remote_port && ip_addr_cmp(&scope->local, local) &&
           ip_addr_cmp(&scope->remote, remote);
}

uint16_t wwLwipPortScopeAllocate(ww_lwip_transport_t transport, ww_lwip_port_scope_t *scope, const ip_addr_t *local,
                                 const ip_addr_t *remote, uint16_t remote_port, uint16_t first, uint16_t last)
{
    LWIP_ASSERT("valid transport", transport == kWwLwipTcp || transport == kWwLwipUdp);
    LWIP_ASSERT("empty stable scope", scope != NULL && scope->port == 0);
    LWIP_ASSERT("concrete endpoints",
                local != NULL && remote != NULL && ! ip_addr_isany(local) && ! ip_addr_isany(remote) &&
                    IP_GET_TYPE(local) != IPADDR_TYPE_ANY && IP_GET_TYPE(local) == IP_GET_TYPE(remote) &&
                    remote_port != 0);
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
        if (occupancy[transport][candidate] != 0)
            continue;
        ww_lwip_port_scope_t *current = connected[transport][candidate];
        while (current != NULL && ! wwLwipPortScopeMatches(current, local, remote, remote_port))
            current = current->next;
        if (current != NULL)
            continue;
        scope->local       = *local;
        scope->remote      = *remote;
        scope->port        = candidate;
        scope->remote_port = remote_port;
        scope->previous    = NULL;
        scope->next        = connected[transport][candidate];
        if (scope->next != NULL)
            scope->next->previous = scope;
        connected[transport][candidate] = scope;
        ++holders[transport];
        ++scoped_holders[transport];
        if (holders[transport] > peak[transport])
            peak[transport] = holders[transport];
        cursor[transport] = candidate;
        SYS_ARCH_UNPROTECT(protection);
        return candidate;
    }
    ++refused[transport];
    SYS_ARCH_UNPROTECT(protection);
    return 0;
}

void wwLwipPortScopeRelease(ww_lwip_transport_t transport, ww_lwip_port_scope_t *scope)
{
    LWIP_ASSERT("valid transport", transport == kWwLwipTcp || transport == kWwLwipUdp);
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    if (scope->port != 0)
    {
        if (scope->previous != NULL)
            scope->previous->next = scope->next;
        else
        {
            LWIP_ASSERT("registered connected scope", connected[transport][scope->port] == scope);
            connected[transport][scope->port] = scope->next;
        }
        if (scope->next != NULL)
            scope->next->previous = scope->previous;
        LWIP_ASSERT("port holders cannot underflow", holders[transport] != 0);
        --holders[transport];
        --scoped_holders[transport];
        scope->port     = 0;
        scope->next     = NULL;
        scope->previous = NULL;
    }
    SYS_ARCH_UNPROTECT(protection);
}

static bool scopeConflictsLocked(ww_lwip_transport_t transport, const ip_addr_t *local, uint16_t port)
{
    for (const ww_lwip_port_scope_t *scope = connected[transport][port]; scope != NULL; scope = scope->next)
    {
        if (IP_GET_TYPE(local) == IPADDR_TYPE_ANY || (IP_GET_TYPE(local) == IP_GET_TYPE(&scope->local) &&
                                                      (ip_addr_isany(local) || ip_addr_cmp(local, &scope->local))))
        {
            return true;
        }
    }
    return false;
}

bool wwLwipPortTryCommitBound(ww_lwip_transport_t transport, uint16_t *tracked, uint16_t port, const ip_addr_t *local)
{
    LWIP_ASSERT("valid transport", transport == kWwLwipTcp || transport == kWwLwipUdp);
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    const bool conflict = scopeConflictsLocked(transport, local, port);
    if (conflict)
        ++refused[transport];
    else
        portCommitLocked(transport, tracked, port, false);
    SYS_ARCH_UNPROTECT(protection);
    return ! conflict;
}

void wwLwipPortGetStats(ww_lwip_transport_t transport, ww_lwip_port_stats_t *stats)
{
    LWIP_ASSERT("valid transport", transport == kWwLwipTcp || transport == kWwLwipUdp);
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    *stats = (ww_lwip_port_stats_t) {.active   = holders[transport],
                                     .peak     = peak[transport],
                                     .refused  = refused[transport],
                                     .scoped   = scoped_holders[transport],
                                     .unscoped = holders[transport] - scoped_holders[transport]};
    SYS_ARCH_UNPROTECT(protection);
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
uint64_t wwLwipTestPortOccupancy(ww_lwip_transport_t transport, uint16_t port)
{
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    uint64_t count = occupancy[transport][port];
    for (const ww_lwip_port_scope_t *scope = connected[transport][port]; scope != NULL; scope = scope->next)
        ++count;
    SYS_ARCH_UNPROTECT(protection);
    return count;
}
#endif
