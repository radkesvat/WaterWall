#include "dns_strategy.h"

bool dnsstrategyFamilyAllowedByStrategy(int family, enum domain_strategy strategy)
{
    switch (strategy)
    {
    case kDsOnlyIpV4:
        return family == AF_INET;
    case kDsOnlyIpV6:
        return family == AF_INET6;
    default:
        return family == AF_INET || family == AF_INET6;
    }
}

bool dnsstrategyFamilyPreferredByStrategy(int family, enum domain_strategy strategy)
{
    switch (strategy)
    {
    case kDsPreferIpV4:
    case kDsOnlyIpV4:
        return family == AF_INET;
    case kDsPreferIpV6:
    case kDsOnlyIpV6:
        return family == AF_INET6;
    default:
        return true;
    }
}

const dns_resolved_addr_t *dnsstrategySelectResolvedAddress(const dns_resolved_addr_t *addrs, size_t naddrs,
                                                            enum domain_strategy strategy)
{
    if (UNLIKELY(addrs == NULL))
    {
        return NULL;
    }

    const dns_resolved_addr_t *fallback = NULL;

    for (size_t i = 0; i < naddrs; ++i)
    {
        if (UNLIKELY(! dnsstrategyFamilyAllowedByStrategy(addrs[i].family, strategy)))
        {
            continue;
        }

        if (fallback == NULL)
        {
            fallback = &addrs[i];
        }

        if (dnsstrategyFamilyPreferredByStrategy(addrs[i].family, strategy))
        {
            return &addrs[i];
        }
    }

    return fallback;
}

bool dnsstrategyApplyResolvedAddress(address_context_t *ctx, const dns_resolved_addr_t *resolved)
{
    if (UNLIKELY(ctx == NULL || resolved == NULL || (resolved->family != AF_INET && resolved->family != AF_INET6) ||
                 (uintmax_t) resolved->addrlen > (uintmax_t) sizeof(sockaddr_u)))
    {
        return false;
    }

    sockaddr_u resolved_addr;
    memoryZero(&resolved_addr, sizeof(resolved_addr));
    memoryCopy(&resolved_addr, &resolved->addr, (size_t) resolved->addrlen);

    if (UNLIKELY(! sockaddrToIpAddr(&resolved_addr, &ctx->ip_address)))
    {
        return false;
    }

    ctx->type_ip         = kCCTypeIp;
    ctx->domain_resolved = true;
    return true;
}
