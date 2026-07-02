#include "structure.h"

#include "loggers/network_logger.h"

static bool routerHasChar(const char *s, char c)
{
    for (uint32_t i = 0; s[i] != '\0'; ++i)
    {
        if (s[i] == c)
        {
            return true;
        }
    }
    return false;
}

static bool routerParseIpEntry(const char *pattern, router_ip_range_t *out)
{
    if (routerHasChar(pattern, '/'))
    {
        int family = parseIPWithSubnetMask(pattern, &out->ip, &out->mask);
        if (family != 4 && family != 6)
        {
            return false;
        }
        out->family = (uint8_t) family;
        return true;
    }

    int type = parseIpAddress(pattern, &out->ip);
    if (type == IPADDR_TYPE_V4)
    {
        out->mask.type            = IPADDR_TYPE_V4;
        out->mask.u_addr.ip4.addr = 0xFFFFFFFFU;
        out->family               = 4;
        return true;
    }
    if (type == IPADDR_TYPE_V6)
    {
        out->mask.type = IPADDR_TYPE_V6;
        for (int i = 0; i < 4; ++i)
        {
            out->mask.u_addr.ip6.addr[i] = 0xFFFFFFFFU;
        }
        out->family = 6;
        return true;
    }

    return false;
}

bool routerIpRangesParse(const router_string_list_t *patterns, router_ip_range_t **out_ranges, uint32_t *out_count,
                         const char *json_path)
{
    *out_ranges = NULL;
    *out_count  = 0;

    if (patterns->count == 0)
    {
        return true;
    }

    router_ip_range_t *ranges = memoryAllocateZero(sizeof(*ranges) * (size_t) patterns->count);
    uint32_t           count  = 0;

    for (uint32_t i = 0; i < patterns->count; ++i)
    {
        const char *pattern = patterns->items[i];

        if (stringStartsWithIgnoreCase(pattern, "geoip:"))
        {
            continue;
        }

        if (! routerParseIpEntry(pattern, &ranges[count]))
        {
            LOGF("JSON Error: %s : \"%s\" is not a valid IP or CIDR range", json_path, pattern);
            memoryFree(ranges);
            return false;
        }
        ++count;
    }

    *out_ranges = ranges;
    *out_count  = count;
    return true;
}

bool routerIpRangesMatch(const address_context_t *ctx, const router_ip_range_t *ranges, uint32_t count)
{
    if (! addresscontextIsIpType(ctx))
    {
        return false;
    }

    const ip_addr_t *test = &ctx->ip_address;

    for (uint32_t i = 0; i < count; ++i)
    {
        const router_ip_range_t *range = &ranges[i];

        if (range->family == 4 && test->type == IPADDR_TYPE_V4)
        {
            if (checkIPRange4(test->u_addr.ip4, range->ip.u_addr.ip4, range->mask.u_addr.ip4))
            {
                return true;
            }
        }
        else if (range->family == 6 && test->type == IPADDR_TYPE_V6)
        {
            if (checkIPRange6(test->u_addr.ip6, range->ip.u_addr.ip6, range->mask.u_addr.ip6))
            {
                return true;
            }
        }
    }

    return false;
}
