#include "structure.h"

static uint8_t asciiLower(uint8_t c)
{
    if (c >= 'A' && c <= 'Z')
    {
        return (uint8_t) (c | 0x20U);
    }
    return c;
}

static bool hostEndsWith(const uint8_t *host, uint32_t host_len, const char *suffix, uint32_t suffix_len)
{
    if (host_len < suffix_len)
    {
        return false;
    }

    uint32_t offset = host_len - suffix_len;
    for (uint32_t i = 0; i < suffix_len; ++i)
    {
        if (asciiLower(host[offset + i]) != (uint8_t) suffix[i])
        {
            return false;
        }
    }

    return true;
}

static bool hostEquals(const uint8_t *host, uint32_t host_len, const char *domain, uint32_t domain_len)
{
    if (host_len != domain_len)
    {
        return false;
    }

    for (uint32_t i = 0; i < domain_len; ++i)
    {
        if (asciiLower(host[i]) != (uint8_t) domain[i])
        {
            return false;
        }
    }

    return true;
}

bool sniffrouterDomainMatches(const char *pattern, const uint8_t *host, uint32_t host_len)
{
    uint32_t pattern_len = (uint32_t) stringLength(pattern);

    if (pattern_len == 1U && pattern[0] == '*')
    {
        return true;
    }

    if (pattern_len > 2U && pattern[0] == '*' && pattern[1] == '.')
    {
        const char *suffix     = pattern + 1;
        uint32_t    suffix_len = pattern_len - 1U;

        return host_len > suffix_len && hostEndsWith(host, host_len, suffix, suffix_len);
    }

    return hostEquals(host, host_len, pattern, pattern_len);
}

void sniffrouterRouteTableDestroy(sniffrouter_tstate_t *ts)
{
    if (ts->routes == NULL)
    {
        return;
    }

    for (uint32_t ri = 0; ri < ts->routes_count; ++ri)
    {
        sniffrouter_route_t *route = &ts->routes[ri];
        if (route->domains != NULL)
        {
            for (uint32_t di = 0; di < route->domains_count; ++di)
            {
                memoryFree(route->domains[di]);
            }
            memoryFree(route->domains);
        }
    }

    memoryFree(ts->routes);
    ts->routes       = NULL;
    ts->routes_count = 0;
}
