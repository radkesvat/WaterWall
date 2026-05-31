#include "structure.h"

typedef enum sniffrouter_host_parse_e
{
    kSniffHostNeedMore = 0,
    kSniffHostMissing  = 1,
    kSniffHostFound    = 2
} sniffrouter_host_parse_t;

static uint8_t asciiLower(uint8_t c)
{
    if (c >= 'A' && c <= 'Z')
    {
        return (uint8_t) (c | 0x20U);
    }
    return c;
}

static bool headerNameEquals(const uint8_t *p, uint32_t n, const char *name)
{
    for (uint32_t i = 0; i < n; ++i)
    {
        if (name[i] == '\0' || asciiLower(p[i]) != (uint8_t) name[i])
        {
            return false;
        }
    }
    return name[n] == '\0';
}

static int classifyHttpMethod(const uint8_t *p, uint32_t n)
{
    static const char *const methods[] = {"GET ",     "POST ",  "PUT ",     "HEAD ", "DELETE ",
                                           "OPTIONS ", "PATCH ", "TRACE ",   "CONNECT ",
                                           "PRI ", /* HTTP/2 connection preface: "PRI * HTTP/2.0" */
                                           NULL};

    bool any_prefix = false;

    for (int i = 0; methods[i] != NULL; ++i)
    {
        const char *m    = methods[i];
        uint32_t    mlen = (uint32_t) stringLength(m);
        uint32_t    cmp  = n < mlen ? n : mlen;

        if (memoryCompare(p, m, cmp) == 0)
        {
            if (n >= mlen)
            {
                return 1;
            }
            any_prefix = true;
        }
    }

    return any_prefix ? -1 : 0;
}

static bool findLineFeed(const uint8_t *p, uint32_t start, uint32_t end, uint32_t *lf)
{
    for (uint32_t i = start; i < end; ++i)
    {
        if (p[i] == '\n')
        {
            *lf = i;
            return true;
        }
    }
    return false;
}

static bool findHeaderEnd(const uint8_t *p, uint32_t n, uint32_t *header_end)
{
    for (uint32_t i = 0; i + 3U < n; ++i)
    {
        if (p[i] == '\r' && p[i + 1U] == '\n' && p[i + 2U] == '\r' && p[i + 3U] == '\n')
        {
            *header_end = i;
            return true;
        }
    }

    for (uint32_t i = 0; i + 1U < n; ++i)
    {
        if (p[i] == '\n' && p[i + 1U] == '\n')
        {
            *header_end = i;
            return true;
        }
    }

    return false;
}

static void stripHostPortAndDot(const uint8_t **host, uint32_t *host_len)
{
    while (*host_len > 0 && ((*host)[*host_len - 1U] == ' ' || (*host)[*host_len - 1U] == '\t' ||
                             (*host)[*host_len - 1U] == '\r'))
    {
        *host_len -= 1U;
    }

    if (*host_len > 0 && (*host)[0] == '[')
    {
        return;
    }

    int  colon_index = -1;
    bool multiple_colons = false;

    for (uint32_t i = 0; i < *host_len; ++i)
    {
        if ((*host)[i] == ':')
        {
            if (colon_index >= 0)
            {
                multiple_colons = true;
                break;
            }
            colon_index = (int) i;
        }
    }

    if (colon_index > 0 && ! multiple_colons && (uint32_t) colon_index + 1U < *host_len)
    {
        bool port_is_numeric = true;
        for (uint32_t i = (uint32_t) colon_index + 1U; i < *host_len; ++i)
        {
            if ((*host)[i] < '0' || (*host)[i] > '9')
            {
                port_is_numeric = false;
                break;
            }
        }

        if (port_is_numeric)
        {
            *host_len = (uint32_t) colon_index;
        }
    }

    while (*host_len > 0 && (*host)[*host_len - 1U] == '.')
    {
        *host_len -= 1U;
    }
}

static sniffrouter_host_parse_t findHttpHost(const uint8_t *p, uint32_t n, const uint8_t **host, uint32_t *host_len)
{
    uint32_t header_end = 0;
    if (! findHeaderEnd(p, n, &header_end))
    {
        return n < (uint32_t) kSniffMaxHeaderBytes ? kSniffHostNeedMore : kSniffHostMissing;
    }

    uint32_t request_line_end = 0;
    if (! findLineFeed(p, 0, header_end, &request_line_end))
    {
        return kSniffHostMissing;
    }

    uint32_t line_start = request_line_end + 1U;
    while (line_start < header_end)
    {
        uint32_t line_end = header_end;
        discard findLineFeed(p, line_start, header_end, &line_end);

        uint32_t content_end = line_end;
        if (content_end > line_start && p[content_end - 1U] == '\r')
        {
            content_end -= 1U;
        }

        uint32_t colon = line_start;
        while (colon < content_end && p[colon] != ':')
        {
            ++colon;
        }

        uint32_t name_end = colon;
        while (name_end > line_start && (p[name_end - 1U] == ' ' || p[name_end - 1U] == '\t'))
        {
            name_end -= 1U;
        }

        if (colon < content_end && headerNameEquals(p + line_start, name_end - line_start, "host"))
        {
            uint32_t value_start = colon + 1U;
            while (value_start < content_end && (p[value_start] == ' ' || p[value_start] == '\t'))
            {
                ++value_start;
            }

            const uint8_t *value     = p + value_start;
            uint32_t       value_len = content_end - value_start;
            stripHostPortAndDot(&value, &value_len);

            if (value_len == 0)
            {
                return kSniffHostMissing;
            }

            *host     = value;
            *host_len = value_len;
            return kSniffHostFound;
        }

        line_start = line_end + 1U;
    }

    return kSniffHostMissing;
}

static tunnel_t *findMatchingRoute(sniffrouter_tstate_t *ts, const uint8_t *host, uint32_t host_len)
{
    for (uint32_t ri = 0; ri < ts->routes_count; ++ri)
    {
        sniffrouter_route_t *route = &ts->routes[ri];
        for (uint32_t di = 0; di < route->domains_count; ++di)
        {
            if (sniffrouterDomainMatches(route->domains[di], host, host_len))
            {
                return route->tunnel;
            }
        }
    }

    return NULL;
}

sniffrouter_match_t sniffrouterClassify(sniffrouter_tstate_t *ts, const uint8_t *p, uint32_t n)
{
    sniffrouter_match_t match = {
        .result = kSniffClassifyDefault,
        .target = NULL,
    };

    int http_method = classifyHttpMethod(p, n);
    if (http_method < 0 && n < (uint32_t) kSniffMethodDecideBytes)
    {
        match.result = kSniffClassifyNeedMore;
        return match;
    }

    if (http_method <= 0)
    {
        return match;
    }

    const uint8_t *host     = NULL;
    uint32_t       host_len = 0;

    switch (findHttpHost(p, n, &host, &host_len))
    {
    case kSniffHostNeedMore:
        match.result = kSniffClassifyNeedMore;
        return match;
    case kSniffHostFound:
        match.target = findMatchingRoute(ts, host, host_len);
        if (match.target != NULL)
        {
            match.result = kSniffClassifyTarget;
        }
        return match;
    case kSniffHostMissing:
    default:
        return match;
    }
}
