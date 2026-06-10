#include "structure.h"

typedef enum sniffrouter_host_parse_e
{
    kSniffHostNeedMore = 0,
    kSniffHostMissing  = 1,
    kSniffHostFound    = 2
} sniffrouter_host_parse_t;



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

static sniffrouter_host_parse_t classifyHttpHost(const uint8_t *p, uint32_t n, const uint8_t **host,
                                                 uint32_t *host_len)
{
    int http_method = classifyHttpMethod(p, n);
    if (http_method < 0 && n < (uint32_t) kSniffMethodDecideBytes)
    {
        return kSniffHostNeedMore;
    }

    if (http_method <= 0)
    {
        return kSniffHostMissing;
    }

    return findHttpHost(p, n, host, host_len);
}

static bool remainingAtLeast(const uint8_t *cursor, const uint8_t *end, size_t needed)
{
    return cursor <= end && (size_t) (end - cursor) >= needed;
}

static sniffrouter_host_parse_t findTlsClientHelloSni(const uint8_t *p, uint32_t n, const uint8_t **host,
                                                      uint32_t *host_len)
{
    if (n == 0)
    {
        return kSniffHostNeedMore;
    }

    if (p[0] != 0x16)
    {
        return kSniffHostMissing;
    }

    if (n < 5U)
    {
        return kSniffHostNeedMore;
    }

    if (p[1] != 0x03 || p[2] > 0x03)
    {
        return kSniffHostMissing;
    }

    uint16_t tls_record_len = GET_BE16(p + 3);
    if (tls_record_len < 4U)
    {
        return kSniffHostMissing;
    }

    uint32_t tls_record_total_len = (uint32_t) tls_record_len + 5U;
    if (n < tls_record_total_len)
    {
        return n < (uint32_t) kSniffMaxHeaderBytes ? kSniffHostNeedMore : kSniffHostMissing;
    }

    if (p[5] != 0x01)
    {
        return kSniffHostMissing;
    }

    uint32_t client_hello_len = GET_BE24(p + 6);
    if (client_hello_len < 34U || client_hello_len + 4U > (uint32_t) tls_record_len)
    {
        return kSniffHostMissing;
    }

    const uint8_t *client_hello = p + 9;
    const uint8_t *cursor       = client_hello + 34;
    const uint8_t *hello_end    = client_hello + client_hello_len;

    if (! remainingAtLeast(cursor, hello_end, 1U))
    {
        return kSniffHostMissing;
    }

    uint8_t session_id_len = cursor[0];
    cursor += 1;
    if (! remainingAtLeast(cursor, hello_end, (size_t) session_id_len + 2U))
    {
        return kSniffHostMissing;
    }
    cursor += session_id_len;

    uint16_t cipher_suites_len = GET_BE16(cursor);
    cursor += 2;
    if (! remainingAtLeast(cursor, hello_end, (size_t) cipher_suites_len + 1U))
    {
        return kSniffHostMissing;
    }
    cursor += cipher_suites_len;

    uint8_t compression_methods_len = cursor[0];
    cursor += 1;
    if (! remainingAtLeast(cursor, hello_end, (size_t) compression_methods_len + 2U))
    {
        return kSniffHostMissing;
    }
    cursor += compression_methods_len;

    uint16_t extensions_len = GET_BE16(cursor);
    cursor += 2;
    if (! remainingAtLeast(cursor, hello_end, extensions_len))
    {
        return kSniffHostMissing;
    }

    const uint8_t *extensions_end = cursor + extensions_len;
    while (remainingAtLeast(cursor, extensions_end, 4U))
    {
        uint16_t       extension_type = GET_BE16(cursor);
        uint16_t       extension_len  = GET_BE16(cursor + 2);
        const uint8_t *extension_data = cursor + 4;
        if (! remainingAtLeast(extension_data, extensions_end, extension_len))
        {
            return kSniffHostMissing;
        }
        const uint8_t *next_extension = extension_data + extension_len;

        if (extension_type == 0x0000)
        {
            if (extension_len < 2U)
            {
                return kSniffHostMissing;
            }

            uint16_t       server_name_list_len = GET_BE16(extension_data);
            const uint8_t *server_name_cursor   = extension_data + 2;

            if (server_name_list_len > extension_len - 2U)
            {
                return kSniffHostMissing;
            }
            const uint8_t *server_name_list_end = server_name_cursor + server_name_list_len;

            while (remainingAtLeast(server_name_cursor, server_name_list_end, 3U))
            {
                uint8_t        name_type = server_name_cursor[0];
                uint16_t       name_len  = GET_BE16(server_name_cursor + 1);
                const uint8_t *name_data = server_name_cursor + 3;
                if (! remainingAtLeast(name_data, server_name_list_end, name_len))
                {
                    return kSniffHostMissing;
                }
                const uint8_t *next_name = name_data + name_len;

                if (name_type == 0x00)
                {
                    const uint8_t *value     = name_data;
                    uint32_t       value_len = name_len;
                    stripHostPortAndDot(&value, &value_len);

                    if (value_len == 0)
                    {
                        return kSniffHostMissing;
                    }

                    *host     = value;
                    *host_len = value_len;
                    return kSniffHostFound;
                }

                server_name_cursor = next_name;
            }

            return kSniffHostMissing;
        }

        cursor = next_extension;
    }

    return kSniffHostMissing;
}

// Detects the ReverseClient/ReverseServer reverse-link handshake using
// ReverseClient's exported byte sequence. SniffRouter merely peeks; the buffered
// bytes are replayed intact to the chosen route, and ReverseServer re-validates
// and strips the handshake itself.
static sniffrouter_host_parse_t findReverseHandshake(const uint8_t *p, uint32_t n)
{
    uint32_t limit = n < reverseclientHandshakeLength ? n : reverseclientHandshakeLength;

    for (uint32_t i = 0; i < limit; ++i)
    {
        if (p[i] != reverseclientHandshakeBytes[i])
        {
            return kSniffHostMissing;
        }
    }

    if (n < reverseclientHandshakeLength)
    {
        return kSniffHostNeedMore;
    }

    return kSniffHostFound;
}

static bool anyRouteHasDetection(sniffrouter_tstate_t *ts, uint8_t detection)
{
    for (uint32_t ri = 0; ri < ts->routes_count; ++ri)
    {
        if ((ts->routes[ri].detection & detection) != 0)
        {
            return true;
        }
    }

    return false;
}

static bool routeMatchesHost(sniffrouter_route_t *route, const uint8_t *host, uint32_t host_len)
{
    for (uint32_t di = 0; di < route->domains_count; ++di)
    {
        if (sniffrouterDomainMatches(route->domains[di], host, host_len))
        {
            return true;
        }
    }

    return false;
}

static tunnel_t *findMatchingRoute(sniffrouter_tstate_t *ts, const uint8_t *http_host, uint32_t http_host_len,
                                   bool http_found, const uint8_t *tls_sni, uint32_t tls_sni_len, bool tls_found,
                                   bool reverse_found)
{
    for (uint32_t ri = 0; ri < ts->routes_count; ++ri)
    {
        sniffrouter_route_t *route = &ts->routes[ri];

        if (http_found && (route->detection & kSniffDetectionHttp) != 0 &&
            routeMatchesHost(route, http_host, http_host_len))
        {
            return route->tunnel;
        }

        if (tls_found && (route->detection & kSniffDetectionTlsClientHello) != 0 &&
            routeMatchesHost(route, tls_sni, tls_sni_len))
        {
            return route->tunnel;
        }

        // Reverse detection is a binary-signature match and intentionally ignores
        // "domains": the reverse link carries no Host/SNI of its own.
        if (reverse_found && (route->detection & kSniffDetectionReverse) != 0)
        {
            return route->tunnel;
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

    if (ts->routes_count == 0)
    {
        return match;
    }

    bool http_enabled    = anyRouteHasDetection(ts, kSniffDetectionHttp);
    bool tls_enabled     = anyRouteHasDetection(ts, kSniffDetectionTlsClientHello);
    bool reverse_enabled = anyRouteHasDetection(ts, kSniffDetectionReverse);

    const uint8_t *http_host     = NULL;
    uint32_t       http_host_len = 0;
    bool           http_found    = false;
    bool           need_more     = false;

    if (http_enabled)
    {
        switch (classifyHttpHost(p, n, &http_host, &http_host_len))
        {
        case kSniffHostNeedMore:
            need_more = true;
            break;
        case kSniffHostFound:
            http_found = true;
            break;
        case kSniffHostMissing:
        default:
            break;
        }
    }

    const uint8_t *tls_sni     = NULL;
    uint32_t       tls_sni_len = 0;
    bool           tls_found   = false;

    if (tls_enabled)
    {
        switch (findTlsClientHelloSni(p, n, &tls_sni, &tls_sni_len))
        {
        case kSniffHostNeedMore:
            need_more = true;
            break;
        case kSniffHostFound:
            tls_found = true;
            break;
        case kSniffHostMissing:
        default:
            break;
        }
    }

    bool reverse_found = false;

    if (reverse_enabled)
    {
        switch (findReverseHandshake(p, n))
        {
        case kSniffHostNeedMore:
            need_more = true;
            break;
        case kSniffHostFound:
            reverse_found = true;
            break;
        case kSniffHostMissing:
        default:
            break;
        }
    }

    match.target =
        findMatchingRoute(ts, http_host, http_host_len, http_found, tls_sni, tls_sni_len, tls_found, reverse_found);
    if (match.target != NULL)
    {
        match.result = kSniffClassifyTarget;
        return match;
    }

    if (need_more)
    {
        match.result = kSniffClassifyNeedMore;
    }

    return match;
}
