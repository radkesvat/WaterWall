#include "structure.h"

#include "loggers/network_logger.h"
#include "generic_sniffer.h"

typedef enum sniffrouter_reverse_parse_e
{
    kSniffReverseMissing    = 0,
    kSniffReverseIncomplete = 1,
    kSniffReverseFound      = 2
} sniffrouter_reverse_parse_t;


// Detects the ReverseClient/ReverseServer reverse-link handshake using
// ReverseClient's exported byte sequence. SniffRouter merely peeks; the buffered
// bytes are replayed intact to the chosen route, and ReverseServer re-validates
// and strips the handshake itself.
static const uint8_t *getReverseHandshakeBytes(sniffrouter_tstate_t *ts)
{
    return ts->reverse_handshake_bytes != NULL ? ts->reverse_handshake_bytes : reverseclientHandshakeBytes;
}

static uint32_t getReverseHandshakeLength(sniffrouter_tstate_t *ts)
{
    return ts->reverse_handshake_length > 0 ? ts->reverse_handshake_length : reverseclientHandshakeLength;
}

static sniffrouter_reverse_parse_t findReverseHandshake(sniffrouter_tstate_t *ts, const uint8_t *p, uint32_t n)
{
    const uint8_t *handshake_bytes  = getReverseHandshakeBytes(ts);
    uint32_t       handshake_length = getReverseHandshakeLength(ts);

    if (n < handshake_length)
    {
        if (n > 0 && memoryCompare(p, handshake_bytes, n) == 0)
        {
            LOGW("SniffRouter: reverse handshake is incomplete in first payload, using default route");
            return kSniffReverseIncomplete;
        }

        return kSniffReverseMissing;
    }

    if (memoryCompare(p, handshake_bytes, handshake_length) != 0)
    {
        return kSniffReverseMissing;
    }

    return kSniffReverseFound;
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

        if (http_found && (route->detection & kSniffDetectionHttp1) != 0 &&
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

static sniffrouter_match_t classifyFoundSignals(sniffrouter_tstate_t *ts, const uint8_t *http_host,
                                                uint32_t http_host_len, bool http_found, const uint8_t *tls_sni,
                                                uint32_t tls_sni_len, bool tls_found, bool reverse_found,
                                                bool need_more)
{
    sniffrouter_match_t match = {
        .result = kSniffClassifyDefault,
        .target = findMatchingRoute(ts, http_host, http_host_len, http_found, tls_sni, tls_sni_len, tls_found,
                                    reverse_found),
    };

    if (match.target != NULL)
    {
        match.result = kSniffClassifyTarget;
    }
    else if (need_more)
    {
        match.result = kSniffClassifyNeedMore;
    }

    return match;
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

    bool http_enabled    = anyRouteHasDetection(ts, kSniffDetectionHttp1);
    bool tls_enabled     = anyRouteHasDetection(ts, kSniffDetectionTlsClientHello);
    bool reverse_enabled = anyRouteHasDetection(ts, kSniffDetectionReverse);

    const uint8_t *http_host     = NULL;
    uint32_t       http_host_len = 0;
    bool           http_found    = false;
    bool           need_more     = false;

    if (http_enabled)
    {
        switch (genericsnifferSniffHttp1Host(p, n, &http_host, &http_host_len))
        {
        case kGenericSnifferNeedMore:
            need_more = true;
            break;
        case kGenericSnifferFound:
            http_found = true;
            break;
        case kGenericSnifferMissing:
        default:
            break;
        }
    }

    if (http_found)
    {
        // A complete HTTP/1 Host makes TLS SNI/reverse signature checks pointless for this payload.
        return classifyFoundSignals(ts, http_host, http_host_len, true, NULL, 0, false, false, false);
    }

    const uint8_t *tls_sni     = NULL;
    uint32_t       tls_sni_len = 0;
    bool           tls_found   = false;

    if (tls_enabled)
    {
        switch (genericsnifferSniffTlsClientHelloSni(p, n, &tls_sni, &tls_sni_len))
        {
        case kGenericSnifferNeedMore:
            need_more = true;
            break;
        case kGenericSnifferFound:
            tls_found = true;
            break;
        case kGenericSnifferMissing:
        default:
            break;
        }
    }

    if (tls_found)
    {
        // A complete TLS SNI result is also definitive; avoid reverse-signature probing afterward.
        return classifyFoundSignals(ts, NULL, 0, false, tls_sni, tls_sni_len, true, false, false);
    }

    bool reverse_found = false;
    bool reverse_incomplete = false;

    if (reverse_enabled)
    {
        switch (findReverseHandshake(ts, p, n))
        {
        case kSniffReverseIncomplete:
            reverse_incomplete = true;
            break;
        case kSniffReverseFound:
            reverse_found = true;
            break;
        case kSniffReverseMissing:
        default:
            break;
        }
    }

    if (reverse_incomplete)
    {
        return match;
    }

    return classifyFoundSignals(ts, http_host, http_host_len, http_found, tls_sni, tls_sni_len, tls_found,
                                reverse_found, need_more);
}
