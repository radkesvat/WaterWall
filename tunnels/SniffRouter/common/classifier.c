#include "structure.h"

#include "loggers/network_logger.h"

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

/* Complete HTTP/TLS detection returns immediately, so matching sees one signal. */
static sniffrouter_match_t classifyFoundSignal(sniffrouter_tstate_t *ts, uint8_t detection, const uint8_t *host,
                                               uint32_t host_len)
{
    sniffrouter_match_t match = {.result = kSniffClassifyDefault, .target = NULL};
    for (uint32_t ri = 0; ri < ts->routes_count; ++ri)
    {
        sniffrouter_route_t *route = &ts->routes[ri];
        if ((route->detection & detection) == 0)
            continue;
        // Reverse detection is a binary-signature match and intentionally ignores
        // "domains": the reverse link carries no Host/SNI of its own.
        if (detection != kSniffDetectionReverse && ! routeMatchesHost(route, host, host_len))
            continue;
        match.target = route->tunnel;
        match.result = match.target != NULL ? kSniffClassifyTarget : kSniffClassifyDefault;
        break;
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
    bool           need_more     = false;

    if (http_enabled)
    {
        switch (genericsnifferSniffHttp1Host(p, n, &http_host, &http_host_len))
        {
        case kGenericSnifferNeedMore:
            need_more = true;
            break;
        case kGenericSnifferFound:
            // A complete HTTP Host is definitive; do not probe TLS or reverse signatures.
            return classifyFoundSignal(ts, kSniffDetectionHttp1, http_host, http_host_len);
        case kGenericSnifferMissing:
        default:
            break;
        }
    }

    const uint8_t *tls_sni     = NULL;
    uint32_t       tls_sni_len = 0;
    uint8_t        tls_scratch[kGenericSnifferMaxWindowBytes];

    if (tls_enabled)
    {
        switch (genericsnifferSniffTlsClientHelloSni(p, n, tls_scratch, &tls_sni, &tls_sni_len))
        {
        case kGenericSnifferNeedMore:
            need_more = true;
            break;
        case kGenericSnifferFound:
            // A complete TLS SNI result is definitive; do not probe reverse signatures.
            return classifyFoundSignal(ts, kSniffDetectionTlsClientHello, tls_sni, tls_sni_len);
        case kGenericSnifferMissing:
        default:
            break;
        }
    }

    if (reverse_enabled)
    {
        switch (findReverseHandshake(ts, p, n))
        {
        case kSniffReverseIncomplete:
            return match;
        case kSniffReverseFound:
            match = classifyFoundSignal(ts, kSniffDetectionReverse, NULL, 0);
            break;
        case kSniffReverseMissing:
        default:
            break;
        }
    }

    if (match.target == NULL && need_more)
        match.result = kSniffClassifyNeedMore;
    return match;
}
