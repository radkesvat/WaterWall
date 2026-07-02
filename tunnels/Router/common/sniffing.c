#include "structure.h"

#include "loggers/network_logger.h"
#include "modules/protocol/protocol.h"
#include "generic_sniffer.h"

#ifdef ROUTER_ENABLE_HTTP2_SNIFFING
#include "http2_sniffing.h"
#endif

#ifdef ROUTER_ENABLE_QUIC_SNIFFING
#include "quic_sniffing.h"
#endif

bool routerLoadSniffing(router_tstate_t *ts, const cJSON *settings)
{
    ts->sniffing_modes                           = 0;
    ts->sniff_even_if_domain_is_already_provided = false;

    if (settings == NULL)
    {
        return true;
    }

    const cJSON *sniff_even_if_domain_is_already_provided =
        cJSON_GetObjectItemCaseSensitive(settings, "sniff-even-if-domain-is-already-provided");
    if (sniff_even_if_domain_is_already_provided != NULL)
    {
        if (! cJSON_IsBool(sniff_even_if_domain_is_already_provided))
        {
            LOGF("JSON Error: Router->settings->sniff-even-if-domain-is-already-provided (boolean field) : expected "
                 "a boolean");
            return false;
        }

        ts->sniff_even_if_domain_is_already_provided = cJSON_IsTrue(sniff_even_if_domain_is_already_provided);
    }

    const cJSON *sniffing = cJSON_GetObjectItemCaseSensitive(settings, "sniffing");
    if (sniffing == NULL)
    {
        return true;
    }

    if (! cJSON_IsArray(sniffing))
    {
        LOGF("JSON Error: Router->settings->sniffing (array field) : expected an array");
        return false;
    }

    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, sniffing)
    {
        char *value = NULL;
        if (! getStringFromJson(&value, item))
        {
            LOGF("JSON Error: Router->settings->sniffing[] (string field) : expected string entries");
            return false;
        }

        if (routerStringEqualsIgnoreCase(value, "http"))
        {
#ifdef ROUTER_ENABLE_HTTP2_SNIFFING
            ts->sniffing_modes |= kRouterSniffHttp1 | kRouterSniffHttp2;
#else
            LOGF("JSON Error: Router->settings->sniffing[] : value \"http\" requires building with "
                 "-Drouter_enable_http2_sniffing=ON because it expands to \"http1\" + \"http2\"");
            memoryFree(value);
            return false;
#endif
        }
        else if (routerStringEqualsIgnoreCase(value, "http1"))
        {
            ts->sniffing_modes |= kRouterSniffHttp1;
        }
        else if (routerStringEqualsIgnoreCase(value, "http2"))
        {
#ifdef ROUTER_ENABLE_HTTP2_SNIFFING
            ts->sniffing_modes |= kRouterSniffHttp2;
#else
            LOGF("JSON Error: Router->settings->sniffing[] : value \"http2\" requires building with "
                 "-Drouter_enable_http2_sniffing=ON");
            memoryFree(value);
            return false;
#endif
        }
        else if (routerStringEqualsIgnoreCase(value, "tls"))
        {
            ts->sniffing_modes |= kRouterSniffTls;
        }
        else if (routerStringEqualsIgnoreCase(value, "quic") || routerStringEqualsIgnoreCase(value, "http3"))
        {
#ifdef ROUTER_ENABLE_QUIC_SNIFFING
            ts->sniffing_modes |= kRouterSniffQuic;
#else
            LOGF("JSON Error: Router->settings->sniffing[] : value \"%s\" requires building with "
                 "-Drouter_enable_quic_sniffing=ON",
                 value);
            memoryFree(value);
            return false;
#endif
        }
        else
        {
            LOGF("JSON Error: Router->settings->sniffing[] : unsupported value \"%s\" (expected \"http\", "
                 "\"http1\", \"http2\", \"tls\", \"quic\", or \"http3\")",
                 value);
            memoryFree(value);
            return false;
        }

        memoryFree(value);
    }

    return true;
}

typedef generic_sniffer_result_t (*router_domain_sniff_fn)(const uint8_t *payload, uint32_t payload_len,
                                                           uint8_t scratch[UINT8_MAX + 1U],
                                                           const uint8_t **host, uint32_t *host_len);

typedef struct router_domain_sniffer_s
{
    const char            *name;
    uint8_t                mode_flag;
    bool (*applies)(line_t *line);
    router_domain_sniff_fn sniff;
} router_domain_sniffer_t;

static bool routerLineHasKnownDomain(line_t *line)
{
    address_context_t *dest = lineGetDestinationAddressContext(line);
    return dest->domain != NULL && dest->domain_len > 0;
}

#ifdef ROUTER_ENABLE_HTTP2_SNIFFING
static bool routerLineIsTcpOnly(line_t *line)
{
    const address_context_t *dest = lineGetDestinationAddressContext(line);
    return dest->proto_tcp && ! dest->proto_udp && ! dest->proto_icmp && ! dest->proto_packet;
}
#endif

#ifdef ROUTER_ENABLE_QUIC_SNIFFING
static bool routerLineIsUdpOnly(line_t *line)
{
    const address_context_t *dest = lineGetDestinationAddressContext(line);
    return dest->proto_udp && ! dest->proto_tcp && ! dest->proto_icmp && ! dest->proto_packet;
}
#endif

static generic_sniffer_result_t routerSniffAdapterHttp1Host(const uint8_t *payload, uint32_t payload_len,
                                                            uint8_t scratch[UINT8_MAX + 1U],
                                                            const uint8_t **host, uint32_t *host_len)
{
    discard scratch;
    return genericsnifferSniffHttp1Host(payload, payload_len, host, host_len);
}

#ifdef ROUTER_ENABLE_HTTP2_SNIFFING
static generic_sniffer_result_t routerSniffAdapterHttp2Domain(const uint8_t *payload, uint32_t payload_len,
                                                              uint8_t scratch[UINT8_MAX + 1U],
                                                              const uint8_t **host, uint32_t *host_len)
{
    generic_sniffer_result_t result =
        routerHttp2SniffDomain(payload, payload_len, scratch, UINT8_MAX + 1U, host_len);
    if (result == kGenericSnifferFound)
    {
        *host = scratch;
    }
    return result;
}
#endif

static generic_sniffer_result_t routerSniffAdapterTlsSni(const uint8_t *payload, uint32_t payload_len,
                                                         uint8_t scratch[UINT8_MAX + 1U], const uint8_t **host,
                                                         uint32_t *host_len)
{
    discard scratch;
    return genericsnifferSniffTlsClientHelloSni(payload, payload_len, host, host_len);
}

#ifdef ROUTER_ENABLE_QUIC_SNIFFING
static generic_sniffer_result_t routerSniffAdapterQuicSni(const uint8_t *payload, uint32_t payload_len,
                                                          uint8_t scratch[UINT8_MAX + 1U], const uint8_t **host,
                                                          uint32_t *host_len)
{
    generic_sniffer_result_t result =
        routerQuicSniffClientHelloSni(payload, payload_len, scratch, UINT8_MAX + 1U, host_len);
    if (result == kGenericSnifferFound)
    {
        *host = scratch;
    }
    return result;
}
#endif

static const router_domain_sniffer_t kRouterDomainSniffers[] = {
    {"http1", kRouterSniffHttp1, NULL, routerSniffAdapterHttp1Host},
#ifdef ROUTER_ENABLE_HTTP2_SNIFFING
    {"http2", kRouterSniffHttp2, routerLineIsTcpOnly, routerSniffAdapterHttp2Domain},
#endif
    {"tls", kRouterSniffTls, NULL, routerSniffAdapterTlsSni},
#ifdef ROUTER_ENABLE_QUIC_SNIFFING
    {"quic", kRouterSniffQuic, routerLineIsUdpOnly, routerSniffAdapterQuicSni},
#endif
};

enum
{
    kRouterDomainSniffersCount = (int) (sizeof(kRouterDomainSniffers) / sizeof(kRouterDomainSniffers[0]))
};

static router_sniff_result_t routerSniffResult(bool need_more)
{
    return need_more ? kRouterSniffNeedMore : kRouterSniffDone;
}

static bool routerShouldSniffHttpUpgrade(const router_tstate_t *ts, router_match_ctx_t *mctx)
{
    return (ts->sniffing_modes & kRouterSniffHttp1) != 0 && ts->needs_http_upgrade_attribute &&
           mctx->line_state != NULL && (mctx->line_state->sniffed_attributes & kRouterAttributeHttpUpgradePresent) == 0;
}

static bool routerStoreSniffedDomain(line_t *line, const uint8_t *host, uint32_t host_len)
{
    if (host_len > UINT8_MAX)
    {
        LOGW("Router: sniffed destination domain is longer than %u bytes; ignoring", (unsigned int) UINT8_MAX);
        return false;
    }

    address_context_t *dest = lineGetDestinationAddressContext(line);
    if (! addresscontextSetObservedDomain(dest, host, host_len))
    {
        LOGW("Router: failed to store sniffed destination domain; ignoring");
        return false;
    }

    return true;
}

static bool routerSniffDetectProtocols(router_tstate_t *ts, router_match_ctx_t *mctx)
{
    uint32_t needed_protocols = ts->needed_protocols;
    if (needed_protocols == 0)
    {
        return false;
    }

    address_context_t *dest              = lineGetDestinationAddressContext(mctx->line);
    uint32_t           missing_protocols = needed_protocols & ~dest->optional_flags.detected_protocols;
    bool               need_more         = false;

    uint32_t                            protocol_count = 0;
    const router_protocol_descriptor_t *protocols      = routerProtocolDescriptors(&protocol_count);
    for (uint32_t i = 0; i < protocol_count; ++i)
    {
        uint32_t flag = protocols[i].flag;
        if ((missing_protocols & flag) == 0)
        {
            continue;
        }

        switch (protocols[i].sniff(mctx->payload, mctx->payload_len))
        {
        case kGenericSnifferFound:
            dest->optional_flags.detected_protocols |= flag;
            break;
        case kGenericSnifferNeedMore:
            need_more = true;
            break;
        case kGenericSnifferMissing:
        default:
            break;
        }
    }

    return need_more;
}

static bool routerSniffDetectHttpUpgrade(router_match_ctx_t *mctx)
{
    switch (genericsnifferSniffHttp1UpgradeHeader(mctx->payload, mctx->payload_len))
    {
    case kGenericSnifferFound:
        mctx->line_state->sniffed_attributes |= kRouterAttributeHttpUpgradePresent;
        break;
    case kGenericSnifferNeedMore:
        return true;
    case kGenericSnifferMissing:
    default:
        break;
    }

    return false;
}

static bool routerSniffDetectDomain(router_tstate_t *ts, router_match_ctx_t *mctx, bool *need_more)
{
    uint8_t scratch[UINT8_MAX + 1U];

    for (int i = 0; i < kRouterDomainSniffersCount; ++i)
    {
        const router_domain_sniffer_t *sniffer = &kRouterDomainSniffers[i];

        if ((ts->sniffing_modes & sniffer->mode_flag) == 0 ||
            (sniffer->applies != NULL && ! sniffer->applies(mctx->line)))
        {
            continue;
        }

        const uint8_t *host     = NULL;
        uint32_t       host_len = 0;

        switch (sniffer->sniff(mctx->payload, mctx->payload_len, scratch, &host, &host_len))
        {
        case kGenericSnifferFound:
            discard routerStoreSniffedDomain(mctx->line, host, host_len);
            return true;
        case kGenericSnifferNeedMore:
            *need_more = true;
            break;
        case kGenericSnifferMissing:
        default:
            break;
        }
    }

    return false;
}

router_sniff_result_t routerSniffRun(router_tstate_t *ts, router_match_ctx_t *mctx)
{
    bool need_more = routerSniffDetectProtocols(ts, mctx);

    if (ts->sniffing_modes == 0)
    {
        return routerSniffResult(need_more);
    }

    bool sniff_domain = ts->sniff_even_if_domain_is_already_provided || ! routerLineHasKnownDomain(mctx->line);
    bool sniff_upgrade = routerShouldSniffHttpUpgrade(ts, mctx);

    if (! sniff_domain && ! sniff_upgrade)
    {
        return routerSniffResult(need_more);
    }

    if (sniff_upgrade)
    {
        need_more = routerSniffDetectHttpUpgrade(mctx) || need_more;
    }

    if (sniff_domain)
    {
        discard routerSniffDetectDomain(ts, mctx, &need_more);
    }

    return routerSniffResult(need_more);
}
