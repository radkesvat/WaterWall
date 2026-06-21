#include "structure.h"

#include "loggers/network_logger.h"
#include "modules/protocol/protocol.h"
#include "protocol_sniff.h"

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
            LOGF("JSON Error: Router->settings->sniffing[] : value \"http\" was removed and migrated to \"http1\"");
            memoryFree(value);
            return false;
        }

        if (routerStringEqualsIgnoreCase(value, "http1"))
        {
            ts->sniffing_modes |= kRouterSniffHttp1;
        }
        else if (routerStringEqualsIgnoreCase(value, "tls"))
        {
            ts->sniffing_modes |= kRouterSniffTls;
        }
        else
        {
            LOGF("JSON Error: Router->settings->sniffing[] : unsupported value \"%s\" (expected \"http1\" or \"tls\")",
                 value);
            memoryFree(value);
            return false;
        }

        memoryFree(value);
    }

    return true;
}

static bool routerDestinationAlreadyHasDomain(line_t *line)
{
    address_context_t *dest = lineGetDestinationAddressContext(line);
    return dest->domain != NULL && dest->domain_len > 0;
}

static bool routerNeedsHttpUpgradeSniff(const router_tstate_t *ts, const router_match_ctx_t *mctx)
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

static router_sniff_result_t routerSniffProtocolsBeforeClassify(router_tstate_t *ts, const router_match_ctx_t *mctx)
{
    uint32_t needed_protocols = ts->needed_protocols;
    if (needed_protocols == 0)
    {
        return kRouterSniffDone;
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
        case kProtocolSniffFound:
            dest->optional_flags.detected_protocols |= flag;
            break;
        case kProtocolSniffNeedMore:
            need_more = true;
            break;
        case kProtocolSniffMissing:
        default:
            break;
        }
    }

    return need_more ? kRouterSniffNeedMore : kRouterSniffDone;
}

router_sniff_result_t routerSniffBeforeClassify(router_tstate_t *ts, const router_match_ctx_t *mctx)
{
    bool need_more = routerSniffProtocolsBeforeClassify(ts, mctx) == kRouterSniffNeedMore;

    if (ts->sniffing_modes == 0)
    {
        return need_more ? kRouterSniffNeedMore : kRouterSniffDone;
    }

    bool sniff_domain = ts->sniff_even_if_domain_is_already_provided || ! routerDestinationAlreadyHasDomain(mctx->line);
    bool sniff_http_upgrade = routerNeedsHttpUpgradeSniff(ts, mctx);

    if (! sniff_domain && ! sniff_http_upgrade)
    {
        return need_more ? kRouterSniffNeedMore : kRouterSniffDone;
    }

    const uint8_t *http_host     = NULL;
    uint32_t       http_host_len = 0;

    if ((ts->sniffing_modes & kRouterSniffHttp1) != 0)
    {
        if (sniff_http_upgrade)
        {
            switch (protocolsniffHttpUpgradeHeader(mctx->payload, mctx->payload_len))
            {
            case kProtocolSniffFound:
                mctx->line_state->sniffed_attributes |= kRouterAttributeHttpUpgradePresent;
                break;
            case kProtocolSniffNeedMore:
                need_more = true;
                break;
            case kProtocolSniffMissing:
            default:
                break;
            }
        }

        if (sniff_domain)
        {
            switch (protocolsniffHttpHost(mctx->payload, mctx->payload_len, &http_host, &http_host_len))
            {
            case kProtocolSniffFound:
                discard routerStoreSniffedDomain(mctx->line, http_host, http_host_len);
                return need_more ? kRouterSniffNeedMore : kRouterSniffDone;
            case kProtocolSniffNeedMore:
                need_more = true;
                break;
            case kProtocolSniffMissing:
            default:
                break;
            }
        }
    }

    const uint8_t *tls_sni     = NULL;
    uint32_t       tls_sni_len = 0;

    if (sniff_domain && (ts->sniffing_modes & kRouterSniffTls) != 0)
    {
        switch (protocolsniffTlsClientHelloSni(mctx->payload, mctx->payload_len, &tls_sni, &tls_sni_len))
        {
        case kProtocolSniffFound:
            discard routerStoreSniffedDomain(mctx->line, tls_sni, tls_sni_len);
            return need_more ? kRouterSniffNeedMore : kRouterSniffDone;
        case kProtocolSniffNeedMore:
            need_more = true;
            break;
        case kProtocolSniffMissing:
        default:
            break;
        }
    }

    return need_more ? kRouterSniffNeedMore : kRouterSniffDone;
}
