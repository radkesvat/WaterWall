#include "structure.h"

#include "loggers/network_logger.h"
#include "protocol_sniff.h"

static bool routerSniffValueEquals(const char *value, const char *expected)
{
    uint32_t i = 0;
    while (value[i] != '\0' && expected[i] != '\0')
    {
        if (asciiLower((uint8_t) value[i]) != (uint8_t) expected[i])
        {
            return false;
        }
        ++i;
    }
    return value[i] == '\0' && expected[i] == '\0';
}

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

        if (routerSniffValueEquals(value, "http"))
        {
            ts->sniffing_modes |= kRouterSniffHttp;
        }
        else if (routerSniffValueEquals(value, "tls"))
        {
            ts->sniffing_modes |= kRouterSniffTls;
        }
        else
        {
            LOGF("JSON Error: Router->settings->sniffing[] : unsupported value \"%s\" (expected \"http\" or \"tls\")",
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

router_sniff_result_t routerSniffBeforeClassify(router_tstate_t *ts, const router_match_ctx_t *mctx)
{
    if (ts->sniffing_modes == 0)
    {
        return kRouterSniffDone;
    }

    if (! ts->sniff_even_if_domain_is_already_provided && routerDestinationAlreadyHasDomain(mctx->line))
    {
        return kRouterSniffDone;
    }

    const uint8_t *http_host     = NULL;
    uint32_t       http_host_len = 0;
    bool           need_more     = false;

    if ((ts->sniffing_modes & kRouterSniffHttp) != 0)
    {
        switch (protocolsniffHttpHost(mctx->payload, mctx->payload_len, &http_host, &http_host_len))
        {
        case kProtocolSniffFound:
            discard routerStoreSniffedDomain(mctx->line, http_host, http_host_len);
            return kRouterSniffDone;
        case kProtocolSniffNeedMore:
            need_more = true;
            break;
        case kProtocolSniffMissing:
        default:
            break;
        }
    }

    const uint8_t *tls_sni     = NULL;
    uint32_t       tls_sni_len = 0;

    if ((ts->sniffing_modes & kRouterSniffTls) != 0)
    {
        switch (protocolsniffTlsClientHelloSni(mctx->payload, mctx->payload_len, &tls_sni, &tls_sni_len))
        {
        case kProtocolSniffFound:
            discard routerStoreSniffedDomain(mctx->line, tls_sni, tls_sni_len);
            return kRouterSniffDone;
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
