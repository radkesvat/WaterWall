#include "modules/protocol/protocol.h"

#include "loggers/network_logger.h"

static const router_protocol_descriptor_t kRouterProtocolDescriptors[] = {
    {"http1", kAddressContextProtocolHttp1, protocolsniffHttp1Request},
    {"tls", kAddressContextProtocolTls, protocolsniffTlsClientHello},
    {"bittorrent", kAddressContextProtocolBittorrent, protocolsniffBittorrentHandshake},
};

const router_protocol_descriptor_t *routerProtocolDescriptors(uint32_t *out_count)
{
    if (out_count != NULL)
    {
        *out_count = (uint32_t) (sizeof(kRouterProtocolDescriptors) / sizeof(kRouterProtocolDescriptors[0]));
    }
    return kRouterProtocolDescriptors;
}

const router_protocol_descriptor_t *routerProtocolFindDescriptorByName(const char *name)
{
    uint32_t                            count       = 0;
    const router_protocol_descriptor_t *descriptors = routerProtocolDescriptors(&count);
    for (uint32_t i = 0; i < count; ++i)
    {
        if (routerStringEqualsIgnoreCase(name, descriptors[i].name))
        {
            return &descriptors[i];
        }
    }
    return NULL;
}

static router_field_parse_t routerProtocolValueToFlag(const char *value, uint32_t *out_flag)
{
    if (routerStringEqualsIgnoreCase(value, "http"))
    {
        LOGF("JSON Error: Router->settings->rules[]->protocol : value \"http\" was removed and migrated to "
             "\"http1\"");
        return kRouterFieldError;
    }

    const router_protocol_descriptor_t *descriptor = routerProtocolFindDescriptorByName(value);
    if (descriptor != NULL)
    {
        *out_flag = descriptor->flag;
        return kRouterFieldPresent;
    }

    LOGF("JSON Error: Router->settings->rules[]->protocol : unsupported value \"%s\" (expected \"http1\", "
         "\"tls\", or \"bittorrent\")",
         value);
    return kRouterFieldError;
}

router_field_parse_t routerProtocolParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(rule_json, "protocol");
    if (value == NULL)
    {
        rule->protocol.present      = false;
        rule->protocol.wanted_flags = 0;
        return kRouterFieldAbsent;
    }

    if (! routerStringListParse(&rule->protocol.values, value, "Router->settings->rules[]->protocol"))
    {
        LOGW("Router: rule %u has an invalid \"protocol\" condition", (unsigned int) rule_index);
        routerStringListDestroy(&rule->protocol.values);
        rule->protocol.wanted_flags = 0;
        return kRouterFieldError;
    }

    rule->protocol.wanted_flags = 0;
    for (uint32_t i = 0; i < rule->protocol.values.count; ++i)
    {
        uint32_t flag = 0;
        if (routerProtocolValueToFlag(rule->protocol.values.items[i], &flag) != kRouterFieldPresent)
        {
            routerStringListDestroy(&rule->protocol.values);
            rule->protocol.wanted_flags = 0;
            return kRouterFieldError;
        }
        rule->protocol.wanted_flags |= flag;
    }

    if (rule->protocol.wanted_flags == 0)
    {
        LOGF("Router: rule %u has an empty \"protocol\" condition", (unsigned int) rule_index);
        routerStringListDestroy(&rule->protocol.values);
        return kRouterFieldError;
    }

    rule->protocol.present = true;
    return kRouterFieldPresent;
}

bool routerProtocolMatch(const router_rule_t *rule, const router_match_ctx_t *mctx)
{
    if (! rule->protocol.present)
    {
        return true;
    }

    const address_context_t *dest = lineGetDestinationAddressContext(mctx->line);
    return (dest->optional_flags.detected_protocols & rule->protocol.wanted_flags) != 0;
}

void routerProtocolDestroy(router_rule_t *rule)
{
    routerStringListDestroy(&rule->protocol.values);
    rule->protocol.present      = false;
    rule->protocol.wanted_flags = 0;
}
