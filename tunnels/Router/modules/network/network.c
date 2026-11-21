#include "modules/network/network.h"

#include "loggers/network_logger.h"

static bool routerTokenEquals(const char *p, uint32_t len, const char *word)
{
    for (uint32_t i = 0; i < len; ++i)
    {
        if (word[i] == '\0' || asciiLower((uint8_t) p[i]) != (uint8_t) word[i])
        {
            return false;
        }
    }
    return word[len] == '\0';
}

static bool routerNetworkTokenMask(const char *p, uint32_t len, uint8_t *mask, const char *json_path)
{
    while (len > 0 && (p[0] == ' ' || p[0] == '\t'))
    {
        ++p;
        --len;
    }
    while (len > 0 && (p[len - 1U] == ' ' || p[len - 1U] == '\t'))
    {
        --len;
    }

    if (len == 0)
    {
        return true;
    }

    if (routerTokenEquals(p, len, "tcp"))
    {
        *mask |= kRouterNetworkTcp;
        return true;
    }
    if (routerTokenEquals(p, len, "udp"))
    {
        *mask |= kRouterNetworkUdp;
        return true;
    }
    if (routerTokenEquals(p, len, "icmp"))
    {
        *mask |= kRouterNetworkIcmp;
        return true;
    }
    if (routerTokenEquals(p, len, "packet"))
    {
        *mask |= kRouterNetworkPacket;
        return true;
    }

    LOGF("JSON Error: %s : unsupported network type (expected tcp, udp, icmp or packet)", json_path);
    return false;
}

static bool routerNetworkMaskParse(const router_string_list_t *values, uint8_t *out_mask, const char *json_path)
{
    uint8_t mask = 0;

    for (uint32_t i = 0; i < values->count; ++i)
    {
        const char *value = values->items[i];
        uint32_t    len   = (uint32_t) stringLength(value);

        uint32_t start = 0;
        for (uint32_t j = 0; j <= len; ++j)
        {
            if (j == len || value[j] == ',')
            {
                if (! routerNetworkTokenMask(value + start, j - start, &mask, json_path))
                {
                    return false;
                }
                start = j + 1U;
            }
        }
    }

    if (mask == 0)
    {
        LOGF("JSON Error: %s : no valid network type configured", json_path);
        return false;
    }

    *out_mask = mask;
    return true;
}

router_field_parse_t routerNetworkParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(rule_json, "network");
    if (value == NULL)
    {
        rule->network.present = false;
        return kRouterFieldAbsent;
    }

    if (! routerStringListParse(&rule->network.values, value, "Router->settings->rules[]->network"))
    {
        LOGW("Router: rule %u has an invalid \"network\" condition", (unsigned int) rule_index);
        return kRouterFieldError;
    }

    if (! routerNetworkMaskParse(&rule->network.values, &rule->network.wanted, "Router->settings->rules[]->network"))
    {
        return kRouterFieldError;
    }

    rule->network.present = true;
    return kRouterFieldPresent;
}

uint8_t routerNetworkOffer(const address_context_t *dest)
{
    const uint8_t offer = addresscontextGetTransportOffer(dest);
    if (offer != 0 || dest->proto_tcp || dest->proto_udp || addresscontextDestinationIsPinned(dest))
        return offer;

    // Keep the existing non-L4 network match flags on their own paths.
    return (dest->proto_icmp ? kRouterNetworkIcmp : 0) | (dest->proto_packet ? kRouterNetworkPacket : 0);
}

bool routerNetworkMatch(const router_rule_t *rule, router_match_ctx_t *mctx)
{
    const uint8_t offer     = mctx->line_state->network_offer;
    mctx->eligible_networks = rule->network.present ? offer & rule->network.wanted : offer;
    return ! rule->network.present || mctx->eligible_networks != 0;
}

void routerNetworkDestroy(router_rule_t *rule)
{
    routerStringListDestroy(&rule->network.values);
    rule->network.wanted  = 0;
    rule->network.present = false;
}
