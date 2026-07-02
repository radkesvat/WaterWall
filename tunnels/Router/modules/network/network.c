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

bool routerNetworkMatch(const router_rule_t *rule, const router_match_ctx_t *mctx)
{
    if (! rule->network.present)
    {
        return true;
    }

    // Match against the destination context's protocol bit flags.
    const address_context_t *dest = lineGetDestinationAddressContext(mctx->line);

    uint8_t have = 0;
    if (dest->proto_tcp)
    {
        have |= kRouterNetworkTcp;
    }
    if (dest->proto_udp)
    {
        have |= kRouterNetworkUdp;
    }
    if (dest->proto_icmp)
    {
        have |= kRouterNetworkIcmp;
    }
    if (dest->proto_packet)
    {
        have |= kRouterNetworkPacket;
    }

    // The rule matches if any requested network type is present (OR semantics
    // within the field, e.g. "tcp,udp").
    return (rule->network.wanted & have) != 0;
}

void routerNetworkDestroy(router_rule_t *rule)
{
    routerStringListDestroy(&rule->network.values);
    rule->network.wanted  = 0;
    rule->network.present = false;
}
