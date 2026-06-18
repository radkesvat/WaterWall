#include "modules/network/network.h"

#include "loggers/network_logger.h"

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
