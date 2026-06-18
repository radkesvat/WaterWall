#include "modules/destination_ip/destination_ip.h"

#include "loggers/network_logger.h"

router_field_parse_t routerDestinationIpParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(rule_json, "destination-ip");
    if (value == NULL)
    {
        rule->destination_ip.present = false;
        return kRouterFieldAbsent;
    }

    if (! routerStringListParse(&rule->destination_ip.patterns, value, "Router->settings->rules[]->destination-ip"))
    {
        LOGW("Router: rule %u has an invalid \"destination-ip\" condition", (unsigned int) rule_index);
        return kRouterFieldError;
    }

    if (! routerIpRangesParse(&rule->destination_ip.patterns,
                              &rule->destination_ip.ranges,
                              &rule->destination_ip.ranges_count,
                              "Router->settings->rules[]->destination-ip"))
    {
        return kRouterFieldError;
    }

    rule->destination_ip.present = true;
    return kRouterFieldPresent;
}

bool routerDestinationIpMatch(const router_rule_t *rule, const router_match_ctx_t *mctx)
{
    if (! rule->destination_ip.present)
    {
        return true;
    }

    const address_context_t *dest = lineGetDestinationAddressContext(mctx->line);
    return routerIpRangesMatch(dest, rule->destination_ip.ranges, rule->destination_ip.ranges_count);
}

void routerDestinationIpDestroy(router_rule_t *rule)
{
    routerStringListDestroy(&rule->destination_ip.patterns);
    if (rule->destination_ip.ranges != NULL)
    {
        memoryFree(rule->destination_ip.ranges);
        rule->destination_ip.ranges = NULL;
    }
    rule->destination_ip.ranges_count = 0;
    rule->destination_ip.present      = false;
}
