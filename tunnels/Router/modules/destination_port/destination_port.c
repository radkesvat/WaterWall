#include "modules/destination_port/destination_port.h"

#include "loggers/network_logger.h"

router_field_parse_t routerDestinationPortParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(rule_json, "destination-port");
    if (value == NULL)
    {
        rule->destination_port.present = false;
        return kRouterFieldAbsent;
    }

    if (! routerPortRangesParse(value,
                                &rule->destination_port.ranges,
                                &rule->destination_port.ranges_count,
                                "Router->settings->rules[]->destination-port"))
    {
        LOGW("Router: rule %u has an invalid \"destination-port\" condition", (unsigned int) rule_index);
        return kRouterFieldError;
    }

    rule->destination_port.present = true;
    return kRouterFieldPresent;
}

bool routerDestinationPortMatch(const router_rule_t *rule, const router_match_ctx_t *mctx)
{
    if (! rule->destination_port.present)
    {
        return true;
    }

    const address_context_t *dest = lineGetDestinationAddressContext(mctx->line);
    return routerPortRangesMatch(dest->port, rule->destination_port.ranges, rule->destination_port.ranges_count);
}

void routerDestinationPortDestroy(router_rule_t *rule)
{
    if (rule->destination_port.ranges != NULL)
    {
        memoryFree(rule->destination_port.ranges);
        rule->destination_port.ranges = NULL;
    }
    rule->destination_port.ranges_count = 0;
    rule->destination_port.present      = false;
}
