#include "modules/source_port/source_port.h"

#include "loggers/network_logger.h"

router_field_parse_t routerSourcePortParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(rule_json, "source-port");
    if (value == NULL)
    {
        rule->source_port.present = false;
        return kRouterFieldAbsent;
    }

    if (! routerPortRangesParse(value,
                                &rule->source_port.ranges,
                                &rule->source_port.ranges_count,
                                "Router->settings->rules[]->source-port"))
    {
        LOGW("Router: rule %u has an invalid \"source-port\" condition", (unsigned int) rule_index);
        return kRouterFieldError;
    }

    rule->source_port.present = true;
    return kRouterFieldPresent;
}

bool routerSourcePortMatch(const router_rule_t *rule, const router_match_ctx_t *mctx)
{
    if (! rule->source_port.present)
    {
        return true;
    }

    // src_ctx.port is the port the peer connected to (the real local/inbound port,
    // resolved per-connection even on multiport backends) — i.e. the destination
    // port in the packets the source peer sends us.
    const address_context_t *src = lineGetSourceAddressContext(mctx->line);
    return routerPortRangesMatch(src->port, rule->source_port.ranges, rule->source_port.ranges_count);
}

void routerSourcePortDestroy(router_rule_t *rule)
{
    if (rule->source_port.ranges != NULL)
    {
        memoryFree(rule->source_port.ranges);
        rule->source_port.ranges = NULL;
    }
    rule->source_port.ranges_count = 0;
    rule->source_port.present      = false;
}
