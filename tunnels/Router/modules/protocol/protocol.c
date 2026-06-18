#include "modules/protocol/protocol.h"

#include "loggers/network_logger.h"

router_field_parse_t routerProtocolParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(rule_json, "protocol");
    if (value == NULL)
    {
        rule->protocol.present = false;
        return kRouterFieldAbsent;
    }

    if (! routerStringListParse(&rule->protocol.values, value, "Router->settings->rules[]->protocol"))
    {
        LOGW("Router: rule %u has an invalid \"protocol\" condition", (unsigned int) rule_index);
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

    discard mctx;
    // TODO: sniff mctx->payload (and/or use already-detected metadata) and match
    //       against rule->protocol.values (http/tls/quic/bittorrent/...).
    return true;
}

void routerProtocolDestroy(router_rule_t *rule)
{
    routerStringListDestroy(&rule->protocol.values);
    rule->protocol.present = false;
}
