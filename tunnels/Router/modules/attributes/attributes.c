#include "modules/attributes/attributes.h"

#include "loggers/network_logger.h"

router_field_parse_t routerAttributesParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(rule_json, "attributes");
    if (value == NULL)
    {
        rule->attributes.present = false;
        rule->attributes.count   = 0;
        return kRouterFieldAbsent;
    }

    if (! cJSON_IsArray(value))
    {
        LOGW("Router: rule %u \"attributes\" must be an array", (unsigned int) rule_index);
        return kRouterFieldError;
    }

    rule->attributes.present = true;
    rule->attributes.count   = (uint32_t) cJSON_GetArraySize(value);
    return kRouterFieldPresent;
}

bool routerAttributesMatch(const router_rule_t *rule, const router_match_ctx_t *mctx)
{
    if (! rule->attributes.present)
    {
        return true;
    }

    discard mctx;
    // Reserved for future metadata-based matching.
    return true;
}

void routerAttributesDestroy(router_rule_t *rule)
{
    rule->attributes.present = false;
    rule->attributes.count   = 0;
}
