#include "modules/attributes/attributes.h"

#include "loggers/network_logger.h"

router_field_parse_t routerAttributesParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(rule_json, "attributes");
    if (value == NULL)
    {
        rule->attributes.present        = false;
        rule->attributes.count          = 0;
        rule->attributes.required_flags = 0;
        return kRouterFieldAbsent;
    }

    if (! cJSON_IsArray(value))
    {
        LOGF("Router: rule %u \"attributes\" must be an array", (unsigned int) rule_index);
        return kRouterFieldError;
    }

    if (cJSON_GetArraySize(value) <= 0)
    {
        LOGF("Router: rule %u \"attributes\" must not be empty", (unsigned int) rule_index);
        return kRouterFieldError;
    }

    rule->attributes.present        = true;
    rule->attributes.count          = (uint32_t) cJSON_GetArraySize(value);
    rule->attributes.required_flags = 0;

    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, value)
    {
        char *attribute = NULL;
        if (! getStringFromJson(&attribute, item))
        {
            LOGF("Router: rule %u \"attributes\" entries must be strings", (unsigned int) rule_index);
            return kRouterFieldError;
        }

        if (routerStringEqualsIgnoreCase(attribute, "http_upgrade_present"))
        {
            rule->attributes.required_flags |= kRouterAttributeHttpUpgradePresent;
        }
        else
        {
            LOGF("Router: rule %u has unsupported attribute \"%s\"", (unsigned int) rule_index, attribute);
            memoryFree(attribute);
            return kRouterFieldError;
        }

        memoryFree(attribute);
    }

    return kRouterFieldPresent;
}

bool routerAttributesMatch(const router_rule_t *rule, const router_match_ctx_t *mctx)
{
    if (! rule->attributes.present)
    {
        return true;
    }

    if (rule->attributes.required_flags == 0)
    {
        return true;
    }

    if (mctx->line_state == NULL)
    {
        return false;
    }

    return (mctx->line_state->sniffed_attributes & rule->attributes.required_flags) ==
           rule->attributes.required_flags;
}

void routerAttributesDestroy(router_rule_t *rule)
{
    rule->attributes.present        = false;
    rule->attributes.count          = 0;
    rule->attributes.required_flags = 0;
}
