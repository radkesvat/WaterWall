#include "modules/password/password.h"

#include "loggers/network_logger.h"

router_field_parse_t routerPasswordParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(rule_json, "password");
    if (value == NULL)
    {
        rule->password.present = false;
        return kRouterFieldAbsent;
    }

    if (! routerStringListParse(&rule->password.values, value, "Router->settings->rules[]->password"))
    {
        LOGW("Router: rule %u has an invalid \"password\" condition", (unsigned int) rule_index);
        return kRouterFieldError;
    }

    rule->password.present = true;
    return kRouterFieldPresent;
}

bool routerPasswordMatch(const router_rule_t *rule, const router_match_ctx_t *mctx)
{
    if (! rule->password.present)
    {
        return true;
    }

    return routerAuthenticatedCredentialsMatch(rule, mctx->line);
}

void routerPasswordDestroy(router_rule_t *rule)
{
    routerStringListDestroy(&rule->password.values);
    rule->password.present = false;
}
