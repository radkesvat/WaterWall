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

    // The authenticating tunnel stores the raw password on the line. NULL means
    // no authenticated user, so a password rule cannot match.
    const char *password = lineGetAuthenticatedPassword(mctx->line);
    if (password == NULL)
    {
        return false;
    }

    // Exact, case-sensitive match against any configured password.
    for (uint32_t i = 0; i < rule->password.values.count; ++i)
    {
        if (stringCompare(rule->password.values.items[i], password) == 0)
        {
            return true;
        }
    }

    return false;
}

void routerPasswordDestroy(router_rule_t *rule)
{
    routerStringListDestroy(&rule->password.values);
    rule->password.present = false;
}
