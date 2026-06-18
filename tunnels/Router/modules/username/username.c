#include "modules/username/username.h"

#include "loggers/network_logger.h"

router_field_parse_t routerUsernameParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(rule_json, "username");
    if (value == NULL)
    {
        rule->username.present = false;
        return kRouterFieldAbsent;
    }

    if (! routerStringListParse(&rule->username.values, value, "Router->settings->rules[]->username"))
    {
        LOGW("Router: rule %u has an invalid \"username\" condition", (unsigned int) rule_index);
        return kRouterFieldError;
    }

    rule->username.present = true;
    return kRouterFieldPresent;
}

bool routerUsernameMatch(const router_rule_t *rule, const router_match_ctx_t *mctx)
{
    if (! rule->username.present)
    {
        return true;
    }

    // The authenticating tunnel stores the raw username on the line. NULL means
    // no authenticated user, so a username rule cannot match.
    const char *username = lineGetAuthenticatedUsername(mctx->line);
    if (username == NULL)
    {
        return false;
    }

    // Exact, case-sensitive match against any configured username.
    for (uint32_t i = 0; i < rule->username.values.count; ++i)
    {
        if (stringCompare(rule->username.values.items[i], username) == 0)
        {
            return true;
        }
    }

    return false;
}

void routerUsernameDestroy(router_rule_t *rule)
{
    routerStringListDestroy(&rule->username.values);
    rule->username.present = false;
}
