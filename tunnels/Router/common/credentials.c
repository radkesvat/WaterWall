#include "structure.h"

bool routerAuthenticatedCredentialsMatch(const router_rule_t *rule, const line_t *line)
{
    bool need_username = rule->username.present;
    bool need_password = rule->password.present;

    if (need_username && need_password)
    {
        for (uint32_t ui = 0; ui < rule->username.values.count; ++ui)
        {
            for (uint32_t pi = 0; pi < rule->password.values.count; ++pi)
            {
                if (lineHasAuthenticatedCredentials(line, rule->username.values.items[ui],
                                                    rule->password.values.items[pi]))
                {
                    return true;
                }
            }
        }
        return false;
    }

    if (need_username)
    {
        for (uint32_t i = 0; i < rule->username.values.count; ++i)
        {
            if (lineHasAuthenticatedUsername(line, rule->username.values.items[i]))
            {
                return true;
            }
        }
        return false;
    }

    for (uint32_t i = 0; i < rule->password.values.count; ++i)
    {
        if (lineHasAuthenticatedPassword(line, rule->password.values.items[i]))
        {
            return true;
        }
    }
    return false;
}
