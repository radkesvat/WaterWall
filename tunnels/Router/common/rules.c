#include "structure.h"

#include "loggers/network_logger.h"

bool routerStringListParse(router_string_list_t *list, const cJSON *value_json, const char *json_path)
{
    list->items = NULL;
    list->count = 0;

    if (cJSON_IsString(value_json))
    {
        char *single = NULL;
        if (! getStringFromJson(&single, value_json))
        {
            LOGF("JSON Error: %s (string field) : expected a non-empty string value", json_path);
            return false;
        }

        list->items    = memoryAllocateZero(sizeof(char *));
        list->items[0] = single;
        list->count    = 1;
        return true;
    }

    if (! cJSON_IsArray(value_json) || cJSON_GetArraySize(value_json) <= 0)
    {
        LOGF("JSON Error: %s (array field) : expected a non-empty string or array of strings", json_path);
        return false;
    }

    list->count = (uint32_t) cJSON_GetArraySize(value_json);
    list->items = memoryAllocateZero(sizeof(char *) * (size_t) list->count);

    uint32_t     index = 0;
    const cJSON *item  = NULL;
    cJSON_ArrayForEach(item, value_json)
    {
        char *value = NULL;
        if (! getStringFromJson(&value, item))
        {
            // Partially filled list; routerStringListDestroy tolerates NULL slots.
            LOGF("JSON Error: %s[] (string field) : expected string entries", json_path);
            return false;
        }
        list->items[index++] = value;
    }

    return true;
}

void routerStringListDestroy(router_string_list_t *list)
{
    if (list->items != NULL)
    {
        for (uint32_t i = 0; i < list->count; ++i)
        {
            if (list->items[i] != NULL)
            {
                memoryFree(list->items[i]);
            }
        }
        memoryFree(list->items);
    }

    list->items = NULL;
    list->count = 0;
}

static bool routerLoadRuleTarget(router_rule_t *rule, node_t *node, const cJSON *rule_json, uint32_t rule_index)
{
    char *target_name = NULL;
    if (! getStringFromJsonObject(&target_name, rule_json, "target"))
    {
        LOGF("Router: rule %u requires a \"target\" (target node name)", (unsigned int) rule_index);
        return false;
    }

    rule->target_node = nodemanagerGetConfigNodeByName(node->node_manager_config, target_name);
    if (rule->target_node == NULL)
    {
        LOGF("Router: rule %u target node \"%s\" not found", (unsigned int) rule_index, target_name);
        memoryFree(target_name);
        return false;
    }

    memoryFree(target_name);

    if (rule->target_node == node)
    {
        LOGF("Router: rule %u must not reference the Router itself", (unsigned int) rule_index);
        return false;
    }

    return true;
}

static void routerWarnUnknownRuleKeys(const cJSON *rule_json, uint32_t rule_index)
{
    const cJSON *child = NULL;
    cJSON_ArrayForEach(child, rule_json)
    {
        const char *key = child->string;
        if (key == NULL || stringCompare(key, "target") == 0 || routerIsKnownConditionKey(key))
        {
            continue;
        }
        LOGW("Router: rule %u has unsupported field \"%s\" (ignored)", (unsigned int) rule_index, key);
    }
}

bool routerLoadRules(router_tstate_t *ts, node_t *node, const cJSON *settings)
{
    ts->needs_http_upgrade_attribute = false;

    const cJSON *rules = cJSON_GetObjectItemCaseSensitive(settings, "rules");

    if (rules == NULL)
    {
        ts->rules       = NULL;
        ts->rules_count = 0;
        return true;
    }

    if (! cJSON_IsArray(rules))
    {
        LOGF("JSON Error: Router->settings->rules (array field) : expected an array of rule objects");
        return false;
    }

    int rules_count = cJSON_GetArraySize(rules);
    if (rules_count <= 0)
    {
        LOGF("JSON Error: Router->settings->rules (array field) : The array was empty or invalid");
        return false;
    }

    ts->rules_count = (uint32_t) rules_count;
    ts->rules       = memoryAllocateZero(sizeof(*ts->rules) * (size_t) ts->rules_count);

    uint32_t     index     = 0;
    const cJSON *rule_json = NULL;
    cJSON_ArrayForEach(rule_json, rules)
    {
        if (! checkJsonIsObjectAndHasChild(rule_json))
        {
            LOGF("JSON Error: Router->settings->rules[%u] (object field) : The object was empty or invalid",
                 (unsigned int) index);
            return false;
        }

        if (! routerLoadRuleTarget(&ts->rules[index], node, rule_json, index))
        {
            return false;
        }

        uint32_t present_count = 0;
        if (! routerRuleParseConditions(&ts->rules[index], rule_json, index, &present_count))
        {
            return false;
        }

        if (present_count == 0)
        {
            LOGF("Router: rule %u must define at least one match condition besides \"target\"", (unsigned int) index);
            return false;
        }

        if ((ts->rules[index].attributes.required_flags & kRouterAttributeHttpUpgradePresent) != 0)
        {
            ts->needs_http_upgrade_attribute = true;
        }

        routerWarnUnknownRuleKeys(rule_json, index);

        ++index;
    }

    return true;
}

void routerRuleTableDestroy(router_tstate_t *ts)
{
    if (ts->rules == NULL)
    {
        ts->rules_count = 0;
        return;
    }

    for (uint32_t ri = 0; ri < ts->rules_count; ++ri)
    {
        routerRuleDestroyConditions(&ts->rules[ri]);
    }

    memoryFree(ts->rules);
    ts->rules       = NULL;
    ts->rules_count = 0;
    ts->needs_http_upgrade_attribute = false;
}
