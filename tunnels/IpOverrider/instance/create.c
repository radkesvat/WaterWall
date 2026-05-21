#include "structure.h"

#include "loggers/network_logger.h"

static bool ipoverriderParseIpv4String(uint32_t *dest, const char *ipbuf, const char *json_path)
{
    ip4_addr_t parsed_ipv4;

    if (ip4AddrAddressToNetwork(ipbuf, &parsed_ipv4) == 0)
    {
        LOGF("JSON Error: %s (string field) : expected a single IPv4 address, not CIDR or hostname", json_path);
        return false;
    }

    *dest = ip4AddrGetU32(&parsed_ipv4);
    return true;
}

static bool ipoverriderParseRuleIpv4(ipoverrider_rule_t *rule, const cJSON *ipv4_json, const char *json_path)
{
    rule->support4 = true;

    if (cJSON_IsString(ipv4_json) && ipv4_json->valuestring != NULL)
    {
        return ipoverriderParseIpv4String(&(rule->ov_4), ipv4_json->valuestring, json_path);
    }

    if (! cJSON_IsArray(ipv4_json))
    {
        LOGF("JSON Error: %s (string or array field) : expected a single IPv4 string or an array of IPv4 strings",
             json_path);
        return false;
    }

    const int array_size = cJSON_GetArraySize(ipv4_json);
    if (array_size <= 0)
    {
        LOGF("JSON Error: %s (array field) : the IPv4 array must not be empty", json_path);
        return false;
    }

    rule->ov_4_list = memoryAllocate((size_t) array_size * sizeof(*(rule->ov_4_list)));
    rule->ov_4_count = (uint32_t) array_size;
    atomicStoreRelaxed(&(rule->ov_4_rr_cursor), 0);

    for (int i = 0; i < array_size; ++i)
    {
        const cJSON *ipv4_item = cJSON_GetArrayItem(ipv4_json, i);
        char         ipv4_item_json_path[320];
        snprintf(ipv4_item_json_path, sizeof(ipv4_item_json_path), "%s[%d]", json_path, i);

        if (! (cJSON_IsString(ipv4_item) && ipv4_item->valuestring != NULL))
        {
            LOGF("JSON Error: %s[%d] (string field) : each IPv4 array item must be a string", json_path, i);
            memoryFree(rule->ov_4_list);
            rule->ov_4_list  = NULL;
            rule->ov_4_count = 0;
            return false;
        }

        if (! ipoverriderParseIpv4String(&(rule->ov_4_list[i]), ipv4_item->valuestring, ipv4_item_json_path))
        {
            memoryFree(rule->ov_4_list);
            rule->ov_4_list  = NULL;
            rule->ov_4_count = 0;
            return false;
        }
    }

    return true;
}

static bool ipoverriderParseRuleAddress(ipoverrider_rule_t *rule, const cJSON *settings, const char *json_path)
{
    const cJSON *ipv4_json = cJSON_GetObjectItemCaseSensitive(settings, "ipv4");
    if (ipv4_json != NULL)
    {
        char ipv4_json_path[256];
        snprintf(ipv4_json_path, sizeof(ipv4_json_path), "%s->ipv4", json_path);
        return ipoverriderParseRuleIpv4(rule, ipv4_json, ipv4_json_path);
    }

    char *ipbuf = NULL;
    if (getStringFromJsonObject(&ipbuf, settings, "ipv6"))
    {
        sockaddr_u sa;
        rule->support6 = true;
        sockaddrSetIpAddress(&(sa), ipbuf);
        memoryCopy(&(rule->ov_6), &(sa.sin6.sin6_addr.s6_addr), sizeof(sa.sin6.sin6_addr.s6_addr));
        memoryFree(ipbuf);
        return true;
    }

    LOGF("JSON Error: %s : please give the ip, use ipv4 or ipv6 json keys", json_path);
    return false;
}

static bool ipoverriderParseRule(ipoverrider_rule_t *rule, const cJSON *settings, const char *json_path)
{
    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: %s (object field) : The object was empty or invalid", json_path);
        return false;
    }

    if (getIntFromJsonObjectOrDefault(&rule->skip_chance, settings, "chance", -1))
    {
        if (rule->skip_chance < 0 || rule->skip_chance > 100)
        {
            LOGF("JSON Error: %s->chance (int field) : chance is less than 0 or more than 100", json_path);
            return false;
        }

        rule->skip_chance = 100 - rule->skip_chance;
    }

    getBoolFromJsonObjectOrDefault(&rule->only120, settings, "only120", false);

    if (! ipoverriderParseRuleAddress(rule, settings, json_path))
    {
        return false;
    }

    rule->enabled = true;
    return true;
}

static bool ipoverriderParseLegacySettings(ipoverrider_tstate_t *state, const cJSON *settings)
{
    dynamic_value_t directon_dv = parseDynamicNumericValueFromJsonObject(settings, "direction", 2, "up", "down");
    if (directon_dv.status != kDvsUp && directon_dv.status != kDvsDown)
    {
        LOGF("IpOverrider: IpOverrider->settings->direction (string field)  must be either up or down ");
        terminateProgram(1);
    }

    dynamic_value_t mode_dv = parseDynamicNumericValueFromJsonObject(settings, "mode", 2, "source-ip", "dest-ip");
    if (mode_dv.status != kDvsDestMode && mode_dv.status != kDvsSourceMode)
    {
        LOGF("IpOverrider: IpOverrider->settings->mode (string field)  mode is not set or invalid, do you "
             "want to override source ip or dest ip?");
        terminateProgram(1);
    }

    uint8_t direction_index =
        (directon_dv.status == kDvsUp) ? kIpOverriderDirectionUp : kIpOverriderDirectionDown;
    uint8_t mode_index = (mode_dv.status == kDvsSourceMode) ? kIpOverriderModeSource : kIpOverriderModeDest;

    dynamicvalueDestroy(directon_dv);
    dynamicvalueDestroy(mode_dv);
    return ipoverriderParseRule(&(state->rules[direction_index][mode_index]), settings, "IpOverrider->settings");
}

static bool ipoverriderParseDirectionalSettings(ipoverrider_tstate_t *state, const cJSON *settings)
{
    const char *direction_keys[kIpOverriderDirectionCount] = {"up", "down"};
    const char *mode_keys[kIpOverriderModeCount]           = {"source-ip", "dest-ip"};
    const char *json_paths[kIpOverriderDirectionCount][kIpOverriderModeCount] = {
        {"IpOverrider->settings->up->source-ip", "IpOverrider->settings->up->dest-ip"},
        {"IpOverrider->settings->down->source-ip", "IpOverrider->settings->down->dest-ip"},
    };

    bool parsed_any_rule = false;

    for (uint8_t direction_index = 0; direction_index < kIpOverriderDirectionCount; ++direction_index)
    {
        const cJSON *direction_settings = cJSON_GetObjectItemCaseSensitive(settings, direction_keys[direction_index]);
        if (direction_settings == NULL)
        {
            continue;
        }

        if (! checkJsonIsObjectAndHasChild(direction_settings))
        {
            LOGF("JSON Error: IpOverrider->settings->%s (object field) : The object was empty or invalid",
                 direction_keys[direction_index]);
            return false;
        }

        for (uint8_t mode_index = 0; mode_index < kIpOverriderModeCount; ++mode_index)
        {
            const cJSON *rule_settings = cJSON_GetObjectItemCaseSensitive(direction_settings, mode_keys[mode_index]);
            if (rule_settings == NULL)
            {
                continue;
            }

            if (! ipoverriderParseRule(&(state->rules[direction_index][mode_index]), rule_settings,
                                       json_paths[direction_index][mode_index]))
            {
                return false;
            }

            parsed_any_rule = true;
        }
    }

    if (! parsed_any_rule)
    {
        LOGF("JSON Error: IpOverrider->settings : please provide at least one of up/down source-ip or dest-ip rules");
    }

    return parsed_any_rule;
}

tunnel_t *ipoverriderCreate(node_t *node)
{
    tunnel_t *t = packettunnelCreate(node, sizeof(ipoverrider_tstate_t), 0);

    t->fnInitD    = &ipoverriderDownStreamInit;
    t->fnPayloadU = &ipoverriderUpStreamPayload;
    t->fnPayloadD = &ipoverriderDownStreamPayload;
    t->onPrepare  = &ipoverriderOnPrepair;
    t->onStart    = &ipoverriderOnStart;
    t->onDestroy  = &ipoverriderDestroy;

    ipoverrider_tstate_t *state = tunnelGetState(t);

    const cJSON *settings = node->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: IpOverrider->settings (object field) : The object was empty or invalid");
        ipoverriderDestroy(t);
        return NULL;
    }

    if (cJSON_GetObjectItemCaseSensitive(settings, "up") != NULL ||
        cJSON_GetObjectItemCaseSensitive(settings, "down") != NULL)
    {
        if (! ipoverriderParseDirectionalSettings(state, settings))
        {
            ipoverriderDestroy(t);
            return NULL;
        }
    }
    else if (! ipoverriderParseLegacySettings(state, settings))
    {
        ipoverriderDestroy(t);
        return NULL;
    }

    return t;
}
