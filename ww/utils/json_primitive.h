#pragma once

#include "cJSON.h"
#include "net/domain_strategy.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#ifndef _WIN32
#include <strings.h>
#endif

static inline bool getBoolFromJsonObjectOrDefault(bool *dest, const cJSON *json_obj, const char *key, bool def)
{
    assert(dest != NULL);
    const cJSON *jbool = cJSON_GetObjectItemCaseSensitive(json_obj, key);
    if (cJSON_IsBool(jbool))
    {
        *dest = cJSON_IsTrue(jbool);
        return true;
    }
    *dest = def;
    return false;
}

typedef enum json_value_status_e
{
    kJsonValueMissing,
    kJsonValueInvalid,
    kJsonValuePresent
} json_value_status_t;

static inline bool jsonGetIntegerInRange(const cJSON *item, int64_t minimum, int64_t maximum, int64_t *value_out)
{
    if (item == NULL || ! cJSON_IsNumber(item) || value_out == NULL)
    {
        return false;
    }

    int64_t val;
    if (! cJSON_GetInt64Value(item, &val))
    {
        return false;
    }

    if (val < minimum || val > maximum)
    {
        return false;
    }

    *value_out = val;
    return true;
}

static inline json_value_status_t jsonGetObjectIntegerInRange(const cJSON *object, const char *key, int64_t minimum,
                                                              int64_t maximum, int64_t *value_out)
{
    if (object == NULL || key == NULL)
    {
        return kJsonValueMissing;
    }

    const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, key);
    if (item == NULL)
    {
        return kJsonValueMissing;
    }

    if (jsonGetIntegerInRange(item, minimum, maximum, value_out))
    {
        return kJsonValuePresent;
    }

    return kJsonValueInvalid;
}

static inline int jsonCompareCaseInsensitive(const char *left, const char *right)
{
#ifdef _WIN32
    return _stricmp(left, right);
#else
    return strcasecmp(left, right);
#endif
}

static inline bool getDomainStrategyFromJson(const cJSON *json_value, enum domain_strategy *dest)
{
    assert(dest != NULL);

    int64_t strategy_value;
    if (jsonGetIntegerInRange(json_value, kDsInvalid, kDsOnlyIpV6, &strategy_value))
    {
        *dest = (enum domain_strategy) strategy_value;
        return true;
    }

    if (! cJSON_IsString(json_value) || json_value->valuestring == NULL || json_value->valuestring[0] == '\0')
    {
        return false;
    }

    const char *strategy = json_value->valuestring;
    if (jsonCompareCaseInsensitive(strategy, "accept-dns-returned-order") == 0)
    {
        *dest = kDsInvalid;
        return true;
    }
    if (jsonCompareCaseInsensitive(strategy, "prefer-ipv4") == 0)
    {
        *dest = kDsPreferIpV4;
        return true;
    }
    if (jsonCompareCaseInsensitive(strategy, "prefer-ipv6") == 0)
    {
        *dest = kDsPreferIpV6;
        return true;
    }
    if (jsonCompareCaseInsensitive(strategy, "only-ipv4") == 0)
    {
        *dest = kDsOnlyIpV4;
        return true;
    }
    if (jsonCompareCaseInsensitive(strategy, "only-ipv6") == 0)
    {
        *dest = kDsOnlyIpV6;
        return true;
    }

    return false;
}
