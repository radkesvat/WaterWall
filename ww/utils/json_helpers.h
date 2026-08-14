#pragma once
#include "wlibc.h"

#include "cJSON.h"
#include "net/address_context.h"
#include "objects/dynamic_value.h"

/* Parse a base-10 unsigned 64-bit integer from a string, rejecting empty input,
 * a negative sign, and any trailing non-space characters. */
static inline bool jsonParseUint64String(const char *value, uint64_t *dest)
{
    if (value == NULL)
    {
        return false;
    }

    while (isspace((unsigned char) *value))
    {
        ++value;
    }
    if (! isdigit((unsigned char) *value))
    {
        return false;
    }

    char *end = NULL;
    errno     = 0;

    unsigned long long parsed = strtoull(value, &end, 10);
    if (end == value || errno == ERANGE)
    {
        return false;
    }

    while (*end != '\0')
    {
        if (! isspace((unsigned char) *end))
        {
            return false;
        }
        ++end;
    }

    *dest = (uint64_t) parsed;
    return true;
}

/* Read an unsigned 64-bit integer from a JSON node. Accepts a JSON number (when
 * it is a non-negative integer that fits losslessly) or a decimal string (the
 * lossless encoding used for values above INT64_MAX). */
static inline bool getUint64FromJson(uint64_t *dest, const cJSON *json_node)
{
    if (cJSON_IsString(json_node))
    {
        return jsonParseUint64String(json_node->valuestring, dest);
    }

    if (! cJSON_IsNumber(json_node) || json_node->valueint < 0 ||
        json_node->valuedouble != (double) json_node->valueint)
    {
        return false;
    }

    *dest = (uint64_t) json_node->valueint;
    return true;
}

/* Add an unsigned 64-bit integer to a JSON object. cJSON keeps exact integers in
 * a signed int64_t, so 0..INT64_MAX round-trips as a real JSON number; larger
 * values are stored as a lossless decimal string. */
static inline bool jsonAddUint64ToObject(cJSON *json_obj, const char *key, uint64_t value)
{
    cJSON *item = NULL;

    if (value <= (uint64_t) INT64_MAX)
    {
        item = cJSON_CreateNumber((double) (int64_t) value);
        if (item != NULL)
        {
            item->valueint    = (int64_t) value;
            item->valuedouble = (double) item->valueint;
        }
    }
    else
    {
        char number_buf[32];
        snprintf(number_buf, sizeof(number_buf), "%" PRIu64, value);
        item = cJSON_CreateString(number_buf);
    }

    if (item == NULL)
    {
        return false;
    }
    if (! cJSON_AddItemToObject(json_obj, key, item))
    {
        cJSON_Delete(item);
        return false;
    }

    return true;
}

static inline bool checkJsonIsObjectAndHasChild(const cJSON *json_obj)
{
    return cJSON_IsObject(json_obj) && json_obj->child != NULL;
}

static inline bool getBoolFromJsonObject(bool *dest, const cJSON *json_obj, const char *key)
{
    assert(dest != NULL);
    const cJSON *jbool = cJSON_GetObjectItemCaseSensitive(json_obj, key);
    if (cJSON_IsBool(jbool))
    {
        *dest = cJSON_IsTrue(jbool);
        return true;
    }
    return false;
}

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

    if (item->valuedouble != (double) item->valueint)
    {
        return false;
    }

    int64_t val = (int64_t) item->valueint;
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

/*
 * Presence-aware strict readers, the boolean and string counterparts of
 * jsonGetObjectIntegerInRange().
 *
 * The ...OrDefault() helpers below cannot tell an omitted field from a present
 * one of the wrong type: both answer false and both write the default. That is
 * fine where a default is the intent, and wrong where a configuration mistake
 * should be reported - `"enabled": "yes"` silently enabling a feature reads
 * exactly like `"enabled"` having been left out.
 */
static inline json_value_status_t jsonGetObjectBoolean(const cJSON *object, const char *key, bool *value_out)
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

    if (cJSON_IsBool(item) == 0 || value_out == NULL)
    {
        return kJsonValueInvalid;
    }

    *value_out = cJSON_IsTrue(item) != 0;
    return kJsonValuePresent;
}

/* Borrows the cJSON-owned string; it stays valid for the document's lifetime. */
static inline json_value_status_t jsonGetObjectNonEmptyString(const cJSON *object, const char *key,
                                                              const char **value_out)
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

    if (cJSON_IsString(item) == 0 || item->valuestring == NULL || item->valuestring[0] == '\0' || value_out == NULL)
    {
        return kJsonValueInvalid;
    }

    *value_out = item->valuestring;
    return kJsonValuePresent;
}

static inline bool getIntFromJsonObject(int *dest, const cJSON *json_obj, const char *key)
{
    assert(dest != NULL);
    const cJSON *jnumber = cJSON_GetObjectItemCaseSensitive(json_obj, key);
    if (cJSON_IsNumber(jnumber))
    {
        *dest = (int) jnumber->valueint;
        return true;
    }
    return false;
}

static inline bool getIntFromJsonObjectOrDefault(int *dest, const cJSON *json_obj, const char *key, int def)
{
    assert(dest != NULL);
    const cJSON *jnumber = cJSON_GetObjectItemCaseSensitive(json_obj, key);
    if (cJSON_IsNumber(jnumber))
    {
        *dest = (int) jnumber->valueint;
        return true;
    }
    *dest = def;
    return false;
}

static inline bool getDomainStrategyFromJson(const cJSON *json_value, enum domain_strategy *dest)
{
    assert(dest != NULL);

    if (cJSON_IsNumber(json_value) && json_value->valuedouble == (double) json_value->valueint &&
        json_value->valueint >= kDsInvalid && json_value->valueint <= kDsOnlyIpV6)
    {
        *dest = (enum domain_strategy) json_value->valueint;
        return true;
    }

    if (! cJSON_IsString(json_value) || json_value->valuestring == NULL || json_value->valuestring[0] == '\0')
    {
        return false;
    }

    const char *strategy = json_value->valuestring;
    if (stricmp(strategy, "accept-dns-returned-order") == 0)
    {
        *dest = kDsInvalid;
        return true;
    }
    if (stricmp(strategy, "prefer-ipv4") == 0)
    {
        *dest = kDsPreferIpV4;
        return true;
    }
    if (stricmp(strategy, "prefer-ipv6") == 0)
    {
        *dest = kDsPreferIpV6;
        return true;
    }
    if (stricmp(strategy, "only-ipv4") == 0)
    {
        *dest = kDsOnlyIpV4;
        return true;
    }
    if (stricmp(strategy, "only-ipv6") == 0)
    {
        *dest = kDsOnlyIpV6;
        return true;
    }

    return false;
}

static inline bool getDomainStrategyFromJsonObjectOrDefault(enum domain_strategy *dest, const cJSON *json_obj,
                                                            const char *key, enum domain_strategy def)
{
    assert(dest != NULL);

    const cJSON *json_value = cJSON_GetObjectItemCaseSensitive(json_obj, key);
    if (json_value == NULL)
    {
        *dest = def;
        return true;
    }

    return getDomainStrategyFromJson(json_value, dest);
}

static inline bool getPositiveIntFromJsonObjectOrBoolDefault(int *dest, const cJSON *json_obj, const char *key,
                                                             int true_value, int def)
{
    assert(dest != NULL);

    const cJSON *jvalue = cJSON_GetObjectItemCaseSensitive(json_obj, key);
    if (jvalue == NULL)
    {
        *dest = def;
        return true;
    }

    if (cJSON_IsBool(jvalue))
    {
        *dest = cJSON_IsTrue(jvalue) ? true_value : 0;
        return true;
    }

    if (cJSON_IsNumber(jvalue) && jvalue->valueint > 0 && jvalue->valuedouble == (double) jvalue->valueint)
    {
        *dest = (int) jvalue->valueint;
        return true;
    }

    return false;
}

static inline bool getStringFromJson(char **dest, const cJSON *json_str_node)
{
    assert(*dest == NULL);
    if (cJSON_IsString(json_str_node) && (json_str_node->valuestring != NULL))
    {

        *dest = memoryAllocate(strlen(json_str_node->valuestring) + 1);
        stringCopy(*dest, json_str_node->valuestring);
        return true;
    }
    return false;
}

static inline bool getStringFromJsonObject(char **dest, const cJSON *json_obj, const char *key)
{

    assert(*dest == NULL);
    const cJSON *jstr = cJSON_GetObjectItemCaseSensitive(json_obj, key);
    if (cJSON_IsString(jstr) && (jstr->valuestring != NULL))
    {

        *dest = memoryAllocate(strlen(jstr->valuestring) + 1);
        stringCopy(*dest, jstr->valuestring);
        return true;
    }
    return false;
}

static inline const cJSON *getJsonObjectItemByKeys(const cJSON *json_obj, const char *key1, const char *key2,
                                                   const char *key3)
{
    const char *keys[3] = {key1, key2, key3};

    for (size_t i = 0; i < ARRAY_SIZE(keys); ++i)
    {
        if (keys[i] == NULL)
        {
            continue;
        }

        const cJSON *item = cJSON_GetObjectItemCaseSensitive(json_obj, keys[i]);
        if (item != NULL)
        {
            return item;
        }
    }

    return NULL;
}

static inline bool getStringFromJsonObjectByKeys(char **dest, const cJSON *json_obj, const char *key1, const char *key2,
                                                 const char *key3)
{
    assert(dest != NULL);

    const cJSON *jstr = getJsonObjectItemByKeys(json_obj, key1, key2, key3);
    if (cJSON_IsString(jstr) && jstr->valuestring != NULL)
    {
        *dest = memoryAllocate(stringLength(jstr->valuestring) + 1U);
        stringCopy(*dest, jstr->valuestring);
        return true;
    }

    return false;
}

static inline bool getStringFromJsonObjectOrDefault(char **dest, const cJSON *json_obj, const char *key,
                                                    const char *def) // NOLINT
{
    assert(def != NULL);
    if (! getStringFromJsonObject(dest, json_obj, key))
    {
        *dest = memoryAllocate(strlen(def) + 1);
        stringCopy(*dest, def);
        return false;
    }
    return true;
}

static inline dynamic_value_t parseDynamicStrValueFromJsonObject(const cJSON *json_obj, const char *key,
                                                                 size_t matchers, ...)
{

    dynamic_value_t result = {0};
    result.status          = kDvsEmpty;

    if (! cJSON_IsObject(json_obj) || json_obj->child == NULL)
    {
        return result;
    }

    const cJSON *jstr = cJSON_GetObjectItemCaseSensitive(json_obj, key);
    if (cJSON_IsString(jstr) && (jstr->valuestring != NULL))
    {

        va_list argp;
        va_start(argp, matchers);
        for (size_t mi = kDvsConstant + 1; mi < matchers + kDvsConstant + 1; mi++)
        {
            const char *matcher = va_arg(argp, const char *);
            if (stringCompare(matcher, jstr->valuestring) == 0)
            {
                va_end(argp);
                result.status = (int) mi;
                return result;
            }
        }

        va_end(argp);
        result.status = kDvsConstant;
        result.string = memoryAllocate(strlen(jstr->valuestring) + 1);
        stringCopy(result.string, jstr->valuestring);
    }
    return result;
}

static inline dynamic_value_t parseDynamicNumericValueFromJsonObject(const cJSON *json_obj, const char *key,
                                                                     size_t matchers, ...)
{

    dynamic_value_t result = {0};
    result.status          = kDvsEmpty;

    if (! cJSON_IsObject(json_obj) || json_obj->child == NULL)
    {
        return result;
    }
    const cJSON *jstr = cJSON_GetObjectItemCaseSensitive(json_obj, key);
    if (cJSON_IsString(jstr) && (jstr->valuestring != NULL))
    {

        va_list argp;
        va_start(argp, matchers);
        for (size_t mi = kDvsConstant + 1; mi < matchers + kDvsConstant + 1; mi++)
        {
            const char *matcher = va_arg(argp, const char *);
            if (stringCompare(matcher, jstr->valuestring) == 0)
            {
                va_end(argp);
                result.status = (int) mi;
                return result;
            }
        }

        va_end(argp);
        result.status = kDvsEmpty;
    }
    else if (cJSON_IsNumber(jstr))
    {
        result.status  = kDvsConstant;
        result.integer = (uint32_t) jstr->valueint;
    }
    return result;
}
