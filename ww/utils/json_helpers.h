#pragma once
#include "cJSON.h"
#include "objects/dynamic_value.h"
#include "wlibc.h"

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

static inline bool getIntFromJsonObject(int *dest, const cJSON *json_obj, const char *key)
{
    assert(dest != NULL);
    const cJSON *jnumber = cJSON_GetObjectItemCaseSensitive(json_obj, key);
    if (cJSON_IsNumber(jnumber))
    {
        *dest = jnumber->valueint;
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
        *dest = jnumber->valueint;
        return true;
    }
    *dest = def;
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
            char *matcher = va_arg(argp, char *);
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
            char *matcher = va_arg(argp, char *);
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
        result.integer = jstr->valueint;
    }
    return result;
}
