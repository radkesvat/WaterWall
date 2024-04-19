#pragma once
#include "basic_types.h"
#include "cJSON.h"
#include "hv/hplatform.h" // for bool

// dest must be pre-allocated
bool getBoolFromJsonObject(bool *dest, const cJSON *json_obj, const char *key);
bool getBoolFromJsonObjectOrDefault(bool *dest, const cJSON *json_obj, const char *key, bool def);
bool getIntFromJsonObject(int *dest, const cJSON *json_obj, const char *key);
bool getIntFromJsonObjectOrDefault(int *dest, const cJSON *json_obj, const char *key, int def);

// will allocate dest because it knows the string-len
bool            getStringFromJsonObject(char **dest, const cJSON *json_obj, const char *key);
bool            getStringFromJsonObjectOrDefault(char **dest, const cJSON *json_obj, const char *key, const char *def);
bool            getStringFromJson(char **dest, const cJSON *json_str_node);

dynamic_value_t parseDynamicStrValueFromJsonObject(const cJSON *json_obj, const char *key, size_t matchers, ...);
dynamic_value_t parseDynamicNumericValueFromJsonObject(const cJSON *json_obj, const char *key, size_t matchers, ...);
