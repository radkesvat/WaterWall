#pragma once
#include "cJSON.h"
#include "basic_types.h"
#include "hv/hplatform.h" // for bool 


// dest must be pre-allocated
bool getBoolFromJsonObject(bool *dest,const  cJSON *json_obj, const char *key);
bool getIntFromJsonObject(int *dest,const  cJSON *json_obj, const char *key);
// will allocate dest because it knows the string-len
bool getStringFromJsonObject(char **dest,const  cJSON *json_obj, const char *key);
bool getStringFromJsonObjectOrDefault(char **dest,const  cJSON *json_obj, const char *key, const char *def);



dynamic_value_t parseDynamicStrValueFromJsonObject(const cJSON *json_obj, char *key, size_t matchers, ...);
dynamic_value_t parseDynamicNumericValueFromJsonObject(const cJSON *json_obj, char *key, size_t matchers, ...);
