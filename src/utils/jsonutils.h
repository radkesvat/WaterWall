#pragma once
#include "cJSON.h"
#include "hv/hplatform.h" // for bool 


// dest must be pre-allocated
bool getBoolFromJsonObject(bool *dest,const  cJSON *json_obj, const char *key);
bool geIntFromJsonObject(int *dest,const  cJSON *json_obj, const char *key);
// will allocate dest because it knows the string-len
bool getStringFromJsonObject(char **dest,const  cJSON *json_obj, const char *key);
bool getStringFromJsonObjectOrDefault(char **dest,const  cJSON *json_obj, const char *key, const char *def);

bool parseUserFromJsonObject(struct user_s * dest,const  cJSON *user_json);