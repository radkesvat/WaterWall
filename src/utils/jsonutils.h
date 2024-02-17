#pragma once
#include "cJSON.h"
#include "hv/hplatform.h" // for bool 

bool getBoolFromJsonObject(bool *dest,const  cJSON *json_obj, const char *key);
bool geIntFromJsonObject(int *dest,const  cJSON *json_obj, const char *key);
bool getStringFromJsonObject(char **dest,const  cJSON *json_obj, const char *key);
bool getStringFromJsonObjectOrDefault(char **dest,const  cJSON *json_obj, const char *key, const char *def);


