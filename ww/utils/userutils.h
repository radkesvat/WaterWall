#pragma once
#include "user_types.h"
#include "cJSON.h"

struct user_s;
struct user_s *parseUserFromJsonObject(const cJSON *user_json);
