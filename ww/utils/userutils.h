#pragma once
#include "basic_types.h"
#include "jsonutils.h"

struct user_s;
struct user_s *parseUserFromJsonObject(const cJSON *user_json);