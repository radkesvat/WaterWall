#pragma once

#include <stdbool.h>

struct cJSON;

/* Validate a parsed core snapshot before requesting replacement. This never
 * opens node files, initializes the runtime, or changes filtering policy. */
bool waterwallValidateProtectedCore(const struct cJSON *json);
