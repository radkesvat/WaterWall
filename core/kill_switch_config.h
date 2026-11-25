#pragma once

#include <stdbool.h>
#include <stddef.h>

struct cJSON;

/* Read the machine-wide opt-in from the same core snapshot in the launcher and
 * runtime. Omitting the setting leaves protection disabled for this launch. */
bool waterwallParseKillSwitch(const struct cJSON *json, const char *input, size_t length, bool restricted,
                              bool *enabled);
