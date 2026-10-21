#pragma once

#include "wwapi.h"

/* The caller supplies a lexically validated object with unique decoded keys.
 * String leaves borrow the JSON tree until a core preparation helper copies them.
 * Only the outer configuration object may be empty; nested policy objects cannot. */
bool authenticationserverConfigUnsignedString(const cJSON *, uint64_t *);
bool authenticationserverParseConfigFields(const cJSON *, user_config_patch_t *, bool allow_empty);
