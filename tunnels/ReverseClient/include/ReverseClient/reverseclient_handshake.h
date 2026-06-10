#pragma once

#include "cJSON.h"
#include "wwapi.h"

WW_EXPORT extern const uint8_t  reverseclientHandshakeBytes[];
WW_EXPORT extern const uint32_t reverseclientHandshakeLength;
WW_EXPORT extern const uint32_t reverseclientHandshakeMaxLength;

WW_EXPORT bool reverseclientHandshakeBuildFromSettings(const cJSON *settings, const char *node_name,
                                                       uint8_t **bytes_out, uint32_t *length_out);
WW_EXPORT void reverseclientHandshakeDestroy(uint8_t *bytes);
