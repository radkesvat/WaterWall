#pragma once

#include "wwapi.h"

enum
{
    kAuthenticationServerEditTokenChars = 48
};

/* Opaque optimistic edit precondition: instance identity followed by revision.
 * The caller copies both values under the same server state lock. */
void authenticationserverEditTokenFormat(const uint8_t instance_id[16], uint64_t revision,
                                         char token[kAuthenticationServerEditTokenChars + 1]);

/* Accept exactly the canonical lowercase hexadecimal representation. Failed
 * parsing leaves both outputs unchanged. */
bool authenticationserverEditTokenParse(const char *token, uint8_t instance_id[16], uint64_t *revision);
