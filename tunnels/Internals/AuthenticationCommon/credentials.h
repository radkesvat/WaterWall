#pragma once

#include "wwapi.h"

enum
{
    kAuthenticationPreAuthPayloadLimit   = 16U * 1024U,
    kAuthenticationAuthenticateDataLimit = kAuthenticationPreAuthPayloadLimit - 9U
};

/* Exact cJSON unformatted string escaping, including a full resume epoch.
 * Count incrementally so even a huge configured string cannot wrap the budget. */
static inline bool authenticationCredentialsFit(const char *name, const char *secret)
{
    size_t remaining =
        kAuthenticationAuthenticateDataLimit - (sizeof("{\"name\":\"\",\"secret\":\"\",\"epoch\":\"\"}") - 1U) - 64U;
    const char *values[] = {name, secret};
    for (size_t i = 0; i < 2U; ++i)
    {
        const unsigned char *p = (const unsigned char *) values[i];
        for (; *p != '\0'; ++p)
        {
            size_t bytes = 1U;
            if (*p == '"' || *p == '\\' || *p == '\b' || *p == '\f' || *p == '\n' || *p == '\r' || *p == '\t')
                bytes = 2U;
            else if (*p < 0x20U)
                bytes = 6U;
            if (bytes > remaining)
                return false;
            remaining -= bytes;
        }
    }
    return true;
}
