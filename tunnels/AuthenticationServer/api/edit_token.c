#include "AuthenticationServer/edit_token.h"

void authenticationserverEditTokenFormat(const uint8_t instance_id[16], uint64_t revision,
                                         char token[kAuthenticationServerEditTokenChars + 1])
{
    assert(instance_id != NULL && token != NULL);
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 16; ++i)
    {
        token[2 * i]     = hex[instance_id[i] >> 4];
        token[2 * i + 1] = hex[instance_id[i] & 15];
        token[47 - i]    = hex[revision & 15];
        revision >>= 4;
    }
    token[kAuthenticationServerEditTokenChars] = '\0';
}

bool authenticationserverEditTokenParse(const char *token, uint8_t instance_id[16], uint64_t *revision)
{
    assert(token != NULL && instance_id != NULL && revision != NULL);
    uint8_t  decoded[16] = {0};
    uint64_t parsed      = 0;
    for (size_t i = 0; i < kAuthenticationServerEditTokenChars; ++i)
    {
        const unsigned char c = (unsigned char) token[i];
        unsigned            digit;
        if (c >= '0' && c <= '9')
            digit = c - '0';
        else if (c >= 'a' && c <= 'f')
            digit = c - 'a' + 10;
        else
            return false;
        if (i < 32)
            decoded[i / 2] = (uint8_t) ((decoded[i / 2] << 4) | digit);
        else
            parsed = (parsed << 4) | digit;
    }
    if (token[kAuthenticationServerEditTokenChars] != '\0')
        return false;
    memoryCopy(instance_id, decoded, sizeof(decoded));
    *revision = parsed;
    return true;
}
