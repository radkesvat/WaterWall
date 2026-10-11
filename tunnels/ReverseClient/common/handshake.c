#include "ReverseClient/reverseclient_handshake.h"

#include "loggers/network_logger.h"

#define REVERSECLIENT_HANDSHAKE_MAX_LENGTH 1024U

#define REVERSECLIENT_HANDSHAKE_BYTES_16 \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF

#define REVERSECLIENT_HANDSHAKE_BYTES_64 \
    REVERSECLIENT_HANDSHAKE_BYTES_16, REVERSECLIENT_HANDSHAKE_BYTES_16, \
    REVERSECLIENT_HANDSHAKE_BYTES_16, REVERSECLIENT_HANDSHAKE_BYTES_16

#define REVERSECLIENT_HANDSHAKE_BYTES_256 \
    REVERSECLIENT_HANDSHAKE_BYTES_64, REVERSECLIENT_HANDSHAKE_BYTES_64, \
    REVERSECLIENT_HANDSHAKE_BYTES_64, REVERSECLIENT_HANDSHAKE_BYTES_64

WW_EXPORT const uint8_t reverseclientHandshakeBytes[] = {
    REVERSECLIENT_HANDSHAKE_BYTES_256,
    REVERSECLIENT_HANDSHAKE_BYTES_256,
    REVERSECLIENT_HANDSHAKE_BYTES_64,
    REVERSECLIENT_HANDSHAKE_BYTES_64,
};

WW_EXPORT const uint32_t reverseclientHandshakeLength = (uint32_t) sizeof(reverseclientHandshakeBytes);
WW_EXPORT const uint32_t reverseclientHandshakeMaxLength = REVERSECLIENT_HANDSHAKE_MAX_LENGTH;

static bool parseReverseHandshakeLength(const cJSON *settings, const char *node_name, uint32_t *length_out)
{
    *length_out = reverseclientHandshakeLength;

    if (settings == NULL)
    {
        return true;
    }

    const cJSON *length_json = cJSON_GetObjectItemCaseSensitive(settings, "reverse-secret-length");
    if (length_json == NULL)
    {
        return true;
    }

    if (! cJSON_IsNumber(length_json) || length_json->valuedouble != (double) length_json->valueint ||
        length_json->valueint <= 0 || length_json->valueint > (int) reverseclientHandshakeMaxLength)
    {
        LOGF("%s: reverse-secret-length must be an integer in range [1, %u]",
             node_name,
             (unsigned int) reverseclientHandshakeMaxLength);
        return false;
    }

    *length_out = (uint32_t) length_json->valueint;
    return true;
}

static bool parseReverseHandshakeSecret(const cJSON *settings, const char *node_name, const char **secret_out,
                                        uint32_t *secret_length_out)
{
    *secret_out        = NULL;
    *secret_length_out = 0;

    if (settings == NULL)
    {
        return true;
    }

    const cJSON *secret_json = cJSON_GetObjectItemCaseSensitive(settings, "reverse-secret");
    if (secret_json == NULL)
    {
        return true;
    }

    if (! cJSON_IsString(secret_json) || secret_json->valuestring == NULL || secret_json->valuestring[0] == '\0')
    {
        LOGF("%s: reverse-secret must be a non-empty ASCII string", node_name);
        return false;
    }

    uint32_t secret_length = (uint32_t) stringLength(secret_json->valuestring);
    for (uint32_t i = 0; i < secret_length; ++i)
    {
        if (((const uint8_t *) secret_json->valuestring)[i] > 0x7FU)
        {
            LOGF("%s: reverse-secret must be a non-empty ASCII string", node_name);
            return false;
        }
    }

    *secret_out        = secret_json->valuestring;
    *secret_length_out = secret_length;
    return true;
}

WW_EXPORT bool reverseclientHandshakeBuildFromSettings(const cJSON *settings, const char *node_name,
                                                       uint8_t **bytes_out, uint32_t *length_out)
{
    assert(bytes_out != NULL);
    assert(length_out != NULL);

    *bytes_out  = NULL;
    *length_out = 0;

    uint32_t length = reverseclientHandshakeLength;
    if (! parseReverseHandshakeLength(settings, node_name, &length))
    {
        return false;
    }

    const char *secret        = NULL;
    uint32_t    secret_length = 0;
    if (! parseReverseHandshakeSecret(settings, node_name, &secret, &secret_length))
    {
        return false;
    }

    uint8_t *bytes = memoryAllocate(length);
    for (uint32_t i = 0; i < length; ++i)
    {
        uint8_t value = reverseclientHandshakeBytes[i % reverseclientHandshakeLength];
        if (secret_length > 0)
        {
            value ^= (uint8_t) secret[i % secret_length];
        }
        bytes[i] = value;
    }

    *bytes_out  = bytes;
    *length_out = length;
    return true;
}

WW_EXPORT void reverseclientHandshakeDestroy(uint8_t *bytes)
{
    memoryFree(bytes);
}

#undef REVERSECLIENT_HANDSHAKE_BYTES_256
#undef REVERSECLIENT_HANDSHAKE_BYTES_64
#undef REVERSECLIENT_HANDSHAKE_BYTES_16
#undef REVERSECLIENT_HANDSHAKE_MAX_LENGTH
