#include "structure.h"

#include "loggers/network_logger.h"

static bool authorityPortIsValid(const char *port)
{
    if (port == NULL || port[0] == '\0')
    {
        return false;
    }

    uint32_t value = 0;
    do
    {
        uint8_t digit = (uint8_t) (*port - '0');
        if (digit > 9 || value > (UINT16_MAX - digit) / 10U)
        {
            return false;
        }

        value = value * 10U + digit;
        ++port;
    } while (*port != '\0');

    return true;
}

static bool authorityHostLength(const char *authority, size_t *host_len)
{
    if (authority == NULL || authority[0] == '\0' || host_len == NULL)
    {
        return false;
    }

    const char *port = NULL;
    if (authority[0] == '[')
    {
        const char *closing_bracket = strchr(authority + 1, ']');
        if (closing_bracket == NULL || closing_bracket == authority + 1)
        {
            return false;
        }

        *host_len = (size_t) (closing_bracket - authority) + 1U;
        if (closing_bracket[1] == '\0')
        {
            return true;
        }
        if (closing_bracket[1] != ':')
        {
            return false;
        }

        port = closing_bracket + 2;
    }
    else
    {
        const char *colon = strchr(authority, ':');
        if (colon == NULL)
        {
            *host_len = strlen(authority);
            return true;
        }
        if (colon == authority || strchr(colon + 1, ':') != NULL)
        {
            return false;
        }

        *host_len = (size_t) (colon - authority);
        port      = colon + 1;
    }

    return authorityPortIsValid(port);
}

bool httpserverAuthorityMatchesExpectedHost(const char *expected, const char *actual)
{
    if (expected == NULL || expected[0] == '\0')
    {
        return true;
    }
    if (actual == NULL || actual[0] == '\0')
    {
        return false;
    }
    if (stringAsciiCaseEquals(expected, actual))
    {
        return true;
    }

    size_t host_len;
    if (! authorityHostLength(actual, &host_len) || strlen(expected) != host_len)
    {
        return false;
    }

    for (size_t i = 0; i < host_len; ++i)
    {
        if (! asciiCaseEqual((uint8_t) expected[i], (uint8_t) actual[i]))
        {
            return false;
        }
    }

    return true;
}

sbuf_t *httpserverAllocBufferForLength(line_t *l, uint32_t len)
{
    buffer_pool_t *pool = lineGetBufferPool(l);
    uint32_t       small_size = bufferpoolGetSmallBufferSize(pool);
    uint32_t       large_size = bufferpoolGetLargeBufferSize(pool);

    if (len <= small_size)
    {
        return bufferpoolGetSmallBuffer(pool);
    }

    if (len <= large_size)
    {
        return bufferpoolGetLargeBuffer(pool);
    }

    return sbufCreateWithPadding(len, bufferpoolGetLargeBufferPadding(pool));
}
