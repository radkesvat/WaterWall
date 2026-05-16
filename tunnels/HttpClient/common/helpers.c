#include "structure.h"

#include "loggers/network_logger.h"

static inline bool asciiCaseEqual(char a, char b)
{
    return (char) tolower((unsigned char) a) == (char) tolower((unsigned char) b);
}

bool httpclientStringCaseEquals(const char *a, const char *b)
{
    if (a == NULL || b == NULL)
    {
        return false;
    }

    while (*a != '\0' && *b != '\0')
    {
        if (! asciiCaseEqual(*a, *b))
        {
            return false;
        }
        ++a;
        ++b;
    }

    return (*a == '\0' && *b == '\0');
}

bool httpclientStringCaseContains(const char *haystack, const char *needle)
{
    if (haystack == NULL || needle == NULL || *needle == '\0')
    {
        return false;
    }

    size_t needle_len = strlen(needle);
    size_t hay_len    = strlen(haystack);

    if (needle_len > hay_len)
    {
        return false;
    }

    for (size_t i = 0; i <= hay_len - needle_len; i++)
    {
        bool match = true;
        for (size_t j = 0; j < needle_len; j++)
        {
            if (! asciiCaseEqual(haystack[i + j], needle[j]))
            {
                match = false;
                break;
            }
        }

        if (match)
        {
            return true;
        }
    }

    return false;
}

bool httpclientStringCaseContainsToken(const char *value, const char *token)
{
    if (value == NULL || token == NULL)
    {
        return false;
    }

    size_t token_len = strlen(token);
    if (token_len == 0)
    {
        return false;
    }

    const char *p = value;
    while (*p != '\0')
    {
        while (*p == ' ' || *p == '\t' || *p == ',')
        {
            p++;
        }

        if (*p == '\0')
        {
            break;
        }

        const char *end = p;
        while (*end != '\0' && *end != ',')
        {
            end++;
        }

        const char *tail = end;
        while (tail > p && (tail[-1] == ' ' || tail[-1] == '\t'))
        {
            tail--;
        }

        size_t part_len = tail - p;
        if (part_len == token_len)
        {
            bool match = true;
            for (size_t i = 0; i < part_len; i++)
            {
                if (! asciiCaseEqual(p[i], token[i]))
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                return true;
            }
        }

        p = end;
    }

    return false;
}

bool bufferstreamFindCRLF(buffer_stream_t *stream, size_t *line_end)
{
    size_t len = bufferstreamGetBufLen(stream);

    if (len < 2)
    {
        return false;
    }

    size_t offset = 0;
    int    state  = 0;

    c_foreach(i, bs_doublequeue_t, stream->q)
    {
        sbuf_t  *b    = *i.ref;
        size_t   blen = sbufGetLength(b);
        uint8_t *ptr  = (uint8_t *) sbufGetRawPtr(b);

        for (size_t j = 0; j < blen; j++)
        {
            uint8_t c = ptr[j];
            if (state == 0 && c == '\r')
            {
                state = 1;
            }
            else if (state == 1 && c == '\n')
            {
                *line_end = offset + j - 1;
                return true;
            }
            else
            {
                if (c == '\r')
                {
                    state = 1;
                }
                else
                {
                    state = 0;
                }
            }
        }
        offset += blen;
    }

    return false;
}

bool bufferstreamFindDoubleCRLF(buffer_stream_t *stream, size_t *header_end)
{
    size_t len = bufferstreamGetBufLen(stream);

    if (len < 4)
    {
        return false;
    }

    size_t offset = 0;
    int    state  = 0;

    c_foreach(i, bs_doublequeue_t, stream->q)
    {
        sbuf_t  *b    = *i.ref;
        size_t   blen = sbufGetLength(b);
        uint8_t *ptr  = (uint8_t *) sbufGetRawPtr(b);

        for (size_t j = 0; j < blen; j++)
        {
            uint8_t c = ptr[j];
            if (state == 0 && c == '\r')
            {
                state = 1;
            }
            else if (state == 1 && c == '\n')
            {
                state = 2;
            }
            else if (state == 2 && c == '\r')
            {
                state = 3;
            }
            else if (state == 3 && c == '\n')
            {
                *header_end = offset + j + 1;
                return true;
            }
            else
            {
                if (c == '\r')
                {
                    state = 1;
                }
                else
                {
                    state = 0;
                }
            }
        }
        offset += blen;
    }

    return false;
}

sbuf_t *allocBufferForLength(line_t *l, uint32_t len)
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
