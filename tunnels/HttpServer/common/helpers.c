#include "structure.h"

#include "loggers/network_logger.h"

static inline bool asciiCaseEqual(char a, char b)
{
    return (char) tolower((unsigned char) a) == (char) tolower((unsigned char) b);
}

bool httpserverStringCaseEquals(const char *a, const char *b)
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

bool httpserverStringCaseContains(const char *haystack, const char *needle)
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

bool httpserverStringCaseContainsToken(const char *value, const char *token)
{
    if (value == NULL || token == NULL || *token == '\0')
    {
        return false;
    }

    size_t token_len = strlen(token);

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

        const char *token_end = end;
        while (token_end > p && (token_end[-1] == ' ' || token_end[-1] == '\t'))
        {
            token_end--;
        }

        size_t part_len = (size_t) (token_end - p);

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

bool httpserverBufferstreamFindCRLF(buffer_stream_t *stream, size_t *line_end)
{
    size_t len = bufferstreamGetBufLen(stream);

    if (len < 2)
    {
        return false;
    }

    int    state      = 0;
    size_t match_idx  = 0;
    size_t cur_offset = 0;

    c_foreach(qi, bs_doublequeue_t, stream->q)
    {
        sbuf_t *b = *qi.ref;
        size_t b_size = sbufGetLength(b);
        uint8_t *b_data = (uint8_t *)sbufGetRawPtr(b);

        for (size_t i = 0; i < b_size; i++)
        {
            uint8_t c = b_data[i];

            if (state == 0)
            {
                if (c == '\r')
                {
                    state     = 1;
                    match_idx = cur_offset + i;
                }
            }
            else if (state == 1)
            {
                if (c == '\n')
                {
                    *line_end = match_idx;
                    return true;
                }
                else if (c == '\r')
                {
                    match_idx = cur_offset + i;
                }
                else
                {
                    state = 0;
                }
            }
        }
        cur_offset += b_size;
    }

    return false;
}

bool httpserverBufferstreamFindDoubleCRLF(buffer_stream_t *stream, size_t *header_end)
{
    size_t len = bufferstreamGetBufLen(stream);

    if (len < 4)
    {
        return false;
    }

    int    state      = 0;
    size_t match_idx  = 0;
    size_t cur_offset = 0;

    c_foreach(qi, bs_doublequeue_t, stream->q)
    {
        sbuf_t *b = *qi.ref;
        size_t b_size = sbufGetLength(b);
        uint8_t *b_data = (uint8_t *)sbufGetRawPtr(b);

        for (size_t i = 0; i < b_size; i++)
        {
            uint8_t c = b_data[i];

            if (state == 0)
            {
                if (c == '\r')
                {
                    state     = 1;
                    match_idx = cur_offset + i;
                }
            }
            else if (state == 1)
            {
                if (c == '\n')
                {
                    state = 2;
                }
                else if (c == '\r')
                {
                    match_idx = cur_offset + i;
                }
                else
                {
                    state = 0;
                }
            }
            else if (state == 2)
            {
                if (c == '\r')
                {
                    state = 3;
                }
                else
                {
                    state = 0;
                }
            }
            else if (state == 3)
            {
                if (c == '\n')
                {
                    *header_end = match_idx + 4;
                    return true;
                }
                else if (c == '\r')
                {
                    state     = 1;
                    match_idx = cur_offset + i;
                }
                else
                {
                    state = 0;
                }
            }
        }
        cur_offset += b_size;
    }

    return false;
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
