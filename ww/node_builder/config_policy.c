#include "config_policy.h"

static bool restricted;

void configPolicyRestrict(void)
{
    restricted = true;
}

bool configPolicyIsRestricted(void)
{
    return restricted;
}

const char *configPolicyDiagnostic(const char *identifier)
{
    return restricted ? "<restricted>" : identifier;
}

static bool rejectInput(const char *category, size_t offset)
{
    printError("Restricted config: %s at byte %zu\n", category, offset);
    return false;
}

char *configPolicyRead(FILE *input, size_t limit, size_t *length)
{
    assert(limit <= WW_HOST_NODE_JSON_LIMIT);
    size_t capacity = min((size_t) 4096, limit + 1);
    char  *buffer   = memoryAllocate(capacity);
    *length         = 0;
    if (buffer == NULL)
    {
        rejectInput("allocation failure", 0);
        return NULL;
    }
    for (;;)
    {
        if (*length == limit)
        {
            if (fgetc(input) != EOF || ferror(input))
            {
                rejectInput("input limit or read failure", *length);
                memoryFree(buffer);
                return NULL;
            }
            break;
        }
        if (*length == capacity - 1)
        {
            size_t next  = min(capacity * 2, limit + 1);
            char  *grown = memoryReAllocate(buffer, next);
            if (grown == NULL)
            {
                rejectInput("allocation failure", *length);
                memoryFree(buffer);
                return NULL;
            }
            buffer   = grown;
            capacity = next;
        }
        size_t count = fread(buffer + *length, 1, capacity - *length - 1, input);
        *length += count;
        if (ferror(input))
        {
            rejectInput("read failure", *length);
            memoryFree(buffer);
            return NULL;
        }
        if (feof(input))
        {
            break;
        }
    }
    buffer[*length] = '\0';
    if (! configPolicyCheckEncoding(buffer, *length))
    {
        memoryFree(buffer);
        return NULL;
    }
    return buffer;
}

bool configPolicyCheckEncoding(const char *input, size_t length)
{
    for (size_t i = 0; i < length; ++i)
    {
        unsigned char c = (unsigned char) input[i];
        if (c == 0)
        {
            return rejectInput("NUL", i);
        }
        if (c < 0x80)
        {
            continue;
        }
        unsigned int count;
        uint32_t     value;
        uint32_t     minimum;
        if (c >= 0xc2 && c <= 0xdf)
        {
            count   = 1;
            value   = c & 0x1f;
            minimum = 0x80;
        }
        else if (c >= 0xe0 && c <= 0xef)
        {
            count   = 2;
            value   = c & 0x0f;
            minimum = 0x800;
        }
        else if (c >= 0xf0 && c <= 0xf4)
        {
            count   = 3;
            value   = c & 0x07;
            minimum = 0x10000;
        }
        else
        {
            return rejectInput("UTF-8", i);
        }
        if (count >= length - i)
        {
            return rejectInput("UTF-8", i);
        }
        for (unsigned int j = 0; j < count; ++j)
        {
            c = (unsigned char) input[++i];
            if ((c & 0xc0) != 0x80)
            {
                return rejectInput("UTF-8", i);
            }
            value = (value << 6) | (c & 0x3f);
        }
        if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff))
        {
            return rejectInput("UTF-8", i);
        }
    }
    return true;
}

/* cJSON accepts control whitespace and some non-JSON number spellings. Check
 * those tokens and depth before allocating its tree; cJSON owns the grammar. */
static bool checkTokens(const char *input, size_t length)
{
    size_t depth     = 0;
    bool   in_string = false;
    for (size_t i = 0; i < length; ++i)
    {
        unsigned char c = (unsigned char) input[i];
        if (in_string)
        {
            if (c < 0x20)
            {
                return rejectInput("string control character", i);
            }
            if (c == '\\')
            {
                if (++i == length)
                {
                    return rejectInput("string escape", i);
                }
                if (input[i] == 'u')
                {
                    if (length - i < 5)
                    {
                        return rejectInput("Unicode escape", i - 1);
                    }
                    for (size_t j = 1; j <= 4; ++j)
                    {
                        if (! isxdigit((unsigned char) input[i + j]))
                        {
                            return rejectInput("Unicode escape", i - 1);
                        }
                    }
                    if (memcmp(input + i + 1, "0000", 4) == 0)
                    {
                        return rejectInput("decoded NUL", i - 1);
                    }
                }
            }
            else if (c == '"')
            {
                in_string = false;
            }
            continue;
        }
        if (c == '"')
        {
            in_string = true;
        }
        else if (c == '{' || c == '[')
        {
            if (++depth > WW_HOST_JSON_DEPTH_LIMIT)
            {
                return rejectInput("depth limit", i);
            }
        }
        else if (c == '}' || c == ']')
        {
            if (depth == 0)
            {
                return rejectInput("unmatched container", i);
            }
            --depth;
        }
        else if (c <= 0x20 && c != ' ' && c != '\t' && c != '\r' && c != '\n')
        {
            return rejectInput("whitespace", i);
        }
        else if (c == '-' || (c >= '0' && c <= '9'))
        {
            size_t end = i;
            if (input[end] == '-')
                ++end;
            if (end == length || input[end] < '0' || input[end] > '9')
                return rejectInput("number", i);
            if (input[end++] != '0')
                while (end < length && input[end] >= '0' && input[end] <= '9')
                    ++end;
            if (end < length && input[end] == '.')
            {
                size_t first = ++end;
                while (end < length && input[end] >= '0' && input[end] <= '9')
                    ++end;
                if (first == end)
                    return rejectInput("number", i);
            }
            if (end < length && (input[end] == 'e' || input[end] == 'E'))
            {
                ++end;
                if (end < length && (input[end] == '+' || input[end] == '-'))
                    ++end;
                size_t first = end;
                while (end < length && input[end] >= '0' && input[end] <= '9')
                    ++end;
                if (first == end)
                    return rejectInput("number", i);
            }
            if (end < length && strchr(" \t\r\n,]}", input[end]) == NULL)
                return rejectInput("number", i);
            i = end - 1;
        }
    }
    return true;
}

static int compareKeys(const void *left, const void *right)
{
    return strcmp(*(const char *const *) left, *(const char *const *) right);
}

static bool checkKeys(const cJSON *item)
{
    if (cJSON_IsNumber(item) && ! isfinite(item->valuedouble))
    {
        return false;
    }
    if (cJSON_IsObject(item))
    {
        size_t count = 0;
        for (const cJSON *child = item->child; child != NULL; child = child->next)
            ++count;
        if (count > 1)
        {
            const char **keys = memoryAllocate(count * sizeof(*keys));
            if (keys == NULL)
                return false;
            size_t index = 0;
            for (const cJSON *child = item->child; child != NULL; child = child->next)
                keys[index++] = child->string;
            qsort(keys, count, sizeof(*keys), compareKeys);
            bool unique = true;
            for (size_t i = 1; i < count; ++i)
                if (strcmp(keys[i - 1], keys[i]) == 0)
                    unique = false;
            memoryFree(keys);
            if (! unique)
                return false;
        }
    }
    for (const cJSON *child = item->child; child != NULL; child = child->next)
        if (! checkKeys(child))
            return false;
    return true;
}

cJSON *configPolicyParse(const char *input, size_t length)
{
    assert(length <= WW_HOST_NODE_JSON_LIMIT);
    if (length >= 3 && memcmp(input, "\xef\xbb\xbf", 3) == 0)
    {
        rejectInput("unexpected BOM", 0);
        return NULL;
    }
    if (! configPolicyCheckEncoding(input, length) || ! checkTokens(input, length))
        return NULL;
    const char *end  = input;
    cJSON      *json = cJSON_ParseWithLengthOpts(input, length, &end, false);
    if (json == NULL)
    {
        rejectInput("JSON syntax", (size_t) (end - input));
        return NULL;
    }
    while ((size_t) (end - input) < length && strchr(" \t\r\n", *end) != NULL)
        ++end;
    if ((size_t) (end - input) != length)
    {
        rejectInput("trailing input", (size_t) (end - input));
        cJSON_Delete(json);
        return NULL;
    }
    if (! checkKeys(json))
    {
        rejectInput("duplicate key, number range or allocation failure (document end)", length);
        cJSON_Delete(json);
        return NULL;
    }
    return json;
}
