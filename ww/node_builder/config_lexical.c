#include "config_lexical.h"

#include <assert.h>
#include <ctype.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool rejectInput(const char *category, size_t offset)
{
    fprintf(stderr, "Restricted config: %s at byte %zu\n", category, offset);
    return false;
}

bool configLexicalCheckEncoding(const char *input, size_t length)
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

bool configLexicalCheckTokens(const char *input, size_t length, size_t max_depth)
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
            if (++depth > max_depth)
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

bool configLexicalCheckKeys(const cJSON *item)
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
            const char **keys = malloc(count * sizeof(*keys));
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
            free(keys);
            if (! unique)
                return false;
        }
    }
    for (const cJSON *child = item->child; child != NULL; child = child->next)
        if (! configLexicalCheckKeys(child))
            return false;
    return true;
}

cJSON *configLexicalParse(const char *input, size_t length, size_t max_depth)
{
    if (length >= 3 && memcmp(input, "\xef\xbb\xbf", 3) == 0)
    {
        rejectInput("unexpected BOM", 0);
        return NULL;
    }
    if (! configLexicalCheckEncoding(input, length) || ! configLexicalCheckTokens(input, length, max_depth))
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
    if (! configLexicalCheckKeys(json))
    {
        rejectInput("duplicate key, number range or allocation failure (document end)", length);
        cJSON_Delete(json);
        return NULL;
    }
    return json;
}
