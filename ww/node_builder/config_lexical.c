#include "config_lexical.h"

#include <assert.h>
#include <ctype.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if ! defined(WW_CJSON_CRT_ALLOCATOR)
#include "wmem.h"
#endif

static bool configLexicalRejectInput(bool diagnose, config_lexical_error_t *error, const char *category, size_t offset)
{
    if (error != NULL)
        *error = (config_lexical_error_t) {.category = category, .offset = offset};
    if (diagnose)
        fprintf(stderr, "Restricted config: %s at byte %zu\n", category, offset);
    return false;
}

static bool checkEncoding(const char *input, size_t length, bool diagnose, config_lexical_error_t *error)
{
    for (size_t i = 0; i < length; ++i)
    {
        unsigned char c = (unsigned char) input[i];
        if (c == 0)
        {
            return configLexicalRejectInput(diagnose, error, "NUL", i);
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
            return configLexicalRejectInput(diagnose, error, "UTF-8", i);
        }
        if (count >= length - i)
        {
            return configLexicalRejectInput(diagnose, error, "UTF-8", i);
        }
        for (unsigned int j = 0; j < count; ++j)
        {
            c = (unsigned char) input[++i];
            if ((c & 0xc0) != 0x80)
            {
                return configLexicalRejectInput(diagnose, error, "UTF-8", i);
            }
            value = (value << 6) | (c & 0x3f);
        }
        if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff))
        {
            return configLexicalRejectInput(diagnose, error, "UTF-8", i);
        }
    }
    return true;
}

bool configLexicalCheckEncoding(const char *input, size_t length)
{
    return checkEncoding(input, length, true, NULL);
}

bool configLexicalCheckEncodingQuiet(const char *input, size_t length)
{
    return checkEncoding(input, length, false, NULL);
}

static bool checkTokensBounded(const char *input, size_t length, size_t max_depth, size_t max_values, bool diagnose,
                               config_lexical_error_t *error)
{
    size_t depth     = 0;
    size_t values    = 0;
    bool   in_string = false;
    for (size_t i = 0; i < length; ++i)
    {
        unsigned char c = (unsigned char) input[i];
        if (in_string)
        {
            if (c < 0x20)
            {
                return configLexicalRejectInput(diagnose, error, "string control character", i);
            }
            if (c == '\\')
            {
                if (++i == length)
                {
                    return configLexicalRejectInput(diagnose, error, "string escape", i);
                }
                if (input[i] == 'u')
                {
                    if (length - i < 5)
                    {
                        return configLexicalRejectInput(diagnose, error, "Unicode escape", i - 1);
                    }
                    for (size_t j = 1; j <= 4; ++j)
                    {
                        if (! isxdigit((unsigned char) input[i + j]))
                        {
                            return configLexicalRejectInput(diagnose, error, "Unicode escape", i - 1);
                        }
                    }
                    if (memcmp(input + i + 1, "0000", 4) == 0)
                    {
                        return configLexicalRejectInput(diagnose, error, "decoded NUL", i - 1);
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
            if (++values > max_values)
                return configLexicalRejectInput(diagnose, error, "value limit", i);
            in_string = true;
        }
        else if (c == '{' || c == '[')
        {
            if (++values > max_values)
                return configLexicalRejectInput(diagnose, error, "value limit", i);
            if (++depth > max_depth)
            {
                return configLexicalRejectInput(diagnose, error, "depth limit", i);
            }
        }
        else if (c == '}' || c == ']')
        {
            if (depth == 0)
            {
                return configLexicalRejectInput(diagnose, error, "unmatched container", i);
            }
            --depth;
        }
        else if (c <= 0x20 && c != ' ' && c != '\t' && c != '\r' && c != '\n')
        {
            return configLexicalRejectInput(diagnose, error, "whitespace", i);
        }
        else if (c == '-' || (c >= '0' && c <= '9'))
        {
            if (++values > max_values)
                return configLexicalRejectInput(diagnose, error, "value limit", i);
            size_t end = i;
            if (input[end] == '-')
                ++end;
            if (end == length || input[end] < '0' || input[end] > '9')
                return configLexicalRejectInput(diagnose, error, "number", i);
            if (input[end++] != '0')
                while (end < length && input[end] >= '0' && input[end] <= '9')
                    ++end;
            if (end < length && input[end] == '.')
            {
                size_t first = ++end;
                while (end < length && input[end] >= '0' && input[end] <= '9')
                    ++end;
                if (first == end)
                    return configLexicalRejectInput(diagnose, error, "number", i);
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
                    return configLexicalRejectInput(diagnose, error, "number", i);
            }
            if (end < length && strchr(" \t\r\n,]}", input[end]) == NULL)
                return configLexicalRejectInput(diagnose, error, "number", i);
            i = end - 1;
        }
        else if (c == 't' || c == 'f' || c == 'n')
        {
            if (++values > max_values)
                return configLexicalRejectInput(diagnose, error, "value limit", i);
        }
    }
    return true;
}

bool configLexicalCheckTokens(const char *input, size_t length, size_t max_depth)
{
    return checkTokensBounded(input, length, max_depth, SIZE_MAX, true, NULL);
}

static int compareKeys(const void *left, const void *right)
{
    return strcmp(*(const char *const *) left, *(const char *const *) right);
}

static bool checkKeys(const cJSON *item, const char **category)
{
    if (cJSON_IsNumber(item) && ! isfinite(item->valuedouble))
    {
        if (category != NULL)
            *category = "number range (document end)";
        return false;
    }
    if (cJSON_IsObject(item))
    {
        size_t count = 0;
        for (const cJSON *child = item->child; child != NULL; child = child->next)
            ++count;
        if (count > 1)
        {
            if (count > SIZE_MAX / sizeof(const char *))
            {
                if (category != NULL)
                    *category = "size overflow (document end)";
                return false;
            }
#if defined(WW_CJSON_CRT_ALLOCATOR)
            const char **keys = malloc(count * sizeof(*keys));
            if (keys == NULL)
            {
                if (category != NULL)
                    *category = "allocation failure (document end)";
                return false;
            }
#else
            const char **keys = memoryAllocate(count * sizeof(*keys));
#endif
            size_t index = 0;
            for (const cJSON *child = item->child; child != NULL; child = child->next)
                keys[index++] = child->string;
            qsort(keys, count, sizeof(*keys), compareKeys);
            bool unique = true;
            for (size_t i = 1; i < count; ++i)
                if (strcmp(keys[i - 1], keys[i]) == 0)
                    unique = false;
#if defined(WW_CJSON_CRT_ALLOCATOR)
            free(keys);
#else
            memoryFree(keys);
#endif
            if (! unique)
            {
                if (category != NULL)
                    *category = "duplicate key (document end)";
                return false;
            }
        }
    }
    for (const cJSON *child = item->child; child != NULL; child = child->next)
        if (! checkKeys(child, category))
            return false;
    return true;
}

bool configLexicalCheckKeys(const cJSON *item)
{
    return checkKeys(item, NULL);
}

static cJSON *parseBounded(const char *input, size_t length, size_t max_depth, size_t max_values, bool diagnose,
                           void (*before_delete)(cJSON *), config_lexical_error_t *error)
{
    if (error != NULL)
        *error = (config_lexical_error_t) {0};
    if (length >= 3 && memcmp(input, "\xef\xbb\xbf", 3) == 0)
    {
        configLexicalRejectInput(diagnose, error, "unexpected BOM", 0);
        return NULL;
    }
    if (! checkEncoding(input, length, diagnose, error) ||
        ! checkTokensBounded(input, length, max_depth, max_values, diagnose, error))
        return NULL;
    const char *end  = input;
    cJSON      *json = cJSON_ParseWithLengthOpts(input, length, &end, false);
    if (json == NULL)
    {
        configLexicalRejectInput(diagnose, error, "JSON syntax", (size_t) (end - input));
        return NULL;
    }
    while ((size_t) (end - input) < length && strchr(" \t\r\n", *end) != NULL)
        ++end;
    if ((size_t) (end - input) != length)
    {
        configLexicalRejectInput(diagnose, error, "trailing input", (size_t) (end - input));
        if (before_delete != NULL)
            before_delete(json);
        cJSON_Delete(json);
        return NULL;
    }
    const char *category = NULL;
    if (! checkKeys(json, &category))
    {
        configLexicalRejectInput(diagnose, error, category, length);
        if (before_delete != NULL)
            before_delete(json);
        cJSON_Delete(json);
        return NULL;
    }
    return json;
}

cJSON *configLexicalParse(const char *input, size_t length, size_t max_depth)
{
    return configLexicalParseBounded(input, length, max_depth, SIZE_MAX);
}

cJSON *configLexicalParseQuiet(const char *input, size_t length, size_t max_depth)
{
    return parseBounded(input, length, max_depth, SIZE_MAX, false, NULL, NULL);
}

cJSON *configLexicalParseBounded(const char *input, size_t length, size_t max_depth, size_t max_values)
{
    return parseBounded(input, length, max_depth, max_values, true, NULL, NULL);
}

cJSON *configLexicalParseBoundedQuiet(const char *input, size_t length, size_t max_depth, size_t max_values)
{
    return parseBounded(input, length, max_depth, max_values, false, NULL, NULL);
}

cJSON *configLexicalParseBoundedQuietWithCleanup(const char *input, size_t length, size_t max_depth, size_t max_values,
                                                 void (*before_delete)(cJSON *))
{
    return parseBounded(input, length, max_depth, max_values, false, before_delete, NULL);
}

cJSON *configLexicalParseBoundedWithError(const char *input, size_t length, size_t max_depth, size_t max_values,
                                          void (*before_delete)(cJSON *), config_lexical_error_t *error)
{
    return parseBounded(input, length, max_depth, max_values, false, before_delete, error);
}
