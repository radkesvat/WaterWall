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
    return configLexicalCheckEncoding(input, length);
}

cJSON *configPolicyParse(const char *input, size_t length)
{
    return configLexicalParse(input, length, WW_HOST_JSON_DEPTH_LIMIT);
}
