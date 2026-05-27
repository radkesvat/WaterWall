/*
 * Parses node config files and provides guarded commit helpers.
 */

#include "config_file.h"
#include "loggers/internal_logger.h"
#include "utils/json_helpers.h"

static inline bool isJsonWhitespace(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static bool appendJsonChunk(char **buffer, size_t *length, size_t *capacity, const char *src, size_t src_len)
{
    assert(buffer != NULL);
    assert(*buffer != NULL);
    assert(length != NULL);
    assert(capacity != NULL);

    if (src_len == 0)
    {
        return true;
    }

    size_t required = *length + src_len + 1;
    if (required > *capacity)
    {
        size_t new_capacity = *capacity;
        while (new_capacity < required)
        {
            if (new_capacity > (SIZE_MAX / 2))
            {
                new_capacity = required;
                break;
            }
            new_capacity *= 2;
        }

        char *grown = memoryReAllocate(*buffer, new_capacity);
        if (grown == NULL)
        {
            return false;
        }

        *buffer   = grown;
        *capacity = new_capacity;
    }

    memoryCopy((*buffer) + *length, src, src_len);
    *length += src_len;
    (*buffer)[*length] = '\0';

    return true;
}

static char *stripJsonLineComments(const char *json_text)
{
    size_t input_len = stringLength(json_text);
    size_t capacity  = input_len + 1;
    size_t out_len   = 0;
    bool   in_string = false;
    bool   escaped   = false;

    char *output = memoryAllocate(capacity);
    if (output == NULL)
    {
        return NULL;
    }
    output[0] = '\0';

    for (size_t i = 0; i < input_len; ++i)
    {
        char ch = json_text[i];

        if (in_string)
        {
            if (! appendJsonChunk(&output, &out_len, &capacity, &ch, 1))
            {
                memoryFree(output);
                return NULL;
            }

            if (escaped)
            {
                escaped = false;
            }
            else if (ch == '\\')
            {
                escaped = true;
            }
            else if (ch == '"')
            {
                in_string = false;
            }
            continue;
        }

        if (ch == '"')
        {
            in_string = true;
            if (! appendJsonChunk(&output, &out_len, &capacity, &ch, 1))
            {
                memoryFree(output);
                return NULL;
            }
            continue;
        }

        if (ch == '/' && (i + 1) < input_len && json_text[i + 1] == '/')
        {
            i += 2;
            while (i < input_len && json_text[i] != '\n' && json_text[i] != '\r')
            {
                ++i;
            }

            if (i >= input_len)
            {
                break;
            }

            i--;
            continue;
        }

        if (! appendJsonChunk(&output, &out_len, &capacity, &ch, 1))
        {
            memoryFree(output);
            return NULL;
        }
    }

    return output;
}

static bool findMatchingJsonBrace(const char *json_text, size_t brace_start, size_t *brace_end_out)
{
    bool in_string = false;
    bool escaped   = false;
    int  depth     = 0;

    for (size_t i = brace_start; json_text[i] != '\0'; ++i)
    {
        char ch = json_text[i];

        if (in_string)
        {
            if (escaped)
            {
                escaped = false;
            }
            else if (ch == '\\')
            {
                escaped = true;
            }
            else if (ch == '"')
            {
                in_string = false;
            }
            continue;
        }

        if (ch == '"')
        {
            in_string = true;
            continue;
        }

        if (ch == '{')
        {
            depth++;
            continue;
        }

        if (ch == '}')
        {
            depth--;
            if (depth == 0)
            {
                *brace_end_out = i;
                return true;
            }
        }
    }

    return false;
}

static bool findVariablesObjectRange(const char *json_text, size_t *start_out, size_t *end_out, const char **key_out,
                                     bool *found_out)
{
    *found_out = false;
    int depth = 0;

    for (size_t i = 0; json_text[i] != '\0'; ++i)
    {
        char ch = json_text[i];
        if (ch == '"')
        {
            size_t string_start = i + 1;
            bool   escaped      = false;

            for (++i; json_text[i] != '\0'; ++i)
            {
                if (escaped)
                {
                    escaped = false;
                    continue;
                }

                if (json_text[i] == '\\')
                {
                    escaped = true;
                    continue;
                }

                if (json_text[i] == '"')
                {
                    break;
                }
            }

            if (json_text[i] == '\0')
            {
                return false;
            }

            size_t key_len = i - string_start;
            if (depth != 1)
            {
                continue;
            }

            const char *cursor = json_text + i + 1;
            while (isJsonWhitespace(*cursor))
            {
                ++cursor;
            }

            bool is_variables = key_len == 9 && memoryCompare(json_text + string_start, "variables", 9) == 0;

            if (! is_variables || *cursor != ':')
            {
                continue;
            }

            *found_out = true;
            ++cursor;
            while (isJsonWhitespace(*cursor))
            {
                ++cursor;
            }

            if (*cursor != '{')
            {
                LOGF("JSON Error: top-level \"variables\" block must be an object");
                return false;
            }

            size_t object_start = (size_t) (cursor - json_text);
            size_t object_end   = 0;
            if (! findMatchingJsonBrace(json_text, object_start, &object_end))
            {
                LOGF("JSON Error: top-level \"variables\" block is malformed");
                return false;
            }

            *start_out = object_start;
            *end_out   = object_end;
            *key_out   = "variables";
            return true;
        }

        if (ch == '{')
        {
            depth++;
        }
        else if (ch == '}')
        {
            depth--;
        }
    }

    return true;
}

static cJSON *parseVariablesObject(const char *json_text, const char *file_path, bool *ok_out)
{
    size_t      object_start = 0;
    size_t      object_end   = 0;
    const char *block_name   = NULL;
    bool        found_block  = false;

    *ok_out = true;

    if (! findVariablesObjectRange(json_text, &object_start, &object_end, &block_name, &found_block))
    {
        *ok_out = false;
        return NULL;
    }

    if (! found_block)
    {
        return NULL;
    }

    size_t object_len = object_end - object_start + 1;
    cJSON *json       = cJSON_ParseWithLength(json_text + object_start, object_len);
    if (json == NULL)
    {
        LOGF("JSON Error: config file \"%s\" -> %s block could not be parsed", file_path, block_name);
        if (cJSON_GetErrorPtr() != NULL)
        {
            LOGF("JSON Error: before: %s", cJSON_GetErrorPtr());
        }
        *ok_out = false;
        return NULL;
    }

    if (! cJSON_IsObject(json))
    {
        LOGF("JSON Error: config file \"%s\" -> %s must be an object", file_path, block_name);
        cJSON_Delete(json);
        *ok_out = false;
        return NULL;
    }

    return json;
}

static char *substituteVariables(const char *json_text, const cJSON *variables, const char *file_path)
{
    size_t input_len = stringLength(json_text);
    size_t capacity  = input_len + 1;
    size_t out_len   = 0;
    bool   in_string = false;
    bool   escaped   = false;

    char *output = memoryAllocate(capacity);
    if (output == NULL)
    {
        return NULL;
    }
    output[0] = '\0';

    for (size_t i = 0; i < input_len; ++i)
    {
        char ch = json_text[i];

        if (in_string)
        {
            if (! appendJsonChunk(&output, &out_len, &capacity, &ch, 1))
            {
                memoryFree(output);
                return NULL;
            }

            if (escaped)
            {
                escaped = false;
            }
            else if (ch == '\\')
            {
                escaped = true;
            }
            else if (ch == '"')
            {
                in_string = false;
            }
            continue;
        }

        if (ch == '"')
        {
            in_string = true;
            if (! appendJsonChunk(&output, &out_len, &capacity, &ch, 1))
            {
                memoryFree(output);
                return NULL;
            }
            continue;
        }

        if (ch != '$')
        {
            if (! appendJsonChunk(&output, &out_len, &capacity, &ch, 1))
            {
                memoryFree(output);
                return NULL;
            }
            continue;
        }

        size_t placeholder_end = i + 1;
        while (placeholder_end < input_len && json_text[placeholder_end] != '$' && json_text[placeholder_end] != '\n' &&
               json_text[placeholder_end] != '\r')
        {
            ++placeholder_end;
        }

        if (placeholder_end >= input_len || json_text[placeholder_end] != '$')
        {
            LOGF("JSON Error: config file \"%s\" contains an unterminated variable placeholder", file_path);
            memoryFree(output);
            return NULL;
        }

        if (placeholder_end == i + 1)
        {
            LOGF("JSON Error: config file \"%s\" contains an empty variable placeholder", file_path);
            memoryFree(output);
            return NULL;
        }

        size_t variable_name_len = placeholder_end - i - 1;
        char  *variable_name     = memoryAllocate(variable_name_len + 1);
        if (variable_name == NULL)
        {
            memoryFree(output);
            return NULL;
        }

        memoryCopy(variable_name, json_text + i + 1, variable_name_len);
        variable_name[variable_name_len] = '\0';
        const cJSON *variable_value = variables != NULL ? cJSON_GetObjectItemCaseSensitive(variables, variable_name) : NULL;
        if (variable_value == NULL)
        {
            LOGF("JSON Error: config file \"%s\" references undefined variable \"%s\"", file_path, variable_name);
            memoryFree(variable_name);
            memoryFree(output);
            return NULL;
        }

        char *replacement = cJSON_PrintUnformatted((cJSON *) variable_value);
        if (replacement == NULL)
        {
            LOGF("JSON Error: config file \"%s\" could not serialize variable \"%s\"", file_path, variable_name);
            memoryFree(variable_name);
            memoryFree(output);
            return NULL;
        }

        bool append_ok = appendJsonChunk(&output, &out_len, &capacity, replacement, stringLength(replacement));
        cJSON_free(replacement);
        memoryFree(variable_name);

        if (! append_ok)
        {
            memoryFree(output);
            return NULL;
        }

        i = placeholder_end;
    }

    return output;
}

/**
 * @brief Internal config cleanup routine shared by destroy wrappers.
 *
 * @param state Config object.
 */
static void freeConfigFile(config_file_t *state)
{
    if (state == NULL)
    {
        return;
    }
    cJSON_Delete(state->root);
    memoryFree(state->file_path);
    memoryFree(state->name);
    memoryFree(state->author);
    mutexDestroy(&(state->guard));
    memoryFree(state);
}

void destroyConfigFile(config_file_t *state)
{
    freeConfigFile(state);
}

void acquireUpdateLock(config_file_t *state)
{
    mutexLock(&(state->guard));
}

void releaseUpdateLock(config_file_t *state)
{
    mutexUnlock(&(state->guard));
}

// only use if you acquired lock before
void unsafeCommitChanges(config_file_t *state)
{
    char *string = cJSON_PrintBuffered(state->root, (int) ((state->file_prebuffer_size) * 2), true);
    if (string == NULL)
    {
        LOGE("WriteFile Error: cJSON_PrintBuffered failed for \"%s\"", state->file_path);
        return;
    }
    size_t    len         = strlen(string);
    const int max_retries = 3;
    for (int i = 0; i < max_retries; i++)
    {
        if (writeFile(state->file_path, string, len))
        {
            state->file_prebuffer_size = len;
            memoryFree(string);
            return;
        }
        LOGE("WriteFile Error: could not write to \"%s\". retry...", state->file_path);
    }
    LOGE("WriteFile Error: giving up writing to config file \"%s\"", state->file_path);
    memoryFree(string);
}

void commitChangesHard(config_file_t *state)
{
    acquireUpdateLock(state);
    unsafeCommitChanges(state);
    releaseUpdateLock(state);
}

// will not write if the mutex is locked
void commitChangesSoft(config_file_t *state)
{
#ifdef OS_WIN
    commitChangesHard(state);
#else
    if (mutexTryLock(&(state->guard)))
    {
        unsafeCommitChanges(state);
        releaseUpdateLock(state);
    }

#endif
}

config_file_t *configfileParse(const char *const file_path)
{
    config_file_t *state = memoryAllocate(sizeof(config_file_t));
    memorySet(state, 0, sizeof(config_file_t));
    mutexInit(&(state->guard));

    state->file_path = memoryAllocate(strlen(file_path) + 1);
    stringCopy(state->file_path, file_path);

    char *data_json = readFile(file_path);

    if (! data_json)
    {
        LOGF("File Error: config file \"%s\" could not be read", file_path);
        configfileDestroy(state);
        return NULL;
    }

    char *json_without_comments = stripJsonLineComments(data_json);
    memoryFree(data_json);

    if (json_without_comments == NULL)
    {
        LOGF("JSON Error: config file \"%s\" comment stripping failed", file_path);
        configfileDestroy(state);
        return NULL;
    }

    bool   variables_ok   = false;
    cJSON *variables_json = parseVariablesObject(json_without_comments, file_path, &variables_ok);
    if (! variables_ok)
    {
        memoryFree(json_without_comments);
        configfileDestroy(state);
        return NULL;
    }

    char  *resolved_json  = substituteVariables(json_without_comments, variables_json, file_path);
    cJSON_Delete(variables_json);
    memoryFree(json_without_comments);

    if (resolved_json == NULL)
    {
        configfileDestroy(state);
        return NULL;
    }

    state->file_prebuffer_size = stringLength(resolved_json);

    cJSON *json = cJSON_ParseWithLength(resolved_json, state->file_prebuffer_size);
    state->root = json;
    memoryFree(resolved_json);

    if (json == NULL)
    {
        LOGF("JSON Error: config file \"%s\" could not be parsed", file_path);
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            LOGF("JSON Error: before: %s\n", error_ptr);
        }
        configfileDestroy(state);
        return NULL;
    }

    if (! getStringFromJsonObject((&state->name), json, "name"))
    {
        LOGF("JSON Error: config file \"%s\" -> name (string field) the value was empty or invalid", file_path);
        configfileDestroy(state);
        return NULL;
    }

    getStringFromJsonObjectOrDefault(&(state->author), json, "author", "EMPTY_AUTHOR");
    getIntFromJsonObject(&(state->config_version), json, "config-version");
    getIntFromJsonObject(&(state->core_minimum_version), json, "core-minimum-version");
    getBoolFromJsonObject(&(state->encrypted), json, "encrypted");
    cJSON *nodes = cJSON_GetObjectItemCaseSensitive(json, "nodes");
    if (! (cJSON_IsArray(nodes) && nodes->child != NULL))
    {
        LOGF("JSON Error: config file \"%s\" -> nodes (array field) the array was empty or invalid", file_path);
        configfileDestroy(state);
        return NULL;
    }
    state->nodes = nodes;
    return state;
}

void configfileDestroy(config_file_t *cf)
{
    freeConfigFile(cf);
}
