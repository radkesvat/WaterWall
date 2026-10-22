/*
 * Parses node config files and provides guarded commit helpers.
 */

#include "config_file.h"
#include "config_policy.h"
#include "loggers/internal_logger.h"
#include "utils/json_helpers.h"

static inline bool isJsonWhitespace(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

/* These span helpers follow a tree already accepted by cJSON. They retain raw
 * evidence for API configuration and variable substitution without imposing
 * strict parsing on unrelated configuration values. */
static size_t apiConfigSkipWhitespace(const char *text, size_t length, size_t offset)
{
    while (offset < length && isJsonWhitespace(text[offset]))
        ++offset;
    return offset;
}

static size_t apiConfigStringEnd(const char *text, size_t length, size_t offset)
{
    assert(offset < length && text[offset] == '"');
    for (++offset; offset < length; ++offset)
    {
        if (text[offset] == '\\')
            ++offset;
        else if (text[offset] == '"')
            return offset + 1;
    }
    return length;
}

static size_t apiConfigValueEnd(const char *text, size_t length, size_t offset)
{
    if (offset == length)
        return length;
    if (text[offset] == '"')
        return apiConfigStringEnd(text, length, offset);
    if (text[offset] == '{' || text[offset] == '[')
    {
        size_t depth = 0;
        for (; offset < length; ++offset)
        {
            if (text[offset] == '"')
                offset = apiConfigStringEnd(text, length, offset) - 1;
            else if (text[offset] == '{' || text[offset] == '[')
                ++depth;
            else if ((text[offset] == '}' || text[offset] == ']') && --depth == 0)
                return offset + 1;
        }
        return length;
    }
    while (offset < length && ! isJsonWhitespace(text[offset]) && text[offset] != ',' && text[offset] != '}' &&
           text[offset] != ']')
        ++offset;
    return offset;
}

static bool apiConfigStringValid(const char *text, size_t length)
{
    if (! configLexicalCheckEncodingQuiet(text, length))
        return false;
    for (size_t i = 0; i + 1 < length; ++i)
    {
        if (text[i] != '\\')
            continue;
        ++i;
        if (text[i] == 'u' && length - i >= 5 && memcmp(text + i + 1, "0000", 4) == 0)
            return false;
    }
    return true;
}

static bool apiConfigFieldSpan(const char *text, size_t length, size_t *cursor, size_t *key_begin, size_t *key_end,
                               size_t *value_begin, size_t *value_end)
{
    size_t offset = apiConfigSkipWhitespace(text, length, *cursor);
    if (offset < length && text[offset] == ',')
        offset = apiConfigSkipWhitespace(text, length, offset + 1);
    if (offset == length || text[offset] != '"')
        return false;
    *key_begin = offset;
    *key_end   = apiConfigStringEnd(text, length, offset);
    offset     = apiConfigSkipWhitespace(text, length, *key_end);
    if (offset == length || text[offset] != ':')
        return false;
    *value_begin = apiConfigSkipWhitespace(text, length, offset + 1);
    *value_end   = apiConfigValueEnd(text, length, *value_begin);
    *cursor      = *value_end;
    return *value_begin < *value_end;
}

static bool apiConfigInspectNode(config_file_t *state, const char *text, size_t length, const cJSON *node)
{
    if (! cJSON_IsObject(node))
        return true;
    const cJSON *type     = cJSON_GetObjectItemCaseSensitive(node, "type");
    const bool   endpoint = cJSON_IsString(type) && strcmp(type->valuestring, "APIServer") == 0;
    size_t       cursor   = apiConfigSkipWhitespace(text, length, 0) + 1;
    for (const cJSON *field = node->child; field; field = field->next)
    {
        size_t kb, ke, vb, ve;
        if (! apiConfigFieldSpan(text, length, &cursor, &kb, &ke, &vb, &ve))
        {
            state->api_selector_strings_invalid = true;
            return ! endpoint;
        }
        if (strcmp(field->string, "name") == 0 &&
            (! apiConfigStringValid(text + kb, ke - kb) || ! apiConfigStringValid(text + vb, ve - vb)))
            state->api_selector_strings_invalid = true;
        if (endpoint && (strcmp(field->string, "settings") == 0 || strcmp(field->string, "type") == 0) &&
            (! apiConfigStringValid(text + kb, ke - kb) || ! configLexicalCheckEncoding(text + vb, ve - vb) ||
             ! configLexicalCheckTokens(text + vb, ve - vb, SIZE_MAX)))
            return false;
    }
    return true;
}

static bool apiConfigCaptureLexicalFacts(config_file_t *state, const char *text, size_t length, const cJSON *root)
{
    if (! cJSON_IsObject(root))
        return true;
    const cJSON *nodes  = cJSON_GetObjectItemCaseSensitive(root, "nodes");
    size_t       cursor = apiConfigSkipWhitespace(text, length, 0) + 1;
    for (const cJSON *field = root->child; field; field = field->next)
    {
        size_t kb, ke, vb, ve;
        if (! apiConfigFieldSpan(text, length, &cursor, &kb, &ke, &vb, &ve))
        {
            state->api_selector_strings_invalid = true;
            return true;
        }
        if (strcmp(field->string, "name") == 0 &&
            (! apiConfigStringValid(text + kb, ke - kb) || ! apiConfigStringValid(text + vb, ve - vb)))
            state->api_selector_strings_invalid = true;
        if (field != nodes || ! cJSON_IsArray(nodes))
            continue;
        if (! apiConfigStringValid(text + kb, ke - kb))
            state->api_selector_strings_invalid = true;
        size_t entry_begin = vb + 1;
        for (const cJSON *entry = nodes->child; entry; entry = entry->next)
        {
            entry_begin = apiConfigSkipWhitespace(text, length, entry_begin);
            if (entry_begin < length && text[entry_begin] == ',')
                entry_begin = apiConfigSkipWhitespace(text, length, entry_begin + 1);
            size_t entry_end = apiConfigValueEnd(text, length, entry_begin);
            if (! apiConfigInspectNode(state, text + entry_begin, entry_end - entry_begin, entry))
                return false;
            entry_begin = entry_end;
        }
    }
    return true;
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

    const size_t limit = configPolicyIsRestricted() ? WW_HOST_NODE_JSON_LIMIT : SIZE_MAX - 1;
    if (*length > limit || src_len > limit - *length)
    {
        LOGF("JSON Error: resolved output exceeds the size limit");
        return false;
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

        if (configPolicyIsRestricted() && new_capacity > WW_HOST_NODE_JSON_LIMIT + 1U)
        {
            new_capacity = WW_HOST_NODE_JSON_LIMIT + 1U;
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
    int depth  = 0;

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

            if (! is_variables && configPolicyIsRestricted() && *cursor == ':')
            {
                cJSON *key = configPolicyParse(json_text + string_start - 1, key_len + 2);
                if (key == NULL)
                {
                    return false;
                }
                is_variables = cJSON_IsString(key) && strcmp(key->valuestring, "variables") == 0;
                cJSON_Delete(key);
            }

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
                LOGF("JSON Error: top-level \"variables\" block must be an object at byte %zu",
                     (size_t) (cursor - json_text));
                return false;
            }

            size_t object_start = (size_t) (cursor - json_text);
            size_t object_end   = 0;
            if (! findMatchingJsonBrace(json_text, object_start, &object_end))
            {
                LOGF("JSON Error: top-level \"variables\" block is malformed at byte %zu", object_start);
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
    cJSON *json       = configPolicyIsRestricted() ? configPolicyParse(json_text + object_start, object_len)
                                                   : cJSON_ParseWithLength(json_text + object_start, object_len);
    if (json == NULL)
    {
        LOGF("JSON Error: config file \"%s\" -> %s block could not be parsed",
             configPolicyDiagnostic(file_path),
             block_name);
        if (! configPolicyIsRestricted() && cJSON_GetErrorPtr() != NULL)
        {
            LOGF("JSON Error: variables byte %zu", (size_t) (cJSON_GetErrorPtr() - (json_text + object_start)));
        }
        *ok_out = false;
        return NULL;
    }

    if (! cJSON_IsObject(json))
    {
        LOGF("JSON Error: config file \"%s\" -> %s must be an object", configPolicyDiagnostic(file_path), block_name);
        cJSON_Delete(json);
        *ok_out = false;
        return NULL;
    }

    return json;
}

static bool apiConfigRawVariableSpan(const char *raw_variables, size_t raw_variables_length, const cJSON *variables,
                                     const cJSON *value, const char **raw, size_t *raw_length)
{
    if (raw_variables == NULL)
        return false;
    size_t cursor = 1;
    for (const cJSON *entry = variables->child; entry; entry = entry->next)
    {
        size_t kb, ke, vb, ve;
        if (! apiConfigFieldSpan(raw_variables, raw_variables_length, &cursor, &kb, &ke, &vb, &ve))
            return false;
        if (entry == value)
        {
            *raw        = raw_variables + vb;
            *raw_length = ve - vb;
            return true;
        }
    }
    return false;
}

static char *substituteVariables(const char *json_text, const cJSON *variables, const char *file_path)
{
    size_t      variables_begin = 0, variables_end = 0;
    const char *variables_key   = NULL;
    bool        variables_found = false;
    if (variables != NULL &&
        ! findVariablesObjectRange(json_text, &variables_begin, &variables_end, &variables_key, &variables_found))
        return NULL;
    const char *raw_variables        = variables_found ? json_text + variables_begin : NULL;
    size_t      raw_variables_length = variables_found ? variables_end - variables_begin + 1 : 0;
    size_t      input_len            = stringLength(json_text);
    size_t      capacity             = input_len + 1;
    size_t      out_len              = 0;
    bool        in_string            = false;
    bool        escaped              = false;

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
            LOGF("JSON Error: config file \"%s\" contains an unterminated variable placeholder at byte %zu",
                 configPolicyDiagnostic(file_path),
                 i);
            memoryFree(output);
            return NULL;
        }

        if (placeholder_end == i + 1)
        {
            LOGF("JSON Error: config file \"%s\" contains an empty variable placeholder at byte %zu",
                 configPolicyDiagnostic(file_path),
                 i);
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
        const cJSON *variable_value =
            variables != NULL ? cJSON_GetObjectItemCaseSensitive(variables, variable_name) : NULL;
        if (variable_value == NULL)
        {
            LOGF("JSON Error: config file \"%s\" references undefined variable \"%s\"",
                 configPolicyDiagnostic(file_path),
                 configPolicyDiagnostic(variable_name));
            memoryFree(variable_name);
            memoryFree(output);
            return NULL;
        }

        /* Preserve invalid string evidence through substitution: cJSON's
         * serializer truncates decoded NUL and could otherwise turn a malformed
         * configured string into a valid prefix. Unrelated host
         * values retain their permissive parsing and ordinary serialization. */
        const char *raw        = NULL;
        size_t      raw_length = 0;
        if (apiConfigRawVariableSpan(
                raw_variables, raw_variables_length, variables, variable_value, &raw, &raw_length) &&
            ! apiConfigStringValid(raw, raw_length))
        {
            bool append_ok = appendJsonChunk(&output, &out_len, &capacity, raw, raw_length);
            memoryFree(variable_name);
            if (! append_ok)
            {
                memoryFree(output);
                return NULL;
            }
            i = placeholder_end;
            continue;
        }

        char *replacement;
        if (configPolicyIsRestricted())
        {
            /* cJSON asks for five spare bytes even for an exact-fit print.
             * It cannot grow this buffer; reject before copying excess output. */
            size_t room = WW_HOST_NODE_JSON_LIMIT - out_len;
            replacement = memoryAllocate(room + 5);
            if (replacement != NULL &&
                (! cJSON_PrintPreallocated((cJSON *) variable_value, replacement, (int) (room + 5), false) ||
                 strlen(replacement) > room))
            {
                memoryFree(replacement);
                replacement = NULL;
            }
        }
        else
        {
            replacement = cJSON_PrintUnformatted((cJSON *) variable_value);
        }
        if (replacement == NULL)
        {
            LOGF("JSON Error: config file \"%s\" could not serialize variable \"%s\"",
                 configPolicyDiagnostic(file_path),
                 configPolicyDiagnostic(variable_name));
            memoryFree(variable_name);
            memoryFree(output);
            return NULL;
        }

        bool append_ok = appendJsonChunk(&output, &out_len, &capacity, replacement, stringLength(replacement));
        if (configPolicyIsRestricted())
        {
            memoryFree(replacement);
        }
        else
        {
            cJSON_free(replacement);
        }
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
        LOGE("WriteFile Error: cJSON_PrintBuffered failed for \"%s\"", configPolicyDiagnostic(state->file_path));
        return;
    }
    size_t    len         = strlen(string);
    const int max_retries = 3;
    for (int i = 0; i < max_retries; i++)
    {
        if (writeFile(state->file_path, string, len))
        {
            state->file_prebuffer_size = len;
            cJSON_free(string);
            return;
        }
        LOGE("WriteFile Error: could not write to \"%s\". retry...", configPolicyDiagnostic(state->file_path));
    }
    LOGE("WriteFile Error: giving up writing to config file \"%s\"", configPolicyDiagnostic(state->file_path));
    cJSON_free(string);
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
    config_file_t *state = memoryAllocateZero(sizeof(config_file_t));
    if (UNLIKELY(state == NULL))
    {
        LOGF("Config file: failed to allocate parser state");
        return NULL;
    }
    if (UNLIKELY(! mutexTryInit(&(state->guard))))
    {
        LOGF("Config file: failed to initialize parser mutex");
        memoryFree(state);
        return NULL;
    }

    state->file_path = memoryAllocate(strlen(file_path) + 1);
    if (UNLIKELY(state->file_path == NULL))
    {
        LOGF("Config file: failed to allocate file path");
        configfileDestroy(state);
        return NULL;
    }
    stringCopy(state->file_path, file_path);

    char *data_json;
    if (configPolicyIsRestricted())
    {
        FILE  *input  = fopen(file_path, "rb");
        size_t length = 0;
        data_json     = input != NULL ? configPolicyRead(input, WW_HOST_NODE_JSON_LIMIT, &length) : NULL;
        if (input != NULL && fclose(input) != 0)
        {
            memoryFree(data_json);
            data_json = NULL;
        }
    }
    else
    {
        data_json = readFile(file_path);
    }

    if (! data_json)
    {
        LOGF("File Error: config file \"%s\" could not be read", configPolicyDiagnostic(file_path));
        configfileDestroy(state);
        return NULL;
    }

    char *json_without_comments = stripJsonLineComments(data_json);
    memoryFree(data_json);

    if (json_without_comments == NULL)
    {
        LOGF("JSON Error: config file \"%s\" comment stripping failed", configPolicyDiagnostic(file_path));
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

    char *resolved_json = substituteVariables(json_without_comments, variables_json, file_path);
    cJSON_Delete(variables_json);
    memoryFree(json_without_comments);

    if (resolved_json == NULL)
    {
        configfileDestroy(state);
        return NULL;
    }

    state->file_prebuffer_size = stringLength(resolved_json);

    cJSON *json = configPolicyIsRestricted() ? configPolicyParse(resolved_json, state->file_prebuffer_size)
                                             : cJSON_ParseWithLength(resolved_json, state->file_prebuffer_size);

    if (json == NULL)
    {
        LOGF("JSON Error: config file \"%s\" could not be parsed", configPolicyDiagnostic(file_path));
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL && ! configPolicyIsRestricted())
        {
            LOGF("JSON Error: resolved byte %zu", (size_t) (error_ptr - resolved_json));
        }
        memoryFree(resolved_json);
        configfileDestroy(state);
        return NULL;
    }

    state->root = json;
    if (! apiConfigCaptureLexicalFacts(state, resolved_json, state->file_prebuffer_size, json))
    {
        LOGF("JSON Error: APIServer credentials and settings require valid exact strings");
        memoryFree(resolved_json);
        configfileDestroy(state);
        return NULL;
    }
    memoryFree(resolved_json);

    if (! getStringFromJsonObject((&state->name), json, "name"))
    {
        LOGF("JSON Error: config file \"%s\" -> name (string field) the value was empty or invalid",
             configPolicyDiagnostic(file_path));
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
        LOGF("JSON Error: config file \"%s\" -> nodes (array field) the array was empty or invalid",
             configPolicyDiagnostic(file_path));
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
