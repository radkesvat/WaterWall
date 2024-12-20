#include "config_file.h"
#include "cJSON.h"
#include "ww.h"
#include "loggers/ww_logger.h" //NOLINT
#include "utils/fileutils.h"
#include "utils/jsonutils.h"
#include <hmutex.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

void destroyConfigFile(config_file_t *state)
{
    cJSON_Delete(state->root);

    if (state->file_path != NULL)
    {
        globalFree(state->file_path);
    }
    if (state->name != NULL)
    {
        globalFree(state->name);
    }
    if (state->author != NULL)
    {
        globalFree(state->author);
    }
    hmutex_destroy(&(state->guard));

    globalFree(state);
}

void acquireUpdateLock(config_file_t *state)
{
    hmutex_lock(&(state->guard));
}

void releaseUpdateLock(config_file_t *state)
{
    hmutex_unlock(&(state->guard));
}

// only use if you acquired lock before
void unsafeCommitChanges(config_file_t *state)
{
    char     *string      = cJSON_PrintBuffered(state->root, (int) ((state->file_prebuffer_size) * 2), true);
    size_t    len         = strlen(string);
    const int max_retries = 3;
    for (int i = 0; i < max_retries; i++)
    {
        if (writeFile(state->file_path, string, len))
        {
            return;
        }
        LOGE("WriteFile Error: could not write to \"%s\". retry...", state->file_path);
    }
    LOGE("WriteFile Error: giving up writing to config file \"%s\"", state->file_path);
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
    if (hmutex_trylock(&(state->guard)))
    {
        unsafeCommitChanges(state);
        releaseUpdateLock(state);
    }

#endif
}

config_file_t *parseConfigFile(const char *const file_path)
{
    config_file_t *state = globalMalloc(sizeof(config_file_t));
    memset(state, 0, sizeof(config_file_t));
    hmutex_init(&(state->guard));

    state->file_path = globalMalloc(strlen(file_path) + 1);
    strcpy(state->file_path, file_path);

    char *data_json = readFile(file_path);

    if (! data_json)
    {
        LOGF("File Error: config file \"%s\" could not be read", file_path);
        exit(1);
    }
    state->file_prebuffer_size = strlen(data_json);

    cJSON *json = cJSON_ParseWithLength(data_json, state->file_prebuffer_size);
    state->root = json;

    if (json == NULL)
    {
        LOGF("JSON Error: config file \"%s\" could not be parsed", file_path);
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            LOGF("JSON Error: before: %s\n", error_ptr);
        }
        exit(1);
    }
    globalFree(data_json);

    if (! getStringFromJsonObject((&state->name), json, "name"))
    {
        LOGF("JSON Error: config file \"%s\" -> name (string field) the value was empty or invalid", file_path);
        exit(1);
    }

    getStringFromJsonObjectOrDefault(&(state->author), json, "author", "EMPTY_AUTHOR");
    getIntFromJsonObject(&(state->config_version), json, "config-version");
    getIntFromJsonObject(&(state->core_minimum_version), json, "core-minimum-version");
    getBoolFromJsonObject(&(state->encrypted), json, "encrypted");
    cJSON *nodes = cJSON_GetObjectItemCaseSensitive(json, "nodes");
    if (! (cJSON_IsArray(nodes) && nodes->child != NULL))
    {
        LOGF("JSON Error: config file \"%s\" -> nodes (array field) the array was empty or invalid", file_path);
        exit(1);
    }
    state->nodes = nodes;
    return state;
}
