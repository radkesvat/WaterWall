#include "hv/hplatform.h"
#include "config_file.h"
#include "loggers/core_logger.h"
#include "utils/fileutils.h"

void destroyConfigFile(config_file_t *state)
{
    cJSON_Delete(state->root);

    if (state->file_path != NULL)
        free(state->file_path);
    if (state->name != NULL)
        free(state->name);
    if (state->author != NULL)
        free(state->author);
    hmutex_destroy(state->guard);

    free(state);
}

void acquireUpdateLock(config_file_t *state)
{
    hmutex_lock(state->guard);
}
void releaseUpdateLock(config_file_t *state)
{
    hmutex_unlock(state->guard);
}
// only use if you acquired lock before
void unsafeCommitChanges(config_file_t *state)
{
    char *string = cJSON_PrintBuffered(state->root, (state->file_prebuffer_size) * 2, true);
    size_t len = strlen(string);
    const max_retries = 3;
    for (size_t i = 0; i < max_retries; i++)
    {
        if (writeFile(state->filepath, string, len))
            return;
        LOGE("WriteFile Error: could not write to \"%s\". retry...", state->filepath);
    }
    LOGE("WriteFile Error: giving up writing to config file \"%s\"", state->filepath);
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
#ifdef OS_WI
    commitChangesHard(state);
#else
    if (0 == pthread_mutex_trylock(state->guard))
    {
        unsafeCommitChanges(state);
        releaseUpdateLock(state);
    }

#endif
}

config_file_t *parseConfigFile(const char *const file_path)
{
    config_file_t *state = malloc(sizeof(config_file_t));
    memset(state, 0, sizeof(config_file_t));
    hmutex_init(state->guard);

    state->file_path = malloc(strlen(file_path) + 1);
    strcpy(state->filepath, file_path);

    char *data_json = readFile(file_path);

    if (!data_json)
    {
        LOGF("File Error: config file \"%s\" could not be read", filepath);
        exit(1);
    }
    state->file_prebuffer_size = strlen(data_json);

    cJSON *json = cJSON_ParseWithLength(data_json, state->file_prebuffer_size);
    state->root = json;

    if (json == NULL)
    {
        LOGF("JSON Error: config file \"%s\" could not be parsed", filepath);
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            fprintf(stderr, "JSON Error before: %s\n", error_ptr);
        }
        exit(1);
    }

    if (!getStringFromJsonObject(state->name, json, "name"))
    {
        LOGF("JSON Error: config file \"%s\" -> name (string field) the value was empty or invalid ", file_path);
    }

    getStringFromJsonObjectOrDefault(state->name, json, "name")
}
