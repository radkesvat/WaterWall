#include "config.h"
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
}

void commitChangesHard(config_file_t *state);
// will not write if the mutex is locked
void commitChangesSoft(config_file_t *state);

config_file_t *parseConfigFile(const char *const file_path)
{
    config_file_t *state = malloc(sizeof(config_file_t));
    memset(state, 0, sizeof(config_file_t));
    hmutex_init(state->guard);
    state->file_path = malloc(strlen(file_path) + 1);
    strcpy(state->filepath, file_path);

    state->handle = fopen(file_path, "rb");
    if (! state->handle)
    {
        LOGF("File Error: config file \"%s\" could not be read", filepath);
        exit(1);
    }
}

void inihConfigFile(const char *const file_path)
{

    char *data_json = readFileFromHandle(file_path);


    cJSON *json = cJSON_Parse(data_json);
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
