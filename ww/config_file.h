#pragma once

#include "hmutex.h"
#include <stddef.h>

typedef struct config_file_s
{
    char *file_path;
    char *name;
    char *author;
    int   config_version;
    int   core_minimum_version;
    bool  encrypted;

    struct cJSON   *root;
    struct cJSON   *nodes;
    size_t   file_prebuffer_size;
    hmutex_t guard;
} config_file_t;

// a config is loaded in ram and can be updated continously by other threads forexample when a user
// uses some traffic, at some point the config file will be updated, the live data however is available through the api
// so , i see no reason to destroy a config file...
void destroyConfigFile(config_file_t *state);

void acquireUpdateLock(config_file_t *state);
void releaseUpdateLock(config_file_t *state);
// only use if you acquired lock before
void unsafeCommitChanges(config_file_t *state);

void commitChangesHard(config_file_t *state);
// will not write if the mutex is locked
void commitChangesSoft(config_file_t *state);

config_file_t *parseConfigFile(const char *file_path);
