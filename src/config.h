#pragma once

#include "common_types.h"
#include "tunnel.h"
#include "utils/jsonutils.h"
#include "hv/hmutex.h"

#define i_type map_node_t
#define i_key hash_t
#define i_val node_t *

#include "stc/hmap.h"


typedef struct config_file_s
{
    FILE * handle;
    char *file_path;
    char *name;
    char *author;
    size_t minimum_version;
    bool encrypted;
    cJSON *root;
    cJSON *nodes;

    hmutex_t guard;
} config_file_t;

#define i_type vec_config_file_t
#define i_key config_file_t
#include "stc/vec.h"


// a config is loaded in ram and can be updated continously by other threas forexample when a user 
// uses some traffic, at some point the config file will be update, the live data however is available through the api
// so , i see no reason to destroy a config file...
void destroyConfigFile(config_file_t *state);


void acquireUpdateLock(config_file_t *state);
void releaseUpdateLock(config_file_t *state);
// only use if you acquired lock before
void unsafeCommitChanges(config_file_t *state);

void commitChangesHard(config_file_t *state);
// will not write if the mutex is locked
void commitChangesSoft(config_file_t *state);

config_file_t *initConfigFile(const char *const file_path);
